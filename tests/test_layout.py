# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Tests for the report's section sequence (priority / middle / BAU bands)."""

from __future__ import annotations

from collections.abc import Collection

import pytest

from github_security_report import layout
from github_security_report.categories import CategoryKey, category_meta
from github_security_report.config import (
    DEFAULT_BAU,
    DEFAULT_PRIORITY,
    OrderConfig,
    OrderStyle,
)
from github_security_report.models import (
    Repo,
    RepoSignal,
    RepoState,
    SeverityCounts,
    SignalType,
)
from github_security_report.report import (
    SIGNAL_ORDER,
    OrgReport,
    SignalSection,
    TableRow,
    TableSection,
    build_org_report,
    dt,
)


def _repo(name: str = "r") -> Repo:
    return Repo(name, f"o/{name}", f"https://github.com/o/{name}")


def _offender(signal: SignalType) -> RepoSignal:
    return RepoSignal(
        repo=_repo(),
        signal=signal,
        state=RepoState.OFFENDER,
        counts=SeverityCounts(high=1),
    )


def _table(key: CategoryKey, *, rows: int = 0) -> TableSection:
    return TableSection(
        category=category_meta(key),
        columns=("Repository", "Count"),
        rows=[TableRow(repo=_repo(f"r{index}"), cells=("1",)) for index in range(rows)],
    )


def _report(
    *,
    offenders: Collection[SignalType] = (),
    populated_tables: Collection[CategoryKey] = (),
    dependabot_tables: bool = False,
) -> OrgReport:
    """A report whose sections are populated or empty exactly as asked.

    Every category the org-mode pipeline builds is present, so the band
    membership under test is exercised against the full set rather than a
    convenient subset.
    """
    signals = [_offender(signal) for signal in offenders]
    report = build_org_report(
        "o", signals, repo_count=1, generated_at=dt.datetime.now(dt.timezone.utc)
    )
    for key, attr in (
        (CategoryKey.RELEASES, "releases"),
        (CategoryKey.MUTABLE_RELEASES, "mutable_releases"),
        (
            CategoryKey.PRIVATE_VULNERABILITY_REPORTING,
            "private_vulnerability_reporting",
        ),
        (CategoryKey.GITHUB_ISSUES, "issues"),
        (CategoryKey.PULL_REQUESTS, "pull_requests"),
        (CategoryKey.PULL_REQUESTS_ASSIGNED, "assigned_pull_requests"),
    ):
        setattr(report, attr, _table(key, rows=1 if key in populated_tables else 0))
    if dependabot_tables:
        report.dependabot_tables = [
            _table(CategoryKey.DEPENDABOT_ALERTS_ENABLED, rows=1)
        ]
    return report


def _keys(report: OrgReport) -> list[CategoryKey]:
    return [item.key for item in layout.plan(report)]


def _resolved(report: OrgReport, order: OrderConfig) -> list[CategoryKey]:
    report.section_order = layout.resolve(report, order)
    return _keys(report)


class TestDefaultItems:
    """The unordered input: every section the report actually produced."""

    def test_repo_mode_report_has_signals_only(self) -> None:
        # Repo mode never builds the generic tables, so they must be absent
        # rather than present and empty -- an empty Releases table in a
        # single-repo report is a claim, not a gap.
        report = build_org_report("o/r", [], repo_count=1)
        assert _keys(report) == [signal.category_key for signal in SIGNAL_ORDER]

    def test_dependabot_posture_tables_travel_with_their_parent(self) -> None:
        report = _report(dependabot_tables=True)
        item = next(
            i for i in layout.plan(report) if i.key is CategoryKey.DEPENDABOT_ALERTS
        )
        assert [child.category.key for child in item.children] == [
            CategoryKey.DEPENDABOT_ALERTS_ENABLED
        ]
        # And they are never placed as top-level items of their own, which
        # would leave three near-identical headings with nothing to say which
        # signal they qualified.
        assert CategoryKey.DEPENDABOT_ALERTS_ENABLED not in _keys(report)


class TestAutoBands:
    """The default layout: urgent findings first, background last."""

    def test_populated_priority_leads_and_bau_trails(self) -> None:
        report = _report(
            offenders={SignalType.SECRET_SCANNING, SignalType.SCORECARD},
            populated_tables={CategoryKey.GITHUB_ISSUES},
        )
        keys = _resolved(report, OrderConfig())
        assert keys[0] is CategoryKey.SECRET_SCANNING
        # Scorecard and Issues both carry data, so both hold their BAU slots at
        # the very bottom, in the configured BAU order.
        assert keys[-2:] == [CategoryKey.SCORECARD, CategoryKey.GITHUB_ISSUES]

    def test_empty_priority_category_demotes_into_the_middle(self) -> None:
        report = _report(offenders={SignalType.SECRET_SCANNING})
        keys = _resolved(report, OrderConfig())
        # Secret scanning has findings and leads.
        assert keys[0] is CategoryKey.SECRET_SCANNING
        # CodeQL has none, so it must not sit above a populated section.
        assert keys.index(CategoryKey.CODEQL) > 0

    def test_a_clean_run_puts_nothing_in_the_priority_band(self) -> None:
        keys = _resolved(_report(), OrderConfig())
        # Every category is empty, so every band member demotes and the order
        # collapses to: demoted priority, middle, demoted BAU.
        assert keys[: len(DEFAULT_PRIORITY)] == list(DEFAULT_PRIORITY)
        assert keys[-len(DEFAULT_BAU) :] == list(DEFAULT_BAU)

    def test_demoted_members_bound_the_middle_from_each_side(self) -> None:
        # One populated member in each band, one empty. The empty ones must
        # land inside the middle, adjacent to the band they came from.
        report = _report(
            offenders={SignalType.SECRET_SCANNING, SignalType.SCORECARD},
        )
        keys = _resolved(report, OrderConfig())
        assert keys[0] is CategoryKey.SECRET_SCANNING
        assert keys[-1] is CategoryKey.SCORECARD
        # A demoted priority member sits above a demoted BAU member.
        assert keys.index(CategoryKey.CODEQL) < keys.index(CategoryKey.PULL_REQUESTS)

    def test_a_signal_with_posture_rows_keeps_its_slot(self) -> None:
        # The Dependabot Alerts signal itself is clean, but its posture
        # sub-tables carry rows, so the reader still sees results there.
        report = _report(dependabot_tables=True)
        keys = _resolved(report, OrderConfig())
        assert keys[0] is CategoryKey.DEPENDABOT_ALERTS


class TestDualStyle:
    """Operator-supplied bands, same demotion behaviour."""

    def test_configured_priority_order_is_honoured(self) -> None:
        report = _report(
            offenders={SignalType.CODEQL, SignalType.SECRET_SCANNING},
        )
        order = OrderConfig(
            style=OrderStyle.DUAL,
            priority=(CategoryKey.CODEQL, CategoryKey.SECRET_SCANNING),
        )
        assert _resolved(report, order)[:2] == [
            CategoryKey.CODEQL,
            CategoryKey.SECRET_SCANNING,
        ]

    def test_an_omitted_band_keeps_the_built_in_one(self) -> None:
        report = _report(offenders={SignalType.SCORECARD})
        order = OrderConfig(style=OrderStyle.DUAL, priority=(CategoryKey.CODEQL,))
        # bau was not supplied, so Scorecard is still BAU and still trails.
        assert _resolved(report, order)[-1] is CategoryKey.SCORECARD


class TestSingleStyle:
    """A strict hierarchy, applied whatever the data says."""

    def test_sequence_is_applied_verbatim_without_demotion(self) -> None:
        report = _report(offenders={SignalType.SECRET_SCANNING})
        order = OrderConfig(
            style=OrderStyle.SINGLE,
            sequence=(CategoryKey.GITHUB_ISSUES, CategoryKey.CODEQL),
        )
        keys = _resolved(report, order)
        # Both named categories are empty, and both stay exactly where the
        # sequence put them -- ahead of the populated secret-scanning section.
        assert keys[:2] == [CategoryKey.GITHUB_ISSUES, CategoryKey.CODEQL]
        assert keys.index(CategoryKey.SECRET_SCANNING) > 1

    def test_unnamed_categories_keep_assembly_order_behind_it(self) -> None:
        report = _report()
        order = OrderConfig(
            style=OrderStyle.SINGLE, sequence=(CategoryKey.GITHUB_ISSUES,)
        )
        keys = _resolved(report, order)
        assert keys[0] is CategoryKey.GITHUB_ISSUES
        assert keys[1:] == [
            key for key in _keys(_report()) if key is not CategoryKey.GITHUB_ISSUES
        ]


class TestFixedStyle:
    """The pre-existing order, kept available."""

    def test_nothing_moves(self) -> None:
        report = _report(offenders={SignalType.SECRET_SCANNING})
        before = _keys(report)
        assert _resolved(report, OrderConfig(style=OrderStyle.FIXED)) == before

    def test_resolves_to_the_empty_sequence(self) -> None:
        # Empty means "assembly order", which is what an unresolved report
        # already renders in, so fixed needs to store nothing.
        assert layout.resolve(_report(), OrderConfig(style=OrderStyle.FIXED)) == ()


class TestNoDuplication:
    """A category holds exactly one position, whatever the config says."""

    @pytest.mark.parametrize(
        "order",
        [
            OrderConfig(
                style=OrderStyle.DUAL,
                priority=(CategoryKey.CODEQL, CategoryKey.CODEQL),
            ),
            OrderConfig(
                style=OrderStyle.SINGLE,
                sequence=(CategoryKey.CODEQL, CategoryKey.CODEQL),
            ),
        ],
    )
    def test_repeated_keys_place_a_section_once(self, order: OrderConfig) -> None:
        keys = _resolved(_report(), order)
        assert keys.count(CategoryKey.CODEQL) == 1

    def test_every_section_survives_reordering(self) -> None:
        report = _report(offenders={SignalType.CODEQL})
        before = sorted(_keys(report), key=lambda key: key.value)
        after = sorted(_resolved(report, OrderConfig()), key=lambda key: key.value)
        assert after == before

    def test_a_key_naming_an_absent_category_is_skipped(self) -> None:
        # Repo mode builds no Releases table, so a band naming it must not
        # invent one (or crash).
        report = build_org_report("o/r", [], repo_count=1)
        keys = _resolved(
            report,
            OrderConfig(style=OrderStyle.DUAL, priority=(CategoryKey.RELEASES,)),
        )
        assert CategoryKey.RELEASES not in keys


class TestEverySurfaceAgrees:
    """The point of resolving the order once: no surface may disagree.

    A Slack digest whose sections run in a different order from the page it
    links to is worse than either order alone, so this pins all four surfaces
    against the same resolved sequence rather than testing one and trusting
    the rest.
    """

    def _headings(self, text: str, pattern: str, titles: list[str]) -> list[str]:
        """``titles`` in the order their *headings* appear in ``text``.

        Matched as headings rather than bare titles: "Pull Requests" also
        occurs inside the "Assigned to Me" description, and "CodeQL" inside
        its own, so a substring search would order sections by whichever
        paragraph happened to mention them first.
        """
        found = [
            (text.index(heading), title)
            for title in titles
            if (heading := pattern.format(title=title)) in text
        ]
        return [title for _, title in sorted(found)]

    def _report(self) -> OrgReport:
        report = _report(
            offenders={SignalType.SECRET_SCANNING, SignalType.SCORECARD},
            populated_tables={CategoryKey.GITHUB_ISSUES},
        )
        report.section_order = layout.resolve(report, OrderConfig())
        return report

    def test_markdown_slack_and_html_share_the_resolved_order(self) -> None:
        from github_security_report.render import html as html_render
        from github_security_report.render import markdown as md_render
        from github_security_report.render import slack as slack_render

        report = self._report()
        expected = [category_meta(key).title for key in report.section_order]

        slack_text = "\n".join(
            block.get("text", {}).get("text", "")
            for block in slack_render.render_org_blocks(
                report, top_n=10, pages_url=None
            )
        )
        surfaces = {
            "markdown": (md_render.render_org(report), "## {title}"),
            "html": (html_render.render_org_html(report), "<h2>{title}</h2>"),
            "slack": (slack_text, "*{title}*"),
        }

        for name, (text, pattern) in surfaces.items():
            rendered = self._headings(text, pattern, expected)
            # Every surface must present the sections it renders in the one
            # resolved order -- and must render enough of them for that to
            # mean something.
            assert len(rendered) > 4, name
            assert rendered == [title for title in expected if title in rendered], name

    def test_secret_scanning_leads_the_rendered_markdown(self) -> None:
        from github_security_report.render import markdown as md_render

        text = md_render.render_org(self._report())
        # The whole point of the default layout: the urgent finding is the
        # first heading a reader meets, not OpenSSF Scorecard.
        assert text.index("## Secret Scanning") < text.index("## OpenSSF Scorecard")


class TestPopulated:
    """What counts as \"nothing to report\"."""

    def test_a_skipped_signal_section_demotes(self) -> None:
        # Feature gating renders one line of explanation, not results, so it is
        # not a reason to hold the top of the page.
        section = SignalSection(signal=SignalType.CODEQL, skipped=True)
        assert layout.LayoutItem(section).populated is False

    def test_offenders_count_as_populated(self) -> None:
        section = SignalSection(
            signal=SignalType.CODEQL, offenders=[_offender(SignalType.CODEQL)]
        )
        assert layout.LayoutItem(section).populated is True

    def test_child_rows_count_towards_the_parent(self) -> None:
        item = layout.LayoutItem(
            SignalSection(signal=SignalType.DEPENDABOT),
            children=(_table(CategoryKey.DEPENDABOT_ALERTS_ENABLED, rows=1),),
        )
        assert item.populated is True
