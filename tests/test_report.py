# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Tests for report aggregation."""

from __future__ import annotations

import datetime as dt

from github_security_report import report
from github_security_report.classify import RepoFacts, classify_repo
from github_security_report.models import (
    Repo,
    RepoSignal,
    RepoState,
    SeverityCounts,
    SignalType,
)

WHEN = dt.datetime(2026, 6, 16, 9, 0, tzinfo=dt.timezone.utc)


def _repo(name: str, **flags: bool) -> Repo:
    return Repo(
        name,
        f"lfreleng-actions/{name}",
        f"https://github.com/lfreleng-actions/{name}",
        archived=flags.get("archived", False),
    )


def _sections(org: report.OrgReport) -> dict[SignalType, report.SignalSection]:
    return {s.signal: s for s in org.sections}


class TestBuildSummary:
    def test_all_pass_collapses_to_all_label(self) -> None:
        # When nothing else needs attention the pass line drops its number.
        lines = report.build_summary([report.SummaryCount("pass", 86, "Clean")])
        assert [(line.kind, line.text) for line in lines] == [("pass", "All Clean")]

    def test_all_pass_uses_the_alternative_collapse_label(self) -> None:
        # A counted label that is a noun phrase ("12 No open issues") does not
        # parse after "All", so a category may supply adjectival wording for
        # the collapsed line only.
        lines = report.build_summary(
            [report.SummaryCount("pass", 86, "No open issues", all_label="Clean")]
        )
        assert [line.text for line in lines] == ["All Clean"]

    def test_alternative_collapse_label_is_unused_when_counted(self) -> None:
        lines = report.build_summary(
            [
                report.SummaryCount("fail", 2, "With open issues"),
                report.SummaryCount("pass", 84, "No open issues", all_label="Clean"),
            ]
        )
        assert [line.text for line in lines] == [
            "2 With open issues",
            "84 No open issues",
        ]

    def test_pass_keeps_number_when_excluded_present(self) -> None:
        lines = report.build_summary(
            [
                report.SummaryCount("pass", 85, "Clean"),
                report.SummaryCount("excluded", 1, "Excluded", ("art",)),
            ]
        )
        assert [(line.kind, line.text) for line in lines] == [
            ("pass", "85 Clean"),
            ("excluded", "1 Excluded"),
        ]

    def test_failures_sort_first(self) -> None:
        # Footer order is remediation-first: fail, disabled, unknown, pass,
        # excluded -- regardless of input order.
        lines = report.build_summary(
            [
                report.SummaryCount("pass", 5, "Clean"),
                report.SummaryCount("excluded", 1, "Excluded", ("x",)),
                report.SummaryCount("fail", 2, "Mutable"),
                report.SummaryCount("unknown", 3, "Unknown"),
                report.SummaryCount("disabled", 4, "Disabled", ("y",)),
            ]
        )
        assert [line.kind for line in lines] == [
            "fail",
            "disabled",
            "unknown",
            "pass",
            "excluded",
        ]

    def test_zero_counts_dropped(self) -> None:
        lines = report.build_summary(
            [
                report.SummaryCount("fail", 0, "Mutable"),
                report.SummaryCount("pass", 3, "Immutable"),
            ]
        )
        assert [line.text for line in lines] == ["All Immutable"]

    def test_non_render_bucket_suppresses_collapse_without_a_line(self) -> None:
        # A render=False bucket (e.g. a severity signal's offenders, which live
        # in the table rather than as a footer line) must still stop the pass
        # line collapsing to "All <pass>", but must not emit its own line.
        lines = report.build_summary(
            [
                report.SummaryCount("fail", 2, "With findings", render=False),
                report.SummaryCount("pass", 84, "Clean"),
            ]
        )
        assert [(line.kind, line.text) for line in lines] == [("pass", "84 Clean")]

    def test_signal_section_with_offenders_does_not_claim_all_clean(self) -> None:
        # A severity section that has offenders AND clean repos but no nag,
        # unknown or excluded repositories must not collapse its pass line to a
        # falsely reassuring "All Clean"; the offenders are in the table.
        section = report.SignalSection(
            signal=SignalType.CODEQL,
            offenders=[
                RepoSignal(
                    _repo("bad"),
                    SignalType.CODEQL,
                    RepoState.OFFENDER,
                    SeverityCounts(high=1),
                )
            ],
            clean_count=85,
        )
        lines = report.build_summary(section.summary_counts())
        # Only the pass line shows, and it keeps its number (no "All Clean").
        assert [(line.kind, line.text) for line in lines] == [("pass", "85 Clean")]

    def test_fully_clean_signal_section_collapses_to_all(self) -> None:
        # With no offenders (and nothing else outstanding) the collapse to
        # "All <pass>" still applies.
        section = report.SignalSection(signal=SignalType.CODEQL, clean_count=86)
        lines = report.build_summary(section.summary_counts())
        assert [(line.kind, line.text) for line in lines] == [("pass", "All Clean")]


class TestBuildOrgReport:
    def test_sections_in_fixed_order(self) -> None:
        org = report.build_org_report("o", [], repo_count=0, generated_at=WHEN)
        assert [s.signal for s in org.sections] == list(report.SIGNAL_ORDER)

    def test_buckets_offenders_clean_nag_unknown(self) -> None:
        signals = [
            RepoSignal(
                _repo("a"),
                SignalType.CODEQL,
                RepoState.OFFENDER,
                SeverityCounts(high=2),
            ),
            RepoSignal(_repo("b"), SignalType.CODEQL, RepoState.CLEAN),
            RepoSignal(_repo("c"), SignalType.CODEQL, RepoState.NAG),
            RepoSignal(_repo("d"), SignalType.CODEQL, RepoState.UNKNOWN),
        ]
        org = report.build_org_report("o", signals, repo_count=4, generated_at=WHEN)
        codeql = _sections(org)[SignalType.CODEQL]
        assert [s.repo.name for s in codeql.offenders] == ["a"]
        assert codeql.clean_count == 1
        assert [r.name for r in codeql.nag_repos] == ["c"]
        assert codeql.unknown_count == 1

    def test_offenders_ranked_worst_first(self) -> None:
        signals = [
            RepoSignal(
                _repo("low"),
                SignalType.CODEQL,
                RepoState.OFFENDER,
                SeverityCounts(low=9),
            ),
            RepoSignal(
                _repo("crit"),
                SignalType.CODEQL,
                RepoState.OFFENDER,
                SeverityCounts(critical=1),
            ),
        ]
        org = report.build_org_report("o", signals, repo_count=2, generated_at=WHEN)
        assert [s.repo.name for s in _sections(org)[SignalType.CODEQL].offenders] == [
            "crit",
            "low",
        ]

    def test_top_n_limits_offenders(self) -> None:
        signals = [
            RepoSignal(
                _repo(f"r{i}"),
                SignalType.CODEQL,
                RepoState.OFFENDER,
                SeverityCounts(high=i),
            )
            for i in range(1, 6)
        ]
        section = _sections(
            report.build_org_report("o", signals, repo_count=5, generated_at=WHEN)
        )[SignalType.CODEQL]
        assert len(section.offenders) == 5  # full list retained
        assert len(section.top(2)) == 2  # only Slack truncates

    def test_archived_excluded_from_nag(self) -> None:
        signals = [
            RepoSignal(_repo("old", archived=True), SignalType.CODEQL, RepoState.NAG),
            RepoSignal(_repo("live"), SignalType.CODEQL, RepoState.NAG),
        ]
        org = report.build_org_report("o", signals, repo_count=2, generated_at=WHEN)
        # Archived repo is never nagged, even when otherwise in scope.
        assert [r.name for r in _sections(org)[SignalType.CODEQL].nag_repos] == ["live"]

    def test_end_to_end_from_facts(self) -> None:
        facts = RepoFacts(
            repo=_repo("dependamerge"),
            code_scanning_status=200,
            code_scanning_tools={"CodeQL", "Scorecard"},
            code_scanning_alerts=[
                {
                    "tool": {"name": "Scorecard"},
                    "rule": {"security_severity_level": "high"},
                }
            ],
            secret_scanning_status=200,
            dependabot_enabled=True,
            scorecard_status=200,
            scorecard_score=8.2,
        )
        org = report.build_org_report(
            "lfreleng-actions", classify_repo(facts), repo_count=1, generated_at=WHEN
        )
        sections = _sections(org)
        assert sections[SignalType.SCORECARD].offenders[0].score == 8.2
        assert sections[SignalType.CODEQL].clean_count == 1
        assert sections[SignalType.SECRET_SCANNING].clean_count == 1


class TestOffenderColumnTotals:
    def test_total_includes_informational(self) -> None:
        # The Total column sums every severity rung, including the hidden
        # informational one. The trailing totals row must therefore accumulate
        # informational too, so the Total column sums vertically (each row's
        # Total already counts informational via SeverityCounts.total).
        offenders = [
            RepoSignal(
                _repo("a"),
                SignalType.ZIZMOR,
                RepoState.OFFENDER,
                SeverityCounts(high=2, informational=3),
            ),
            RepoSignal(
                _repo("b"),
                SignalType.ZIZMOR,
                RepoState.OFFENDER,
                SeverityCounts(medium=1, informational=4),
            ),
        ]
        totals = report.offender_column_totals(offenders)
        assert totals.high == 2
        assert totals.medium == 1
        assert totals.informational == 7
        # 2 high + 1 medium + 7 informational == sum of the per-row Totals (5+5).
        assert totals.total == sum(o.counts.total for o in offenders) == 10


class TestTruncate:
    def test_no_limit_returns_all(self) -> None:
        assert report.truncate([1, 2, 3], None) == ([1, 2, 3], 0)

    def test_zero_limit_returns_all(self) -> None:
        # 0 is the documented "no limit" setting: show everything, hide nothing.
        assert report.truncate([1, 2, 3], 0) == ([1, 2, 3], 0)

    def test_under_limit_returns_all(self) -> None:
        assert report.truncate([1, 2], 5) == ([1, 2], 0)

    def test_over_limit_truncates_and_counts_hidden(self) -> None:
        shown, hidden = report.truncate([1, 2, 3, 4, 5], 2)
        assert shown == [1, 2]
        assert hidden == 3

    def test_exact_limit_hides_nothing(self) -> None:
        assert report.truncate([1, 2, 3], 3) == ([1, 2, 3], 0)


class TestTableColumnTotals:
    """The shared trailing totals row for generic tables."""

    def _section(self, rows: list[report.TableRow], **kwargs) -> report.TableSection:
        from github_security_report.categories import CategoryKey, category_meta

        return report.TableSection(
            category=category_meta(CategoryKey.GITHUB_ISSUES),
            columns=("Repository", "Bug", "Total", "Oldest"),
            rows=rows,
            **kwargs,
        )

    def _rows(self) -> list[report.TableRow]:
        return [
            report.TableRow(repo=_repo("a"), cells=("1", "4", "3 days")),
            report.TableRow(repo=_repo("b"), cells=("2", "5", "9 days")),
        ]

    def test_no_sum_columns_means_no_totals_row(self) -> None:
        section = self._section(self._rows())
        assert report.table_column_totals(section, section.rows) is None

    def test_sums_numeric_columns_and_blanks_the_rest(self) -> None:
        section = self._section(self._rows(), sum_columns=frozenset({1, 2}))
        assert report.table_column_totals(section, section.rows) == (
            "Total",
            "3",
            "9",
            "",
        )

    def test_totals_cover_only_the_displayed_rows(self) -> None:
        # Callers pass the already-truncated set, so the totals must describe
        # the visible table rather than the full row list.
        section = self._section(self._rows(), sum_columns=frozenset({1, 2}))
        shown, _hidden = report.truncate(section.rows, 1)
        assert report.table_column_totals(section, shown) == ("Total", "1", "4", "")

    def test_unparsable_cell_contributes_zero(self) -> None:
        rows = [report.TableRow(repo=_repo("a"), cells=("n/a", "4", "3 days"))]
        section = self._section(rows, sum_columns=frozenset({1, 2}))
        assert report.table_column_totals(section, rows) == ("Total", "0", "4", "")

    def test_empty_row_set_totals_to_zero(self) -> None:
        section = self._section([], sum_columns=frozenset({1, 2}))
        assert report.table_column_totals(section, []) == ("Total", "0", "0", "")


class TestExcludedDisplay:
    """When a category's footer shows the excluded repositories."""

    BASELINE = ("fixture", "sandbox")

    def _org(self) -> report.OrgReport:
        return report.build_org_report(
            "o",
            [],
            repo_count=3,
            generated_at=WHEN,
            excluded_repos=[_repo(name) for name in self.BASELINE],
        )

    def _shown(
        self,
        org: report.OrgReport,
        mode: report.ExcludedDisplay,
        key: report.CategoryKey = report.CategoryKey.CODEQL,
    ) -> list[str]:
        options = report.FooterOptions(excluded=mode)
        return [repo.name for repo in options.excluded_shown(org, key)]

    def test_always_show_is_the_default_and_shows_the_baseline(self) -> None:
        org = self._org()
        assert report.FooterOptions().excluded is report.ExcludedDisplay.ALWAYS_SHOW
        assert self._shown(org, report.ExcludedDisplay.ALWAYS_SHOW) == [
            "fixture",
            "sandbox",
        ]

    def test_always_hide_hides_every_category(self) -> None:
        org = self._org()
        org.category_excluded[report.CategoryKey.RELEASES] = [_repo("other")]
        hide = report.ExcludedDisplay.ALWAYS_HIDE
        assert self._shown(org, hide) == []
        # Even a category whose exclusions differ: "always" means always.
        assert self._shown(org, hide, report.CategoryKey.RELEASES) == []

    def test_conditional_hide_hides_a_category_matching_the_baseline(self) -> None:
        assert self._shown(self._org(), report.ExcludedDisplay.CONDITIONAL_HIDE) == []

    def test_conditional_hide_shows_a_deviating_category_in_full(self) -> None:
        # The whole list, not the difference: a reader sees exactly what that
        # category left out without reconstructing it from the baseline.
        org = self._org()
        org.category_excluded[report.CategoryKey.RELEASES] = [
            _repo("fixture"),
            _repo("sandbox"),
            _repo("internal-only"),
        ]
        mode = report.ExcludedDisplay.CONDITIONAL_HIDE
        assert self._shown(org, mode, report.CategoryKey.RELEASES) == [
            "fixture",
            "sandbox",
            "internal-only",
        ]
        # Categories inheriting the baseline stay hidden.
        assert self._shown(org, mode, report.CategoryKey.CODEQL) == []

    def test_conditional_hide_compares_membership_not_order(self) -> None:
        org = self._org()
        org.category_excluded[report.CategoryKey.RELEASES] = [
            _repo(name) for name in reversed(self.BASELINE)
        ]
        mode = report.ExcludedDisplay.CONDITIONAL_HIDE
        assert self._shown(org, mode, report.CategoryKey.RELEASES) == []

    def test_a_category_with_fewer_exclusions_also_deviates(self) -> None:
        # Excluding *less* than the organisation is as much a difference as
        # excluding more, and hiding it would imply the baseline applied.
        org = self._org()
        org.category_excluded[report.CategoryKey.RELEASES] = [_repo("fixture")]
        mode = report.ExcludedDisplay.CONDITIONAL_HIDE
        assert self._shown(org, mode, report.CategoryKey.RELEASES) == ["fixture"]

    def test_hiding_lets_a_clean_category_collapse_to_all(self) -> None:
        # The header's repository count already leaves excluded repositories
        # out, so once no Excluded line qualifies it "All Clean" is accurate.
        section = report.SignalSection(signal=SignalType.CODEQL, clean_count=3)
        org = self._org()
        shown = report.build_summary(section.summary_counts(org.excluded_repos))
        hidden = report.build_summary(section.summary_counts(()))
        assert [line.text for line in shown] == ["3 Clean", "2 Excluded"]
        assert [line.text for line in hidden] == ["All Clean"]
