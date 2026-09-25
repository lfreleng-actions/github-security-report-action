# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Tests for Rich terminal rendering (rendered to a recording console)."""

from __future__ import annotations

import datetime as dt

from rich.console import Console

from github_security_report import remediate, report
from github_security_report.categories import CategoryKey, category_meta
from github_security_report.models import (
    Repo,
    RepoSignal,
    RepoState,
    SeverityCounts,
    SignalType,
)
from github_security_report.render import terminal

WHEN = dt.datetime(2026, 6, 16, 9, 0, tzinfo=dt.timezone.utc)


def _repo(name: str) -> Repo:
    return Repo(name, f"o/{name}", f"https://github.com/o/{name}")


def _org(signals: list[RepoSignal], count: int = 1) -> report.OrgReport:
    return report.build_org_report(
        "lfreleng-actions", signals, repo_count=count, generated_at=WHEN
    )


def _render(org: report.OrgReport, width: int = 120) -> str:
    console = Console(record=True, width=width, no_color=True)
    terminal.render_org(org, console)
    return console.export_text()


def test_offender_table_rendered() -> None:
    sig = RepoSignal(
        _repo("bad"),
        SignalType.CODEQL,
        RepoState.OFFENDER,
        SeverityCounts(critical=1, high=2),
    )
    out = _render(_org([sig]))
    assert "Security report: lfreleng-actions" in out
    assert "CodeQL" in out
    assert "bad" in out


def test_informational_column_shown_when_present() -> None:
    # A zizmor offender carrying note-level findings gets an Info column,
    # and the informational count contributes to the Total column.
    sig = RepoSignal(
        _repo("noisy"),
        SignalType.ZIZMOR,
        RepoState.OFFENDER,
        SeverityCounts(high=2, informational=3),
    )
    out = _render(_org([sig]))
    assert "Info" in out
    # Header order and both the row and totals carry the 3 info / 5 total.
    assert "Zizmor" in out
    assert "noisy" in out


def test_informational_column_absent_without_info() -> None:
    sig = RepoSignal(
        _repo("bad"),
        SignalType.CODEQL,
        RepoState.OFFENDER,
        SeverityCounts(critical=1, high=2),
    )
    out = _render(_org([sig]))
    assert "Info" not in out


def test_skipped_section_renders_single_skip_line() -> None:
    # A gated-out signal shows only its heading, the skip line, and the
    # setup-guide pointer -- never a table, footer or nag list.
    org = report.build_org_report(
        "lfreleng-actions",
        [],
        repo_count=1,
        generated_at=WHEN,
        skipped_signals={SignalType.AISLOP},
    )
    out = _render(org, width=200)
    assert "AI Slop Analysis" in out
    assert report.SKIP_MESSAGE in out
    assert report.ORG_SETUP_DOC_URL in out


def test_clean_nag_unknown_notes() -> None:
    signals = [
        RepoSignal(_repo("clean"), SignalType.CODEQL, RepoState.CLEAN),
        RepoSignal(_repo("nagme"), SignalType.CODEQL, RepoState.NAG),
        RepoSignal(_repo("dunno"), SignalType.CODEQL, RepoState.UNKNOWN),
    ]
    out = _render(_org(signals, count=3))
    assert "1 Clean" in out
    assert "1 Disabled" in out  # numerical total
    assert "Disabled: nagme" in out  # name breakdown, separate line
    assert "1 Unknown" in out


def test_scorecard_score_shown() -> None:
    sig = RepoSignal(
        _repo("r"),
        SignalType.SCORECARD,
        RepoState.OFFENDER,
        SeverityCounts(high=1),
        score=6.5,
    )
    out = _render(_org([sig]))
    assert "6.5" in out


def test_all_sections_present() -> None:
    out = _render(_org([]))
    for signal in report.SIGNAL_ORDER:
        assert signal.heading in out


def test_dependabot_tables_and_releases_rendered() -> None:
    org = _org([], count=2)
    org.dependabot_tables = [
        report.TableSection(
            category=category_meta(CategoryKey.DEPENDABOT_ALERTS_ENABLED),
            columns=("Repository",),
            rows=[report.TableRow(repo=_repo("off"), cells=())],
            fail_count=1,
        )
    ]
    org.releases = report.TableSection(
        category=category_meta(CategoryKey.RELEASES),
        columns=("Repository", "Last release", "Last tag"),
        rows=[report.TableRow(repo=_repo("stale"), cells=("never", "never"))],
        fail_count=1,
    )
    out = _render(org)
    assert "Dependabot: Alerts Enabled" in out
    assert "off" in out
    assert "Releases / Tagging" in out
    assert "stale" in out


def test_mutable_releases_rendered_with_summary() -> None:
    org = _org([], count=84)
    org.mutable_releases = report.TableSection(
        category=category_meta(CategoryKey.MUTABLE_RELEASES),
        columns=("Repository", "Releases"),
        rows=[report.TableRow(repo=_repo("img"), cells=("v0.1.0 (latest)",))],
        pass_count=82,
        fail_count=2,
    )
    out = _render(org)
    # The heading is bare; the standardised summary is beneath the table.
    assert "Mutable Releases" in out
    assert "2 Mutable" in out
    assert "82 Immutable" in out
    assert "img" in out


def test_excluded_repos_shown_under_each_section_with_count() -> None:
    signals = [RepoSignal(_repo("clean"), SignalType.CODEQL, RepoState.CLEAN)]
    org = _org(signals, count=5)
    org.excluded_repos = [_repo("opted-out")]
    out = _render(org)
    # Numerical total separated from the name breakdown.
    assert "1 Excluded" in out
    assert "Excluded: opted-out" in out


def test_terminal_omits_category_description() -> None:
    # The terminal is a brevity-first surface: the explanatory description is
    # reserved for the Markdown/HTML outputs and must not appear here.
    org = _org([], count=1)
    org.releases = report.TableSection(
        category=category_meta(CategoryKey.RELEASES),
        columns=("Repository", "Last release", "Last tag"),
        rows=[report.TableRow(repo=_repo("r"), cells=("never", "never"))],
        fail_count=1,
    )
    out = _render(org)
    assert "ranks highest" not in out


def test_disabled_total_and_names_on_separate_lines() -> None:
    signals = [RepoSignal(_repo("nagme"), SignalType.CODEQL, RepoState.NAG)]
    out = _render(_org(signals, count=1))
    assert "1 Disabled" in out  # total line
    assert "Disabled: nagme" in out  # names line
    assert "not enabled" not in out  # old lowercase label is gone


def test_boolean_feature_section_lists_offenders_inline() -> None:
    # A single-column feature section (enabled/not enabled) must not draw a
    # table: the offenders appear inline under the fail line, like a signal
    # section's "Disabled:" breakdown, labelled with the category's fail wording.
    org = _org([], count=3)
    org.private_vulnerability_reporting = report.TableSection(
        category=category_meta(CategoryKey.PRIVATE_VULNERABILITY_REPORTING),
        columns=("Repository",),
        rows=[
            report.TableRow(repo=_repo("alpha"), cells=()),
            report.TableRow(repo=_repo("beta"), cells=()),
        ],
        pass_count=1,
        fail_count=2,
    )
    out = _render(org)
    assert "Private Vulnerability Reporting" in out
    assert "2 Not enabled" in out
    assert "Not enabled: alpha, beta" in out
    # No table border characters are drawn for the single-column section.
    assert "┃" not in out
    assert "┏" not in out


def test_boolean_feature_section_offenders_honour_top_n() -> None:
    org = _org([], count=5)
    org.private_vulnerability_reporting = report.TableSection(
        category=category_meta(CategoryKey.PRIVATE_VULNERABILITY_REPORTING),
        columns=("Repository",),
        rows=[report.TableRow(repo=_repo(f"r{i}"), cells=()) for i in range(5)],
        pass_count=0,
        fail_count=5,
    )
    console = Console(record=True, width=200, no_color=True)
    terminal.render_org(org, console, top_n=2)
    out = console.export_text()
    assert "5 Not enabled" in out  # the count is the true total
    assert "(+3 more)" in out  # the inline name list is truncated to 2


def test_top_n_limits_generic_table_and_name_lists() -> None:
    # top_n must apply consistently: offender table, generic tables, and the
    # Disabled/Excluded name lists all honour the same limit with a tally.
    signals = [
        RepoSignal(_repo(f"nag{i}"), SignalType.CODEQL, RepoState.NAG) for i in range(5)
    ]
    org = _org(signals, count=10)
    org.excluded_repos = [_repo(f"ex{i}") for i in range(4)]
    org.releases = report.TableSection(
        category=category_meta(CategoryKey.RELEASES),
        columns=("Repository", "Last release", "Last tag"),
        rows=[
            report.TableRow(repo=_repo(f"r{i}"), cells=("never", "never"))
            for i in range(7)
        ],
        fail_count=7,
    )
    console = Console(record=True, width=200, no_color=True)
    terminal.render_org(org, console, top_n=2)
    out = console.export_text()
    # Totals remain the true count; the name lists are truncated with a tally.
    assert "5 Disabled" in out
    assert "(+3 more)" in out  # 5 disabled, 2 shown
    assert "4 Excluded" in out
    assert "(+2 more)" in out  # 4 excluded, 2 shown
    # The generic Releases table is limited to 2 rows + an "and N more" line.
    assert "… and 5 more" in out  # 7 rows, 2 shown


def test_generic_table_escapes_rich_markup_in_headers_and_cells() -> None:
    # Column names come from configuration and cells can carry arbitrary text
    # (a release tag, say). Rich reads '[' as markup, so an unescaped value
    # would raise MarkupError mid-render and take the whole report with it.
    org = _org([], count=1)
    org.releases = report.TableSection(
        category=category_meta(CategoryKey.RELEASES),
        columns=("Repository", "Bug [P1]", "Last tag"),
        rows=[report.TableRow(repo=_repo("r0"), cells=("[/]", "v1.0[rc]"))],
        fail_count=1,
    )
    console = Console(record=True, width=200, no_color=True)
    terminal.render_org(org, console, top_n=0)
    out = console.export_text()
    assert "Bug [P1]" in out
    assert "[/]" in out
    assert "v1.0[rc]" in out


def test_offender_table_has_totals_row() -> None:
    signals = [
        RepoSignal(
            _repo("a"),
            SignalType.CODEQL,
            RepoState.OFFENDER,
            SeverityCounts(critical=1, high=2, medium=3, low=4),
        ),
        RepoSignal(
            _repo("b"),
            SignalType.CODEQL,
            RepoState.OFFENDER,
            SeverityCounts(critical=1, high=1, medium=1, low=1),
        ),
    ]
    out = _render(_org(signals, count=2))
    # A trailing Total row sums each severity column plus the Total column.
    total_line = next(
        line for line in out.splitlines() if "Total" in line and "14" in line
    )
    # critical 2, high 3, medium 4, low 5, total 14.
    for value in ("2", "3", "4", "5", "14"):
        assert value in total_line


def test_scorecard_totals_row_omits_score() -> None:
    signals = [
        RepoSignal(
            _repo("a"),
            SignalType.SCORECARD,
            RepoState.OFFENDER,
            SeverityCounts(high=2, medium=1),
            score=6.5,
        ),
        RepoSignal(
            _repo("b"),
            SignalType.SCORECARD,
            RepoState.OFFENDER,
            SeverityCounts(high=1, low=1),
            score=6.8,
        ),
    ]
    out = _render(_org(signals, count=2))
    # "Total" now also heads the trailing per-row sum column, so pick the
    # totals *row* rather than the first line mentioning the word.
    total_line = next(
        line for line in out.splitlines() if line.lstrip("│ ").startswith("Total")
    )
    # high 3, medium 1, low 1 are summed; the score column is left blank.
    assert "3" in total_line
    # The row total sums the severity columns only (3 + 1 + 1).
    assert "5" in total_line
    # No summed score (the individual scores 6.5/6.8 do not add up to 13.3).
    assert "13.3" not in total_line


def test_secret_scanning_has_no_totals_row() -> None:
    signals = [
        RepoSignal(
            _repo("a"),
            SignalType.SECRET_SCANNING,
            RepoState.OFFENDER,
            SeverityCounts(high=1),
        ),
    ]
    out = _render(_org(signals, count=1))
    secret_block = out.split(SignalType.SECRET_SCANNING.heading, 1)[1]
    assert "Total" not in secret_block


def test_show_predicate_hides_disabled_categories() -> None:
    # A category whose visibility predicate returns False is omitted entirely,
    # including its heading -- the data is still present on the report object.
    sig = RepoSignal(
        _repo("bad"), SignalType.CODEQL, RepoState.OFFENDER, SeverityCounts(high=1)
    )
    org = _org([sig], count=1)
    org.mutable_releases = report.TableSection(
        category=category_meta(CategoryKey.MUTABLE_RELEASES),
        columns=("Repository", "Releases"),
        rows=[report.TableRow(repo=_repo("img"), cells=("v1 (latest)",))],
        fail_count=1,
    )
    console = Console(record=True, width=120, no_color=True)
    terminal.render_org(
        org,
        console,
        show=lambda key: key not in {CategoryKey.CODEQL, CategoryKey.MUTABLE_RELEASES},
    )
    out = console.export_text()
    assert "CodeQL" not in out
    assert "Mutable Releases" not in out
    # A category left enabled by the predicate still renders.
    assert "Secret Scanning" in out


# --------------------------------------------------------------------------- #
# Remediation rendering
# --------------------------------------------------------------------------- #
def _remediation(
    key: CategoryKey, outcomes: list[tuple[str, str, str]]
) -> remediate.CategoryRemediation:
    return remediate.CategoryRemediation(
        category=category_meta(key),
        outcomes=tuple(
            remediate.RepoOutcome(name, action, note) for name, action, note in outcomes
        ),
    )


def test_render_remediation_dry_run_previews_without_apply_banner() -> None:
    results = [
        _remediation(
            CategoryKey.CODEQL,
            [("a", "would enable", ""), ("b", "would enable", "")],
        ),
        _remediation(CategoryKey.SECRET_SCANNING, []),
    ]
    console = Console(record=True, width=120, no_color=True)
    terminal.render_remediation("lfreleng-actions", results, console, apply=False)
    out = console.export_text()
    assert "Remediation: lfreleng-actions" in out
    assert "DRY RUN" in out
    assert "2 would enable: a, b" in out
    assert "Nothing to remediate" in out
    assert "2 to enable (dry run)" in out
    assert "APPLYING CHANGES" not in out


def test_render_remediation_apply_reports_enabled_and_failures() -> None:
    results = [
        _remediation(
            CategoryKey.PRIVATE_VULNERABILITY_REPORTING,
            [
                ("ok1", "enabled", ""),
                ("ok2", "enabled", ""),
                ("bad", "FAILED", "403 Forbidden"),
            ],
        ),
    ]
    console = Console(record=True, width=120, no_color=True)
    terminal.render_remediation("o", results, console, apply=True)
    out = console.export_text()
    # Apply mode prints no pre-amble banner (the writes are already done).
    assert "APPLYING CHANGES" not in out
    assert "DRY RUN" not in out
    assert "2 enabled: ok1, ok2" in out
    assert "bad failed: 403 Forbidden" in out
    assert "Summary:" in out and "2 enabled, 1 failed" in out


def test_render_remediation_honours_top_n() -> None:
    results = [
        _remediation(
            CategoryKey.CODEQL,
            [(f"r{i}", "would enable", "") for i in range(5)],
        ),
    ]
    console = Console(record=True, width=200, no_color=True)
    terminal.render_remediation("o", results, console, apply=False, top_n=2)
    out = console.export_text()
    assert "5 would enable" in out  # the count is the true total
    assert "(+3 more)" in out  # the inline name list is truncated to 2


def test_render_remediation_escapes_bracketed_failure_notes() -> None:
    # A note such as "[Errno 8]" must render literally, not be swallowed by Rich
    # as markup (which would drop the bracketed span from the output).
    results = [
        _remediation(
            CategoryKey.CODEQL,
            [("bad", "FAILED", "422 [Errno 8] nodename nor servname")],
        ),
    ]
    console = Console(record=True, width=200, no_color=True)
    terminal.render_remediation("o", results, console, apply=True)
    out = console.export_text()
    assert "[Errno 8]" in out
    assert "bad failed: 422 [Errno 8] nodename nor servname" in out


def _auto_merge_org() -> report.OrgReport:
    """Two repositories with auto-merge on, five with it off."""
    org = _org([], count=7)
    org.auto_merge = report.TableSection(
        category=category_meta(CategoryKey.AUTO_MERGE),
        columns=("Repository",),
        rows=[report.TableRow(repo=_repo(n), cells=()) for n in "vwxyz"],
        pass_count=2,
        fail_count=5,
        pass_repos=(_repo("a"), _repo("b")),
    )
    return org


def test_auto_repo_list_names_the_shorter_side() -> None:
    out = _render(_auto_merge_org())
    assert "5 Not enabled" in out  # both sides are still counted
    assert "2 Enabled" in out
    assert "Enabled: a, b" in out
    assert "Not enabled: v" not in out


def test_repo_list_can_force_the_disabled_side() -> None:
    console = Console(record=True, width=120, no_color=True)
    terminal.render_org(
        _auto_merge_org(),
        console,
        footer=report.FooterOptions(repo_list=lambda _key: report.RepoList.DISABLED),
    )
    out = console.export_text()
    assert "Not enabled: v, w, x, y, z" in out
    assert "Enabled: a" not in out


def _excluded_org() -> report.OrgReport:
    """Two org-wide exclusions, and an Auto-merge table that excludes a third."""
    org = report.build_org_report(
        "lfreleng-actions",
        [],
        repo_count=7,
        generated_at=WHEN,
        excluded_repos=[_repo("fixture"), _repo("sandbox")],
    )
    org.auto_merge = _auto_merge_org().auto_merge
    org.category_excluded[CategoryKey.AUTO_MERGE] = [
        _repo("fixture"),
        _repo("sandbox"),
        _repo("internal-only"),
    ]
    return org


def _render_excluded(mode: report.ExcludedDisplay) -> str:
    console = Console(record=True, width=120, no_color=True)
    terminal.render_org(
        _excluded_org(), console, footer=report.FooterOptions(excluded=mode)
    )
    return console.export_text()


def test_always_show_repeats_the_excluded_line_under_every_category() -> None:
    out = _render_excluded(report.ExcludedDisplay.ALWAYS_SHOW)
    assert out.count("Excluded: fixture, sandbox") > 1


def test_always_hide_drops_every_excluded_line() -> None:
    out = _render_excluded(report.ExcludedDisplay.ALWAYS_HIDE)
    assert "Excluded" not in out


def test_conditional_hide_keeps_only_the_deviating_category() -> None:
    out = _render_excluded(report.ExcludedDisplay.CONDITIONAL_HIDE)
    assert out.count("Excluded:") == 1
    assert "Excluded: fixture, sandbox, internal-only" in out
    assert "3 Excluded" in out


def _cleanup(
    outcomes: list[tuple[str, str, str, str]],
) -> remediate.CategoryRemediation:
    return remediate.CategoryRemediation(
        category=category_meta(CategoryKey.CODEQL_STALE_CONFIGURATIONS),
        outcomes=tuple(
            remediate.RepoOutcome(name, action, note, verb)
            for name, action, note, verb in outcomes
        ),
    )


def test_render_remediation_groups_verbs_and_lists_refusals() -> None:
    # One category can delete one configuration and re-enable another's
    # workflow; each verb gets its own line, a refusal carries its reason, and
    # the summary totals by verb rather than calling a deletion "enabled".
    results = [
        _cleanup(
            [
                ("a (Default, python)", "deleted", "12 analyses deleted", "delete"),
                ("b (Advanced, python)", "re-enabled", "", "re-enable"),
                ("c (Default, actions)", "refused", "add scanning first", "delete"),
            ]
        )
    ]
    console = Console(record=True, width=120, no_color=True)
    terminal.render_remediation("o", results, console, apply=True)
    out = console.export_text()
    assert "1 deleted: a (Default, python)" in out
    assert "1 re-enabled: b (Advanced, python)" in out
    assert "c (Default, actions) refused: add scanning first" in out
    assert "Summary: 1 deleted, 1 re-enabled, 0 failed, 1 refused." in out


def test_render_remediation_dry_run_names_each_verb() -> None:
    results = [
        _cleanup(
            [
                ("a (Default, python)", "would delete", "", "delete"),
                ("b (Advanced, python)", "would re-enable", "", "re-enable"),
            ]
        )
    ]
    console = Console(record=True, width=120, no_color=True)
    terminal.render_remediation("o", results, console, apply=False)
    out = console.export_text()
    assert "1 would delete: a (Default, python)" in out
    assert "1 would re-enable: b (Advanced, python)" in out
    assert "1 to delete, 1 to re-enable (dry run)" in out
