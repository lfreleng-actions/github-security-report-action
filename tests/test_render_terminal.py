# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Tests for Rich terminal rendering (rendered to a recording console)."""

from __future__ import annotations

import datetime as dt

from rich.console import Console

from github_security_report import report
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
            title="Enablement",
            columns=("Repository", "Dependabot alerts"),
            rows=[report.TableRow(repo=_repo("off"), cells=("❌ not enabled",))],
        )
    ]
    org.releases = report.TableSection(
        title="Releases / Tagging",
        columns=("Repository", "Last release", "Last tag"),
        rows=[report.TableRow(repo=_repo("stale"), cells=("never", "never"))],
    )
    out = _render(org)
    assert "Enablement" in out
    assert "off" in out
    assert "Releases / Tagging" in out
    assert "stale" in out


def test_excluded_repos_shown_under_each_section_with_count() -> None:
    signals = [RepoSignal(_repo("clean"), SignalType.CODEQL, RepoState.CLEAN)]
    org = _org(signals, count=5)
    org.excluded_repos = [_repo("opted-out")]
    out = _render(org)
    # Numerical total separated from the name breakdown.
    assert "1 Excluded" in out
    assert "Excluded: opted-out" in out


def test_table_note_split_one_sentence_per_line() -> None:
    org = _org([], count=1)
    org.releases = report.TableSection(
        title="Releases / Tagging",
        columns=("Repository", "Last release", "Last tag"),
        rows=[report.TableRow(repo=_repo("r"), cells=("never", "never"))],
        note="First sentence here. Second sentence here. Third one.",
    )
    out = _render(org)
    # Each sentence on its own line (no two sentences joined on one line).
    assert "First sentence here.\n" in out
    assert "Second sentence here." in out
    assert "Third one." in out


def test_disabled_total_and_names_on_separate_lines() -> None:
    signals = [RepoSignal(_repo("nagme"), SignalType.CODEQL, RepoState.NAG)]
    out = _render(_org(signals, count=1))
    assert "1 Disabled" in out  # total line
    assert "Disabled: nagme" in out  # names line
    assert "not enabled" not in out  # old lowercase label is gone


def test_top_n_limits_generic_table_and_name_lists() -> None:
    # top_n must apply consistently: offender table, generic tables, and the
    # Disabled/Excluded name lists all honour the same limit with a tally.
    signals = [
        RepoSignal(_repo(f"nag{i}"), SignalType.CODEQL, RepoState.NAG) for i in range(5)
    ]
    org = _org(signals, count=10)
    org.excluded_repos = [_repo(f"ex{i}") for i in range(4)]
    org.releases = report.TableSection(
        title="Releases / Tagging",
        columns=("Repository", "Last release", "Last tag"),
        rows=[
            report.TableRow(repo=_repo(f"r{i}"), cells=("never", "never"))
            for i in range(7)
        ],
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
