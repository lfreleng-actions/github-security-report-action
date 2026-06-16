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
    assert "1 clean" in out
    assert "not enabled" in out
    assert "nagme" in out
    assert "unknown" in out


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
