# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Tests for canonical Markdown rendering."""

from __future__ import annotations

import datetime as dt

from github_security_report import report
from github_security_report.models import (
    Repo,
    RepoSignal,
    RepoState,
    SeverityCounts,
    SignalType,
)
from github_security_report.render import markdown

WHEN = dt.datetime(2026, 6, 16, 9, 0, tzinfo=dt.timezone.utc)


def _repo(name: str) -> Repo:
    return Repo(name, f"o/{name}", f"https://github.com/o/{name}")


def _org(signals: list[RepoSignal], count: int = 1) -> report.OrgReport:
    return report.build_org_report(
        "lfreleng-actions", signals, repo_count=count, generated_at=WHEN
    )


class TestSection:
    def test_offender_table_codeql(self) -> None:
        sig = RepoSignal(
            _repo("bad"),
            SignalType.CODEQL,
            RepoState.OFFENDER,
            SeverityCounts(critical=1, high=2),
        )
        out = markdown.render_section(_org([sig]).sections[0])
        assert "## CodeQL" in out
        assert "| Repository | Critical | High | Medium | Low | Total |" in out
        assert "[bad](https://github.com/o/bad)" in out
        assert "| 1 | 2 | 0 | 0 | 3 |" in out

    def test_secret_scanning_single_count_column(self) -> None:
        sig = RepoSignal(
            _repo("leaky"),
            SignalType.SECRET_SCANNING,
            RepoState.OFFENDER,
            SeverityCounts(critical=4),
        )
        section = next(
            s for s in _org([sig]).sections if s.signal is SignalType.SECRET_SCANNING
        )
        out = markdown.render_section(section)
        assert "| Repository | Open |" in out
        assert "| [leaky](https://github.com/o/leaky) | 4 |" in out

    def test_scorecard_has_score_column(self) -> None:
        sig = RepoSignal(
            _repo("repo"),
            SignalType.SCORECARD,
            RepoState.OFFENDER,
            SeverityCounts(high=1),
            score=6.5,
        )
        section = next(
            s for s in _org([sig]).sections if s.signal is SignalType.SCORECARD
        )
        out = markdown.render_section(section)
        assert "| Repository | Score | Critical | High | Medium | Low |" in out
        assert "| 6.5 | 0 | 1 | 0 | 0 |" in out

    def test_clean_count_and_nag_and_unknown(self) -> None:
        signals = [
            RepoSignal(_repo("clean"), SignalType.CODEQL, RepoState.CLEAN),
            RepoSignal(_repo("nagme"), SignalType.CODEQL, RepoState.NAG),
            RepoSignal(_repo("dunno"), SignalType.CODEQL, RepoState.UNKNOWN),
        ]
        out = markdown.render_section(_org(signals, count=3).sections[0])
        assert "✅ 1 repositories clean" in out
        assert "**Not enabled**" in out
        assert "- [nagme](https://github.com/o/nagme)" in out
        assert "unknown status" in out

    def test_empty_section(self) -> None:
        out = markdown.render_section(_org([]).sections[0])
        assert "_No data available._" in out


class TestOrgAndReport:
    def test_org_header(self) -> None:
        out = markdown.render_org(_org([], count=5))
        assert "# Security report: lfreleng-actions" in out
        assert "5 repositories analysed" in out
        assert "2026-06-16 09:00 UTC" in out

    def test_full_report_multi_org(self) -> None:
        r = report.Report(
            orgs=[_org([], count=1), _org([], count=2)], generated_at=WHEN
        )
        out = markdown.render_report(r)
        assert out.count("# Security report: lfreleng-actions") == 2
