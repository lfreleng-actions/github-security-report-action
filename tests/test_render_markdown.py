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

    def test_top_n_limits_offender_rows(self) -> None:
        signals = [
            RepoSignal(
                _repo(f"r{i}"),
                SignalType.CODEQL,
                RepoState.OFFENDER,
                SeverityCounts(high=i),
            )
            for i in range(1, 6)
        ]
        section = _org(signals, count=5).sections[0]
        out = markdown.render_section(section, top_n=2)
        # Two data rows under the header + separator.
        body_rows = [ln for ln in out.splitlines() if ln.startswith("| [r")]
        assert len(body_rows) == 2

    def test_offender_table_has_totals_row(self) -> None:
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
        out = markdown.render_section(_org(signals, count=2).sections[0])
        # A trailing Total row sums each severity column plus the Total column.
        assert "| Total | 2 | 3 | 4 | 5 | 14 |" in out

    def test_scorecard_totals_row_blanks_score(self) -> None:
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
        section = next(
            s
            for s in _org(signals, count=2).sections
            if s.signal is SignalType.SCORECARD
        )
        out = markdown.render_section(section)
        # The score column is blank; the severity columns are summed.
        assert "| Total |  | 0 | 3 | 1 | 1 |" in out

    def test_secret_scanning_has_no_totals_row(self) -> None:
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
        assert "| Total |" not in out


class TestOrgAndReport:
    def test_org_header(self) -> None:
        out = markdown.render_org(_org([], count=5))
        assert "# Security report: lfreleng-actions" in out
        assert "5 repositories analysed" in out
        assert "2026-06-16 09:00 UTC" in out
        assert "Incomplete" not in out  # complete report carries no banner

    def test_partial_report_shows_incomplete_banner(self) -> None:
        org = report.build_org_report(
            "lfreleng-actions", [], repo_count=1, generated_at=WHEN, partial=True
        )
        out = markdown.render_org(org)
        assert "Incomplete" in out

    def test_full_report_multi_org(self) -> None:
        r = report.Report(
            orgs=[_org([], count=1), _org([], count=2)], generated_at=WHEN
        )
        out = markdown.render_report(r)
        assert out.count("# Security report: lfreleng-actions") == 2


class TestExtraTables:
    def _table(self) -> report.TableSection:
        return report.TableSection(
            title="Update Cooldown",
            columns=("Repository", "Ecosystems without cooldown"),
            rows=[report.TableRow(repo=_repo("a"), cells=("pip, npm",))],
            note="A cooldown is mandatory.",
        )

    def test_render_table_section_renders_rows_and_note(self) -> None:
        out = markdown.render_table_section(self._table(), level=3)
        assert out.startswith("### Update Cooldown")
        assert "| Repository | Ecosystems without cooldown |" in out
        assert "| [a](https://github.com/o/a) | pip, npm |" in out
        assert "_A cooldown is mandatory._" in out

    def test_render_table_section_empty_note(self) -> None:
        empty = report.TableSection(
            title="Enablement",
            columns=("Repository", "Dependabot alerts"),
            rows=[],
            empty_note="All enabled.",
        )
        out = markdown.render_table_section(empty, level=3)
        assert "✅ All enabled." in out

    def test_org_nests_dependabot_tables_and_releases(self) -> None:
        org = _org([], count=2)
        org.dependabot_tables = [self._table()]
        org.releases = report.TableSection(
            title="Releases / Tagging",
            columns=("Repository", "Last release", "Last tag"),
            rows=[report.TableRow(repo=_repo("z"), cells=("never", "never"))],
        )
        out = markdown.render_org(org)
        # Dependabot sub-table nested under (after) the Dependabot signal heading.
        assert out.index("## Dependabot: Security Alerts") < out.index(
            "### Update Cooldown"
        )
        # Releases section rendered at the top level after all signals.
        assert "## Releases / Tagging" in out
        assert "| [z](https://github.com/o/z) | never | never |" in out

    def test_org_renders_mutable_releases_with_summary(self) -> None:
        org = _org([], count=84)
        org.mutable_releases = report.TableSection(
            title="Mutable Releases",
            columns=("Repository", "Releases"),
            rows=[report.TableRow(repo=_repo("img"), cells=("v0.1.0 (latest)",))],
            note="Recent releases in the repositories above are not immutable.",
            summary="2 with findings, 82 clean",
        )
        out = markdown.render_org(org)
        # The heading is bare; the count summary is rendered beneath the table.
        assert "## Mutable Releases\n" in out
        assert "## Mutable Releases —" not in out
        assert "\n2 with findings, 82 clean\n" in out
        assert "| [img](https://github.com/o/img) | v0.1.0 (latest) |" in out
        assert "_Recent releases in the repositories above are not immutable._" in out

    def test_org_shows_excluded_repos(self) -> None:
        org = _org([], count=2)
        org.excluded_repos = [_repo("opted-out")]
        out = markdown.render_org(org)
        assert "Excluded from analysis (1)" in out
        assert "`opted-out`" in out
