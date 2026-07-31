# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Tests for the domain models, ranking, and severity counts."""

from __future__ import annotations

from github_security_report.models import (
    Repo,
    RepoSignal,
    RepoState,
    SeverityCounts,
    SignalType,
    rank_offenders,
)
from github_security_report.severity import Severity


def _repo(name: str) -> Repo:
    return Repo(
        name=name,
        full_name=f"lfreleng-actions/{name}",
        html_url=f"https://github.com/lfreleng-actions/{name}",
    )


def _offender(
    name: str,
    signal: SignalType,
    *,
    critical: int = 0,
    high: int = 0,
    medium: int = 0,
    low: int = 0,
    score: float | None = None,
) -> RepoSignal:
    return RepoSignal(
        repo=_repo(name),
        signal=signal,
        state=RepoState.OFFENDER,
        counts=SeverityCounts(critical=critical, high=high, medium=medium, low=low),
        score=score,
    )


class TestSeverityCounts:
    def test_total_and_weighted(self) -> None:
        c = SeverityCounts(critical=1, high=2, medium=3, low=4, informational=5)
        assert c.total == 15
        assert c.weighted == 10000 + 2000 + 300 + 40 + 5

    def test_add(self) -> None:
        c = SeverityCounts()
        c.add(Severity.CRITICAL)
        c.add(Severity.LOW, 5)
        c.add(Severity.INFORMATIONAL, 2)
        assert c.critical == 1
        assert c.low == 5
        assert c.informational == 2

    def test_at_or_above_cutoff(self) -> None:
        c = SeverityCounts(high=1, medium=2, low=3, informational=4)
        # Medium cutoff counts high + medium only (low/informational pass).
        assert c.at_or_above(Severity.MEDIUM) == 3
        # Low cutoff also counts the low findings, but not informational.
        assert c.at_or_above(Severity.LOW) == 6
        # Informational cutoff counts everything.
        assert c.at_or_above(Severity.INFORMATIONAL) == 10

    def test_one_critical_outranks_many_low(self) -> None:
        one_crit = SeverityCounts(critical=1)
        many_low = SeverityCounts(low=50)
        assert one_crit.sort_key > many_low.sort_key
        assert one_crit.weighted > many_low.weighted

    def test_by_rung_is_worst_first(self) -> None:
        c = SeverityCounts(critical=1, high=2, medium=3, low=4, informational=5)
        assert list(c.by_rung.items()) == [
            (Severity.CRITICAL, 1),
            (Severity.HIGH, 2),
            (Severity.MEDIUM, 3),
            (Severity.LOW, 4),
            (Severity.INFORMATIONAL, 5),
        ]


class TestSignalType:
    def test_secret_scanning_has_no_severity_columns(self) -> None:
        assert not SignalType.SECRET_SCANNING.uses_severity_columns
        assert SignalType.CODEQL.uses_severity_columns

    def test_only_scorecard_sorts_ascending(self) -> None:
        assert SignalType.SCORECARD.sort_ascending
        assert not SignalType.CODEQL.sort_ascending


class TestRankOffenders:
    def test_worst_first_by_severity_hierarchy(self) -> None:
        a = _offender("a", SignalType.CODEQL, high=10)  # many high
        b = _offender("b", SignalType.CODEQL, critical=1)  # one critical
        ranked = rank_offenders([a, b])
        assert [s.repo.name for s in ranked] == ["b", "a"]

    def test_ties_broken_by_name_ascending(self) -> None:
        a = _offender("zebra", SignalType.CODEQL, high=1)
        b = _offender("alpha", SignalType.CODEQL, high=1)
        ranked = rank_offenders([a, b])
        assert [s.repo.name for s in ranked] == ["alpha", "zebra"]

    def test_prefix_name_ties_sort_ascending(self) -> None:
        # Regression: a name that is a prefix of another must still sort first.
        a = _offender("aa", SignalType.CODEQL, high=1)
        b = _offender("a", SignalType.CODEQL, high=1)
        ranked = rank_offenders([a, b])
        assert [s.repo.name for s in ranked] == ["a", "aa"]

    def test_scorecard_sorts_by_score_ascending(self) -> None:
        good = _offender("good", SignalType.SCORECARD, score=8.5)
        bad = _offender("bad", SignalType.SCORECARD, score=4.1)
        ranked = rank_offenders([good, bad])
        assert [s.repo.name for s in ranked] == ["bad", "good"]

    def test_scorecard_leads_on_critical_then_score(self) -> None:
        # Regression: a critical finding must surface at the top even when the
        # repository carrying it has the healthiest score in the table.
        crit = _offender("crit", SignalType.SCORECARD, critical=1, score=7.5)
        many_crit = _offender("many", SignalType.SCORECARD, critical=6, score=9.1)
        weak = _offender("weak", SignalType.SCORECARD, high=3, score=6.3)
        weaker = _offender("weaker", SignalType.SCORECARD, high=3, score=6.1)
        ranked = rank_offenders([weak, crit, weaker, many_crit])
        assert [s.repo.name for s in ranked] == ["many", "crit", "weaker", "weak"]

    def test_scorecard_leading_rung_cascades_to_high(self) -> None:
        # No critical anywhere, so High leads and score breaks the tie.
        a = _offender("a", SignalType.SCORECARD, high=1, medium=9, score=4.0)
        b = _offender("b", SignalType.SCORECARD, high=3, score=8.0)
        c = _offender("c", SignalType.SCORECARD, high=3, score=7.0)
        ranked = rank_offenders([a, b, c])
        assert [s.repo.name for s in ranked] == ["c", "b", "a"]

    def test_scorecard_leading_rung_cascades_to_medium(self) -> None:
        a = _offender("a", SignalType.SCORECARD, medium=1, low=9, score=4.0)
        b = _offender("b", SignalType.SCORECARD, medium=2, score=8.0)
        ranked = rank_offenders([a, b])
        assert [s.repo.name for s in ranked] == ["b", "a"]

    def test_scorecard_leading_rung_cascades_to_low(self) -> None:
        a = _offender("a", SignalType.SCORECARD, low=1, score=4.0)
        b = _offender("b", SignalType.SCORECARD, low=2, score=8.0)
        ranked = rank_offenders([a, b])
        assert [s.repo.name for s in ranked] == ["b", "a"]

    def test_scorecard_without_findings_sorts_by_score_alone(self) -> None:
        # Informational never leads: it is the non-actionable rung.
        a = RepoSignal(
            _repo("a"),
            SignalType.SCORECARD,
            RepoState.OFFENDER,
            counts=SeverityCounts(informational=9),
            score=8.0,
        )
        b = RepoSignal(
            _repo("b"),
            SignalType.SCORECARD,
            RepoState.OFFENDER,
            counts=SeverityCounts(informational=1),
            score=4.0,
        )
        ranked = rank_offenders([a, b])
        assert [s.repo.name for s in ranked] == ["b", "a"]

    def test_scorecard_missing_score_sorts_last_within_rung(self) -> None:
        unknown = _offender("unknown", SignalType.SCORECARD, high=1)
        known = _offender("known", SignalType.SCORECARD, high=1, score=9.9)
        ranked = rank_offenders([unknown, known])
        assert [s.repo.name for s in ranked] == ["known", "unknown"]

    def test_scorecard_full_ties_broken_by_name(self) -> None:
        z = _offender("zebra", SignalType.SCORECARD, high=2, score=5.0)
        a = _offender("alpha", SignalType.SCORECARD, high=2, score=5.0)
        ranked = rank_offenders([z, a])
        assert [s.repo.name for s in ranked] == ["alpha", "zebra"]

    def test_excludes_non_offenders(self) -> None:
        offender = _offender("a", SignalType.CODEQL, high=1)
        clean = RepoSignal(_repo("b"), SignalType.CODEQL, RepoState.CLEAN)
        nag = RepoSignal(_repo("c"), SignalType.CODEQL, RepoState.NAG)
        ranked = rank_offenders([offender, clean, nag])
        assert [s.repo.name for s in ranked] == ["a"]

    def test_empty(self) -> None:
        assert rank_offenders([]) == []
