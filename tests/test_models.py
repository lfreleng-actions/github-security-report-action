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


def _offender(name: str, signal: SignalType, **kwargs: object) -> RepoSignal:
    counts = SeverityCounts(
        **{
            k: v
            for k, v in kwargs.items()
            if k in {"critical", "high", "medium", "low"}
        }
    )
    return RepoSignal(
        repo=_repo(name),
        signal=signal,
        state=RepoState.OFFENDER,
        counts=counts,
        score=kwargs.get("score"),  # type: ignore[arg-type]
    )


class TestSeverityCounts:
    def test_total_and_weighted(self) -> None:
        c = SeverityCounts(critical=1, high=2, medium=3, low=4)
        assert c.total == 10
        assert c.weighted == 1000 + 200 + 30 + 4

    def test_add(self) -> None:
        c = SeverityCounts()
        c.add(Severity.CRITICAL)
        c.add(Severity.LOW, 5)
        assert c.critical == 1
        assert c.low == 5

    def test_one_critical_outranks_many_low(self) -> None:
        one_crit = SeverityCounts(critical=1)
        many_low = SeverityCounts(low=50)
        assert one_crit.sort_key > many_low.sort_key
        assert one_crit.weighted > many_low.weighted


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

    def test_excludes_non_offenders(self) -> None:
        offender = _offender("a", SignalType.CODEQL, high=1)
        clean = RepoSignal(_repo("b"), SignalType.CODEQL, RepoState.CLEAN)
        nag = RepoSignal(_repo("c"), SignalType.CODEQL, RepoState.NAG)
        ranked = rank_offenders([offender, clean, nag])
        assert [s.repo.name for s in ranked] == ["a"]

    def test_empty(self) -> None:
        assert rank_offenders([]) == []
