# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Tests for the domain models and severity counts."""

from __future__ import annotations

from github_security_report.models import (
    Repo,
    RepoSignal,
    RepoState,
    SeverityCounts,
    SignalType,
)
from github_security_report.severity import RUNGS_WORST_FIRST, Severity


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

    def test_at_returns_the_single_rung_count(self) -> None:
        c = SeverityCounts(critical=1, high=2, medium=3, low=4, informational=5)
        assert [c.at(rung) for rung in RUNGS_WORST_FIRST] == [1, 2, 3, 4, 5]


class TestSignalType:
    def test_secret_scanning_has_no_severity_columns(self) -> None:
        assert not SignalType.SECRET_SCANNING.uses_severity_columns
        assert SignalType.CODEQL.uses_severity_columns

    def test_only_scorecard_sorts_ascending(self) -> None:
        assert SignalType.SCORECARD.sort_ascending
        assert not SignalType.CODEQL.sort_ascending
