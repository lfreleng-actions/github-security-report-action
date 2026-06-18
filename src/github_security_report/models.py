# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Domain models for the security report.

Encodes the Phase 0 design (see ``docs/BRIEF.md`` and
``docs/phase0-findings.md``): the five v1 signals, the four-state per-report
classification, severity counts with hierarchical worst-first ordering, and the
ranking rules (alert tables sort by severity descending; Scorecard by score
ascending).
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from enum import Enum

from github_security_report.severity import Severity


class SignalType(str, Enum):
    """The five v1 ranked signals."""

    CODEQL = "codeql"
    SCORECARD = "scorecard"
    ZIZMOR = "zizmor"
    DEPENDABOT = "dependabot"
    SECRET_SCANNING = "secret_scanning"

    @property
    def heading(self) -> str:
        return {
            SignalType.CODEQL: "CodeQL",
            SignalType.SCORECARD: "OpenSSF Scorecard",
            SignalType.ZIZMOR: "Zizmor Static Analysis",
            SignalType.DEPENDABOT: "Dependabot: Security Alerts",
            SignalType.SECRET_SCANNING: "Secret scanning",
        }[self]

    @property
    def uses_severity_columns(self) -> bool:
        """Secret scanning is a flat open-count; the rest use severity columns.

        Scorecard's primary metric is its aggregate score, but its
        code-scanning findings still carry severities, so it keeps the columns.
        """
        return self is not SignalType.SECRET_SCANNING

    @property
    def sort_ascending(self) -> bool:
        """Scorecard ranks by score ascending (lower == worse); others descend."""
        return self is SignalType.SCORECARD


class RepoState(str, Enum):
    """The four-state per-report classification (BRIEF section 6)."""

    OFFENDER = "offender"  # enabled + has open findings -> table row
    CLEAN = "clean"  # enabled + zero findings -> counted beneath table
    NAG = "nag"  # supported but not enabled -> bulleted nag list
    UNKNOWN = "unknown"  # indeterminate (403 / insufficient permission)


@dataclass(frozen=True)
class Repo:
    """Minimal repository identity carried through the report."""

    name: str
    full_name: str
    html_url: str
    archived: bool = False
    fork: bool = False
    is_template: bool = False
    private: bool = False
    default_branch: str = "main"
    # Repository creation time (UTC); used to exclude freshly-created repos from
    # the release/tag age requirement. None when the API did not provide it.
    created_at: dt.datetime | None = None


@dataclass
class SeverityCounts:
    """Open-finding counts by severity, with worst-first ordering."""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0

    def add(self, severity: Severity, count: int = 1) -> None:
        if severity is Severity.CRITICAL:
            self.critical += count
        elif severity is Severity.HIGH:
            self.high += count
        elif severity is Severity.MEDIUM:
            self.medium += count
        else:
            self.low += count

    @property
    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low

    @property
    def weighted(self) -> int:
        """Severity-weighted score, so 1 critical outranks many low findings."""
        return (
            self.critical * 1000
            + self.high * 100
            + self.medium * 10
            + self.low
        )

    @property
    def sort_key(self) -> tuple[int, int, int, int]:
        """Hierarchical key: critical, then high, then medium, then low.

        Use with ``reverse=True`` for worst-first ordering.
        """
        return (self.critical, self.high, self.medium, self.low)


@dataclass
class RepoSignal:
    """One repository's result for one signal."""

    repo: Repo
    signal: SignalType
    state: RepoState
    counts: SeverityCounts = field(default_factory=SeverityCounts)
    score: float | None = None  # Scorecard aggregate (0-10), lower == worse
    detail: str = ""  # short human note (e.g. "secret scanning disabled")

    @property
    def is_offender(self) -> bool:
        return self.state is RepoState.OFFENDER


def rank_offenders(signals: list[RepoSignal]) -> list[RepoSignal]:
    """Sort offenders worst-first for a single signal.

    Alert-based signals sort by the hierarchical severity key descending, with
    total as a tiebreaker. Scorecard sorts by aggregate score ascending (lower
    == worse). Repo name breaks remaining ties, ascending.

    Numeric components are negated so the whole sort runs ascending (no
    ``reverse=True``); that keeps the name tiebreaker correctly ascending even
    when one name is a prefix of another.
    """
    offenders = [s for s in signals if s.is_offender]
    if not offenders:
        return []
    signal = offenders[0].signal
    if signal.sort_ascending:
        return sorted(
            offenders,
            key=lambda s: (
                s.score if s.score is not None else float("inf"),
                s.repo.name,
            ),
        )
    return sorted(
        offenders,
        key=lambda s: (
            -s.counts.critical,
            -s.counts.high,
            -s.counts.medium,
            -s.counts.low,
            -s.counts.total,
            s.repo.name,
        ),
    )
