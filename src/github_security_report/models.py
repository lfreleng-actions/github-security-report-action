# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Domain models for the security report.

Encodes the Phase 0 design (see ``docs/BRIEF.md`` and
``docs/phase0-findings.md``): the six ranked signals, the four-state per-report
classification, severity counts with hierarchical worst-first ordering, and the
ranking rules (alert tables sort by severity descending; Scorecard by its worst
populated severity rung descending, then by score ascending).
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from enum import Enum

from github_security_report.categories import CategoryKey, CategoryMeta, category_meta
from github_security_report.severity import RUNGS_WORST_FIRST, Severity


class SignalType(str, Enum):
    """The six ranked signals."""

    CODEQL = "codeql"
    SCORECARD = "scorecard"
    ZIZMOR = "zizmor"
    AISLOP = "aislop"
    DEPENDABOT = "dependabot"
    SECRET_SCANNING = "secret_scanning"

    @property
    def category_key(self) -> CategoryKey:
        """The metadata-registry key for this signal's report category."""
        return {
            SignalType.CODEQL: CategoryKey.CODEQL,
            SignalType.SCORECARD: CategoryKey.SCORECARD,
            SignalType.ZIZMOR: CategoryKey.ZIZMOR,
            SignalType.AISLOP: CategoryKey.AISLOP,
            SignalType.DEPENDABOT: CategoryKey.DEPENDABOT_ALERTS,
            SignalType.SECRET_SCANNING: CategoryKey.SECRET_SCANNING,
        }[self]

    @property
    def meta(self) -> CategoryMeta:
        """Display/documentation metadata for this signal's category."""
        return category_meta(self.category_key)

    @property
    def fail_severity(self) -> Severity:
        """Default cutoff at/above which a finding marks this signal failing."""
        return self.meta.fail_severity

    @property
    def heading(self) -> str:
        return self.meta.title

    @property
    def uses_severity_columns(self) -> bool:
        """Secret scanning is a flat open-count; the rest use severity columns.

        Scorecard's primary metric is its aggregate score, but its
        code-scanning findings still carry severities, so it keeps the columns.
        """
        return self is not SignalType.SECRET_SCANNING

    @property
    def sort_ascending(self) -> bool:
        """Whether lower is worse for this signal's primary metric.

        True only for Scorecard, whose aggregate score runs the opposite way to
        a finding count (lower == weaker). The score is Scorecard's *secondary*
        key: ``rank_offenders`` leads on the worst severity rung present in the
        table and uses the score to order repositories within that rung.
        """
        return self is SignalType.SCORECARD


# The code-scanning ``tool.name`` for every signal derived from the shared
# code-scanning alert feed. The single authority for those names: the client's
# per-repo enabled-probes, the classifiers and the feature gating all read this
# mapping, so adding a SARIF-uploading tool is one entry here plus its
# classifier. Signals absent from this mapping (Dependabot, secret scanning)
# have their own APIs.
CODE_SCANNING_TOOLS: dict[SignalType, str] = {
    SignalType.CODEQL: "CodeQL",
    SignalType.SCORECARD: "Scorecard",
    SignalType.ZIZMOR: "zizmor",
    SignalType.AISLOP: "aislop",
}


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


@dataclass(frozen=True)
class ReleaseRef:
    """A single release's identity and immutability, for the release checks.

    ``published_at`` falls back to the release's creation time when GitHub does
    not supply a publish timestamp. ``is_latest`` marks the release carrying
    GitHub's "Latest" badge; ``is_prerelease`` distinguishes a pre-release.
    ``immutable`` is ``None`` when GitHub does not report an immutability state
    (the GraphQL field is nullable), distinct from a confirmed mutable (False).
    """

    tag: str
    immutable: bool | None
    published_at: dt.datetime | None = None
    is_latest: bool = False
    is_prerelease: bool = False


@dataclass(frozen=True)
class IssueRef:
    """One open issue's triage-relevant facts.

    Carries only what the open-issues reporting needs: the label set, so issues
    can be classified into buckets (bug, enhancement, and so on), and the
    creation time, so the oldest outstanding issue and its age can be reported.
    ``created_at`` is ``None`` when GitHub supplied no usable timestamp, in
    which case the issue cannot contribute to the oldest-issue age.
    """

    number: int
    title: str
    labels: tuple[str, ...] = ()
    created_at: dt.datetime | None = None


@dataclass
class RepoGraphData:
    """Per-repository data fetched in the batched GraphQL prefetch.

    One aliased GraphQL query gathers these for many repositories at once,
    folding the former per-repo Dependabot-enabled, latest-release, latest-tag
    and ``dependabot.yml`` round-trips into a single request. Defaults model the
    degraded case (an unreadable repository or a failed query), so affected
    repositories drop out of the dependent tables rather than being mislabelled.

    ``open_issues`` and ``issues`` deliberately disagree on a large backlog:
    ``open_issues`` is the authoritative total, whereas ``issues`` is a bounded
    window capped by the query's page size. A caller classifying labels or
    summing per-label counts therefore sees at most the window, never more than
    ``open_issues``, and should present its own totals as covering the window
    rather than the whole backlog. The window is ordered oldest-first, so the
    oldest issue -- the one the age check reports -- is always present even when
    the window truncates.
    """

    dependabot_alerts_enabled: bool | None = None
    latest_tag_at: dt.datetime | None = None
    # Publish time of the "Latest" release, for release/tag staleness.
    latest_release_at: dt.datetime | None = None
    # The "Latest" release and the most-recent published release (which may be a
    # newer pre-release), for the immutability check. None when absent.
    latest_release: ReleaseRef | None = None
    last_published_release: ReleaseRef | None = None
    # Raw ``.github/dependabot.yml`` text, or None when the file is absent.
    dependabot_config: str | None = None
    # Total open issues (authoritative count from GraphQL ``totalCount``).
    open_issues: int = 0
    # A bounded, oldest-first window of those issues, for label classification
    # and the oldest-issue age. May be shorter than ``open_issues`` on a
    # repository with a very large backlog.
    issues: tuple[IssueRef, ...] = ()


@dataclass
class SeverityCounts:
    """Open-finding counts by severity, with worst-first ordering."""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    informational: int = 0

    def add(self, severity: Severity, count: int = 1) -> None:
        if severity is Severity.CRITICAL:
            self.critical += count
        elif severity is Severity.HIGH:
            self.high += count
        elif severity is Severity.MEDIUM:
            self.medium += count
        elif severity is Severity.LOW:
            self.low += count
        else:
            self.informational += count

    @property
    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low + self.informational

    def at(self, rung: Severity) -> int:
        """The count at exactly one severity rung.

        Attribute access rather than a ``by_rung`` lookup, so the ranking hot
        path does not build a dict per comparison.
        """
        if rung is Severity.CRITICAL:
            return self.critical
        if rung is Severity.HIGH:
            return self.high
        if rung is Severity.MEDIUM:
            return self.medium
        if rung is Severity.LOW:
            return self.low
        return self.informational

    def at_or_above(self, cutoff: Severity) -> int:
        """Count of findings whose severity is at least ``cutoff``.

        The basis for the per-category pass/fail decision: a repository fails a
        category only when it carries at least one finding at or above that
        category's ``fail_severity`` cutoff. Findings below the cutoff (e.g.
        informational-only) do not count towards a failure.
        """
        return sum(count for rung, count in self.by_rung.items() if rung >= cutoff)

    @property
    def by_rung(self) -> dict[Severity, int]:
        """Per-severity counts keyed by rung, in worst-first iteration order."""
        return {rung: self.at(rung) for rung in RUNGS_WORST_FIRST}

    @property
    def weighted(self) -> int:
        """Severity-weighted score, so 1 critical outranks many low findings."""
        return (
            self.critical * 10000
            + self.high * 1000
            + self.medium * 100
            + self.low * 10
            + self.informational
        )

    @property
    def sort_key(self) -> tuple[int, int, int, int, int]:
        """Hierarchical key: critical, high, medium, low, then informational.

        Use with ``reverse=True`` for worst-first ordering.
        """
        return (
            self.critical,
            self.high,
            self.medium,
            self.low,
            self.informational,
        )


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


# The rungs eligible to lead the Scorecard ordering, worst-first.
# ``INFORMATIONAL`` is deliberately absent: it is the non-actionable rung, so it
# never displaces the score as the primary key.
LEAD_RUNGS: tuple[Severity, ...] = tuple(
    rung for rung in RUNGS_WORST_FIRST if rung is not Severity.INFORMATIONAL
)


def lead_rung(offenders: list[RepoSignal]) -> Severity | None:
    """The worst severity rung any offender actually carries.

    Returns ``None`` when no offender carries a finding at Low or above, in
    which case there is no severity tier worth leading on.
    """
    return next(
        (rung for rung in LEAD_RUNGS if any(s.counts.at(rung) for s in offenders)),
        None,
    )


def rank_offenders(signals: list[RepoSignal]) -> list[RepoSignal]:
    """Sort offenders worst-first for a single signal.

    Alert-based signals sort by the hierarchical severity key descending, with
    total as a tiebreaker.

    Scorecard sorts on two tiers: the count at the worst severity rung present
    anywhere in the table (descending), then the aggregate score (ascending,
    lower == worse). The leading rung cascades -- Critical, else High, else
    Medium, else Low -- so the rung that actually discriminates between
    repositories leads, and a lone Critical can never be buried mid-table by a
    weaker repository with a lower score. When no offender carries a finding at
    Low or above, the score alone orders the table.

    Repo name breaks remaining ties, ascending.

    Numeric components are negated so the whole sort runs ascending (no
    ``reverse=True``); that keeps the name tiebreaker correctly ascending even
    when one name is a prefix of another.
    """
    offenders = [s for s in signals if s.is_offender]
    if not offenders:
        return []
    signal = offenders[0].signal
    if signal.sort_ascending:
        rung = lead_rung(offenders)
        return sorted(
            offenders,
            key=lambda s: (
                -s.counts.at(rung) if rung is not None else 0,
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
