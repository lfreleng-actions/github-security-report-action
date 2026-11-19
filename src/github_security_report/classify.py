# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Classification: raw API facts -> four-state RepoSignal results.

Pure, transport-free logic encoding every Phase 0 finding
(``docs/phase0-findings.md``):

- the single code-scanning feed is partitioned by ``tool.name`` into CodeQL,
  Scorecard, zizmor and aislop -- counts are filtered per tool;
- CodeQL/Scorecard/zizmor/aislop enablement is the presence of that tool in
  ``code-scanning/analyses`` (not ``default-setup``); a 404 on code scanning
  means it is disabled entirely;
- secret scanning 404 = disabled, 200 [] = enabled-clean;
- Dependabot ``hasVulnerabilityAlertsEnabled == false`` = disabled;
- Scorecard prefers the external aggregate score, else code-scanning findings;
- 403 / indeterminate -> the unknown bucket, never clean or nag;
- an alert read that failed (even part-way, keeping the alerts it had
  collected) is unknown unless an alert in hand already fails the cutoff:
  the pages never read could hold the failing alerts.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Set
from dataclasses import dataclass, field

from github_security_report import severity
from github_security_report.models import (
    CODE_SCANNING_TOOLS,
    Repo,
    RepoSignal,
    RepoState,
    SeverityCounts,
    SignalType,
)
from github_security_report.severity import Severity

# A resolved per-signal fail-severity cutoff. When a signal is absent the
# classifier falls back to the signal's own default (its category metadata).
FailSeverities = Mapping[SignalType, Severity]


def _cutoff(signal: SignalType, fail_severities: FailSeverities | None) -> Severity:
    """The fail-severity cutoff for ``signal`` (config override or default)."""
    if fail_severities is not None and signal in fail_severities:
        return fail_severities[signal]
    return signal.fail_severity


def _alert_signal(
    repo: Repo,
    signal: SignalType,
    counts: SeverityCounts,
    alerts_status: int,
    cutoff: Severity,
) -> RepoSignal:
    """State of an enabled signal from the alerts collected and their read.

    Any alert at or above ``cutoff`` makes an offender even when the read was
    incomplete, since positive evidence is actionable. Otherwise a read status
    other than 200 is unknown, as the pages never read could hold failing
    alerts; only a complete read with nothing failing is clean. An unknown
    result keeps the collected counts as a lower bound.
    """
    if counts.at_or_above(cutoff):
        return RepoSignal(repo, signal, RepoState.OFFENDER, counts=counts)
    if alerts_status != 200:
        detail = "alert data incomplete" if counts.total else "alert data unavailable"
        return RepoSignal(repo, signal, RepoState.UNKNOWN, counts=counts, detail=detail)
    return RepoSignal(repo, signal, RepoState.CLEAN, counts=counts)


@dataclass
class RepoFacts:
    """Raw per-repository facts gathered by the client, pre-classification."""

    repo: Repo
    # Code scanning (covers CodeQL, Scorecard, zizmor, aislop).
    code_scanning_status: int = 200  # 200 ok, 404 disabled, 403 forbidden
    code_scanning_tools: set[str] = field(default_factory=set)  # analyses tool names
    code_scanning_alerts: list[dict] = field(default_factory=list)  # all tools
    code_scanning_alerts_status: int = 200  # status of the alert read (200 ok)
    # Secret scanning.
    secret_scanning_status: int = 200  # 200 enabled, 404 disabled, 403 forbidden
    secret_scanning_open: int = 0
    secret_scanning_open_status: int = 200  # status of the open-count read
    # Dependabot.
    dependabot_enabled: bool | None = None  # None = indeterminate
    dependabot_alerts: list[dict] = field(default_factory=list)
    dependabot_alerts_status: int = 200  # status of the alert read
    # Scorecard (external API).
    scorecard_status: int = 404  # 200 has score, 404 none, 403 forbidden
    scorecard_score: float | None = None
    # Signals (by value) enforced for this repo via an org/branch ruleset
    # (e.g. zizmor required by a central workflow), even with no per-repo file.
    ruleset_signals: set[str] = field(default_factory=set)


# --------------------------------------------------------------------------- #
# Counting helpers
# --------------------------------------------------------------------------- #
def count_code_scanning(alerts: list[dict], tool_name: str) -> SeverityCounts:
    """Sum open code-scanning alerts for a single tool, by severity."""
    counts = SeverityCounts()
    for alert in alerts:
        if (alert.get("tool") or {}).get("name") != tool_name:
            continue
        rule = alert.get("rule") or {}
        sev = severity.from_code_scanning(
            rule.get("security_severity_level"), rule.get("severity")
        )
        counts.add(sev)
    return counts


def count_dependabot(alerts: list[dict]) -> SeverityCounts:
    """Sum open Dependabot alerts by advisory severity."""
    counts = SeverityCounts()
    for alert in alerts:
        advisory = alert.get("security_advisory") or {}
        vuln = alert.get("security_vulnerability") or {}
        sev = severity.from_name(advisory.get("severity") or vuln.get("severity"))
        counts.add(sev or severity.Severity.LOW)
    return counts


# --------------------------------------------------------------------------- #
# Per-signal classification
# --------------------------------------------------------------------------- #
def _code_scanning_tool_signal(
    facts: RepoFacts,
    signal: SignalType,
    tool_name: str,
    fail_severities: FailSeverities | None = None,
) -> RepoSignal:
    """Shared four-state logic for the code-scanning-derived signals.

    A tool is enabled when its analyses are present, OR when an org/branch
    ruleset enforces it for this repo (a central required workflow) -- the
    latter prevents falsely nagging repos whose tool runs from a ruleset.
    """
    repo = facts.repo
    covered = signal.value in facts.ruleset_signals
    # An indeterminate code-scanning probe (403 forbidden, a 5xx, or a synthetic
    # 0 from a transport failure) is unknown, not a nag -- unless a ruleset
    # already proves the tool is enabled for this repo.
    if not covered and facts.code_scanning_status not in (200, 404):
        detail = (
            "insufficient permission"
            if facts.code_scanning_status == 403
            else "indeterminate"
        )
        return RepoSignal(repo, signal, RepoState.UNKNOWN, detail=detail)
    enabled = covered or (
        facts.code_scanning_status == 200 and tool_name in facts.code_scanning_tools
    )
    if not enabled:
        detail = (
            "code scanning disabled"
            if facts.code_scanning_status == 404
            else f"{tool_name} not enabled"
        )
        return RepoSignal(repo, signal, RepoState.NAG, detail=detail)
    # Only findings at or above the category's fail-severity cutoff make the
    # repo an offender; sub-threshold findings (e.g. informational) fold into
    # the clean count when the alert read was complete. An unreadable or
    # partial sweep (e.g. an org-bulk 403/5xx) must not masquerade as clean.
    return _alert_signal(
        repo,
        signal,
        count_code_scanning(facts.code_scanning_alerts, tool_name),
        facts.code_scanning_alerts_status,
        _cutoff(signal, fail_severities),
    )


def classify_codeql(
    facts: RepoFacts, fail_severities: FailSeverities | None = None
) -> RepoSignal:
    return _code_scanning_tool_signal(
        facts,
        SignalType.CODEQL,
        CODE_SCANNING_TOOLS[SignalType.CODEQL],
        fail_severities,
    )


def classify_zizmor(
    facts: RepoFacts, fail_severities: FailSeverities | None = None
) -> RepoSignal:
    return _code_scanning_tool_signal(
        facts,
        SignalType.ZIZMOR,
        CODE_SCANNING_TOOLS[SignalType.ZIZMOR],
        fail_severities,
    )


def classify_aislop(
    facts: RepoFacts, fail_severities: FailSeverities | None = None
) -> RepoSignal:
    return _code_scanning_tool_signal(
        facts,
        SignalType.AISLOP,
        CODE_SCANNING_TOOLS[SignalType.AISLOP],
        fail_severities,
    )


def classify_scorecard(
    facts: RepoFacts, fail_severities: FailSeverities | None = None
) -> RepoSignal:
    """Scorecard: prefer the external aggregate score, else code-scanning findings."""
    repo = facts.repo
    counts = count_code_scanning(
        facts.code_scanning_alerts, CODE_SCANNING_TOOLS[SignalType.SCORECARD]
    )
    has_cs = (
        CODE_SCANNING_TOOLS[SignalType.SCORECARD] in facts.code_scanning_tools
        and facts.code_scanning_status == 200
    )
    cutoff = _cutoff(SignalType.SCORECARD, fail_severities)

    if facts.scorecard_status == 200 and facts.scorecard_score is not None:
        # A perfect 10 with no at-or-above-cutoff findings is clean; anything
        # else is an offender. The score itself is the failure axis here, so an
        # imperfect score is an offender regardless of finding severity, but
        # sub-threshold findings on a perfect score fold into clean -- matching
        # the code-scanning cutoff logic used elsewhere in this file.
        clean = facts.scorecard_score >= 10.0 and not counts.at_or_above(cutoff)
        state = RepoState.CLEAN if clean else RepoState.OFFENDER
        return RepoSignal(
            repo,
            SignalType.SCORECARD,
            state,
            counts=counts,
            score=facts.scorecard_score,
        )
    if has_cs:
        return _alert_signal(
            repo,
            SignalType.SCORECARD,
            counts,
            facts.code_scanning_alerts_status,
            cutoff,
        )
    # An indeterminate external request (a 403 forbidden/blocked, a 5xx
    # including the synthetic 503 a transport failure produces, or a forbidden
    # code-scanning probe) is unknown, not a definitive nag. Only a clean 404
    # with no code-scanning Scorecard data means "no results".
    if facts.code_scanning_status == 403 or facts.scorecard_status not in (200, 404):
        return RepoSignal(
            repo, SignalType.SCORECARD, RepoState.UNKNOWN, detail="indeterminate"
        )
    return RepoSignal(
        repo, SignalType.SCORECARD, RepoState.NAG, detail="no Scorecard results"
    )


def classify_secret_scanning(
    facts: RepoFacts, _fail_severities: FailSeverities | None = None
) -> RepoSignal:
    # Secret scanning has no per-severity cutoff (a leaked secret is binary), so
    # the cutoff argument is accepted only for signature uniformity with the
    # other classifiers (they are dispatched positionally) and is unused here.
    repo = facts.repo
    if facts.secret_scanning_status == 403:
        return RepoSignal(
            repo,
            SignalType.SECRET_SCANNING,
            RepoState.UNKNOWN,
            detail="insufficient permission",
        )
    if facts.secret_scanning_status == 404:
        return RepoSignal(
            repo,
            SignalType.SECRET_SCANNING,
            RepoState.NAG,
            detail="secret scanning disabled",
        )
    # Flat open count; stored as HIGH so ranking (more == worse) works and the
    # repo-mode gate treats leaked secrets as serious, without conflating them
    # with CRITICAL code findings (which would make --fail-threshold critical
    # trip on any secret alert). Rendered as a single total because
    # SignalType.uses_severity_columns is False for secret scanning.
    counts = SeverityCounts(high=facts.secret_scanning_open)
    # Any leaked secret fails, so the cutoff is the lowest rung: positive
    # evidence is actionable even when the read was incomplete (a later page
    # failed) or the enablement probe was indeterminate. A zero count is only
    # "clean" when both the enablement probe and the open-count read
    # succeeded, so an indeterminate probe (5xx) counts as a failed read.
    read_status = (
        facts.secret_scanning_open_status
        if facts.secret_scanning_status == 200
        else facts.secret_scanning_status
    )
    return _alert_signal(
        repo,
        SignalType.SECRET_SCANNING,
        counts,
        read_status,
        Severity.INFORMATIONAL,
    )


def classify_dependabot(
    facts: RepoFacts, fail_severities: FailSeverities | None = None
) -> RepoSignal:
    repo = facts.repo
    if facts.dependabot_enabled is None:
        return RepoSignal(
            repo, SignalType.DEPENDABOT, RepoState.UNKNOWN, detail="indeterminate"
        )
    if facts.dependabot_enabled is False:
        return RepoSignal(
            repo,
            SignalType.DEPENDABOT,
            RepoState.NAG,
            detail="Dependabot alerts disabled",
        )
    # Enabled with no failing alerts is only "clean" when the alert read
    # succeeded in full.
    return _alert_signal(
        repo,
        SignalType.DEPENDABOT,
        count_dependabot(facts.dependabot_alerts),
        facts.dependabot_alerts_status,
        _cutoff(SignalType.DEPENDABOT, fail_severities),
    )


# One classifier per signal, keyed so orchestration can skip gated-out signals.
_Classifier = Callable[["RepoFacts", "FailSeverities | None"], RepoSignal]

_CLASSIFIERS: dict[SignalType, _Classifier] = {
    SignalType.CODEQL: classify_codeql,
    SignalType.SCORECARD: classify_scorecard,
    SignalType.ZIZMOR: classify_zizmor,
    SignalType.AISLOP: classify_aislop,
    SignalType.DEPENDABOT: classify_dependabot,
    SignalType.SECRET_SCANNING: classify_secret_scanning,
}


def classify_repo(
    facts: RepoFacts,
    fail_severities: FailSeverities | None = None,
    *,
    skip: Set[SignalType] = frozenset(),
) -> list[RepoSignal]:
    """Classify a repository across all signals (minus any in ``skip``).

    ``fail_severities`` optionally overrides the per-signal fail-severity cutoff
    (otherwise each signal uses its category default); it governs which findings
    are severe enough to mark a repository as an offender. ``skip`` names
    signals to leave unclassified entirely -- used when organisation feature
    gating (:mod:`gating`) found no support for a workflow-driven tool, so the
    repository is neither nagged nor counted for that signal.
    """
    return [
        classifier(facts, fail_severities)
        for signal, classifier in _CLASSIFIERS.items()
        if signal not in skip
    ]
