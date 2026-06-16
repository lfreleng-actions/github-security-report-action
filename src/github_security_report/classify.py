# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Classification: raw API facts -> four-state RepoSignal results.

Pure, transport-free logic encoding every Phase 0 finding
(``docs/phase0-findings.md``):

- the single code-scanning feed is partitioned by ``tool.name`` into CodeQL,
  Scorecard and zizmor -- counts are filtered per tool;
- CodeQL/Scorecard/zizmor enablement is the presence of that tool in
  ``code-scanning/analyses`` (not ``default-setup``); a 404 on code scanning
  means it is disabled entirely;
- secret scanning 404 = disabled, 200 [] = enabled-clean;
- Dependabot ``hasVulnerabilityAlertsEnabled == false`` = disabled;
- Scorecard prefers the external aggregate score, else code-scanning findings;
- 403 / indeterminate -> the unknown bucket, never clean or nag.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from github_security_report import severity
from github_security_report.models import (
    Repo,
    RepoSignal,
    RepoState,
    SeverityCounts,
    SignalType,
)


@dataclass
class RepoFacts:
    """Raw per-repository facts gathered by the client, pre-classification."""

    repo: Repo
    # Code scanning (covers CodeQL, Scorecard, zizmor).
    code_scanning_status: int = 200  # 200 ok, 404 disabled, 403 forbidden
    code_scanning_tools: set[str] = field(default_factory=set)  # analyses tool names
    code_scanning_alerts: list[dict] = field(default_factory=list)  # all tools
    # Secret scanning.
    secret_scanning_status: int = 200  # 200 enabled, 404 disabled, 403 forbidden
    secret_scanning_open: int = 0
    # Dependabot.
    dependabot_enabled: bool | None = None  # None = indeterminate
    dependabot_alerts: list[dict] = field(default_factory=list)
    # Scorecard (external API).
    scorecard_status: int = 404  # 200 has score, 404 none, 403 forbidden
    scorecard_score: float | None = None


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
    facts: RepoFacts, signal: SignalType, tool_name: str
) -> RepoSignal:
    """Shared four-state logic for the code-scanning-derived signals."""
    repo = facts.repo
    if facts.code_scanning_status == 403:
        return RepoSignal(repo, signal, RepoState.UNKNOWN, detail="insufficient permission")
    if facts.code_scanning_status == 404:
        return RepoSignal(repo, signal, RepoState.NAG, detail="code scanning disabled")
    if tool_name not in facts.code_scanning_tools:
        return RepoSignal(repo, signal, RepoState.NAG, detail=f"{tool_name} not enabled")
    counts = count_code_scanning(facts.code_scanning_alerts, tool_name)
    state = RepoState.OFFENDER if counts.total else RepoState.CLEAN
    return RepoSignal(repo, signal, state, counts=counts)


def classify_codeql(facts: RepoFacts) -> RepoSignal:
    return _code_scanning_tool_signal(facts, SignalType.CODEQL, "CodeQL")


def classify_zizmor(facts: RepoFacts) -> RepoSignal:
    return _code_scanning_tool_signal(facts, SignalType.ZIZMOR, "zizmor")


def classify_scorecard(facts: RepoFacts) -> RepoSignal:
    """Scorecard: prefer the external aggregate score, else code-scanning findings."""
    repo = facts.repo
    counts = count_code_scanning(facts.code_scanning_alerts, "Scorecard")
    has_cs = "Scorecard" in facts.code_scanning_tools and facts.code_scanning_status == 200

    if facts.scorecard_status == 200 and facts.scorecard_score is not None:
        # A perfect 10 with no findings is clean; anything else is an offender.
        clean = facts.scorecard_score >= 10.0 and counts.total == 0
        state = RepoState.CLEAN if clean else RepoState.OFFENDER
        return RepoSignal(repo, SignalType.SCORECARD, state, counts=counts, score=facts.scorecard_score)
    if has_cs:
        state = RepoState.OFFENDER if counts.total else RepoState.CLEAN
        return RepoSignal(repo, SignalType.SCORECARD, state, counts=counts)
    # An indeterminate external request (transient error -> status 0, a 5xx, or
    # a forbidden code-scanning probe) is unknown, not a definitive nag. Only a
    # clean 404 with no code-scanning Scorecard data means "no results".
    if facts.code_scanning_status == 403 or facts.scorecard_status == 0 or facts.scorecard_status >= 500:
        return RepoSignal(repo, SignalType.SCORECARD, RepoState.UNKNOWN, detail="indeterminate")
    return RepoSignal(repo, SignalType.SCORECARD, RepoState.NAG, detail="no Scorecard results")


def classify_secret_scanning(facts: RepoFacts) -> RepoSignal:
    repo = facts.repo
    if facts.secret_scanning_status == 403:
        return RepoSignal(repo, SignalType.SECRET_SCANNING, RepoState.UNKNOWN, detail="insufficient permission")
    if facts.secret_scanning_status == 404:
        return RepoSignal(repo, SignalType.SECRET_SCANNING, RepoState.NAG, detail="secret scanning disabled")
    # Flat open count; stored as HIGH so ranking (more == worse) works and the
    # repo-mode gate treats leaked secrets as serious, without conflating them
    # with CRITICAL code findings (which would make --fail-threshold critical
    # trip on any secret alert). Rendered as a single total because
    # SignalType.uses_severity_columns is False for secret scanning.
    counts = SeverityCounts(high=facts.secret_scanning_open)
    state = RepoState.OFFENDER if facts.secret_scanning_open else RepoState.CLEAN
    return RepoSignal(repo, SignalType.SECRET_SCANNING, state, counts=counts)


def classify_dependabot(facts: RepoFacts) -> RepoSignal:
    repo = facts.repo
    if facts.dependabot_enabled is None:
        return RepoSignal(repo, SignalType.DEPENDABOT, RepoState.UNKNOWN, detail="indeterminate")
    if facts.dependabot_enabled is False:
        return RepoSignal(repo, SignalType.DEPENDABOT, RepoState.NAG, detail="Dependabot alerts disabled")
    counts = count_dependabot(facts.dependabot_alerts)
    state = RepoState.OFFENDER if counts.total else RepoState.CLEAN
    return RepoSignal(repo, SignalType.DEPENDABOT, state, counts=counts)


_CLASSIFIERS = (
    classify_codeql,
    classify_scorecard,
    classify_zizmor,
    classify_dependabot,
    classify_secret_scanning,
)


def classify_repo(facts: RepoFacts) -> list[RepoSignal]:
    """Classify a repository across all five signals."""
    return [classifier(facts) for classifier in _CLASSIFIERS]
