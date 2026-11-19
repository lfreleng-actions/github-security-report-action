# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Organisation feature gating for the workflow-driven signals.

The Scorecard, zizmor, aislop and fuzz signals only produce data when an
organisation has deployed supporting workflows (a daily org-wide scan that
uploads SARIF to code scanning, a PR ruleset requiring the scan workflow, or --
for Scorecard -- a per-repository reusable workflow; see
``docs/org-scan-setup.md``). An organisation without that infrastructure would
otherwise see every repository nagged as "not enabled" plus a per-repo probe
spent on a tool that can never be found.

This module performs a cheap, layered support check per gated signal before
any per-repo telemetry is gathered:

1. **Alert evidence** (free): the already-fetched org-bulk code-scanning sweep
   contains at least one alert from the tool.
2. **Ruleset evidence** (free): an already-fetched active org ruleset requires
   a workflow whose path matches the signal's configured keyword.
3. **Sampled analyses** (bounded): the code-scanning analyses endpoint of up to
   ``SAMPLE_SIZE`` repositories is probed for the tool (one filtered request
   per repo). For Scorecard the external scorecard.dev API is sampled too,
   since publish-enabled orgs have scores without code-scanning uploads.

A signal with no evidence at any layer is *skipped*: it is not probed, not
classified, and its report section carries a single
"Skipping feature: organisation support missing" line with a pointer to the
setup guide -- instead of noisy nag lists or failed-query output. The check is
evidence-based, so a brand-new deployment (before the first SARIF upload
lands) may be skipped for one run; ``report.gating: false`` disables gating
entirely for such cases.

CodeQL, Dependabot and secret scanning are GitHub-native features probed via
first-party APIs, so they are never gated.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol

from github_security_report import rulesets
from github_security_report.models import CODE_SCANNING_TOOLS, Repo, SignalType
from github_security_report.rulesets import WorkflowRuleset

log = logging.getLogger(__name__)

# The signals subject to organisation support gating: exactly the
# code-scanning-derived signals that depend on org-deployed workflows.
# CodeQL is code-scanning-derived too but GitHub-native (default setup /
# per-repo config, no org workflow needed), so it is exempt.
GATED_SIGNALS: tuple[SignalType, ...] = (
    SignalType.SCORECARD,
    SignalType.ZIZMOR,
    SignalType.AISLOP,
    SignalType.FUZZ,
)

# Repositories sampled for the analyses-presence probe when the free evidence
# layers find nothing. Bounds the gate's cost at one request per sampled repo
# per undecided signal (plus one external Scorecard read per sampled repo).
SAMPLE_SIZE = 10


def _spread_sample(repos: list[Repo], sample_size: int) -> list[Repo]:
    """Pick up to ``sample_size`` repositories evenly spread across ``repos``.

    Taking the first N repos would systematically miss evidence when a tool is
    only deployed on later repositories, wrongly skipping the signal. Whenever
    at least two repos are sampled the spacing is endpoint-inclusive -- it
    contains the first and last repository -- so a tool present only on the
    earliest or latest repos is still probed. The probe count is unchanged and
    the fixed step keeps the choice deterministic. Degenerate inputs collapse
    sensibly: an empty or non-positive request yields nothing, a request at or
    above the repo count returns every repo, and a single-repo request returns
    the first repo.
    """
    if sample_size <= 0:
        return []
    if len(repos) <= sample_size:
        return list(repos)
    if sample_size == 1:
        return [repos[0]]
    step = (len(repos) - 1) / (sample_size - 1)
    return [repos[round(i * step)] for i in range(sample_size)]


@dataclass(frozen=True)
class GateResult:
    """The support decision for one gated signal."""

    signal: SignalType
    supported: bool
    # Short human note naming the evidence found (for logs), e.g.
    # "code-scanning alerts", "org ruleset", "analyses on <repo>"; empty when
    # no evidence was found.
    evidence: str = ""


class GateClientProtocol(Protocol):
    """The client subset the sampled-probe layer needs."""

    async def code_scanning_tool_present(self, org: str, repo: str, tool: str) -> bool:
        """Whether ``tool`` has uploaded code-scanning analyses to the repo."""
        raise NotImplementedError

    async def scorecard_score(self, org: str, repo: str) -> tuple[int, float | None]:
        """Return a repository's OpenSSF Scorecard score and read status."""
        raise NotImplementedError


def _alert_evidence(alerts: list[dict], tool: str) -> bool:
    """Whether any org-sweep code-scanning alert was produced by ``tool``."""
    return any((alert.get("tool") or {}).get("name") == tool for alert in alerts)


async def _sample_evidence(
    client: GateClientProtocol,
    org: str,
    sample: list[Repo],
    signal: SignalType,
    tool: str,
) -> str:
    """Probe a bounded repo sample for the tool; return evidence text or ''."""
    if not sample:
        return ""
    present = await asyncio.gather(
        *(client.code_scanning_tool_present(org, r.name, tool) for r in sample)
    )
    for repo, hit in zip(sample, present, strict=True):
        if hit:
            return f"analyses on {repo.name}"
    if signal is SignalType.SCORECARD:
        # Publish-enabled Scorecard workflows surface via the external API even
        # when nothing was uploaded to code scanning, and the OpenSSF weekly
        # scan covers many public repositories -- either counts as support.
        scores = await asyncio.gather(
            *(client.scorecard_score(org, r.name) for r in sample)
        )
        for repo, (status, score) in zip(sample, scores, strict=True):
            if status == 200 and score is not None:
                return f"external score for {repo.name}"
    return ""


async def gate_signals(
    client: GateClientProtocol,
    org: str,
    repos: list[Repo],
    *,
    workflow_rulesets: list[WorkflowRuleset],
    code_scanning_alerts: list[dict],
    ruleset_workflows: Mapping[str, str],
    sample_size: int = SAMPLE_SIZE,
) -> dict[SignalType, GateResult]:
    """Decide organisation support for every gated signal.

    Consumes only data the orchestration has already fetched (the org
    code-scanning sweep and the org rulesets) plus a bounded number of extra
    probes for signals the free layers cannot decide. Never raises for a
    missing feature; an undecidable signal is simply unsupported this run.
    """
    results: dict[SignalType, GateResult] = {}
    undecided: list[SignalType] = []
    for signal in GATED_SIGNALS:
        tool = CODE_SCANNING_TOOLS[signal]
        if _alert_evidence(code_scanning_alerts, tool):
            results[signal] = GateResult(signal, True, "code-scanning alerts")
        elif rulesets.any_ruleset_matches(
            workflow_rulesets, ruleset_workflows.get(signal.value, "")
        ):
            results[signal] = GateResult(signal, True, "org ruleset")
        else:
            undecided.append(signal)

    sample = _spread_sample(repos, sample_size)
    if undecided and sample:
        evidence = await asyncio.gather(
            *(
                _sample_evidence(
                    client, org, sample, signal, CODE_SCANNING_TOOLS[signal]
                )
                for signal in undecided
            )
        )
        for signal, found in zip(undecided, evidence, strict=True):
            results[signal] = GateResult(signal, bool(found), found)
    else:
        for signal in undecided:
            results[signal] = GateResult(signal, False)

    for result in results.values():
        if result.supported:
            log.info(
                "gate: %s supported in %s (%s)",
                result.signal.value,
                org,
                result.evidence,
            )
        else:
            log.info(
                "gate: %s support missing in %s; skipping feature",
                result.signal.value,
                org,
            )
    return results
