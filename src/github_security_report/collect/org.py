# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Org-mode orchestration: sweep, gate, probe, classify, aggregate.

Ties the transport (:mod:`client`), scoping (:mod:`scope`), classification
(:mod:`classify`) and aggregation (:mod:`report`) together for a single
organisation, following the Phase 0 strategy: one org-bulk sweep per signal,
then bounded per-repo enabled-probes.

:func:`collect_org` reads as a pipeline of named phases, each implemented by a
helper in this module:

1. :func:`_resolve_scope` -- list the organisation's repositories and scope them
2. :func:`_run_sweeps` -- one org-bulk read per signal, plus ruleset coverage
3. :func:`_gate_signals` -- decide which workflow-driven signals to collect
4. :func:`_build_context` -- freeze the org-wide evidence per-repo probes need
5. :func:`_collect_facts` -- bounded per-repo probes, then classification
6. :mod:`collect.extras` -- the tables outside the four-state signal model
"""

from __future__ import annotations

import asyncio
import datetime as dt
import logging
from collections import defaultdict
from dataclasses import dataclass

from github_security_report import gating, rulesets, scope
from github_security_report.classify import RepoFacts, classify_repo
from github_security_report.collect.context import (
    GRAPH_BATCH,
    OrgCollectContext,
    gather_in_batches,
)
from github_security_report.collect.extras import attach_extra_tables
from github_security_report.collect.protocols import ClientProtocol
from github_security_report.config import OrgConfig, ReportConfig
from github_security_report.models import (
    CODE_SCANNING_TOOLS,
    Repo,
    RepoGraphData,
    SignalType,
)
from github_security_report.report import OrgReport, build_org_report
from github_security_report.rulesets import WorkflowRuleset

log = logging.getLogger(__name__)

# The org-bulk alert sweeps, in the order their results are unpacked.
_SWEEP_KINDS = ("code-scanning", "dependabot", "secret-scanning")


def _group_by_repo(alerts: list[dict]) -> dict[str, list[dict]]:
    """Group org-bulk alerts by repository name (each carries ``repository``)."""
    grouped: dict[str, list[dict]] = defaultdict(list)
    for alert in alerts:
        name = (alert.get("repository") or {}).get("name")
        if name:
            grouped[name].append(alert)
    return grouped


# --------------------------------------------------------------------------- #
# Repository scope
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class _OrgScope:
    """The repositories a run covers, and whether the listing was complete."""

    status: int
    in_scope: list[Repo]
    excluded: list[Repo]

    @property
    def partial(self) -> bool:
        """Whether the listing was incomplete, so the report must say so."""
        return self.status != 200


async def _resolve_scope(
    client: ClientProtocol, org_cfg: OrgConfig, report_cfg: ReportConfig
) -> _OrgScope:
    """List the organisation's repositories and apply the scoping rules."""
    org = org_cfg.name
    status, repos = await client.list_org_repos(org)
    if status != 200:
        log.warning(
            "repository listing for org %s is incomplete (status %s); the "
            "report may omit repositories and their findings",
            org,
            status,
        )
    in_scope = scope.filter_repos(
        repos,
        include_archived=report_cfg.include_archived,
        include_test=report_cfg.include_test,
        exclude=org_cfg.exclude,
    )
    # Repositories removed specifically by the per-org exclude list (not by
    # fork/template/archived/test filtering) are tracked so the report can show
    # them as explicitly excluded rather than silently dropping them.
    exclude_names = set(org_cfg.exclude)
    return _OrgScope(
        status=status,
        in_scope=in_scope,
        excluded=[repo for repo in repos if repo.name in exclude_names],
    )


# --------------------------------------------------------------------------- #
# Org-bulk sweeps
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class _OrgSweeps:
    """One org-bulk alert read per signal family, plus org ruleset coverage."""

    # Sweep kind -> repository name -> that repository's alerts.
    alerts: dict[str, dict[str, list[dict]]]
    # Sweep kind -> HTTP status, so an unreadable sweep degrades its signals.
    status: dict[str, int]
    # The ungrouped code-scanning alerts, which feature gating reads as
    # free evidence that a tool runs somewhere in the organisation.
    code_scanning_alerts: list[dict]
    workflow_rulesets: list[WorkflowRuleset]


async def _run_sweeps(client: ClientProtocol, org: str) -> _OrgSweeps:
    """Read every org-wide signal concurrently: bulk alerts plus rulesets.

    Each sweep returns its HTTP status so an unreadable sweep (e.g. 403/5xx)
    degrades the affected signals to UNKNOWN rather than CLEAN. Ruleset coverage
    degrades gracefully when the token cannot read org rulesets: repositories
    then fall back to per-repo evidence.
    """
    sweeps, (rs_status, rs_details) = await asyncio.gather(
        asyncio.gather(*(client.org_bulk_alerts(org, kind) for kind in _SWEEP_KINDS)),
        client.org_workflow_rulesets(org),
    )
    status = {
        kind: result[0] for kind, result in zip(_SWEEP_KINDS, sweeps, strict=True)
    }
    for kind, kind_status in status.items():
        if kind_status != 200:
            log.warning(
                "%s alert sweep for org %s unavailable (status %s); affected "
                "signals reported as unknown rather than clean",
                kind,
                org,
                kind_status,
            )
    if rs_status != 200:
        log.warning(
            "org rulesets unavailable for %s (status %s); ruleset-based tool "
            "coverage disabled",
            org,
            rs_status,
        )
    return _OrgSweeps(
        alerts={
            kind: _group_by_repo(result[1])
            for kind, result in zip(_SWEEP_KINDS, sweeps, strict=True)
        },
        status=status,
        code_scanning_alerts=sweeps[0][1],
        workflow_rulesets=rulesets.parse_workflow_rulesets(rs_details),
    )


# --------------------------------------------------------------------------- #
# Organisation feature gating
# --------------------------------------------------------------------------- #
async def _gate_signals(
    client: ClientProtocol,
    org: str,
    in_scope: list[Repo],
    sweeps: _OrgSweeps,
    report_cfg: ReportConfig,
) -> frozenset[SignalType]:
    """Decide, from evidence already in hand, which signals to skip entirely.

    Uses a bounded sample of analyses probes on top of the free evidence to
    settle which workflow-driven signals this organisation supports at all.
    Unsupported signals are skipped -- not probed per repo, not classified --
    and their sections render a single skip line pointing at the setup guide
    instead of nagging every repository.
    """
    if not report_cfg.gating:
        return frozenset()
    gates = await gating.gate_signals(
        client,
        org,
        in_scope,
        workflow_rulesets=sweeps.workflow_rulesets,
        code_scanning_alerts=sweeps.code_scanning_alerts,
        ruleset_workflows=report_cfg.ruleset_workflows,
    )
    return frozenset(signal for signal, gate in gates.items() if not gate.supported)


# --------------------------------------------------------------------------- #
# Shared per-repo context
# --------------------------------------------------------------------------- #
async def _collect_graph(
    client: ClientProtocol, org: str, repos: list[Repo]
) -> dict[str, RepoGraphData]:
    """Prefetch batched GraphQL data for every in-scope repository.

    Issues one aliased query per ``GRAPH_BATCH`` repositories, folding the
    former per-repo Dependabot-enabled, latest-release, latest-tag and
    ``dependabot.yml`` round-trips into a handful of requests.
    """
    graph: dict[str, RepoGraphData] = {}
    for start in range(0, len(repos), GRAPH_BATCH):
        batch = repos[start : start + GRAPH_BATCH]
        graph.update(await client.repo_graph_batch(org, [r.name for r in batch]))
    return graph


async def _build_context(
    client: ClientProtocol,
    org: str,
    in_scope: list[Repo],
    sweeps: _OrgSweeps,
    report_cfg: ReportConfig,
    skipped: frozenset[SignalType],
) -> OrgCollectContext:
    """Freeze the org-wide evidence that every per-repository probe reads."""
    return OrgCollectContext(
        client=client,
        org=org,
        code_scanning=sweeps.alerts["code-scanning"],
        dependabot=sweeps.alerts["dependabot"],
        secret=sweeps.alerts["secret-scanning"],
        sweep_status=sweeps.status,
        coverage={
            repo.name: rulesets.signals_covered(
                repo.name, sweeps.workflow_rulesets, report_cfg.ruleset_workflows
            )
            for repo in in_scope
        },
        graph=await _collect_graph(client, org, in_scope),
        probe_tools=tuple(
            tool
            for signal, tool in CODE_SCANNING_TOOLS.items()
            if signal not in skipped
        ),
        probe_scorecard=SignalType.SCORECARD not in skipped,
    )


# --------------------------------------------------------------------------- #
# Per-repo probes
# --------------------------------------------------------------------------- #
async def _facts_for_repo(repo: Repo, ctx: OrgCollectContext) -> RepoFacts:
    """Combine the org-wide evidence with this repository's own probes.

    These per-repo probes are independent, so they are gathered and each repo's
    reads overlap; real HTTP concurrency stays bounded by the client semaphore.
    The Dependabot-enabled flag comes from the batched GraphQL prefetch rather
    than a probe of its own. ``ctx.probe_tools`` names the code-scanning tools
    worth probing (feature gating removes unsupported ones), and
    ``ctx.probe_scorecard`` skips the external Scorecard read when the signal is
    gated out -- the facts then default to "no score" and the skipped classifier
    never reads them.
    """

    async def no_scorecard() -> tuple[int, float | None]:
        return 404, None

    (
        (cs_status, cs_tools),
        secret_status,
        (scorecard_status, score),
    ) = await asyncio.gather(
        ctx.client.code_scanning_tools(ctx.org, repo.name, ctx.probe_tools),
        ctx.client.secret_scanning_status(ctx.org, repo.name),
        ctx.client.scorecard_score(ctx.org, repo.name)
        if ctx.probe_scorecard
        else no_scorecard(),
    )
    return RepoFacts(
        repo=repo,
        code_scanning_status=cs_status,
        code_scanning_tools=cs_tools,
        code_scanning_alerts=ctx.code_scanning.get(repo.name, []),
        code_scanning_alerts_status=ctx.sweep_status["code-scanning"],
        secret_scanning_status=secret_status,
        secret_scanning_open=len(ctx.secret.get(repo.name, [])),
        secret_scanning_open_status=ctx.sweep_status["secret-scanning"],
        dependabot_enabled=ctx.graph_for(repo.name).dependabot_alerts_enabled,
        dependabot_alerts=ctx.dependabot.get(repo.name, []),
        dependabot_alerts_status=ctx.sweep_status["dependabot"],
        scorecard_status=scorecard_status,
        scorecard_score=score,
        ruleset_signals=ctx.ruleset_signals(repo.name),
    )


def _classify(
    facts: list[RepoFacts], report_cfg: ReportConfig, skipped: frozenset[SignalType]
) -> list:
    """Classify every repository, honouring configured fail-severity overrides.

    Signals with no configured override fall back to their category default
    inside the classifier.
    """
    fail_severities = {
        signal: override
        for signal in SignalType
        if (override := report_cfg.fail_severity_for(signal.category_key)) is not None
    }
    return [
        sig
        for repo_facts in facts
        for sig in classify_repo(repo_facts, fail_severities, skip=skipped)
    ]


# --------------------------------------------------------------------------- #
# The pipeline
# --------------------------------------------------------------------------- #
async def collect_org(
    client: ClientProtocol,
    org_cfg: OrgConfig,
    report_cfg: ReportConfig,
    *,
    generated_at: dt.datetime | None = None,
) -> OrgReport:
    """Collect and build the report for one organisation."""
    org = org_cfg.name
    log.info("collecting %s", org)

    scoped = await _resolve_scope(client, org_cfg, report_cfg)
    sweeps = await _run_sweeps(client, org)
    skipped = await _gate_signals(client, org, scoped.in_scope, sweeps, report_cfg)
    ctx = await _build_context(
        client, org, scoped.in_scope, sweeps, report_cfg, skipped
    )

    facts = await gather_in_batches(
        scoped.in_scope, lambda repo: _facts_for_repo(repo, ctx)
    )
    report = build_org_report(
        org,
        _classify(facts, report_cfg, skipped),
        repo_count=len(scoped.in_scope),
        generated_at=generated_at,
        partial=scoped.partial,
        excluded_repos=scoped.excluded,
        skipped_signals=skipped,
    )
    await attach_extra_tables(report, scoped.in_scope, ctx, org_cfg, report_cfg)
    return report
