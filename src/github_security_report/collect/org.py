# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Org-mode orchestration: sweep, gate, probe, classify, aggregate.

Ties the transport (:mod:`client`), scoping (:mod:`scope`), classification
(:mod:`classify`) and aggregation (:mod:`report`) together for a single
organisation, following the Phase 0 strategy: one org-bulk sweep per signal,
then bounded per-repo enabled-probes.

:func:`collect_org` reads as a pipeline of named phases, each implemented by a
helper in this module:

1. :func:`~github_security_report.collect.scoping.resolve_scope` -- list the organisation's repositories and scope them
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
from collections.abc import Sequence
from dataclasses import dataclass

from github_security_report import gating, rulesets
from github_security_report.classify import RepoFacts, classify_repo
from github_security_report.client import GraphBatchError
from github_security_report.collect.context import (
    OrgCollectContext,
    gather_in_batches,
)
from github_security_report.collect.extras import attach_extra_tables
from github_security_report.collect.protocols import ClientProtocol
from github_security_report.collect.scoping import resolve_scope, selected_scope
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

# GitHub gates ``GET /orgs/{org}/rulesets`` behind an org-admin permission
# (classic ``admin:org``, or fine-grained Administration *write*) and answers
# 404 -- not 403 -- for a token that lacks it. That permission is deliberately
# absent from the minimal tokens the README recommends, because ruleset coverage
# is optional: a tool is still detected from the code-scanning analyses it
# uploads, so only a repository covered *solely* by a required-workflow ruleset
# that has never run is affected. Reporting the documented, recommended token's
# own outcome as a WARNING implies a broken deployment, so these statuses log at
# INFO and only a genuinely unexpected failure (e.g. a 5xx) warns. Deliberately
# limited to the permission-shaped statuses: a 401 means the credential itself
# is bad or expired, which is a real fault and must keep warning.
_RULESET_OPTIONAL_STATUSES = frozenset({403, 404})


def _group_by_repo(alerts: list[dict]) -> dict[str, list[dict]]:
    """Group org-bulk alerts by repository name (each carries ``repository``)."""
    grouped: dict[str, list[dict]] = defaultdict(list)
    for alert in alerts:
        name = (alert.get("repository") or {}).get("name")
        if name:
            grouped[name].append(alert)
    return grouped


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


def _log_ruleset_status(org: str, status: int) -> None:
    """Report an unreadable org-rulesets list at a level matching its cause."""
    if status == 200:
        return
    if status in _RULESET_OPTIONAL_STATUSES:
        log.info(
            "org rulesets not readable for %s (status %s); expected unless the "
            "token carries the optional org-admin permission (classic "
            "admin:org, or fine-grained Administration write). Tools are still "
            "detected from their code-scanning analyses, so only a repository "
            "covered solely by a required-workflow ruleset is affected",
            org,
            status,
        )
        return
    log.warning(
        "org rulesets read failed unexpectedly for %s (status %s); "
        "ruleset-based tool coverage is disabled for this run",
        org,
        status,
    )


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
    _log_ruleset_status(org, rs_status)
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
    client: ClientProtocol, org: str, repos: list[Repo], *, batch_size: int
) -> dict[str, RepoGraphData]:
    """Prefetch batched GraphQL data for every in-scope repository.

    Issues one aliased query per ``batch_size`` repositories
    (``report.graph_batch``), folding the former per-repo Dependabot-enabled,
    latest-release, latest-tag and ``dependabot.yml`` round-trips into a
    handful of requests.

    The batch size adapts downwards. GitHub bounds GraphQL execution per query
    and reports a breach as a gateway timeout (502/504), a 200 with no
    ``data``, or a 200 whose ``errors`` say the query's resource limits were
    exceeded, so a query can fail purely because of how many repositories it
    carries; the same repositories then read fine in two smaller queries. When
    a batch fails that way after the transport's own retries, it is re-queued
    at half the size and every later batch of this organisation uses the
    smaller size too: a slow day at GitHub is a property of the collection,
    not of the one batch that happened to hit it first. The learned size is
    deliberately scoped to the organisation rather than carried across a
    multi-org run -- each organisation collects with its own client and may
    configure its own ``graph_batch``, and organisations differ in how much
    data a repository carries -- at the bounded cost of one oversized batch
    (plus its retries) per organisation on a bad day. A failure that a
    smaller query could not fix (a permission error, an exhausted rate limit,
    a 500/503 outage) propagates unchanged, as does a single-repository query
    that still fails: at that point the API is genuinely unusable and aborting
    beats fabricating "never released" for the repository. The client makes
    that call (see :func:`client.batch_errors._batch_response`); this loop
    only acts on it.
    """
    graph: dict[str, RepoGraphData] = {}
    pending = [repo.name for repo in repos]
    size = max(1, batch_size)
    while pending:
        batch, pending = pending[:size], pending[size:]
        try:
            graph.update(await client.repo_graph_batch(org, batch))
        except GraphBatchError as exc:
            if len(batch) == 1 or not exc.splittable:
                raise
            size = len(batch) // 2
            log.warning(
                "GraphQL prefetch for %s failed (%s) for a batch of %d "
                "repositories; retrying them (and the %d remaining) in batches "
                "of %d, since GitHub bounds how much work one query may do",
                org,
                exc.reason,
                len(batch),
                len(pending),
                size,
            )
            pending = batch + pending
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
        graph=await _collect_graph(
            client, org, in_scope, batch_size=report_cfg.graph_batch
        ),
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
    selected: Sequence[Repo] | None = None,
) -> OrgReport:
    """Collect and build the report for one organisation.

    ``selected``, when given, is the exact set of repositories to collect:
    the in-scope matches of a named selection, already validated by
    :func:`~github_security_report.collect.scoping.check_named_repos`. The
    organisation is then not listed again. Per-repository reads cover only
    these; the org-bulk alert sweeps still read the organisation's open
    alerts, as they are single organisation-wide requests.
    """
    org = org_cfg.name
    log.info("collecting %s", org)

    scoped = (
        selected_scope(selected)
        if selected is not None
        else await resolve_scope(client, org_cfg, report_cfg)
    )
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
