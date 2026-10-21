# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Collection of the workflow-run records behind the Workflow Failures tables.

Per organisation: sync every in-scope repository against the run store (see
:mod:`collect.run_sync`), name the failing jobs of every stored failure the
GraphQL drill-down has not yet read, prune what has aged past retention, and
hand back the records of the longest window for aggregation. The store does
the remembering; this module decides what to ask GitHub for this run.
"""

from __future__ import annotations

import datetime as dt
import logging
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from urllib.parse import urlparse

from github_security_report.client import GITHUB_API, GraphBatchError
from github_security_report.client.workflow_runs import RunDrillDown
from github_security_report.collect.context import (
    CollectExtras,
    OrgCollectContext,
    batched,
    gather_in_batches,
)
from github_security_report.collect.run_sync import (
    RepoRunSync,
    RepoSync,
    RunSyncOptions,
)
from github_security_report.config import (
    ReportConfig,
    WorkflowRunsConfig,
    default_cache_dir,
)
from github_security_report.models import Repo
from github_security_report.report import OrgReport
from github_security_report.workflow_runs import (
    RunStore,
    Trigger,
    WindowOptions,
    WorkflowRunRecord,
    store_path,
)
from github_security_report.workflow_runs.tables import build_workflow_failure_tables

log = logging.getLogger(__name__)

# Runs per drill-down query. Fifty node ids cost one rate-limit point and
# answer in a few seconds; the batched driver halves a query GitHub refuses.
DRILL_DOWN_BATCH = 50


@dataclass(frozen=True)
class WorkflowRunsResult:
    """What this run's collection produced for the aggregation.

    ``records`` is every stored run of an in-scope repository within the
    longest window, enriched where possible. ``unknown`` names the
    repositories whose listing could not be read this run: their windows must
    say so rather than claim no failures. ``oldest`` is, per repository, how
    far back its stored history reaches (``None`` when unknown), so a window
    reaching further than that can be marked as truncated.
    """

    records: tuple[WorkflowRunRecord, ...]
    unknown: frozenset[str]
    oldest: Mapping[str, dt.datetime | None]
    syncs: tuple[RepoRunSync, ...]


def _apply_drill_down(
    record: WorkflowRunRecord, found: RunDrillDown
) -> WorkflowRunRecord:
    """The record with what the drill-down learned about it.

    The workflow's current name replaces the run-time name so a renamed
    workflow groups under one heading; a tag prefix turns a push the listing
    could only call a branch into a tag.
    """
    trigger = record.trigger
    if found.ref_is_tag and record.trigger is Trigger.BRANCH:
        trigger = Trigger.TAG
    return replace(
        record,
        failed_jobs=found.failed_jobs,
        workflow_name=found.workflow_name or record.workflow_name,
        ref_is_tag=found.ref_is_tag,
        trigger=trigger,
    )


async def _enrich(
    ctx: OrgCollectContext,
    store: RunStore,
    *,
    since: dt.datetime,
    repos: frozenset[str],
    include_dynamic: bool,
) -> None:
    """Name the failing jobs of every unenriched failure in the window.

    A drill-down the API refuses outright (a rate limit, an outage) is logged
    and left for the next run: the tables render those failures with their
    jobs unreadable, which is accurate, whereas the prefetch's abort would
    cost the whole report for a column of detail.
    """
    pending = [
        record
        for record in store.needing_enrichment(since=since)
        if record.repo in repos
        and record.node_id
        and (include_dynamic or not record.is_dynamic)
    ]
    if not pending:
        return
    by_node = {record.node_id: record for record in pending}
    try:
        found = await batched(
            lambda ids: ctx.client.workflow_run_jobs(ctx.org, ids),
            list(by_node),
            size=DRILL_DOWN_BATCH,
            describe=f"GraphQL run drill-down for {ctx.org}",
        )
    except GraphBatchError as exc:
        log.warning(
            "failing jobs for %d workflow runs in %s left unread: %s",
            len(pending),
            ctx.org,
            exc.reason or f"HTTP {exc.status}",
        )
        return
    enriched = [
        _apply_drill_down(by_node[node_id], drill)
        for node_id, drill in found.items()
        if drill.failed_jobs is not None
    ]
    store.upsert(enriched)
    unread = len(pending) - len(enriched)
    if unread:
        log.info(
            "failing jobs for %d of %d workflow runs in %s could not be read",
            unread,
            len(pending),
            ctx.org,
        )


async def collect_workflow_runs(
    in_scope: list[Repo],
    ctx: OrgCollectContext,
    store: RunStore,
    *,
    now: dt.datetime,
    options: RunSyncOptions,
) -> WorkflowRunsResult:
    """Sync, enrich, prune, and load the longest window's records."""
    syncs = await gather_in_batches(
        in_scope,
        lambda repo: RepoSync(
            ctx.client, store, ctx.org, repo, now=now, options=options
        ).run(),
    )
    names = frozenset(repo.name for repo in in_scope)
    since = now - dt.timedelta(days=options.window_days)
    await _enrich(
        ctx,
        store,
        since=since,
        repos=names,
        include_dynamic=options.include_dynamic,
    )
    pruned = store.prune(now - dt.timedelta(days=options.retention_days))
    unknown = frozenset(sync.repo for sync in syncs if not sync.readable)
    log.info(
        "workflow runs for %s: %d repositories synced (%d unchanged, %d "
        "unreadable), %d records written, %d re-read, %d pruned",
        ctx.org,
        len(syncs),
        sum(1 for sync in syncs if sync.status == 304),
        len(unknown),
        sum(sync.written for sync in syncs),
        sum(sync.rereads for sync in syncs),
        pruned,
    )
    return WorkflowRunsResult(
        records=tuple(r for r in store.records(since=since) if r.repo in names),
        unknown=unknown,
        oldest={name: store.sync_state(name).oldest for name in names},
        syncs=tuple(syncs),
    )


def open_run_store(
    cfg: WorkflowRunsConfig, org: str, *, api_url: str = GITHUB_API
) -> RunStore:
    """The run store for ``org`` under ``cfg``: on disk, or in memory.

    Keyed by the API host as well as the organisation, since the same name
    can exist on github.com and on an enterprise instance. With ``cache``
    off the store lives in memory for this run alone, so the same code path
    serves a run that must not leave anything behind.
    """
    if not cfg.cache:
        return RunStore(Path(":memory:"))
    base = Path(cfg.cache_dir).expanduser() if cfg.cache_dir else default_cache_dir()
    host = urlparse(api_url).netloc or api_url
    return RunStore(store_path(base, host, org))


async def attach_workflow_failures(
    report: OrgReport,
    in_scope: list[Repo],
    ctx: OrgCollectContext,
    report_cfg: ReportConfig,
    extras: CollectExtras,
) -> None:
    """Collect the organisation's runs and attach both tables per window."""
    assert extras.run_store is not None
    cfg = report_cfg.workflow_runs
    result = await collect_workflow_runs(
        in_scope,
        ctx,
        extras.run_store,
        now=report.generated_at,
        options=RunSyncOptions(
            window_days=cfg.longest_window,
            retention_days=cfg.retention,
            backfill_days=cfg.backfill,
            include_dynamic=cfg.include_dynamic,
            refresh=extras.refresh_runs,
        ),
    )
    report.workflow_failures, report.workflow_failures_detail = (
        build_workflow_failure_tables(
            result.records,
            in_scope,
            generated_at=report.generated_at,
            windows=cfg.all_windows,
            options=WindowOptions(
                days=cfg.longest_window,
                min_runs=cfg.min_runs,
                persistent_threshold=cfg.persistent_threshold,
                collapse_matrix=cfg.collapse_matrix,
                include_dynamic=cfg.include_dynamic,
                exclude_workflows=cfg.exclude_workflows,
            ),
            unknown=result.unknown,
            oldest=result.oldest,
        )
    )
