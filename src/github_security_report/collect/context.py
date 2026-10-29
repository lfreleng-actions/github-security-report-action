# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Org-level context shared by every per-repository probe.

The org-mode pipeline gathers a body of organisation-wide evidence up front
(bulk alert sweeps, ruleset coverage, feature-gating decisions, a batched
GraphQL prefetch) and then walks the repositories, combining that evidence with
a small number of per-repo reads. :class:`OrgCollectContext` freezes the shared
half of that pair, so the per-repo helpers take ``(repo, ctx)`` instead of a
long and steadily-growing positional parameter list.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable, Coroutine, Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol, TypeVar

from github_security_report.client import GraphBatchError
from github_security_report.collect.protocols import ClientProtocol
from github_security_report.models import Repo, RepoGraphData
from github_security_report.workflow_runs import RunStore

log = logging.getLogger(__name__)

_T = TypeVar("_T")
_K = TypeVar("_K")
_V = TypeVar("_V")

# Per-repo probe tasks are created in batches of this size so very large orgs
# do not allocate every task at once (HTTP concurrency is bounded separately by
# the client semaphore).
REPO_BATCH = 50

# Batched GraphQL queries kept in flight at once. Each takes seconds on
# GitHub's side while holding one client slot, so a serial walk left the rest
# of the semaphore idle. A constant until a measurement justifies making it a
# setting; it is bounded by the client semaphore regardless.
GRAPH_PREFETCH_IN_FLIGHT = 4


@dataclass(frozen=True)
class RunSyncSummary:
    """What one organisation's workflow-run sync did, for the run summary.

    ``cold`` is whether a store on disk held none of the in-scope
    repositories before the sync: a first-time build, which is when a run
    takes minutes it will not take again. A store in memory is never cold,
    since it is rebuilt on every run. The counts are this run's:
    repositories whose listing was read (``repos``), of which ``unchanged``
    answered 304 and ``unreadable`` could not be read; records ``written``
    and ``pruned``.
    """

    cold: bool
    repos: int
    unchanged: int
    unreadable: int
    written: int
    pruned: int


class CollectProgress(Protocol):
    """What a collection tells a display about where it has got to.

    The collectors call these between awaits and expect them to return at
    once without raising; they import no display code, so the terminal's
    tracker implements this and the default, :class:`NullProgress`, does
    nothing.
    """

    def phase(self, name: str, *, repos: int | None = None) -> None:
        """Enter a named phase; ``repos`` starts a per-repository counter."""

    def repo_done(self) -> None:
        """One repository of the current phase's counter has finished."""

    def notice(self, text: str | None) -> None:
        """Show ``text`` while something exceptional lasts; ``None`` clears it."""

    def store_synced(self, summary: RunSyncSummary) -> None:
        """The workflow-run sync finished and did ``summary``."""


class NullProgress:
    """Progress nobody is watching: the default."""

    def phase(self, name: str, *, repos: int | None = None) -> None:
        return None

    def repo_done(self) -> None:
        return None

    def notice(self, text: str | None) -> None:
        return None

    def store_synced(self, summary: RunSyncSummary) -> None:
        return None


@dataclass(frozen=True)
class CollectExtras:
    """What an org-mode run collects beyond the signals and posture tables.

    ``author_tables`` off skips the Issues, Pull Requests and both Assigned to Me
    tables and the membership and viewer reads behind them; remediation acts
    on none of them. ``run_store`` is the workflow-run cache the Workflow
    Failures tables sync against, or ``None`` to leave them uncollected;
    ``refresh_runs`` re-reads every repository's runs regardless of what the
    store holds. ``progress`` hears which phase the collection is in.
    """

    author_tables: bool = True
    run_store: RunStore | None = None
    refresh_runs: bool = False
    progress: CollectProgress = field(default_factory=NullProgress)


@dataclass(frozen=True)
class OrgCollectContext:
    """Everything a per-repository probe needs beyond the repository itself.

    Built once per organisation by the collection pipeline and passed whole, so
    adding a new org-wide input is a field here rather than another argument
    threaded through every call site.
    """

    client: ClientProtocol
    org: str
    # Org-bulk alerts grouped by repository name, one map per signal family.
    code_scanning: Mapping[str, list[dict]]
    dependabot: Mapping[str, list[dict]]
    secret: Mapping[str, list[dict]]
    # Sweep kind -> HTTP status, so an unreadable sweep degrades the affected
    # signals to UNKNOWN rather than reporting them as CLEAN.
    sweep_status: Mapping[str, int]
    # Repository name -> signal values an active org ruleset enforces for it.
    coverage: Mapping[str, set[str]]
    # Repository name -> batched GraphQL prefetch results.
    graph: Mapping[str, RepoGraphData]
    # Code-scanning tools still worth probing after feature gating, and whether
    # the external Scorecard read is worth making at all.
    probe_tools: tuple[str, ...]
    probe_scorecard: bool

    def graph_for(self, name: str) -> RepoGraphData:
        """Prefetched GraphQL data for a repository, or unreadable defaults.

        A repository missing from the prefetch entirely is marked
        ``unreadable`` so the dependent tables report it as unknown instead of
        mislabelling it with confident negatives (e.g. "never released").
        """
        return self.graph.get(name, RepoGraphData(unreadable=True))

    def ruleset_signals(self, name: str) -> set[str]:
        """Signals an org ruleset enforces for a repository (possibly none)."""
        return self.coverage.get(name, set())


def repo_context(client: ClientProtocol, owner: str) -> OrgCollectContext:
    """A context with no org-wide evidence, for the reads repo mode shares.

    Repo mode never sweeps an organisation, so every org-wide field is empty;
    a collector that reads only ``client`` and ``org`` (the workflow-run
    collection) can then serve both modes unchanged.
    """
    return OrgCollectContext(
        client=client,
        org=owner,
        code_scanning={},
        dependabot={},
        secret={},
        sweep_status={},
        coverage={},
        graph={},
        probe_tools=(),
        probe_scorecard=False,
    )


async def gather_all(*aws: Awaitable[Any]) -> list[Any]:
    """Await every awaitable, or cancel the rest when one of them fails.

    ``asyncio.gather`` propagates the first exception while its siblings
    carry on, so the caller unwinds -- closing the client, the run store --
    under tasks still using them. This waits for the first failure, cancels
    and awaits what is still running, then re-raises, so nothing outlives
    the fan-out that started it. Results come back in argument order.
    """
    tasks = [asyncio.ensure_future(aw) for aw in aws]
    try:
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_EXCEPTION)
        failed = next((t for t in done if not t.cancelled() and t.exception()), None)
        if failed is not None:
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
            raise failed.exception()  # type: ignore[misc]
        return [task.result() for task in tasks]
    except asyncio.CancelledError:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        raise


async def gather_in_batches(
    repos: list[Repo],
    probe: Callable[[Repo], Awaitable[_T]],
    *,
    progress: CollectProgress | None = None,
) -> list[_T]:
    """Run ``probe`` for every repository, creating tasks in bounded batches.

    The client semaphore caps real HTTP concurrency; chunking the gather also
    bounds task creation so very large orgs (hundreds or thousands of repos) do
    not allocate every task at once. A failing probe cancels its batch before
    the error propagates (see :func:`gather_all`). ``progress``, when given,
    is told as each repository's probe completes.
    """

    async def ticking(repo: Repo) -> _T:
        result = await probe(repo)
        if progress is not None:
            progress.repo_done()
        return result

    results: list[_T] = []
    for start in range(0, len(repos), REPO_BATCH):
        batch = repos[start : start + REPO_BATCH]
        results.extend(await gather_all(*(ticking(repo) for repo in batch)))
    return results


async def batched(
    fetch: Callable[[list[_K]], Coroutine[Any, Any, Mapping[_K, _V]]],
    items: list[_K],
    *,
    size: int,
    in_flight: int = GRAPH_PREFETCH_IN_FLIGHT,
    describe: str = "GraphQL batch",
) -> dict[_K, _V]:
    """Run ``fetch`` over ``items`` in batches, halving a batch GitHub refuses.

    Issues one ``fetch`` per ``size`` items with up to ``in_flight`` calls at
    once, and merges what each returns. The result keeps the order of
    ``items`` for the keys that were answered.

    The batch size adapts downwards. GitHub bounds GraphQL execution per query
    and reports a breach as a gateway timeout (502/504), a 200 with no
    ``data``, or a 200 whose ``errors`` say the query's resource limits were
    exceeded, so a query can fail purely because of how many items it
    carries; the same items then read fine in two smaller queries. When a
    batch fails that way after the transport's own retries, it is re-queued
    at half its size, and every batch issued after the failure is observed
    uses the smaller size too: a slow day at GitHub is a property of the
    collection, not of the one batch that happened to hit it first. The
    learned size only ever shrinks, so of two failures observed close
    together the smaller result wins. Batches already in flight when a
    failure is observed were issued at the old size, so on a bad day up to
    ``in_flight`` oversized batches (plus their retries) may fail before the
    smaller size takes effect -- a bounded cost, accepted for the overlap. A
    failure that a smaller query could not fix (a permission error, an
    exhausted rate limit, a 500/503 outage) propagates unchanged, as does a
    single-item query that still fails: at that point the API is genuinely
    unusable. The sibling queries still in flight are cancelled before the
    error propagates. ``fetch`` makes the splittable call (see
    :func:`client.batch_errors._batch_response`); this loop only acts on it.
    """
    out: dict[_K, _V] = {}
    pending = list(items)
    size = max(1, size)
    # Insertion-ordered, so failures observed together are handled in the
    # order their batches were issued.
    running: dict[asyncio.Task[Mapping[_K, _V]], list[_K]] = {}
    try:
        while pending or running:
            while pending and len(running) < in_flight:
                batch, pending = pending[:size], pending[size:]
                running[asyncio.create_task(fetch(batch))] = batch
            done, _ = await asyncio.wait(running, return_when=asyncio.FIRST_COMPLETED)
            for task in [t for t in running if t in done]:
                batch = running.pop(task)
                try:
                    out.update(dict(task.result()))
                except GraphBatchError as exc:
                    if len(batch) == 1 or not exc.splittable:
                        raise
                    size = min(size, len(batch) // 2)
                    log.warning(
                        "%s failed (%s) for a batch of %d; retrying them (and "
                        "the %d remaining) in batches of %d, since GitHub "
                        "bounds how much work one query may do",
                        describe,
                        exc.reason,
                        len(batch),
                        len(pending),
                        size,
                    )
                    pending = batch + pending
    finally:
        for task in running:
            task.cancel()
        await asyncio.gather(*running, return_exceptions=True)
    ordered: dict[_K, _V] = {key: out[key] for key in items if key in out}
    ordered.update(out)
    return ordered
