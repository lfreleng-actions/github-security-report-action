# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""The batched GraphQL prefetch behind every per-repository probe.

One aliased query carries a batch of repositories, several queries run at
once, and the batch size adapts downwards when GitHub cannot finish a query in
time. Org-mode collection (:mod:`collect.org`) awaits the whole prefetch
before any per-repository probe starts.
"""

from __future__ import annotations

import asyncio
import logging

from github_security_report.client import GraphBatchError
from github_security_report.collect.protocols import ClientProtocol
from github_security_report.models import Repo, RepoGraphData

log = logging.getLogger(__name__)

# GraphQL prefetch queries kept in flight at once. Each takes seconds on
# GitHub's side while holding one client slot, so a serial prefetch left the
# rest of the semaphore idle. A constant until a measurement justifies making
# it a setting; it is bounded by the client semaphore regardless.
GRAPH_PREFETCH_IN_FLIGHT = 4


async def collect_graph(
    client: ClientProtocol, org: str, repos: list[Repo], *, batch_size: int
) -> dict[str, RepoGraphData]:
    """Prefetch batched GraphQL data for every in-scope repository.

    Issues one aliased query per ``batch_size`` repositories
    (``report.graph_batch``), folding the former per-repo Dependabot-enabled,
    latest-release, latest-tag and ``dependabot.yml`` round-trips into a
    handful of requests, with up to :data:`GRAPH_PREFETCH_IN_FLIGHT` queries in
    flight at once. The result keeps the order of ``repos``.

    The batch size adapts downwards. GitHub bounds GraphQL execution per query
    and reports a breach as a gateway timeout (502/504), a 200 with no
    ``data``, or a 200 whose ``errors`` say the query's resource limits were
    exceeded, so a query can fail purely because of how many repositories it
    carries; the same repositories then read fine in two smaller queries. When
    a batch fails that way after the transport's own retries, it is re-queued
    at half its size, and every batch issued after the failure is observed
    uses the smaller size too: a slow day at GitHub is a property of the
    collection, not of the one batch that happened to hit it first. The
    learned size only ever shrinks, so of two failures observed close together
    the smaller result wins. Batches already in flight when a failure is
    observed were issued at the old size, so on a bad day up to
    :data:`GRAPH_PREFETCH_IN_FLIGHT` oversized batches (plus their retries) may
    fail before the smaller size takes effect -- a bounded cost, accepted for
    the overlap. The learned size is scoped to the organisation rather than
    carried across a multi-org run: each organisation collects with its own
    client, may configure its own ``graph_batch``, and carries its own amount
    of data per repository. A failure that a smaller query could not fix (a
    permission error, an exhausted rate limit, a 500/503 outage) propagates
    unchanged, as does a single-repository query that still fails: at that
    point the API is genuinely unusable and aborting beats fabricating "never
    released" for the repository. The sibling queries still in flight are
    cancelled before the error propagates. The client makes the splittable
    call (see :func:`client.batch_errors._batch_response`); this loop only
    acts on it.
    """
    names = [repo.name for repo in repos]
    graph: dict[str, RepoGraphData] = {}
    pending = list(names)
    size = max(1, batch_size)
    # Insertion-ordered, so failures observed together are handled in the
    # order their batches were issued.
    in_flight: dict[asyncio.Task[dict[str, RepoGraphData]], list[str]] = {}
    try:
        while pending or in_flight:
            while pending and len(in_flight) < GRAPH_PREFETCH_IN_FLIGHT:
                batch, pending = pending[:size], pending[size:]
                query = asyncio.create_task(client.repo_graph_batch(org, batch))
                in_flight[query] = batch
            done, _ = await asyncio.wait(in_flight, return_when=asyncio.FIRST_COMPLETED)
            for query in [q for q in in_flight if q in done]:
                batch = in_flight.pop(query)
                try:
                    graph.update(query.result())
                except GraphBatchError as exc:
                    if len(batch) == 1 or not exc.splittable:
                        raise
                    size = min(size, len(batch) // 2)
                    log.warning(
                        "GraphQL prefetch for %s failed (%s) for a batch of %d "
                        "repositories; retrying them (and the %d remaining) in "
                        "batches of %d, since GitHub bounds how much work one "
                        "query may do",
                        org,
                        exc.reason,
                        len(batch),
                        len(pending),
                        size,
                    )
                    pending = batch + pending
    finally:
        for query in in_flight:
            query.cancel()
        await asyncio.gather(*in_flight, return_exceptions=True)
    ordered = {name: graph[name] for name in names if name in graph}
    ordered.update(graph)
    return ordered
