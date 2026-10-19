# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""The batched GraphQL prefetch behind every per-repository probe.

One aliased query carries a batch of repositories, and the batch size adapts
downwards when GitHub cannot finish a query in time. Org-mode collection
(:mod:`collect.org`) awaits the whole prefetch before any per-repository probe
starts.
"""

from __future__ import annotations

import logging

from github_security_report.client import GraphBatchError
from github_security_report.collect.protocols import ClientProtocol
from github_security_report.models import Repo, RepoGraphData

log = logging.getLogger(__name__)


async def collect_graph(
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
