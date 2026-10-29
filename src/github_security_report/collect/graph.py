# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""The batched GraphQL prefetch behind every per-repository probe.

One aliased query carries a batch of repositories, several queries run at
once, and the batch size adapts downwards when GitHub cannot finish a query in
time (see :func:`~github_security_report.collect.context.batched`). Org-mode
collection (:mod:`collect.org`) awaits the whole prefetch before any
per-repository probe starts.
"""

from __future__ import annotations

from github_security_report.collect.context import (
    GRAPH_PREFETCH_IN_FLIGHT,
    batched,
)
from github_security_report.collect.protocols import ClientProtocol
from github_security_report.models import Repo, RepoGraphData

__all__ = ["GRAPH_PREFETCH_IN_FLIGHT", "collect_graph"]


async def collect_graph(
    client: ClientProtocol, org: str, repos: list[Repo], *, batch_size: int
) -> dict[str, RepoGraphData]:
    """Prefetch batched GraphQL data for every in-scope repository.

    Issues one aliased query per ``batch_size`` repositories
    (``report.graph_batch``), folding the former per-repo Dependabot-enabled,
    latest-release, latest-tag and ``dependabot.yml`` round-trips into a
    handful of requests, with up to :data:`GRAPH_PREFETCH_IN_FLIGHT` queries in
    flight at once. The result keeps the order of ``repos``.

    A batch GitHub cannot finish is halved and retried; a failure a smaller
    query could not fix aborts the run rather than fabricating "never
    released" for the repository. Both policies live in :func:`batched`. The
    learned size is scoped to the organisation rather than carried across a
    multi-org run: each organisation collects with its own client, may
    configure its own ``graph_batch``, and carries its own amount of data per
    repository.
    """
    return await batched(
        lambda names: client.repo_graph_batch(org, names),
        [repo.name for repo in repos],
        size=batch_size,
        describe=f"GraphQL prefetch for {org}",
    )
