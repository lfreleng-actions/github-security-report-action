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
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import TypeVar

from github_security_report.collect.protocols import ClientProtocol
from github_security_report.models import Repo, RepoGraphData

_T = TypeVar("_T")

# Per-repo probe tasks are created in batches of this size so very large orgs
# do not allocate every task at once (HTTP concurrency is bounded separately by
# the client semaphore).
REPO_BATCH = 50

# Repositories per batched GraphQL prefetch query. Kept smaller than the REST
# probe batch because each aliased sub-query expands the single request's cost.
GRAPH_BATCH = 25


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


async def gather_in_batches(
    repos: list[Repo], probe: Callable[[Repo], Awaitable[_T]]
) -> list[_T]:
    """Run ``probe`` for every repository, creating tasks in bounded batches.

    The client semaphore caps real HTTP concurrency; chunking the gather also
    bounds task creation so very large orgs (hundreds or thousands of repos) do
    not allocate every task at once.
    """
    results: list[_T] = []
    for start in range(0, len(repos), REPO_BATCH):
        batch = repos[start : start + REPO_BATCH]
        results.extend(await asyncio.gather(*(probe(repo) for repo in batch)))
    return results
