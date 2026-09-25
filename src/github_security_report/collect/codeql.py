# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Collection of the CodeQL scan-health facts, one repository at a time.

Two REST reads per repository, issued together: the full CodeQL analysis
history of the default branch, and the default-setup state. The branch head's
commit date comes from the batched GraphQL prefetch. A third read, the Actions
state of an advanced workflow, is spent only on the configurations already
found stale, since only those need a cause explained.
"""

from __future__ import annotations

import asyncio
from dataclasses import replace
from types import MappingProxyType

from github_security_report.codeql import CodeQLFacts
from github_security_report.collect.context import (
    OrgCollectContext,
    gather_in_batches,
)
from github_security_report.models import Repo


async def _codeql_for_repo(
    repo: Repo, ctx: OrgCollectContext, stale_days: int
) -> CodeQLFacts:
    (status, configurations), default_setup = await asyncio.gather(
        ctx.client.codeql_configurations(ctx.org, repo.name, repo.default_branch),
        ctx.client.codeql_default_setup(ctx.org, repo.name),
    )
    facts = CodeQLFacts(
        repo=repo,
        analyses_status=status,
        configurations=configurations,
        head_committed_at=ctx.graph_for(repo.name).head_committed_at,
        default_setup=default_setup,
    )
    if not facts.readable:
        # A partial history or an unknown head: both tables report this
        # repository as unknown, so its workflow states would go unused.
        return facts
    paths = sorted(
        {
            path
            for config in facts.stale_configurations(stale_days)
            if (path := config.workflow_path) is not None
        }
    )
    if not paths:
        return facts
    states = await asyncio.gather(
        *(ctx.client.workflow_state(ctx.org, repo.name, path) for path in paths)
    )
    read = {path: state for path, state in zip(paths, states, strict=True) if state}
    return replace(facts, workflow_states=MappingProxyType(read))


async def collect_codeql_facts(
    in_scope: list[Repo], ctx: OrgCollectContext, *, stale_days: int
) -> list[CodeQLFacts]:
    """The CodeQL scan-health facts for every in-scope repository."""
    return await gather_in_batches(
        in_scope, lambda repo: _codeql_for_repo(repo, ctx, stale_days)
    )
