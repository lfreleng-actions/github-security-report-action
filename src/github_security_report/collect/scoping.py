# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Which repositories a run covers.

:func:`resolve_scope` lists an organisation's repositories and applies the
scoping rules (see :mod:`github_security_report.scope`), narrowed to a named
selection when a run has one. ``remediate --repos`` checks that selection
first with :func:`check_named_repos`, separating the named repositories in
scope from those the configuration excludes, so a typo or an excluded
repository stops the run before any read or write.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass

from github_security_report import scope
from github_security_report.collect.protocols import ClientProtocol
from github_security_report.config import OrgConfig, ReportConfig
from github_security_report.models import Repo

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class OrgScope:
    """The repositories a run covers, and whether the listing was complete."""

    status: int
    in_scope: list[Repo]
    excluded: list[Repo]

    @property
    def partial(self) -> bool:
        """Whether the listing was incomplete, so the report must say so."""
        return self.status != 200


async def resolve_scope(
    client: ClientProtocol,
    org_cfg: OrgConfig,
    report_cfg: ReportConfig,
) -> OrgScope:
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
    exclude_names = {name.lower() for name in org_cfg.exclude}
    return OrgScope(
        status=status,
        in_scope=in_scope,
        excluded=[repo for repo in repos if repo.name.lower() in exclude_names],
    )


@dataclass(frozen=True)
class NamedRepos:
    """What a ``--repos`` selection matched in one organisation."""

    # Named, and in scope: these are what a narrowed run acts on.
    in_scope: tuple[Repo, ...]
    # Named, but removed by the scoping rules, each with the reason why.
    excluded: tuple[tuple[Repo, str], ...]
    # The listing was incomplete, so a name matching nothing may yet exist.
    partial: bool


async def check_named_repos(
    client: ClientProtocol,
    org_cfg: OrgConfig,
    report_cfg: ReportConfig,
    only: Sequence[scope.RepoRef],
) -> NamedRepos:
    """Match a repository selection against one organisation, reading nothing else.

    One repository listing, so a caller can reject unknown or excluded names
    before a run reads or writes anything.
    """
    status, repos = await client.list_org_repos(org_cfg.name)
    exclude = set(org_cfg.exclude)
    in_scope: list[Repo] = []
    excluded: list[tuple[Repo, str]] = []
    for repo in scope.select_named(org_cfg.name, repos, only):
        decision = scope.decide(
            repo,
            include_archived=report_cfg.include_archived,
            include_test=report_cfg.include_test,
            exclude=exclude,
        )
        if decision.included:
            in_scope.append(repo)
        else:
            excluded.append((repo, decision.reason))
    return NamedRepos(tuple(in_scope), tuple(excluded), partial=status != 200)


def selected_scope(repos: Sequence[Repo]) -> OrgScope:
    """The scope of a run limited to already-validated repositories.

    Built from the repositories :func:`check_named_repos` matched in scope,
    rather than a second listing: a listing that came back incomplete this
    time could silently drop a requested repository from a run that then
    reported nothing to do.
    """
    return OrgScope(status=200, in_scope=list(repos), excluded=[])
