# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Structural types for the client subset orchestration depends on.

Orchestration accepts any object satisfying these protocols, so both collection
modes are testable without a live network (see ``tests/test_collect.py``).
:class:`ClientProtocol` is the org-mode surface (bulk sweeps plus bounded
per-repo probes); :class:`RepoClientProtocol` is the smaller repo-mode surface
built entirely from per-repository endpoints.
"""

from __future__ import annotations

from typing import Protocol

from github_security_report.models import Repo, RepoGraphData


class ClientProtocol(Protocol):
    """The subset of :class:`client.GitHubClient` that orchestration needs."""

    async def list_org_repos(self, org: str) -> tuple[int, list[Repo]]:
        """List an organisation's repositories with the read status."""
        raise NotImplementedError

    async def org_bulk_alerts(self, org: str, kind: str) -> tuple[int, list[dict]]:
        """Fetch an organisation's alerts of one kind in a single sweep."""
        raise NotImplementedError

    async def org_workflow_rulesets(self, org: str) -> tuple[int, list[dict]]:
        """Fetch the organisation's workflow rulesets."""
        raise NotImplementedError

    async def org_members(self, org: str) -> frozenset[str] | None:
        """Return the organisation's member logins, normalised.

        ``None`` means membership could not be read in full, which is not the
        same as an organisation with no members: the caller must not treat a
        missing member as evidence that an author is an outsider.
        """
        raise NotImplementedError

    async def viewer_login(self) -> str:
        """Return the authenticated account's login, lower-cased.

        An empty string means the account could not be read, in which case no
        pull request counts as assigned to the caller.
        """
        raise NotImplementedError

    async def code_scanning_tools(
        self, org: str, repo: str, tools: tuple[str, ...] | None = None
    ) -> tuple[int, set[str]]:
        """Return the code-scanning tools enabled on a repository."""
        raise NotImplementedError

    async def code_scanning_tool_present(self, org: str, repo: str, tool: str) -> bool:
        """Whether ``tool`` has uploaded code-scanning analyses to the repo."""
        raise NotImplementedError

    async def secret_scanning_status(self, org: str, repo: str) -> int:
        """Return the secret-scanning read status for a repository."""
        raise NotImplementedError

    async def scorecard_score(self, org: str, repo: str) -> tuple[int, float | None]:
        """Return a repository's OpenSSF Scorecard score and read status."""
        raise NotImplementedError

    async def automated_security_fixes(self, org: str, repo: str) -> bool | None:
        """Whether Dependabot automated security fixes are enabled."""
        raise NotImplementedError

    async def private_vulnerability_reporting(self, org: str, repo: str) -> bool | None:
        """Whether private vulnerability reporting is enabled for a repository."""
        raise NotImplementedError

    async def repo_graph_batch(
        self, org: str, names: list[str]
    ) -> dict[str, RepoGraphData]:
        """Fetch batched per-repo GraphQL data keyed by repository name."""
        raise NotImplementedError


class RepoClientProtocol(Protocol):
    """Extra per-repo methods needed for repo mode."""

    async def get_repo(self, org: str, repo: str) -> Repo | None:
        """Fetch a single repository, or None when it is absent."""
        raise NotImplementedError

    async def code_scanning_tools(
        self, org: str, repo: str, tools: tuple[str, ...] | None = None
    ) -> tuple[int, set[str]]:
        """Return the code-scanning tools enabled on a repository."""
        raise NotImplementedError

    async def repo_code_scanning_alerts(
        self, org: str, repo: str
    ) -> tuple[int, list[dict]]:
        """Fetch a repository's code-scanning alerts with the read status."""
        raise NotImplementedError

    async def repo_secret_scanning(self, org: str, repo: str) -> tuple[int, int, int]:
        """Return a repo's secret-scanning enablement, read status and count."""
        raise NotImplementedError

    async def dependabot_enabled(self, org: str, repo: str) -> bool | None:
        """Whether Dependabot alerts are enabled for a repository."""
        raise NotImplementedError

    async def repo_dependabot_alerts(
        self, org: str, repo: str
    ) -> tuple[int, list[dict]]:
        """Fetch a repository's Dependabot alerts with the read status."""
        raise NotImplementedError

    async def repo_branch_rules(
        self, org: str, repo: str, branch: str
    ) -> tuple[int, list[dict]]:
        """Fetch the branch-protection rules for a repository branch."""
        raise NotImplementedError

    async def scorecard_score(self, org: str, repo: str) -> tuple[int, float | None]:
        """Return a repository's OpenSSF Scorecard score and read status."""
        raise NotImplementedError
