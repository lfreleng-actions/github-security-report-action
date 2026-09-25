# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""The remediation data model: the client it writes through, targets, outcomes.

Shared by the registry in :mod:`github_security_report.remediate` and the
CodeQL cleanup in :mod:`.codeql`, and free of either, so both can depend on it.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Protocol

from github_security_report.categories import CategoryMeta
from github_security_report.codeql import CleanupItem
from github_security_report.models import Repo
from github_security_report.report import OrgReport


class RemediationClient(Protocol):
    """The write surface a remediator needs (a subset of ``GitHubClient``).

    Each method enables one feature on one repository and returns
    ``(ok, note)``: ``ok`` is whether the write succeeded, and ``note`` carries
    a short diagnostic (an error status/body on failure, or a hint such as
    ``"accepted (async)"`` on success). Tests supply an in-memory fake.
    """

    async def enable_dependabot_alerts(
        self, org: str, repo: str
    ) -> tuple[bool, str]: ...

    async def enable_dependabot_security_updates(
        self, org: str, repo: str
    ) -> tuple[bool, str]: ...

    async def enable_private_vulnerability_reporting(
        self, org: str, repo: str
    ) -> tuple[bool, str]: ...

    async def enable_codeql_default_setup(
        self, org: str, repo: str
    ) -> tuple[bool, str]: ...

    async def enable_secret_scanning(self, org: str, repo: str) -> tuple[bool, str]: ...

    async def enable_auto_merge(self, org: str, repo: str) -> tuple[bool, str]: ...

    async def delete_codeql_analyses(
        self, org: str, repo: str, analysis_ids: tuple[int, ...]
    ) -> tuple[bool, str]: ...

    async def enable_workflow(
        self, org: str, repo: str, path: str
    ) -> tuple[bool, str]: ...

    async def codeql_alert_holders(
        self, org: str, repo: str, branch: str
    ) -> list[frozenset[str]] | None: ...


# Outcome states. "would <verb>" is the dry-run preview; the past participle
# and "FAILED" are the two terminal states after an apply; "refused" is a
# target a guard stopped, in either mode, before anything was written.
_FAILED = "FAILED"
_REFUSED = "refused"

# The past participle of each verb a remediator acts with.
_DONE = {"enable": "enabled", "delete": "deleted", "re-enable": "re-enabled"}


@dataclass(frozen=True)
class RepoOutcome:
    """The result of (planning to) remediate one target.

    ``name`` is the target as the output names it: a repository, or for the
    CodeQL cleanup a repository and configuration. ``verb`` is what was, or
    would be, done to it.
    """

    name: str
    action: str  # "would <verb>" | past participle | "FAILED" | "refused"
    note: str = ""
    verb: str = "enable"

    @property
    def failed(self) -> bool:
        return self.action == _FAILED

    @property
    def refused(self) -> bool:
        return self.action == _REFUSED


@dataclass(frozen=True)
class CategoryRemediation:
    """Every repository outcome for one remediated category."""

    category: CategoryMeta
    outcomes: tuple[RepoOutcome, ...]

    @property
    def failures(self) -> int:
        return sum(1 for o in self.outcomes if o.failed)


# --------------------------------------------------------------------------- #
# Targets
# --------------------------------------------------------------------------- #
@dataclass
class _AlertHolders:
    """One repository's open-alert holders, read once and shared by its targets."""

    loaded: bool = False
    holders: list[frozenset[str]] | None = None


@dataclass(frozen=True)
class _Target:
    """One unit of remediation work, with anything its write needs."""

    repo: Repo
    name: str
    verb: str = "enable"
    # Set when the plan already knows this target must not be written.
    refusal: str | None = None
    # The CodeQL cleanup's planned item; None for a feature toggle.
    cleanup: CleanupItem | None = None
    # Every category this run plans to delete in the same repository, so the
    # alert guard judges the batch, not one deletion in isolation.
    batch: frozenset[str] = frozenset()
    # The repository's alert holders, shared by all of its cleanup targets.
    alerts: _AlertHolders = field(default_factory=_AlertHolders)


def _repo_targets(
    offenders: Callable[[OrgReport], list[Repo]],
) -> Callable[[OrgReport], list[_Target]]:
    """A feature toggle's targets: one per offending repository."""

    def _get(report: OrgReport) -> list[_Target]:
        return [_Target(repo, repo.name) for repo in offenders(report)]

    return _get
