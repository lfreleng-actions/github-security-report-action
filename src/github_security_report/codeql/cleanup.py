# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""The cleanup plan for stale CodeQL configurations: what may be done, and why.

Pure planning over the collected :class:`CodeQLFacts`, in the same terms the
Stale Configurations table reports, so the plan acts on exactly the rows the
reader was shown. Each stale configuration yields at most one item:

- **Delete** an orphaned configuration: one that can never upload again (its
  setup is gone, or blocked by default setup). Deleting removes its analyses
  and with them the stale "results may be out of date" warning.
- **Re-enable** the workflow behind a configuration that GitHub disabled for
  repository inactivity; that restores the scan rather than discarding it.

Every other cause is left alone: it may yet resume, or it needs a person.

A deletion is *refused* while no current configuration scans its language.
The stale results are then the only record of that language, and removing
them would turn "scanned, but out of date" into "never scanned" without
anything having improved. Add scanning for the language first; the refusal
names it. Whether a deletion would close an open alert needs a network read,
so the remediator checks that separately before any write.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum

from github_security_report.codeql.facts import (
    CodeQLConfiguration,
    CodeQLFacts,
    StaleCause,
)
from github_security_report.codeql.tables import stale_cause
from github_security_report.models import Repo


class CleanupAction(str, Enum):
    """What remediation does about one stale configuration.

    The value is the verb the remediation output uses.
    """

    DELETE = "delete"
    REENABLE_WORKFLOW = "re-enable"


@dataclass(frozen=True)
class CleanupItem:
    """One planned action on one stale configuration."""

    repo: Repo
    config: CodeQLConfiguration
    cause: StaleCause
    action: CleanupAction
    # Why this item must not be acted on, or None when it may be.
    refusal: str | None = None

    @property
    def label(self) -> str:
        """The repository and the configuration, as remediation output names it."""
        language = self.config.language or "unknown language"
        return f"{self.repo.name} ({self.config.setup.value}, {language})"


def plan_cleanup(facts: Sequence[CodeQLFacts], *, stale_days: int) -> list[CleanupItem]:
    """The cleanup items for every stale configuration that has a safe fix.

    Only fully readable repositories are planned: an unknown state is never
    acted on, matching every other remediator. Items come out in repository
    order, stalest configuration first within each.
    """
    items: list[CleanupItem] = []
    for repo_facts in sorted(facts, key=lambda f: f.repo.name):
        if not repo_facts.readable:
            continue
        current = repo_facts.current_languages(stale_days)
        stale = sorted(
            repo_facts.stale_configurations(stale_days),
            key=lambda c: (c.scan_order, c.category),
        )
        for config in stale:
            item = _plan_one(repo_facts, config, current)
            if item is not None:
                items.append(item)
    return items


def _plan_one(
    facts: CodeQLFacts, config: CodeQLConfiguration, current: frozenset[str]
) -> CleanupItem | None:
    cause = stale_cause(config, facts)
    if cause.reenable_workflow:
        return CleanupItem(facts.repo, config, cause, CleanupAction.REENABLE_WORKFLOW)
    if not cause.orphaned:
        return None
    refusal = None
    if config.language is None or config.language not in current:
        refusal = (
            f"no current configuration scans {config.language or 'its language'}; "
            "add scanning for it first"
        )
    elif not config.analysis_ids:
        refusal = "no analyses recorded to delete"
    return CleanupItem(facts.repo, config, cause, CleanupAction.DELETE, refusal)
