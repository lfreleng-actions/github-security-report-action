# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Report category metadata.

A single, render-surface-agnostic registry describing every reporting category
the tool produces. Each category carries its display title, the pass/fail
vocabulary used in the standardised summary footer, a documentation URL, and a
default human description. Renderers read this registry instead of hard-coding
per-category headings, labels and explanatory text, so a wording change here
flows to the terminal, Slack, Markdown and HTML surfaces at once.

The registry deliberately holds no behaviour and imports nothing from the rest
of the package except the leaf ``severity`` and ``secret_patterns`` modules
(which themselves import nothing from the package), so both the domain models
and the renderers can depend on it without a cycle. ``key`` values are the
stable identifiers used by the per-category configuration toggles, so treat
them as part of the config contract: rename with care.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from github_security_report.secret_patterns import (
    AI_DETECTED_SECRET_TYPES,
    GENERIC_SECRET_TYPES,
)
from github_security_report.severity import Severity


class CategoryKey(str, Enum):
    """Stable identifier for one reporting category (also the config key)."""

    CODEQL = "codeql"
    SCORECARD = "scorecard"
    ZIZMOR = "zizmor"
    AISLOP = "aislop"
    DEPENDABOT_ALERTS = "dependabot_alerts"
    SECRET_SCANNING = "secret_scanning"
    DEPENDABOT_ALERTS_ENABLED = "dependabot_alerts_enabled"
    DEPENDABOT_UPDATES_ENABLED = "dependabot_updates_enabled"
    DEPENDABOT_COOLDOWN = "dependabot_cooldown"
    RELEASES = "releases"
    MUTABLE_RELEASES = "mutable_releases"
    PRIVATE_VULNERABILITY_REPORTING = "private_vulnerability_reporting"
    GITHUB_ISSUES = "github_issues"
    PULL_REQUESTS = "pull_requests"
    PULL_REQUESTS_ASSIGNED = "pull_requests_assigned"


@dataclass(frozen=True)
class CategoryMeta:
    """Display and documentation metadata for one reporting category.

    ``pass_label`` names the healthy state (e.g. ``"Clean"``, ``"Immutable"``)
    and is what the summary footer reports as ``All <pass_label>`` when nothing
    needs attention. That collapse wants an adjectival label; a category whose
    counted wording is a noun phrase ("12 No open issues") sets
    ``pass_all_label`` to the word that reads correctly after "All" instead.
    ``fail_label`` names the actionable state for categories
    with a binary pass/fail axis (enablement, cooldown, mutability, release
    freshness); it is ``None`` for the severity-ranked signals, whose offenders
    are enumerated in the table itself rather than as a single failure count.
    ``description`` is the default explanatory text shown beneath the table on
    the Markdown and HTML surfaces; a builder may override it at runtime when
    the wording depends on configuration (e.g. the release-age thresholds).
    """

    key: CategoryKey
    title: str
    pass_label: str
    fail_label: str | None
    url: str
    description: str = ""
    # Alternative pass wording for the collapsed "All <label>" footer line,
    # when the counted wording would not read grammatically after "All".
    pass_all_label: str | None = None
    # The lowest finding severity that counts as a failure for this category.
    # A repository fails (appears as an offender) only when it carries a finding
    # at or above this rung; findings below it fold into the clean count. The
    # global default is MEDIUM, so Low and Informational findings pass; a
    # category may lower it (Zizmor uses INFORMATIONAL, so every finding
    # counts). Meaningful only for the severity-ranked signals; binary
    # categories ignore it. Overridable per category via the JSON config.
    fail_severity: Severity = Severity.MEDIUM


_CATEGORIES: dict[CategoryKey, CategoryMeta] = {
    CategoryKey.CODEQL: CategoryMeta(
        key=CategoryKey.CODEQL,
        title="CodeQL",
        pass_label="Clean",
        fail_label=None,
        url="https://codeql.github.com/",
        description=(
            "CodeQL code-scanning findings, ranked worst-first by severity. "
            "Each row shows a repository's open-alert counts."
        ),
    ),
    CategoryKey.SCORECARD: CategoryMeta(
        key=CategoryKey.SCORECARD,
        title="OpenSSF Scorecard",
        pass_label="Clean",
        fail_label=None,
        url="https://github.com/ossf/scorecard",
        description=(
            "OpenSSF Scorecard supply-chain health scores (a lower score is "
            "weaker). Ranked by the worst severity rung present in the table "
            "(most findings at that rung first), then weakest score first. "
            "Total counts findings only; the score is a health rating, not a "
            "finding count, so it is not part of that sum."
        ),
    ),
    CategoryKey.ZIZMOR: CategoryMeta(
        key=CategoryKey.ZIZMOR,
        title="Zizmor Static Analysis",
        pass_label="Clean",
        fail_label=None,
        url="https://github.com/zizmorcore/zizmor",
        description=(
            "Zizmor static analysis of GitHub Actions workflows, ranked "
            "worst-first by severity."
        ),
        # The organisation scan pipeline runs zizmor with an
        # 'informational' floor, so every finding it can report reaches the
        # SARIF. Match that here: any zizmor finding counts, at any
        # severity. This mirrors the ruleset-enforced PR gate, which blocks
        # on any finding regardless of level.
        #
        # zizmor emits both Low and Informational findings at SARIF level
        # "note", and the code-scanning alerts API exposes only that level
        # (not zizmor's own severity property), so the two are
        # indistinguishable here. Cutting at INFORMATIONAL sidesteps the
        # ambiguity: both surface either way.
        fail_severity=Severity.INFORMATIONAL,
    ),
    CategoryKey.AISLOP: CategoryMeta(
        key=CategoryKey.AISLOP,
        title="AI Slop Analysis",
        pass_label="Clean",
        fail_label=None,
        url="https://github.com/scanaislop/aislop",
        description=(
            "aislop AI-slop / code-quality findings, ranked worst-first by severity."
        ),
        # aislop, like zizmor, populates only the SARIF level axis
        # (error/warning/note); "note" normalises to LOW (see severity.py), so
        # any aislop finding fails -- matching the ruleset-enforced PR gate.
        fail_severity=Severity.LOW,
    ),
    CategoryKey.DEPENDABOT_ALERTS: CategoryMeta(
        key=CategoryKey.DEPENDABOT_ALERTS,
        title="Dependabot: Security Alerts",
        pass_label="Clean",
        fail_label=None,
        url=(
            "https://docs.github.com/en/code-security/dependabot/"
            "dependabot-alerts/about-dependabot-alerts"
        ),
        description=(
            "Open Dependabot alerts for vulnerable dependencies, counted by "
            "severity per repository."
        ),
    ),
    CategoryKey.SECRET_SCANNING: CategoryMeta(
        key=CategoryKey.SECRET_SCANNING,
        title="Secret Scanning",
        pass_label="Clean",
        fail_label=None,
        url=(
            "https://docs.github.com/en/code-security/secret-scanning/"
            "about-secret-scanning"
        ),
        description=(
            "Open secret-scanning alerts. Each row shows a repository's count "
            "of detected, unresolved secrets. All three of GitHub's pattern "
            "categories are covered: its default provider patterns, the "
            f"{len(GENERIC_SECRET_TYPES)} generic patterns (private keys, "
            "database connection strings, HTTP authentication headers) and "
            f"the {len(AI_DETECTED_SECRET_TYPES)} AI-detected pattern "
            "(passwords). The alerts API omits the latter two unless they are "
            "requested by name."
        ),
    ),
    CategoryKey.DEPENDABOT_ALERTS_ENABLED: CategoryMeta(
        key=CategoryKey.DEPENDABOT_ALERTS_ENABLED,
        title="Dependabot: Alerts Enabled",
        pass_label="Enabled",
        fail_label="Not enabled",
        url=(
            "https://docs.github.com/en/code-security/dependabot/"
            "dependabot-alerts/configuring-dependabot-alerts"
        ),
        description=(
            "Repositories with Dependabot security alerts disabled. Enable "
            "them so vulnerable dependencies surface as alerts."
        ),
    ),
    CategoryKey.DEPENDABOT_UPDATES_ENABLED: CategoryMeta(
        key=CategoryKey.DEPENDABOT_UPDATES_ENABLED,
        title="Dependabot: Security Updates",
        pass_label="Enabled",
        fail_label="Not enabled",
        url=(
            "https://docs.github.com/en/code-security/concepts/"
            "supply-chain-security/dependabot-security-updates"
        ),
        description=(
            "Repositories with Dependabot security updates disabled. Enable "
            "them so fixes for vulnerable dependencies arrive as pull requests "
            "automatically."
        ),
    ),
    CategoryKey.DEPENDABOT_COOLDOWN: CategoryMeta(
        key=CategoryKey.DEPENDABOT_COOLDOWN,
        title="Dependabot: Cooldown Settings",
        pass_label="Enabled",
        fail_label="Without cooldown",
        url=(
            "https://docs.github.com/en/code-security/reference/"
            "supply-chain-security/dependabot-options-reference#cooldown-"
        ),
        description=(
            "Repositories whose Dependabot configuration omits an update "
            "cooldown. A cooldown is mandatory; any cooldown value passes. "
            "Repositories with no Dependabot configuration do not appear here."
        ),
    ),
    CategoryKey.RELEASES: CategoryMeta(
        key=CategoryKey.RELEASES,
        title="Releases / Tagging",
        pass_label="Current",
        fail_label="Overdue",
        url=(
            "https://docs.github.com/en/repositories/"
            "releasing-projects-on-github/about-releases"
        ),
        description=(
            "Repositories ranked by combined release and tag staleness "
            "(oldest first). A repository with neither a release nor a tag "
            "ranks highest."
        ),
    ),
    CategoryKey.MUTABLE_RELEASES: CategoryMeta(
        key=CategoryKey.MUTABLE_RELEASES,
        title="Mutable Releases",
        pass_label="Immutable",
        fail_label="Mutable",
        url=(
            "https://docs.github.com/en/code-security/concepts/"
            "supply-chain-security/immutable-releases"
        ),
        description=(
            "Repositories whose latest or last-published release is mutable. "
            "Republish them as immutable releases so a published artifact "
            "cannot change after the fact."
        ),
    ),
    CategoryKey.PRIVATE_VULNERABILITY_REPORTING: CategoryMeta(
        key=CategoryKey.PRIVATE_VULNERABILITY_REPORTING,
        title="Private Vulnerability Reporting",
        pass_label="Enabled",
        fail_label="Not enabled",
        url=(
            "https://docs.github.com/en/code-security/security-advisories/"
            "working-with-repository-security-advisories/"
            "configuring-private-vulnerability-reporting-for-a-repository"
        ),
        description=(
            "Repositories with private vulnerability reporting disabled. Enable "
            "it so security researchers can privately report vulnerabilities "
            "instead of disclosing them publicly."
        ),
    ),
    CategoryKey.GITHUB_ISSUES: CategoryMeta(
        key=CategoryKey.GITHUB_ISSUES,
        title="GitHub Issues",
        pass_label="No open issues",
        # "All No open issues" does not parse; the collapsed line reads
        # "All Clean", matching the other categories' vocabulary.
        pass_all_label="Clean",
        fail_label="With open issues",
        url="https://docs.github.com/en/issues",
        description=(
            "Open issues per repository, split by label into the configured "
            "classes. Issues carrying none of the configured labels count as "
            "Other; issues with no labels at all count as Untriaged, which is "
            "the column to watch -- an unlabelled issue has not been triaged. "
            "Ext counts issues raised from outside the organisation, computed "
            "from the collected window rather than the whole backlog. "
            "Ranked by total open issues, then by Untriaged."
        ),
    ),
    CategoryKey.PULL_REQUESTS: CategoryMeta(
        key=CategoryKey.PULL_REQUESTS,
        title="Pull Requests",
        pass_label="No open pull requests",
        # "All No open pull requests" does not parse; the collapsed line reads
        # "All Clean", matching the other categories' vocabulary.
        pass_all_label="Clean",
        fail_label="With open pull requests",
        url="https://docs.github.com/en/pull-requests",
        description=(
            "Open pull requests per repository, split by who raised them and "
            "what is holding them up. Human and Auto partition the total by "
            "author: Auto counts recognised automation (Dependabot, "
            "pre-commit.ci, Renovate and the like), Human counts everyone "
            "else. Ext counts the human pull requests raised from outside the "
            "organisation, so it is a subset of Human and never counts a bot. "
            "Conflict counts pull requests blocked on a merge conflict; Fail "
            "counts those whose latest checks did not pass, which includes "
            "optional checks and so is not by itself proof that a merge is "
            "blocked; Copilot counts those still carrying an unresolved review "
            "thread opened by GitHub's automated code reviewer; Draft counts "
            "those still marked as drafts. Those four "
            "are independent of the author split and of each other, so one "
            "pull request can appear in more than one of them. Ranked by total "
            "open pull requests, then by those failing, conflicting or "
            "awaiting review, counted once each. "
            "Beneath the totals, Unassigned counts the pull requests nobody "
            "has picked up; the rest are on somebody's plate. A terminal run "
            "that authenticated as a personal account splits that remainder "
            "again, into the reader's own queue and everyone else's. A "
            "published report leaves that split out, since its readers are not "
            "the account it ran as."
        ),
    ),
    CategoryKey.PULL_REQUESTS_ASSIGNED: CategoryMeta(
        key=CategoryKey.PULL_REQUESTS_ASSIGNED,
        title="Assigned to Me",
        pass_label="None assigned",
        pass_all_label="Clean",
        fail_label="With assigned pull requests",
        url="https://docs.github.com/en/pull-requests",
        description=(
            "The Pull Requests table narrowed to those assigned to the account "
            "this report ran as -- a personal review queue, so it changes with "
            "the token used. Columns carry the same meaning as the table "
            "above. Empty when the account has nothing assigned; a run that "
            "authenticated as a bot or App has no personal queue at all, and "
            "omits this table rather than reporting an empty one."
        ),
    ),
}


def category_meta(key: CategoryKey) -> CategoryMeta:
    """The :class:`CategoryMeta` for ``key`` (registry lookup)."""
    return _CATEGORIES[key]


# Categories rendered as sub-tables beneath another category rather than as
# sections of their own. The three Dependabot posture tables qualify their
# parent signal -- "Alerts Enabled" means nothing adrift from "Dependabot:
# Security Alerts" -- so they travel with it and cannot be positioned
# independently. Named here rather than in the layout module so the config
# schema can refuse to accept one in an ordering list, which would otherwise be
# a setting that validates and then does nothing.
NESTED_CATEGORIES: frozenset[CategoryKey] = frozenset(
    {
        CategoryKey.DEPENDABOT_ALERTS_ENABLED,
        CategoryKey.DEPENDABOT_UPDATES_ENABLED,
        CategoryKey.DEPENDABOT_COOLDOWN,
    }
)


def orderable_categories() -> tuple[CategoryMeta, ...]:
    """Categories an ordering list may name, in registry order.

    Every category except the nested ones, which have no position of their own
    to configure.
    """
    return tuple(
        meta for meta in _CATEGORIES.values() if meta.key not in NESTED_CATEGORIES
    )


def all_categories() -> tuple[CategoryMeta, ...]:
    """Every category's metadata, in registry (render) order."""
    return tuple(_CATEGORIES.values())
