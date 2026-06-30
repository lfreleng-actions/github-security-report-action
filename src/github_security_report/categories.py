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
of the package except the leaf ``severity`` module (which itself imports nothing
from the package), so both the domain models and the renderers can depend on it
without a cycle. ``key`` values are the stable identifiers used by the
per-category configuration toggles, so treat them as part of the config
contract: rename with care.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from github_security_report.severity import Severity


class CategoryKey(str, Enum):
    """Stable identifier for one reporting category (also the config key)."""

    CODEQL = "codeql"
    SCORECARD = "scorecard"
    ZIZMOR = "zizmor"
    DEPENDABOT_ALERTS = "dependabot_alerts"
    SECRET_SCANNING = "secret_scanning"
    DEPENDABOT_ALERTS_ENABLED = "dependabot_alerts_enabled"
    DEPENDABOT_UPDATES_ENABLED = "dependabot_updates_enabled"
    DEPENDABOT_COOLDOWN = "dependabot_cooldown"
    RELEASES = "releases"
    MUTABLE_RELEASES = "mutable_releases"


@dataclass(frozen=True)
class CategoryMeta:
    """Display and documentation metadata for one reporting category.

    ``pass_label`` names the healthy state (e.g. ``"Clean"``, ``"Immutable"``)
    and is what the summary footer reports as ``All <pass_label>`` when nothing
    needs attention. ``fail_label`` names the actionable state for categories
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
    # The lowest finding severity that counts as a failure for this category.
    # A repository fails (appears as an offender) only when it carries a finding
    # at or above this rung; findings below it fold into the clean count. The
    # global default is MEDIUM, so Low and Informational findings pass; a
    # category may lower it (Zizmor uses LOW, so only Informational passes).
    # Meaningful only for the severity-ranked signals; binary categories ignore
    # it. Overridable per category via the JSON config.
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
            "weaker), ranked weakest-first."
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
        # Zizmor's advisory "note" findings normalise to informational; only
        # those pass. A low-or-higher zizmor finding is treated as a failure.
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
        title="Secret scanning",
        pass_label="Clean",
        fail_label=None,
        url=(
            "https://docs.github.com/en/code-security/secret-scanning/"
            "about-secret-scanning"
        ),
        description=(
            "Open secret-scanning alerts. Each row shows a repository's count "
            "of detected, unresolved secrets."
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
}


def category_meta(key: CategoryKey) -> CategoryMeta:
    """The :class:`CategoryMeta` for ``key`` (registry lookup)."""
    return _CATEGORIES[key]


def all_categories() -> tuple[CategoryMeta, ...]:
    """Every category's metadata, in registry (render) order."""
    return tuple(_CATEGORIES.values())
