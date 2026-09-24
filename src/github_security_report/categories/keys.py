# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""The category identifier and the shape of its metadata.

Leaf types shared by the registry halves in :mod:`.signals` and :mod:`.tables`.
``CategoryKey`` values are the stable identifiers used by the per-category
configuration toggles, so treat them as part of the config contract: rename
with care.
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
    AISLOP = "aislop"
    DEPENDABOT_ALERTS = "dependabot_alerts"
    SECRET_SCANNING = "secret_scanning"
    DEPENDABOT_ALERTS_ENABLED = "dependabot_alerts_enabled"
    DEPENDABOT_UPDATES_ENABLED = "dependabot_updates_enabled"
    DEPENDABOT_COOLDOWN = "dependabot_cooldown"
    RELEASES = "releases"
    MUTABLE_RELEASES = "mutable_releases"
    PRIVATE_VULNERABILITY_REPORTING = "private_vulnerability_reporting"
    AUTO_MERGE = "auto_merge"
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
