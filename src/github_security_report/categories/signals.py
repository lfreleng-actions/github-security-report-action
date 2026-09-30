# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Metadata for the six ranked signal categories, in render order."""

from __future__ import annotations

from github_security_report.categories.keys import CategoryKey, CategoryMeta
from github_security_report.secret_patterns import (
    AI_DETECTED_SECRET_TYPES,
    GENERIC_SECRET_TYPES,
)
from github_security_report.severity import Severity

SIGNAL_CATEGORIES: dict[CategoryKey, CategoryMeta] = {
    CategoryKey.CODEQL: CategoryMeta(
        key=CategoryKey.CODEQL,
        # Qualified so the alerts table reads apart from the two CodeQL
        # scan-health tables nested beneath it.
        title="CodeQL: Results/Findings",
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
}
