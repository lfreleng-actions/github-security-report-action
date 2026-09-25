# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""CodeQL scan health: stale configurations and language coverage.

The CodeQL signal reports the alerts CodeQL has raised, but not whether CodeQL
is still running. A repository whose scans stopped months ago reads "Clean" in
that table, on the strength of results for code that has since changed. The
tables here close that gap. They qualify the CodeQL signal the way the
Dependabot posture tables qualify Dependabot alerts, so they render beneath it.
"""

from __future__ import annotations

from github_security_report.codeql.cleanup import (
    CleanupAction,
    CleanupItem,
    plan_cleanup,
)
from github_security_report.codeql.facts import (
    CodeQLConfiguration,
    CodeQLFacts,
    CodeQLHealth,
    DefaultSetup,
    SetupType,
    StaleCause,
    normalise_language,
)
from github_security_report.codeql.tables import (
    build_codeql_tables,
    build_language_coverage_table,
    build_stale_configurations_table,
    stale_cause,
)

__all__ = [
    "CleanupAction",
    "CleanupItem",
    "CodeQLConfiguration",
    "CodeQLFacts",
    "CodeQLHealth",
    "DefaultSetup",
    "SetupType",
    "StaleCause",
    "build_codeql_tables",
    "build_language_coverage_table",
    "build_stale_configurations_table",
    "normalise_language",
    "plan_cleanup",
    "stale_cause",
]
