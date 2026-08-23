# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""One signal's four-state results, and the wording for a skipped section.

The per-signal half of the report structure: offenders (ranked worst-first),
the clean count, the not-enabled nag list and the unknown count, as described
in ``docs/BRIEF.md`` sections 4-6.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from github_security_report.models import Repo, RepoSignal, SignalType
from github_security_report.summary import SummaryCount

# Wording and pointer for a feature-gated (skipped) section, shared by every
# render surface so the single skip line reads identically everywhere. The URL
# points at the organisation onboarding guide describing the workflows an org
# needs before the workflow-driven signals produce data.
SKIP_MESSAGE = "Skipping feature: organisation support missing"
ORG_SETUP_DOC_URL = (
    "https://github.com/lfreleng-actions/github-security-report-action/"
    "blob/main/docs/org-scan-setup.md"
)


@dataclass
class SignalSection:
    """One signal's results for one organisation."""

    signal: SignalType
    offenders: list[RepoSignal] = field(default_factory=list)  # ranked worst-first
    clean_count: int = 0
    nag_repos: list[Repo] = field(default_factory=list)
    unknown_count: int = 0
    # True when organisation feature gating found no support for this signal's
    # tooling (no ruleset, alerts or analyses), so no telemetry was gathered.
    # A skipped section renders as a single "Skipping feature" line with a
    # pointer to the org setup guide instead of a table/footers.
    skipped: bool = False
    # Resolved explanatory description (Markdown/HTML only). Empty falls back to
    # the category's default description at render time. Populated only when a
    # configured ordering overrides the default ranking, whose wording the
    # default description states and would otherwise misreport.
    description: str = ""

    def resolved_description(self) -> str:
        """The description to show, falling back to the category default."""
        return self.description or self.signal.meta.description

    def top(self, n: int) -> list[RepoSignal]:
        """The worst N offenders (used for the Slack digest only)."""
        return self.offenders[:n]

    def summary_counts(self, excluded: Sequence[Repo] = ()) -> list[SummaryCount]:
        """Footer count buckets for this signal (offenders are the table).

        Severity signals enumerate their failures as table rows, so there is no
        single failure count here -- the footer carries the not-enabled (nag)
        count, the unknown count, the clean (pass) count, and the org-level
        excluded repositories passed in by the caller.
        """
        meta = self.signal.meta
        return [
            # Offenders are enumerated as table rows, not a footer line, so this
            # bucket is counted but not rendered: it exists solely to stop a
            # partially-clean section collapsing its pass line to "All <pass>".
            SummaryCount(
                "fail",
                len(self.offenders),
                meta.fail_label or "With findings",
                render=False,
            ),
            SummaryCount(
                "disabled",
                len(self.nag_repos),
                "Disabled",
                tuple(r.name for r in self.nag_repos),
            ),
            SummaryCount("unknown", self.unknown_count, "Unknown"),
            SummaryCount(
                "pass",
                self.clean_count,
                meta.pass_label,
                all_label=meta.pass_all_label,
            ),
            SummaryCount(
                "excluded",
                len(excluded),
                "Excluded",
                tuple(r.name for r in excluded),
            ),
        ]
