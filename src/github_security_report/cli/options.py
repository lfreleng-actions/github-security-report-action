# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""What a run takes from the command line, as values rather than parameters.

Bundled here rather than beside the run modes so the publishing stage can
accept them without importing the module that calls it.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from pathlib import Path

from github_security_report.categories import CategoryKey
from github_security_report.cli.outputs import TopNLimits
from github_security_report.config import OrgConfig, ReportConfig
from github_security_report.report import OrgReport

# An org config paired with the report collected for it.
OrgPair = tuple[OrgConfig, OrgReport]


@dataclass(frozen=True)
class ReportOverrides:
    """Command-line overrides for the ``report`` block of every organisation.

    CLI overrides win over config; an unset override (``None``) leaves the
    org's own configured value in place. Each field is ``None`` rather than a
    concrete default for exactly the reason ``--token-env`` needed the same
    treatment: an eager default cannot be told apart from an unset one, so it
    could never be applied as an override.

    The three booleans are one-way. ``--no-gating`` can switch gating off but
    not on, and ``--include-archived`` / ``--include-test`` can widen the scope
    but not narrow it, so a flag can loosen what the configuration asked for
    without being able to tighten it behind the operator's back.
    """

    repo_min_age_days: int | None = None
    release_max_age_days: int | None = None
    releases_exclude: tuple[str, ...] | None = None
    gating: bool | None = None
    include_archived: bool | None = None
    include_test: bool | None = None

    def apply(self, org_cfg: OrgConfig) -> tuple[OrgConfig, ReportConfig]:
        """The org and report configs to collect with, overrides applied.

        The two age thresholds and the three booleans are scalar policy, so
        applying one uniformly across every configured organisation is what a
        reader of the flag expects, and matches how ``--top-n`` already behaves.

        ``releases_exclude`` is not scalar: it is a curated per-organisation
        list, and one flag replacing all of them loses data the config
        deliberately carried. The command line refuses it outright for a
        multi-org run rather than silently flattening them (see cli/app.py), so
        by the time this runs there is only one organisation it could mean.
        """
        report_cfg = org_cfg.report
        for name in (
            "repo_min_age_days",
            "release_max_age_days",
            "gating",
            "include_archived",
            "include_test",
        ):
            value = getattr(self, name)
            if value is not None:
                report_cfg = replace(report_cfg, **{name: value})
        effective_cfg = org_cfg
        if self.releases_exclude is not None:
            effective_cfg = replace(org_cfg, releases_exclude=self.releases_exclude)
        return effective_cfg, report_cfg


@dataclass(frozen=True)
class OrgRunOptions:
    """Everything an org-mode run takes from the command line.

    Bundled into one value so each run stage receives a single options argument
    rather than a dozen individually-threaded parameters.
    """

    output_dir: Path | None = None
    pages_url: str | None = None
    slack_channel: str | None = None
    force_notify: bool = False
    limits: TopNLimits = field(default_factory=TopNLimits)
    overrides: ReportOverrides = field(default_factory=ReportOverrides)
    # Categories the invocation suppressed outright. Outranks the config, so a
    # scheduled run can keep a reader-specific category out of its published
    # artifacts without editing (or contradicting) the shared configuration.
    hidden: frozenset[CategoryKey] = frozenset()
