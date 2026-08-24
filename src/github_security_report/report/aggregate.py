# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Aggregation of classified signals into the renderable report structure.

Groups a flat list of classified :class:`RepoSignal` results into one
:class:`SignalSection` per signal, and holds the per-organisation and
whole-run documents those sections hang from -- including the extra
:class:`TableSection` tables (Dependabot posture, releases, issues, pull
requests) collected alongside them.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Set
from dataclasses import dataclass, field

from github_security_report import scope
from github_security_report.models import (
    Repo,
    RepoSignal,
    RepoState,
    SignalType,
    rank_offenders,
)
from github_security_report.report.signals import SignalSection
from github_security_report.report.tables import TableSection

SIGNAL_ORDER: tuple[SignalType, ...] = (
    SignalType.SCORECARD,
    SignalType.AISLOP,
    SignalType.DEPENDABOT,
    SignalType.CODEQL,
    SignalType.ZIZMOR,
    SignalType.SECRET_SCANNING,
)


@dataclass
class OrgReport:
    org: str
    sections: list[SignalSection]
    repo_count: int
    generated_at: dt.datetime
    # True when the repository listing was incomplete (e.g. a truncated or
    # forbidden org repos read), so the report may omit repositories.
    partial: bool = False
    # Repositories removed from analysis by the per-org ``exclude`` list. These
    # are reported as "excluded" (counted, never analysed) so an explicit
    # exclusion is visible and distinct from a "not enabled" nag.
    excluded_repos: list[Repo] = field(default_factory=list)
    # Extra Dependabot posture tables rendered as sub-sections beneath the
    # Dependabot signal heading (alerts not enabled, security updates not
    # enabled, cooldown settings). Empty in repo mode / when not collected.
    dependabot_tables: list[TableSection] = field(default_factory=list)
    # The Releases / Tagging table (release and tag staleness). None only when
    # not collected (repo mode); org mode always assigns a section, which may
    # have zero rows and render its empty_note instead.
    releases: TableSection | None = None
    # The Mutable Releases table: repositories whose "Latest" or last-published
    # release is not immutable. None in repo mode / when not collected.
    mutable_releases: TableSection | None = None
    # The Private Vulnerability Reporting table: repositories where the feature
    # is not enabled. None in repo mode / when not collected.
    private_vulnerability_reporting: TableSection | None = None
    # The GitHub Issues table (open issues per repository, split by label).
    # None in repo mode / when not collected.
    issues: TableSection | None = None
    # The Pull Requests table (open pull requests per repository, split by
    # author and by what blocks them). None in repo mode / when not collected.
    pull_requests: TableSection | None = None
    # The same table narrowed to the running account's own assigned pull
    # requests. None in repo mode / when not collected.
    assigned_pull_requests: TableSection | None = None


@dataclass
class Report:
    orgs: list[OrgReport]
    generated_at: dt.datetime


def build_org_report(
    org: str,
    repo_signals: list[RepoSignal],
    *,
    repo_count: int,
    generated_at: dt.datetime | None = None,
    partial: bool = False,
    excluded_repos: list[Repo] | None = None,
    skipped_signals: Set[SignalType] = frozenset(),
) -> OrgReport:
    """Assemble an :class:`OrgReport` from a flat list of classified signals.

    ``skipped_signals`` marks sections whose telemetry was never gathered
    because organisation feature gating found no supporting workflows; such a
    section renders as a single skip line on every surface.
    """
    when = generated_at or dt.datetime.now(dt.timezone.utc)
    by_signal: dict[SignalType, list[RepoSignal]] = {s: [] for s in SIGNAL_ORDER}
    for sig in repo_signals:
        by_signal.setdefault(sig.signal, []).append(sig)

    sections: list[SignalSection] = []
    for signal in SIGNAL_ORDER:
        results = by_signal.get(signal, [])
        nag = [
            s.repo
            for s in results
            if s.state is RepoState.NAG and scope.in_nag_scope(s.repo)
        ]
        sections.append(
            SignalSection(
                signal=signal,
                offenders=rank_offenders(results),
                clean_count=sum(1 for s in results if s.state is RepoState.CLEAN),
                nag_repos=sorted(nag, key=lambda r: r.name),
                unknown_count=sum(1 for s in results if s.state is RepoState.UNKNOWN),
                skipped=signal in skipped_signals,
            )
        )
    return OrgReport(
        org=org,
        sections=sections,
        repo_count=repo_count,
        generated_at=when,
        partial=partial,
        excluded_repos=sorted(excluded_repos or [], key=lambda r: r.name),
    )
