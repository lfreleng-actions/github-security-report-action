# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Report aggregation.

Groups classified :class:`RepoSignal` results into the renderable report
structure: one section per signal, each with ranked offenders (full list -- the
top-N limit applies only to Slack), a clean count, a nag list (archived/test
repos excluded), and an unknown count. See ``docs/BRIEF.md`` sections 4-6, 11.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field

from github_security_report import scope
from github_security_report.models import (
    Repo,
    RepoSignal,
    RepoState,
    SignalType,
    rank_offenders,
)

# Render order for the five sections.
SIGNAL_ORDER: tuple[SignalType, ...] = (
    SignalType.CODEQL,
    SignalType.SCORECARD,
    SignalType.ZIZMOR,
    SignalType.DEPENDABOT,
    SignalType.SECRET_SCANNING,
)


@dataclass
class SignalSection:
    """One signal's results for one organisation."""

    signal: SignalType
    offenders: list[RepoSignal] = field(default_factory=list)  # ranked worst-first
    clean_count: int = 0
    nag_repos: list[Repo] = field(default_factory=list)
    unknown_count: int = 0

    def top(self, n: int) -> list[RepoSignal]:
        """The worst N offenders (used for the Slack digest only)."""
        return self.offenders[:n]


@dataclass
class OrgReport:
    org: str
    sections: list[SignalSection]
    repo_count: int
    generated_at: dt.datetime
    # True when the repository listing was incomplete (e.g. a truncated or
    # forbidden org repos read), so the report may omit repositories.
    partial: bool = False


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
) -> OrgReport:
    """Assemble an :class:`OrgReport` from a flat list of classified signals."""
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
            )
        )
    return OrgReport(
        org=org,
        sections=sections,
        repo_count=repo_count,
        generated_at=when,
        partial=partial,
    )
