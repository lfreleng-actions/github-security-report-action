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
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import TypeVar

from github_security_report import scope
from github_security_report.models import (
    Repo,
    RepoSignal,
    RepoState,
    SeverityCounts,
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
class TableRow:
    """A generic, repository-keyed table row with pre-formatted cells.

    Used by the Dependabot posture and Releases/Tagging tables, which do not fit
    the four-state :class:`SignalSection` model. ``cells`` excludes the leading
    repository link cell (each renderer supplies that from ``repo``).
    """

    repo: Repo
    cells: tuple[str, ...]


@dataclass
class TableSection:
    """A generic titled table rendered as a sub-section under a heading.

    The **first** column is always the repository column -- every renderer puts
    the repository link/name there (from each :class:`TableRow`'s ``repo``).
    Its header *label* is free-form (usually ``"Repository"``, but a single-list
    table may describe its contents instead, e.g. ``"Repositories NOT
    Enabled"``); downstream consumers should treat column 0 as the repository
    regardless of the label.
    """

    title: str
    columns: tuple[str, ...]  # column 0 is the repository column (label varies)
    rows: list[TableRow] = field(default_factory=list)
    # Shown in place of the table when there are no rows (a clean state).
    empty_note: str = ""
    # Optional explanatory footnote rendered beneath the table.
    note: str = ""
    # Optional one-line count summary rendered beneath the table (after any
    # note), e.g. "2 with findings, 82 clean". Empty for tables that show no
    # summary.
    summary: str = ""


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


@dataclass
class Report:
    orgs: list[OrgReport]
    generated_at: dt.datetime


_T = TypeVar("_T")

# Splits a footnote on a sentence-ending period followed by whitespace, keeping
# the period. A semicolon does not end a sentence, so a clause such as
# "mandatory; any value passes." stays on one line.
_SENTENCE_BREAK = re.compile(r"(?<=\.)\s+")


def note_sentences(note: str) -> list[str]:
    """Split a table footnote into one sentence per line.

    Render surfaces that show a note across multiple lines (the terminal and
    HTML) share this splitter so a multi-sentence note breaks identically. A
    single-sentence note returns one line; an empty note returns no lines.
    """
    return [part for part in _SENTENCE_BREAK.split(note.strip()) if part]


def truncate(items: Sequence[_T], top_n: int | None) -> tuple[list[_T], int]:
    """Limit a sequence for display, returning ``(shown, hidden_count)``.

    The single place every render surface applies an offender limit, so the
    GitHub Pages, terminal and Slack outputs truncate tables and name lists
    identically. ``top_n`` of ``None`` or any value of ``0`` or below shows
    everything and reports ``0`` hidden: ``0`` is the documented "no limit"
    setting, and the negative case is a defensive no-op (negative slicing would
    otherwise drop items from the end).
    """
    seq = list(items)
    if top_n is None or top_n <= 0 or len(seq) <= top_n:
        return seq, 0
    return seq[:top_n], len(seq) - top_n


def offender_column_totals(offenders: Sequence[RepoSignal]) -> SeverityCounts:
    """Sum the severity columns across a set of offender rows.

    Every render surface uses this to draw a trailing "Total" row beneath an
    offender table. Only the rows passed in are summed (callers pass the
    displayed, already-truncated set), so the totals match the visible table
    even when an "and N more" tally hides further offenders.
    """
    totals = SeverityCounts()
    for sig in offenders:
        totals.critical += sig.counts.critical
        totals.high += sig.counts.high
        totals.medium += sig.counts.medium
        totals.low += sig.counts.low
    return totals


def build_org_report(
    org: str,
    repo_signals: list[RepoSignal],
    *,
    repo_count: int,
    generated_at: dt.datetime | None = None,
    partial: bool = False,
    excluded_repos: list[Repo] | None = None,
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
        excluded_repos=sorted(excluded_repos or [], key=lambda r: r.name),
    )
