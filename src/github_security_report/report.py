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
from collections.abc import Callable, Sequence, Set
from dataclasses import dataclass, field
from typing import TypeVar

from github_security_report import scope
from github_security_report.categories import CategoryKey, CategoryMeta
from github_security_report.models import (
    Repo,
    RepoSignal,
    RepoState,
    SeverityCounts,
    SignalType,
    rank_offenders,
)
from github_security_report.summary import (
    SUMMARY_EMOJI,
    SummaryCount,
    SummaryLine,
    build_summary,
)

# Re-exported so every renderer keeps importing the footer vocabulary from
# ``report`` alongside the structures it decorates.
__all__ = [
    "ORG_SETUP_DOC_URL",
    "SKIP_MESSAGE",
    "SUMMARY_EMOJI",
    "LimitFor",
    "OrgReport",
    "Report",
    "SignalSection",
    "SummaryCount",
    "SummaryLine",
    "TableRow",
    "TableSection",
    "build_org_report",
    "build_summary",
    "limit_resolver",
    "offender_column_totals",
    "section_shows_informational",
    "table_column_totals",
    "truncate",
]

SIGNAL_ORDER: tuple[SignalType, ...] = (
    SignalType.SCORECARD,
    SignalType.AISLOP,
    SignalType.DEPENDABOT,
    SignalType.CODEQL,
    SignalType.ZIZMOR,
    SignalType.SECRET_SCANNING,
)

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
            SummaryCount("pass", self.clean_count, meta.pass_label),
            SummaryCount(
                "excluded",
                len(excluded),
                "Excluded",
                tuple(r.name for r in excluded),
            ),
        ]


@dataclass
class TableRow:
    """A generic, repository-keyed table row with pre-formatted cells.

    Used by the Dependabot posture, Releases/Tagging and GitHub Issues tables,
    which do not fit the four-state :class:`SignalSection` model. ``cells``
    excludes the leading repository link cell (each renderer supplies that from
    ``repo``).

    ``sort_values`` carries the typed value behind each cell, parallel to
    ``cells``, so a configured column ordering sorts on the number rather than
    its rendering -- "16 days" and "9 days" compare correctly as 16 and 9, but
    backwards as strings. Empty means the builder published no sort values, in
    which case ordering falls back to the displayed text.
    """

    repo: Repo
    cells: tuple[str, ...]
    sort_values: tuple[float | str, ...] = ()


@dataclass
class TableSection:
    """A generic titled table rendered as a sub-section under a heading.

    Carries its :class:`CategoryMeta` (title, pass/fail labels, docs URL,
    description) plus the normalised pass/fail/unknown counts that feed the
    shared :func:`build_summary` footer, so every category presents its results
    in the same standardised form. The **first** column is always the
    repository column -- every renderer puts the repository link/name there
    (from each :class:`TableRow`'s ``repo``). Its header *label* is free-form
    (usually ``"Repository"``); downstream consumers treat column 0 as the
    repository regardless of the label.
    """

    category: CategoryMeta
    columns: tuple[str, ...]  # column 0 is the repository column (label varies)
    rows: list[TableRow] = field(default_factory=list)
    # Column indices (into ``columns``) whose cells are numeric and should be
    # summed into a trailing totals row. Empty means the table has no summable
    # columns and renders without one -- the case for every qualitative table
    # (release ages, ecosystems, release tags).
    sum_columns: frozenset[int] = frozenset()
    # Normalised footer counts. ``fail_count`` is the number of listed (rows)
    # offenders; ``pass_count`` the healthy repositories; ``unknown_count`` the
    # repositories whose state could not be determined.
    pass_count: int = 0
    fail_count: int = 0
    unknown_count: int = 0
    # Resolved explanatory description (Markdown/HTML only). Empty falls back to
    # the category's default description at render time.
    description: str = ""

    @property
    def title(self) -> str:
        return self.category.title

    def resolved_description(self) -> str:
        """The description to show, falling back to the category default."""
        return self.description or self.category.description

    def summary_counts(self, excluded: Sequence[Repo] = ()) -> list[SummaryCount]:
        """Footer count buckets for this table (failure, unknown, pass, excluded)."""
        fail_label = self.category.fail_label or "Failing"
        return [
            SummaryCount("fail", self.fail_count, fail_label),
            SummaryCount("unknown", self.unknown_count, "Unknown"),
            SummaryCount("pass", self.pass_count, self.category.pass_label),
            SummaryCount(
                "excluded",
                len(excluded),
                "Excluded",
                tuple(r.name for r in excluded),
            ),
        ]


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
    # The GitHub Issues table: open issues per repository, split by label class.
    # None in repo mode / when not collected.
    issues: TableSection | None = None


@dataclass
class Report:
    orgs: list[OrgReport]
    generated_at: dt.datetime


_T = TypeVar("_T")

# A per-category row limit, mirroring the ``show`` visibility predicate every
# render surface already accepts. Returning ``None`` or ``0`` means "no limit".
LimitFor = Callable[[CategoryKey], int | None]


def limit_resolver(top_n: int | None, limit: LimitFor | None) -> LimitFor:
    """Build the per-category limit lookup a render surface should use.

    Renderers accept both a single ``top_n`` (the same cap for every category)
    and an optional per-category ``limit`` callable. This is the one place that
    reconciles them, so every surface resolves a category's limit identically:
    an explicit ``limit`` wins, otherwise the shared ``top_n`` applies to all.
    """
    if limit is not None:
        return limit
    return lambda _key: top_n


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
        # Informational has no visible column, but it is part of each row's
        # ``Total`` cell, so the totals row must accumulate it too -- otherwise
        # the ``Total`` column would not sum vertically whenever an offender
        # carries informational findings (e.g. zizmor note-level results).
        totals.informational += sig.counts.informational
    return totals


def section_shows_informational(offenders: Sequence[RepoSignal]) -> bool:
    """Whether any offender carries informational (sub-low) findings.

    Drives the conditional Informational severity column: it is rendered only
    for tables that actually have sub-low findings -- e.g. zizmor's note-level
    results -- so severity tables without such data (CodeQL, Dependabot alerts)
    are not padded with an all-zero column. Callers pass the displayed
    (already-truncated) offenders, so the column matches the visible rows.
    """
    return any(sig.counts.informational for sig in offenders)


def table_column_totals(
    section: TableSection, rows: Sequence[TableRow]
) -> tuple[str, ...] | None:
    """The trailing totals row for a table, or ``None`` when it has none.

    Every render surface uses this to draw a "Total" row beneath a table with
    numeric columns, so the wording and the column alignment match everywhere.
    Only the rows passed in are summed -- callers pass the displayed,
    already-truncated set -- so the totals describe the visible table even when
    an "and N more" tally hides further rows, matching
    :func:`offender_column_totals`.

    Non-numeric columns render an empty cell: an "oldest issue" age or a list of
    ecosystems has no meaningful sum. A cell that cannot be read as a number
    contributes zero rather than raising, so a malformed row degrades the total
    instead of failing the whole report.
    """
    if not section.sum_columns:
        return None
    cells = ["Total"]
    for index in range(1, len(section.columns)):
        if index not in section.sum_columns:
            cells.append("")
            continue
        cells.append(str(sum(_as_int(row.cells[index - 1]) for row in rows)))
    return tuple(cells)


def _as_int(cell: str) -> int:
    """A table cell as a number, or 0 when it does not parse."""
    try:
        return int(cell)
    except (TypeError, ValueError):
        return 0


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
