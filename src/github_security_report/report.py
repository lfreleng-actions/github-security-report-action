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
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import TypeVar

from github_security_report import scope
from github_security_report.categories import CategoryMeta
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

    def summary_counts(
        self, excluded: Sequence[Repo] = ()
    ) -> list[SummaryCount]:
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


@dataclass(frozen=True)
class SummaryCount:
    """One labelled count feeding the standardised summary footer.

    ``kind`` selects the glyph, colour and ordering; ``names`` carries the
    repository names listed beneath the count line (used for the disabled and
    excluded kinds, where naming the repositories is actionable). ``render``
    false keeps the bucket out of the visible footer while still letting it
    count towards the "nothing needs attention" test that collapses the pass
    line to ``All <pass>``: a severity signal's offenders live in the table
    (not as a footer line), but they must still suppress a falsely reassuring
    ``All <pass>`` when the section is only partially clean.
    """

    kind: str  # "fail" | "disabled" | "unknown" | "pass" | "excluded"
    count: int
    label: str
    names: tuple[str, ...] = ()
    render: bool = True


@dataclass(frozen=True)
class SummaryLine:
    """A formatted summary footer line, ready for any render surface.

    ``kind`` lets each surface pick its own glyph/colour; ``text`` is the
    surface-agnostic body (e.g. ``"All Clean"`` or ``"1 Mutable"``).
    """

    kind: str
    text: str
    names: tuple[str, ...] = ()


# Footer ordering: actionable items first (failures, then not-enabled, then
# unknown), then the healthy pass line, then the neutral excluded line last.
# This tool drives remediation, so the work to do sits at the top.
_SUMMARY_ORDER = {"fail": 0, "disabled": 1, "unknown": 2, "pass": 3, "excluded": 4}

# Glyph per summary kind, shared by every render surface.
SUMMARY_EMOJI = {
    "fail": "\u274c",
    "disabled": "\u274c",
    "unknown": "\u2753",
    "pass": "\u2705",
    "excluded": "\u23e9",
}


def build_summary(counts: Sequence[SummaryCount]) -> list[SummaryLine]:
    """Turn raw count buckets into ordered, formatted summary lines.

    The single place every surface builds its under-table footer, so the
    wording, ordering and the ``All <pass>`` collapse behave identically
    everywhere. The pass line reads ``All <pass_label>`` -- with no number --
    only when nothing else needs attention (no failures, not-enabled, unknown
    or excluded repositories); otherwise every present bucket shows its count.
    Zero-valued buckets are dropped, as are buckets flagged ``render=False``
    (which still count towards the collapse test but emit no visible line).
    """
    present = [c for c in counts if c.count > 0]
    non_pass = sum(c.count for c in present if c.kind != "pass")
    lines: list[SummaryLine] = []
    for count in sorted(present, key=lambda c: _SUMMARY_ORDER[c.kind]):
        if not count.render:
            continue
        if count.kind == "pass" and non_pass == 0:
            text = f"All {count.label}"
        else:
            text = f"{count.count} {count.label}"
        lines.append(SummaryLine(kind=count.kind, text=text, names=count.names))
    return lines


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

    def summary_counts(
        self, excluded: Sequence[Repo] = ()
    ) -> list[SummaryCount]:
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


@dataclass
class Report:
    orgs: list[OrgReport]
    generated_at: dt.datetime


_T = TypeVar("_T")


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
