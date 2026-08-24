# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Row limits, totals and footer rows shared by every render surface.

One place each for the decisions a table's presentation turns on -- how many
rows a category shows, what its trailing totals row reads, and which aggregate
rows sit beneath it -- so the GitHub Pages, Markdown, terminal and Slack
surfaces present the same table the same way.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import TypeVar

from github_security_report.categories import CategoryKey
from github_security_report.models import RepoSignal, SeverityCounts
from github_security_report.report.tables import TableRow, TableSection

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


def table_footer_rows(
    section: TableSection, rows: Sequence[TableRow], *, personal: bool = False
) -> tuple[tuple[str, ...], ...]:
    """Aggregate rows drawn beneath a table's totals row, full width.

    A breakdown *of* the rows rather than *within* them: the Pull Requests table
    uses it to split its backlog by who each pull request is assigned to, which
    is a partition of the same pull requests the columns already count and so
    cannot be another column without double-counting them.

    Each row is returned at the table's full width, with the label in the
    repository column and the value under the **last** column. That placement
    is the point: these values partition the whole row -- automation included --
    so aligning them under ``Total`` says what they total, whereas the second
    column would file an unassigned bot pull request under ``Human``. Returning
    complete rows also keeps every renderer from padding them itself, which is
    where that misalignment came from.

    ``personal`` declares that this surface is read by the account the report
    ran as, and is the **only** thing that admits the section's
    ``personal_footer_labels``. It defaults to off, so a surface that says
    nothing gets the objective rows alone: a published artifact is read by
    people who are not the token owner, for whom "Mine" names a stranger's
    queue. Little is lost by omitting them -- the objective rows still sit
    against the totals row, so what they would have said remains bounded.

    Summed over the rows passed in -- the displayed, already-truncated set --
    for the same reason :func:`table_column_totals` is: a footer the reader
    cannot reconcile against the rows above it is worse than no footer.
    Returns an empty tuple for a table that declares no footer labels.
    """
    if not section.footer_labels:
        return ()
    # One label cell, one value cell, and blanks for whatever lies between.
    gap = max(len(section.columns) - 2, 0)
    return tuple(
        (
            label,
            *([""] * gap),
            str(
                sum(
                    row.footer_values[index]
                    for row in rows
                    if index < len(row.footer_values)
                )
            ),
        )
        for index, label in enumerate(section.footer_labels)
        if personal or label not in section.personal_footer_labels
    )


def _as_int(cell: str) -> int:
    """A table cell as a number, or 0 when it does not parse.

    Reads the leading numeric token rather than requiring the whole cell to be a
    number, so a count annotated with a trailing marker (e.g. the Pull Requests
    table's ``"12 +"``, flagging a partial breakdown) still contributes its
    value to the totals row instead of silently summing as zero.
    """
    try:
        return int(str(cell).split()[0])
    except (AttributeError, IndexError, TypeError, ValueError):
        return 0
