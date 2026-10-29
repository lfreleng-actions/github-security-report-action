# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""How the GitHub Issues tables present their counts.

The fixed column headers, the markers a partial or undated row carries, the
emphasis each cell earns and the caveats a table's description gains. Shared by
the whole-backlog table and the one narrowed to the running account, so the
two read alike.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Mapping, Set

from github_security_report.models import IssueRef, RepoGraphData
from github_security_report.report import CELL_BAD, CELL_GOOD, CELL_WARN

# Columns appended after the configured label classes. ``Other`` is "labelled,
# but not as anything we were asked about"; ``Untriaged`` is "not labelled at
# all". They are deliberately distinct: the first is a classification gap, the
# second a triage gap.
OTHER_COLUMN = "Other"
UNTRIAGED_COLUMN = "Untriaged"

# The remaining fixed headers, framing the configured ones.
REPOSITORY_COLUMN = "Repository"
TOTAL_COLUMN = "Total"
EXTERNAL_COLUMN = "Ext"
OLDEST_COLUMN = "Oldest"

# Every header the table supplies itself. A configured column may not reuse one:
# it would either share a counter with the implicit column (breaking the sum) or
# duplicate a header and make a ``sort`` term naming it ambiguous.
RESERVED_COLUMNS = (
    REPOSITORY_COLUMN,
    OTHER_COLUMN,
    UNTRIAGED_COLUMN,
    TOTAL_COLUMN,
    EXTERNAL_COLUMN,
    OLDEST_COLUMN,
)

# Marker appended to a repository's oldest-issue cell when its open issues
# exceed the collected window, so a partial label breakdown is visible as such.
TRUNCATED_MARKER = "+"

# Stands in for an age GitHub did not give us a usable creation date for. Kept
# distinct from an absent backlog: the repository has open issues either way.
UNKNOWN_AGE = "unknown"

# Emphasis for the count columns, keyed case-insensitively by header so it
# follows ``Bug`` and ``Docs`` into an ``issue_labels`` that keeps those names,
# and simply does not apply to one that renames them. Untriaged is the triage
# gap the table exists to surface, and Bug the class most likely to hurt a
# user, so both are red; documentation work is a healthy backlog, so green.
_COLUMN_LEVELS: Mapping[str, str] = {
    "bug": CELL_BAD,
    "docs": CELL_GOOD,
    UNTRIAGED_COLUMN.casefold(): CELL_BAD,
}


def _age_days(when: dt.datetime | None, now: dt.datetime) -> int | None:
    """Whole days between ``when`` and ``now`` (>= 0), or None when absent."""
    if when is None:
        return None
    return max((now - when).days, 0)


def _oldest_age(
    data: RepoGraphData, selected: tuple[IssueRef, ...], now: dt.datetime
) -> int | None:
    """Age in days of the oldest selected open issue, or None when unknown.

    The window is ordered oldest-first, so the first selected entry *is* the
    oldest open issue of its kind, however short the window is relative to the
    backlog. That ordering is the only evidence of which issue is oldest, so the
    age is unknown whenever a node dropped in parsing preceded the first
    selected entry (it may have been an older match) or that entry carries no
    usable date: falling through to the next entry would report a newer issue's
    age as the oldest, which is worse than admitting the age is unknown.
    """
    if not selected:
        return None
    if data.issue_gap is not None:
        before_gap = {issue.number for issue in data.issues[: data.issue_gap]}
        if selected[0].number not in before_gap:
            return None
    return _age_days(selected[0].created_at, now)


def _oldest_cell(age: int | None, truncated: bool) -> str:
    """Render the oldest-issue age, marked when the window truncated.

    An unknown age still carries the marker: the label breakdown behind it is
    just as partial, and dropping the marker would present it as complete.
    """
    if age is None:
        return f"{UNKNOWN_AGE} {TRUNCATED_MARKER}" if truncated else UNKNOWN_AGE
    text = "today" if age == 0 else "1 day" if age == 1 else f"{age} days"
    return f"{text} {TRUNCATED_MARKER}" if truncated else text


def age_level(age: int | None, *, warn_days: int, error_days: int) -> str | None:
    """Emphasis for an oldest open issue that is ``age`` days old.

    Both thresholds read "older than": warning once the age exceeds
    ``warn_days``, error once it exceeds ``error_days``, and good at or below
    every active threshold. Either may be ``0`` to turn that level off, matching
    the ``0 = no limit`` idiom used elsewhere; with both off the column is left
    plain rather than painted uniformly green. An unknown age has nothing to
    measure, so it is never coloured.
    """
    if age is None or not (warn_days or error_days):
        return None
    if error_days and age > error_days:
        return CELL_BAD
    if warn_days and age > warn_days:
        return CELL_WARN
    return CELL_GOOD


def _cell_levels(
    columns: tuple[str, ...],
    counts: Mapping[str, int],
    age: str | None,
) -> tuple[str | None, ...]:
    """Semantic emphasis for one row's cells, parallel to its columns.

    Only *non-zero* counts are emphasised, as in the Pull Requests table: a
    column of red zeros trains the reader to ignore the colour. Total and Ext
    carry none -- Total sums classes that disagree about what good looks like.
    """
    counted = (
        _COLUMN_LEVELS.get(column.casefold()) if counts[column] else None
        for column in columns
    )
    return (*counted, None, None, age)


def _describe(
    base: str,
    age_cells: list[str],
    members: Set[str] | None,
    *,
    filtered: bool = False,
) -> str:
    """Extend the category description with the caveats the table earned.

    Each caveat is appended only when a row actually shows it, so a report with
    complete data carries no unexplained qualifications -- and, conversely, an
    unknown age is never described as exact. ``filtered`` marks the assigned
    table, whose Total counts matches in the window and so is partial too.
    """
    description = base
    if any(cell.endswith(TRUNCATED_MARKER) for cell in age_cells):
        description += (
            f" A trailing '{TRUNCATED_MARKER}' marks a repository whose "
            "window-scoped columns are partial -- its open issues exceed the "
            "collected window, or an issue carries more labels than were "
            "fetched -- so the label classes and Ext each describe only the "
            "issues collected, and Ext in particular can undercount. "
        )
        description += (
            "Total, too, counts only the assigned issues collected, so it is a "
            "lower bound; Oldest stays exact wherever an age is shown, since "
            "the window holds the oldest open issues."
            if filtered
            else "Total stays exact either way, as does Oldest wherever an age "
            "is shown."
        )
    if any(cell.startswith(UNKNOWN_AGE) for cell in age_cells):
        description += (
            f" An Oldest of '{UNKNOWN_AGE}' means the oldest open issue "
            "counted came back undated, or an unreadable issue preceded it "
            "and may be older, so its age could not be determined."
        )
    if members is None:
        description += (
            " Organisation membership could not be read for this run, so an "
            "author can only be placed outside the organisation when GitHub "
            "says so unambiguously; Ext therefore undercounts and should be "
            "read as a lower bound."
        )
    return description
