# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""How a counted row reads: its total cell, its emphasis, and its caveats.

The presentation half of the pull-request table -- what a count is worded as,
which cells are worth colouring, and which qualifications the description has
to carry for the figures above it to be read correctly.
"""

from __future__ import annotations

from collections.abc import Set

from github_security_report.pulls.columns import (
    AUTOMATION_COLUMN,
    BREAKDOWN_COLUMNS,
    CONFLICT_COLUMN,
    EXTERNAL_COLUMN,
    FAILING_COLUMN,
    HUMAN_COLUMN,
    TRUNCATED_MARKER,
)
from github_security_report.report import CELL_BAD, CELL_GOOD, CELL_WARN


def _total_cell(total: int, truncated: bool) -> str:
    """The total, marked when the collected window did not cover it."""
    return f"{total} {TRUNCATED_MARKER}" if truncated else str(total)


def automation_level(
    value: int, *, warn_threshold: int, error_threshold: int
) -> str | None:
    """Emphasis for an automation backlog of ``value`` open pull requests.

    Dependabot stops raising pull requests once a repository reaches its
    open-pull-request limit, so the repository quietly stops receiving
    dependency updates. That makes a large automation backlog an outage in
    waiting rather than a tidiness problem, so it is flagged before it arrives:
    warning *above* the warn threshold, error *at or above* the error one.

    The thresholds are the operator's policy; the defaults track GitHub's own
    limit of 5. ``value`` counts every automation author rather than Dependabot
    alone, and GitHub applies its limit per package ecosystem, so the colour is
    a prompt to look at a backlog worth looking at, not a verdict that
    Dependabot is stalled.

    Either threshold of ``0`` turns that level off, matching the ``0 = no
    limit`` idiom the row limits already use.
    """
    if error_threshold and value >= error_threshold:
        return CELL_BAD
    if warn_threshold and value > warn_threshold:
        return CELL_WARN
    return None


def _cell_levels(
    counts: dict[str, int], *, warn_threshold: int, error_threshold: int
) -> tuple[str | None, ...]:
    """Semantic emphasis for one row's cells, parallel to its columns.

    Only *non-zero* counts are emphasised. A table whose every Conflict and
    Fail cell reads a red ``0`` trains the reader to ignore the colour, which
    costs exactly the signal the colour exists to carry; an unemphasised zero
    lets the eye land on the rows that have something wrong with them.

    The trailing Total is never emphasised: it is the sum of columns that
    disagree about what good looks like, so no one colour is true of it.
    """
    levels: list[str | None] = []
    for column in BREAKDOWN_COLUMNS:
        value = counts[column]
        if column == AUTOMATION_COLUMN:
            levels.append(
                automation_level(
                    value,
                    warn_threshold=warn_threshold,
                    error_threshold=error_threshold,
                )
            )
        elif column in (HUMAN_COLUMN, EXTERNAL_COLUMN):
            levels.append(CELL_GOOD if value else None)
        elif column in (CONFLICT_COLUMN, FAILING_COLUMN):
            levels.append(CELL_BAD if value else None)
        else:
            # Draft is neither good nor bad: a draft is not blocked, it is
            # simply not finished, so it carries no emphasis.
            levels.append(None)
    return (*levels, None)


def _describe(
    base: str, total_cells: list[str], members: Set[str] | None, *, filtered: bool
) -> str:
    """Extend the category description with the caveats the table earned.

    Appended only when a row actually shows it, so a report whose windows all
    covered their backlogs carries no unexplained qualification.

    ``filtered`` distinguishes the two tables, whose truncation means different
    things. Unfiltered, Total is the authoritative ``totalCount`` and stays
    exact however short the window is; filtered, it can only be the matches
    *within* the window, so it is a lower bound too -- and that table has no
    assignment breakdown to qualify.
    """
    description = base
    if any(cell.endswith(TRUNCATED_MARKER) for cell in total_cells):
        if filtered:
            description += (
                f" A trailing '{TRUNCATED_MARKER}' marks a repository whose "
                "open pull requests exceed the collected window. Every figure "
                "on that row, Total included, then describes only the pull "
                "requests collected, so it is a lower bound: a match may sit "
                "in the pull requests this run never saw."
            )
        else:
            description += (
                f" A trailing '{TRUNCATED_MARKER}' marks a repository whose "
                "open pull requests exceed the collected window. Every column "
                "except Total then describes only the pull requests "
                "collected, as does the assignment breakdown beneath the "
                "table, so neither reconciles with that repository's Total. "
                "Total itself stays exact."
            )
    if members is None:
        description += (
            " Organisation membership could not be read for this run, so an "
            "author can only be placed outside the organisation when GitHub "
            "says so unambiguously; Ext therefore undercounts and should be "
            "read as a lower bound."
        )
    return description
