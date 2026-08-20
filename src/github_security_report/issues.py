# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Open GitHub issues per repository, classified by label.

A reporting category outside the four-state per-signal model: a plain table
counting each repository's open issues, split into configurable label classes
plus two implicit columns.

The two implicit columns carry most of the value. **Other** holds issues that
are labelled but match no configured class, and **Untriaged** holds issues with
no labels at all -- an unlabelled issue is one nobody has categorised, so that
column is the backlog-hygiene signal the table exists to surface.

Two accuracy notes, both stemming from the bounded GraphQL window
(:mod:`client.queries`):

- ``Total`` and ``Oldest`` are exact at any backlog size. ``totalCount`` is not
  window-limited, and the window is ordered oldest-first, so its first entry is
  genuinely the oldest open issue. ``Oldest`` reads ``unknown`` in the rare case
  where that entry carries no usable creation date.
- The label-class columns are window-scoped, in two senses. A repository whose
  open issues exceed the window classifies only the oldest of them, so the class
  columns can sum to less than ``Total``; and an issue may carry labels beyond
  the per-issue label window. The row is marked so the table never implies a
  breakdown it did not actually see.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Mapping, Set

from github_security_report.authors import is_external_author
from github_security_report.categories import CategoryKey, category_meta
from github_security_report.models import IssueRef, Repo, RepoGraphData
from github_security_report.report import TableRow, TableSection

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


def classify_issue(
    issue: IssueRef, label_columns: Mapping[str, tuple[str, ...]]
) -> str:
    """The column an issue counts towards.

    An issue falls in the first configured column whose labels it carries, so
    declaration order resolves an issue labelled both ``bug`` and ``feature``
    (it counts once, under whichever column comes first). Matching is
    case-insensitive on the whole label name -- not a substring test, which
    would let ``docs`` swallow an unrelated ``docs-needed`` label.
    """
    if not issue.labels:
        return UNTRIAGED_COLUMN
    carried = {label.casefold() for label in issue.labels}
    for column, labels in label_columns.items():
        if carried & {label.casefold() for label in labels}:
            return column
    return OTHER_COLUMN


def _classification_is_certain(
    issue: IssueRef, column: str, label_columns: Mapping[str, tuple[str, ...]]
) -> bool:
    """Whether labels beyond the fetched window could have changed the column.

    Only the **first** configured column is immune. Classification walks the
    configured columns in declaration order rather than the order labels came
    back in, so a match on any later column could still be outranked by an
    unseen label belonging to an earlier one -- and ``Other`` or ``Untriaged``
    could be displaced by any match at all.
    """
    if not issue.labels_truncated:
        return True
    return column == next(iter(label_columns), None)


def _is_external(issue: IssueRef, members: Set[str]) -> bool:
    """Whether an issue was raised from outside the organisation.

    An author who cannot be classified is *not* counted: the column reports
    contributions confirmed to come from outside, so an indeterminate author
    understates it rather than inventing an outsider.
    """
    author = issue.author
    if author is None:
        return False
    return (
        is_external_author(
            author.login,
            association=author.association,
            members=members,
            typename=author.typename,
        )
        is True
    )


def _age_days(when: dt.datetime | None, now: dt.datetime) -> int | None:
    """Whole days between ``when`` and ``now`` (>= 0), or None when absent."""
    if when is None:
        return None
    return max((now - when).days, 0)


def _oldest_age(data: RepoGraphData, now: dt.datetime) -> int | None:
    """Age in days of the oldest open issue, or None when it cannot be known.

    The window is ordered oldest-first, so entry 0 *is* the oldest open issue,
    however short the window is relative to the backlog. That ordering is the
    only evidence of which issue is oldest, so the age is unknown whenever
    entry 0 is missing (dropped in parsing) or carries no usable date: falling
    through to the next entry would report a newer issue's age as the oldest,
    which is worse than admitting the age is unknown.
    """
    if data.oldest_issue_unreadable or not data.issues:
        return None
    return _age_days(data.issues[0].created_at, now)


def _oldest_cell(age: int | None, truncated: bool) -> str:
    """Render the oldest-issue age, marked when the window truncated.

    An unknown age still carries the marker: the label breakdown behind it is
    just as partial, and dropping the marker would present it as complete.
    """
    if age is None:
        return f"{UNKNOWN_AGE} {TRUNCATED_MARKER}" if truncated else UNKNOWN_AGE
    text = "today" if age == 0 else "1 day" if age == 1 else f"{age} days"
    return f"{text} {TRUNCATED_MARKER}" if truncated else text


def _describe(base: str, age_cells: list[str]) -> str:
    """Extend the category description with the caveats the table earned.

    Each caveat is appended only when a row actually shows it, so a report with
    complete data carries no unexplained qualifications -- and, conversely, an
    unknown age is never described as exact.
    """
    description = base
    if any(cell.endswith(TRUNCATED_MARKER) for cell in age_cells):
        description += (
            f" A trailing '{TRUNCATED_MARKER}' marks a repository whose label "
            "breakdown is partial -- its open issues exceed the collected "
            "window, or an issue carries more labels than were fetched. Total "
            "stays exact either way, as does Oldest wherever an age is shown."
        )
    if any(cell.startswith(UNKNOWN_AGE) for cell in age_cells):
        description += (
            f" An Oldest of '{UNKNOWN_AGE}' means the oldest open issue came "
            "back unreadable or undated, so its age could not be determined."
        )
    return description


def build_issues_table(
    graph: Mapping[str, RepoGraphData],
    repos: list[Repo],
    *,
    generated_at: dt.datetime,
    label_columns: Mapping[str, tuple[str, ...]],
    members: Set[str] = frozenset(),
) -> TableSection:
    """The GitHub Issues table, largest backlog first.

    Only repositories with at least one open issue are listed; the rest are
    counted as the healthy (pass) total in the standardised footer, matching
    every other table in the report. Ranking leads on total open issues -- the
    headline the table exists to report -- then on Untriaged, so two repositories
    with equal backlogs surface the less-triaged one first.

    ``members`` is the organisation's membership, used to count the issues
    raised from outside it (see :mod:`authors`).
    """
    columns = (*label_columns, OTHER_COLUMN, UNTRIAGED_COLUMN)
    rows: list[tuple[int, int, str, TableRow]] = []
    clean_count = 0
    unknown_count = 0
    for repo in repos:
        data = graph.get(repo.name, RepoGraphData())
        if data.open_issues is None:
            # The issues connection could not be read for this repository, so
            # its backlog is unknown -- never "none open".
            unknown_count += 1
            continue
        if data.open_issues <= 0:
            clean_count += 1
            continue
        counts = dict.fromkeys(columns, 0)
        external = 0
        partial = data.open_issues > len(data.issues)
        for issue in data.issues:
            if _is_external(issue, members):
                external += 1
            if issue.labels_truncated and not issue.labels:
                # Not one label was readable, so there is nothing to classify
                # on. Counting it as Untriaged would invent a triage gap out of
                # data the run never saw; the class columns omit it instead and
                # the row is marked partial to explain the shortfall.
                partial = True
                continue
            column = classify_issue(issue, label_columns)
            counts[column] += 1
            if not _classification_is_certain(issue, column, label_columns):
                partial = True
        oldest = _oldest_age(data, generated_at)
        cells = (
            *(str(counts[column]) for column in columns),
            str(data.open_issues),
            str(external),
            _oldest_cell(oldest, partial),
        )
        # An unknown age has no value to rank on, so it is published as None:
        # the ordering layer keeps such rows last in either direction rather
        # than treating "unknown" as younger than "today".
        sort_values: tuple[float | str | None, ...] = (
            *(float(counts[column]) for column in columns),
            float(data.open_issues),
            float(external),
            float(oldest) if oldest is not None else None,
        )
        rows.append(
            (
                data.open_issues,
                counts[UNTRIAGED_COLUMN],
                repo.name,
                TableRow(repo=repo, cells=cells, sort_values=sort_values),
            )
        )
    # Negated numerics so the whole sort runs ascending, keeping the name
    # tiebreaker correctly ascending even when one name prefixes another.
    rows.sort(key=lambda item: (-item[0], -item[1], item[2]))

    meta = category_meta(CategoryKey.GITHUB_ISSUES)
    all_columns = (
        REPOSITORY_COLUMN,
        *columns,
        TOTAL_COLUMN,
        EXTERNAL_COLUMN,
        OLDEST_COLUMN,
    )
    description = _describe(meta.description, [row.cells[-1] for *_, row in rows])
    return TableSection(
        category=meta,
        columns=all_columns,
        rows=[row for _, _, _, row in rows],
        # Every column except the repository and the trailing age is a count.
        sum_columns=frozenset(range(1, len(all_columns) - 1)),
        # Every column but the repository sorts numerically, including the age:
        # its cells render as text but its sort values are days.
        numeric_columns=frozenset(range(1, len(all_columns))),
        pass_count=clean_count,
        fail_count=len(rows),
        unknown_count=unknown_count,
        description=description,
    )
