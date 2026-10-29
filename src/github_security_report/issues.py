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

The same table narrowed to the issues assigned to the running account (GitHub
Issues: Assigned to Me) shares the columns, but its ``Total`` counts the matches
in the window, since ``totalCount`` knows nothing of assignees.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Mapping, Set
from dataclasses import dataclass

from github_security_report.authors import is_external_author
from github_security_report.categories import CategoryKey, category_meta
from github_security_report.issue_presentation import (
    EXTERNAL_COLUMN,
    OLDEST_COLUMN,
    OTHER_COLUMN,
    REPOSITORY_COLUMN,
    RESERVED_COLUMNS,
    TOTAL_COLUMN,
    TRUNCATED_MARKER,
    UNKNOWN_AGE,
    UNTRIAGED_COLUMN,
    _cell_levels,
    _describe,
    _oldest_age,
    _oldest_cell,
    age_level,
)
from github_security_report.models import IssueRef, Repo, RepoGraphData
from github_security_report.report import TableRow, TableSection

# The presentation names are re-exported so the category keeps one import
# site: the configuration validates against ``RESERVED_COLUMNS`` and the tests
# read the markers and headers from here.
__all__ = [
    "EXTERNAL_COLUMN",
    "OLDEST_COLUMN",
    "OTHER_COLUMN",
    "REPOSITORY_COLUMN",
    "RESERVED_COLUMNS",
    "TOTAL_COLUMN",
    "TRUNCATED_MARKER",
    "UNKNOWN_AGE",
    "UNTRIAGED_COLUMN",
    "age_level",
    "build_assigned_issues_table",
    "build_issues_table",
    "classify_issue",
    "is_assigned",
]


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


def _is_external(issue: IssueRef, members: Set[str] | None) -> bool:
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


def is_assigned(issue: IssueRef, viewer: str) -> bool:
    """Whether ``viewer`` is among an issue's assignees, ignoring case.

    An empty ``viewer`` is nobody, so a run that could not identify its own
    account never claims somebody else's issue as the reader's.
    """
    mine = viewer.casefold()
    return bool(mine) and any(login.casefold() == mine for login in issue.assignees)


def _count(
    selected: tuple[IssueRef, ...],
    columns: tuple[str, ...],
    label_columns: Mapping[str, tuple[str, ...]],
    members: Set[str] | None,
) -> tuple[dict[str, int], int, bool]:
    """Label-class counts, the external count and whether either is partial."""
    counts = dict.fromkeys(columns, 0)
    external = 0
    partial = False
    for issue in selected:
        if _is_external(issue, members):
            external += 1
        if issue.labels_truncated and not issue.labels:
            # Not one label was readable, so there is nothing to classify on.
            # Counting it as Untriaged would invent a triage gap out of data
            # the run never saw; the class columns omit it instead and the row
            # is marked partial to explain the shortfall.
            partial = True
            continue
        column = classify_issue(issue, label_columns)
        counts[column] += 1
        if not _classification_is_certain(issue, column, label_columns):
            partial = True
    return counts, external, partial


@dataclass(frozen=True)
class _TableSpec:
    """The settings every row of one issues table is built under."""

    generated_at: dt.datetime
    label_columns: Mapping[str, tuple[str, ...]]
    age_warn_days: int
    age_error_days: int
    members: Set[str] | None

    @property
    def columns(self) -> tuple[str, ...]:
        """The count columns: the configured label classes, then the implicit."""
        return (*self.label_columns, OTHER_COLUMN, UNTRIAGED_COLUMN)


def _row(
    repo: Repo,
    data: RepoGraphData,
    selected: tuple[IssueRef, ...],
    total: int,
    spec: _TableSpec,
) -> TableRow:
    """One repository's row over the ``selected`` issues, totalling ``total``."""
    columns = spec.columns
    counts, external, partial = _count(
        selected, columns, spec.label_columns, spec.members
    )
    partial = partial or (data.open_issues or 0) > len(data.issues)
    oldest = _oldest_age(data, selected, spec.generated_at)
    cells = (
        *(str(counts[column]) for column in columns),
        str(total),
        # Ext is window-scoped like the label classes, so it carries the same
        # partial-breakdown marker: without it an undercount reads as an exact
        # zero.
        f"{external} {TRUNCATED_MARKER}" if partial else str(external),
        _oldest_cell(oldest, partial),
    )
    # An unknown age has no value to rank on, so it is published as None: the
    # ordering layer keeps such rows last in either direction rather than
    # treating "unknown" as younger than "today".
    sort_values: tuple[float | str | None, ...] = (
        *(float(counts[column]) for column in columns),
        float(total),
        float(external),
        float(oldest) if oldest is not None else None,
    )
    return TableRow(
        repo=repo,
        cells=cells,
        sort_values=sort_values,
        cell_levels=_cell_levels(
            columns,
            counts,
            age_level(
                oldest, warn_days=spec.age_warn_days, error_days=spec.age_error_days
            ),
        ),
    )


def _build_table(
    graph: Mapping[str, RepoGraphData],
    repos: list[Repo],
    spec: _TableSpec,
    *,
    category: CategoryKey,
    viewer: str | None = None,
) -> TableSection:
    """Assemble an issues table, optionally over a subset of each backlog.

    A ``viewer`` narrows the issues a row counts to those assigned to that
    account; ``None`` counts them all. With no filter the row total is the
    authoritative ``totalCount``, exact at any size; with one it can only be
    the number of matches *in the collected window*, since GitHub was never
    asked how many matches exist beyond it. A filtered repository with no match
    in a truncated window is unknown rather than clean: a match may sit in the
    issues this run never collected.
    """
    rows: list[tuple[int, int, str, TableRow]] = []
    clean_count = 0
    unknown_count = 0
    for repo in repos:
        data = graph.get(repo.name, RepoGraphData())
        if viewer == "":
            # No account to match, so nothing can be assigned to the caller in
            # this repository or any other. That is certain whatever was
            # collected, so a direct caller gets an empty, clean table rather
            # than a wall of unknowns.
            clean_count += 1
            continue
        if data.open_issues is None:
            # The issues connection could not be read for this repository, so
            # its backlog is unknown -- never "none open".
            unknown_count += 1
            continue
        selected = (
            data.issues
            if viewer is None
            else tuple(issue for issue in data.issues if is_assigned(issue, viewer))
        )
        total = data.open_issues if viewer is None else len(selected)
        if total <= 0:
            if viewer is not None and data.open_issues > len(data.issues):
                unknown_count += 1
            else:
                clean_count += 1
            continue
        row = _row(repo, data, selected, total, spec)
        untriaged = int(row.cells[len(spec.columns) - 1])
        rows.append((total, untriaged, repo.name, row))
    # Negated numerics so the whole sort runs ascending, keeping the name
    # tiebreaker correctly ascending even when one name prefixes another.
    rows.sort(key=lambda item: (-item[0], -item[1], item[2]))

    meta = category_meta(category)
    all_columns = (
        REPOSITORY_COLUMN,
        *spec.columns,
        TOTAL_COLUMN,
        EXTERNAL_COLUMN,
        OLDEST_COLUMN,
    )
    description = _describe(
        meta.description,
        [row.cells[-1] for *_, row in rows],
        spec.members,
        filtered=viewer is not None,
    )
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


def build_issues_table(
    graph: Mapping[str, RepoGraphData],
    repos: list[Repo],
    *,
    generated_at: dt.datetime,
    label_columns: Mapping[str, tuple[str, ...]],
    age_warn_days: int,
    age_error_days: int,
    members: Set[str] | None = frozenset(),
) -> TableSection:
    """The GitHub Issues table, largest backlog first.

    Only repositories with at least one open issue are listed; the rest are
    counted as the healthy (pass) total in the standardised footer, matching
    every other table in the report. Ranking leads on total open issues -- the
    headline the table exists to report -- then on Untriaged, so two repositories
    with equal backlogs surface the less-triaged one first.

    ``members`` is the organisation's membership, used to count the issues
    raised from outside it (see :mod:`authors`). ``age_warn_days`` and
    ``age_error_days`` colour the Oldest column (see :func:`age_level`).
    """
    spec = _TableSpec(
        generated_at, label_columns, age_warn_days, age_error_days, members
    )
    return _build_table(graph, repos, spec, category=CategoryKey.GITHUB_ISSUES)


def build_assigned_issues_table(
    graph: Mapping[str, RepoGraphData],
    repos: list[Repo],
    *,
    generated_at: dt.datetime,
    label_columns: Mapping[str, tuple[str, ...]],
    age_warn_days: int,
    age_error_days: int,
    members: Set[str] | None = frozenset(),
    viewer: str = "",
) -> TableSection:
    """The GitHub Issues table narrowed to the running account's own issues.

    The same columns over the same data, so the two tables read alike; only the
    population differs. A repository with open issues but none assigned to the
    account counts as clean here rather than as a row of zeros.

    An empty ``viewer`` yields an empty table: a run that could not identify
    its own account has no personal queue, and guessing at one would put
    somebody else's work under the reader's name. Collection skips the table
    entirely in that case, so the empty result is a safety net for a direct
    caller rather than something a report renders.
    """
    spec = _TableSpec(
        generated_at, label_columns, age_warn_days, age_error_days, members
    )
    return _build_table(
        graph,
        repos,
        spec,
        category=CategoryKey.GITHUB_ISSUES_ASSIGNED,
        viewer=viewer,
    )
