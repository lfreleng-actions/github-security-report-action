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
  genuinely the oldest open issue.
- The label-class columns are window-scoped. A repository whose open issues
  exceed the window classifies only the oldest of them, so the class columns can
  sum to less than ``Total``. The row is marked so the table never implies a
  breakdown it did not actually see.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Mapping

from github_security_report.categories import CategoryKey, category_meta
from github_security_report.models import IssueRef, Repo, RepoGraphData
from github_security_report.report import TableRow, TableSection

# Columns appended after the configured label classes. ``Other`` is "labelled,
# but not as anything we were asked about"; ``Untriaged`` is "not labelled at
# all". They are deliberately distinct: the first is a classification gap, the
# second a triage gap.
OTHER_COLUMN = "Other"
UNTRIAGED_COLUMN = "Untriaged"

# Marker appended to a repository's oldest-issue cell when its open issues
# exceed the collected window, so a partial label breakdown is visible as such.
TRUNCATED_MARKER = "+"


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


def _age_days(when: dt.datetime | None, now: dt.datetime) -> int | None:
    """Whole days between ``when`` and ``now`` (>= 0), or None when absent."""
    if when is None:
        return None
    return max((now - when).days, 0)


def _oldest_cell(
    issues: tuple[IssueRef, ...], now: dt.datetime, truncated: bool
) -> str:
    """The age of the oldest open issue, marked when the window truncated.

    The window is ordered oldest-first, so the first dated entry is the oldest
    open issue even when the window is shorter than the backlog.
    """
    age = next(
        (
            days
            for issue in issues
            if (days := _age_days(issue.created_at, now)) is not None
        ),
        None,
    )
    if age is None:
        return "unknown"
    text = "today" if age == 0 else "1 day" if age == 1 else f"{age} days"
    return f"{text} {TRUNCATED_MARKER}" if truncated else text


def build_issues_table(
    graph: Mapping[str, RepoGraphData],
    repos: list[Repo],
    *,
    generated_at: dt.datetime,
    label_columns: Mapping[str, tuple[str, ...]],
) -> TableSection:
    """The GitHub Issues table, largest backlog first.

    Only repositories with at least one open issue are listed; the rest are
    counted as the healthy (pass) total in the standardised footer, matching
    every other table in the report. Ranking leads on total open issues -- the
    headline the table exists to report -- then on Untriaged, so two repositories
    with equal backlogs surface the less-triaged one first.
    """
    columns = (*label_columns, OTHER_COLUMN, UNTRIAGED_COLUMN)
    ranked: list[tuple[int, int, str, tuple[str, ...], Repo]] = []
    clean_count = 0
    for repo in repos:
        data = graph.get(repo.name, RepoGraphData())
        if data.open_issues <= 0:
            clean_count += 1
            continue
        counts = dict.fromkeys(columns, 0)
        for issue in data.issues:
            counts[classify_issue(issue, label_columns)] += 1
        truncated = data.open_issues > len(data.issues)
        cells = (
            *(str(counts[column]) for column in columns),
            str(data.open_issues),
            _oldest_cell(data.issues, generated_at, truncated),
        )
        ranked.append(
            (data.open_issues, counts[UNTRIAGED_COLUMN], repo.name, cells, repo)
        )
    # Negated numerics so the whole sort runs ascending, keeping the name
    # tiebreaker correctly ascending even when one name prefixes another.
    ranked.sort(key=lambda item: (-item[0], -item[1], item[2]))

    meta = category_meta(CategoryKey.GITHUB_ISSUES)
    all_columns = ("Repository", *columns, "Total", "Oldest")
    description = meta.description
    if any(cells[-1].endswith(TRUNCATED_MARKER) for _, _, _, cells, _ in ranked):
        description += (
            f" A trailing '{TRUNCATED_MARKER}' marks a repository whose open "
            "issues exceed the collected window: its Total and Oldest are still "
            "exact, but the label columns cover only the oldest of its issues."
        )
    return TableSection(
        category=meta,
        columns=all_columns,
        rows=[TableRow(repo=repo, cells=cells) for _, _, _, cells, repo in ranked],
        # Every column except the repository and the trailing age is a count.
        sum_columns=frozenset(range(1, len(all_columns) - 1)),
        pass_count=clean_count,
        fail_count=len(ranked),
        description=description,
    )
