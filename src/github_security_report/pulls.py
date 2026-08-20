# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Open pull requests per repository, split by author and by what blocks them.

A reporting category outside the four-state per-signal model, and a sibling of
:mod:`issues`: a plain table counting each repository's open pull requests
across two independent groupings.

**Who raised it.** ``Human`` and ``Auto`` partition the counted pull requests:
``Auto`` is recognised automation (Dependabot, pre-commit.ci, Renovate and any
other bot actor -- see :mod:`authors`), ``Human`` is everyone else. ``Ext``
counts the human pull requests raised from outside the organisation, so it is a
**subset of Human**, never a bot. Counting automation as external would be
literally true by GitHub's association (``dependabot[bot]`` reports
``CONTRIBUTOR`` or ``NONE``) and useless in practice: it would bury genuine
outside contributions under routine dependency updates.

**What is holding it up.** ``Conflict``, ``Fail`` and ``Draft`` are independent
of the author split and of each other, so one pull request can be counted in
several of them. They therefore do not sum to the total, and are not meant to.

The same bounded-window caveat as the issues table applies: ``Total`` is exact
at any size because it comes from ``totalCount``, while the breakdown columns
only see the collected window, so they can sum to less than ``Total``. A row
whose window truncated is marked, so a partial breakdown is visible as such.
"""

from __future__ import annotations

from collections.abc import Mapping, Set

from github_security_report.authors import is_automation_author, is_external_author
from github_security_report.categories import CategoryKey, category_meta
from github_security_report.models import PullRequestRef, Repo, RepoGraphData
from github_security_report.report import (
    CELL_BAD,
    CELL_GOOD,
    CELL_WARN,
    TableRow,
    TableSection,
)

REPOSITORY_COLUMN = "Repository"
HUMAN_COLUMN = "Human"
AUTOMATION_COLUMN = "Auto"
DRAFT_COLUMN = "Draft"
EXTERNAL_COLUMN = "Ext"
FAILING_COLUMN = "Fail"
CONFLICT_COLUMN = "Conflict"
TOTAL_COLUMN = "Total"

# Counted columns in render order, framed by the repository and the total.
# Ordered so related columns read together: the author split first, with Ext
# beside Human because it qualifies it (Ext is a subset of Human, never of
# Auto), then the blockers, worst first -- a conflict needs a human to rebase,
# a failing check may only need a re-run, and a draft is not blocked at all.
BREAKDOWN_COLUMNS = (
    HUMAN_COLUMN,
    EXTERNAL_COLUMN,
    AUTOMATION_COLUMN,
    CONFLICT_COLUMN,
    FAILING_COLUMN,
    DRAFT_COLUMN,
)

ALL_COLUMNS = (REPOSITORY_COLUMN, *BREAKDOWN_COLUMNS, TOTAL_COLUMN)

# Marker appended to a repository's total when its open pull requests exceed the
# collected window, so a partial breakdown is visible as such.
TRUNCATED_MARKER = "+"


def _is_automation(pull: PullRequestRef) -> bool:
    """Whether a pull request was raised by recognised automation."""
    author = pull.author
    if author is None:
        return False
    return is_automation_author(author.login, author.typename)


def _is_external(pull: PullRequestRef, members: Set[str]) -> bool:
    """Whether a pull request came from a human outside the organisation.

    An author who cannot be classified is not counted: the column reports
    contributions confirmed to come from outside, so an indeterminate author
    understates it rather than inventing an outsider.
    """
    author = pull.author
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


def count_pull_requests(
    pulls: tuple[PullRequestRef, ...], members: Set[str]
) -> dict[str, int]:
    """Per-column counts for one repository's collected pull requests.

    Every pull request lands in exactly one of Human/Auto, and independently in
    any of the blocked columns, so the blocked counts overlap the author split
    by design.
    """
    counts: dict[str, int] = dict.fromkeys(BREAKDOWN_COLUMNS, 0)
    for pull in pulls:
        automation = _is_automation(pull)
        counts[AUTOMATION_COLUMN if automation else HUMAN_COLUMN] += 1
        if pull.draft:
            counts[DRAFT_COLUMN] += 1
        if not automation and _is_external(pull, members):
            counts[EXTERNAL_COLUMN] += 1
        # Only an established failure or conflict counts. GitHub computes
        # mergeability lazily and reports no rollup at all when no checks have
        # run, and neither absence is evidence that a pull request is ready.
        if pull.failing is True:
            counts[FAILING_COLUMN] += 1
        if pull.conflicting is True:
            counts[CONFLICT_COLUMN] += 1
    return counts


def _total_cell(total: int, truncated: bool) -> str:
    """The total, marked when the collected window did not cover it."""
    return f"{total} {TRUNCATED_MARKER}" if truncated else str(total)


def automation_level(
    value: int, *, warn_threshold: int, error_threshold: int
) -> str | None:
    """Emphasis for an automation backlog of ``value`` open pull requests.

    An organisation caps how many pull requests automation may hold open per
    repository; at the cap, Dependabot stops raising them and the repository
    quietly stops receiving dependency updates. That makes a large automation
    backlog an outage in waiting rather than a tidiness problem, so it is
    flagged before it arrives: warning *above* the warn threshold, error *at or
    above* the error threshold, which is the cap itself.

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


def _describe(base: str, total_cells: list[str]) -> str:
    """Extend the category description with the caveat the table earned.

    Appended only when a row actually shows it, so a report whose windows all
    covered their backlogs carries no unexplained qualification.
    """
    if any(cell.endswith(TRUNCATED_MARKER) for cell in total_cells):
        return base + (
            f" A trailing '{TRUNCATED_MARKER}' marks a repository whose "
            "breakdown is partial -- its open pull requests exceed the "
            "collected window, so the columns sum to less than Total. Total "
            "stays exact either way."
        )
    return base


def build_pull_requests_table(
    graph: Mapping[str, RepoGraphData],
    repos: list[Repo],
    *,
    members: Set[str] = frozenset(),
    warn_threshold: int = 0,
    error_threshold: int = 0,
) -> TableSection:
    """The Pull Requests table, largest backlog first.

    Only repositories with at least one open pull request are listed; the rest
    are counted as the healthy (pass) total in the standardised footer, matching
    every other table in the report. Ranking leads on the total -- the headline
    the table exists to report -- then on the pull requests that are actually
    blocked (failing checks or conflicting), so two repositories with equal
    backlogs surface the more stuck one first.

    The thresholds colour the Auto column (see :func:`automation_level`); both
    default to ``0`` (off), so a caller that does not care about the automation
    cap gets a plainly rendered table.
    """
    rows: list[tuple[int, int, str, TableRow]] = []
    clean_count = 0
    unknown_count = 0
    for repo in repos:
        data = graph.get(repo.name, RepoGraphData())
        if data.open_pull_requests is None:
            # The connection could not be read for this repository, so its
            # backlog is unknown -- never "none open".
            unknown_count += 1
            continue
        if data.open_pull_requests <= 0:
            clean_count += 1
            continue
        counts = count_pull_requests(data.pull_requests, members)
        truncated = data.open_pull_requests > len(data.pull_requests)
        blocked = counts[FAILING_COLUMN] + counts[CONFLICT_COLUMN]
        cells = (
            *(str(counts[column]) for column in BREAKDOWN_COLUMNS),
            _total_cell(data.open_pull_requests, truncated),
        )
        sort_values: tuple[float | str | None, ...] = (
            *(float(counts[column]) for column in BREAKDOWN_COLUMNS),
            float(data.open_pull_requests),
        )
        rows.append(
            (
                data.open_pull_requests,
                blocked,
                repo.name,
                TableRow(
                    repo=repo,
                    cells=cells,
                    sort_values=sort_values,
                    cell_levels=_cell_levels(
                        counts,
                        warn_threshold=warn_threshold,
                        error_threshold=error_threshold,
                    ),
                ),
            )
        )
    # Negated numerics so the whole sort runs ascending, keeping the name
    # tiebreaker correctly ascending even when one name prefixes another.
    rows.sort(key=lambda item: (-item[0], -item[1], item[2]))

    meta = category_meta(CategoryKey.PULL_REQUESTS)
    description = _describe(meta.description, [row.cells[-1] for *_, row in rows])
    return TableSection(
        category=meta,
        columns=ALL_COLUMNS,
        rows=[row for _, _, _, row in rows],
        # Every column but the repository is an additive count, including the
        # total (whose cell may carry a truncation marker, which parses to 0
        # only if the whole cell is unreadable -- the marker is separated by a
        # space, so the leading integer still reads).
        sum_columns=frozenset(range(1, len(ALL_COLUMNS))),
        numeric_columns=frozenset(range(1, len(ALL_COLUMNS))),
        pass_count=clean_count,
        fail_count=len(rows),
        unknown_count=unknown_count,
        description=description,
    )
