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

from collections.abc import Callable, Mapping, Set

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

# Aggregate rows drawn beneath the totals, splitting the same pull requests by
# who is expected to move them. A partition, not another set of columns: every
# collected pull request falls in exactly one, so the three sum to the total.
UNASSIGNED_ROW = "Unassigned"
OTHERS_ROW = "Others"
MINE_ROW = "Mine"
ASSIGNMENT_ROWS = (UNASSIGNED_ROW, OTHERS_ROW, MINE_ROW)

# Marker appended to a repository's total when its open pull requests exceed the
# collected window, so a partial breakdown is visible as such.
TRUNCATED_MARKER = "+"


def _is_automation(pull: PullRequestRef) -> bool:
    """Whether a pull request was raised by recognised automation."""
    author = pull.author
    if author is None:
        return False
    return is_automation_author(author.login, author.typename)


def _is_external(pull: PullRequestRef, members: Set[str] | None) -> bool:
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
    pulls: tuple[PullRequestRef, ...], members: Set[str] | None
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


def is_mine(pull: PullRequestRef, viewer: str) -> bool:
    """Whether ``viewer`` is among a pull request's assignees.

    An empty ``viewer`` is nobody: a run whose account could not be read (or a
    bot token with no personal queue) must not claim another person's review
    backlog as its own, so it reports everything assigned as somebody else's.
    """
    return bool(viewer) and viewer in pull.assignees


def assignment_counts(pulls: tuple[PullRequestRef, ...], viewer: str) -> dict[str, int]:
    """Split one repository's pull requests by who they are assigned to.

    A pull request assigned to several people, one of whom is the viewer,
    counts as theirs: it is in their queue regardless of who else is on it.
    That keeps the three buckets a true partition of the collected set.
    """
    counts: dict[str, int] = dict.fromkeys(ASSIGNMENT_ROWS, 0)
    for pull in pulls:
        if not pull.assignees:
            counts[UNASSIGNED_ROW] += 1
        elif is_mine(pull, viewer):
            counts[MINE_ROW] += 1
        else:
            counts[OTHERS_ROW] += 1
    return counts


def _blocked_count(pulls: tuple[PullRequestRef, ...]) -> int:
    """Pull requests that are failing *or* conflicting, counted once each.

    The ranking tie-breaker, and deliberately a union rather than the sum of
    the two columns: those overlap, so adding them would count a pull request
    that is both as two, letting one stuck pull request outrank two separately
    stuck ones. The table already says the two columns overlap; the ranking has
    to agree with it.
    """
    return sum(1 for pull in pulls if pull.failing is True or pull.conflicting is True)


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


def _build_table(
    graph: Mapping[str, RepoGraphData],
    repos: list[Repo],
    *,
    category: CategoryKey,
    members: Set[str] | None,
    warn_threshold: int,
    error_threshold: int,
    viewer: str = "",
    select: Callable[[PullRequestRef], bool] | None = None,
    footer: bool = False,
) -> TableSection:
    """Assemble a pull-request table, optionally over a subset of each backlog.

    ``select`` narrows the pull requests a row counts. With no filter the row
    total is the authoritative ``totalCount``, exact at any size; with one, it
    can only be the number of matches *in the collected window*, since GitHub
    was never asked how many matches exist beyond it. Both cases still mark a
    truncated window, so a partial answer is never presented as a complete one.
    """
    rows: list[tuple[int, int, str, TableRow]] = []
    clean_count = 0
    unknown_count = 0
    for repo in repos:
        data = graph.get(repo.name, RepoGraphData())
        if select is not None and not viewer:
            # No account to match, so nothing can be assigned to the caller in
            # this repository or any other. That is certain regardless of what
            # was collected -- even an unreadable connection cannot hide a
            # match -- so a bot or App run gets the documented empty table
            # rather than a wall of unknowns.
            clean_count += 1
            continue
        if data.open_pull_requests is None:
            # The connection could not be read for this repository, so its
            # backlog is unknown -- never "none open".
            unknown_count += 1
            continue
        collected = data.pull_requests
        truncated = data.open_pull_requests > len(collected)
        selected = (
            collected if select is None else tuple(p for p in collected if select(p))
        )
        total = data.open_pull_requests if select is None else len(selected)
        if total <= 0:
            if select is not None and truncated:
                # Nothing matched, but the window did not cover the backlog, so
                # a match may sit in the pull requests we never collected.
                # "None of yours" is a claim this run cannot support.
                unknown_count += 1
                continue
            clean_count += 1
            continue
        counts = count_pull_requests(selected, members)
        blocked = _blocked_count(selected)
        cells = (
            *(str(counts[column]) for column in BREAKDOWN_COLUMNS),
            _total_cell(total, truncated),
        )
        sort_values: tuple[float | str | None, ...] = (
            *(float(counts[column]) for column in BREAKDOWN_COLUMNS),
            float(total),
        )
        assigned = assignment_counts(selected, viewer) if footer else {}
        rows.append(
            (
                total,
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
                    footer_values=tuple(assigned[label] for label in ASSIGNMENT_ROWS)
                    if footer
                    else (),
                ),
            )
        )
    # Negated numerics so the whole sort runs ascending, keeping the name
    # tiebreaker correctly ascending even when one name prefixes another.
    rows.sort(key=lambda item: (-item[0], -item[1], item[2]))

    meta = category_meta(category)
    description = _describe(
        meta.description,
        [row.cells[-1] for *_, row in rows],
        members,
        filtered=select is not None,
    )
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
        footer_labels=ASSIGNMENT_ROWS if footer else (),
    )


def build_pull_requests_table(
    graph: Mapping[str, RepoGraphData],
    repos: list[Repo],
    *,
    members: Set[str] | None = frozenset(),
    warn_threshold: int = 0,
    error_threshold: int = 0,
    viewer: str = "",
) -> TableSection:
    """The Pull Requests table, largest backlog first.

    Only repositories with at least one open pull request are listed; the rest
    are counted as the healthy (pass) total in the standardised footer, matching
    every other table in the report. Ranking leads on the total -- the headline
    the table exists to report -- then on the pull requests that are failing
    checks or conflicting, so two repositories with equal backlogs surface the
    more stuck one first.

    The thresholds colour the Auto column (see :func:`automation_level`); both
    default to ``0`` (off), so a caller that does not care about the automation
    cap gets a plainly rendered table. ``viewer`` drives the assignment rows
    beneath the totals; an empty one still splits Unassigned from Others, and
    simply finds nothing that is "mine".
    """
    return _build_table(
        graph,
        repos,
        category=CategoryKey.PULL_REQUESTS,
        members=members,
        warn_threshold=warn_threshold,
        error_threshold=error_threshold,
        viewer=viewer,
        footer=True,
    )


def build_assigned_pull_requests_table(
    graph: Mapping[str, RepoGraphData],
    repos: list[Repo],
    *,
    members: Set[str] | None = frozenset(),
    warn_threshold: int = 0,
    error_threshold: int = 0,
    viewer: str = "",
) -> TableSection:
    """The Pull Requests table narrowed to the running account's own queue.

    The same columns over the same data, so the two tables read alike; only the
    population differs. A repository with open pull requests but none assigned
    to the account counts as clean here rather than as a row of zeros, which
    keeps the table to the reader's actual inbox.

    An empty ``viewer`` yields an empty table: a run that could not identify
    its own account (a bot or App token, say) has no personal queue, and
    guessing at one would put somebody else's work under the reader's name.
    """
    return _build_table(
        graph,
        repos,
        category=CategoryKey.PULL_REQUESTS_ASSIGNED,
        members=members,
        warn_threshold=warn_threshold,
        error_threshold=error_threshold,
        viewer=viewer,
        select=lambda pull: is_mine(pull, viewer),
    )
