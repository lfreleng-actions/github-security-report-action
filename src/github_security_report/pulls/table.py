# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Assembling the two pull-request tables from collected backlogs.

One builder over the collected graph data, and the two public entry points
that narrow it: the whole backlog, and the running account's own queue.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Set

from github_security_report.categories import CategoryKey, category_meta
from github_security_report.models import PullRequestRef, Repo, RepoGraphData
from github_security_report.pulls.columns import (
    ALL_COLUMNS,
    BREAKDOWN_COLUMNS,
    PERSONAL_ASSIGNMENT_ROWS,
)
from github_security_report.pulls.counting import (
    _blocked_count,
    assignment_counts,
    assignment_rows,
    count_pull_requests,
    is_mine,
)
from github_security_report.pulls.presentation import (
    _cell_levels,
    _describe,
    _total_cell,
)
from github_security_report.report import TableRow, TableSection


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
    footer_labels = assignment_rows(viewer) if footer else ()
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
                    footer_values=tuple(assigned[label] for label in footer_labels),
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
        footer_labels=footer_labels,
        # Declared unconditionally: it names which labels *would* be personal,
        # and an empty footer has none of them anyway.
        personal_footer_labels=frozenset(PERSONAL_ASSIGNMENT_ROWS),
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
    beneath the totals: with a personal account they partition the backlog into
    Unassigned, Mine and Others, and without one only Unassigned is drawn (see
    :func:`assignment_rows`).
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
    Collection skips the table entirely in that case, so the empty result is a
    safety net for a direct caller rather than something a report renders.
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
