# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Placing one repository's pull requests in the table's buckets.

Two independent groupings over the same collected pull requests: the column
counts (who raised it, and what is holding it up) and the aggregate rows
beneath the totals (who is expected to move it).
"""

from __future__ import annotations

from collections.abc import Set

from github_security_report.authors import is_automation_author, is_external_author
from github_security_report.models import PullRequestRef
from github_security_report.pulls.columns import (
    ASSIGNMENT_ROWS,
    AUTOMATION_COLUMN,
    BREAKDOWN_COLUMNS,
    CONFLICT_COLUMN,
    COPILOT_COLUMN,
    DRAFT_COLUMN,
    EXTERNAL_COLUMN,
    FAILING_COLUMN,
    HUMAN_COLUMN,
    MINE_ROW,
    OTHERS_ROW,
    UNASSIGNED_ROW,
)


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
        # Only an established failure, conflict or outstanding review counts.
        # GitHub computes mergeability lazily and reports no rollup at all when
        # no checks have run, and a review-thread window can fall short of a
        # long review cycle; none of those absences is evidence that a pull
        # request is ready.
        if pull.failing is True:
            counts[FAILING_COLUMN] += 1
        if pull.conflicting is True:
            counts[CONFLICT_COLUMN] += 1
        if pull.copilot_unresolved is True:
            counts[COPILOT_COLUMN] += 1
    return counts


def is_mine(pull: PullRequestRef, viewer: str) -> bool:
    """Whether ``viewer`` is among a pull request's assignees.

    An empty ``viewer`` is nobody: a run whose account could not be read (or a
    bot token with no personal queue) must not claim another person's review
    backlog as its own, so it reports everything assigned as somebody else's.
    """
    return bool(viewer) and viewer in pull.assignees


def assignment_rows(viewer: str) -> tuple[str, ...]:
    """The assignment rows a run with this ``viewer`` can honestly draw.

    With a personal account, all three: the reader can place themselves in the
    breakdown. Without one -- a bot or App token, or an account that could not
    be read -- ``Mine`` is empty by construction and ``Others`` degenerates into
    "assigned to somebody", a partition drawn against a person who is not there.
    Such a run reports ``Unassigned`` alone, which is a property of the pull
    request rather than of the token, and loses nothing: the assigned count is
    the totals row minus that one figure.
    """
    return ASSIGNMENT_ROWS if viewer else (UNASSIGNED_ROW,)


def assignment_counts(pulls: tuple[PullRequestRef, ...], viewer: str) -> dict[str, int]:
    """Split one repository's pull requests by who they are assigned to.

    A pull request assigned to several people, one of whom is the viewer,
    counts as theirs: it is in their queue regardless of who else is on it.
    That keeps the buckets a true partition of the collected set.

    Keyed by :func:`assignment_rows`, so a run with no personal account gets no
    viewer-relative counts at all -- they are not computed, rather than computed
    and then withheld.
    """
    counts: dict[str, int] = dict.fromkeys(assignment_rows(viewer), 0)
    for pull in pulls:
        if not pull.assignees:
            counts[UNASSIGNED_ROW] += 1
        elif viewer:
            counts[MINE_ROW if is_mine(pull, viewer) else OTHERS_ROW] += 1
    return counts


def copilot_indeterminate(pulls: tuple[PullRequestRef, ...]) -> bool:
    """Whether any of these pull requests left the Copilot question unsettled.

    An indeterminate reading is dropped from the count, exactly like an
    unestablished conflict or check failure, which renders it as an ordinary
    zero. For Conflict and Fail that is fair: those absences are GitHub still
    computing, and settle themselves on a later run. A Copilot absence is
    different -- it is *this* collection's bounded thread window falling short,
    a limit of the report rather than of the moment -- so a row carrying one is
    a lower bound, and the table has to say so rather than presenting a zero it
    has not earned.
    """
    return any(pull.copilot_unresolved is None for pull in pulls)


def _blocked_count(pulls: tuple[PullRequestRef, ...]) -> int:
    """Pull requests that are failing, conflicting *or* awaiting Copilot, once each.

    The ranking tie-breaker, and deliberately a union rather than the sum of
    the three columns: those overlap, so adding them would count a pull request
    that is both as two, letting one stuck pull request outrank two separately
    stuck ones. The table already says the columns overlap; the ranking has
    to agree with it.

    Unresolved Copilot feedback joins the union because it is the same kind of
    fact as the other two -- work the pull request is waiting on a human for --
    and the table already colours it as blocking. Leaving it out would rank a
    repository whose whole backlog is awaiting review below an untouched one.
    """
    return sum(
        1
        for pull in pulls
        if pull.failing is True
        or pull.conflicting is True
        or pull.copilot_unresolved is True
    )
