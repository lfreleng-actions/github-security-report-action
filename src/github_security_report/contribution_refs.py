# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Who opened an issue or pull request, and the triage facts each carries.

Kept apart from :mod:`github_security_report.models`, which re-exports them,
so the domain models stay within the size the repository's gate allows.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass


@dataclass(frozen=True)
class AuthorRef:
    """The identity facts needed to classify who made a contribution.

    Deliberately raw: the transport layer records what GitHub said, and the
    table builders apply the policy (see :mod:`authors`). ``association`` is
    GitHub's ``authorAssociation``, which is computed relative to the viewing
    token and so is evidence rather than a verdict.
    """

    login: str = ""
    # GraphQL ``__typename`` of the actor: "User", "Bot", "Organization", ...
    typename: str = ""
    association: str = ""


@dataclass(frozen=True)
class IssueRef:
    """One open issue's triage-relevant facts.

    Carries only what the open-issues reporting needs: the label set, so issues
    can be classified into buckets (bug, enhancement, and so on), the creation
    time, so the oldest outstanding issue and its age can be reported, and the
    author, so contributions from outside the organisation can be counted.
    ``created_at`` is ``None`` when GitHub supplied no usable timestamp, in
    which case the issue cannot contribute to the oldest-issue age.
    """

    number: int
    title: str
    labels: tuple[str, ...] = ()
    # True when the issue carries more labels than the query's window returned,
    # so ``labels`` may omit the one that would have classified it.
    labels_truncated: bool = False
    created_at: dt.datetime | None = None
    # None when GitHub returned no usable author (a deleted account renders the
    # ``author`` field null), which is distinct from a known insider.
    author: AuthorRef | None = None
    # Logins of everyone the issue is assigned to, lower-cased. GitHub caps
    # assignees at 10, so the collected window is exhaustive and an empty tuple
    # genuinely means "nobody is assigned" rather than "not read".
    assignees: tuple[str, ...] = ()


@dataclass(frozen=True)
class PullRequestRef:
    """One open pull request's review-load facts.

    ``draft`` and the four blocked flags are independent of the author and of
    each other, so one pull request may be a draft *and* conflicting *and*
    awaiting review; the table counts each axis separately rather than bucketing
    rows.
    """

    number: int
    author: AuthorRef | None = None
    draft: bool = False
    # Logins of everyone the pull request is assigned to, lower-cased. GitHub
    # caps assignees at 10, so the collected window is exhaustive and an empty
    # tuple genuinely means "nobody is assigned" rather than "not read".
    assignees: tuple[str, ...] = ()
    # True when GitHub reports the branch as CONFLICTING. None while GitHub has
    # not finished computing mergeability (it is calculated lazily, and answers
    # UNKNOWN until then), so a cold sweep reports "not established" rather than
    # asserting a clean merge it never confirmed.
    conflicting: bool | None = None
    # True when the head commit's combined check rollup failed. None when no
    # checks have run at all, which is not a passing result.
    failing: bool | None = None
    # True when at least one of the pull request's review threads was opened by
    # GitHub's automated code reviewer and is still unresolved. None when the
    # question could not be settled -- the review threads were unreadable, or
    # the collected window did not cover them and none of the threads it did
    # cover was an unresolved Copilot thread, so an unresolved one may sit in
    # the threads this run never saw. As with ``conflicting`` and ``failing``,
    # None is "not established" rather than "nothing outstanding".
    copilot_unresolved: bool | None = None
    # True when a *person* has requested changes and not withdrawn it. Read
    # from ``reviewDecision``, which GitHub computes over every review and so is
    # exact at any review count, attributed through the bounded window of
    # opinionated reviews -- the decision names nobody, and a GitHub App can
    # request changes exactly as a person can.
    #
    # None where that attribution could not be settled: the fields were
    # unreadable, a request carried no author, or the window held only automated
    # requests without covering every reviewer. As with the flags above, None is
    # "not established" rather than "nothing outstanding" -- though it is far
    # rarer here, since it needs GitHub to report changes requested *and* the
    # window to fall short.
    #
    # Only CHANGES_REQUESTED counts. REVIEW_REQUIRED is deliberately excluded:
    # it reports that a branch rule demands a review, not that anyone objected,
    # so on an organisation that requires review by default it would mark almost
    # every human pull request and say nothing about any of them.
    changes_requested: bool | None = None
