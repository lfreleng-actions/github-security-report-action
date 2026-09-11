# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Reading an outstanding request for changes from a pull-request node.

One question, asked of the two review fields the batched prefetch requests: is a
*person* waiting on this pull request's author? Kept apart from the general node
parsing for the same reason as the Copilot reading beside it -- it has to reason
about a bounded window, and so about what that window's edge does and does not
prove.
"""

from __future__ import annotations

from github_security_report.authors import is_automation_author

# The one review decision that means somebody objected. An allow-list of that
# single state rather than "anything that is not APPROVED": REVIEW_REQUIRED says
# a branch rule demands a review, not that a reviewer objected, so counting it
# would mark nearly every pull request in an organisation that requires review by
# default. Writing the rule positively also means a state GitHub adds later
# arrives *uncounted* rather than pre-counted as a blocker.
_BLOCKING_DECISION = "CHANGES_REQUESTED"


def _changes_requested(node: dict) -> bool | None:
    """Whether a *person* has asked for changes and not withdrawn it.

    Two fields, each covering the other's blind spot. ``reviewDecision`` is
    GitHub's own verdict, computed over every review and accounting for
    dismissals, so it is exact however long the review ran -- but it names
    nobody, and a GitHub App holding pull-request write permission can request
    changes exactly as a person can. ``latestOpinionatedReviews`` names the
    reviewers but is a bounded window.

    So the decision *gates* and the window *attributes*. Anything other than
    ``CHANGES_REQUESTED`` is a definite False whatever the window holds, and
    only once GitHub says changes are outstanding does identity matter. That
    keeps the cheap exact answer for the overwhelming majority of pull requests
    and pays the window's uncertainty on the few where it changes the reading.

    ``None`` is the open question: the fields could not be read, a requested
    change carried no author to attribute it to, or the window held only
    automated requests without covering every opinionated reviewer -- in which
    case a person's may sit among the reviews this run never saw. As elsewhere,
    None is "not established" rather than "nothing outstanding".
    """
    if "reviewDecision" not in node:
        return None
    decision = node["reviewDecision"]
    if not isinstance(decision, str) or decision != _BLOCKING_DECISION:
        return False
    reviews = node.get("latestOpinionatedReviews")
    if not isinstance(reviews, dict):
        return None
    nodes = reviews.get("nodes")
    if not isinstance(nodes, list):
        return None
    seen = 0
    for review in nodes:
        if not isinstance(review, dict):
            continue
        seen += 1
        if review.get("state") != _BLOCKING_DECISION:
            continue
        author = review.get("author")
        if not isinstance(author, dict):
            # A request for changes we cannot attribute -- a deleted account,
            # say. Counting it would guess at a person; skipping it would let
            # the loop fall through to a confident False.
            return None
        if not is_automation_author(author.get("login"), author.get("__typename")):
            return True
    total = reviews.get("totalCount")
    if not isinstance(total, int) or isinstance(total, bool) or total > seen:
        return None
    return False
