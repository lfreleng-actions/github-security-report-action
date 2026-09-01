# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Reading outstanding Copilot review feedback from a pull-request node.

One question, asked of the ``reviewThreads`` connection the batched prefetch
requests: is this pull request still waiting on a human to answer GitHub's
automated code reviewer? Kept apart from the general node parsing because it is
the only reading that has to reason about a *nested* bounded window, and so
about what the window's edge does and does not prove.
"""

from __future__ import annotations

from github_security_report.authors import is_copilot_reviewer


def _thread_opened_by_copilot(thread: dict) -> bool:
    """Whether a review thread was opened by the automated code reviewer.

    The author is taken from the thread's **first** comment, which is the one
    that opened it. Later replies are commonly the human answering the review,
    so keying on any comment would credit Copilot with threads it did not raise.
    """
    comments = thread.get("comments")
    if not isinstance(comments, dict):
        return False
    nodes = comments.get("nodes") or []
    opening = nodes[0] if nodes else None
    if not isinstance(opening, dict):
        return False
    author = opening.get("author")
    if not isinstance(author, dict):
        return False
    return is_copilot_reviewer(author.get("login"), author.get("__typename"))


def _copilot_unresolved(node: dict) -> bool | None:
    """Whether the pull request has unresolved Copilot review feedback.

    ``True`` when a review thread opened by GitHub's automated code reviewer is
    still unresolved. ``False`` only when the collected window covered *every*
    thread and none of them qualified, so the answer is complete.

    ``None`` is the indeterminate case, and covers three readings that must not
    be presented as "nothing outstanding": review threads that could not be read
    at all; a pull request carrying more threads than the window returned with
    no qualifying thread among the ones it did -- an unresolved thread may sit
    in those never collected; and a ``totalCount`` that is absent or unusable,
    which leaves the window's coverage unproven and so cannot establish that
    every thread was seen. This mirrors the rule ``mergeable`` and the check
    rollup already follow: not established is not the same as nothing to report.

    An outdated thread still counts. GitHub marks a thread outdated when the
    code beneath it changes but does not resolve it, so the feedback remains
    unanswered -- which is exactly what the column reports.
    """
    threads = node.get("reviewThreads")
    if not isinstance(threads, dict):
        return None
    nodes = threads.get("nodes")
    if not isinstance(nodes, list):
        return None
    seen = 0
    for thread in nodes:
        if not isinstance(thread, dict):
            continue
        seen += 1
        if thread.get("isResolved") is not True and _thread_opened_by_copilot(thread):
            return True
    total = threads.get("totalCount")
    if not isinstance(total, int) or isinstance(total, bool) or total > seen:
        return None
    return False
