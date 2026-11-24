# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""The exceptions that abort a run rather than degrade a signal.

Almost every failure the client meets is absorbed: an unreadable feature
renders as unknown and the report goes on. These are the exceptions to that
rule -- the cases where continuing would publish a report that is confidently
wrong -- gathered here so the transport, the read layers and the CLI share one
definition of "stop".
"""

from __future__ import annotations

# The ``reason`` a :class:`GraphBatchError` carries when a GraphQL rate limit
# refused the query, which the CLI exits on as it does a spent REST budget.
GRAPH_RATE_LIMITED = "rate limited"


class NetworkError(RuntimeError):
    """The GitHub API was unusable after exhausting the retry budget.

    Raised for transport-level failures (DNS, connection, TLS, or read
    timeout) against the GitHub API that persist across every retry within
    ``API_MAX_TOTAL_WAIT_SECONDS``, and by callers whose data is load-bearing
    for the whole report (the batched GraphQL prefetch) when GitHub keeps
    answering with server errors. The run aborts rather than rendering a
    report from missing data: when the API itself cannot be relied on, an
    empty or "all clean / all unknown" report is actively misleading.
    Transport failures against the third-party Scorecard endpoint do not
    raise this -- they degrade that one signal instead.
    """


class AuthError(NetworkError):
    """GitHub rejected the credentials (HTTP 401).

    Distinct from the permission-shaped failures the report degrades over. A
    403 usually means "this token cannot see this one feature", which is a
    legitimate per-signal unknown; a 401 means the token itself is invalid,
    expired or revoked, so every remaining read fails the same way. Degrading
    would render a confident "all clean" report out of nothing but rejections
    -- the false negative a security report must never publish, and one that a
    scheduled run would happily push to GitHub Pages over a good report.

    Subclasses :class:`NetworkError` so any caller already aborting on an
    unusable API keeps doing so; the CLI catches it first to report the cause
    and exit with its own status.
    """


class RateLimitError(NetworkError):
    """A read found GitHub's primary rate limit spent (403/429, remaining 0).

    GitHub's guidance is not to retry until ``x-ratelimit-reset``, and every
    later read would be refused the same way, so a run that carried on would
    publish a report made of unknowns. The transport waits out a reset that
    falls within the retry budget; otherwise it raises this at once.

    Subclasses :class:`NetworkError`, as :class:`AuthError` does, so a caller
    already aborting on an unusable API keeps doing so; the CLI catches it
    first to word the message and exit with its own status. ``reset`` is the
    reset time in UTC epoch seconds and ``retry_after`` the ``Retry-After``
    wait in seconds, each ``None`` where GitHub gave none; ``resource`` is
    the ``x-ratelimit-resource`` the request counted against.
    """

    def __init__(
        self,
        *,
        method: str,
        url: str,
        status: int,
        resource: str | None,
        reset: int | None,
        retry_after: float | None,
    ) -> None:
        super().__init__(
            f"Rate limit exhausted: {method} {url} answered HTTP {status} with "
            "no requests remaining"
        )
        self.method = method
        self.url = url
        self.status = status
        self.resource = resource
        self.reset = reset
        self.retry_after = retry_after


class GraphBatchError(NetworkError):
    """A batched GraphQL prefetch failed as a whole, for every repository in it.

    Carries whether the failure is ``splittable`` -- one that a *smaller*
    query might survive -- so the collection layer can tell it from one that
    is not. GitHub enforces a per-query execution budget on GraphQL and
    reports breaching it in three shapes -- a 502 or 504 gateway timeout from
    the edge, an HTTP 200 with a ``null`` ``data`` object, or an HTTP 200
    whose ``errors`` say the query exceeded its resource limits part-way
    through -- so a large aliased query can fail for no reason other than its
    own size: the same repositories read fine in two halves. A permission
    error, an exhausted rate limit or a 500/503 outage, by contrast, would
    fail identically at any size, and splitting
    would only multiply the requests. The raiser decides, because only it has
    seen the response: a rate limit on GraphQL also arrives as HTTP 200 with
    no ``data``, told apart from a timeout only by its ``errors`` entry.

    ``reason`` is the short phrase a log line can carry (``HTTP 502``,
    ``resource limits exceeded``); the full message stays for the abort.
    """

    def __init__(
        self,
        message: str,
        *,
        status: int,
        splittable: bool,
        reason: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.splittable = splittable
        self.reason = reason if reason is not None else f"HTTP {status}"

    @property
    def rate_limited(self) -> bool:
        """Whether a spent GraphQL rate limit refused the query."""
        return self.reason == GRAPH_RATE_LIMITED
