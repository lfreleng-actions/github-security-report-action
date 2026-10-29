# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Reading the ``errors`` array of a batched GraphQL query.

GitHub answers a partially-failed aliased query with HTTP 200: the readable
aliases populated, the rest ``null`` or missing individual fields, and an
``errors`` array explaining why. Deciding what those entries mean for each
repository -- unreadable, unreadable in one isolable field, or a symptom of the
whole batch being too large -- is a policy of its own, kept here so the client
that issues the query stays about issuing it.
"""

from __future__ import annotations

from github_security_report.client.errors import GraphBatchError
from github_security_report.client.paging import GraphQLResult

# Fields whose failure can be isolated to the data they feed instead of failing
# the whole repository. Only fields the model already carries a dedicated
# "unknown" for qualify: ``pullRequests`` has ``open_pull_requests=None``, which
# every pull-request table already renders as unknown, so a token that cannot
# read pull requests loses that one table rather than the repository's releases,
# issues, tags and Dependabot posture as well.
_ISOLABLE_FIELDS = frozenset({"pullRequests"})

# The message GitHub attaches to every error when a query is cut short for
# exceeding its execution budget. Unlike a field the token cannot read, this is
# a property of the query's size: the same repositories resolve in full when
# asked for in smaller batches, so it is reported as a batch failure to split
# rather than as repositories to mark unknown.
_RESOURCE_LIMIT_MESSAGE = "Resource limits for this query exceeded"

# The statuses GitHub's edge answers with when a GraphQL query runs past its
# time limit: 502 is the shape observed against lfreleng-actions (arriving
# ~10.7 s after each request), and 504 is the gateway's own timeout status. A
# 500 or 503 is an outage rather than a verdict on the query's size; splitting
# would hand each smaller batch a fresh retry budget against a service that is
# down, multiplying requests and delaying an abort that smaller queries cannot
# avert.
_QUERY_TIMEOUT_STATUSES = frozenset({502, 504})

# The ``type`` GitHub puts on every error when a GraphQL rate limit is spent.
# Two spellings are in use -- ``RATE_LIMITED`` for the hourly point budget and
# ``RATE_LIMIT`` (with ``code: graphql_rate_limit``) for the secondary limit on
# concurrent or bursty queries -- so the prefix is matched. Either arrives as
# HTTP 200 with a ``null`` ``data`` object, the same shape as a timed-out query,
# and is the one such response that a smaller batch cannot fix: every retry
# would burn another request against an exhausted budget.
_RATE_LIMIT_TYPE_PREFIX = "RATE_LIMIT"


def _exceeded_resource_limits(errors: object) -> bool:
    """Whether ``errors`` shows GitHub cut the query short for its size."""
    if not isinstance(errors, list):
        return False
    return any(
        isinstance(e, dict) and _RESOURCE_LIMIT_MESSAGE in str(e.get("message", ""))
        for e in errors
    )


def _rate_limited(errors: object) -> bool:
    """Whether ``errors`` shows a GraphQL rate limit is exhausted."""
    if not isinstance(errors, list):
        return False
    return any(
        isinstance(e, dict)
        and str(e.get("type", "")).startswith(_RATE_LIMIT_TYPE_PREFIX)
        for e in errors
    )


def _batch_response(
    org: str,
    count: int,
    result: GraphQLResult,
    *,
    what: str = "prefetch",
    unit: str = "repositories",
) -> tuple[dict, list]:
    """The ``(data, errors)`` of a batched query, or the failure to abort on.

    ``what`` names the query in the messages and ``unit`` what it carried
    (``prefetch`` of ``repositories``; ``run drill-down`` of ``runs``), since
    both share this policy and an operator reading the error needs to know
    which one failed.

    Raises :class:`GraphBatchError` when the query failed as a whole -- for
    every one of the ``count`` repositories -- and says whether the caller may
    retry them in smaller batches. Four shapes are told apart, in this order:

    * A non-200 ``status`` (``data`` is then ``None``): a 502 or 504 is
      GitHub's edge giving up on a query that ran too long, which a smaller
      batch may avoid; any other status -- a 403/429 that outlived the
      transport's retry budget, or a 500/503 outage -- would recur at any size.
    * ``RATE_LIMITED`` or ``RATE_LIMIT`` in ``errors``: a GraphQL rate limit
      (hourly points or the secondary burst limit) is spent, so a retry in any
      batch size would only burn requests against it.
    * "Resource limits exceeded" in ``errors``: GitHub ran out of execution
      budget part-way through and nulled the rest. Those nulls are a symptom of
      the batch's size, not per-repository read failures, so the batch is
      failed for splitting rather than (typically most of) it marked unknown.
    * No ``data`` object at all: with the rate limit ruled out, this is how
      GitHub reports a query it could not finish in time.

    Anything else is a response the caller can read alias by alias.

    Each message ends with the remedy that fits the failure: a batch of
    several repositories can be retried smaller, but by the time a failure
    escapes the adaptive collector the batch is usually a single repository,
    and advising a smaller batch then would be advice that cannot be followed;
    a permission error was never retried, so it must not claim a retry budget
    was spent.
    """
    status = result.status
    if status != 200:
        raise GraphBatchError(
            f"GraphQL {what} for {org} failed with HTTP {status}; aborting "
            f"because the data for {count} {unit} would otherwise be "
            "fabricated from defaults (e.g. a repository reported as never "
            f"released). {_status_remedy(status, count)}",
            status=status,
            splittable=status in _QUERY_TIMEOUT_STATUSES,
        )
    errors = result.errors
    if _rate_limited(errors):
        raise GraphBatchError(
            f"GraphQL {what} for {org} was refused: a GraphQL API rate "
            f"limit is exhausted; aborting rather than reporting "
            f"{count} {unit} from fabricated defaults. "
            "Retry once the budget resets.",
            status=status,
            splittable=False,
            reason="rate limited",
        )
    if _exceeded_resource_limits(errors):
        raise GraphBatchError(
            f"GraphQL {what} for {org} exceeded GitHub's resource limits "
            f"for a single query across {count} {unit}; "
            "aborting rather than reporting the unresolved fields as "
            f"unknown. {_size_remedy(count)}",
            status=status,
            splittable=True,
            reason="resource limits exceeded",
        )
    data = result.data
    if data is None:
        raise GraphBatchError(
            f"GraphQL {what} for {org} returned no data for any of "
            f"{count} {unit}; aborting rather than reporting "
            f"fabricated defaults. {_size_remedy(count)} "
            f"errors={errors!r}",
            status=status,
            splittable=True,
            reason="HTTP 200 with no data",
        )
    return data, errors


def _size_remedy(count: int) -> str:
    """The operator's next step after a size-shaped failure of ``count`` repos."""
    if count > 1:
        return "Retry with a smaller --graph-batch."
    return (
        "This repository's query exceeds GitHub's limits on its own; retry "
        "later, or exclude the repository if it persists."
    )


def _status_remedy(status: int, count: int) -> str:
    """The operator's next step after a non-200 answer to a batched query.

    Mirrors the transport's own handling of each status: a gateway timeout
    and a 5xx outage both outlived the retry budget, whereas a 403 is handed
    back at once when it carries no rate-limit headers (a genuine permission
    error) and only after the budget when it does, so it is described as
    either without claiming a delay that may not have happened.
    """
    if status in _QUERY_TIMEOUT_STATUSES:
        return (
            "GitHub timed the query out on every retry, which points at its "
            f"size. {_size_remedy(count)}"
        )
    if status == 403:
        return (
            "HTTP 403 is either a permission error (check that the token can "
            "read this organisation's repositories) or a secondary rate limit "
            "that outlived the retry budget (retry later)."
        )
    if status == 429:
        return "Rate limited beyond the retry budget; retry later."
    if status >= 500:
        return (
            "GitHub answered with a server error on every retry, which is an "
            "outage rather than a problem with the query; retry later."
        )
    return "Check the GitHub API status and retry."


def _alias_errors(errors: object, alias_count: int) -> tuple[set[str], set[str]]:
    """Alias keys implicated by a batched query's ``errors`` array.

    Returns ``(unreadable, pull_requests_only)``: aliases that must be failed
    wholesale, and aliases whose only failures were confined to fields in
    :data:`_ISOLABLE_FIELDS`.

    GitHub reports a *field-level* failure with HTTP 200: the alias is still a
    populated dictionary, the field that failed is null, and an ``errors``
    entry carries its path (e.g. ``["r3", "latestRelease"]``). Parsing such a
    node would convert a read failure into a confident negative -- a nulled
    ``latestRelease`` is indistinguishable from "never released" -- so the
    whole alias is treated as unreadable rather than partially trusted.

    The alias is failed wholesale rather than per field, because a per-field
    flag would have to be threaded through every table to be honest about which
    half of a row is trustworthy, whereas one unknown repository is already a
    state every table renders correctly. The exception is a field the model
    *already* carries a dedicated unknown for: failing the whole repository for
    one of those would let an optional, permission-sensitive section take the
    rest of the report down with it -- a token without pull-request access would
    lose its releases, issues and Dependabot posture too.

    An error whose path names no alias cannot be attributed, so it implicates
    every alias in the batch: with no way to tell which repositories it
    touched, treating any of them as successfully read would be a guess.

    An error *nested* inside an isolable field is classified by that field, and
    deliberately so. ``reviewThreads`` is non-null in GitHub's schema
    (``PullRequestReviewThreadConnection!``), so a resolver failure there does
    not null the connection: it propagates up to the nearest nullable ancestor,
    which is the pull-request node itself. The node arrives as ``null`` and
    carries none of its facts, so ignoring the error would silently drop that
    pull request from every column while ``totalCount`` still counted it --
    understating the breakdown with nothing to say so. Failing the connection
    reports the repository as unknown instead, which every table renders
    correctly.
    """
    all_aliases = {f"r{i}" for i in range(alias_count)}
    if not isinstance(errors, list):
        return set(), set()
    unreadable: set[str] = set()
    isolated: set[str] = set()
    for entry in errors:
        path = entry.get("path") if isinstance(entry, dict) else None
        if not isinstance(path, list) or not path:
            return all_aliases, set()
        head = path[0]
        if not isinstance(head, str) or head not in all_aliases:
            return all_aliases, set()
        field = path[1] if len(path) > 1 else None
        if isinstance(field, str) and field in _ISOLABLE_FIELDS:
            isolated.add(head)
        else:
            unreadable.add(head)
    # An alias with failures on both sides is unreadable: the isolable one is
    # the lesser problem, and the other still poisons the rest of the node.
    return unreadable, isolated - unreadable
