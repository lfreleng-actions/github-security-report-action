# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Request accounting: what a client's run cost, for the operator's log.

:class:`~github_security_report.client.transport.Transport` reports every
attempt it issues and every response it receives to a :class:`_RequestTally`;
:class:`RequestStats` is the frozen snapshot it exposes as ``stats``.
"""

from __future__ import annotations

import time
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Literal

import httpx

from github_security_report.client.events import RequestKind

# What a retried request is retrying: a transport failure that produced no
# response, or a degraded (5xx/403/429) response the backoff policy retries.
RetryKind = Literal["transport", "degraded"]


@dataclass(frozen=True)
class RequestStats:
    """What a client's run has cost so far, for the operator's log.

    ``requests`` counts every HTTP request *issued*, retried ones included,
    whether or not it was answered. ``by_status`` breaks the answered ones down
    by status code, so ``requests - responses`` is the number of attempts that
    never produced a response (a DNS, connection, TLS or read failure).
    ``transport_retries`` counts those that were retried, and
    ``degraded_retries`` the 5xx/403/429 responses retried under the shared
    backoff policy.

    ``rest_requests``, ``graphql_requests`` and ``external_requests`` split
    ``requests`` by what was asked: a REST endpoint, the GraphQL endpoint, or
    a third-party API (Scorecard). ``not_modified`` is how many answers were
    ``304``: conditional reads the run-store sync made that cost no budget.

    ``rate_limit_events`` counts the backoffs taken because GitHub reported a
    rate limit (a 403/429 with ``Retry-After`` or an exhausted budget), as
    distinct from the retries of a 5xx, and ``rate_limit_wait_seconds`` the
    seconds spent waiting in them (a backoff cut short by a cancellation
    counts the time it waited, not the time it was told). ``remaining`` is
    the lowest ``x-ratelimit-remaining`` seen per resource and ``limits`` the
    resource's ``x-ratelimit-limit``, so :meth:`low_budget` can name a
    resource the run came close to exhausting.

    ``points`` is the rate-limit consumption per GitHub resource (``core``,
    ``graphql``, ...), read from GitHub's own ``x-ratelimit-*`` headers rather
    than counted. GitHub meters one token across more than one bucket per
    resource -- identical requests seconds apart can report different
    ``x-ratelimit-reset`` values with independent ``x-ratelimit-used``
    counters -- so each bucket is tracked on its own and the figure is the sum,
    over a resource's buckets, of the spread between the lowest and highest
    reading seen. The lowest reading already includes that request's own cost,
    so the sum is short by the first request of each bucket: one point for a
    REST read, the query's cost for GraphQL. It is a measurement aid, not a
    bill. The external Scorecard API sends no such headers, so it shows up in
    the request and byte counts only.
    """

    requests: int = 0
    by_status: Mapping[int, int] = field(default_factory=lambda: MappingProxyType({}))
    transport_retries: int = 0
    degraded_retries: int = 0
    bytes_received: int = 0
    points: Mapping[str, int] = field(default_factory=lambda: MappingProxyType({}))
    elapsed: float = 0.0
    rest_requests: int = 0
    graphql_requests: int = 0
    external_requests: int = 0
    rate_limit_events: int = 0
    rate_limit_wait_seconds: float = 0.0
    remaining: Mapping[str, int] = field(default_factory=lambda: MappingProxyType({}))
    limits: Mapping[str, int] = field(default_factory=lambda: MappingProxyType({}))

    @property
    def responses(self) -> int:
        """Every response received, whatever its status."""
        return sum(self.by_status.values())

    @property
    def retries(self) -> int:
        """Every retry the backoff policy took, whatever triggered it."""
        return self.transport_retries + self.degraded_retries

    @property
    def not_modified(self) -> int:
        """Conditional reads GitHub answered ``304 Not Modified``."""
        return self.by_status.get(304, 0)

    def low_budget(self, fraction: float = 0.1) -> dict[str, int]:
        """Resources whose remaining budget fell under ``fraction`` of the limit.

        Maps each such resource to the lowest ``x-ratelimit-remaining`` seen.
        A resource whose limit was never reported cannot be judged, so it is
        left out.
        """
        return {
            resource: left
            for resource, left in self.remaining.items()
            if resource in self.limits and left < self.limits[resource] * fraction
        }

    def summary(self) -> str:
        """One line for the log: requests, retries, points, bytes, seconds."""
        split = f"REST {self.rest_requests}, GraphQL {self.graphql_requests}"
        if self.external_requests:
            split += f", external {self.external_requests}"
        parts = [
            f"{self.requests} requests ({split}; {self.retries} retries; "
            f"{self.not_modified} not modified)"
        ]
        for resource in sorted(self.points):
            parts.append(f"{self.points[resource]} {resource} points")
        parts.append(
            f"{self.rate_limit_events} rate-limit backoffs "
            f"({self.rate_limit_wait_seconds:.0f} s)"
        )
        parts.append(f"{self.bytes_received / (1024 * 1024):.1f} MiB received")
        parts.append(f"{self.elapsed:.1f} s")
        return ", ".join(parts)


class _RateBucket:
    """The ``x-ratelimit-used`` readings seen for one bucket of one resource.

    Concurrent requests can be answered out of order, so the readings are not
    assumed to arrive ascending: the spread is between the lowest and highest
    seen, not between the first and last.
    """

    def __init__(self, used: int) -> None:
        self.low = used
        self.high = used

    def observe(self, used: int) -> None:
        self.low = min(self.low, used)
        self.high = max(self.high, used)

    @property
    def spread(self) -> int:
        return self.high - self.low


class _RequestTally:
    """Running totals behind :class:`RequestStats`; mutated by ``_request``."""

    def __init__(self) -> None:
        self.started = time.monotonic()
        self.finished: float | None = None
        self.attempts = 0
        self.by_status: Counter[int] = Counter()
        self.transport_retries = 0
        self.degraded_retries = 0
        self.bytes_received = 0
        self.kinds: Counter[RequestKind] = Counter()
        self.rate_limit_events = 0
        self.rate_limit_wait_seconds = 0.0
        self.remaining: dict[str, int] = {}
        self.limits: dict[str, int] = {}
        # Keyed by resource *and* reset time: the reset time is what tells one
        # of a resource's buckets from another (see RequestStats.points).
        self.buckets: dict[tuple[str, str | None], _RateBucket] = {}

    def attempt(
        self, kind: RequestKind = "rest", *, retry_of: RetryKind | None = None
    ) -> None:
        """Count a request about to be issued, answered or not.

        ``retry_of`` names the failure this attempt retries, if any, and is
        what the retry counters count: a retry is a request that was issued
        again, so a backoff cancelled before its retry is not one.
        """
        self.attempts += 1
        self.kinds[kind] += 1
        if retry_of == "transport":
            self.transport_retries += 1
        elif retry_of == "degraded":
            self.degraded_retries += 1

    def rate_limited(self) -> None:
        """Count a backoff taken because GitHub reported a rate limit."""
        self.rate_limit_events += 1

    def rate_limit_waited(self, seconds: float) -> None:
        """Charge the seconds a rate-limit backoff spent waiting.

        Separate from :meth:`rate_limited` because the two are known at
        different times: the backoff when it starts, the wait once it is over,
        which for a cancelled one is sooner than it was told.
        """
        self.rate_limit_wait_seconds += max(0.0, seconds)

    def record(self, resp: httpx.Response) -> None:
        """Count a response received, and its rate-limit reading if it has one."""
        self.by_status[resp.status_code] += 1
        self.bytes_received += len(resp.content)
        resource = resp.headers.get("x-ratelimit-resource")
        if not resource:
            return
        used = _header_int(resp, "x-ratelimit-used")
        remaining = _header_int(resp, "x-ratelimit-remaining")
        limit = _header_int(resp, "x-ratelimit-limit")
        if remaining is not None:
            self.remaining[resource] = min(
                self.remaining.get(resource, remaining), remaining
            )
        if limit is not None:
            self.limits[resource] = limit
        if used is None:
            return
        key = (resource, resp.headers.get("x-ratelimit-reset"))
        bucket = self.buckets.get(key)
        if bucket is None:
            self.buckets[key] = _RateBucket(used)
        else:
            bucket.observe(used)

    def snapshot(self) -> RequestStats:
        end = self.finished if self.finished is not None else time.monotonic()
        points: dict[str, int] = {}
        for (resource, _reset), bucket in self.buckets.items():
            points[resource] = points.get(resource, 0) + bucket.spread
        return RequestStats(
            requests=self.attempts,
            by_status=MappingProxyType(dict(self.by_status)),
            transport_retries=self.transport_retries,
            degraded_retries=self.degraded_retries,
            bytes_received=self.bytes_received,
            points=MappingProxyType(points),
            elapsed=end - self.started,
            rest_requests=self.kinds["rest"],
            graphql_requests=self.kinds["graphql"],
            external_requests=self.kinds["external"],
            rate_limit_events=self.rate_limit_events,
            rate_limit_wait_seconds=self.rate_limit_wait_seconds,
            remaining=MappingProxyType(dict(self.remaining)),
            limits=MappingProxyType(dict(self.limits)),
        )


def _header_int(resp: httpx.Response, name: str) -> int | None:
    """An integer header, or ``None`` when absent or not a number."""
    value = resp.headers.get(name)
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None
