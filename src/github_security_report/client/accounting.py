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

    @property
    def responses(self) -> int:
        """Every response received, whatever its status."""
        return sum(self.by_status.values())

    @property
    def retries(self) -> int:
        """Every retry the backoff policy took, whatever triggered it."""
        return self.transport_retries + self.degraded_retries

    def summary(self) -> str:
        """One line for the log: requests, retries, points, bytes, seconds."""
        parts = [f"{self.requests} requests ({self.retries} retries)"]
        for resource in sorted(self.points):
            parts.append(f"{self.points[resource]} {resource} points")
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
        # Keyed by resource *and* reset time: the reset time is what tells one
        # of a resource's buckets from another (see RequestStats.points).
        self.buckets: dict[tuple[str, str | None], _RateBucket] = {}

    def attempt(self, *, retry_of: RetryKind | None = None) -> None:
        """Count a request about to be issued, answered or not.

        ``retry_of`` names the failure this attempt retries, if any, and is
        what the retry counters count: a retry is a request that was issued
        again, so a backoff cancelled before its retry is not one.
        """
        self.attempts += 1
        if retry_of == "transport":
            self.transport_retries += 1
        elif retry_of == "degraded":
            self.degraded_retries += 1

    def record(self, resp: httpx.Response) -> None:
        """Count a response received, and its rate-limit reading if it has one."""
        self.by_status[resp.status_code] += 1
        self.bytes_received += len(resp.content)
        resource = resp.headers.get("x-ratelimit-resource")
        used_header = resp.headers.get("x-ratelimit-used")
        if not resource or used_header is None:
            return
        try:
            used = int(used_header)
        except ValueError:
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
        )
