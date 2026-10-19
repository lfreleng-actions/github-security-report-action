# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Request accounting: what a client's run cost, for the operator's log.

:class:`~github_security_report.client.transport.Transport` feeds every
response it receives into a :class:`_RequestTally`; :class:`RequestStats` is
the frozen snapshot it exposes as ``stats``.
"""

from __future__ import annotations

import time
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

import httpx


@dataclass(frozen=True)
class RequestStats:
    """What a client's run has cost so far, for the operator's log.

    ``requests`` counts every HTTP response received, retried ones included,
    and ``by_status`` breaks them down by status code. A request that never
    produced a response (DNS, connection, TLS or read failure) appears only in
    ``transport_retries`` when it was retried. ``degraded_retries`` counts the
    5xx/403/429 responses retried under the shared backoff policy.

    ``points`` is the rate-limit consumption per GitHub resource (``core``,
    ``graphql``, ...), read from GitHub's own ``x-ratelimit-*`` headers rather
    than counted: the spread between the lowest and highest
    ``x-ratelimit-used`` seen for the resource. The first request's own cost is
    already inside the lowest reading, so this slightly undercounts; it is a
    measurement aid, not a bill. ``None`` means the resource's window reset
    during the run, which makes the spread meaningless. The external Scorecard
    API sends no such headers, so it shows up in the request and byte counts
    only.
    """

    requests: int = 0
    by_status: Mapping[int, int] = field(default_factory=lambda: MappingProxyType({}))
    transport_retries: int = 0
    degraded_retries: int = 0
    bytes_received: int = 0
    points: Mapping[str, int | None] = field(
        default_factory=lambda: MappingProxyType({})
    )
    elapsed: float = 0.0

    @property
    def retries(self) -> int:
        """Every retry the backoff policy took, whatever triggered it."""
        return self.transport_retries + self.degraded_retries

    def summary(self) -> str:
        """One line for the log: requests, retries, points, bytes, seconds."""
        parts = [f"{self.requests} requests ({self.retries} retries)"]
        for resource in sorted(self.points):
            used = self.points[resource]
            parts.append(f"{'unknown' if used is None else used} {resource} points")
        parts.append(f"{self.bytes_received / (1024 * 1024):.1f} MiB received")
        parts.append(f"{self.elapsed:.1f} s")
        return ", ".join(parts)


class _RateWindow:
    """The ``x-ratelimit-used`` readings seen for one resource's window."""

    def __init__(self, reset: str | None, used: int) -> None:
        self.reset = reset
        self.low = used
        self.high = used
        self.reset_seen = False

    def observe(self, reset: str | None, used: int) -> None:
        if reset != self.reset:
            self.reset_seen = True
            return
        self.low = min(self.low, used)
        self.high = max(self.high, used)

    def consumed(self) -> int | None:
        return None if self.reset_seen else self.high - self.low


class _RequestTally:
    """Running totals behind :class:`RequestStats`; mutated by ``_request``."""

    def __init__(self) -> None:
        self.started = time.monotonic()
        self.finished: float | None = None
        self.by_status: Counter[int] = Counter()
        self.transport_retries = 0
        self.degraded_retries = 0
        self.bytes_received = 0
        self.windows: dict[str, _RateWindow] = {}

    def record(self, resp: httpx.Response) -> None:
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
        reset = resp.headers.get("x-ratelimit-reset")
        window = self.windows.get(resource)
        if window is None:
            self.windows[resource] = _RateWindow(reset, used)
        else:
            window.observe(reset, used)

    def snapshot(self) -> RequestStats:
        end = self.finished if self.finished is not None else time.monotonic()
        return RequestStats(
            requests=sum(self.by_status.values()),
            by_status=MappingProxyType(dict(self.by_status)),
            transport_retries=self.transport_retries,
            degraded_retries=self.degraded_retries,
            bytes_received=self.bytes_received,
            points=MappingProxyType(
                {name: w.consumed() for name, w in self.windows.items()}
            ),
            elapsed=end - self.started,
        )
