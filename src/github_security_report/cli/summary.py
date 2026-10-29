# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""The run summary printed before an organisation's report.

Three dim lines say what the collection cost and what the workflow-run store
holds, so an operator reading the report in a terminal sees at a glance
whether a slow run was slow because of a rate limit, a first-time build of
the store, or the organisation's size. The same figures reach the log at
INFO under ``--verbose``; nothing here reaches the rendered report.

The figures are captured as a :class:`RunSummary` while the organisation's
store is still open and printed later, immediately above that
organisation's report: with several organisations every collection finishes
before the first report renders, so a summary printed as each collection
ended would stand above the wrong report.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from rich.console import Console

from github_security_report.client.accounting import RequestStats
from github_security_report.collect.context import RunSyncSummary
from github_security_report.workflow_runs.store import RunStore


def _n(count: int) -> str:
    """A count with thin-space thousands separators: ``12 340``."""
    return f"{count:,}".replace(",", "\u2009")


def _plural(count: int, noun: str, plural: str | None = None) -> str:
    """``1 retry`` / ``2 retries``: the count with the noun that fits it."""
    if count == 1:
        return f"{_n(count)} {noun}"
    return f"{_n(count)} {plural or noun + 's'}"


def _mib(size: int) -> str:
    return f"{size / (1024 * 1024):.1f} MiB"


def _size(size: int) -> str:
    """A file size in KiB under a mebibyte, in MiB from there."""
    if size < 1024 * 1024:
        return f"{size // 1024} KiB"
    return _mib(size)


def requests_line(stats: RequestStats) -> str:
    """``1 234 requests (REST 1 100 · GraphQL 120 · 300 not modified) · ...``."""
    split = [f"REST {_n(stats.rest_requests)}", f"GraphQL {_n(stats.graphql_requests)}"]
    if stats.external_requests:
        split.append(f"external {_n(stats.external_requests)}")
    if stats.not_modified:
        split.append(f"{_n(stats.not_modified)} not modified")
    if stats.retries:
        split.append(_plural(stats.retries, "retry", "retries"))
    return (
        f"{_plural(stats.requests, 'request')} ({' · '.join(split)}) · "
        f"{_mib(stats.bytes_received)} · {stats.elapsed:.1f} s"
    )


def rate_limit_line(stats: RequestStats) -> tuple[str, bool]:
    """The rate-limit line and whether it deserves attention.

    Attention means a backoff happened or a resource's remaining budget fell
    under a tenth of its limit: either is what the operator must know before
    scheduling the run more often.
    """
    parts = [f"{_n(stats.points[r])} {r} points" for r in sorted(stats.points)]
    if not parts:
        parts.append("no rate-limit headers seen")
    wait = (
        f" ({stats.rate_limit_wait_seconds:.0f} s)" if stats.rate_limit_events else ""
    )
    parts.append(_plural(stats.rate_limit_events, "backoff") + wait)
    low = stats.low_budget()
    for resource in sorted(low):
        parts.append(f"{resource} budget low: {_n(low[resource])} remaining")
    return " · ".join(parts), bool(stats.rate_limit_events or low)


def store_line(
    store: RunStore | None, *, cached: bool, sync: RunSyncSummary | None
) -> str:
    """What the workflow-run store holds and what this run did to it."""
    if store is None:
        return "not collected"
    parts: list[str] = []
    if cached:
        try:
            parts.append(_size(os.stat(store.path).st_size))
        except OSError:
            parts.append("size unknown")
    else:
        parts.append("in memory (not cached)")
    parts.append(_plural(store.count(), "run"))
    parts.append(_plural(len(store.synced_repos()), "repository", "repositories"))
    if sync is None:
        return " · ".join(parts)
    if sync.cold:
        parts.append("built (first run)")
    did = [f"{_n(sync.repos)} synced"]
    if sync.unchanged:
        did.append(f"{_n(sync.unchanged)} unchanged")
    if sync.unreadable:
        did.append(f"{_n(sync.unreadable)} unreadable")
    did.append(f"{_n(sync.written)} written")
    if sync.pruned:
        did.append(f"{_n(sync.pruned)} pruned")
    parts.append("this run: " + ", ".join(did))
    return " · ".join(parts)


@dataclass(frozen=True)
class RunSummary:
    """One organisation's run summary, captured while its store was open.

    ``stats`` is the client's snapshot at the end of the collection and
    ``store`` the finished store line: the store's size, counts and synced
    repositories are read from the open store, which has closed by the time
    the summary prints.
    """

    org: str
    stats: RequestStats
    store: str

    @classmethod
    def capture(
        cls,
        *,
        org: str,
        stats: RequestStats,
        store: RunStore | None,
        cached: bool,
        sync: RunSyncSummary | None,
    ) -> RunSummary:
        """Read everything the summary needs while ``store`` is still open."""
        return cls(
            org=org, stats=stats, store=store_line(store, cached=cached, sync=sync)
        )


def print_run_summary(console: Console, summary: RunSummary) -> None:
    """Print the three-line run summary, then a blank line.

    Dim, so the report that follows stands out; the rate-limit line turns
    yellow when it has something to say.
    """
    rate, attention = rate_limit_line(summary.stats)
    lines = [
        (f"Run summary for {summary.org}", "dim"),
        (f"  requests: {requests_line(summary.stats)}", "dim"),
        (f"  rate limit: {rate}", "yellow" if attention else "dim"),
        (f"  workflow-run store: {summary.store}", "dim"),
    ]
    # Soft-wrapped: one line each however narrow the terminal, as the log
    # line they mirror would be, rather than a hard-wrapped dim paragraph.
    for text, style in lines:
        console.print(text, style=style, markup=False, highlight=False, soft_wrap=True)
    console.print()
