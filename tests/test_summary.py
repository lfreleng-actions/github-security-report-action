# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""The run summary's lines: what they say for each shape of run."""

from __future__ import annotations

import io
from pathlib import Path

from rich.console import Console

from github_security_report.cli.summary import (
    RunSummary,
    print_run_summary,
    rate_limit_line,
    requests_line,
    store_line,
)
from github_security_report.client.accounting import RequestStats
from github_security_report.collect.context import RunSyncSummary
from github_security_report.workflow_runs.store import RunStore


def test_requests_line_shows_only_the_parts_that_happened() -> None:
    quiet = RequestStats(requests=3, rest_requests=3, elapsed=1.25)
    assert requests_line(quiet) == "3 requests (REST 3 · GraphQL 0) · 0.0 MiB · 1.2 s"
    busy = RequestStats(
        requests=1234,
        by_status={200: 900, 304: 300},
        rest_requests=1100,
        graphql_requests=120,
        external_requests=14,
        transport_retries=1,
        degraded_retries=1,
        bytes_received=12 * 1024 * 1024,
        elapsed=95.2,
    )
    assert requests_line(busy) == (
        "1\u2009234 requests (REST 1\u2009100 · GraphQL 120 · external 14 · "
        "300 not modified · 2 retries) · 12.0 MiB · 95.2 s"
    )


def test_rate_limit_line_is_calm_until_github_pushes_back() -> None:
    calm = RequestStats(points={"core": 980, "graphql": 230})
    assert rate_limit_line(calm) == (
        "980 core points · 230 graphql points · 0 backoffs",
        False,
    )
    # One backoff with its wait, and a budget that nearly ran out.
    tight = RequestStats(
        points={"core": 4900},
        rate_limit_events=2,
        rate_limit_wait_seconds=61.4,
        remaining={"core": 120, "graphql": 4000},
        limits={"core": 5000, "graphql": 5000},
    )
    assert rate_limit_line(tight) == (
        "4\u2009900 core points · 2 backoffs (61 s) · core budget low: 120 remaining",
        True,
    )
    # No headers at all: say so rather than print nothing.
    assert rate_limit_line(RequestStats()) == (
        "no rate-limit headers seen · 0 backoffs",
        False,
    )


def test_store_line_for_each_kind_of_store(tmp_path: Path) -> None:
    assert store_line(None, cached=True, sync=None) == "not collected"
    with RunStore(tmp_path / "runs.sqlite") as store:
        assert store_line(store, cached=True, sync=None).endswith(
            " KiB · 0 runs · 0 repositories"
        )
        cold = RunSyncSummary(
            cold=True, repos=12, unchanged=0, unreadable=1, written=340, pruned=0
        )
        assert store_line(store, cached=True, sync=cold).endswith(
            "0 repositories · built (first run) · "
            "this run: 12 synced, 1 unreadable, 340 written"
        )
        warm = RunSyncSummary(
            cold=False, repos=12, unchanged=11, unreadable=0, written=3, pruned=50
        )
        assert store_line(store, cached=True, sync=warm).endswith(
            "0 repositories · this run: 12 synced, 11 unchanged, 3 written, 50 pruned"
        )
    with RunStore(Path(":memory:")) as memory:
        assert store_line(memory, cached=False, sync=None) == (
            "in memory (not cached) · 0 runs · 0 repositories"
        )


def test_capture_reads_the_store_while_it_is_open(tmp_path: Path) -> None:
    # The summary prints after the store has closed, so the store line is
    # fixed at capture time rather than read then.
    with RunStore(tmp_path / "runs.sqlite") as store:
        summary = RunSummary.capture(
            org="o", stats=RequestStats(), store=store, cached=True, sync=None
        )
    assert summary.org == "o"
    assert summary.store.endswith(" KiB · 0 runs · 0 repositories")


def test_print_run_summary_is_four_lines_then_a_blank() -> None:
    out = io.StringIO()
    console = Console(file=out, force_terminal=False, width=200)
    summary = RunSummary.capture(
        org="o",
        stats=RequestStats(requests=1, rest_requests=1, elapsed=0.5),
        store=None,
        cached=True,
        sync=None,
    )
    print_run_summary(console, summary)
    assert out.getvalue().splitlines() == [
        "Run summary for o",
        "  requests: 1 request (REST 1 · GraphQL 0) · 0.0 MiB · 0.5 s",
        "  rate limit: no rate-limit headers seen · 0 backoffs",
        "  workflow-run store: not collected",
        "",
    ]
