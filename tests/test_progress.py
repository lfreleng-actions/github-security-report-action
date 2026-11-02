# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""The live progress tracker: what it shows, and when it stays silent."""

from __future__ import annotations

import io
import logging
import sys
from collections.abc import Iterator
from typing import Any

import pytest
from rich.console import Console

from github_security_report.cli import progress
from github_security_report.cli.progress import (
    NullTracker,
    RunTracker,
    make_tracker,
    progress_wanted,
)
from github_security_report.client.events import RequestKind


class _Clock:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        return self.now


def _console() -> Console:
    return Console(file=io.StringIO(), force_terminal=True, width=200)


def _tracker() -> tuple[RunTracker, _Clock]:
    clock = _Clock()
    return RunTracker(_console(), clock=clock), clock


def _plain(tracker: RunTracker) -> str:
    console = Console(file=io.StringIO(), width=200, no_color=True)
    with console.capture() as captured:
        console.print(tracker.render())
    return captured.get()


# --------------------------------------------------------------------------- #
# The three lines
# --------------------------------------------------------------------------- #
def test_lines_split_where_traffic_and_progress() -> None:
    tracker, clock = _tracker()
    tracker._started = clock.now  # no Live: start() is exercised below
    tracker.phase("probing repositories", repos=142)
    for _ in range(12):
        tracker.repo_done()
    for _ in range(3):
        tracker.on_request("rest", 1)
    tracker.on_request("graphql", 1)
    tracker.on_response("rest", 200, 0)
    tracker._org = "lfreleng-actions"
    clock.now += 12.4
    assert tracker.lines() == [
        "lfreleng-actions · probing repositories",
        "REST 3 (2 in flight) · GraphQL 1 (1 in flight)",
        "12.4 s · 12/142 repos",
    ]


def test_lines_omit_the_counter_and_in_flight_when_there_is_nothing() -> None:
    tracker, _clock = _tracker()
    tracker._org = "o"
    tracker.phase("listing repositories")
    assert tracker.lines() == [
        "o · listing repositories",
        "REST 0 · GraphQL 0",
        "0.0 s",
    ]


def test_external_requests_show_only_once_made() -> None:
    tracker, _clock = _tracker()
    tracker._org = "o"
    assert "external" not in tracker.lines()[1]
    tracker.on_request("external", 1)
    tracker.on_response("external", None, 0)
    assert tracker.lines()[1] == "REST 0 · GraphQL 0 · external 1"


def test_a_new_phase_resets_the_counter() -> None:
    tracker, _clock = _tracker()
    tracker.phase("probing repositories", repos=3)
    tracker.repo_done()
    tracker.phase("posture, scan health, authors and workflow runs", repos=3)
    assert tracker.lines()[2] == "0.0 s · 0/3 repos"
    tracker.phase("building tables")
    assert "repos" not in " ".join(tracker.lines())


# --------------------------------------------------------------------------- #
# Exceptional states
# --------------------------------------------------------------------------- #
def _backoff(tracker: RunTracker) -> str:
    return tracker.lines()[2].partition("⏳ ")[2]


def test_rate_limit_counts_down_after_the_clock_and_clears() -> None:
    tracker, clock = _tracker()
    assert "⏳" not in tracker.lines()[2]
    tracker.on_rate_limited(41.0, "core")
    assert tracker.lines()[2] == (
        "0.0 s · ⏳ rate limited by GitHub (core); resuming in 41 s"
    )
    clock.now += 30
    assert _backoff(tracker) == "rate limited by GitHub (core); resuming in 11 s"
    tracker.on_rate_limit_cleared()
    assert tracker.lines()[2] == "30.0 s"


def test_overlapping_backoffs_clear_when_the_last_one_ends() -> None:
    tracker, _clock = _tracker()
    tracker.on_rate_limited(10.0, "core")
    tracker.on_rate_limited(40.0, None)
    tracker.on_rate_limit_cleared()
    assert _backoff(tracker)
    tracker.on_rate_limit_cleared()
    assert not _backoff(tracker)


def test_the_resource_named_is_the_one_whose_countdown_shows() -> None:
    # A short graphql wait inside a long core one must not relabel the core
    # countdown, before or after the graphql wait ends.
    tracker, clock = _tracker()
    tracker.on_rate_limited(60.0, "core")
    clock.now += 5
    tracker.on_rate_limited(5.0, "graphql")
    assert _backoff(tracker) == "rate limited by GitHub (core); resuming in 55 s"
    clock.now += 5
    tracker.on_rate_limit_cleared()
    assert _backoff(tracker) == "rate limited by GitHub (core); resuming in 50 s"
    # A later deadline takes the line over, resource and all.
    tracker.on_rate_limited(90.0, "graphql")
    assert _backoff(tracker) == "rate limited by GitHub (graphql); resuming in 90 s"
    tracker.on_rate_limit_cleared()
    tracker.on_rate_limit_cleared()
    # A fresh backoff after a quiet spell starts its own countdown.
    clock.now += 1000
    tracker.on_rate_limited(3.0, "search")
    assert _backoff(tracker) == "rate limited by GitHub (search); resuming in 3 s"


def test_notice_takes_a_fourth_line_until_cleared() -> None:
    tracker, _clock = _tracker()
    tracker.notice("building the workflow-run store for the first time")
    assert tracker.lines()[3:] == [
        "📦 building the workflow-run store for the first time"
    ]
    tracker.on_rate_limited(5.0, "core")
    assert len(tracker.lines()) == 4
    assert _backoff(tracker)
    tracker.on_rate_limit_cleared()
    tracker.notice(None)
    assert len(tracker.lines()) == 3


def test_render_aligns_the_lines_under_the_first() -> None:
    tracker, _clock = _tracker()
    tracker._org = "o"
    tracker.notice("one-off")
    rows = _plain(tracker).splitlines()
    assert len(rows) == 4, rows
    assert rows[0][2:].rstrip() == "o · starting"
    assert rows[1].rstrip() == "  REST 0 · GraphQL 0"
    assert rows[2].rstrip() == "  0.0 s"
    assert rows[3].rstrip() == "  📦 one-off"


def _busy_tracker() -> RunTracker:
    tracker, _clock = _tracker()
    tracker._org = "lfreleng-actions"
    tracker.phase("posture, scan health, authors and workflow runs", repos=142)
    kinds: list[tuple[RequestKind, int]] = [("rest", 311), ("graphql", 18)]
    for kind, count in kinds:
        for _ in range(count):
            tracker.on_request(kind, 1)
    tracker.on_rate_limited(42.0, "core")
    tracker.notice(
        "building the workflow-run store for the first time "
        "(90 days, 142 repositories); this one-off takes several minutes"
    )
    return tracker


def _rendered(tracker: RunTracker, width: int) -> list[str]:
    console = Console(file=io.StringIO(), width=width, no_color=True)
    with console.capture() as captured:
        console.print(tracker.render())
    return captured.get().splitlines()


@pytest.mark.parametrize("width", [80, 40, 24, 200])
def test_each_row_is_one_physical_line_at_any_width(width: int) -> None:
    # Four rows at most: a row that does not fit is cut with an ellipsis, and
    # the clock leads the third so it survives the cut.
    rows = _rendered(_busy_tracker(), width)
    assert len(rows) == 4, rows
    assert all(len(row) <= width for row in rows), rows
    assert rows[0][2:].startswith("lfreleng-")
    assert rows[1].startswith("  REST ")
    assert rows[2].startswith("  0.0 s ·")
    assert rows[3].startswith("  📦 ")
    if width >= 150:
        assert not any("…" in row for row in rows), rows
        assert rows[3].rstrip().endswith("takes several minutes")
    else:
        assert "…" in rows[3]


_PHASES = [
    "listing repositories",
    "sweeping alerts, gating signals and prefetching (GraphQL)",
    "probing repositories",
    "posture, scan health, authors and workflow runs",
    "building tables",
    "syncing workflow runs",
    "probing repository",
    "applying remediation",
    "previewing remediation",
]


@pytest.mark.parametrize("phase", _PHASES)
def test_no_phase_is_truncated_at_80_columns(phase: str) -> None:
    tracker, clock = _tracker()
    tracker._org = "lfreleng-actions"
    tracker.phase(phase, repos=142)
    for _ in range(141):
        tracker.repo_done()
    kinds: list[tuple[RequestKind, int, int]] = [
        ("rest", 1234, 16),
        ("graphql", 120, 4),
        ("external", 14, 0),
    ]
    for kind, count, busy in kinds:
        for _ in range(count):
            tracker.on_request(kind, 1)
        for _ in range(count - busy):
            tracker.on_response(kind, 200, 0)
    clock.now += 95.2
    tracker.on_rate_limited(42.0, "graphql")
    rows = _rendered(tracker, 80)
    assert len(rows) == 3, rows
    assert not any("…" in row for row in rows), rows
    assert rows[0].rstrip().endswith(phase)
    assert rows[1].rstrip().endswith("· external 14")
    assert rows[2].rstrip().endswith("resuming in 42 s")


# --------------------------------------------------------------------------- #
# Lifecycle
# --------------------------------------------------------------------------- #
def test_start_and_stop_leave_a_final_frame_that_says_done() -> None:
    tracker, clock = _tracker()
    tracker.start("o")
    try:
        tracker.phase("probing repositories", repos=2)
        tracker.notice("one-off")
        clock.now += 3
    finally:
        tracker.stop()
    # Stopped: the clock froze, the phase reads done and no notice lingers.
    assert tracker.lines() == ["o · done", "REST 0 · GraphQL 0", "3.0 s · 0/2 repos"]
    clock.now += 50
    assert tracker.lines()[2].startswith("3.0 s")
    assert _plain(tracker).startswith("✓ o · done")


def test_start_resets_the_counters_for_the_next_org() -> None:
    tracker, _clock = _tracker()
    tracker.start("o")
    tracker.on_request("rest", 1)
    tracker.stop()
    tracker.start("p")
    try:
        assert tracker.lines()[:2] == ["p · starting", "REST 0 · GraphQL 0"]
    finally:
        tracker.stop()


def test_a_display_that_cannot_start_leaves_the_run_alone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Broken:
        def __init__(self, *args: object, **kwargs: object) -> None:
            pass

        def start(self) -> None:
            raise RuntimeError("no display")

    monkeypatch.setattr(progress, "Live", Broken)
    tracker, _clock = _tracker()
    tracker.start("o")
    tracker.phase("probing repositories")
    tracker.stop()
    assert tracker._live is None


# --------------------------------------------------------------------------- #
# Held warnings
# --------------------------------------------------------------------------- #
@pytest.fixture
def terminal_handler() -> Iterator[logging.StreamHandler[Any]]:
    """A root handler on stderr, so the hold acts on it; the test then points
    it at a private stream to read what reached it and when."""
    handler: logging.StreamHandler[Any] = logging.StreamHandler(io.StringIO())
    handler.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
    handler.stream = sys.stderr
    root = logging.getLogger()
    root.addHandler(handler)
    try:
        yield handler
    finally:
        root.removeHandler(handler)


def test_warnings_during_the_live_display_are_replayed_after_it(
    terminal_handler: logging.StreamHandler[Any],
) -> None:
    stream = io.StringIO()
    tracker, _clock = _tracker()
    tracker.start("o")
    try:
        terminal_handler.stream = stream
        logging.getLogger("t").warning("first")
        logging.getLogger("t").warning("second")
        logging.getLogger("t").info("quiet")
        seen_during = stream.getvalue()
    finally:
        tracker.stop()
    assert seen_during == ""
    assert stream.getvalue() == "WARNING first\nWARNING second\n"
    assert terminal_handler.level == logging.NOTSET
    # Released: a later warning reaches the terminal at once.
    logging.getLogger("t").warning("third")
    assert stream.getvalue().endswith("WARNING third\n")


def test_a_display_that_cannot_stop_still_restores_logging(
    monkeypatch: pytest.MonkeyPatch, terminal_handler: logging.StreamHandler[Any]
) -> None:
    # stop() runs from a finally: a failing last frame must neither replace
    # the run's own error nor leave handlers muted and warnings unreplayed.
    class Stuck:
        def __init__(self, *args: object, **kwargs: object) -> None:
            pass

        def start(self) -> None:
            return None

        def stop(self) -> None:
            raise RuntimeError("no final frame")

    monkeypatch.setattr(progress, "Live", Stuck)
    stream = io.StringIO()
    tracker, _clock = _tracker()
    tracker.start("o")
    terminal_handler.stream = stream
    logging.getLogger("t").warning("held")
    assert stream.getvalue() == ""
    tracker.stop()
    assert tracker._live is None
    assert terminal_handler.level == logging.NOTSET
    assert stream.getvalue() == "WARNING held\n"


def test_handlers_not_bound_to_the_terminal_are_left_alone() -> None:
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    root = logging.getLogger()
    root.addHandler(handler)
    try:
        tracker, _clock = _tracker()
        tracker.start("o")
        try:
            logging.getLogger("t").warning("now")
            assert "now" in stream.getvalue()
        finally:
            tracker.stop()
    finally:
        root.removeHandler(handler)


# --------------------------------------------------------------------------- #
# Choosing a tracker
# --------------------------------------------------------------------------- #
@pytest.fixture
def _terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CI", raising=False)
    logging.getLogger().setLevel(logging.WARNING)


@pytest.mark.usefixtures("_terminal")
def test_an_interactive_quiet_terminal_gets_the_live_tracker() -> None:
    assert progress_wanted(_console()) is True
    assert isinstance(make_tracker(_console()), RunTracker)


@pytest.mark.usefixtures("_terminal")
def test_no_progress_chooses_the_null_tracker() -> None:
    assert isinstance(make_tracker(_console(), no_progress=True), NullTracker)


@pytest.mark.usefixtures("_terminal")
def test_ci_chooses_the_null_tracker(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CI", "1")
    assert isinstance(make_tracker(_console()), NullTracker)


@pytest.mark.usefixtures("_terminal")
def test_a_pipe_chooses_the_null_tracker() -> None:
    piped = Console(file=io.StringIO(), width=200)
    assert piped.is_terminal is False
    assert isinstance(make_tracker(piped), NullTracker)


@pytest.mark.usefixtures("_terminal")
def test_verbose_logging_chooses_the_null_tracker() -> None:
    logging.getLogger().setLevel(logging.INFO)
    try:
        assert isinstance(make_tracker(_console()), NullTracker)
    finally:
        logging.getLogger().setLevel(logging.WARNING)


def test_the_null_tracker_accepts_every_call() -> None:
    tracker = NullTracker()
    tracker.start("o")
    tracker.phase("x", repos=1)
    tracker.repo_done()
    tracker.notice("n")
    tracker.on_request("rest", 1)
    tracker.on_response("rest", 200, 0)
    tracker.on_rate_limited(1.0, "core")
    tracker.on_rate_limit_cleared()
    tracker.stop()
