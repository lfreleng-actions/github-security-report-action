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
# The line
# --------------------------------------------------------------------------- #
def test_line_names_the_org_phase_counts_and_clock() -> None:
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
    assert tracker.line() == (
        "lfreleng-actions · probing repositories · 12/142 repos · "
        "REST 3 (2 in flight) · GraphQL 1 (1 in flight) · 12.4 s"
    )


def test_line_omits_the_counter_and_in_flight_when_there_is_nothing() -> None:
    tracker, _clock = _tracker()
    tracker._org = "o"
    tracker.phase("listing repositories")
    assert tracker.line() == "o · listing repositories · REST 0 · GraphQL 0 · 0.0 s"


def test_external_requests_show_only_once_made() -> None:
    tracker, _clock = _tracker()
    tracker._org = "o"
    assert "external" not in tracker.line()
    tracker.on_request("external", 1)
    tracker.on_response("external", None, 0)
    assert "external 1" in tracker.line()


def test_a_new_phase_resets_the_counter() -> None:
    tracker, _clock = _tracker()
    tracker.phase("probing repositories", repos=3)
    tracker.repo_done()
    tracker.phase("posture, scan health, authors and workflow runs", repos=3)
    assert "0/3 repos" in tracker.line()
    tracker.phase("building tables")
    assert "repos" not in tracker.line()


# --------------------------------------------------------------------------- #
# The exceptional second line
# --------------------------------------------------------------------------- #
def test_rate_limit_line_counts_down_and_clears() -> None:
    tracker, clock = _tracker()
    assert tracker.exceptional() is None
    tracker.on_rate_limited(41.0, "core")
    marker, text = tracker.exceptional() or ("", "")
    assert marker == "⏳"
    assert text == "rate limited by GitHub (core); resuming in 41 s"
    clock.now += 30
    assert "resuming in 11 s" in (tracker.exceptional() or ("", ""))[1]
    tracker.on_rate_limit_cleared()
    assert tracker.exceptional() is None


def test_overlapping_backoffs_clear_when_the_last_one_ends() -> None:
    tracker, _clock = _tracker()
    tracker.on_rate_limited(10.0, "core")
    tracker.on_rate_limited(40.0, None)
    tracker.on_rate_limit_cleared()
    assert tracker.exceptional() is not None
    tracker.on_rate_limit_cleared()
    assert tracker.exceptional() is None


def test_the_resource_named_is_the_one_whose_countdown_shows() -> None:
    # A short graphql wait inside a long core one must not relabel the core
    # countdown, before or after the graphql wait ends.
    tracker, clock = _tracker()
    tracker.on_rate_limited(60.0, "core")
    clock.now += 5
    tracker.on_rate_limited(5.0, "graphql")
    assert (tracker.exceptional() or ("", ""))[1] == (
        "rate limited by GitHub (core); resuming in 55 s"
    )
    clock.now += 5
    tracker.on_rate_limit_cleared()
    assert (tracker.exceptional() or ("", ""))[1] == (
        "rate limited by GitHub (core); resuming in 50 s"
    )
    # A later deadline takes the line over, resource and all.
    tracker.on_rate_limited(90.0, "graphql")
    assert (tracker.exceptional() or ("", ""))[1] == (
        "rate limited by GitHub (graphql); resuming in 90 s"
    )
    tracker.on_rate_limit_cleared()
    tracker.on_rate_limit_cleared()
    # A fresh backoff after a quiet spell starts its own countdown.
    clock.now += 1000
    tracker.on_rate_limited(3.0, "search")
    assert (tracker.exceptional() or ("", ""))[1] == (
        "rate limited by GitHub (search); resuming in 3 s"
    )


def test_notice_shows_until_cleared_and_yields_to_a_rate_limit() -> None:
    tracker, _clock = _tracker()
    tracker.notice("building the workflow-run store for the first time")
    assert tracker.exceptional() == (
        "📦",
        "building the workflow-run store for the first time",
    )
    tracker.on_rate_limited(5.0, "core")
    assert (tracker.exceptional() or ("", ""))[0] == "⏳"
    tracker.on_rate_limit_cleared()
    tracker.notice(None)
    assert tracker.exceptional() is None


def test_render_carries_both_lines() -> None:
    tracker, _clock = _tracker()
    tracker._org = "o"
    tracker.notice("one-off")
    text = _plain(tracker)
    assert "o · starting" in text
    assert "📦 one-off" in text


def _busy_tracker() -> RunTracker:
    tracker, _clock = _tracker()
    tracker._org = "lfreleng-actions"
    tracker.phase("posture, scan health, authors and workflow runs", repos=142)
    kinds: list[tuple[RequestKind, int]] = [("rest", 311), ("graphql", 18)]
    for kind, count in kinds:
        for _ in range(count):
            tracker.on_request(kind, 1)
    tracker.notice(
        "building the workflow-run store for the first time "
        "(90 days, 142 repositories); this one-off takes several minutes"
    )
    return tracker


@pytest.mark.parametrize("width", [80, 40, 200])
def test_each_row_is_one_physical_line_at_any_width(width: int) -> None:
    # Two lines at most: a row that does not fit is cut with an ellipsis, and
    # the clock is kept at the end of the first.
    tracker = _busy_tracker()
    console = Console(file=io.StringIO(), width=width, no_color=True)
    with console.capture() as captured:
        console.print(tracker.render())
    rows = captured.get().splitlines()
    assert len(rows) == 2, rows
    assert all(len(row) <= width for row in rows), rows
    assert rows[0][3:].startswith("lfreleng-actions · posture")
    assert rows[0].rstrip().endswith("· 0.0 s")
    assert rows[1].startswith("📦 building the workflow-run st")
    if width < 150:
        assert "…" in rows[0] and "…" in rows[1]
    else:
        assert "GraphQL 18 (18 in flight)" in rows[0]
        assert rows[1].rstrip().endswith("takes several minutes")


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
    assert tracker.line() == "o · done · 0/2 repos · REST 0 · GraphQL 0 · 3.0 s"
    assert tracker.exceptional() is None
    clock.now += 50
    assert tracker.line().endswith("3.0 s")
    assert "✓" in _plain(tracker)


def test_start_resets_the_counters_for_the_next_org() -> None:
    tracker, _clock = _tracker()
    tracker.start("o")
    tracker.on_request("rest", 1)
    tracker.stop()
    tracker.start("p")
    try:
        assert tracker.line().startswith("p · starting · REST 0")
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
