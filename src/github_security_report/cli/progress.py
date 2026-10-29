# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Live progress in the terminal while an organisation is collected.

:class:`RunTracker` is both the
:class:`~github_security_report.client.events.ProgressSink` the transport
reports requests to and the
:class:`~github_security_report.collect.context.CollectProgress` the
collectors name their phases through, and renders what it hears as one Rich
``Live`` line per organisation: a spinner, the phase, the repository count
where the phase is per-repository, the REST and GraphQL request counts with
how many are in flight, and the clock. A second line appears only while
something exceptional lasts: a rate-limit backoff, or a first-time build of
the workflow-run store.

While the line is on screen, WARNINGs bound for the terminal are held and
replayed once it stops, so a transport warning cannot tear through it and the
operator still reads every one, in order, in a single block before the run
summary. Off (a :class:`NullTracker`) in CI, when stdout is not a terminal,
under ``--verbose`` (log lines and a live line fight for the same screen),
on ``--no-progress``, or when Rich cannot start the display.
"""

from __future__ import annotations

import logging
import os
import sys
import time
from collections.abc import Callable

from rich.console import Console, RenderableType
from rich.live import Live
from rich.spinner import Spinner
from rich.table import Table
from rich.text import Text

from github_security_report.client.events import RequestKind
from github_security_report.collect.context import RunSyncSummary

log = logging.getLogger(__name__)

_HELD = logging.CRITICAL + 1


def _in_ci() -> bool:
    return bool(os.environ.get("CI"))


def interactive() -> bool:
    """Whether the run is talking to a person at a terminal.

    The decision behind the console's colour: off under ``CI`` or when stdout
    is not a TTY. :func:`progress_wanted` asks the console it was given the
    same question, so the two agree on a real terminal.
    """
    return not _in_ci() and sys.stdout.isatty()


def progress_wanted(console: Console, *, no_progress: bool = False) -> bool:
    """Whether a live display belongs on ``console``.

    Off on request, in CI, when the console is not a terminal, and while
    INFO logging is on (``--verbose``): the collectors log at INFO as they
    go, and a stream of log lines through a live line leaves neither
    readable.
    """
    if no_progress or _in_ci() or not console.is_terminal:
        return False
    return not logging.getLogger().isEnabledFor(logging.INFO)


class NullTracker:
    """A tracker that shows nothing, with :class:`RunTracker`'s surface.

    It still keeps the sync summary, which the run summary prints whether or
    not a live line was shown.
    """

    def __init__(self) -> None:
        self.sync: RunSyncSummary | None = None

    def start(self, org: str) -> None:
        self.sync = None

    def stop(self) -> None:
        return None

    def phase(self, name: str, *, repos: int | None = None) -> None:
        return None

    def repo_done(self) -> None:
        return None

    def notice(self, text: str | None) -> None:
        return None

    def store_synced(self, summary: RunSyncSummary) -> None:
        self.sync = summary

    def on_request(self, kind: RequestKind, in_flight: int) -> None:
        return None

    def on_response(
        self, kind: RequestKind, status: int | None, in_flight: int
    ) -> None:
        return None

    def on_rate_limited(self, delay: float, resource: str | None) -> None:
        return None

    def on_rate_limit_cleared(self) -> None:
        return None


class _LogHold:
    """Hold terminal-bound WARNINGs while the live display is up.

    Every root handler writing to a terminal stream is raised above CRITICAL
    and a buffering handler takes its place; :meth:`release` restores the
    levels and replays what was held through the handlers that would have
    shown it, in the order it was logged.
    """

    def __init__(self) -> None:
        self._held: list[tuple[logging.Handler, int]] = []
        self._records: list[logging.LogRecord] = []
        self._buffer: logging.Handler | None = None

    @staticmethod
    def _terminal_bound(handler: logging.Handler) -> bool:
        if not isinstance(handler, logging.StreamHandler):
            return False
        stream = handler.stream
        return stream in (sys.stdout, sys.stderr, sys.__stdout__, sys.__stderr__)

    def hold(self) -> None:
        root = logging.getLogger()
        for handler in root.handlers:
            if self._terminal_bound(handler):
                self._held.append((handler, handler.level))
                handler.setLevel(_HELD)
        if not self._held:
            return
        records = self._records

        class _Buffer(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                records.append(record)

        self._buffer = _Buffer(level=logging.WARNING)
        root.addHandler(self._buffer)

    def release(self) -> None:
        root = logging.getLogger()
        if self._buffer is not None:
            root.removeHandler(self._buffer)
            self._buffer = None
        for handler, level in self._held:
            handler.setLevel(level)
        for record in self._records:
            for handler, level in self._held:
                if record.levelno >= level:
                    handler.handle(record)
        self._held.clear()
        self._records.clear()


class RunTracker:
    """One organisation's live progress line (see the module docstring)."""

    def __init__(
        self, console: Console, *, clock: Callable[[], float] = time.monotonic
    ) -> None:
        self._console = console
        self._clock = clock
        self._live: Live | None = None
        self._hold = _LogHold()
        self._spinner = Spinner("dots")
        self._org = ""
        self._started = clock()
        self._stopped: float | None = None
        self._phase = "starting"
        self._repos_total: int | None = None
        self._repos_done = 0
        self._requests: dict[RequestKind, int] = {}
        self._in_flight: dict[RequestKind, int] = {}
        self._notice: str | None = None
        self._backoffs = 0
        self._resume_at = 0.0
        self._limited_resource: str | None = None
        self.sync: RunSyncSummary | None = None

    # -- lifecycle ----------------------------------------------------------
    def start(self, org: str) -> None:
        """Reset the counters for ``org`` and put the line on screen."""
        self._org = org
        self._started = self._clock()
        self._stopped = None
        self._phase = "starting"
        self._repos_total = None
        self._repos_done = 0
        self._requests = {}
        self._in_flight = {}
        self._notice = None
        self._backoffs = 0
        self.sync = None
        self._hold.hold()
        try:
            live = Live(
                get_renderable=self.render,
                console=self._console,
                refresh_per_second=2,
                transient=False,
            )
            live.start()
        except Exception:  # noqa: BLE001 - a display failure must not end the run
            log.debug("live progress unavailable", exc_info=True)
            self._hold.release()
            return
        self._live = live

    def stop(self) -> None:
        """Freeze the line, take the display down and replay held warnings.

        Best effort: callers run this from ``finally``, so a display that
        fails to draw its last frame must neither replace the error the run
        is already raising nor fail a run that succeeded. Whatever happens to
        the display, the log handlers are restored and the held warnings
        replayed; without that a failed teardown would leave the terminal
        silent for the rest of the process.
        """
        self._stopped = self._clock()
        self._notice = None
        self._backoffs = 0
        live, self._live = self._live, None
        try:
            if live is not None:
                live.stop()
        except Exception:  # noqa: BLE001 - see the docstring
            log.debug("live progress failed to stop", exc_info=True)
        finally:
            self._hold.release()

    # -- CollectProgress ------------------------------------------------------
    def phase(self, name: str, *, repos: int | None = None) -> None:
        self._phase = name
        self._repos_total = repos
        self._repos_done = 0

    def repo_done(self) -> None:
        self._repos_done += 1

    def notice(self, text: str | None) -> None:
        self._notice = text

    def store_synced(self, summary: RunSyncSummary) -> None:
        self.sync = summary

    # -- ProgressSink ---------------------------------------------------------
    def on_request(self, kind: RequestKind, in_flight: int) -> None:
        self._requests[kind] = self._requests.get(kind, 0) + 1
        self._in_flight[kind] = self._in_flight.get(kind, 0) + 1

    def on_response(
        self, kind: RequestKind, status: int | None, in_flight: int
    ) -> None:
        self._in_flight[kind] = max(0, self._in_flight.get(kind, 0) - 1)

    def on_rate_limited(self, delay: float, resource: str | None) -> None:
        # The line shows one countdown: the latest deadline among the backoffs
        # in progress. The resource is set with the deadline it belongs to, so
        # a short graphql wait inside a long core one does not relabel the
        # core countdown.
        resume_at = self._clock() + delay
        if self._backoffs == 0 or resume_at >= self._resume_at:
            self._resume_at = resume_at
            self._limited_resource = resource
        self._backoffs += 1

    def on_rate_limit_cleared(self) -> None:
        self._backoffs = max(0, self._backoffs - 1)

    # -- rendering ------------------------------------------------------------
    def _elapsed(self) -> float:
        end = self._stopped if self._stopped is not None else self._clock()
        return end - self._started

    def _count(self, label: str, kind: RequestKind) -> str:
        part = f"{label} {self._requests.get(kind, 0)}"
        busy = self._in_flight.get(kind, 0)
        return f"{part} ({busy} in flight)" if busy else part

    def _clock_text(self) -> str:
        return f"{self._elapsed():.1f} s"

    def _body(self) -> str:
        """The line without its clock: what the renderer may truncate."""
        parts = [self._org, self._phase if self._stopped is None else "done"]
        if self._repos_total is not None:
            parts.append(f"{self._repos_done}/{self._repos_total} repos")
        parts.append(self._count("REST", "rest"))
        parts.append(self._count("GraphQL", "graphql"))
        if self._requests.get("external"):
            parts.append(self._count("external", "external"))
        return " · ".join(parts)

    def line(self) -> str:
        """The progress line as plain text: what the spinner follows."""
        return f"{self._body()} · {self._clock_text()}"

    def exceptional(self) -> tuple[str, str] | None:
        """The second line, as ``(marker, text)``, while something warrants it."""
        if self._backoffs:
            wait = max(0.0, self._resume_at - self._clock())
            where = f" ({self._limited_resource})" if self._limited_resource else ""
            return "⏳", f"rate limited by GitHub{where}; resuming in {wait:.0f} s"
        if self._notice:
            return "📦", self._notice
        return None

    @staticmethod
    def _cell(text: str, style: str = "") -> Text:
        return Text(text, style=style, no_wrap=True, overflow="ellipsis")

    def render(self) -> RenderableType:
        """The one or two physical lines, however narrow the terminal.

        Each row is one line: the text in the middle column truncates with an
        ellipsis rather than wrapping, since a wrapped line is as unreadable
        as a torn one. The clock has a column of its own so it is the last
        thing to go, not the first: it is what tells a stalled run from a
        slow one once the counts are cut off.
        """
        grid = Table.grid(padding=(0, 1))
        grid.add_column(no_wrap=True)
        grid.add_column()
        grid.add_column(no_wrap=True)
        marker: RenderableType = (
            self._spinner if self._stopped is None else Text("✓", style="green")
        )
        grid.add_row(marker, self._cell(self._body()), f"· {self._clock_text()}")
        second = self.exceptional()
        if second is not None:
            second_marker, text = second
            grid.add_row(Text(second_marker), self._cell(text, "yellow"), "")
        return grid


def make_tracker(
    console: Console, *, no_progress: bool = False
) -> RunTracker | NullTracker:
    """The tracker for this run: live when a terminal wants it, else silent."""
    if progress_wanted(console, no_progress=no_progress):
        return RunTracker(console)
    return NullTracker()
