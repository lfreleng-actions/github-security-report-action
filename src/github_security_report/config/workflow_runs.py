# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Configuration for the Workflow Failures tables.

How the run history is collected, cached and judged, and which time windows
each surface shows.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

# Default time windows, in days, for the Workflow Failures tables per surface.
# The terminal and Slack get the week; the published report adds the month
# and the quarter, where a reader has room to compare them.
DEFAULT_RUN_WINDOWS: Mapping[str, tuple[int, ...]] = MappingProxyType(
    {"cli": (7,), "report": (7, 30, 90), "slack": (7,)}
)


@dataclass(frozen=True)
class WorkflowRunsConfig:
    """How the Workflow Failures tables are collected and judged.

    ``windows`` maps each surface (``cli``, ``report``, ``slack``) to the
    windows it shows, in days. ``retention_days`` is how long the run store
    keeps records and ``backfill_days`` how deep a never-seen repository is
    read; both default to the longest configured window, which is the most
    any table can use. ``cache`` off keeps the store in memory for the run,
    so every report re-reads the windows from GitHub; ``cache_dir`` overrides
    the XDG cache location.
    """

    windows: Mapping[str, tuple[int, ...]] = field(
        default_factory=lambda: DEFAULT_RUN_WINDOWS
    )
    retention_days: int | None = None
    backfill_days: int | None = None
    # GitHub-managed workflows (Dependabot updates, default-setup CodeQL,
    # Copilot review) have no file in the repository to fix, so they are
    # left out of the tables unless asked for.
    include_dynamic: bool = False
    # Globs matched against the workflow path, for workflows whose failures
    # are expected (an experiment, a deliberately failing canary).
    exclude_workflows: tuple[str, ...] = ()
    # Fold "Build (ubuntu-22.04)" and "Build (ubuntu-24.04)" into one job.
    collapse_matrix: bool = True
    # A workflow failing at or above this rate is persistent; below it,
    # intermittent. Fewer than ``min_runs`` concluded runs is too few to say.
    persistent_threshold: float = 0.9
    min_runs: int = 3
    # A repository failing more than this share of its runs has its Fail %
    # shown as an error; any lower non-zero rate is a warning.
    fail_rate_error_threshold: float = 0.05
    cache: bool = True
    cache_dir: str | None = None

    def windows_for(self, output: str) -> tuple[int, ...]:
        """The windows ``output`` (``cli``/``report``/``slack``) shows."""
        return self.windows.get(output, ())

    @property
    def all_windows(self) -> tuple[int, ...]:
        """Every configured window once, longest first."""
        return tuple(
            sorted({d for days in self.windows.values() for d in days}, reverse=True)
        )

    @property
    def longest_window(self) -> int:
        """The longest window any surface shows; what the store must hold."""
        return max(self.all_windows, default=7)

    @property
    def retention(self) -> int:
        """Days the store keeps, never shorter than the longest window."""
        return max(self.retention_days or 0, self.longest_window)

    @property
    def backfill(self) -> int:
        """Days a never-seen repository is read back, bounded by retention."""
        return min(self.backfill_days or self.retention, self.retention)
