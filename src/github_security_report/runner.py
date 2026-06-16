# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""CLI support: mode resolution, fail-threshold, and GitHub Actions I/O.

Pure helpers kept out of the Typer command so they can be unit-tested. See
``docs/BRIEF.md`` sections 9-12.
"""

from __future__ import annotations

import logging
import os
from enum import Enum

from github_security_report.models import RepoSignal
from github_security_report.severity import Severity

log = logging.getLogger(__name__)


class Mode(str, Enum):
    ORG = "org"
    REPO = "repo"


class ModeError(RuntimeError):
    """Raised when an operating mode cannot be resolved."""


def resolve_mode(
    requested: str,
    *,
    has_org_config: bool,
    detected_repo: tuple[str, str] | None,
) -> Mode:
    """Resolve the operating mode, logging the outcome loudly.

    Precedence: an explicit ``org``/``repo`` request wins; ``auto`` resolves to
    org when org config is present, else repo when a repository was detected.
    """
    requested = requested.lower()
    if requested == "org":
        if not has_org_config:
            raise ModeError("scope 'org' requires organisation configuration")
        mode = Mode.ORG
    elif requested == "repo":
        if detected_repo is None:
            raise ModeError("scope 'repo' requires a detected/--specified repository")
        mode = Mode.REPO
    elif requested == "auto":
        if has_org_config:
            mode = Mode.ORG
        elif detected_repo is not None:
            mode = Mode.REPO
        else:
            raise ModeError(
                "cannot resolve scope: provide config (org mode) or run inside a "
                "GitHub checkout (repo mode)"
            )
    else:
        raise ModeError(f"unknown scope: {requested!r}")
    log.info("resolved operating mode: %s", mode.value)
    return mode


_THRESHOLDS = {
    "none": None,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


def _max_severity(sig: RepoSignal) -> Severity | None:
    c = sig.counts
    if c.critical:
        return Severity.CRITICAL
    if c.high:
        return Severity.HIGH
    if c.medium:
        return Severity.MEDIUM
    if c.low:
        return Severity.LOW
    return None


def should_fail(signals: list[RepoSignal], threshold: str) -> bool:
    """Whether the run should fail given a severity threshold (repo-mode gate).

    ``none`` never fails; ``any`` fails on any offender; a severity name fails
    when any offending signal has a finding at or above that severity.
    """
    threshold = threshold.lower()
    if threshold == "none":
        return False
    if threshold == "any":
        return any(s.is_offender for s in signals)
    if threshold not in _THRESHOLDS:
        raise ModeError(f"unknown fail threshold: {threshold!r}")
    floor = _THRESHOLDS[threshold]
    assert floor is not None
    return any(
        s.is_offender and (sev := _max_severity(s)) is not None and sev >= floor
        for s in signals
    )


def write_github_output(values: dict[str, str], path: str | None = None) -> None:
    """Append ``key=value`` pairs to ``$GITHUB_OUTPUT`` (multiline-safe)."""
    target = path or os.environ.get("GITHUB_OUTPUT")
    if not target:
        return
    with open(target, "a", encoding="utf-8") as handle:
        for key, value in values.items():
            if "\n" in value:
                handle.write(f"{key}<<__GSR_EOF__\n{value}\n__GSR_EOF__\n")
            else:
                handle.write(f"{key}={value}\n")


def append_step_summary(markdown: str, path: str | None = None) -> None:
    """Append Markdown to ``$GITHUB_STEP_SUMMARY`` if available."""
    target = path or os.environ.get("GITHUB_STEP_SUMMARY")
    if not target:
        return
    with open(target, "a", encoding="utf-8") as handle:
        handle.write(markdown.rstrip() + "\n")
