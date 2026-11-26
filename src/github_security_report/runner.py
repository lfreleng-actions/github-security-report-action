# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""CLI support: mode resolution, fail-threshold, and GitHub Actions I/O.

Pure helpers kept out of the Typer command so they can be unit-tested. See
``docs/BRIEF.md`` sections 9-12.
"""

from __future__ import annotations

import logging
import os
import re
import secrets
from dataclasses import dataclass
from enum import Enum

from github_security_report.models import RepoSignal, RepoState
from github_security_report.severity import Severity

log = logging.getLogger(__name__)

# GitHub Actions output names are alphanumeric plus '-'/'_'. Validating the key
# (not just the value) stops a non-identifier key -- e.g. one containing a
# newline, '=' or '<<' -- from corrupting $GITHUB_OUTPUT or injecting outputs.
_OUTPUT_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*$")


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


@dataclass(frozen=True)
class GateDecision:
    """The repo-mode gate's verdict, with one line per cause when it fails.

    The exit code and the ``failed`` output both read this one value, so the
    two cannot disagree.
    """

    reasons: tuple[str, ...] = ()

    @property
    def failed(self) -> bool:
        return bool(self.reasons)


def _breaches(sig: RepoSignal, threshold: str) -> bool:
    """Whether one signal fails ``threshold``, whatever its state.

    The threshold judges findings rather than offenders: a signal classified
    clean under its category's cutoff, or unknown with alerts in hand, still
    holds findings the gate can weigh.
    """
    if threshold == "none":
        return False
    if threshold == "any":
        return sig.is_offender or sig.counts.total > 0
    floor = _THRESHOLDS[threshold]
    assert floor is not None
    return sig.counts.at_or_above(floor) > 0


def gate(
    signals: list[RepoSignal], threshold: str, *, fail_on_unknown: bool = False
) -> GateDecision:
    """Decide the repo-mode gate, naming each cause of a failure.

    ``none`` never fails on findings; ``any`` fails on every offender and on
    any open finding; a severity name fails when any signal holds an open
    finding at or above it. With ``fail_on_unknown``, every signal in the
    unknown state also fails the gate, at any threshold.
    """
    threshold = threshold.lower()
    if threshold != "any" and threshold not in _THRESHOLDS:
        raise ModeError(f"unknown fail threshold: {threshold!r}")
    reasons: list[str] = []
    hits = [s.signal.meta.title for s in signals if _breaches(s, threshold)]
    if hits:
        scope = (
            "offenders or open findings under"
            if threshold == "any"
            else "open findings at or above"
        )
        reasons.append(f"{scope} '{threshold}' in {', '.join(hits)}")
    if fail_on_unknown:
        reasons.extend(
            f"{s.signal.meta.title} could not be read: "
            f"{s.detail or 'no reason recorded'}"
            for s in signals
            if s.state is RepoState.UNKNOWN
        )
    return GateDecision(tuple(reasons))


def should_fail(
    signals: list[RepoSignal], threshold: str, *, fail_on_unknown: bool = False
) -> bool:
    """Whether the repo-mode gate fails; see :func:`gate`."""
    return gate(signals, threshold, fail_on_unknown=fail_on_unknown).failed


def write_github_output(values: dict[str, str], path: str | None = None) -> None:
    """Append ``key=value`` pairs to ``$GITHUB_OUTPUT`` (multiline-safe).

    Multiline values use a unique random delimiter per value, regenerated if it
    ever collides with the value, to prevent output-file injection.
    """
    target = path or os.environ.get("GITHUB_OUTPUT")
    if not target:
        return
    with open(target, "a", encoding="utf-8") as handle:
        for key, value in values.items():
            if not _OUTPUT_KEY.match(key):
                # A non-identifier key would corrupt the output file; skip it
                # loudly rather than write something injectable.
                log.error("refusing to write unsafe GITHUB_OUTPUT key: %r", key)
                continue
            if "\n" in value:
                delimiter = f"ghadelim_{secrets.token_hex(16)}"
                while delimiter in value:
                    delimiter = f"ghadelim_{secrets.token_hex(16)}"
                handle.write(f"{key}<<{delimiter}\n{value}\n{delimiter}\n")
            else:
                handle.write(f"{key}={value}\n")


def append_step_summary(markdown: str, path: str | None = None) -> None:
    """Append Markdown to ``$GITHUB_STEP_SUMMARY`` if available."""
    target = path or os.environ.get("GITHUB_STEP_SUMMARY")
    if not target:
        return
    with open(target, "a", encoding="utf-8") as handle:
        handle.write(markdown.rstrip() + "\n")
