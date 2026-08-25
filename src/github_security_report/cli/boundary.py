# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Boundary checks and dispatch shared by the commands.

The rejections a command performs before it does any work, plus the two pieces
of dispatch both run modes need. Kept apart from :mod:`cli.app` so the command
bodies there stay a readable sequence of named steps rather than the checks
themselves.

Every function here either returns a resolved value or exits. Each rejection
exists because the alternative is a flag that was accepted, validated and then
silently ignored, which leaves the caller no signal that the run did something
other than what they asked for.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Coroutine, Sequence
from typing import Any

import typer
from rich.console import Console

from github_security_report import gitctx, runner
from github_security_report.categories import CategoryKey
from github_security_report.cli.modes import _abort_auth, _abort_network
from github_security_report.client import AuthError, NetworkError
from github_security_report.config import Config


def check_non_negative(console: Console, name: str, value: int | None) -> None:
    """Reject a negative numeric override at the CLI boundary.

    Mirrors the config schema, whose minimum for these controls is 0; 0 itself
    is permitted and carries the "no limit" / "no threshold" meaning.
    """
    if value is not None and value < 0:
        console.print(f"[red]{name} must be 0 or greater[/red]")
        raise typer.Exit(2)


def check_limits(console: Console, limits: Sequence[tuple[str, int | None]]) -> None:
    """Reject a negative row limit, naming the flag and the 0 convention."""
    for name, value in limits:
        if value is not None and value < 0:
            console.print(f"[red]{name} must be 0 or greater (0 = no limit)[/red]")
            raise typer.Exit(2)


def resolve_hidden(console: Console, hide: list[str] | None) -> frozenset[CategoryKey]:
    """Validate ``--hide`` values into category keys, or abort.

    An unrecognised category is rejected rather than ignored: the point of the
    flag is to keep something off a published surface, so a typo that silently
    published it anyway would be the one failure mode that matters.
    """
    if not hide:
        return frozenset()
    valid = {key.value: key for key in CategoryKey}
    unknown = sorted({name for name in hide if name not in valid})
    if unknown:
        # markup=False: the user-supplied values are printed literally, so
        # bracketed input cannot be interpreted as Rich markup.
        console.print(
            f"Unknown --hide category: {', '.join(unknown)}. "
            f"Valid values: {', '.join(sorted(valid))}",
            style="red",
            markup=False,
        )
        raise typer.Exit(2)
    return frozenset(valid[name] for name in hide)


def reject_org_only(console: Console, supplied: Sequence[str]) -> None:
    """Refuse organisation-only flags once the run has resolved to repo mode.

    Repo mode renders a single repository to the terminal and the job summary:
    it publishes no Pages directory, posts no digest, and builds no
    Releases/Tagging table, so none of these flags has anything to act on.
    Accepting them silently is the one failure mode worth ruling out -- the
    caller would have no signal that the run ignored what they asked for -- so
    they are rejected with the flags named rather than dropped.
    """
    if not supplied:
        return
    console.print(
        f"{', '.join(supplied)} apply to organisation mode only, but this run "
        "resolved to repo mode. Drop the flag, or pass --scope org with a "
        "configuration that names an organisation.",
        style="red",
        markup=False,
    )
    raise typer.Exit(2)


def check_releases_exclude(
    console: Console, cfg: Config, releases_exclude: Sequence[str] | None
) -> None:
    """Refuse ``--releases-exclude`` when it cannot say which org it means.

    One list would replace the per-org list of every configured organisation,
    so a three-org config carrying three curated lists would lose all three.
    Inventing an ``org/repo`` syntax for the flag would be a worse answer than
    pointing at the config key that already expresses this per organisation.
    """
    if not releases_exclude or len(cfg.organizations) <= 1:
        return
    names = ", ".join(o.name for o in cfg.organizations)
    console.print(
        "--releases-exclude replaces the configured list for every "
        f"organisation, and this run covers {len(cfg.organizations)} of them "
        f"({names}). Set releases_exclude per organisation in the "
        "configuration instead.",
        style="red",
        markup=False,
    )
    raise typer.Exit(2)


def detect_target(
    console: Console, repo: str | None, scope: str
) -> tuple[str, str] | None:
    """The ``owner/name`` a repo-mode run would target, if there is one.

    An explicit ``--repo`` must be exactly ``owner/name`` (one slash, both
    parts non-empty). A malformed value would otherwise be split incorrectly or
    fall back to git detection, risking a report against an unintended
    repository.
    """
    if repo:
        if not re.fullmatch(r"[^/]+/[^/]+", repo):
            console.print("[red]--repo must be in 'owner/name' format[/red]")
            raise typer.Exit(2)
        owner, name = repo.split("/", 1)
        return owner, name
    if scope != "org":
        return gitctx.detect_repo()
    return None


def resolve_mode(
    console: Console,
    scope: str,
    *,
    cfg: Config | None,
    detected: tuple[str, str] | None,
) -> runner.Mode:
    """The run mode, or exit 2 with the reason it could not be resolved."""
    try:
        return runner.resolve_mode(
            scope, has_org_config=cfg is not None, detected_repo=detected
        )
    except runner.ModeError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(2) from exc


def run_guarded(console: Console, coro: Coroutine[Any, Any, int]) -> int:
    """Run a mode coroutine, turning credential and network failures into exits.

    Both run modes need the same two handlers, and both distinguish the two
    causes by exit code so an automated caller can tell "rotate the token" from
    "retry later" without parsing the message.
    """
    try:
        return asyncio.run(coro)
    except AuthError as exc:
        _abort_auth(console, exc)
    except NetworkError as exc:
        _abort_network(console, exc)
