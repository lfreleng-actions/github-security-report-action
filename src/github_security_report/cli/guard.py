# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""The net beneath every command: an unexpected error exits 7, not 1.

Exit 1 means "findings met the repo-mode gate", so a traceback that escaped
to the interpreter would read to an automated caller as a failed gate. Every
command runs inside :meth:`GuardedGroup.invoke`, the root group's dispatch,
so a command added later is covered without registering anything.

What already has a meaning passes through untouched: Typer's own exits,
aborts and usage errors keep their codes, and ``KeyboardInterrupt`` and
``asyncio.CancelledError`` are not :class:`Exception` subclasses at all.
"""

from __future__ import annotations

import errno
import traceback
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any

import typer
from rich.console import Console

# Typer vendors Click; this is the base of its usage errors in every release
# the project and its type-checking hook pin.
from typer._click.exceptions import ClickException
from typer.core import TyperGroup

from github_security_report.cli.progress import interactive

if TYPE_CHECKING:
    from typer._click import Context

INTERNAL_ERROR = 7


def _passes_through(exc: Exception) -> bool:
    """Whether ``exc`` already carries its own exit code and message."""
    if isinstance(exc, typer.Exit | typer.Abort | ClickException):
        return True
    # A closed pipe has its own quiet handling in Typer's main loop.
    return isinstance(exc, OSError) and exc.errno == errno.EPIPE


def _no_color(args: Sequence[str]) -> bool:
    """Whether the subcommand's own arguments ask for ``--no-color``."""
    if "--" in args:
        args = args[: list(args).index("--")]
    return "--no-color" in args


def report_internal_error(
    console: Console, exc: Exception, *, command: str | None, verbose: bool
) -> None:
    """Print the short internal-error message, and with ``verbose`` the trace.

    The traceback is formatted without frame locals: a frame on the request
    path can hold a token.
    """
    if verbose:
        console.print(
            "".join(traceback.format_exception(exc)).rstrip(),
            markup=False,
            highlight=False,
            emoji=False,
            soft_wrap=True,
        )
    detail = str(exc).strip()
    lines = [
        f"Internal error: {type(exc).__name__}"
        + (f": {detail.splitlines()[0]}" if detail else ""),
        "This is an unexpected failure in github-security-report, not a "
        "finding. Output files this run wrote may be incomplete: do not "
        "publish them.",
    ]
    if command == "remediate":
        lines.append(
            "Changes remediate made before the error stand: check what the "
            "run printed above before re-running."
        )
    if not verbose:
        lines.append("Re-run with --verbose to see the traceback.")
    console.print(
        "\n".join(lines),
        style="red",
        markup=False,
        highlight=False,
        emoji=False,
        soft_wrap=True,
    )


class GuardedGroup(TyperGroup):
    """The root command group: turns an unexpected error into exit 7."""

    def invoke(self, ctx: Context) -> Any:
        """Dispatch to the subcommand, reporting any error nothing handled."""
        # Read before dispatch, which empties ctx.args: what follows the
        # subcommand's name, so the message honours its --no-color.
        no_color = _no_color(ctx.args)
        try:
            return super().invoke(ctx)
        except Exception as exc:
            if _passes_through(exc):
                raise
            # Built as every command builds its own, on the same stream.
            console = Console(no_color=no_color or not interactive(), highlight=False)
            report_internal_error(
                console,
                exc,
                command=ctx.invoked_subcommand,
                verbose=bool(ctx.params.get("verbose")),
            )
            raise typer.Exit(INTERNAL_ERROR) from None


def install(app: typer.Typer) -> None:
    """Route every command of ``app`` through :class:`GuardedGroup`.

    Also turns off frame locals in Typer's own exception rendering, whatever
    this Typer version's default, for anything that still reaches it.
    """
    app.info.cls = GuardedGroup
    app.pretty_exceptions_show_locals = False
