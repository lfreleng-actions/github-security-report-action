# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""The ``config`` command: check a configuration, list the keys it takes.

``config check`` reads a configuration the way ``report`` does (an explicit
path, ``--config-data``, or the per-user file) and stops there: it prints
every finding and exits 2, or prints any warning and confirms the
configuration is valid. ``config keys`` lists the key dictionary generated
from the schema, so the keys it shows are the keys the loader accepts.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Annotated

import typer
from rich.console import Console
from rich.padding import Padding
from rich.text import Text

from github_security_report import config
from github_security_report.cli.config_source import (
    ConfigLoadError,
    abort_config,
    find_config,
    read_config,
)
from github_security_report.cli.progress import interactive
from github_security_report.config.dictionary import KeyEntry, keys_under

config_app = typer.Typer(
    help="Check a configuration, or list the keys a configuration takes.",
    no_args_is_help=True,
)

# The loader warns, rather than fails, about what it accepts but advises
# against: a deprecated key, a dead fail_severity, a token value in token_env.
_LOADER_LOG = logging.getLogger("github_security_report.config.loader")

_NoColor = Annotated[
    bool, typer.Option("--no-color", help="Disable colour in terminal output.")
]


def _console(no_color: bool) -> Console:
    return Console(no_color=no_color or not interactive(), highlight=False)


class _Collect(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.WARNING)
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(record.getMessage())


@contextmanager
def _loader_warnings() -> Iterator[list[str]]:
    """Collect the loader's warnings instead of logging them."""
    handler = _Collect()
    propagate = _LOADER_LOG.propagate
    _LOADER_LOG.addHandler(handler)
    _LOADER_LOG.propagate = False
    try:
        yield handler.messages
    finally:
        _LOADER_LOG.removeHandler(handler)
        _LOADER_LOG.propagate = propagate


_Source = tuple[str, Callable[[str], config.Config], str]


def _check_source(path: str | None, config_data: str | None) -> _Source | None:
    """The source label, its loader and the argument to load, if any.

    An explicit ``--config-data`` is checked even when empty, so an unset
    variable passed to it fails rather than quietly checking another file.
    """
    if path:
        return path, config.load_file, path
    if config_data is not None:
        return "--config-data", config.loads, config_data
    found = find_config()
    return (str(found), config.load_file, str(found)) if found else None


@config_app.command()
def check(
    path: Annotated[
        str | None,
        typer.Argument(
            help="Configuration file to check (default: the per-user file).",
            show_default=False,
        ),
    ] = None,
    config_data: Annotated[
        str | None,
        typer.Option(
            "--config-data",
            help="Configuration to check, as JSON or base64-encoded JSON.",
        ),
    ] = None,
    no_color: _NoColor = False,
) -> None:
    """Check a configuration and report every problem in it.

    Exits 0 when the configuration is valid (deprecated keys still are) and 2
    when it is not.
    """
    console = _console(no_color)
    try:
        resolved = _check_source(path, config_data)
    except ConfigLoadError as exc:
        abort_config(console, exc)
    if resolved is None:
        console.print(
            "No configuration to check: give a file, --config-data, or create "
            f"{config.default_config_path()}",
            style="red",
            markup=False,
            soft_wrap=True,
        )
        raise typer.Exit(2)
    source, load, arg = resolved
    try:
        with _loader_warnings() as warnings:
            read_config(source, load, arg)
    except ConfigLoadError as exc:
        abort_config(console, exc)
    for warning in warnings:
        console.print(warning, style="yellow", markup=False, soft_wrap=True)
    console.print(
        f"Configuration {source} is valid.",
        style="green",
        markup=False,
        soft_wrap=True,
    )


def _heading(entry: KeyEntry) -> Text:
    """``path  (type; default: value)``, the path first so it can be copied."""
    detail = entry.kind
    if entry.default:
        detail = f"{detail}; default: {entry.default}"
    return Text.assemble((entry.path, "bold"), f"  ({detail})")


def _description(entry: KeyEntry) -> str:
    if entry.replacement:
        return f"{entry.description} (deprecated; use {entry.replacement})".strip()
    return entry.description


@config_app.command()
def keys(
    prefix: Annotated[
        str,
        typer.Argument(
            help="Show only the keys at or under this dotted path.",
            show_default=False,
        ),
    ] = "",
    no_color: _NoColor = False,
) -> None:
    """List the configuration keys, with type, default and description."""
    console = _console(no_color)
    entries = keys_under(prefix)
    if not entries:
        console.print(
            f"No configuration key matches {prefix!r}; run 'config keys' "
            "for the full list",
            style="red",
            markup=False,
        )
        raise typer.Exit(2)
    for entry in entries:
        console.print(_heading(entry), soft_wrap=True)
        if description := _description(entry):
            console.print(Padding(Text(description), (0, 0, 0, 4)))
