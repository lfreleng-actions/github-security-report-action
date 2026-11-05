# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Reading a configuration at the command-line boundary.

Every way a configuration can be unusable -- a file that is missing or
unreadable, text that is neither JSON nor base64 JSON, or content the schema
or the loader rejects -- becomes one red block that names the source and
every finding, and exit code 2, the same as any other usage error. Nothing
about a configuration problem prints a traceback; ``--verbose`` logs the
exception chain for whoever needs it.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path
from typing import NoReturn

import typer
from rich.console import Console

from github_security_report import config
from github_security_report.config import Config, ConfigError

log = logging.getLogger(__name__)

# What reading a configuration can raise besides ConfigError: OSError for a
# path that is missing, a directory or unreadable, and UnicodeDecodeError for
# a file that is not UTF-8 text.
_READ_ERRORS = (OSError, UnicodeDecodeError)


class ConfigLoadError(Exception):
    """A configuration that could not be used, and where it came from."""

    def __init__(self, source: str, cause: Exception) -> None:
        super().__init__(f"{source}: {cause}")
        self.source = source
        self.cause = cause

    def render(self) -> str:
        """The message the command line prints for this failure."""
        cause = self.cause
        if isinstance(cause, ConfigError):
            lines = "\n".join(f"  {finding}" for finding in cause.findings)
            return f"Configuration {self.source} is invalid:\n{lines}"
        if isinstance(cause, UnicodeDecodeError):
            reason = f"it is not UTF-8 text ({cause.reason} at byte {cause.start})"
        elif isinstance(cause, OSError):
            reason = cause.strerror or str(cause)
        else:
            reason = str(cause)
        return f"Configuration {self.source} could not be read: {reason}"


def read_config(source: str, load: Callable[[str], Config], arg: str) -> Config:
    """``load(arg)``, with any configuration failure tagged with ``source``."""
    try:
        return load(arg)
    except (ConfigError, *_READ_ERRORS) as exc:
        raise ConfigLoadError(source, exc) from exc


def find_config() -> Path | None:
    """The per-user configuration file if one exists, else ``None``.

    A location that cannot be checked is a configuration that cannot be read,
    not an absent one: before Python 3.14, a parent directory without search
    permission makes the check raise ``PermissionError``.
    """
    try:
        return config.find_default_config()
    except OSError as exc:
        raise ConfigLoadError(str(config.default_config_path()), exc) from exc


def abort_config(console: Console, exc: ConfigLoadError) -> NoReturn:
    """Print ``exc`` as a red block and exit 2, without a traceback.

    ``markup=False`` keeps configuration text (a key, a pattern such as
    ``[a-z]``) literal rather than letting Rich read it as markup, and
    ``soft_wrap=True`` leaves wrapping to the terminal so a long path stays
    one string a user can copy.
    """
    log.info("configuration %s could not be used", exc.source, exc_info=exc)
    console.print(exc.render(), style="red", markup=False, soft_wrap=True)
    raise typer.Exit(2)
