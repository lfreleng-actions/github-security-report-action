# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Building typed configuration from raw JSON, and locating it on disk.

Parses and validates a configuration mapping into the dataclasses from
:mod:`github_security_report.config.models`, resolves the conventional per-user
config location, and looks up organisation tokens from the environment.
"""

from __future__ import annotations

import base64
import json
import logging
import os
from collections.abc import Callable
from functools import partial
from pathlib import Path
from typing import TypeVar

from github_security_report.config.blocks import _report_from, patterns_from
from github_security_report.config.errors import (
    check_schema,
    deprecation_findings,
    located,
)
from github_security_report.config.models import (
    Config,
    OrgConfig,
    ReportConfig,
    ReportDay,
    SlackConfig,
)
from github_security_report.config.schema import (
    _TOKEN_PREFIXES,
    WEEKDAYS,
    ConfigError,
    collecting,
)
from github_security_report.models import SignalType

log = logging.getLogger(__name__)

_Block = TypeVar("_Block", SlackConfig, ReportConfig)


def parse_report_day(value: str | list[str] | None) -> ReportDay:
    """Parse ``report_day`` into a :class:`ReportDay`.

    Accepts a single weekday, a list of weekdays, ``"never"`` or ``"always"``
    (case-insensitive). Defaults to Tuesday when unset.
    """
    if value is None:
        return ReportDay(days=frozenset({"tuesday"}))
    items = [value] if isinstance(value, str) else list(value)
    normalised = [item.strip().lower() for item in items if item.strip()]
    if normalised == ["always"]:
        return ReportDay(always=True)
    if normalised == ["never"]:
        return ReportDay(never=True)
    for day in normalised:
        if day in {"always", "never"}:
            raise ConfigError(f"'{day}' cannot be combined with weekdays")
        if day not in WEEKDAYS:
            raise ConfigError(f"{day!r} is not a weekday, 'always' or 'never'")
    if not normalised:
        return ReportDay(days=frozenset({"tuesday"}))
    return ReportDay(days=frozenset(normalised))


def _slack_from(data: dict, base: SlackConfig) -> SlackConfig:
    report_day = base.report_day
    if "report_day" in data:
        try:
            report_day = parse_report_day(data["report_day"])
        except ConfigError as exc:
            raise located(exc, "slack.report_day: ") from exc
    return SlackConfig(
        channel=data.get("channel", base.channel),
        report_day=report_day,
    )


def _block(
    problems: list[str],
    prefix: str,
    parse: Callable[[dict, _Block], _Block],
    data: dict,
    base: _Block,
) -> _Block:
    """Parse one block, recording its findings under ``prefix`` on failure."""
    try:
        return parse(data, base)
    except ConfigError as exc:
        problems.extend(located(exc, prefix).findings)
        return base


def _warn_dead_keys(data: dict) -> None:
    """Warn about keys a schema-valid configuration sets to no effect."""
    # A deprecated key (the `release_min_age_days` alias) can appear in the
    # global report block and in any org override; warn exactly once, naming
    # every place it appears, so users are not alarmed by a repeated message.
    deprecated = deprecation_findings(data)
    if deprecated:
        log.warning("deprecated configuration keys:\n  %s", "\n  ".join(deprecated))
    report_blocks = [data.get("report", {})]
    report_blocks += [o.get("report", {}) for o in data.get("organizations", [])]

    # `fail_severity` only governs the severity-ranked signals (their classifier
    # is the sole reader, via fail_severity_for); setting it on a binary
    # category (enablement, cooldown, releases, mutability) silently does
    # nothing. Warn so the dead override is not a quiet footgun.
    signal_keys = {signal.category_key.value for signal in SignalType}
    misplaced = sorted(
        {
            key
            for block in report_blocks
            for key, raw in block.get("categories", {}).items()
            if isinstance(raw, dict)
            and "fail_severity" in raw
            and key not in signal_keys
        }
    )
    if misplaced:
        log.warning(
            "config 'fail_severity' has no effect on the non-severity "
            "categories %s; it applies only to the severity-ranked signals "
            "(%s)",
            ", ".join(misplaced),
            ", ".join(sorted(signal_keys)),
        )
    for raw in data["organizations"]:
        if raw.get("token_env", "").startswith(_TOKEN_PREFIXES):
            log.warning(
                "organization %r token_env looks like a literal token; it must "
                "be an environment-variable NAME, not a token value",
                raw["name"],
            )


def build_config(data: dict) -> Config:
    """Validate a config mapping and build the typed :class:`Config`.

    Every block is checked even after one fails, so a configuration with
    several mistakes reports them all in one run. A block the schema rejects
    is not parsed further, since its values are not the types its checks
    expect, but every block the schema leaves intact still gets its
    semantic checks, and both kinds of finding are reported together in path
    order. A failed block's parent falls back to the defaults so its children
    can still be checked; the defaults are not what the parent asked for, so
    an override of a failed report block skips the checks that compare it
    against inherited values rather than report a finding against the wrong
    ones.
    """
    schema = check_schema(data)
    if not schema:
        _warn_dead_keys(data)

    problems: list[str] = []
    global_slack = SlackConfig()
    if not schema.touches(("slack",)):
        global_slack = _block(
            problems, "", _slack_from, data.get("slack", {}), SlackConfig()
        )
    found = len(problems)
    global_report = ReportConfig()
    report_ok = not schema.touches(("report",))
    if report_ok:
        global_report = _block(
            problems, "", _report_from, data.get("report", {}), ReportConfig()
        )
        report_ok = len(problems) == found
    org_report = _report_from if report_ok else partial(_report_from, inherited=False)

    raw_orgs = data.get("organizations")
    orgs: list[OrgConfig] = []
    for index, raw in enumerate(raw_orgs if isinstance(raw_orgs, list) else []):
        if not isinstance(raw, dict):
            continue
        here = ("organizations", index)
        where = f"organizations[{index}]."
        # Kept as the operator wrote them; validated here so a bad pattern
        # fails the load, and compiled again where they are matched.
        for name in ("exclude", "releases_exclude"):
            if name in raw and not schema.touches((*here, name)):
                with collecting(problems):
                    patterns_from(raw[name], f"{where}{name}")
        slack = global_slack
        if not schema.touches((*here, "slack")):
            slack = _block(
                problems, where, _slack_from, raw.get("slack", {}), global_slack
            )
        report = global_report
        if not schema.touches((*here, "report")):
            report = _block(
                problems, where, org_report, raw.get("report", {}), global_report
            )
        if not schema:
            orgs.append(
                OrgConfig(
                    name=raw["name"],
                    token_env=raw.get("token_env", "GITHUB_TOKEN"),
                    exclude=tuple(raw.get("exclude", ())),
                    releases_exclude=tuple(raw.get("releases_exclude", ())),
                    slack=slack,
                    report=report,
                )
            )
    if schema or problems:
        raise ConfigError(*schema.findings(problems))
    return Config(organizations=tuple(orgs), slack=global_slack, report=global_report)


def loads(raw: str) -> Config:
    """Load config from a string that is either raw JSON or base64-of-JSON.

    Tries JSON first; if that fails, tries base64-decoding then JSON. This lets
    the same loader read a plain ``vars.`` entry or a base64 ``secrets.`` entry
    without the caller knowing which it is.
    """
    text = raw.strip()
    try:
        data = json.loads(text)
    except json.JSONDecodeError as json_exc:
        try:
            decoded = base64.b64decode(text, validate=True).decode("utf-8")
            data = json.loads(decoded)
        # ValueError covers every way the fallback can fail but one:
        # binascii.Error, UnicodeDecodeError and JSONDecodeError are all
        # subclasses, and b64decode raises a bare ValueError for text that is
        # not ASCII. RecursionError is the exception: over-deep nesting.
        except (ValueError, RecursionError) as exc:
            raise ConfigError(
                "configuration is neither valid JSON "
                f"({json_exc.msg} at line {json_exc.lineno} column "
                f"{json_exc.colno}) nor base64-encoded JSON"
            ) from exc
    # Valid JSON the decoder still refuses: an integer longer than Python's
    # int_max_str_digits limit (ValueError) or nesting deeper than the
    # interpreter's recursion limit (RecursionError).
    except (ValueError, RecursionError) as exc:
        raise ConfigError(f"configuration could not be decoded: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(
            f"configuration must be a JSON object, not {type(data).__name__}"
        )
    return build_config(data)


def load_file(path: str) -> Config:
    with open(path, encoding="utf-8") as handle:
        return loads(handle.read())


# Conventional per-user config location, so a local run with no flags picks up
# a central config instead of erroring. Honours $XDG_CONFIG_HOME, falling back
# to ~/.config (the XDG Base Directory default).
DEFAULT_CONFIG_DIR = "github-security-report"
DEFAULT_CONFIG_FILE = "config.json"


def default_config_path() -> Path:
    """The conventional per-user config path (whether or not it exists).

    ``$XDG_CONFIG_HOME/github-security-report/config.json`` when the variable is
    set, otherwise ``~/.config/github-security-report/config.json``.
    """
    base = os.environ.get("XDG_CONFIG_HOME", "").strip() or str(Path.home() / ".config")
    return Path(base) / DEFAULT_CONFIG_DIR / DEFAULT_CONFIG_FILE


# Conventional per-user cache location for data that is expensive to rebuild
# but safe to lose (the workflow-run store). Honours $XDG_CACHE_HOME, falling
# back to ~/.cache (the XDG Base Directory default).
DEFAULT_CACHE_DIR = "github-security-report"


def default_cache_dir() -> Path:
    """The conventional per-user cache directory (whether or not it exists).

    ``$XDG_CACHE_HOME/github-security-report`` when the variable is set,
    otherwise ``~/.cache/github-security-report``.
    """
    base = os.environ.get("XDG_CACHE_HOME", "").strip() or str(Path.home() / ".cache")
    return Path(base) / DEFAULT_CACHE_DIR


def find_default_config() -> Path | None:
    """The per-user config path if a readable file exists there, else None."""
    path = default_config_path()
    return path if path.is_file() else None


def resolve_token(org: OrgConfig, env: dict[str, str] | None = None) -> str | None:
    """Resolve an organisation's token from the environment by name."""
    environ = env if env is not None else os.environ
    token = environ.get(org.token_env, "").strip()
    return token or None
