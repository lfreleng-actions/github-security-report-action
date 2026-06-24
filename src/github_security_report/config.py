# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Configuration: schema, loading, token resolution, and Slack-day gating.

The tool's configuration is JSON, supplied either as a CLI file, a plain
GitHub ``vars.`` entry, or base64 inside a ``secrets.`` entry (base64 only to
stop raw JSON braces tripping GitHub's log redaction -- it is encoding, not
encryption). Tokens are referenced by environment-variable name, never embedded
literally. See ``docs/BRIEF.md`` sections 8-9.
"""

from __future__ import annotations

import base64
import binascii
import datetime as dt
import json
import logging
import os
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path
from types import MappingProxyType

import jsonschema

log = logging.getLogger(__name__)

WEEKDAYS = (
    "monday",
    "tuesday",
    "wednesday",
    "thursday",
    "friday",
    "saturday",
    "sunday",
)

# Heuristic to warn when a token value, rather than an env-var name, is given.
_TOKEN_PREFIXES = ("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_")


class ConfigError(ValueError):
    """Raised when configuration is malformed or fails validation."""


CONFIG_SCHEMA: dict = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "slack": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "channel": {"type": "string"},
                "report_day": {
                    "oneOf": [
                        {"type": "string"},
                        {"type": "array", "items": {"type": "string"}},
                    ]
                },
            },
        },
        "report": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                # 0 disables the per-signal offender limit (show everything);
                # any positive value caps each table/list at that many rows.
                "top_n": {"type": "integer", "minimum": 0},
                "top_n_report": {"type": "integer", "minimum": 0},
                "top_n_cli": {"type": "integer", "minimum": 0},
                "top_n_slack": {"type": "integer", "minimum": 0},
                "include_archived": {"type": "boolean"},
                "include_test": {"type": "boolean"},
                # Repository-age grace period: repos created within this many
                # days are omitted from Releases/Tagging (0 = include all).
                # `release_min_age_days` is the deprecated former name for this
                # same control and is still accepted for backward compatibility.
                "repo_min_age_days": {"type": "integer", "minimum": 0},
                "release_min_age_days": {"type": "integer", "minimum": 0},
                # Release-staleness threshold: a repo is flagged in
                # Releases/Tagging only when its newest release or tag is older
                # than this many days (0 = flag every eligible repository).
                "release_max_age_days": {"type": "integer", "minimum": 0},
                "ruleset_workflows": {
                    "type": "object",
                    "additionalProperties": {"type": "string"},
                },
            },
        },
        "organizations": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["name"],
                "properties": {
                    "name": {"type": "string", "minLength": 1},
                    "token_env": {"type": "string"},
                    "exclude": {"type": "array", "items": {"type": "string"}},
                    "releases_exclude": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                    "slack": {"$ref": "#/properties/slack"},
                    "report": {"$ref": "#/properties/report"},
                },
            },
        },
    },
    "required": ["organizations"],
}


@dataclass(frozen=True)
class ReportDay:
    """When to post the Slack digest. Owned and evaluated by the tool."""

    always: bool = False
    never: bool = False
    days: frozenset[str] = field(default_factory=frozenset)

    def should_notify(
        self, *, now: dt.date | None = None, force: bool = False
    ) -> bool:
        if force or self.always:
            return True
        if self.never:
            return False
        today = (now or dt.date.today()).strftime("%A").lower()
        return today in self.days


@dataclass(frozen=True)
class SlackConfig:
    channel: str = ""
    report_day: ReportDay = field(default_factory=lambda: ReportDay(days=frozenset({"tuesday"})))


# Default mapping of signal value -> required-workflow path keyword. A repo
# covered by an active org ruleset whose required workflow path contains the
# keyword is treated as having that tool enabled (see :mod:`rulesets`).
DEFAULT_RULESET_WORKFLOWS = {"zizmor": "zizmor"}


@dataclass(frozen=True)
class ReportConfig:
    # Shared default number of offenders shown per signal; per-output overrides
    # below take precedence when set. report = GitHub Pages (Markdown + HTML),
    # cli = terminal, slack = the Slack digest. A value of 0 disables the limit
    # for that output (every offender is shown).
    top_n: int = 10
    top_n_report: int | None = None
    top_n_cli: int | None = None
    top_n_slack: int | None = None
    include_archived: bool = False
    include_test: bool = False
    # Repositories created within this many days are excluded from the
    # Releases/Tagging requirement, giving brand-new repositories a grace
    # period before a release or tag is expected (0 = include all repositories).
    repo_min_age_days: int = 28
    # A repository is flagged in the Releases/Tagging table only when its most
    # recent release or tag is older than this many days; a repository with
    # neither a release nor a tag is always flagged. 0 disables the threshold,
    # so every eligible repository is listed (ranked by staleness).
    release_max_age_days: int = 0
    # Read-only mapping (frozen dataclasses do not deep-freeze a plain dict, so a
    # MappingProxyType prevents in-place mutation of a shared config).
    ruleset_workflows: Mapping[str, str] = field(
        default_factory=lambda: MappingProxyType(dict(DEFAULT_RULESET_WORKFLOWS))
    )

    @property
    def report_top_n(self) -> int:
        """Offenders shown per signal in the GitHub Pages output."""
        return self.top_n_report if self.top_n_report is not None else self.top_n

    @property
    def cli_top_n(self) -> int:
        """Offenders shown per signal in the terminal output."""
        return self.top_n_cli if self.top_n_cli is not None else self.top_n

    @property
    def slack_top_n(self) -> int:
        """Offenders shown per signal in the Slack digest."""
        return self.top_n_slack if self.top_n_slack is not None else self.top_n


@dataclass(frozen=True)
class OrgConfig:
    name: str
    token_env: str = "GITHUB_TOKEN"
    exclude: tuple[str, ...] = ()
    # Repositories excluded from the Releases/Tagging table only (e.g. repos
    # that are never released/consumed externally).
    releases_exclude: tuple[str, ...] = ()
    slack: SlackConfig = field(default_factory=SlackConfig)
    report: ReportConfig = field(default_factory=ReportConfig)


@dataclass(frozen=True)
class Config:
    organizations: tuple[OrgConfig, ...]
    slack: SlackConfig = field(default_factory=SlackConfig)
    report: ReportConfig = field(default_factory=ReportConfig)


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
            raise ConfigError(
                f"'{day}' cannot be combined with weekdays in report_day"
            )
        if day not in WEEKDAYS:
            raise ConfigError(f"invalid report_day value: {day!r}")
    if not normalised:
        return ReportDay(days=frozenset({"tuesday"}))
    return ReportDay(days=frozenset(normalised))


def _slack_from(data: dict, base: SlackConfig) -> SlackConfig:
    return SlackConfig(
        channel=data.get("channel", base.channel),
        report_day=(
            parse_report_day(data["report_day"])
            if "report_day" in data
            else base.report_day
        ),
    )


def _report_from(data: dict, base: ReportConfig) -> ReportConfig:
    data = dict(data)
    # Back-compat: `release_min_age_days` was the original (misleading) name for
    # the repository-age grace period now called `repo_min_age_days`. Accept it
    # as an alias and let an explicit new key win if both appear. The (single)
    # deprecation warning is emitted by build_config, which sees every block.
    if "release_min_age_days" in data:
        legacy = data.pop("release_min_age_days")
        data.setdefault("repo_min_age_days", legacy)
    result = replace(
        base,
        **{
            k: v
            for k, v in data.items()
            if k in {
                "top_n",
                "top_n_report",
                "top_n_cli",
                "top_n_slack",
                "include_archived",
                "include_test",
                "repo_min_age_days",
                "release_max_age_days",
            }
        },
    )
    if "ruleset_workflows" in data:
        # Merge so the built-in defaults (e.g. zizmor) survive unless overridden.
        merged = {**base.ruleset_workflows, **data["ruleset_workflows"]}
        result = replace(result, ruleset_workflows=MappingProxyType(merged))
    return result


def build_config(data: dict) -> Config:
    """Validate a config mapping and build the typed :class:`Config`."""
    try:
        jsonschema.validate(data, CONFIG_SCHEMA)
    except jsonschema.ValidationError as exc:
        raise ConfigError(f"configuration is invalid: {exc.message}") from exc

    # The deprecated `release_min_age_days` alias can appear in the global report
    # block and in any org override; warn exactly once however many blocks use
    # it, so users are not alarmed by a repeated message.
    report_blocks = [data.get("report", {})]
    report_blocks += [o.get("report", {}) for o in data.get("organizations", [])]
    if any("release_min_age_days" in block for block in report_blocks):
        log.warning(
            "config key 'release_min_age_days' is deprecated; use "
            "'repo_min_age_days' (the repository-age grace period) instead"
        )

    global_slack = _slack_from(data.get("slack", {}), SlackConfig())
    global_report = _report_from(data.get("report", {}), ReportConfig())

    orgs: list[OrgConfig] = []
    for raw in data["organizations"]:
        token_env = raw.get("token_env", "GITHUB_TOKEN")
        if token_env.startswith(_TOKEN_PREFIXES):
            log.warning(
                "organization %r token_env looks like a literal token; it must "
                "be an environment-variable NAME, not a token value",
                raw["name"],
            )
        orgs.append(
            OrgConfig(
                name=raw["name"],
                token_env=token_env,
                exclude=tuple(raw.get("exclude", ())),
                releases_exclude=tuple(raw.get("releases_exclude", ())),
                slack=_slack_from(raw.get("slack", {}), global_slack),
                report=_report_from(raw.get("report", {}), global_report),
            )
        )
    return Config(
        organizations=tuple(orgs), slack=global_slack, report=global_report
    )


def loads(raw: str) -> Config:
    """Load config from a string that is either raw JSON or base64-of-JSON.

    Tries JSON first; if that fails, tries base64-decoding then JSON. This lets
    the same loader read a plain ``vars.`` entry or a base64 ``secrets.`` entry
    without the caller knowing which it is.
    """
    text = raw.strip()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        try:
            decoded = base64.b64decode(text, validate=True).decode("utf-8")
            data = json.loads(decoded)
        except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ConfigError(
                "configuration is neither valid JSON nor base64-encoded JSON"
            ) from exc
    if not isinstance(data, dict):
        raise ConfigError("configuration must be a JSON object")
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


def find_default_config() -> Path | None:
    """The per-user config path if a readable file exists there, else None."""
    path = default_config_path()
    return path if path.is_file() else None


def resolve_token(org: OrgConfig, env: dict[str, str] | None = None) -> str | None:
    """Resolve an organisation's token from the environment by name."""
    environ = env if env is not None else os.environ
    token = environ.get(org.token_env, "").strip()
    return token or None
