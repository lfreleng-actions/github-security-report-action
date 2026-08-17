# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Building typed configuration from raw JSON, and locating it on disk.

Parses and validates a configuration mapping into the dataclasses from
:mod:`github_security_report.config.models`, resolves the conventional per-user
config location, and looks up organisation tokens from the environment.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import os
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from types import MappingProxyType

import jsonschema

from github_security_report.config.models import (
    CategoryToggle,
    Config,
    OrgConfig,
    ReportConfig,
    ReportDay,
    SlackConfig,
)
from github_security_report.config.schema import (
    _TOKEN_PREFIXES,
    CONFIG_SCHEMA,
    REPORT_OUTPUTS,
    WEEKDAYS,
    ConfigError,
)
from github_security_report.issues import RESERVED_COLUMNS
from github_security_report.models import SignalType
from github_security_report.severity import Severity, from_name

log = logging.getLogger(__name__)

# Characters that would break the surfaces a column header is rendered into:
# a pipe ends a Markdown table cell, a backtick can close the Slack code fence.
_UNSAFE_COLUMN = ("|", "`")


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
            raise ConfigError(f"'{day}' cannot be combined with weekdays in report_day")
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


def _issue_labels_from(data: Mapping[str, list[str]]) -> Mapping[str, tuple[str, ...]]:
    """Validate and convert the ``issue_labels`` column -> labels mapping.

    Three ways a column name can break the Issues table, none of which JSON
    Schema can express as a useful error:

    * **Reusing a fixed header.** The table supplies five of its own
      (:data:`~github_security_report.issues.RESERVED_COLUMNS`). A configured
      ``Other`` shares the implicit column's counter, so those issues are shown
      twice and the class columns stop summing to ``Total``; a configured
      ``Repository`` is worse, because ``sort: ["repository"]`` would then
      resolve to a count column rather than the repository name.
    * **Differing only by case.** ``Bug`` and ``bug`` are two columns but one
      sort target, and ``ordering.resolve_terms`` matches case-insensitively.
    * **Being blank, padded, or structurally unsafe.** A blank name renders a
      column nothing can refer to; a padded one such as ``" Bug "`` could never
      be named in ``sort``, whose terms are stripped before matching; and a
      name carrying ``|``, a backtick or a control character would corrupt the
      Markdown table or Slack code fence it is rendered into, since headers go
      out verbatim.
    """
    reserved = {column.casefold(): column for column in RESERVED_COLUMNS}
    seen: set[str] = set()
    for column in data:
        folded = column.casefold()
        if not column.strip():
            raise ConfigError("issue_labels column names cannot be blank")
        if column != column.strip():
            raise ConfigError(
                f"issue_labels column {column!r} has leading or trailing "
                "whitespace; sort terms are stripped before matching, so this "
                "column could never be named in a `sort` list"
            )
        if not column.isprintable() or any(ch in column for ch in _UNSAFE_COLUMN):
            raise ConfigError(
                f"issue_labels column {column!r} contains a character that "
                "would corrupt the rendered tables; column names go into "
                "Markdown headers and Slack code fences verbatim, so they must "
                "be printable single-line text without '|' or backticks"
            )
        if folded in reserved:
            raise ConfigError(
                f"issue_labels column {column!r} collides with {reserved[folded]!r}, "
                "one of the columns the Issues table always supplies "
                f"({', '.join(RESERVED_COLUMNS)}); choose a different name"
            )
        if folded in seen:
            raise ConfigError(
                f"issue_labels column {column!r} duplicates an earlier column "
                "differing only in case; column names must be distinct "
                "case-insensitively so they can be sorted on unambiguously"
            )
        seen.add(folded)
    return MappingProxyType({column: tuple(labels) for column, labels in data.items()})


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
            if k
            in {
                "top_n",
                "top_n_report",
                "top_n_cli",
                "top_n_slack",
                "include_archived",
                "include_test",
                "repo_min_age_days",
                "release_max_age_days",
                "gating",
            }
        },
    )
    if "ruleset_workflows" in data:
        # Merge so the built-in defaults (e.g. zizmor) survive unless overridden.
        merged = {**base.ruleset_workflows, **data["ruleset_workflows"]}
        result = replace(result, ruleset_workflows=MappingProxyType(merged))
    if "issue_labels" in data:
        # Replace rather than merge: the mapping defines the Issues table's
        # column set, so merging would keep default columns the operator
        # deliberately left out.
        result = replace(result, issue_labels=_issue_labels_from(data["issue_labels"]))
    if "categories" in data:
        result = replace(
            result,
            categories=_categories_from(data["categories"], base.categories),
        )
    return result


def _categories_from(
    data: dict, base: Mapping[str, CategoryToggle]
) -> Mapping[str, CategoryToggle]:
    """Merge a ``categories`` block over the inherited toggles.

    Each category is merged independently and key-by-key, so an org override
    that flips a single output leaves the inherited ``enabled`` switch and the
    other outputs untouched.
    """
    merged: dict[str, CategoryToggle] = dict(base)
    for key, raw in data.items():
        current = merged.get(key, CategoryToggle())
        outputs = current.outputs
        if "outputs" in raw:
            outputs = replace(
                outputs,
                **{
                    output: value
                    for output, value in raw["outputs"].items()
                    if output in REPORT_OUTPUTS
                },
            )
        fail_severity = current.fail_severity
        if "fail_severity" in raw:
            # The schema constrains the value to a known severity name, so
            # from_name resolves it; informational is handled explicitly as it
            # is below the security-severity scale from_name covers.
            name = raw["fail_severity"]
            fail_severity = (
                Severity.INFORMATIONAL if name == "informational" else from_name(name)
            )
        merged[key] = CategoryToggle(
            enabled=raw.get("enabled", current.enabled),
            outputs=outputs,
            fail_severity=fail_severity,
            top_n=raw.get("top_n", current.top_n),
            sort=tuple(raw["sort"]) if "sort" in raw else current.sort,
        )
    return MappingProxyType(merged)


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
