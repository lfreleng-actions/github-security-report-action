# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""The configuration key dictionary, generated from ``CONFIG_SCHEMA``.

Every key the schema accepts is listed once with its dotted path, its type or
allowed values, its default and a one-line description. The path, type and
values come from the schema and the default from the typed models, so the
schema stays the single source of truth; the descriptions, and defaults the
models cannot express, come from :mod:`~github_security_report.config.key_notes`.

The dictionary backs ``github-security-report config keys`` and the
unknown-key messages in :mod:`~github_security_report.config.errors`.
"""

from __future__ import annotations

import dataclasses
import json
import re
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from functools import cache, singledispatch
from typing import Any

from github_security_report.config.key_notes import DEPRECATED, NOTES
from github_security_report.config.models import (
    CategoryToggle,
    OrgConfig,
    ReportConfig,
    ReportDay,
    SlackConfig,
)
from github_security_report.config.schema import (
    CATEGORY_KEYS,
    CONFIG_SCHEMA,
    WEEKDAYS,
)

CATEGORY_PLACEHOLDER = "<category>"


@dataclass(frozen=True)
class KeyEntry:
    """One configuration key, as ``config keys`` lists it."""

    path: str
    kind: str
    default: str
    description: str
    replacement: str | None = None

    @property
    def status(self) -> str:
        """``current``, or ``deprecated`` when a replacement exists."""
        return "deprecated" if self.replacement else "current"


def note_path(parts: Sequence[str]) -> str:
    """The dictionary path describing ``parts``, a schema-level key path.

    ``parts`` names an array element with a ``[]`` suffix (``organizations[]``);
    an organisation's ``slack`` and ``report`` overrides share the top-level
    blocks' keys, so their children map to those. Any category key becomes
    ``<category>``.
    """
    names = list(parts)
    if len(names) > 2 and names[0] == "organizations[]":
        names = names[1:]
    if len(names) > 2 and names[:2] == ["report", "categories"]:
        names[2] = CATEGORY_PLACEHOLDER
    return ".".join(names)


def dotted(parts: Sequence[str | int]) -> str:
    """Render an instance path as ``organizations[0].report.top_n``."""
    text = ""
    for part in parts:
        if isinstance(part, int):
            text += f"[{part}]"
        else:
            text += f".{part}" if text else part
    return text


def schema_parts(parts: Sequence[str | int]) -> tuple[str, ...]:
    """Map an instance path to schema-level parts: list indexes become ``[]``."""
    names: list[str] = []
    for part in parts:
        if isinstance(part, int):
            if names:
                names[-1] += "[]"
        else:
            names.append(part)
    return tuple(names)


def kind_of(schema: Mapping[str, Any]) -> str:
    """A short description of the values a schema accepts."""
    if "$ref" in schema:
        return "object"
    if "enum" in schema:
        return "one of: " + ", ".join(str(value) for value in schema["enum"])
    if "oneOf" in schema:
        return " or ".join(kind_of(option) for option in schema["oneOf"])
    kind = schema.get("type", "any")
    if kind == "array":
        items = schema.get("items", {})
        text = (
            "list of category keys"
            if items.get("enum") == CATEGORY_KEYS
            else f"list of {kind_of(items)}"
        )
        return f"{text} (unique)" if schema.get("uniqueItems") else text
    if kind == "object":
        values = schema.get("additionalProperties")
        if isinstance(values, Mapping):
            return f"map of name to {kind_of(values)}"
        return "object"
    if kind == "string" and schema.get("minLength"):
        return "non-empty string"
    low = schema.get("minimum")
    high = schema.get("maximum")
    if "exclusiveMinimum" in schema:
        text = f"{kind} > {schema['exclusiveMinimum']}"
        return f"{text} and <= {high}" if high is not None else text
    if low is not None and high is not None:
        return f"{kind} {low}-{high}"
    if low is not None:
        return f"{kind} >= {low}"
    return str(kind)


@singledispatch
def _format(value: object) -> str:
    """Render a model default the way a configuration would spell it."""
    return str(value)


@_format.register(type(None))
def _format_none(_value: None) -> str:
    return "unset"


@_format.register(bool)
def _format_bool(value: bool) -> str:
    return "true" if value else "false"


@_format.register(Enum)
def _format_enum(value: Enum) -> str:
    return value.value if isinstance(value.value, str) else value.name.lower()


@_format.register(ReportDay)
def _format_report_day(value: ReportDay) -> str:
    if value.always or value.never:
        return "always" if value.always else "never"
    return ", ".join(day for day in WEEKDAYS if day in value.days)


@_format.register(re.Pattern)
def _format_pattern(value: re.Pattern[str]) -> str:
    return value.pattern


@_format.register(Mapping)
def _format_mapping(value: Mapping[str, object]) -> str:
    return json.dumps(
        {
            key: list(item) if isinstance(item, tuple) else item
            for key, item in value.items()
        }
    )


@_format.register(tuple)
@_format.register(list)
@_format.register(frozenset)
def _format_sequence(value: Sequence[object] | frozenset[object]) -> str:
    return ", ".join(_format(item) for item in value) or "[]"


def _child(default: object, parts: tuple[str, ...], key: str) -> object:
    """The model default for ``key`` beneath ``default``."""
    if parts == ("report", "categories") and isinstance(default, Mapping):
        return default.get(key, CategoryToggle())
    if isinstance(default, Mapping):
        return default.get(key)
    if dataclasses.is_dataclass(default):
        return getattr(default, key, None)
    return None


def _entry(
    schema: Mapping[str, Any], parts: tuple[str, ...], default: object
) -> KeyEntry:
    path = note_path(parts)
    note = NOTES.get(path)
    return KeyEntry(
        path=".".join(parts),
        kind=kind_of(schema),
        default=note.default if note and note.default else _format(default),
        description=note.description if note else "",
        replacement=DEPRECATED.get(path),
    )


def _walk(
    schema: Mapping[str, Any], parts: tuple[str, ...], default: object
) -> Iterator[tuple[Mapping[str, Any], tuple[str, ...], object, bool]]:
    """Yield ``(schema, parts, default, is_leaf)`` for every schema key."""
    items = schema.get("items")
    if (
        schema.get("type") == "array"
        and isinstance(items, Mapping)
        and "properties" in items
    ):
        parts = (*parts[:-1], f"{parts[-1]}[]")
        schema = items
    properties = schema.get("properties")
    if not properties or "$ref" in schema:
        yield schema, parts, default, True
        return
    if parts:
        yield schema, parts, default, False
    for key, child in properties.items():
        yield from _walk(child, (*parts, key), _child(default, parts, key))


_ROOT: tuple[str, ...] = ()

_ROOT_DEFAULTS: Mapping[str, object] = {
    "slack": SlackConfig(),
    "report": ReportConfig(),
    "organizations": OrgConfig(name=""),
}


@cache
def config_keys() -> tuple[KeyEntry, ...]:
    """Every configuration key the schema accepts, in schema order."""
    return tuple(
        _entry(schema, parts, default)
        for schema, parts, default, leaf in _walk(CONFIG_SCHEMA, _ROOT, _ROOT_DEFAULTS)
        if leaf
    )


def keys_under(prefix: str) -> tuple[KeyEntry, ...]:
    """The keys at or beneath ``prefix`` (every key for an empty prefix)."""
    prefix = prefix.strip().strip(".")
    return tuple(
        entry
        for entry in config_keys()
        if not prefix
        or entry.path == prefix
        or entry.path.startswith((f"{prefix}.", f"{prefix}["))
    )


@cache
def key_homes() -> Mapping[str, tuple[str, ...]]:
    """Each key name -> the dictionary paths of the blocks that accept it."""
    homes: dict[str, list[str]] = {}
    for _schema, parts, _default, _leaf in _walk(CONFIG_SCHEMA, _ROOT, _ROOT_DEFAULTS):
        *head, last = parts
        parent = note_path(head)
        name = last.removesuffix("[]")
        places = homes.setdefault(name, [])
        if parent not in places:
            places.append(parent)
    return {name: tuple(places) for name, places in homes.items()}
