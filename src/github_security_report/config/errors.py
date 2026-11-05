# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Turning schema violations into findings a person can act on.

``jsonschema`` reports the first error it meets in its own vocabulary
(``Additional properties are not allowed ('x' was unexpected)``). This module
walks every error instead, sorts them by where they sit in the configuration,
and renders each as ``<dotted.path>: <message>`` in the configuration's own
terms: the keys valid at that level, a close match for a typo, the block a
misplaced key belongs in, and what replaced a removed key.
"""

from __future__ import annotations

import difflib
import json
import re
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

import jsonschema

from github_security_report import __version__
from github_security_report.config.dictionary import (
    dotted,
    key_homes,
    kind_of,
    note_path,
    schema_parts,
)
from github_security_report.config.key_notes import DEPRECATED, REMOVED
from github_security_report.config.schema import CONFIG_SCHEMA, ConfigError

Path = tuple[str | int, ...]

_TYPE_NAMES = {
    "integer": "an integer",
    "number": "a number",
    "string": "a string",
    "boolean": "true or false",
    "array": "a list",
    "object": "an object",
}

_VALIDATOR = jsonschema.Draft202012Validator(CONFIG_SCHEMA)


def version_note() -> str:
    """The pointer appended when a key is unknown: it may be from a later release."""
    return (
        f"(github-security-report {__version__}; a key added in a later "
        "release needs an upgrade)"
    )


def located(exc: ConfigError, prefix: str) -> ConfigError:
    """``exc`` with each finding's path placed under ``prefix``."""
    return ConfigError(*(f"{prefix}{finding}" for finding in exc.findings))


def _schema_of(error: jsonschema.ValidationError) -> Mapping[str, Any]:
    return error.schema if isinstance(error.schema, Mapping) else {}


def _show(value: object) -> str:
    text = json.dumps(value)
    return text if len(text) <= 40 else f"{text[:37]}..."


def _where(path: Path) -> str:
    return dotted(path) or "(top level)"


def _sort_key(path: Path) -> tuple[tuple[int, str | int], ...]:
    return tuple((0, part) if isinstance(part, int) else (1, part) for part in path)


def _unknown(path: Path, key: str, valid: Sequence[str]) -> tuple[str, bool]:
    """The message for ``key`` found at ``path``, and whether it is unknown."""
    here = note_path((*schema_parts(path), key))
    removed = REMOVED.get(here)
    if removed:
        release, replacement = removed
        hint = f'; use "{replacement}" instead' if replacement else ""
        return f'key "{key}" was removed in {release}{hint}', False
    block = here.rpartition(".")[0]
    text = f'unknown key "{key}"'
    close = difflib.get_close_matches(key, valid, n=1)
    if close:
        text += f' (did you mean "{close[0]}"?)'
    homes = [
        home or "the top level" for home in key_homes().get(key, ()) if home != block
    ]
    if homes:
        text += f'; "{key}" belongs under {" or ".join(homes)}'
    if valid:
        text += f"; valid keys: {', '.join(valid)}"
    return text, True


def _additional(error: jsonschema.ValidationError) -> Iterator[tuple[Path, str, bool]]:
    path: Path = tuple(error.absolute_path)
    known = _schema_of(error).get("properties", {})
    if not isinstance(error.instance, Mapping):
        return
    for key in error.instance:
        if key not in known:
            message, unknown = _unknown(path, key, list(known))
            yield (*path, key), f"{_where(path)}: {message}", unknown


def _required(error: jsonschema.ValidationError) -> Iterator[tuple[Path, str, bool]]:
    path: Path = tuple(error.absolute_path)
    instance = error.instance if isinstance(error.instance, Mapping) else {}
    required: Any = error.validator_value
    for key in required:
        if key not in instance:
            yield (
                (*path, key),
                f"{dotted((*path, key))}: required key is missing",
                False,
            )


def _type(error: jsonschema.ValidationError) -> str:
    wanted: Any = error.validator_value
    names = [wanted] if isinstance(wanted, str) else list(wanted)
    expected = " or ".join(_TYPE_NAMES.get(name, name) for name in names)
    return f"expected {expected}, got {_show(error.instance)}"


def _enum(error: jsonschema.ValidationError) -> str:
    values: Any = error.validator_value
    allowed = ", ".join(str(value) for value in values)
    return f"{_show(error.instance)} is not one of {allowed}"


def _min_items(error: jsonschema.ValidationError) -> str:
    count = error.validator_value
    return f"needs at least {count} {'entry' if count == 1 else 'entries'}"


def _min_length(error: jsonschema.ValidationError) -> str:
    if error.validator_value == 1:
        return "cannot be empty"
    return f"needs at least {error.validator_value} characters"


_MESSAGES: Mapping[str, Callable[[jsonschema.ValidationError], str]] = {
    "type": _type,
    "enum": _enum,
    "minimum": lambda e: (
        f"expected at least {e.validator_value}, got {_show(e.instance)}"
    ),
    "maximum": lambda e: (
        f"expected at most {e.validator_value}, got {_show(e.instance)}"
    ),
    "exclusiveMinimum": lambda e: (
        f"expected more than {e.validator_value}, got {_show(e.instance)}"
    ),
    "minItems": _min_items,
    "minLength": _min_length,
    "uniqueItems": lambda e: "lists a value more than once",
    "oneOf": lambda e: f"expected {kind_of(_schema_of(e))}, got {_show(e.instance)}",
}


def _render(error: jsonschema.ValidationError) -> Iterator[tuple[Path, str, bool]]:
    """Yield ``(path, finding, unknown_key)`` for one schema error."""
    if error.validator == "additionalProperties":
        yield from _additional(error)
        return
    if error.validator == "required":
        yield from _required(error)
        return
    path: Path = tuple(error.absolute_path)
    render = _MESSAGES.get(str(error.validator))
    message = render(error) if render else error.message
    yield path, f"{_where(path)}: {message}", False


_FINDING_PART = re.compile(r"\[(\d+)\]|([^.\[]+)")


def _finding_path(finding: str) -> Path:
    """The path a semantic finding names, parsed back from its dotted prefix."""
    where = finding.partition(": ")[0]
    return tuple(
        int(index) if index else name for index, name in _FINDING_PART.findall(where)
    )


@dataclass(frozen=True)
class SchemaCheck:
    """Every schema violation in a configuration, with where each sits."""

    rendered: tuple[tuple[Path, str], ...] = ()
    unknown: bool = False

    def __bool__(self) -> bool:
        return bool(self.rendered)

    def touches(self, block: Path) -> bool:
        """Whether a violation sits in ``block``, in a block holding it, or
        in a block it holds: ``block`` cannot then be parsed safely."""
        return any(
            path[: len(block)] == block or block[: len(path)] == path
            for path, _text in self.rendered
        )

    def findings(self, problems: Sequence[str] = ()) -> list[str]:
        """These violations and ``problems`` merged in path order, one per
        line, ending with :func:`version_note` when any key is unknown, since
        a key this release has never heard of may be one a later release
        added."""
        merged = [*self.rendered, *((_finding_path(p), p) for p in problems)]
        merged.sort(key=lambda item: (_sort_key(item[0]), item[1]))
        lines = list(dict.fromkeys(text for _path, text in merged))
        if self.unknown:
            lines.append(version_note())
        return lines


def check_schema(data: object) -> SchemaCheck:
    """Validate ``data`` against the schema, collecting every violation."""
    rendered = [
        finding for error in _VALIDATOR.iter_errors(data) for finding in _render(error)
    ]
    return SchemaCheck(
        rendered=tuple((path, text) for path, text, _unknown in rendered),
        unknown=any(unknown for _path, _text, unknown in rendered),
    )


def schema_findings(data: object) -> list[str]:
    """Every schema violation in ``data``, in path order, one line each."""
    return check_schema(data).findings()


def _deprecated(value: Any, path: Path) -> Iterator[str]:
    if isinstance(value, Mapping):
        for key, child in value.items():
            here = (*path, key)
            replacement = DEPRECATED.get(note_path(schema_parts(here)))
            if replacement:
                new = replacement.rpartition(".")[2]
                yield f'{dotted(here)}: deprecated; use "{new}" instead'
            yield from _deprecated(child, here)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _deprecated(child, (*path, index))


def deprecation_findings(data: object) -> list[str]:
    """Each deprecated key in ``data``, with the key that replaces it."""
    return list(_deprecated(data, ()))
