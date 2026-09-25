# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Pure parsers mapping code-scanning payloads onto the CodeQL scan-health facts.

Kept apart from :mod:`.parsers`, which maps the batched GraphQL prefetch, since
these read two REST endpoints of their own: the analyses history and the
default-setup state.
"""

from __future__ import annotations

import datetime as dt
import json
import re
from collections.abc import Iterable, Mapping

from github_security_report.client.parsers import _parse_iso
from github_security_report.codeql.facts import (
    CodeQLConfiguration,
    DefaultSetup,
    normalise_language,
)

# The language segment of a code-scanning analysis category, e.g. the
# "python" in "/language:python" or ".github/workflows/codeql.yml:analyze/
# build-mode:none/language:python".
_LANGUAGE_IN_CATEGORY = re.compile(r"language:([\w#+-]+)")


def _analysis_language(analysis: Mapping[str, object]) -> str | None:
    """The language an analysis scanned, from its category or environment.

    The category carries it for both setup types in practice; the
    ``environment`` JSON is the fallback for a custom category that does not.
    """
    category = analysis.get("category")
    if isinstance(category, str):
        match = _LANGUAGE_IN_CATEGORY.search(category)
        if match:
            return normalise_language(match.group(1))
    environment = analysis.get("environment")
    if not isinstance(environment, str) or not environment:
        return None
    try:
        parsed = json.loads(environment)
    except ValueError:
        return None
    language = parsed.get("language") if isinstance(parsed, dict) else None
    return normalise_language(language) if isinstance(language, str) else None


def latest_codeql_configurations(
    analyses: Iterable[Mapping[str, object]],
) -> tuple[CodeQLConfiguration, ...]:
    """Each configuration's state as of its latest analysis, from raw entries.

    Grouped by ``category``, which is how GitHub itself separates
    configurations: GitHub defines a set of analyses by ref, tool and
    category, so a new setup uploading under the same category continues that
    configuration rather than orphaning it. An entry lacking a category or a
    parsable timestamp is skipped rather than guessed at.

    The last scan is the newest *successful* upload. An analysis whose
    ``error`` is set still has a fresh timestamp, and taking it would let a
    workflow that fails on every run read as current indefinitely. A
    configuration that has never once succeeded has no last scan at all
    (``None``), which makes it stale however recent its attempts. ``failing``
    records whether the newest attempt errored. Every analysis id in the
    configuration is kept, newest first, which is the order GitHub requires
    them deleted in.
    """
    grouped: dict[str, list[tuple[dt.datetime, Mapping[str, object]]]] = {}
    for analysis in analyses:
        category = analysis.get("category")
        created = _parse_iso(analysis.get("created_at"))
        if isinstance(category, str) and created is not None:
            grouped.setdefault(category, []).append((created, analysis))
    # Newest first, by a stable sort, so equal timestamps keep the API's own
    # newest-first order: only the newest analysis is deletable, and a tie
    # resolved the other way would pick an older one as "newest".
    return tuple(
        _configuration(category, sorted(entries, key=lambda e: e[0], reverse=True))
        for category, entries in sorted(grouped.items())
    )


def _errored(analysis: Mapping[str, object]) -> bool:
    error = analysis.get("error")
    return isinstance(error, str) and bool(error.strip())


def _analysis_id(analysis: Mapping[str, object]) -> int | None:
    value = analysis.get("id")
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _configuration(
    category: str, entries: list[tuple[dt.datetime, Mapping[str, object]]]
) -> CodeQLConfiguration:
    """One configuration from its analyses, newest first."""
    _newest_at, newest = entries[0]
    succeeded = [created for created, analysis in entries if not _errored(analysis)]
    # Already newest first: the order GitHub requires them deleted in.
    ids = [_analysis_id(analysis) for _created, analysis in entries]
    key = newest.get("analysis_key")
    return CodeQLConfiguration(
        category=category,
        analysis_key=key if isinstance(key, str) else "",
        last_scan_at=succeeded[0] if succeeded else None,
        language=_analysis_language(newest),
        failing=_errored(newest),
        analysis_ids=tuple(i for i in ids if i is not None),
    )


def _parse_default_setup(body: Mapping[str, object]) -> DefaultSetup:
    """A :class:`DefaultSetup` from a ``code-scanning/default-setup`` body."""
    raw = body.get("languages")
    languages = (
        frozenset(normalise_language(lang) for lang in raw if isinstance(lang, str))
        if isinstance(raw, list)
        else frozenset()
    )
    state = body.get("state")
    return DefaultSetup(
        configured=state == "configured",
        languages=languages,
        transitional=state not in ("configured", "not-configured"),
    )
