# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Pure parsers mapping code-scanning payloads onto the CodeQL scan-health facts.

Kept apart from :mod:`.parsers`, which maps the batched GraphQL prefetch, since
these read two REST endpoints of their own: the analyses history and the
default-setup state.
"""

from __future__ import annotations

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
    """Each configuration's newest analysis, from raw ``analyses`` entries.

    Keyed by ``category``, which is how GitHub itself separates
    configurations. The newest entry wins whatever order the API returned them
    in; an entry lacking a category or a parsable timestamp is skipped rather
    than guessed at.
    """
    newest: dict[str, CodeQLConfiguration] = {}
    for analysis in analyses:
        category = analysis.get("category")
        created = _parse_iso(analysis.get("created_at"))
        if not isinstance(category, str) or created is None:
            continue
        current = newest.get(category)
        if current is not None and current.last_scan_at >= created:
            continue
        key = analysis.get("analysis_key")
        newest[category] = CodeQLConfiguration(
            category=category,
            analysis_key=key if isinstance(key, str) else "",
            last_scan_at=created,
            language=_analysis_language(analysis),
        )
    return tuple(sorted(newest.values(), key=lambda c: c.category))


def _parse_default_setup(body: Mapping[str, object]) -> DefaultSetup:
    """A :class:`DefaultSetup` from a ``code-scanning/default-setup`` body."""
    raw = body.get("languages")
    languages = (
        frozenset(normalise_language(lang) for lang in raw if isinstance(lang, str))
        if isinstance(raw, list)
        else frozenset()
    )
    return DefaultSetup(
        configured=body.get("state") == "configured", languages=languages
    )
