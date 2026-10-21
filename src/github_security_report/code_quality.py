# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""GitHub Code Quality: which repositories it applies to, and their setup.

Code Quality analyses six language families only, so a repository is
classified from its Linguist languages before its setup means anything. One
holding none of them (shell scripts and workflow files alone, say) is not
applicable: there is nothing for Code Quality to analyse, so it is never
reported as off and never remediated. See ADR-0006.

The setup response cannot stand in for the classification: GitHub answers a
``not-configured`` repository with an empty ``languages`` list, whatever the
repository holds.

This module depends on nothing else in the package, so the client, the
collection and the report can all import it without a cycle.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType

# Linguist language name -> Code Quality language identifier. Every other
# Linguist language is ignored.
LINGUIST_TO_CODE_QUALITY: Mapping[str, str] = MappingProxyType(
    {
        "Python": "python",
        "Go": "go",
        "Java": "java-kotlin",
        "Kotlin": "java-kotlin",
        "JavaScript": "javascript-typescript",
        "TypeScript": "javascript-typescript",
        "Ruby": "ruby",
        "C#": "csharp",
    }
)

# The Code Quality language identifiers, in the order the report shows them.
CODE_QUALITY_LANGUAGES: tuple[str, ...] = tuple(
    dict.fromkeys(LINGUIST_TO_CODE_QUALITY.values())
)


def applicable_languages(linguist: Iterable[str]) -> frozenset[str]:
    """The Code Quality identifiers for a repository's Linguist languages.

    Empty means the repository is not applicable to Code Quality.
    """
    return frozenset(
        LINGUIST_TO_CODE_QUALITY[name]
        for name in linguist
        if name in LINGUIST_TO_CODE_QUALITY
    )


def linguist_names(connection: object) -> tuple[str, ...] | None:
    """Linguist language names from a GraphQL ``languages`` connection.

    ``None`` when the connection is missing or malformed, so a repository whose
    languages were never read is not mistaken for one that has none; and when
    the page is truncated (``pageInfo.hasNextPage`` not false), since a
    supported language beyond the window would then go unseen, misreporting
    the repository as Not applicable or Enabled.
    """
    if not isinstance(connection, dict):
        return None
    page = connection.get("pageInfo")
    if not isinstance(page, dict) or page.get("hasNextPage") is not False:
        return None
    nodes = connection.get("nodes")
    if not isinstance(nodes, list):
        return None
    return tuple(
        node["name"]
        for node in nodes
        if isinstance(node, dict) and isinstance(node.get("name"), str)
    )


@dataclass(frozen=True)
class CodeQualitySetup:
    """A repository's Code Quality setup, as ``GET .../code-quality/setup`` reports it.

    ``languages`` holds the identifiers the setup analyses, verbatim; it is
    empty whenever the feature is not configured.
    """

    configured: bool
    languages: frozenset[str] = frozenset()

    @classmethod
    def from_api(cls, body: object) -> CodeQualitySetup | None:
        """Parse a setup response body; ``None`` when it is not a reading.

        The API documents two states, ``configured`` and ``not-configured``.
        Any other, or a body that is not an object, says nothing about whether
        the feature is on, so it is unreadable rather than off.
        """
        if not isinstance(body, dict):
            return None
        state = body.get("state")
        if state not in ("configured", "not-configured"):
            return None
        raw = body.get("languages")
        languages = (
            frozenset(lang for lang in raw if isinstance(lang, str))
            if isinstance(raw, list)
            else frozenset()
        )
        return cls(configured=state == "configured", languages=languages)
