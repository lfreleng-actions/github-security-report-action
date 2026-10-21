# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Tests for the GitHub Code Quality language scope and setup parsing."""

from __future__ import annotations

import pytest

from github_security_report.code_quality import (
    CODE_QUALITY_LANGUAGES,
    CodeQualitySetup,
    applicable_languages,
    linguist_names,
)


@pytest.mark.parametrize(
    ("linguist", "expected"),
    [
        (["Python"], {"python"}),
        (["Makefile", "PowerShell", "Python", "Shell"], {"python"}),
        (["Go"], {"go"}),
        (["Java"], {"java-kotlin"}),
        (["Kotlin", "Java"], {"java-kotlin"}),
        (["JavaScript"], {"javascript-typescript"}),
        (["TypeScript", "JavaScript"], {"javascript-typescript"}),
        (["Ruby"], {"ruby"}),
        (["C#"], {"csharp"}),
        (["Python", "Go", "HCL"], {"python", "go"}),
        # Shell scripts and workflow files alone: not applicable.
        (["Shell", "Dockerfile"], set()),
        ([], set()),
        # Linguist names are matched exactly, never folded.
        (["python", "C++", "Rust"], set()),
    ],
)
def test_applicable_languages_maps_linguist_names(
    linguist: list[str], expected: set[str]
) -> None:
    assert applicable_languages(linguist) == frozenset(expected)


def test_display_order_follows_the_mapping() -> None:
    assert CODE_QUALITY_LANGUAGES == (
        "python",
        "go",
        "java-kotlin",
        "javascript-typescript",
        "ruby",
        "csharp",
    )


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        (
            {"state": "configured", "languages": ["python", "go"]},
            CodeQualitySetup(configured=True, languages=frozenset({"python", "go"})),
        ),
        # A not-configured setup reports no languages, whatever the repository
        # holds.
        (
            {"state": "not-configured", "languages": []},
            CodeQualitySetup(configured=False),
        ),
        ({"state": "not-configured"}, CodeQualitySetup(configured=False)),
        # Non-string entries are dropped rather than failing the read.
        (
            {"state": "configured", "languages": ["ruby", 7, None]},
            CodeQualitySetup(configured=True, languages=frozenset({"ruby"})),
        ),
        # An undocumented state, or a body that is no object, is not a reading.
        ({"state": "updating"}, None),
        ({}, None),
        ([], None),
        (None, None),
    ],
)
def test_setup_from_api(body: object, expected: CodeQualitySetup | None) -> None:
    assert CodeQualitySetup.from_api(body) == expected


_LAST = {"hasNextPage": False}


@pytest.mark.parametrize(
    ("connection", "expected"),
    [
        (
            {"pageInfo": _LAST, "nodes": [{"name": "Python"}, {"name": "Shell"}]},
            ("Python", "Shell"),
        ),
        ({"pageInfo": _LAST, "nodes": []}, ()),
        # A null or nameless node is skipped; the rest still count.
        (
            {"pageInfo": _LAST, "nodes": [None, {"name": 3}, {"name": "Go"}]},
            ("Go",),
        ),
        # No connection at all is unknown, not "no languages".
        (None, None),
        ({"pageInfo": _LAST, "nodes": None}, None),
        # A truncated list is unknown: Python sits past the window here, and
        # reading only the first page would call the repository out of scope.
        (
            {"pageInfo": {"hasNextPage": True}, "nodes": [{"name": "Shell"}]},
            None,
        ),
        # Without page information the list cannot be shown to be complete.
        ({"nodes": [{"name": "Python"}]}, None),
        ({"pageInfo": None, "nodes": [{"name": "Python"}]}, None),
    ],
)
def test_linguist_names(connection: object, expected: tuple[str, ...] | None) -> None:
    assert linguist_names(connection) == expected
