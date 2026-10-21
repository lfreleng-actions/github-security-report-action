# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""The GitHub Code Quality table: enablement, scoped by language (ADR-0006).

Unlike the other enablement checks, Code Quality only means something for a
repository written in a language it analyses, so each repository is classified
before it is counted. Disabled and Partial repositories are the rows; Enabled,
Unreadable and Not applicable are footer counts, and a footer note gives the
enabled-of-applicable count per language on every surface.
"""

from __future__ import annotations

from github_security_report.categories import CategoryKey, category_meta
from github_security_report.code_quality import (
    CODE_QUALITY_LANGUAGES,
    CodeQualityStatus,
    code_quality_status,
    ordered,
)
from github_security_report.posture.facts import RepoPosture
from github_security_report.report import TableRow, TableSection


def _breakdown(enabled: dict[str, int], applicable: dict[str, int]) -> str:
    """``python 30/32 · go 5/5`` for each language with an applicable repo."""
    return " \u00b7 ".join(
        f"{lang} {enabled.get(lang, 0)}/{applicable[lang]}"
        for lang in CODE_QUALITY_LANGUAGES
        if applicable.get(lang)
    )


def build_code_quality_table(postures: list[RepoPosture]) -> TableSection:
    """Repositories where Code Quality is Disabled or Partial.

    ``Languages`` lists the repository's applicable languages and ``Missing``
    those its setup does not analyse yet; on a Disabled repository that is all
    of them. A repository counts under every applicable language it holds, as
    enabled under each its setup configures, whatever its status; one whose
    languages could not be read counts under none.
    """
    rows: list[TableRow] = []
    counts = dict.fromkeys(CodeQualityStatus, 0)
    enabled: dict[str, int] = {}
    applicable: dict[str, int] = {}
    for p in sorted(postures, key=lambda p: p.repo.name):
        languages = p.code_quality_languages
        status = code_quality_status(languages, p.code_quality)
        counts[status] += 1
        if not languages:
            continue
        configured = (
            p.code_quality.languages
            if p.code_quality is not None and p.code_quality.configured
            else frozenset()
        )
        for lang in languages:
            applicable[lang] = applicable.get(lang, 0) + 1
            if lang in configured:
                enabled[lang] = enabled.get(lang, 0) + 1
        if status.offending:
            names = ", ".join(ordered(languages))
            missing = ", ".join(ordered(languages - configured))
            rows.append(
                TableRow(
                    repo=p.repo,
                    cells=(status.value, names, missing),
                    sort_values=(status.value, names, missing),
                )
            )
    breakdown = _breakdown(enabled, applicable)
    return TableSection(
        category=category_meta(CategoryKey.CODE_QUALITY),
        columns=("Repository", "Status", "Languages", "Missing"),
        rows=rows,
        pass_count=counts[CodeQualityStatus.ENABLED],
        fail_count=len(rows),
        unknown_count=counts[CodeQualityStatus.UNREADABLE],
        not_applicable_count=counts[CodeQualityStatus.NOT_APPLICABLE],
        notes=(f"Enabled by language: {breakdown}",) if breakdown else (),
    )
