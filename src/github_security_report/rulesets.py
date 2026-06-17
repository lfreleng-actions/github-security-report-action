# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Org repository-ruleset coverage for workflow-driven tools.

Some tools (e.g. zizmor) are not enabled per-repository; they are enforced
across the estate by an **organisation repository ruleset** containing a
``workflows`` rule that requires a central workflow on every pull request. Such
a repo runs the tool even though it has no matching ``.github/workflows`` file
of its own, so the per-repo enabled-probe would wrongly nag it.

This module reads the authoritative ruleset definitions and computes, for a
given repository, which signals are covered. A signal is mapped to a ruleset by
a case-insensitive keyword match against the required-workflow path (e.g. the
``zizmor`` signal matches ``.github/workflows/zizmor.yaml``). See the
``GET /orgs/{org}/rulesets`` and ``GET /repos/{o}/{r}/rules/branches/{branch}``
GitHub APIs.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass

# Patterns GitHub uses to mean "every repository".
_MATCH_ALL = {"*", "~all"}


@dataclass(frozen=True)
class WorkflowRuleset:
    """An active org ruleset that requires one or more workflows."""

    name: str
    workflow_paths: tuple[str, ...]
    include: tuple[str, ...]  # repository_name include patterns
    exclude: tuple[str, ...]  # repository_name exclude patterns


def parse_workflow_rulesets(details: list[dict]) -> list[WorkflowRuleset]:
    """Extract active, branch-targeted rulesets that require workflows."""
    out: list[WorkflowRuleset] = []
    for ruleset in details:
        if ruleset.get("enforcement") != "active":
            continue
        if ruleset.get("target") not in (None, "branch"):
            continue
        paths: list[str] = []
        for rule in ruleset.get("rules") or []:
            if rule.get("type") != "workflows":
                continue
            for wf in (rule.get("parameters") or {}).get("workflows") or []:
                path = wf.get("path")
                if path:
                    paths.append(path)
        if not paths:
            continue
        cond = (ruleset.get("conditions") or {}).get("repository_name") or {}
        out.append(
            WorkflowRuleset(
                name=ruleset.get("name", ""),
                workflow_paths=tuple(paths),
                include=tuple(cond.get("include", [])),
                exclude=tuple(cond.get("exclude", [])),
            )
        )
    return out


def _name_matches(name: str, patterns: tuple[str, ...]) -> bool:
    candidate = name.lower()
    for pattern in patterns:
        lowered = pattern.lower()
        if lowered in _MATCH_ALL or fnmatch.fnmatch(candidate, lowered):
            return True
    return False


def repo_covered(name: str, ruleset: WorkflowRuleset) -> bool:
    """Whether a repository name is targeted by the ruleset's conditions."""
    return _name_matches(name, ruleset.include) and not _name_matches(
        name, ruleset.exclude
    )


def _paths_match_keyword(paths: tuple[str, ...] | list[str], keyword: str) -> bool:
    kw = keyword.lower()
    return any(kw in path.lower() for path in paths)


def signals_covered(
    name: str,
    rulesets: list[WorkflowRuleset],
    signal_keywords: dict[str, str],
) -> set[str]:
    """Signals (by value) that an org ruleset enforces for this repository.

    ``signal_keywords`` maps a signal value (e.g. ``"zizmor"``) to a keyword
    that must appear in a required-workflow path.
    """
    covered: set[str] = set()
    for signal, keyword in signal_keywords.items():
        for ruleset in rulesets:
            if _paths_match_keyword(ruleset.workflow_paths, keyword) and repo_covered(
                name, ruleset
            ):
                covered.add(signal)
                break
    return covered


def signals_from_branch_rules(
    rules: list[dict],
    signal_keywords: dict[str, str],
) -> set[str]:
    """Signals covered for a single repo, from its effective branch rules.

    Used in repo mode: ``GET /repos/{o}/{r}/rules/branches/{branch}`` already
    returns the rules in effect for this repository (including inherited org
    rulesets), so no name matching is needed.
    """
    paths: list[str] = []
    for rule in rules:
        if rule.get("type") != "workflows":
            continue
        for wf in (rule.get("parameters") or {}).get("workflows") or []:
            path = wf.get("path")
            if path:
                paths.append(path)
    return {
        signal
        for signal, keyword in signal_keywords.items()
        if _paths_match_keyword(paths, keyword)
    }
