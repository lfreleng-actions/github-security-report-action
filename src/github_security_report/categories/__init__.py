# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Report category metadata.

A single, render-surface-agnostic registry describing every reporting category
the tool produces. Each category carries its display title, the pass/fail
vocabulary used in the standardised summary footer, a documentation URL, and a
default human description. Renderers read this registry instead of hard-coding
per-category headings, labels and explanatory text, so a wording change here
flows to the terminal, Slack, Markdown and HTML surfaces at once.

The registry deliberately holds no behaviour and imports nothing from the rest
of the package except the leaf ``severity`` and ``secret_patterns`` modules
(which themselves import nothing from the package), so both the domain models
and the renderers can depend on it without a cycle. It is split by kind --
the ranked signals in :mod:`.signals`, the tables in :mod:`.tables` -- and
merged here, so callers see one registry in render order.
"""

from __future__ import annotations

from github_security_report.categories.keys import CategoryKey, CategoryMeta
from github_security_report.categories.signals import SIGNAL_CATEGORIES
from github_security_report.categories.tables import TABLE_CATEGORIES

__all__ = [
    "NESTED_CATEGORIES",
    "REPO_LIST_CATEGORIES",
    "CategoryKey",
    "CategoryMeta",
    "all_categories",
    "category_meta",
    "orderable_categories",
]

_CATEGORIES: dict[CategoryKey, CategoryMeta] = {**SIGNAL_CATEGORIES, **TABLE_CATEGORIES}


def category_meta(key: CategoryKey) -> CategoryMeta:
    """The :class:`CategoryMeta` for ``key`` (registry lookup)."""
    return _CATEGORIES[key]


# Categories rendered as sub-tables beneath another category rather than as
# sections of their own. The three Dependabot posture tables qualify their
# parent signal -- "Alerts Enabled" means nothing adrift from "Dependabot:
# Security Alerts" -- so they travel with it and cannot be positioned
# independently, and the two CodeQL scan-health tables likewise qualify the
# CodeQL signal, whose "Clean" means nothing if the scans behind it stopped.
# Named here rather than in the layout module so the config schema can refuse to
# accept one in an ordering list, which would otherwise be a setting that
# validates and then does nothing.
NESTED_CATEGORIES: frozenset[CategoryKey] = frozenset(
    {
        CategoryKey.CODEQL_STALE_CONFIGURATIONS,
        CategoryKey.CODEQL_LANGUAGE_COVERAGE,
        CategoryKey.DEPENDABOT_ALERTS_ENABLED,
        CategoryKey.DEPENDABOT_UPDATES_ENABLED,
        CategoryKey.DEPENDABOT_COOLDOWN,
    }
)

# The boolean feature categories: every repository is either enabled or not, and
# nothing else is known about it, so both sides are plain repository lists and
# either can be the one worth naming. These render their names inline rather
# than as a one-column table, and are the only categories the ``repo_list``
# setting applies to -- the schema refuses it anywhere else, since a table with
# qualitative columns has no "enabled" list to swap in.
REPO_LIST_CATEGORIES: frozenset[CategoryKey] = frozenset(
    {
        CategoryKey.DEPENDABOT_ALERTS_ENABLED,
        CategoryKey.DEPENDABOT_UPDATES_ENABLED,
        CategoryKey.PRIVATE_VULNERABILITY_REPORTING,
        CategoryKey.AUTO_MERGE,
    }
)


def orderable_categories() -> tuple[CategoryMeta, ...]:
    """Categories an ordering list may name, in registry order.

    Every category except the nested ones, which have no position of their own
    to configure.
    """
    return tuple(
        meta for meta in _CATEGORIES.values() if meta.key not in NESTED_CATEGORIES
    )


def all_categories() -> tuple[CategoryMeta, ...]:
    """Every category's metadata, in registry (render) order."""
    return tuple(_CATEGORIES.values())
