# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Open pull requests per repository, split by author and by what blocks them.

A reporting category outside the four-state per-signal model, and a sibling of
:mod:`issues`: a plain table counting each repository's open pull requests
across two independent groupings.

**Who raised it.** ``Human`` and ``Auto`` partition the counted pull requests:
``Auto`` is recognised automation (Dependabot, pre-commit.ci, Renovate and any
other bot actor -- see :mod:`authors`), ``Human`` is everyone else. ``Ext``
counts the human pull requests raised from outside the organisation, so it is a
**subset of Human**, never a bot. Counting automation as external would be
literally true by GitHub's association (``dependabot[bot]`` reports
``CONTRIBUTOR`` or ``NONE``) and useless in practice: it would bury genuine
outside contributions under routine dependency updates.

**What is holding it up.** ``Conflict``, ``Fail``, ``Copilot`` and ``Draft``
are independent of the author split and of each other, so one pull request can
be counted in several of them. They therefore do not sum to the total, and are
not meant to. ``Copilot`` counts the pull requests carrying unresolved review
feedback from GitHub's automated code reviewer.

The same bounded-window caveat as the issues table applies: ``Total`` is exact
at any size because it comes from ``totalCount``, while the breakdown columns
only see the collected window, so they can sum to less than ``Total``. A row
whose window truncated is marked, so a partial breakdown is visible as such.

**Who is expected to move it.** Aggregate rows beneath the totals split the
same pull requests by assignment. Only ``Unassigned`` is a property of the pull
request itself; ``Mine`` and ``Others`` are read relative to the account the
report authenticated as, and so are confined twice over -- to runs that
authenticated as a person, and to the surface that person reads.

The implementation is split across ``columns`` (the table's schema),
``counting`` (placing each pull request in the column and assignment buckets),
``presentation`` (cell wording, emphasis and the description's caveats) and
``table`` (the builder and the two public entry points). This module re-exports
the public surface, so importing from ``github_security_report.pulls`` is
unchanged.
"""

from __future__ import annotations

# Re-exported for their own sake rather than used here: each was resolvable on
# the flat module this package replaces. The ``X as X`` form marks them as
# deliberate re-exports rather than imports nothing uses.
from collections.abc import Callable as Callable
from collections.abc import Mapping as Mapping
from collections.abc import Set as Set

from github_security_report.authors import is_automation_author as is_automation_author
from github_security_report.authors import is_external_author as is_external_author
from github_security_report.categories import CategoryKey as CategoryKey
from github_security_report.categories import category_meta as category_meta
from github_security_report.models import PullRequestRef as PullRequestRef
from github_security_report.models import Repo as Repo
from github_security_report.models import RepoGraphData as RepoGraphData
from github_security_report.pulls.columns import (
    ALL_COLUMNS,
    ASSIGNMENT_ROWS,
    AUTOMATION_COLUMN,
    BREAKDOWN_COLUMNS,
    CONFLICT_COLUMN,
    COPILOT_COLUMN,
    DRAFT_COLUMN,
    EXTERNAL_COLUMN,
    FAILING_COLUMN,
    HUMAN_COLUMN,
    MINE_ROW,
    OTHERS_ROW,
    PERSONAL_ASSIGNMENT_ROWS,
    REPOSITORY_COLUMN,
    TOTAL_COLUMN,
    TRUNCATED_MARKER,
    UNASSIGNED_ROW,
)
from github_security_report.pulls.counting import (
    _blocked_count,
    _is_automation,
    _is_external,
    assignment_counts,
    assignment_rows,
    copilot_indeterminate,
    count_pull_requests,
    is_mine,
)
from github_security_report.pulls.presentation import (
    _cell_levels,
    _describe,
    _total_cell,
    automation_level,
)
from github_security_report.pulls.table import (
    _build_table,
    build_assigned_pull_requests_table,
    build_pull_requests_table,
)
from github_security_report.report import (
    CELL_BAD,
    CELL_GOOD,
    CELL_WARN,
    TableRow,
    TableSection,
)

# The flat module declared no ``__all__``, so ``import *`` exported exactly its
# non-underscore top-level names. Splitting it into a package binds the four
# submodules here too, which would silently widen that surface, so the former
# surface is pinned explicitly. Private names stay importable by name, as
# before; they were never part of the star export.
__all__ = [
    "ALL_COLUMNS",
    "ASSIGNMENT_ROWS",
    "AUTOMATION_COLUMN",
    "BREAKDOWN_COLUMNS",
    "CELL_BAD",
    "CELL_GOOD",
    "CELL_WARN",
    "CONFLICT_COLUMN",
    "COPILOT_COLUMN",
    "Callable",
    "CategoryKey",
    "DRAFT_COLUMN",
    "EXTERNAL_COLUMN",
    "FAILING_COLUMN",
    "HUMAN_COLUMN",
    "MINE_ROW",
    "Mapping",
    "OTHERS_ROW",
    "PERSONAL_ASSIGNMENT_ROWS",
    "PullRequestRef",
    "REPOSITORY_COLUMN",
    "Repo",
    "RepoGraphData",
    "Set",
    "TOTAL_COLUMN",
    "TRUNCATED_MARKER",
    "TableRow",
    "TableSection",
    "UNASSIGNED_ROW",
    "annotations",
    "assignment_counts",
    "assignment_rows",
    "automation_level",
    "build_assigned_pull_requests_table",
    "build_pull_requests_table",
    "category_meta",
    "copilot_indeterminate",
    "count_pull_requests",
    "is_automation_author",
    "is_external_author",
    "is_mine",
]
