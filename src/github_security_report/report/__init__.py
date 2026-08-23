# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Report aggregation.

Groups classified :class:`RepoSignal` results into the renderable report
structure: one section per signal, each with ranked offenders (full list -- the
top-N limit applies only to Slack), a clean count, a nag list (archived/test
repos excluded), and an unknown count. See ``docs/BRIEF.md`` sections 4-6, 11.

The implementation is split across ``signals`` (the four-state
:class:`SignalSection` and the skipped-section wording), ``tables`` (the
generic :class:`TableRow`/:class:`TableSection` model and its cell emphasis
levels), ``aggregate`` (:class:`OrgReport`, :class:`Report` and the builder
that assembles them) and ``display`` (the row limits, totals and footer rows
every render surface shares). This module re-exports the whole surface, so
importing from ``github_security_report.report`` is unchanged.
"""

from __future__ import annotations

# Re-exported for their own sake rather than used here: each was resolvable on
# the flat module this package replaces, and callers reach some of them through
# it (``report.SummaryCount``, ``report.SignalType``). The ``X as X`` form marks
# them as deliberate re-exports rather than imports nothing uses.
from collections.abc import Callable as Callable
from collections.abc import Sequence as Sequence
from collections.abc import Set as Set
from dataclasses import dataclass as dataclass
from dataclasses import field as field
from typing import TypeVar as TypeVar

from github_security_report import scope as scope
from github_security_report.categories import CategoryKey as CategoryKey
from github_security_report.categories import CategoryMeta as CategoryMeta
from github_security_report.models import Repo as Repo
from github_security_report.models import RepoSignal as RepoSignal
from github_security_report.models import RepoState as RepoState
from github_security_report.models import SeverityCounts as SeverityCounts
from github_security_report.models import SignalType as SignalType
from github_security_report.models import rank_offenders as rank_offenders
from github_security_report.report.aggregate import (
    SIGNAL_ORDER,
    OrgReport,
    Report,
    build_org_report,
)

# ``dt`` was the flat module's ``datetime`` alias, re-exported here from the
# submodule that timestamps a report.
from github_security_report.report.aggregate import dt as dt
from github_security_report.report.display import (
    _T,
    LimitFor,
    _as_int,
    limit_resolver,
    offender_column_totals,
    section_shows_informational,
    table_column_totals,
    table_footer_rows,
    truncate,
)
from github_security_report.report.signals import (
    ORG_SETUP_DOC_URL,
    SKIP_MESSAGE,
    SignalSection,
)
from github_security_report.report.tables import (
    CELL_BAD,
    CELL_GOOD,
    CELL_LEVELS,
    CELL_WARN,
    TableRow,
    TableSection,
)
from github_security_report.summary import (
    SUMMARY_EMOJI,
    SummaryCount,
    SummaryLine,
    build_summary,
)

# Re-exported so every renderer keeps importing the footer vocabulary from
# ``report`` alongside the structures it decorates.
__all__ = [
    "ORG_SETUP_DOC_URL",
    "SKIP_MESSAGE",
    "SUMMARY_EMOJI",
    "LimitFor",
    "OrgReport",
    "Report",
    "SignalSection",
    "SummaryCount",
    "SummaryLine",
    "TableRow",
    "TableSection",
    "build_org_report",
    "build_summary",
    "limit_resolver",
    "offender_column_totals",
    "section_shows_informational",
    "table_column_totals",
    "truncate",
]
