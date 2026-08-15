# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Configured row ordering for the generic (non-signal) report tables.

Each table builder ships a sensible default ordering -- largest backlog first,
stalest release first, and so on -- and several rank on values that are never
displayed as columns. ``report.categories.<key>.sort`` lets an operator override
that with a list of column names, evaluated left to right:

.. code-block:: json

    {"sort": ["untriaged", "-total", "+repository"]}

A bare name takes the direction implied by its type: numeric columns descend
(most first, which is also oldest-first for an age column) and text columns
ascend. A leading ``-`` forces descending and ``+`` forces ascending. The
repository name is always applied as the final tiebreaker, so two rows that are
equal under every configured term still order deterministically.

The ordering is applied once, when the report is assembled, rather than per
render surface: unlike a row limit, which legitimately differs between the
terminal and a Slack digest, a table's ordering is a property of the table and
must read the same everywhere -- including in ``report.json``.

The severity signal tables are deliberately out of scope. Their ranking
(:func:`models.rank_offenders`) encodes domain logic -- notably Scorecard's
cascade through the worst populated severity rung, which stops a lone Critical
being buried by a weaker repository with a lower score -- that a column-name sort
would flatten.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from github_security_report.config import ReportConfig
from github_security_report.report import OrgReport, TableRow, TableSection

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class SortTerm:
    """One resolved ordering term: which column, and which direction."""

    index: int  # index into ``TableSection.columns``; 0 is the repository
    descending: bool


def _split_direction(spec: str) -> tuple[str, bool | None]:
    """Split a ``+``/``-`` prefix from a column name.

    Returns the bare name and the forced direction, or ``None`` for "use the
    direction implied by the column's type".
    """
    spec = spec.strip()
    if spec.startswith("-"):
        return spec[1:].strip(), True
    if spec.startswith("+"):
        return spec[1:].strip(), False
    return spec, None


def _column_value(row: TableRow, index: int) -> float | str:
    """The value column ``index`` sorts on for one row.

    Prefers the builder's typed sort value, falling back to the displayed cell
    when a builder published none -- so a table that never opted in still orders
    predictably (alphabetically by its text) rather than raising.
    """
    if index == 0:
        return row.repo.name
    position = index - 1
    if position < len(row.sort_values):
        return row.sort_values[position]
    if position < len(row.cells):
        return row.cells[position]
    return ""


def _is_numeric(section: TableSection, index: int) -> bool:
    """Whether a column sorts numerically, judged from the rows themselves."""
    return any(
        isinstance(_column_value(row, index), (int, float)) for row in section.rows
    )


def resolve_terms(section: TableSection, order: Sequence[str]) -> list[SortTerm]:
    """Resolve configured column names against a table's actual columns.

    Matching is case-insensitive, so ``untriaged`` finds the ``Untriaged``
    column and a custom ``issue_labels`` column such as ``Regression`` works
    without further configuration. A name that matches no column is reported and
    skipped: a typo should not silently reorder the report, but neither should
    it fail a run that is otherwise fine.
    """
    lookup = {name.casefold(): index for index, name in enumerate(section.columns)}
    terms: list[SortTerm] = []
    for spec in order:
        name, forced = _split_direction(spec)
        index = lookup.get(name.casefold())
        if index is None:
            log.warning(
                "ignoring unknown sort column %r for the %s table; available "
                "columns are: %s",
                name,
                section.title,
                ", ".join(section.columns),
            )
            continue
        descending = forced if forced is not None else _is_numeric(section, index)
        terms.append(SortTerm(index=index, descending=descending))
    return terms


def sort_rows(section: TableSection, order: Sequence[str]) -> list[TableRow]:
    """A table's rows ordered by ``order``, most significant term first.

    Applies the terms least-significant first onto Python's stable sort, which
    keeps multi-column ordering correct while letting a text column descend --
    something a single composite key cannot express, since a string has no
    negation.
    """
    terms = resolve_terms(section, order)
    if not terms:
        return list(section.rows)
    rows = sorted(section.rows, key=lambda row: row.repo.name)
    for term in reversed(terms):
        rows.sort(
            key=lambda row, term=term: _column_value(row, term.index),  # type: ignore[misc]
            reverse=term.descending,
        )
    return rows


def apply_configured_order(
    sections: Iterable[TableSection | None], report_cfg: ReportConfig
) -> None:
    """Reorder each table in place using its category's configured ordering.

    A category with no ``sort`` keeps the ordering its builder chose, which
    matters because some defaults rank on values that are not displayed columns
    at all (Releases ranks on missing release/tag signals) and so cannot be
    expressed as a column list.
    """
    for section in sections:
        if section is None:
            continue
        order = report_cfg.category_sort(section.category.key)
        if not order:
            continue
        section.rows = sort_rows(section, order)


def report_tables(report: OrgReport) -> list[TableSection | None]:
    """Every generic table attached to an org report, in render order."""
    return [
        *report.dependabot_tables,
        report.releases,
        report.mutable_releases,
        report.private_vulnerability_reporting,
        report.issues,
    ]
