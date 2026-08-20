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

The severity signal tables (CodeQL, Scorecard, zizmor, aislop, Dependabot
alerts, secret scanning) honour the same configuration key, but resolve their
terms against a **fixed domain vocabulary** rather than a column list -- see
:func:`signal_sort_columns`. Their rows are :class:`models.RepoSignal` objects
whose rendered columns vary by surface and by data (Slack abbreviates the
headers and drops Total, and the Informational column appears only when
populated), so resolving against a renderer's column list would make the
ordering depend on which surface asked. Omitting ``sort`` keeps
:func:`models.rank_offenders`, whose default encodes domain logic a column sort
cannot express -- notably Scorecard's cascade through the worst populated
severity rung, which stops a lone Critical being buried by a weaker repository
with a lower score.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass

from github_security_report.config import ReportConfig
from github_security_report.models import RepoSignal, SignalType
from github_security_report.report import (
    OrgReport,
    SignalSection,
    TableRow,
    TableSection,
)

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class SortTerm:
    """One resolved ordering term: which column, direction, and value type."""

    index: int  # index into ``TableSection.columns``; 0 is the repository
    descending: bool
    numeric: bool


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


def _column_value(row: TableRow, index: int) -> float | str | None:
    """The value column ``index`` sorts on for one row.

    Prefers the builder's typed sort value, falling back to the displayed cell
    when a builder published none -- so a table that never opted in still orders
    predictably (alphabetically by its text) rather than raising. ``None`` means
    the builder published no value for this cell.
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
    """Whether a column sorts numerically.

    Prefers the builder's declaration, so the same configuration resolves the
    same way for every report: judging from the rows alone would call an empty
    table's count column text, and flip its documented default direction.
    Falls back to inspecting values for a table that declares nothing.
    """
    if section.numeric_columns:
        return index in section.numeric_columns
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
        numeric = _is_numeric(section, index)
        descending = forced if forced is not None else numeric
        terms.append(SortTerm(index=index, descending=descending, numeric=numeric))
    return terms


def _missing_last_key(
    value: float | str | None, *, descending: bool, numeric: bool
) -> tuple[bool, float | str]:
    """Sort key for one value, keeping missing values last in either direction.

    A missing value is not a small one: an unknown age, or a repository with no
    published Scorecard score, belongs at the bottom of the table whether the
    column is sorted largest- or smallest-first. Since the sort reverses the
    whole key, the present/absent flag is flipped with the direction so that
    reversing leaves it pointing the same way.
    """
    if value is None:
        return (not descending, 0.0 if numeric else "")
    return (descending, value)


def _sort_key(row: TableRow, term: SortTerm) -> tuple[bool, float | str]:
    """Sort key for one row under one term, keeping missing values last."""
    return _missing_last_key(
        _column_value(row, term.index),
        descending=term.descending,
        numeric=term.numeric,
    )


def _sorted_by(section: TableSection, terms: Sequence[SortTerm]) -> list[TableRow]:
    """A table's rows ordered by resolved ``terms``, most significant first.

    Applies the terms least-significant first onto Python's stable sort, which
    keeps multi-column ordering correct while letting a text column descend --
    something a single composite key cannot express, since a string has no
    negation.
    """
    rows = sorted(section.rows, key=lambda row: row.repo.name)
    for term in reversed(terms):
        rows.sort(
            key=lambda row, term=term: _sort_key(row, term),  # type: ignore[misc]
            reverse=term.descending,
        )
    return rows


def sort_rows(section: TableSection, order: Sequence[str]) -> list[TableRow]:
    """A table's rows ordered by the configured ``order`` column names."""
    terms = resolve_terms(section, order)
    if not terms:
        return list(section.rows)
    return _sorted_by(section, terms)


def _order_note(named: Sequence[tuple[str, bool]]) -> str:
    """A sentence naming the ordering that was actually applied.

    Category descriptions state the ordering their builder chose, so a table
    reordered by configuration would otherwise describe an order it is no
    longer using -- on every surface, including ``report.json``. Takes resolved
    ``(column name, descending)`` pairs so the generic and signal tables word
    the override identically.
    """
    listed = ", then ".join(
        f"{name} ({'descending' if descending else 'ascending'})"
        for name, descending in named
    )
    return (
        f" That default order is overridden here by configuration: {listed}, "
        "with the repository name as the final tiebreaker."
    )


def apply_configured_order(
    sections: Iterable[TableSection | None], report_cfg: ReportConfig
) -> None:
    """Reorder each table in place using its category's configured ordering.

    A category with no ``sort`` keeps the ordering its builder chose, which
    matters because some defaults rank on values that are not displayed columns
    at all (Releases ranks on missing release/tag signals) and so cannot be
    expressed as a column list.

    The description is amended alongside the rows: it states the builder's
    ordering, which would otherwise be a claim the report no longer honours.
    """
    for section in sections:
        if section is None:
            continue
        order = report_cfg.category_sort(section.category.key)
        if not order:
            continue
        terms = resolve_terms(section, order)
        if not terms:
            continue
        section.rows = _sorted_by(section, terms)
        section.description = section.resolved_description() + _order_note(
            [(section.columns[term.index], term.descending) for term in terms]
        )


def report_tables(report: OrgReport) -> list[TableSection | None]:
    """Every generic table attached to an org report, in render order."""
    return [
        *report.dependabot_tables,
        report.releases,
        report.mutable_releases,
        report.private_vulnerability_reporting,
        report.issues,
    ]


# --------------------------------------------------------------------------- #
# Severity signal tables
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class SignalColumn:
    """One sortable value on a severity signal table row.

    ``descending`` is the direction a bare (unprefixed) name selects: the one
    that puts the rows most needing attention at the top. That is descending for
    a finding count (most findings first), but *ascending* for Scorecard's
    score, where a lower score is the weaker repository, and for the repository
    name (A-Z). The rule is "worst first", which for a health rating runs the
    opposite way to a count -- so ``sort: ["score"]`` and the default ranking
    agree rather than contradicting each other.
    """

    value: Callable[[RepoSignal], float | str | None]
    numeric: bool
    descending: bool


def _count_column(attribute: str) -> SignalColumn:
    """A severity-count column reading one attribute of ``RepoSignal.counts``."""
    return SignalColumn(
        value=lambda sig, attribute=attribute: float(  # type: ignore[misc]
            getattr(sig.counts, attribute)
        ),
        numeric=True,
        descending=True,
    )


_REPOSITORY_COLUMN = SignalColumn(
    value=lambda sig: sig.repo.name, numeric=False, descending=False
)
# A repository with no published Scorecard score renders an em dash, and sorts
# as missing (last) rather than as a zero -- unknown health is not bad health.
_SCORE_COLUMN = SignalColumn(
    value=lambda sig: sig.score, numeric=True, descending=False
)

_SEVERITY_SIGNAL_COLUMNS: dict[str, SignalColumn] = {
    "repository": _REPOSITORY_COLUMN,
    "critical": _count_column("critical"),
    "high": _count_column("high"),
    "medium": _count_column("medium"),
    "low": _count_column("low"),
    "info": _count_column("informational"),
    "total": _count_column("total"),
}

# Secret scanning carries no severity breakdown: its single count is headed
# "Open" on every surface.
_SECRET_SCANNING_COLUMNS: dict[str, SignalColumn] = {
    "repository": _REPOSITORY_COLUMN,
    "open": _count_column("total"),
}

# Accepted spellings that fall back to a canonical column name, consulted only
# when the configured name is not already canonical for that signal. This lets
# ``total`` name secret scanning's count (which report.json publishes as a
# total) without displacing the real Total column on every other table, and
# accepts the severity's full name for the column rendered as "Info".
_SIGNAL_ALIASES: dict[str, str] = {"informational": "info", "total": "open"}


def signal_sort_columns(signal: SignalType) -> dict[str, SignalColumn]:
    """The sort vocabulary for one signal's offender table.

    Keyed by the column heading a reader sees, lowercased. Deliberately a
    property of the *signal* rather than of a rendered table: the headings vary
    by surface (Slack abbreviates them to ``C``/``H``/``M``/``L`` and drops
    Total) and the Informational column appears only when some repository
    carries note-level findings, so resolving against a rendered column list
    would make the same configuration mean different things on different
    surfaces, or change meaning as the data changed.
    """
    if signal is SignalType.SECRET_SCANNING:
        return _SECRET_SCANNING_COLUMNS
    if signal is SignalType.SCORECARD:
        return {**_SEVERITY_SIGNAL_COLUMNS, "score": _SCORE_COLUMN}
    return _SEVERITY_SIGNAL_COLUMNS


@dataclass(frozen=True)
class SignalSortTerm:
    """One resolved ordering term for a severity signal table."""

    name: str  # the canonical column name, lowercased
    column: SignalColumn
    descending: bool


def resolve_signal_terms(
    signal: SignalType, order: Sequence[str]
) -> list[SignalSortTerm]:
    """Resolve configured column names against a signal's sort vocabulary.

    Matching is case-insensitive, mirroring the generic tables, and an unknown
    name is reported and skipped rather than raising: a typo should not silently
    reorder the report, but neither should it fail a run that is otherwise fine.
    """
    columns = signal_sort_columns(signal)
    terms: list[SignalSortTerm] = []
    for spec in order:
        name, forced = _split_direction(spec)
        folded = name.casefold()
        if folded not in columns:
            folded = _SIGNAL_ALIASES.get(folded, folded)
        column = columns.get(folded)
        if column is None:
            log.warning(
                "ignoring unknown sort column %r for the %s table; available "
                "columns are: %s",
                name,
                signal.heading,
                ", ".join(columns),
            )
            continue
        descending = forced if forced is not None else column.descending
        terms.append(SignalSortTerm(folded, column, descending))
    return terms


def _signal_sorted_by(
    offenders: Sequence[RepoSignal], terms: Sequence[SignalSortTerm]
) -> list[RepoSignal]:
    """Offenders ordered by resolved ``terms``, most significant first.

    Applies the terms least-significant first onto Python's stable sort, over a
    name-ordered base, exactly as :func:`_sorted_by` does for the generic
    tables -- so the repository name remains the final tiebreaker and a text
    column can still descend.
    """
    rows = sorted(offenders, key=lambda sig: sig.repo.name)
    for term in reversed(terms):
        rows.sort(
            key=lambda sig, term=term: _missing_last_key(  # type: ignore[misc]
                term.column.value(sig),
                descending=term.descending,
                numeric=term.column.numeric,
            ),
            reverse=term.descending,
        )
    return rows


def sort_offenders(
    signal: SignalType, offenders: Sequence[RepoSignal], order: Sequence[str]
) -> list[RepoSignal]:
    """A signal's offender rows ordered by the configured ``order`` names."""
    terms = resolve_signal_terms(signal, order)
    if not terms:
        return list(offenders)
    return _signal_sorted_by(offenders, terms)


def apply_configured_signal_order(
    sections: Iterable[SignalSection], report_cfg: ReportConfig
) -> None:
    """Reorder each signal's offenders in place using its configured ordering.

    A signal with no ``sort`` keeps :func:`models.rank_offenders`, whose default
    is not expressible as a column list: Scorecard cascades through the worst
    severity rung any offender actually carries, which is a property of the
    table as a whole rather than of any one row.

    The description is amended alongside the rows, because the severity
    categories' descriptions state their ranking ("Ranked by the worst severity
    rung present in the table ...") -- a claim the report would otherwise no
    longer honour on the Markdown and HTML surfaces.
    """
    for section in sections:
        order = report_cfg.category_sort(section.signal.category_key)
        if not order:
            continue
        terms = resolve_signal_terms(section.signal, order)
        if not terms:
            continue
        section.offenders = _signal_sorted_by(section.offenders, terms)
        section.description = section.resolved_description() + _order_note(
            [(term.name.title(), term.descending) for term in terms]
        )
