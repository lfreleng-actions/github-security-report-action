# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Tests for configured row ordering of the generic report tables."""

from __future__ import annotations

import logging

import pytest

from github_security_report import config, ordering
from github_security_report.categories import CategoryKey, category_meta
from github_security_report.models import Repo
from github_security_report.report import TableRow, TableSection


def _repo(name: str) -> Repo:
    return Repo(name, f"o/{name}", f"https://github.com/o/{name}")


def _row(name: str, untriaged: float, total: float, oldest: float | None) -> TableRow:
    return TableRow(
        repo=_repo(name),
        cells=(
            str(int(untriaged)),
            str(int(total)),
            "unknown" if oldest is None else f"{int(oldest)} days",
        ),
        sort_values=(untriaged, total, oldest),
    )


def _section(*rows: TableRow) -> TableSection:
    return TableSection(
        category=category_meta(CategoryKey.GITHUB_ISSUES),
        columns=("Repository", "Untriaged", "Total", "Oldest"),
        rows=list(rows),
    )


def _names(section: TableSection, order: list[str]) -> list[str]:
    return [row.repo.name for row in ordering.sort_rows(section, order)]


class TestSortRows:
    def _missing_sample(self) -> TableSection:
        return _section(
            _row("alpha", untriaged=1, total=9, oldest=5),
            _row("bravo", untriaged=5, total=5, oldest=None),
            _row("charlie", untriaged=3, total=7, oldest=0),
        )

    def test_missing_value_sorts_last_descending(self) -> None:
        assert _names(self._missing_sample(), ["oldest"]) == [
            "alpha",
            "charlie",
            "bravo",
        ]

    def test_missing_value_sorts_last_ascending_too(self) -> None:
        # "unknown" is not the youngest age: reversing the direction must not
        # promote a row whose value was never known above one that has a value.
        assert _names(self._missing_sample(), ["+oldest"]) == [
            "charlie",
            "alpha",
            "bravo",
        ]

    def _sample(self) -> TableSection:
        return _section(
            _row("alpha", untriaged=1, total=9, oldest=5),
            _row("bravo", untriaged=5, total=5, oldest=50),
            _row("charlie", untriaged=1, total=2, oldest=99),
        )

    def test_numeric_column_descends_by_default(self) -> None:
        # "Most first" is the implicit direction for a count column.
        assert _names(self._sample(), ["untriaged"]) == ["bravo", "alpha", "charlie"]

    def test_age_column_puts_oldest_first_by_default(self) -> None:
        assert _names(self._sample(), ["oldest"]) == ["charlie", "bravo", "alpha"]

    def test_terms_apply_left_to_right(self) -> None:
        # alpha and charlie tie on untriaged, so Total breaks the tie.
        assert _names(self._sample(), ["untriaged", "total"]) == [
            "bravo",
            "alpha",
            "charlie",
        ]

    def test_minus_forces_descending(self) -> None:
        assert _names(self._sample(), ["-total"]) == ["alpha", "bravo", "charlie"]

    def test_plus_forces_ascending(self) -> None:
        assert _names(self._sample(), ["+total"]) == ["charlie", "bravo", "alpha"]

    def test_plus_overrides_numeric_default(self) -> None:
        # Untriaged would descend by default; '+' flips it.
        assert _names(self._sample(), ["+untriaged"]) == ["alpha", "charlie", "bravo"]

    def test_column_match_is_case_insensitive(self) -> None:
        assert _names(self._sample(), ["UNTRIAGED"]) == _names(
            self._sample(), ["untriaged"]
        )

    def test_repository_column_is_sortable(self) -> None:
        assert _names(self._sample(), ["repository"]) == ["alpha", "bravo", "charlie"]
        assert _names(self._sample(), ["-repository"]) == ["charlie", "bravo", "alpha"]

    def test_name_is_the_final_tiebreaker(self) -> None:
        section = _section(
            _row("zulu", untriaged=1, total=1, oldest=1),
            _row("alpha", untriaged=1, total=1, oldest=1),
        )
        # Every configured term ties, so ordering stays deterministic by name.
        assert _names(section, ["untriaged"]) == ["alpha", "zulu"]

    def test_empty_order_keeps_builder_ordering(self) -> None:
        section = self._sample()
        assert _names(section, []) == [r.repo.name for r in section.rows]

    def test_unknown_column_is_warned_and_skipped(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        section = self._sample()
        with caplog.at_level(logging.WARNING, logger="github_security_report.ordering"):
            result = _names(section, ["bogus", "untriaged"])
        # The typo is dropped; the valid term still applies.
        assert result == ["bravo", "alpha", "charlie"]
        assert any("bogus" in r.getMessage() for r in caplog.records)

    def test_all_terms_unknown_keeps_builder_ordering(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        section = self._sample()
        with caplog.at_level(logging.WARNING, logger="github_security_report.ordering"):
            assert _names(section, ["nope"]) == [r.repo.name for r in section.rows]

    def test_text_column_ascends_by_default_and_can_descend(self) -> None:
        section = TableSection(
            category=category_meta(CategoryKey.MUTABLE_RELEASES),
            columns=("Repository", "Releases"),
            rows=[
                TableRow(repo=_repo("a"), cells=("v2",), sort_values=("v2",)),
                TableRow(repo=_repo("b"), cells=("v1",), sort_values=("v1",)),
            ],
        )
        assert _names(section, ["releases"]) == ["b", "a"]
        # A string cannot be negated into a composite key, so this exercises the
        # stable-sort path rather than a key negation.
        assert _names(section, ["-releases"]) == ["a", "b"]

    def test_falls_back_to_cell_text_without_sort_values(self) -> None:
        section = TableSection(
            category=category_meta(CategoryKey.DEPENDABOT_COOLDOWN),
            columns=("Repository", "Ecosystems"),
            rows=[
                TableRow(repo=_repo("a"), cells=("pip",)),
                TableRow(repo=_repo("b"), cells=("npm",)),
            ],
        )
        assert _names(section, ["ecosystems"]) == ["b", "a"]


class TestApplyConfiguredOrder:
    def _cfg(self, sort: list[str]) -> config.ReportConfig:
        return (
            config.build_config(
                {
                    "report": {"categories": {"github_issues": {"sort": sort}}},
                    "organizations": [{"name": "o"}],
                }
            )
            .organizations[0]
            .report
        )

    def test_declared_numeric_column_keeps_its_direction_when_empty(self) -> None:
        # A count column is numeric by schema, not by whatever rows a given run
        # produced: an all-clean report has no rows, and inferring the type from
        # them would silently flip the documented default direction.
        empty = TableSection(
            category=category_meta(CategoryKey.GITHUB_ISSUES),
            columns=("Repository", "Untriaged", "Total", "Oldest"),
            rows=[],
            numeric_columns=frozenset({1, 2, 3}),
        )
        terms = ordering.resolve_terms(empty, ["untriaged"])
        assert terms[0].descending is True
        assert terms[0].numeric is True

    def test_undeclared_column_still_falls_back_to_values(self) -> None:
        # Tables that publish no schema keep the original behaviour.
        section = _section(_row("alpha", untriaged=1, total=9, oldest=5))
        assert ordering.resolve_terms(section, ["untriaged"])[0].descending is True

    def test_applies_configured_order_in_place(self) -> None:
        section = _section(
            _row("alpha", untriaged=1, total=9, oldest=5),
            _row("bravo", untriaged=5, total=5, oldest=50),
        )
        ordering.apply_configured_order([section], self._cfg(["untriaged"]))
        assert [r.repo.name for r in section.rows] == ["bravo", "alpha"]

    def test_unconfigured_category_is_untouched(self) -> None:
        section = _section(
            _row("alpha", untriaged=1, total=9, oldest=5),
            _row("bravo", untriaged=5, total=5, oldest=50),
        )
        before = [r.repo.name for r in section.rows]
        ordering.apply_configured_order([section], config.ReportConfig())
        assert [r.repo.name for r in section.rows] == before

    def test_configured_order_is_described(self) -> None:
        # A category description states the order its builder chose, so an
        # override must be reported or the table describes an order it is not
        # using -- on every surface, including report.json.
        section = _section(
            _row("alpha", untriaged=1, total=9, oldest=5),
            _row("bravo", untriaged=5, total=5, oldest=50),
        )
        ordering.apply_configured_order([section], self._cfg(["untriaged", "+total"]))
        described = section.resolved_description()
        assert "overridden" in described
        assert "Untriaged (descending)" in described
        assert "Total (ascending)" in described

    def test_unconfigured_category_description_is_untouched(self) -> None:
        section = _section(_row("alpha", untriaged=1, total=9, oldest=5))
        before = section.resolved_description()
        ordering.apply_configured_order([section], config.ReportConfig())
        assert section.resolved_description() == before

    def test_unknown_only_order_leaves_the_description_alone(self) -> None:
        # Every term was skipped, so the builder's order still stands and
        # claiming an override would be wrong.
        section = _section(_row("alpha", untriaged=1, total=9, oldest=5))
        before = section.resolved_description()
        ordering.apply_configured_order([section], self._cfg(["nonesuch"]))
        assert section.resolved_description() == before

    def test_none_sections_are_skipped(self) -> None:
        # Repo mode leaves the extra tables unset; that must not raise.
        ordering.apply_configured_order([None], self._cfg(["untriaged"]))
