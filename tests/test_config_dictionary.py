# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Tests for the configuration key dictionary generated from the schema."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from typing import Any

from github_security_report.config import CONFIG_SCHEMA
from github_security_report.config.dictionary import (
    KeyEntry,
    config_keys,
    dotted,
    key_homes,
    keys_under,
    note_path,
)
from github_security_report.config.key_notes import DEPRECATED, NOTES, REMOVED


def _schema_leaves(schema: Mapping[str, Any], prefix: str = "") -> list[str]:
    """Every leaf key path in ``schema``, walked independently of the module."""
    if schema.get("type") == "array" and "properties" in schema.get("items", {}):
        prefix += "[]"
        schema = schema["items"]
    properties = schema.get("properties")
    if not properties or "$ref" in schema:
        return [prefix]
    leaves: list[str] = []
    for key, child in properties.items():
        leaves += _schema_leaves(child, f"{prefix}.{key}" if prefix else key)
    return leaves


def _entry(path: str) -> KeyEntry:
    (entry,) = [entry for entry in config_keys() if entry.path == path]
    return entry


class TestCoverage:
    def test_every_schema_leaf_appears_exactly_once(self) -> None:
        listed = Counter(entry.path for entry in config_keys())
        leaves = _schema_leaves(CONFIG_SCHEMA)
        assert set(listed) == set(leaves)
        assert all(count == 1 for count in listed.values())

    def test_every_key_is_described(self) -> None:
        undescribed = [entry.path for entry in config_keys() if not entry.description]
        assert undescribed == []

    def test_every_note_names_a_schema_key(self) -> None:
        described = {note_path(entry.path.split(".")) for entry in config_keys()}
        assert set(NOTES) - described == set()

    def test_status_tables_name_known_or_unschema_keys(self) -> None:
        paths = {note_path(entry.path.split(".")) for entry in config_keys()}
        assert set(DEPRECATED) <= paths
        assert not set(REMOVED) & paths


class TestEntries:
    def test_type_and_default_come_from_schema_and_models(self) -> None:
        entry = _entry("report.concurrency")
        assert entry.kind == "integer 1-32"
        assert entry.default == "9"

    def test_enum_lists_allowed_values(self) -> None:
        entry = _entry("report.excluded_display")
        assert entry.kind == "one of: always-show, always-hide, conditional-hide"

    def test_category_defaults_follow_the_category(self) -> None:
        assert _entry("report.categories.codeql.outputs.slack").default == "true"
        assigned = "report.categories.pull_requests_assigned.outputs.slack"
        assert _entry(assigned).default == "false"
        detail = "report.categories.workflow_failures_detail.enabled"
        assert _entry(detail).default == "false"

    def test_inherited_default_is_named(self) -> None:
        assert _entry("report.top_n_cli").default == "report.top_n"

    def test_deprecated_key_names_its_replacement(self) -> None:
        entry = _entry("report.release_min_age_days")
        assert entry.status == "deprecated"
        assert entry.replacement == "report.repo_min_age_days"
        assert _entry("report.top_n").status == "current"


class TestLookup:
    def test_prefix_selects_a_block(self) -> None:
        paths = [entry.path for entry in keys_under("report.categories.code_quality")]
        assert "report.categories.code_quality.exclude" in paths
        assert all(path.startswith("report.categories.code_quality.") for path in paths)

    def test_prefix_does_not_match_a_longer_sibling(self) -> None:
        paths = [entry.path for entry in keys_under("report.top_n")]
        assert paths == ["report.top_n"]

    def test_empty_prefix_lists_everything(self) -> None:
        assert keys_under("") == config_keys()

    def test_key_homes_name_every_block_accepting_a_key(self) -> None:
        assert key_homes()["top_n"] == ("report", "report.categories.<category>")

    def test_dotted_renders_list_indexes(self) -> None:
        assert dotted(["organizations", 0, "report", "top_n"]) == (
            "organizations[0].report.top_n"
        )

    def test_note_path_folds_org_overrides_and_categories(self) -> None:
        parts = ["organizations[]", "report", "categories", "codeql", "top_n"]
        assert note_path(parts) == "report.categories.<category>.top_n"
