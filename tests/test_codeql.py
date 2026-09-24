# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Tests for the CodeQL scan-health facts and tables (pure, no network).

The scenarios mirror what the lfreleng-actions estate actually showed: a
repository that swapped default setup for a narrower advanced workflow, and
repositories that swapped the other way and left their workflow behind.
"""

from __future__ import annotations

import datetime as dt
from types import MappingProxyType

import pytest

from github_security_report.categories import CategoryKey
from github_security_report.client.codeql_parsers import latest_codeql_configurations
from github_security_report.codeql import (
    CodeQLConfiguration,
    CodeQLFacts,
    DefaultSetup,
    SetupType,
    build_codeql_tables,
    build_language_coverage_table,
    build_stale_configurations_table,
    normalise_language,
)
from github_security_report.models import Repo

HEAD = dt.datetime(2026, 9, 24, 7, 26, tzinfo=dt.timezone.utc)
STALE_DAYS = 30
DEFAULT_KEY = "dynamic/github-code-scanning/codeql:analyze"
ADVANCED_KEY = ".github/workflows/codeql.yml:analyze"
RENAMED_KEY = ".github/workflows/codeql.yaml:analyze"


def _repo(name: str) -> Repo:
    return Repo(name, f"o/{name}", f"https://github.com/o/{name}")


def _config(
    language: str, key: str = DEFAULT_KEY, *, days_behind: float = 0
) -> CodeQLConfiguration:
    category = (
        f"/language:{language}"
        if key == DEFAULT_KEY
        else f"{key}/build-mode:none/language:{language}"
    )
    return CodeQLConfiguration(
        category=category,
        analysis_key=key,
        last_scan_at=HEAD - dt.timedelta(days=days_behind),
        language=language,
    )


def _facts(
    name: str,
    *configs: CodeQLConfiguration,
    setup: DefaultSetup | None = None,
    workflows: dict[str, str] | None = None,
    status: int = 200,
    head: dt.datetime | None = HEAD,
) -> CodeQLFacts:
    return CodeQLFacts(
        repo=_repo(name),
        analyses_status=status,
        configurations=configs,
        head_committed_at=head,
        default_setup=setup,
        workflow_states=MappingProxyType(workflows or {}),
    )


def _dependamerge() -> CodeQLFacts:
    """Default setup swapped for a Python-only advanced workflow.

    The two default-setup configurations froze when default setup was turned
    off; the advanced workflow's earlier file name (codeql.yaml) froze when the
    file was renamed; and ``actions``, which only default setup covered, went
    unscanned.
    """
    return _facts(
        "dependamerge",
        _config("python", ADVANCED_KEY, days_behind=0.01),
        _config("python", RENAMED_KEY, days_behind=210),
        _config("python", days_behind=91),
        _config("actions", days_behind=91),
        setup=DefaultSetup(
            configured=False, languages=frozenset({"actions", "python"})
        ),
        workflows={".github/workflows/codeql.yaml": "missing"},
    )


def _superseded() -> CodeQLFacts:
    """Advanced workflow swapped for default setup, and disabled manually."""
    return _facts(
        "semantic-tag-increment",
        _config("python", ADVANCED_KEY, days_behind=101),
        _config("python", days_behind=1),
        _config("actions", days_behind=1),
        setup=DefaultSetup(configured=True, languages=frozenset({"actions", "python"})),
        workflows={".github/workflows/codeql.yml": "disabled_manually"},
    )


# --------------------------------------------------------------------------- #
# Stale configurations
# --------------------------------------------------------------------------- #
def test_stale_table_lists_each_abandoned_configuration_with_its_cause() -> None:
    table = build_stale_configurations_table([_dependamerge()], stale_days=STALE_DAYS)

    assert table.category.key is CategoryKey.CODEQL_STALE_CONFIGURATIONS
    assert table.columns == ("Repository", "Setup", "Language", "Last scan", "Cause")
    assert [row.cells for row in table.rows] == [
        (
            "Advanced (codeql.yaml)",
            "python",
            "2026-02-26",
            "Workflow removed; orphaned",
        ),
        (
            "Default",
            "actions",
            "2026-06-25",
            "Default setup disabled; orphaned",
        ),
        (
            "Default",
            "python",
            "2026-06-25",
            "Default setup disabled; orphaned",
        ),
    ]
    # The footer counts repositories, however many rows each one takes.
    assert (table.fail_count, table.pass_count, table.unknown_count) == (1, 0, 0)


def test_advanced_configuration_superseded_by_default_setup() -> None:
    # GitHub rejects advanced uploads while default setup is on, so the cause
    # is the supersession, with the disabled workflow as a qualifier.
    table = build_stale_configurations_table([_superseded()], stale_days=STALE_DAYS)
    assert [row.cells for row in table.rows] == [
        (
            "Advanced (codeql.yml)",
            "python",
            "2026-06-15",
            "Superseded by default setup; workflow disabled",
        )
    ]


@pytest.mark.parametrize(
    ("state", "cause"),
    [
        ("disabled_inactivity", "Workflow disabled after inactivity"),
        ("disabled_manually", "Workflow disabled"),
        ("deleted", "Workflow removed; orphaned"),
        ("active", "Workflow active, not uploading"),
        (None, "Workflow state unreadable"),
    ],
)
def test_advanced_cause_follows_the_workflow_state(
    state: str | None, cause: str
) -> None:
    facts = _facts(
        "r",
        _config("python", ADVANCED_KEY, days_behind=60),
        setup=DefaultSetup(configured=False),
        workflows={".github/workflows/codeql.yml": state} if state else {},
    )
    table = build_stale_configurations_table([facts], stale_days=STALE_DAYS)
    assert table.rows[0].cells[-1] == cause


@pytest.mark.parametrize(
    ("setup", "cause"),
    [
        (None, "Default setup state unreadable"),
        (
            DefaultSetup(configured=True, languages=frozenset({"python"})),
            "Language removed from default setup",
        ),
        (
            DefaultSetup(configured=True, languages=frozenset({"python", "go"})),
            "Default setup not uploading",
        ),
    ],
)
def test_default_setup_cause(setup: DefaultSetup | None, cause: str) -> None:
    facts = _facts("r", _config("go", days_behind=45), setup=setup)
    table = build_stale_configurations_table([facts], stale_days=STALE_DAYS)
    assert table.rows[0].cells[-1] == cause


def test_staleness_is_measured_against_the_head_not_the_clock() -> None:
    # Nothing pushed for a year, scanned only on push: the scan still
    # describes the code on the branch, so it is current, not stale.
    quiet_head = HEAD - dt.timedelta(days=365)
    facts = _facts(
        "quiet",
        CodeQLConfiguration(
            category="/language:python",
            analysis_key=DEFAULT_KEY,
            last_scan_at=quiet_head,
            language="python",
        ),
        setup=DefaultSetup(configured=True, languages=frozenset({"python"})),
        head=quiet_head,
    )
    table = build_stale_configurations_table([facts], stale_days=STALE_DAYS)
    assert table.rows == []
    assert table.pass_count == 1


def test_threshold_is_exclusive() -> None:
    at_threshold = _facts("edge", _config("python", days_behind=STALE_DAYS))
    beyond = _facts("over", _config("python", days_behind=STALE_DAYS + 1))
    table = build_stale_configurations_table(
        [at_threshold, beyond], stale_days=STALE_DAYS
    )
    assert [row.repo.name for row in table.rows] == ["over"]


def test_repositories_rank_by_their_stalest_configuration() -> None:
    table = build_stale_configurations_table(
        [_superseded(), _dependamerge()], stale_days=STALE_DAYS
    )
    # dependamerge's 210-day configuration outranks the other's 101 days.
    assert [row.repo.name for row in table.rows] == [
        "dependamerge",
        "dependamerge",
        "dependamerge",
        "semantic-tag-increment",
    ]


def test_unreadable_repositories_are_unknown_never_stale() -> None:
    table = build_stale_configurations_table(
        [
            _facts("forbidden", status=403),
            _facts("partial", _config("python", days_behind=90), status=500),
            _facts("headless", _config("python", days_behind=90), head=None),
        ],
        stale_days=STALE_DAYS,
    )
    assert table.rows == []
    assert table.unknown_count == 3


def test_repositories_without_codeql_are_left_to_the_codeql_signal() -> None:
    # No analyses at all (200 []) and code scanning unavailable (404) both
    # already show in the CodeQL table's not-enabled list.
    table = build_stale_configurations_table(
        [_facts("never"), _facts("off", status=404)], stale_days=STALE_DAYS
    )
    assert (table.fail_count, table.pass_count, table.unknown_count) == (0, 0, 0)


def test_description_states_the_threshold() -> None:
    table = build_stale_configurations_table([], stale_days=14)
    assert "more than 14 day(s)" in table.resolved_description()


# --------------------------------------------------------------------------- #
# Language coverage
# --------------------------------------------------------------------------- #
def test_coverage_reports_a_language_only_the_abandoned_setup_scanned() -> None:
    table = build_language_coverage_table([_dependamerge()], stale_days=STALE_DAYS)
    assert table.category.key is CategoryKey.CODEQL_LANGUAGE_COVERAGE
    assert [row.cells for row in table.rows] == [("Advanced", "actions", "python")]
    assert table.fail_count == 1


def test_coverage_clean_when_the_live_setup_covers_every_language() -> None:
    # The stale advanced configuration is cosmetic: default setup scans both.
    table = build_language_coverage_table([_superseded()], stale_days=STALE_DAYS)
    assert table.rows == []
    assert table.pass_count == 1


def test_coverage_folds_language_families() -> None:
    # Default setup names "javascript" and "typescript" separately; CodeQL
    # scans both under one extractor, and must not report either as missing.
    facts = _facts(
        "node-action",
        _config("javascript-typescript"),
        _config("actions"),
        setup=DefaultSetup(
            configured=True,
            languages=frozenset(
                normalise_language(lang)
                for lang in ("javascript", "typescript", "actions")
            ),
        ),
    )
    table = build_language_coverage_table([facts], stale_days=STALE_DAYS)
    assert table.rows == []
    assert table.pass_count == 1


def test_coverage_with_every_configuration_stale_scans_nothing() -> None:
    facts = _facts(
        "stopped",
        _config("python", ADVANCED_KEY, days_behind=90),
        setup=DefaultSetup(configured=False, languages=frozenset({"python"})),
    )
    table = build_language_coverage_table([facts], stale_days=STALE_DAYS)
    assert [row.cells for row in table.rows] == [("None current", "python", "nothing")]


def test_coverage_unknown_without_the_default_setup_reading() -> None:
    # The default-setup read is the only source of detected languages.
    facts = _facts("r", _config("python"), setup=None)
    table = build_language_coverage_table([facts], stale_days=STALE_DAYS)
    assert (table.fail_count, table.pass_count, table.unknown_count) == (0, 0, 1)


def test_build_codeql_tables_orders_stale_then_coverage() -> None:
    tables = build_codeql_tables([_dependamerge()], stale_days=STALE_DAYS)
    assert [t.category.key for t in tables] == [
        CategoryKey.CODEQL_STALE_CONFIGURATIONS,
        CategoryKey.CODEQL_LANGUAGE_COVERAGE,
    ]


# --------------------------------------------------------------------------- #
# Configuration facts and parsing
# --------------------------------------------------------------------------- #
def test_setup_type_and_workflow_path_come_from_the_analysis_key() -> None:
    default = _config("python")
    advanced = _config("python", ADVANCED_KEY)
    assert (default.setup, default.workflow_path) == (SetupType.DEFAULT, None)
    assert advanced.setup is SetupType.ADVANCED
    assert advanced.workflow_path == ".github/workflows/codeql.yml"


def test_latest_configurations_keeps_the_newest_analysis_per_category() -> None:
    # Order-independent: the newest entry wins wherever it appears.
    configs = latest_codeql_configurations(
        [
            {
                "category": "/language:python",
                "analysis_key": DEFAULT_KEY,
                "created_at": "2026-06-20T00:00:00Z",
            },
            {
                "category": "/language:python",
                "analysis_key": DEFAULT_KEY,
                "created_at": "2026-06-24T14:08:17Z",
            },
            {"category": "/language:go", "created_at": "not a date"},
            {"analysis_key": DEFAULT_KEY, "created_at": "2026-06-24T00:00:00Z"},
        ]
    )
    assert len(configs) == 1
    assert configs[0].last_scan_at.day == 24


def test_language_falls_back_to_the_environment() -> None:
    # A custom category need not name the language; the environment does.
    (config,) = latest_codeql_configurations(
        [
            {
                "category": "custom-scan",
                "analysis_key": ADVANCED_KEY,
                "created_at": "2026-09-01T00:00:00Z",
                "environment": '{"language":"Kotlin"}',
            }
        ]
    )
    assert config.language == "java-kotlin"
