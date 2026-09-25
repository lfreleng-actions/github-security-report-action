# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Tests for the CodeQL scan-health facts and tables (pure, no network).

The scenarios mirror what the lfreleng-actions estate actually showed: a
repository that swapped default setup for a narrower advanced workflow, and
repositories that swapped the other way and left their workflow behind.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import replace
from types import MappingProxyType

import pytest

from github_security_report.categories import CategoryKey
from github_security_report.client.codeql_parsers import (
    _parse_default_setup,
    latest_codeql_configurations,
)
from github_security_report.codeql import (
    CleanupAction,
    CodeQLConfiguration,
    CodeQLFacts,
    DefaultSetup,
    SetupType,
    StaleCause,
    build_codeql_tables,
    build_language_coverage_table,
    build_stale_configurations_table,
    normalise_language,
    plan_cleanup,
    stale_cause,
)
from github_security_report.models import Repo

HEAD = dt.datetime(2026, 9, 24, 7, 26, tzinfo=dt.timezone.utc)
STALE_DAYS = 30
DEFAULT_KEY = "dynamic/github-code-scanning/codeql:analyze"
ADVANCED_KEY = ".github/workflows/codeql.yml:analyze"
RENAMED_KEY = ".github/workflows/codeql.yaml:analyze"


def _repo(name: str) -> Repo:
    return Repo(name, f"o/{name}", f"https://github.com/o/{name}")


def _scanned_on(config: CodeQLConfiguration) -> str | None:
    """A configuration's last successful scan as an ISO date (None: never)."""
    return config.last_scan_at.date().isoformat() if config.last_scan_at else None


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
    assert _scanned_on(configs[0]) == "2026-06-24"


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


# --------------------------------------------------------------------------- #
# Failing analyses (Copilot review, #173)
# --------------------------------------------------------------------------- #
def _entry(created: str, error: str = "", key: str = ADVANCED_KEY) -> dict:
    return {
        "category": f"{key}/build-mode:none/language:python",
        "analysis_key": key,
        "created_at": created,
        "error": error,
    }


def test_an_errored_analysis_is_not_a_scan() -> None:
    # A workflow that fails on every run still uploads, with a fresh
    # timestamp. Counting it would keep the configuration looking current
    # indefinitely: the last scan is the newest *successful* upload.
    (config,) = latest_codeql_configurations(
        [
            _entry("2026-06-01T00:00:00Z"),
            _entry("2026-09-20T00:00:00Z", error="CodeQL extraction failed"),
            _entry("2026-09-24T00:00:00Z", error="CodeQL extraction failed"),
        ]
    )
    assert _scanned_on(config) == "2026-06-01"
    assert config.failing is True


def test_a_configuration_that_never_succeeded_has_never_scanned() -> None:
    # A first attempt that failed on the current head of a quiet repository
    # must not read as a scan: measured against the head it would never go
    # stale, and its language would count as covered, although CodeQL has
    # never produced a result.
    (config,) = latest_codeql_configurations(
        [
            _entry("2026-09-24T00:00:00Z", error="boom"),
            _entry("2026-07-01T00:00:00Z", error="boom"),
        ]
    )
    assert (_scanned_on(config), config.failing) == (None, True)
    assert config.is_stale(dt.datetime(2026, 7, 1, tzinfo=dt.timezone.utc), 30)
    facts = _facts(
        "r",
        replace(config, language="python"),
        setup=DefaultSetup(configured=False, languages=frozenset({"python"})),
        head=dt.datetime(2026, 9, 24, tzinfo=dt.timezone.utc),
    )
    stale = build_stale_configurations_table([facts], stale_days=STALE_DAYS)
    assert [row.cells[2:] for row in stale.rows] == [
        ("never", "Analyses failing; check the latest run")
    ]
    coverage = build_language_coverage_table([facts], stale_days=STALE_DAYS)
    assert [row.cells[1] for row in coverage.rows] == ["python"]


def test_a_recovered_configuration_is_not_failing() -> None:
    (config,) = latest_codeql_configurations(
        [
            _entry("2026-09-20T00:00:00Z", error="boom"),
            _entry("2026-09-24T00:00:00Z"),
        ]
    )
    assert (_scanned_on(config), config.failing) == ("2026-09-24", False)


def test_failing_analyses_are_the_reported_cause() -> None:
    # The setup exists and still runs, whatever else is true of it, so the
    # reader's next step is the failing run's logs.
    failing = replace(_config("python", ADVANCED_KEY, days_behind=60), failing=True)
    facts = _facts(
        "r",
        failing,
        setup=DefaultSetup(configured=False, languages=frozenset({"python"})),
        workflows={".github/workflows/codeql.yml": "active"},
    )
    table = build_stale_configurations_table([facts], stale_days=STALE_DAYS)
    assert table.rows[0].cells[-1] == "Analyses failing; check the latest run"


def test_a_new_setup_under_the_same_category_continues_the_configuration() -> None:
    # GitHub defines a configuration as ref + tool + category, so an upload
    # under an existing category continues that configuration whichever setup
    # sent it: the newest analysis's key describes it, and nothing is orphaned.
    shared = "/language:python"
    (config,) = latest_codeql_configurations(
        [
            {
                "category": shared,
                "analysis_key": DEFAULT_KEY,
                "created_at": "2026-06-01T00:00:00Z",
            },
            {
                "category": shared,
                "analysis_key": ADVANCED_KEY,
                "created_at": "2026-09-24T00:00:00Z",
            },
        ]
    )
    assert (config.analysis_key, _scanned_on(config)) == (ADVANCED_KEY, "2026-09-24")


# --------------------------------------------------------------------------- #
# Third review (#173): setup states, external uploaders, sort keys
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("state", "configured", "transitional"),
    [
        ("configured", True, False),
        ("not-configured", False, False),
        ("evaluating", False, True),
        ("failed", False, True),
        (None, False, True),
    ],
)
def test_default_setup_keeps_transitional_states_apart(
    state: str | None, configured: bool, transitional: bool
) -> None:
    # Only a real "not-configured" means default setup is off. A state GitHub
    # is still settling into, or one it failed to reach, is neither on nor
    # off, and must not be read as "disabled".
    setup = _parse_default_setup({"state": state, "languages": ["python"]})
    assert (setup.configured, setup.transitional) == (configured, transitional)


def test_a_transitional_default_setup_is_not_reported_as_disabled() -> None:
    facts = _facts(
        "r",
        _config("python", days_behind=60),
        setup=DefaultSetup(configured=False, transitional=True),
    )
    table = build_stale_configurations_table([facts], stale_days=STALE_DAYS)
    assert table.rows[0].cells[-1] == "Default setup changing state; recheck later"


def test_an_upload_from_outside_actions_is_not_a_workflow_problem() -> None:
    # CodeQL run from another CI system uploads under an analysis key that
    # names no workflow file, so no workflow state is read or blamed.
    external = CodeQLConfiguration(
        category="ci/codeql/language:python",
        analysis_key="jenkins:codeql",
        last_scan_at=HEAD - dt.timedelta(days=60),
        language="python",
    )
    off = _facts(
        "r", external, setup=DefaultSetup(configured=False, languages=frozenset())
    )
    on = _facts(
        "r", external, setup=DefaultSetup(configured=True, languages=frozenset())
    )
    (off_row,) = build_stale_configurations_table([off], stale_days=STALE_DAYS).rows
    (on_row,) = build_stale_configurations_table([on], stale_days=STALE_DAYS).rows
    assert off_row.cells[-1] == "Uploaded outside GitHub Actions; check that pipeline"
    # Default setup blocks advanced uploads from anywhere, so it still wins.
    assert on_row.cells[-1] == "Superseded by default setup"


def test_never_sorts_as_the_oldest_last_scan() -> None:
    # The cell reads "never", but its sort key is the oldest possible date,
    # so a configured ascending sort on Last scan keeps it stalest-first.
    never = replace(
        _config("python", ADVANCED_KEY, days_behind=0), last_scan_at=None, failing=True
    )
    facts = _facts(
        "r",
        never,
        _config("actions", days_behind=90),
        setup=DefaultSetup(configured=False, languages=frozenset()),
    )
    rows = build_stale_configurations_table([facts], stale_days=STALE_DAYS).rows
    by_cell = {row.cells[2]: row.sort_values[2] for row in rows}
    assert by_cell == {"never": "0001-01-01", "2026-06-26": "2026-06-26"}


# --------------------------------------------------------------------------- #
# Fourth review (#173): transitional setup, tie order
# --------------------------------------------------------------------------- #
def test_a_transitional_setup_blames_no_advanced_uploader() -> None:
    # Mid-change, default setup may be about to supersede the configuration,
    # so neither its workflow nor an external pipeline is the cause.
    facts = _facts(
        "r",
        _config("python", ADVANCED_KEY, days_behind=60),
        setup=DefaultSetup(configured=False, transitional=True),
        workflows={".github/workflows/codeql.yml": "active"},
    )
    (row,) = build_stale_configurations_table([facts], stale_days=STALE_DAYS).rows
    assert row.cells[-1] == "Default setup changing state; recheck later"


def test_coverage_is_unknown_while_default_setup_is_transitional() -> None:
    # Its languages are neither the configured set nor the detected
    # inventory, so the repository is neither covered nor a gap.
    facts = _facts(
        "r",
        _config("python", ADVANCED_KEY, days_behind=0),
        setup=DefaultSetup(
            configured=False, transitional=True, languages=frozenset({"go"})
        ),
    )
    table = build_language_coverage_table([facts], stale_days=STALE_DAYS)
    assert (table.fail_count, table.pass_count, table.unknown_count) == (0, 0, 1)


def test_equal_timestamps_keep_the_apis_newest_first_order() -> None:
    # The API lists analyses newest first. Two sharing a timestamp must keep
    # that order, or the older one is taken as the newest attempt.
    same = "2026-09-24T00:00:00Z"
    (config,) = latest_codeql_configurations(
        [
            {**_entry(same, error="boom"), "analysis_key": "newest"},
            {**_entry(same), "analysis_key": "older"},
        ]
    )
    assert (config.analysis_key, config.failing) == ("newest", True)


def test_a_transitional_setup_outranks_a_removed_workflow() -> None:
    # Even a confirmed-removed workflow is not final while default setup is
    # mid-change: reaching "orphaned" here would let a cleanup delete an
    # unsettled configuration.
    facts = _facts(
        "r",
        _config("python", ADVANCED_KEY, days_behind=60),
        setup=DefaultSetup(configured=False, transitional=True),
        workflows={".github/workflows/codeql.yml": "missing"},
    )
    (row,) = build_stale_configurations_table([facts], stale_days=STALE_DAYS).rows
    assert row.cells[-1] == "Default setup changing state; recheck later"


# --------------------------------------------------------------------------- #
# Cleanup plan
# --------------------------------------------------------------------------- #
def _with_ids(config: CodeQLConfiguration, *ids: int) -> CodeQLConfiguration:
    return replace(config, analysis_ids=ids)


def test_plan_deletes_orphans_whose_language_is_still_scanned() -> None:
    # dependamerge before its fix: python is covered by the live workflow, so
    # its orphaned configurations may go; actions is covered by nothing, so
    # deleting its only (stale) results is refused until scanning is added.
    facts = _facts(
        "dependamerge",
        _config("python", ADVANCED_KEY, days_behind=0.01),
        _with_ids(_config("python", RENAMED_KEY, days_behind=210), 9, 8),
        _with_ids(_config("python", days_behind=91), 7),
        _with_ids(_config("actions", days_behind=91), 6),
        setup=DefaultSetup(
            configured=False, languages=frozenset({"actions", "python"})
        ),
        workflows={".github/workflows/codeql.yaml": "missing"},
    )
    items = plan_cleanup([facts], stale_days=STALE_DAYS)
    assert [(i.config.category, i.action, i.refusal) for i in items] == [
        (f"{RENAMED_KEY}/build-mode:none/language:python", CleanupAction.DELETE, None),
        (
            "/language:actions",
            CleanupAction.DELETE,
            "no current configuration scans actions; add scanning for it first",
        ),
        ("/language:python", CleanupAction.DELETE, None),
    ]
    assert items[0].label == "dependamerge (Advanced, python)"


def test_plan_deletes_a_superseded_advanced_configuration() -> None:
    items = plan_cleanup(
        [
            replace(
                _superseded(),
                configurations=(
                    _with_ids(_config("python", ADVANCED_KEY, days_behind=101), 3),
                    _config("python", days_behind=1),
                    _config("actions", days_behind=1),
                ),
            )
        ],
        stale_days=STALE_DAYS,
    )
    assert [(i.cause, i.action, i.refusal) for i in items] == [
        (StaleCause.SUPERSEDED_DISABLED, CleanupAction.DELETE, None)
    ]


def test_plan_reenables_a_workflow_github_disabled_for_inactivity() -> None:
    facts = _facts(
        "quiet",
        _with_ids(_config("python", ADVANCED_KEY, days_behind=70), 1),
        setup=DefaultSetup(configured=False, languages=frozenset({"python"})),
        workflows={".github/workflows/codeql.yml": "disabled_inactivity"},
    )
    (item,) = plan_cleanup([facts], stale_days=STALE_DAYS)
    # Re-enabling restores the scan, so no coverage guard applies to it.
    assert (item.action, item.refusal) == (CleanupAction.REENABLE_WORKFLOW, None)


@pytest.mark.parametrize(
    "state", ["active", "disabled_manually", None], ids=["idle", "manual", "unread"]
)
def test_plan_leaves_causes_that_need_a_person(state: str | None) -> None:
    # A configuration that may yet resume, or whose state is unknown, is
    # reported but never acted on.
    facts = _facts(
        "r",
        _config("python", days_behind=0),
        _with_ids(_config("python", ADVANCED_KEY, days_behind=60), 1),
        setup=DefaultSetup(configured=False, languages=frozenset({"python"})),
        workflows={".github/workflows/codeql.yml": state} if state else {},
    )
    assert plan_cleanup([facts], stale_days=STALE_DAYS) == []


def test_plan_skips_unreadable_repositories() -> None:
    facts = _facts("r", _with_ids(_config("python", days_behind=90), 1), head=None)
    assert plan_cleanup([facts], stale_days=STALE_DAYS) == []


def test_plan_refuses_a_configuration_with_no_analyses_recorded() -> None:
    facts = _facts(
        "r",
        _config("python", ADVANCED_KEY, days_behind=0),
        _config("python", days_behind=90),
        setup=DefaultSetup(configured=False, languages=frozenset({"python"})),
    )
    (item,) = plan_cleanup([facts], stale_days=STALE_DAYS)
    assert item.refusal == "no analyses recorded to delete"


def test_orphaned_causes_are_exactly_those_that_cannot_upload_again() -> None:
    assert {c for c in StaleCause if c.orphaned} == {
        StaleCause.DEFAULT_SETUP_DISABLED,
        StaleCause.LANGUAGE_REMOVED,
        StaleCause.WORKFLOW_REMOVED,
        StaleCause.SUPERSEDED,
        StaleCause.SUPERSEDED_DISABLED,
    }


def test_latest_configurations_record_analysis_ids_newest_first() -> None:
    # GitHub deletes a configuration's analyses newest first, so that is the
    # order they must be kept in, whatever order the API listed them.
    (config,) = latest_codeql_configurations(
        [
            {
                "category": "/language:python",
                "analysis_key": DEFAULT_KEY,
                "created_at": created,
                "id": analysis_id,
            }
            for analysis_id, created in (
                (11, "2026-06-20T00:00:00Z"),
                (33, "2026-06-24T00:00:00Z"),
                (22, "2026-06-22T00:00:00Z"),
            )
        ]
    )
    assert config.analysis_ids == (33, 22, 11)


def test_a_failing_configuration_is_never_planned_for_deletion() -> None:
    # Its setup still runs; fixing the run brings the scan back, and deleting
    # it would throw away the history of a configuration that is not dead.
    failing = replace(_with_ids(_config("python", days_behind=90), 1), failing=True)
    facts = _facts(
        "r",
        _config("python", ADVANCED_KEY, days_behind=0),
        failing,
        setup=DefaultSetup(configured=False, languages=frozenset({"python"})),
    )
    assert stale_cause(failing, facts) is StaleCause.ANALYSES_FAILING
    assert not StaleCause.ANALYSES_FAILING.orphaned
    assert plan_cleanup([facts], stale_days=STALE_DAYS) == []


def test_deletion_ids_include_errored_analyses() -> None:
    # An errored upload is still part of the configuration, so deleting the
    # configuration must remove it too, in the same newest-first order.
    (config,) = latest_codeql_configurations(
        [
            {**_entry("2026-06-01T00:00:00Z"), "id": 1},
            {**_entry("2026-06-02T00:00:00Z", error="boom"), "id": 2},
        ]
    )
    assert config.analysis_ids == (2, 1)
    assert _scanned_on(config) == "2026-06-01"


@pytest.mark.parametrize(
    ("config", "setup"),
    [
        # Default setup mid-change: it may come back, so it is not orphaned.
        (
            _config("python", days_behind=60),
            DefaultSetup(configured=False, transitional=True),
        ),
        # An external pipeline is beyond anything remediate can see or reach.
        (
            CodeQLConfiguration(
                category="ci/codeql/language:python",
                analysis_key="jenkins:codeql",
                last_scan_at=HEAD - dt.timedelta(days=60),
                language="python",
                analysis_ids=(1,),
            ),
            DefaultSetup(configured=False),
        ),
    ],
    ids=["transitional", "external"],
)
def test_plan_leaves_unsettled_and_external_configurations(
    config: CodeQLConfiguration, setup: DefaultSetup
) -> None:
    facts = _facts(
        "r", _config("python", ADVANCED_KEY, days_behind=0), config, setup=setup
    )
    assert plan_cleanup([facts], stale_days=STALE_DAYS) == []
    assert not StaleCause.DEFAULT_SETUP_TRANSITIONAL.orphaned
    assert not StaleCause.EXTERNAL_UPLOADER.orphaned
