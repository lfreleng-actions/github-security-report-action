# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Tests for the Workflow Failures table builder (one pair per window)."""

from __future__ import annotations

import datetime as dt

import pytest

from github_security_report.models import Repo
from github_security_report.report import CELL_BAD, CELL_WARN, TableSection
from github_security_report.workflow_runs import (
    PATTERN_INSUFFICIENT,
    PATTERN_INTERMITTENT,
    PATTERN_PERSISTENT,
    FailedJob,
    Outcome,
    Trigger,
    WindowOptions,
    WorkflowRunRecord,
)
from github_security_report.workflow_runs.tables import (
    DETAIL_COLUMNS,
    REPO_COLUMNS,
    build_workflow_failure_tables,
)

UTC = dt.timezone.utc
NOW = dt.datetime(2026, 3, 1, 12, 0, 0, tzinfo=UTC)
DAY = dt.timedelta(days=1)
WINDOWS = (30, 7)
STRICT = WindowOptions(days=7, persistent_threshold=0.5)
TESTING_URL = "https://github.com/o/a/actions/workflows/testing.yaml"
JOB_URL = "https://github.com/o/a/actions/runs/3/job/30"

_counter = iter(range(1, 10_000))


def _repo(name: str) -> Repo:
    return Repo(name, f"o/{name}", f"https://github.com/o/{name}")


IN_SCOPE = [_repo("a"), _repo("b"), _repo("c")]


def _run(
    repo: str,
    outcome: Outcome,
    trigger: Trigger,
    *,
    days_ago: int,
    workflow_id: int = 1,
    workflow_name: str = "Testing",
    workflow_path: str = ".github/workflows/testing.yaml",
    failed_jobs: tuple[FailedJob, ...] | None = None,
) -> WorkflowRunRecord:
    """One record, ``days_ago`` before ``NOW``, with a unique id."""
    run_id = next(_counter)
    return WorkflowRunRecord(
        id=run_id,
        node_id=f"WFR_{run_id}",
        repo=repo,
        workflow_id=workflow_id,
        workflow_name=workflow_name,
        workflow_path=workflow_path,
        event="push",
        trigger=trigger,
        ref_name="main",
        outcome=outcome,
        conclusion=outcome.value,
        attempt=1,
        created_at=NOW - days_ago * DAY,
        html_url=f"https://github.com/o/{repo}/actions/runs/{run_id}",
        failed_jobs=failed_jobs,
    )


def _records() -> list[WorkflowRunRecord]:
    """Repo ``a``: a failing matrix job and an unreadable one; ``b``: clean."""
    build = (FailedJob("Build (3.12)", "failure", JOB_URL),)
    return [
        *(
            _run("a", Outcome.FAIL, Trigger.MERGE, days_ago=d, failed_jobs=build)
            for d in (1, 2, 3)
        ),
        *(_run("a", Outcome.PASS, Trigger.PULL_REQUEST, days_ago=d) for d in (1, 2)),
        _run("a", Outcome.SKIP, Trigger.MERGE, days_ago=4),
        _run(
            "a",
            Outcome.FAIL,
            Trigger.SCHEDULE,
            days_ago=2,
            workflow_id=2,
            workflow_name="Publish",
            workflow_path=".github/workflows/publish.yaml",
        ),
        *(_run("b", Outcome.PASS, Trigger.MERGE, days_ago=d) for d in (1, 2)),
    ]


def _build(
    options: WindowOptions = STRICT,
    *,
    records: list[WorkflowRunRecord] | None = None,
    unknown: frozenset[str] = frozenset(),
    oldest: dict[str, dt.datetime | None] | None = None,
) -> tuple[tuple[TableSection, ...], tuple[TableSection, ...]]:
    tables: tuple[tuple[TableSection, ...], tuple[TableSection, ...]]
    tables = build_workflow_failure_tables(
        _records() if records is None else records,
        IN_SCOPE,
        generated_at=NOW,
        windows=WINDOWS,
        options=options,
        unknown=unknown,
        oldest=oldest,
    )
    return tables


def test_one_table_per_window_shortest_first() -> None:
    # Two windows give two tables of each grain, ordered by length whatever
    # order the caller listed them in, and the title names the window.
    repo_tables, detail_tables = _build()
    assert [t.window_days for t in repo_tables] == [7, 30]
    assert [t.window_days for t in detail_tables] == [7, 30]
    assert repo_tables[0].title == "Workflow Failures (7 days)"
    assert detail_tables[0].title == "Workflow Failures: Detail (7 days)"
    assert repo_tables[0].columns == REPO_COLUMNS
    assert detail_tables[0].columns == DETAIL_COLUMNS


def test_repo_row_counts_and_worst_workflow() -> None:
    # Repo ``a`` is the only failing repository: 4 failures over 7 concluded
    # runs, a rate over the pass-or-fail runs only (4/6), and the worst
    # workflow named with its own failed/runs figure and linked to its page.
    (repo_table, _), _ = _build()
    assert [row.repo.name for row in repo_table.rows] == ["a"]
    row = repo_table.rows[0]
    assert row.cells == ("4", "7", "67%", "1", "0", "2", "Testing (3/6)")
    assert row.sort_values == (4, 7, pytest.approx(4 / 6), 1, 0, 2, "Testing")
    assert row.cell_urls[-1] == TESTING_URL
    assert row.cell_urls[:-1] == (None,) * 6


@pytest.mark.parametrize(
    ("threshold", "level"), [(0.5, CELL_BAD), (0.9, CELL_WARN)], ids=["at", "below"]
)
def test_repo_fail_rate_level_follows_threshold(threshold: float, level: str) -> None:
    # The Fail % cell is bad at or above the persistent threshold, a warning
    # below it; no other repo cell carries emphasis.
    options = WindowOptions(days=7, persistent_threshold=threshold)
    (repo_table, _), _ = _build(options)
    levels = repo_table.rows[0].cell_levels
    assert levels[2] == level
    assert all(value is None for i, value in enumerate(levels) if i != 2)


def test_repo_footer_counts_and_notes() -> None:
    # Readable repositories without a failure pass (``b`` and ``c``, the
    # latter with no runs at all); the note totals every repository's runs.
    (repo_table, _), _ = _build()
    assert repo_table.pass_count == 2
    assert repo_table.fail_count == 1
    assert repo_table.unknown_count == 0
    assert repo_table.notes == ("9 runs across 3 repositories in 7 days",)
    assert repo_table.sum_columns == frozenset({1, 2, 4, 5, 6})
    assert repo_table.numeric_columns == frozenset({1, 2, 3, 4, 5, 6})


def test_truncated_history_is_noted_per_window() -> None:
    # A repository whose stored history starts inside the window is counted
    # as truncated for that window only: ten days of history satisfy the
    # week but not the month.
    (week, month), _ = _build(oldest={"b": NOW - 10 * DAY, "a": None})
    assert len(week.notes) == 1
    assert month.notes[1] == "1 repositories hold less than 30 days of run history"


def test_unknown_repo_is_counted_not_passed() -> None:
    # An unreadable repository is neither failing nor failure-free.
    (repo_table, _), (detail, _) = _build(unknown=frozenset({"c"}))
    assert repo_table.unknown_count == 1
    assert repo_table.pass_count == 1
    assert detail.unknown_count == 1
    assert repo_table.notes[0].startswith("9 runs across 2 repositories")


def test_unknown_repo_contributes_no_rows_even_with_records() -> None:
    # Records for a repository the sync could not read are not trusted into
    # either table, however many of them the store holds.
    (repo_table, _), (detail, _) = _build(unknown=frozenset({"a"}))
    assert repo_table.rows == []
    assert detail.rows == []
    assert repo_table.unknown_count == 1


def test_detail_rows_worst_workflow_first() -> None:
    # The per-workflow grain lists every failing workflow of ``a``, the one
    # with more failures first, in DETAIL_COLUMNS order.
    _, (detail, _) = _build()
    assert [row.cells[0] for row in detail.rows] == ["Testing", "Publish"]
    testing, publish = detail.rows
    assert testing.cells == (
        "Testing",
        "testing.yaml",
        "Build (3)",
        "3",
        "6",
        "60%",
        PATTERN_PERSISTENT,
        "Merge:3",
        "post-merge only",
        "2026-02-28",
    )
    assert publish.cells[2] == "jobs unreadable"
    assert publish.cells[3:] == (
        "1",
        "1",
        "100%",
        PATTERN_INSUFFICIENT,
        "Sched:1",
        "other",
        "2026-02-27",
    )
    assert detail.fail_count == 2
    assert detail.pass_count == 2
    assert detail.sum_columns == frozenset({4, 5})
    assert detail.numeric_columns == frozenset({4, 5, 6})


def test_detail_links_workflow_job_and_last_failure() -> None:
    # The workflow cell links its run history, the job cell the failing
    # check run's own log, the last-failure cell that run's page.
    records = _records()
    newest_failure = max(
        (r for r in records if r.workflow_id == 1 and r.outcome is Outcome.FAIL),
        key=lambda r: r.created_at,
    )
    _, (detail, _) = _build(records=records)
    testing = detail.rows[0]
    assert testing.cell_urls[0] == TESTING_URL
    assert testing.cell_urls[2] == JOB_URL
    assert testing.cell_urls[-1] == newest_failure.html_url
    assert all(url is None for url in testing.cell_urls[3:-1])
    publish = detail.rows[1]
    assert publish.cell_urls[2] is None


def test_detail_levels_persistent_and_post_merge() -> None:
    # A persistent pattern is bad and a post-merge-only reading a warning;
    # an insufficient sample with an "other" reading carries neither.
    _, (detail, _) = _build()
    testing, publish = detail.rows
    assert testing.cell_levels[6] == CELL_BAD
    assert testing.cell_levels[8] == CELL_WARN
    assert publish.cell_levels[6] is None
    assert publish.cell_levels[8] is None


def test_detail_intermittent_pattern_warns() -> None:
    # Under the default threshold 3 of 5 is intermittent, not persistent.
    _, (detail, _) = _build(WindowOptions(days=7))
    testing = detail.rows[0]
    assert testing.cells[6] == PATTERN_INTERMITTENT
    assert testing.cell_levels[6] == CELL_WARN


def test_matrix_leg_kept_when_collapse_is_off() -> None:
    # With ``collapse_matrix`` off the job keeps its parenthesised leg.
    _, (detail, _) = _build(WindowOptions(days=7, collapse_matrix=False))
    assert detail.rows[0].cells[2] == "Build (3.12) (3)"


def test_dynamic_failures_need_opting_in() -> None:
    # A GitHub-managed workflow's failure is left out of both tables unless
    # ``include_dynamic`` asks for it; its path has no workflow page to link.
    dynamic = _run(
        "b",
        Outcome.FAIL,
        Trigger.DYNAMIC,
        days_ago=1,
        workflow_id=9,
        workflow_name="pages-build-deployment",
        workflow_path="dynamic/pages/pages-build-deployment",
    )
    records = [*_records(), dynamic]
    (repo_table, _), (detail, _) = _build(records=records)
    assert [row.repo.name for row in repo_table.rows] == ["a"]
    assert all(row.repo.name == "a" for row in detail.rows)

    options = WindowOptions(days=7, include_dynamic=True)
    (repo_table, _), (detail, _) = _build(options, records=records)
    assert [row.repo.name for row in repo_table.rows] == ["a", "b"]
    dynamic_row = next(row for row in detail.rows if row.repo.name == "b")
    assert dynamic_row.cells[7] == "Dynamic:1"
    assert dynamic_row.cell_urls[0] is None


def test_excluded_workflow_leaves_both_tables() -> None:
    # A path matching ``exclude_workflows`` drops out of the detail table and
    # out of the repository's own counts.
    options = WindowOptions(
        days=7, exclude_workflows=(".github/workflows/publish.yaml",)
    )
    (repo_table, _), (detail, _) = _build(options)
    assert [row.cells[0] for row in detail.rows] == ["Testing"]
    row = repo_table.rows[0]
    assert row.cells[0] == "3"
    assert row.cells[5] == "1"
    assert repo_table.notes[0].startswith("8 runs")
