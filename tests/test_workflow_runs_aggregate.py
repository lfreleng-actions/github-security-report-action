# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Tests for the pure window aggregation over workflow-run records."""

from __future__ import annotations

import datetime as dt
from types import MappingProxyType

import pytest

from github_security_report.workflow_runs import (
    PATTERN_INSUFFICIENT,
    PATTERN_INTERMITTENT,
    PATTERN_PERSISTENT,
    FailedJob,
    JobFailures,
    Outcome,
    Trigger,
    WindowOptions,
    WorkflowRunRecord,
    WorkflowWindowStats,
    in_window,
    normalise_job_name,
    pattern,
    repo_stats,
    window_records,
    workflow_stats,
)

UTC = dt.timezone.utc
NOW = dt.datetime(2026, 3, 1, 12, 0, 0, tzinfo=UTC)
WEEK = WindowOptions(days=7)

_counter = iter(range(1, 10_000))


def _run(**overrides: object) -> WorkflowRunRecord:
    """A record with sensible defaults, varying only what a test cares about.

    Ids are allocated from a counter so two records built without one are
    never confused for the same run; ``age`` is a shortcut for ``created_at``
    as hours before ``NOW``.
    """
    age = overrides.pop("age", 1)
    assert isinstance(age, (int, float))
    fields: dict[str, object] = {
        "id": next(_counter),
        "repo": "r",
        "workflow_id": 1,
        "workflow_name": "CI",
        "workflow_path": ".github/workflows/ci.yaml",
        "event": "push",
        "trigger": Trigger.MERGE,
        "ref_name": "main",
        "outcome": Outcome.FAIL,
        "conclusion": "failure",
        "attempt": 1,
        "created_at": NOW - dt.timedelta(hours=age),
        "html_url": "",
        **overrides,
    }
    fields.setdefault("node_id", f"WFR_{fields['id']}")
    return WorkflowRunRecord(**fields)  # type: ignore[arg-type]


def _job(name: str, url: str = "") -> FailedJob:
    """A failing check run with the given name."""
    return FailedJob(name=name, conclusion="failure", url=url)


class TestInWindow:
    """The window is closed at both ends."""

    def test_start_is_inclusive(self) -> None:
        record = _run(created_at=NOW - dt.timedelta(days=7))
        assert in_window(record, generated_at=NOW, days=7)

    def test_before_start_is_out(self) -> None:
        record = _run(created_at=NOW - dt.timedelta(days=7, seconds=1))
        assert not in_window(record, generated_at=NOW, days=7)

    def test_after_generated_at_is_out(self) -> None:
        record = _run(created_at=NOW + dt.timedelta(seconds=1))
        assert not in_window(record, generated_at=NOW, days=7)


class TestWindowRecords:
    """Pending, dynamic and excluded runs are dropped before counting."""

    def test_pending_is_dropped(self) -> None:
        kept = _run()
        pending = _run(outcome=Outcome.PENDING, conclusion="")
        assert window_records([kept, pending], generated_at=NOW, options=WEEK) == [kept]

    def test_dynamic_dropped_by_default_and_kept_on_request(self) -> None:
        dynamic = _run(
            trigger=Trigger.DYNAMIC, event="dynamic", workflow_path="dynamic/x"
        )
        assert window_records([dynamic], generated_at=NOW, options=WEEK) == []
        included = WindowOptions(days=7, include_dynamic=True)
        assert window_records([dynamic], generated_at=NOW, options=included) == [
            dynamic
        ]

    def test_exclude_workflows_glob_matches_the_path(self) -> None:
        nightly = _run(workflow_path=".github/workflows/nightly-audit.yaml")
        ci = _run()
        options = WindowOptions(days=7, exclude_workflows=("*/nightly-*",))
        assert window_records([nightly, ci], generated_at=NOW, options=options) == [ci]


class TestPattern:
    """Thresholds are inclusive at the boundary."""

    def test_below_min_runs_is_insufficient(self) -> None:
        assert pattern(2, 0, min_runs=3, persistent_threshold=0.9) == (
            PATTERN_INSUFFICIENT
        )

    def test_exactly_min_runs_is_judged(self) -> None:
        assert pattern(3, 0, min_runs=3, persistent_threshold=0.9) == (
            PATTERN_PERSISTENT
        )

    def test_exactly_at_threshold_is_persistent(self) -> None:
        assert pattern(9, 1, min_runs=3, persistent_threshold=0.9) == (
            PATTERN_PERSISTENT
        )

    def test_just_below_threshold_is_intermittent(self) -> None:
        assert pattern(8, 2, min_runs=3, persistent_threshold=0.9) == (
            PATTERN_INTERMITTENT
        )

    def test_no_runs_is_insufficient_even_with_min_runs_zero(self) -> None:
        assert pattern(0, 0, min_runs=0, persistent_threshold=0.9) == (
            PATTERN_INSUFFICIENT
        )


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("Build (ubuntu-22.04)", "Build"),
        ("Caller / Callee (3.12, ubuntu)", "Caller / Callee"),
        ("Test (x) / Audit", "Test (x) / Audit"),
        ("Job ((a))", "Job"),
        ("  Lint  ", "Lint"),
        ("(only)", "(only)"),
        ("Broken x)", "Broken x)"),
    ],
)
def test_normalise_job_name_collapses_one_trailing_group(
    name: str, expected: str
) -> None:
    """Only a balanced group at the very end is stripped."""
    assert normalise_job_name(name, collapse_matrix=True) == expected


def test_normalise_job_name_off_keeps_the_group() -> None:
    """With collapsing off the matrix leg stays, but whitespace still goes."""
    assert normalise_job_name(" Build (x) ", collapse_matrix=False) == "Build (x)"


def _only(
    records: list[WorkflowRunRecord], options: WindowOptions = WEEK
) -> WorkflowWindowStats:
    """The single workflow entry a fixture is expected to produce."""
    stats = workflow_stats(records, generated_at=NOW, options=options)
    assert len(stats) == 1
    return stats[0]


class TestWorkflowStats:
    """Per-workflow counting, job grouping and the newest-wins fields."""

    def test_fail_rate_ignores_skips(self) -> None:
        stats = _only(
            [
                _run(),
                _run(outcome=Outcome.PASS, conclusion="success"),
                _run(outcome=Outcome.SKIP, conclusion="cancelled"),
                _run(outcome=Outcome.SKIP, conclusion="cancelled"),
            ]
        )
        assert (stats.runs, stats.failed, stats.passed, stats.skipped) == (4, 1, 1, 2)
        assert stats.fail_rate == 0.5

    def test_workflows_without_failures_are_not_listed(self) -> None:
        clean = _run(workflow_id=2, outcome=Outcome.PASS, conclusion="success")
        assert _only([_run(), clean]).workflow_id == 1

    def test_matrix_legs_collapse_into_one_job(self) -> None:
        jobs = (_job("Build (a)", "u1"), _job("Build (b)", "u2"))
        stats = _only([_run(failed_jobs=jobs)])
        assert stats.failing_jobs == (JobFailures("Build", 2, "u2"),)

    def test_matrix_legs_stay_apart_when_collapse_is_off(self) -> None:
        jobs = (_job("Build (a)"), _job("Build (b)"))
        options = WindowOptions(days=7, collapse_matrix=False)
        names = [
            job.name for job in _only([_run(failed_jobs=jobs)], options).failing_jobs
        ]
        assert names == ["Build (a)", "Build (b)"]

    def test_failing_jobs_sorted_by_count_then_name(self) -> None:
        older = _run(age=3, failed_jobs=(_job("Lint", "old"), _job("Build")))
        newer = _run(age=2, failed_jobs=(_job("Lint", "new"),))
        stats = _only([newer, older])
        assert [(j.name, j.count, j.last_url) for j in stats.failing_jobs] == [
            ("Lint", 2, "new"),
            ("Build", 1, ""),
        ]

    def test_unreadable_jobs_are_counted_not_listed(self) -> None:
        stats = _only([_run(failed_jobs=None), _run(failed_jobs=())])
        assert stats.jobs_unreadable == 1
        assert stats.failing_jobs == ()

    def test_last_failure_is_the_newest(self) -> None:
        newest = _run(age=1)
        stats = _only([_run(age=5), newest, _run(age=3)])
        assert stats.last_failure is newest

    def test_name_and_path_are_the_newest_seen(self) -> None:
        stats = _only(
            [
                _run(age=1, workflow_name="New", workflow_path="new.yaml"),
                _run(age=4, workflow_name="Old", workflow_path="old.yaml"),
            ]
        )
        assert (stats.workflow_name, stats.workflow_path) == ("New", "new.yaml")

    def test_retried_counts_records_marked_as_such(self) -> None:
        passed = _run(outcome=Outcome.PASS, conclusion="success", retried=True)
        assert _only([_run(), passed]).retried == 1

    def test_trigger_mappings_hold_only_non_zero_entries(self) -> None:
        stats = _only(
            [_run(), _run(trigger=Trigger.PULL_REQUEST, outcome=Outcome.PASS)]
        )
        assert dict(stats.runs_by_trigger) == {
            Trigger.PULL_REQUEST: 1,
            Trigger.MERGE: 1,
        }
        assert dict(stats.failures_by_trigger) == {Trigger.MERGE: 1}
        assert isinstance(stats.failures_by_trigger, MappingProxyType)

    def test_pattern_uses_the_window_thresholds(self) -> None:
        records = [_run(), _run(), _run(outcome=Outcome.PASS, conclusion="success")]
        assert _only(records).pattern == PATTERN_INTERMITTENT
        lax = WindowOptions(days=7, min_runs=4)
        assert _only(records, lax).pattern == PATTERN_INSUFFICIENT

    def test_sorted_by_failed_then_rate_then_repo_then_name(self) -> None:
        passed = {"outcome": Outcome.PASS, "conclusion": "success"}
        records = [
            _run(repo="b", workflow_id=1, workflow_name="Two fails"),
            _run(repo="b", workflow_id=1, workflow_name="Two fails"),
            _run(repo="b", workflow_id=1, workflow_name="Two fails", **passed),
            _run(repo="a", workflow_id=2, workflow_name="Diluted"),
            _run(repo="a", workflow_id=2, workflow_name="Diluted", **passed),
            _run(repo="a", workflow_id=3, workflow_name="Pure"),
            _run(repo="b", workflow_id=4, workflow_name="Also pure"),
        ]
        stats = workflow_stats(records, generated_at=NOW, options=WEEK)
        assert [(s.repo, s.workflow_name) for s in stats] == [
            ("b", "Two fails"),
            ("a", "Pure"),
            ("b", "Also pure"),
            ("a", "Diluted"),
        ]


class TestRepoStats:
    """Per-repository rollups, including the clean ones."""

    def test_repo_with_zero_failures_is_included(self) -> None:
        clean = _run(repo="clean", outcome=Outcome.PASS, conclusion="success")
        stats = repo_stats([clean], generated_at=NOW, options=WEEK)
        assert [(s.repo, s.failed, s.passed) for s in stats] == [("clean", 0, 1)]
        assert stats[0].worst is None
        assert stats[0].last_failure is None
        assert stats[0].fail_rate == 0.0

    def test_workflows_counts_distinct_failing_workflows(self) -> None:
        records = [
            _run(workflow_id=1),
            _run(workflow_id=1),
            _run(workflow_id=2),
            _run(workflow_id=3, outcome=Outcome.PASS, conclusion="success"),
        ]
        (stats,) = repo_stats(records, generated_at=NOW, options=WEEK)
        assert stats.workflows == 2
        assert (stats.runs, stats.failed, stats.passed) == (4, 3, 1)

    def test_worst_prefers_most_failures_then_rate_then_name(self) -> None:
        passed = {"outcome": Outcome.PASS, "conclusion": "success"}
        records = [
            _run(workflow_id=1, workflow_name="Zed"),
            _run(workflow_id=1, workflow_name="Zed"),
            _run(workflow_id=2, workflow_name="Alpha"),
            _run(workflow_id=2, workflow_name="Alpha"),
            _run(workflow_id=2, workflow_name="Alpha", **passed),
            _run(workflow_id=3, workflow_name="Beta"),
            _run(workflow_id=3, workflow_name="Beta"),
        ]
        (stats,) = repo_stats(records, generated_at=NOW, options=WEEK)
        assert stats.worst is not None
        # Zed and Beta tie on failures and rate; the name decides.
        assert stats.worst.workflow_name == "Beta"

    def test_last_failure_and_failures_by_trigger(self) -> None:
        newest = _run(age=1, trigger=Trigger.TAG)
        records = [_run(age=2), newest, _run(age=3, trigger=Trigger.PULL_REQUEST)]
        (stats,) = repo_stats(records, generated_at=NOW, options=WEEK)
        assert stats.last_failure is newest
        assert dict(stats.failures_by_trigger) == {
            Trigger.PULL_REQUEST: 1,
            Trigger.MERGE: 1,
            Trigger.TAG: 1,
        }

    def test_sorted_by_failed_then_rate_then_repo(self) -> None:
        passed = {"outcome": Outcome.PASS, "conclusion": "success"}
        records = [
            _run(repo="c"),
            _run(repo="c", **passed),
            _run(repo="b"),
            _run(repo="a"),
            _run(repo="a"),
            _run(repo="z", **passed),
        ]
        stats = repo_stats(records, generated_at=NOW, options=WEEK)
        assert [s.repo for s in stats] == ["a", "b", "c", "z"]
