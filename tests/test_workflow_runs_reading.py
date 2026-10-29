# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Tests for the post-merge *reading* of a workflow's window statistics."""

from __future__ import annotations

import datetime as dt

import pytest

from github_security_report.workflow_runs import (
    READING_EVERYWHERE,
    READING_NO_PR_RUNS,
    READING_OTHER,
    READING_POST_MERGE_ONLY,
    Outcome,
    Trigger,
    WindowOptions,
    WorkflowRunRecord,
    workflow_stats,
)

UTC = dt.timezone.utc
NOW = dt.datetime(2026, 3, 1, 12, 0, 0, tzinfo=UTC)
WEEK = WindowOptions(days=7)

_counter = iter(range(1, 10_000))


def _run(trigger: Trigger, outcome: Outcome) -> WorkflowRunRecord:
    """One run of the single workflow under test, on a trigger with an outcome."""
    run_id = next(_counter)
    return WorkflowRunRecord(
        id=run_id,
        node_id=f"WFR_{run_id}",
        repo="r",
        workflow_id=1,
        workflow_name="CI",
        workflow_path=".github/workflows/ci.yaml",
        event="",
        trigger=trigger,
        ref_name="",
        outcome=outcome,
        conclusion="success" if outcome is Outcome.PASS else "failure",
        attempt=1,
        created_at=NOW - dt.timedelta(hours=run_id),
        html_url="",
    )


def _reading(*runs: tuple[Trigger, Outcome]) -> str:
    """The reading of a workflow that had exactly these runs in the window."""
    records = [_run(trigger, outcome) for trigger, outcome in runs]
    (stats,) = workflow_stats(records, generated_at=NOW, options=WEEK)
    return stats.reading


PASS = Outcome.PASS
FAIL = Outcome.FAIL


@pytest.mark.parametrize(
    ("runs", "expected"),
    [
        # Merge fails while every pull-request run passed.
        (
            ((Trigger.MERGE, FAIL), (Trigger.PULL_REQUEST, PASS)),
            READING_POST_MERGE_ONLY,
        ),
        # A tag failure is post-merge too; a skipped PR run still counts as a
        # PR run the workflow had.
        (
            ((Trigger.TAG, FAIL), (Trigger.PULL_REQUEST, Outcome.SKIP)),
            READING_POST_MERGE_ONLY,
        ),
        # Merge fails and the workflow never ran on a pull request.
        (((Trigger.MERGE, FAIL), (Trigger.SCHEDULE, PASS)), READING_NO_PR_RUNS),
        # A single pull-request failure outranks everything else.
        (
            ((Trigger.MERGE, FAIL), (Trigger.PULL_REQUEST, FAIL)),
            READING_EVERYWHERE,
        ),
        (((Trigger.PULL_REQUEST, FAIL),), READING_EVERYWHERE),
        # Failures only on triggers the reading does not interpret.
        (((Trigger.SCHEDULE, FAIL), (Trigger.PULL_REQUEST, PASS)), READING_OTHER),
        (((Trigger.BRANCH, FAIL), (Trigger.MANUAL, FAIL)), READING_OTHER),
    ],
    ids=[
        "post-merge-only",
        "post-merge-only-tag",
        "no-pr-runs",
        "everywhere",
        "everywhere-pr-only",
        "other-schedule",
        "other-branch-manual",
    ],
)
def test_reading(runs: tuple[tuple[Trigger, Outcome], ...], expected: str) -> None:
    """Each of the four readings, from the runs that produce it."""
    assert _reading(*runs) == expected
