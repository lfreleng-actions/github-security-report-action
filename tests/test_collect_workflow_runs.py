# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Tests for the per-organisation workflow-run collection.

Sync, GraphQL enrichment and pruning over the scripted GitHub of
``test_collect_run_sync.py``, plus the merge rule a re-read applies over a
stored record (kept here so that file stays within its size budget).
"""

from __future__ import annotations

import datetime as dt
import logging
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path

import pytest
from test_collect_run_sync import (
    DAY,
    NOW,
    FakeRunsClient,
    _fail,
    _rec,
    _repo,
    as_client,
)

from github_security_report.client import GraphBatchError
from github_security_report.client.workflow_runs import RunDrillDown
from github_security_report.collect.context import OrgCollectContext, RunSyncSummary
from github_security_report.collect.run_sync import RunSyncOptions, _merge
from github_security_report.collect.workflow_runs import (
    DRILL_DOWN_BATCH,
    WorkflowRunsResult,
    collect_workflow_runs,
)
from github_security_report.models import Repo
from github_security_report.workflow_runs import (
    FailedJob,
    Outcome,
    RunStore,
    Trigger,
    WorkflowRunRecord,
)

JOB = FailedJob("Build / test (3.12)", "failure", "https://example.test/job")


@pytest.fixture
def store(tmp_path: Path) -> Iterator[RunStore]:
    with RunStore(tmp_path / "runs.sqlite") as opened:
        yield opened


def _ctx(fake: FakeRunsClient) -> OrgCollectContext:
    return OrgCollectContext(
        client=as_client(fake),
        org="o",
        code_scanning={},
        dependabot={},
        secret={},
        sweep_status={},
        coverage={},
        graph={},
        probe_tools=(),
        probe_scorecard=False,
    )


class _Notices:
    """A CollectProgress that keeps the notices and sync summary it heard."""

    def __init__(self) -> None:
        self.shown: list[str | None] = []
        self.sync: RunSyncSummary | None = None

    def phase(self, name: str, *, repos: int | None = None) -> None:
        return None

    def repo_done(self) -> None:
        return None

    def notice(self, text: str | None) -> None:
        self.shown.append(text)

    def store_synced(self, summary: RunSyncSummary) -> None:
        self.sync = summary


async def _collect(
    fake: FakeRunsClient,
    store: RunStore,
    repos: list[Repo],
    *,
    options: RunSyncOptions = RunSyncOptions(
        window_days=30, retention_days=60, backfill_days=60
    ),
    progress: _Notices | None = None,
) -> WorkflowRunsResult:
    return await collect_workflow_runs(
        repos, _ctx(fake), store, now=NOW, options=options, progress=progress
    )


def _stored(store: RunStore, run_id: int) -> WorkflowRunRecord:
    return store.get_many([run_id])[run_id]


async def test_collection_reports_the_window_of_in_scope_repos(
    store: RunStore,
) -> None:
    """Records are the in-scope window; an unreadable repo is named unknown."""
    fake = FakeRunsClient()
    fake.runs["a"] = [
        _rec(id=1, repo="a"),
        _rec(id=2, repo="a", created_at=NOW - 45 * DAY),
    ]
    fake.runs["b"] = [_rec(id=3, repo="b")]
    fake.status["b"] = 403
    store.upsert([_rec(id=4, repo="c")])  # left over from a repo now out of scope
    result = await _collect(fake, store, [_repo("a"), _repo("b")])
    assert [r.id for r in result.records] == [1]
    assert result.unknown == frozenset({"b"})
    assert result.oldest == {"a": NOW - 60 * DAY, "b": None}
    assert sorted(sync.repo for sync in result.syncs) == ["a", "b"]
    assert store.count("a") == 2  # the window bounds the result, not the store


async def test_a_first_time_build_is_announced_for_as_long_as_it_lasts(
    store: RunStore,
) -> None:
    fake = FakeRunsClient()
    fake.runs["a"] = [_rec(id=1, repo="a")]
    progress = _Notices()
    await _collect(fake, store, [_repo("a"), _repo("b")], progress=progress)
    assert progress.shown == [
        "building the workflow-run store for the first time (60 days, 2 "
        "repositories); this one-off takes several minutes",
        None,
    ]
    assert progress.sync == RunSyncSummary(
        cold=True, repos=2, unchanged=0, unreadable=0, written=1, pruned=0
    )
    # Warm now: the next sync says nothing and writes nothing new.
    progress.shown.clear()
    await _collect(fake, store, [_repo("a"), _repo("b")], progress=progress)
    assert progress.shown == [None, None]
    assert progress.sync is not None
    assert not progress.sync.cold
    assert (progress.sync.repos, progress.sync.written) == (2, 0)


async def test_a_store_lacking_only_a_new_repository_is_not_cold(
    store: RunStore,
) -> None:
    fake = FakeRunsClient()
    await _collect(fake, store, [_repo("a")])
    progress = _Notices()
    await _collect(fake, store, [_repo("a"), _repo("new")], progress=progress)
    assert progress.shown == [None, None]


async def test_an_in_memory_store_is_never_a_first_time_build() -> None:
    # --no-run-cache and repo mode start from an empty store every time, so
    # announcing a one-off there would announce it on every run.
    fake = FakeRunsClient()
    fake.runs["a"] = [_rec(id=1, repo="a")]
    progress = _Notices()
    with RunStore(Path(":memory:")) as store:
        assert not store.persistent
        await _collect(fake, store, [_repo("a"), _repo("b")], progress=progress)
    assert progress.shown == [None, None]
    assert progress.sync is not None
    assert not progress.sync.cold


async def test_a_forced_refresh_is_announced_too(store: RunStore) -> None:
    fake = FakeRunsClient()
    await _collect(fake, store, [_repo("a")])
    progress = _Notices()
    await _collect(
        fake,
        store,
        [_repo("a")],
        options=RunSyncOptions(
            window_days=30, retention_days=60, backfill_days=60, refresh=True
        ),
        progress=progress,
    )
    assert progress.shown[0] == (
        "re-reading every repository's workflow runs (60 days, 1 repository)"
    )


async def test_enrichment_names_the_failing_jobs_in_batches(store: RunStore) -> None:
    """Unenriched failures are drilled down fifty at a time and updated.

    A drill-down that could not read a node leaves its record awaiting the
    next run; a record with no node id, or a GitHub-managed workflow, is not
    asked about at all.
    """
    fake = FakeRunsClient()
    failures = [
        _fail(id=i, created_at=NOW - dt.timedelta(hours=i)) for i in range(1, 61)
    ]
    failures[0] = _fail(
        id=1, trigger=Trigger.BRANCH, ref_name="v2.0", created_at=NOW - DAY
    )
    fake.runs["r"] = [
        *failures,
        _fail(
            id=61,
            trigger=Trigger.DYNAMIC,
            workflow_path="dynamic/dependabot/dependabot-updates",
        ),
        _fail(id=62, node_id=""),
    ]
    for record in failures[:-1]:
        fake.drill[record.node_id] = RunDrillDown(
            node_id=record.node_id,
            failed_jobs=(JOB,),
            workflow_name="Renamed",
            ref_is_tag=record.id == 1,
        )
    fake.drill["WFR_60"] = RunDrillDown(node_id="WFR_60", failed_jobs=None)
    await _collect(fake, store, [_repo()])
    assert sorted(fake.job_batches) == [10, DRILL_DOWN_BATCH]
    assert "WFR_61" not in fake.job_ids and "" not in fake.job_ids
    tagged = _stored(store, 1)
    assert (tagged.failed_jobs, tagged.workflow_name) == ((JOB,), "Renamed")
    assert (tagged.trigger, tagged.ref_is_tag) == (Trigger.TAG, True)
    assert _stored(store, 2).trigger is Trigger.MERGE
    assert _stored(store, 60).failed_jobs is None
    assert _stored(store, 61).failed_jobs is None
    assert _stored(store, 62).failed_jobs is None
    assert sorted(r.id for r in store.needing_enrichment()) == [60, 61, 62]


async def test_dynamic_failures_are_enriched_only_on_request(
    store: RunStore,
) -> None:
    """``include_dynamic`` brings GitHub-managed workflows into the drill-down."""
    fake = FakeRunsClient()
    fake.runs["r"] = [
        _fail(
            id=1, trigger=Trigger.DYNAMIC, workflow_path="dynamic/github-code-scanning"
        )
    ]
    fake.drill["WFR_1"] = RunDrillDown(node_id="WFR_1", failed_jobs=(JOB,))
    await _collect(fake, store, [_repo()])
    assert fake.job_batches == []
    await _collect(fake, store, [_repo()], options=RunSyncOptions(include_dynamic=True))
    assert fake.job_batches == [1]
    assert _stored(store, 1).failed_jobs == (JOB,)


async def test_a_refused_drill_down_is_logged_not_raised(
    store: RunStore, caplog: pytest.LogCaptureFixture
) -> None:
    """A drill-down GitHub refuses outright leaves the jobs unread, with a warning."""
    fake = FakeRunsClient()
    fake.runs["r"] = [_fail(id=1), _fail(id=2, created_at=NOW - 2 * DAY)]
    fake.jobs_error = GraphBatchError("forbidden", status=403, splittable=False)
    with caplog.at_level(
        logging.WARNING, logger="github_security_report.collect.workflow_runs"
    ):
        result = await _collect(fake, store, [_repo()])
    assert [r.failed_jobs for r in result.records] == [None, None]
    assert result.unknown == frozenset()
    warnings = [
        r
        for r in caplog.records
        if r.levelno == logging.WARNING and r.name.endswith("collect.workflow_runs")
    ]
    assert len(warnings) == 1
    assert "2 workflow runs in o left unread: HTTP 403" in warnings[0].getMessage()


async def test_collection_prunes_past_retention(store: RunStore) -> None:
    """A run older than ``retention_days`` is dropped; one inside is kept."""
    fake = FakeRunsClient()
    fake.runs["r"] = [
        _rec(id=1, created_at=NOW - 10 * DAY),
        _rec(id=2, created_at=NOW - 45 * DAY),
    ]
    options = RunSyncOptions(window_days=30, retention_days=30, backfill_days=60)
    await _collect(fake, store, [_repo()], options=options)
    assert [r.id for r in store.records()] == [1]


def test_merge_keeps_enrichment_while_outcome_and_attempt_hold() -> None:
    """Failing jobs survive a re-read of the same failure, not a new attempt.

    The truncation mark travels with them: a listing re-read knows nothing
    of jobs, so it must not quietly clear the partial-list warning either.
    """
    held = replace(_fail(id=1, failed_jobs=(JOB,)), jobs_truncated=True)
    same = _merge(held, _fail(id=1))
    assert (same.failed_jobs, same.jobs_truncated) == ((JOB,), True)
    later = _merge(held, _fail(id=1, attempt=2))
    assert (later.failed_jobs, later.jobs_truncated) == (None, False)


def test_merge_marks_a_failure_reread_as_a_pass_retried() -> None:
    """A stored failure that now passes is the retry the reconciliation seeks."""
    merged = _merge(_fail(id=1), _rec(id=1, attempt=2))
    assert (merged.outcome, merged.retried) == (Outcome.PASS, True)


def test_merge_keeps_a_settled_tag() -> None:
    """The listing cannot see a tag, so a settled TAG survives a BRANCH re-read."""
    held = _fail(id=1, trigger=Trigger.TAG, ref_name="v1.0", ref_is_tag=True)
    fresh = _fail(id=1, trigger=Trigger.BRANCH, ref_name="v1.0")
    merged = _merge(held, fresh)
    assert (merged.trigger, merged.ref_is_tag) == (Trigger.TAG, True)


def test_merge_without_an_existing_record_is_the_fresh_one() -> None:
    """Nothing held means nothing to carry forward."""
    fresh = _fail(id=1)
    assert _merge(None, fresh) is fresh
