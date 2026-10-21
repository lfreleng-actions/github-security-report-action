# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Tests for one repository's incremental run sync, against a scripted GitHub.

:class:`FakeRunsClient` holds the truth GitHub would hold and answers the
three reads the collector makes, with the listing semantics that matter to the
sync: the ``status`` and ``created`` filters, the stop-at-watermark walk, the
pagination ceiling and conditional requests. It is shared with
``test_collect_workflow_runs.py``.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import cast

import pytest

from github_security_report.client import GraphBatchError
from github_security_report.client.workflow_runs import (
    RUN_LISTING_CAP,
    RunDrillDown,
    RunListing,
)
from github_security_report.collect.protocols import ClientProtocol
from github_security_report.collect.run_sync import (
    RepoRunSync,
    RepoSync,
    RunSyncOptions,
)
from github_security_report.models import Repo
from github_security_report.workflow_runs import (
    Outcome,
    RepoSyncState,
    RunStore,
    Trigger,
    WorkflowRunRecord,
)

NOW = dt.datetime(2026, 10, 21, 12, tzinfo=dt.timezone.utc)
DAY = dt.timedelta(days=1)


def _repo(name: str = "r") -> Repo:
    return Repo(name, f"o/{name}", f"https://github.com/o/{name}")


def _rec(**overrides: object) -> WorkflowRunRecord:
    """A record with sane defaults: a passing merge run from yesterday."""
    run_id = int(cast(int, overrides.pop("id", 1)))
    fields: dict[str, object] = {
        "id": run_id,
        "node_id": f"WFR_{run_id}",
        "repo": "r",
        "workflow_id": 1,
        "workflow_name": "Testing",
        "workflow_path": ".github/workflows/testing.yaml",
        "event": "push",
        "trigger": Trigger.MERGE,
        "ref_name": "main",
        "outcome": Outcome.PASS,
        "conclusion": "success",
        "attempt": 1,
        "created_at": NOW - DAY,
        "html_url": f"https://github.com/o/r/actions/runs/{run_id}",
    }
    fields.update(overrides)
    return WorkflowRunRecord(**fields)  # type: ignore[arg-type]


def _fail(**overrides: object) -> WorkflowRunRecord:
    """A failed record, a plain ``failure`` unless the conclusion is given."""
    return _rec(**{"outcome": Outcome.FAIL, "conclusion": "failure", **overrides})


def _pending(**overrides: object) -> WorkflowRunRecord:
    """A record GitHub had not concluded when it was read."""
    return _rec(**{"outcome": Outcome.PENDING, "conclusion": "", **overrides})


def _created_bounds(created: str) -> tuple[dt.date, dt.date]:
    """The inclusive date range a ``created`` filter names."""
    first, _, last = created.removeprefix(">=").partition("..")
    return dt.date.fromisoformat(first), (
        dt.date.fromisoformat(last) if last else dt.date.max
    )


@dataclass(frozen=True)
class ListingCall:
    """One ``workflow_runs`` call as the sync made it."""

    repo: str
    params: Mapping[str, object] | None
    stop_before: dt.datetime | None
    etag: str | None

    @property
    def created(self) -> str | None:
        """The ``created`` filter, if the call carried one."""
        value = (self.params or {}).get("created")
        return None if value is None else str(value)


class FakeRunsClient:
    """Scripted GitHub: the truth per repository, newest first, plus knobs."""

    def __init__(self) -> None:
        self.runs: dict[str, list[WorkflowRunRecord]] = {}
        self.calls: list[ListingCall] = []
        self.rereads: list[int] = []
        self.status: dict[str, int] = {}
        self.drill: dict[str, RunDrillDown] = {}
        self.job_batches: list[int] = []
        self.job_ids: set[str] = set()
        self.jobs_error: GraphBatchError | None = None

    def _matching(
        self, repo: str, params: Mapping[str, object] | None
    ) -> list[WorkflowRunRecord]:
        records = sorted(
            self.runs.get(repo, []), key=lambda r: r.created_at, reverse=True
        )
        params = params or {}
        status = params.get("status")
        if status is not None:
            records = [r for r in records if r.conclusion == status]
        created = params.get("created")
        if created is not None:
            first, last = _created_bounds(str(created))
            records = [r for r in records if first <= r.created_at.date() <= last]
        return records

    @staticmethod
    def _etag(
        repo: str,
        params: Mapping[str, object] | None,
        matching: list[WorkflowRunRecord],
    ) -> str:
        ids = ",".join(str(r.id) for r in matching)
        return f'W/"{repo}:{sorted((params or {}).items())}:{ids}"'

    async def workflow_runs(
        self,
        org: str,
        repo: str,
        *,
        default_branch: str,
        params: dict[str, object] | None = None,
        stop_before: dt.datetime | None = None,
        etag: str | None = None,
    ) -> RunListing:
        self.calls.append(ListingCall(repo, params, stop_before, etag))
        if repo in self.status:
            return RunListing(status=self.status[repo])
        matching = self._matching(repo, params)
        current = self._etag(repo, params, matching)
        if etag is not None and etag == current:
            return RunListing(status=304, etag=current)
        records: list[WorkflowRunRecord] = []
        stopped = False
        for record in matching:
            if len(records) >= RUN_LISTING_CAP:
                break
            if stop_before is not None and record.created_at < stop_before:
                stopped = True
                break
            records.append(record)
        return RunListing(
            status=200,
            records=tuple(records),
            etag=current,
            stopped=stopped,
            capped=not stopped and len(records) >= RUN_LISTING_CAP,
        )

    async def workflow_run(
        self, org: str, repo: str, run_id: int, *, default_branch: str
    ) -> WorkflowRunRecord | None:
        self.rereads.append(run_id)
        return next((r for r in self.runs.get(repo, []) if r.id == run_id), None)

    async def workflow_run_jobs(
        self, org: str, node_ids: list[str]
    ) -> dict[str, RunDrillDown]:
        self.job_batches.append(len(node_ids))
        self.job_ids.update(node_ids)
        if self.jobs_error is not None:
            raise self.jobs_error
        return {
            nid: self.drill.get(nid, RunDrillDown(node_id=nid, failed_jobs=None))
            for nid in node_ids
        }


def as_client(fake: FakeRunsClient) -> ClientProtocol:
    """The fake as the protocol the collector takes (it implements a subset)."""
    return cast(ClientProtocol, fake)


@pytest.fixture
def store(tmp_path: Path) -> Iterator[RunStore]:
    with RunStore(tmp_path / "runs.sqlite") as opened:
        yield opened


async def _sync(
    client: FakeRunsClient,
    store: RunStore,
    *,
    options: RunSyncOptions = RunSyncOptions(backfill_days=30),
) -> RepoRunSync:
    sync = RepoSync(as_client(client), store, "o", _repo(), now=NOW, options=options)
    return await sync.run()


def _stored(store: RunStore, run_id: int) -> WorkflowRunRecord:
    return store.get_many([run_id])[run_id]


def _warm(store: RunStore, *records: WorkflowRunRecord) -> None:
    """A store that has synced before: ``records`` held, watermark a day ago."""
    store.upsert(records)
    store.set_sync_state(RepoSyncState("r", watermark=NOW - DAY, oldest=NOW - 30 * DAY))


async def test_cold_sync_backfills_to_depth_and_records_state(store: RunStore) -> None:
    """A never-seen repo is read back to ``backfill_days``; state is written."""
    client = FakeRunsClient()
    client.runs["r"] = [
        _rec(id=1, created_at=NOW - DAY),
        _rec(id=2, created_at=NOW - 5 * DAY),
        _rec(id=3, created_at=NOW - 40 * DAY),
    ]
    result = await _sync(client, store)
    assert (result.status, result.written, result.readable) == (200, 2, True)
    assert sorted(r.id for r in store.records("r")) == [1, 2]
    assert len(client.calls) == 1
    assert client.calls[0].stop_before == NOW - 30 * DAY
    assert client.calls[0].etag is None
    state = store.sync_state("r")
    assert state.watermark == NOW - DAY
    assert state.etag is not None
    assert state.oldest == NOW - 30 * DAY
    assert state.last_sync_at == NOW


async def test_warm_sync_of_an_unchanged_listing_costs_a_304(store: RunStore) -> None:
    """The second sync presents the stored ETag, gets 304 and writes nothing.

    An unchanged first page means nothing was created, re-run or concluded
    among the newest runs, so the failure list is not re-read either: the
    whole sync is the one free conditional request.
    """
    client = FakeRunsClient()
    client.runs["r"] = [_rec(id=1), _rec(id=2, created_at=NOW - 5 * DAY)]
    await _sync(client, store)
    before = store.sync_state("r")
    calls_before = len(client.calls)
    result = await _sync(client, store)
    assert (result.status, result.written, result.readable) == (304, 0, True)
    assert len(client.calls) == calls_before + 1
    call = client.calls[-1]
    assert (call.etag, call.stop_before) == (before.etag, before.watermark)
    after = store.sync_state("r")
    assert (after.watermark, after.etag) == (before.watermark, before.etag)
    assert after.failures_etag is None  # never read: the listing never moved


async def test_warm_sync_stops_at_the_watermark(store: RunStore) -> None:
    """New runs are read down to the watermark; older ones are not re-read.

    The walk stops at the first run *older* than the watermark, so the run at
    the watermark itself is re-read; the one before it is not.
    """
    client = FakeRunsClient()
    client.runs["r"] = [_rec(id=1), _rec(id=2, created_at=NOW - 2 * DAY)]
    await _sync(client, store)
    client.runs["r"] = [
        _rec(id=10, created_at=NOW - dt.timedelta(hours=6)),
        _rec(id=11, created_at=NOW - dt.timedelta(hours=12)),
        *client.runs["r"],
    ]
    result = await _sync(client, store)
    assert client.calls[1].stop_before == NOW - DAY
    assert (result.status, result.written) == (200, 3)
    assert store.count("r") == 4
    assert store.sync_state("r").watermark == NOW - dt.timedelta(hours=6)


async def test_reconciliation_finds_a_failure_that_passed_on_rerun(
    store: RunStore,
) -> None:
    """A stored failure missing from the failure list is re-read as a retry.

    A startup_failure is never in a ``status=failure`` list, so its absence
    says nothing and it is left alone.
    """
    startup = _fail(id=2, created_at=NOW - 4 * DAY, conclusion="startup_failure")
    _warm(store, _fail(id=1, created_at=NOW - 3 * DAY), startup)
    client = FakeRunsClient()
    client.runs["r"] = [
        _rec(id=3),
        _rec(id=1, attempt=2, created_at=NOW - 3 * DAY),
        startup,
    ]
    result = await _sync(client, store)
    assert client.rereads == [1]
    assert result.rereads == 1
    rerun = _stored(store, 1)
    assert (rerun.outcome, rerun.attempt, rerun.retried) == (Outcome.PASS, 2, True)
    assert _stored(store, 2) == startup


async def test_pending_runs_are_reread_until_they_conclude(store: RunStore) -> None:
    """A pending run that concluded is updated; one GitHub cannot show stays."""
    _warm(
        store,
        _pending(id=1, created_at=NOW - 2 * DAY),
        _pending(id=2, created_at=NOW - 3 * DAY),
    )
    client = FakeRunsClient()
    client.runs["r"] = [_rec(id=3), _rec(id=1, created_at=NOW - 2 * DAY)]
    result = await _sync(client, store)
    assert sorted(client.rereads) == [1, 2]
    assert result.rereads == 2
    assert _stored(store, 1).outcome is Outcome.PASS
    assert _stored(store, 2).outcome is Outcome.PENDING


async def test_reconciliation_writes_a_pending_run_that_failed(
    store: RunStore,
) -> None:
    """A run stored pending that now lists as a failure is written from the list."""
    _warm(store, _pending(id=1, created_at=NOW - 2 * DAY))
    client = FakeRunsClient()
    client.runs["r"] = [_fail(id=1, created_at=NOW - 2 * DAY)]
    await _sync(client, store)
    assert _stored(store, 1).outcome is Outcome.FAIL
    assert client.rereads == []
    assert client.calls[1].params == {"status": "failure", "created": ">=2026-07-23"}


async def test_capped_backfill_is_completed_in_date_slices(store: RunStore) -> None:
    """More runs than one listing shows are read in date slices and deduped."""
    client = FakeRunsClient()
    client.runs["r"] = [
        _rec(id=i, created_at=NOW - dt.timedelta(minutes=12 * i)) for i in range(1200)
    ]
    result = await _sync(client, store)
    assert result.status == 200
    assert store.count("r") == 1200
    assert any(
        call.created is not None and ".." in call.created for call in client.calls
    )
    assert store.sync_state("r").watermark == NOW


async def test_a_slice_that_still_caps_is_halved(store: RunStore) -> None:
    """A 7-day slice hitting the ceiling is retried at 3 days, then 1."""
    client = FakeRunsClient()
    client.runs["r"] = [
        _rec(id=i, created_at=NOW - dt.timedelta(seconds=43 * i)) for i in range(1000)
    ] + [
        _rec(id=2000 + i, created_at=NOW - 5 * DAY - dt.timedelta(minutes=i))
        for i in range(150)
    ]
    await _sync(client, store, options=RunSyncOptions(backfill_days=10))
    ranges = [call.created for call in client.calls if call.created is not None]
    assert ranges[:3] == [
        "2026-10-14..2026-10-21",
        "2026-10-18..2026-10-21",
        "2026-10-20..2026-10-21",
    ]
    assert store.count("r") == 1150


async def test_an_unreadable_listing_leaves_the_store_untouched(
    store: RunStore,
) -> None:
    """A 403 marks the repo unreadable; nothing is written, no state is kept."""
    client = FakeRunsClient()
    client.runs["r"] = [_rec(id=1)]
    client.status["r"] = 403
    result = await _sync(client, store)
    assert (result.status, result.readable, result.written) == (403, False, 0)
    assert store.count("r") == 0
    assert store.sync_state("r") == RepoSyncState("r")


async def test_refresh_rereads_from_scratch(store: RunStore) -> None:
    """``refresh`` ignores the watermark and ETag and backfills again."""
    client = FakeRunsClient()
    client.runs["r"] = [_rec(id=1), _rec(id=2, created_at=NOW - 5 * DAY)]
    await _sync(client, store)
    result = await _sync(
        client, store, options=RunSyncOptions(backfill_days=30, refresh=True)
    )
    first = client.calls[-1]
    assert (first.etag, first.stop_before) == (None, NOW - 30 * DAY)
    assert (result.status, result.written) == (200, 2)
