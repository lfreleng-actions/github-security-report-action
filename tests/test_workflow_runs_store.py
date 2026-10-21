# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Tests for the per-organisation SQLite run store."""

from __future__ import annotations

import datetime as dt
import sqlite3
from collections.abc import Iterator
from contextlib import closing
from dataclasses import replace
from pathlib import Path

import pytest

from github_security_report.workflow_runs import (
    FailedJob,
    Outcome,
    RepoSyncState,
    RunStore,
    Trigger,
    WorkflowRunRecord,
    store_path,
)

UTC = dt.timezone.utc
T0 = dt.datetime(2026, 3, 1, 12, 0, 0, tzinfo=UTC)


def _record(
    run_id: int,
    *,
    repo: str = "org/alpha",
    created_at: dt.datetime = T0,
    outcome: Outcome = Outcome.PASS,
    conclusion: str = "success",
    failed_jobs: tuple[FailedJob, ...] | None = None,
    ref_is_tag: bool | None = None,
    retried: bool = False,
) -> WorkflowRunRecord:
    """A record with every field set, varying only what a test cares about."""
    return WorkflowRunRecord(
        id=run_id,
        node_id=f"WFR_{run_id}",
        repo=repo,
        workflow_id=7,
        workflow_name="CI",
        workflow_path=".github/workflows/ci.yaml",
        event="push",
        trigger=Trigger.MERGE,
        ref_name="main",
        outcome=outcome,
        conclusion=conclusion,
        attempt=1,
        created_at=created_at,
        html_url=f"https://github.com/{repo}/actions/runs/{run_id}",
        failed_jobs=failed_jobs,
        ref_is_tag=ref_is_tag,
        retried=retried,
    )


@pytest.fixture
def store(tmp_path: Path) -> Iterator[RunStore]:
    """An open, empty store under the test's temp dir."""
    with RunStore(tmp_path / "runs.sqlite") as opened:
        yield opened


class TestStorePath:
    def test_layout_under_cache_dir(self, tmp_path: Path) -> None:
        path = store_path(tmp_path, "api.github.com", "lfreleng-actions")
        assert path == tmp_path / "api.github.com" / "lfreleng-actions" / "runs.sqlite"

    def test_hostile_components_cannot_escape(self, tmp_path: Path) -> None:
        path = store_path(tmp_path, "../evil", "../../etc")
        assert path.is_relative_to(tmp_path)
        assert path.parts[-3:] == ("evil", "etc", "runs.sqlite")

    def test_wholly_unsafe_component_still_yields_a_name(self, tmp_path: Path) -> None:
        # ".." strips to nothing; the placeholder keeps the layout intact.
        path = store_path(tmp_path, "..", "org")
        assert path == tmp_path / "_" / "org" / "runs.sqlite"


class TestRoundTrip:
    def test_full_record_round_trips_exactly(self, store: RunStore) -> None:
        full = _record(
            1,
            outcome=Outcome.FAIL,
            conclusion="failure",
            failed_jobs=(FailedJob("Lint / ruff", "failure", "https://x/1"),),
            ref_is_tag=True,
            retried=True,
            created_at=dt.datetime(2026, 3, 1, 12, 0, 0, 123456, tzinfo=UTC),
        )
        assert store.upsert([full]) == 1
        assert store.records() == [full]

    def test_minimal_record_round_trips_exactly(self, store: RunStore) -> None:
        minimal = _record(1)
        store.upsert([minimal])
        (back,) = store.records()
        assert back == minimal
        assert back.failed_jobs is None
        assert back.ref_is_tag is None
        assert back.retried is False

    def test_empty_failed_jobs_is_distinct_from_none(self, store: RunStore) -> None:
        store.upsert([_record(1, failed_jobs=()), _record(2, failed_jobs=None)])
        by_id = {r.id: r for r in store.records()}
        assert by_id[1].failed_jobs == ()
        assert by_id[2].failed_jobs is None

    def test_ref_is_tag_false_is_distinct_from_none(self, store: RunStore) -> None:
        store.upsert([_record(1, ref_is_tag=False), _record(2, ref_is_tag=None)])
        by_id = {r.id: r for r in store.records()}
        assert by_id[1].ref_is_tag is False
        assert by_id[2].ref_is_tag is None

    def test_created_at_comes_back_aware_utc(self, store: RunStore) -> None:
        store.upsert([_record(1)])
        (back,) = store.records()
        assert back.created_at.utcoffset() == dt.timedelta(0)

    def test_non_utc_offset_is_normalised_to_the_same_instant(
        self, store: RunStore
    ) -> None:
        plus_two = dt.timezone(dt.timedelta(hours=2))
        local = T0.astimezone(plus_two)
        store.upsert([_record(1, created_at=local)])
        (back,) = store.records()
        assert back.created_at == T0

    def test_persists_across_reopen(self, tmp_path: Path) -> None:
        path = tmp_path / "runs.sqlite"
        with RunStore(path) as first:
            first.upsert([_record(1)])
        with RunStore(path) as second:
            assert second.count() == 1
            assert second.path == path


class TestNaiveDatetimes:
    def test_naive_created_at_is_rejected(self, store: RunStore) -> None:
        naive = _record(1, created_at=dt.datetime(2026, 3, 1, 12))
        with pytest.raises(ValueError, match="timezone-aware"):
            store.upsert([naive])
        assert store.count() == 0

    def test_naive_since_is_rejected(self, store: RunStore) -> None:
        with pytest.raises(ValueError, match="timezone-aware"):
            store.records(since=dt.datetime(2026, 3, 1))

    def test_naive_sync_state_is_rejected(self, store: RunStore) -> None:
        with pytest.raises(ValueError, match="timezone-aware"):
            store.set_sync_state(
                RepoSyncState(repo="org/alpha", watermark=dt.datetime(2026, 3, 1))
            )


class TestQueries:
    def test_ordered_newest_first_then_highest_id(self, store: RunStore) -> None:
        early = T0 - dt.timedelta(hours=1)
        store.upsert(
            [
                _record(1, created_at=early),
                _record(2, created_at=T0),
                _record(3, created_at=T0),
            ]
        )
        assert [r.id for r in store.records()] == [3, 2, 1]

    def test_since_is_an_inclusive_lower_bound(self, store: RunStore) -> None:
        store.upsert(
            [
                _record(1, created_at=T0 - dt.timedelta(seconds=1)),
                _record(2, created_at=T0),
                _record(3, created_at=T0 + dt.timedelta(seconds=1)),
            ]
        )
        assert [r.id for r in store.records(since=T0)] == [3, 2]

    def test_repo_filter(self, store: RunStore) -> None:
        store.upsert([_record(1, repo="org/alpha"), _record(2, repo="org/beta")])
        assert [r.id for r in store.records("org/beta")] == [2]
        assert store.count("org/alpha") == 1
        assert store.count() == 2

    def test_needing_enrichment_is_fail_without_jobs(self, store: RunStore) -> None:
        store.upsert(
            [
                _record(1, outcome=Outcome.FAIL, conclusion="failure"),
                _record(2, outcome=Outcome.FAIL, conclusion="failure", failed_jobs=()),
                _record(3, outcome=Outcome.PASS),
                _record(4, outcome=Outcome.FAIL, conclusion="failure", repo="o/b"),
            ]
        )
        assert [r.id for r in store.needing_enrichment()] == [4, 1]
        assert [r.id for r in store.needing_enrichment("org/alpha")] == [1]

    def test_pending(self, store: RunStore) -> None:
        store.upsert(
            [
                _record(1, outcome=Outcome.PENDING, conclusion=""),
                _record(2, outcome=Outcome.PASS),
                _record(
                    3,
                    outcome=Outcome.PENDING,
                    conclusion="",
                    created_at=T0 - dt.timedelta(days=2),
                ),
            ]
        )
        assert [r.id for r in store.pending()] == [1, 3]
        assert [r.id for r in store.pending(since=T0 - dt.timedelta(days=1))] == [1]

    def test_failures_scoped_to_repo_and_window(self, store: RunStore) -> None:
        old = T0 - dt.timedelta(days=30)
        store.upsert(
            [
                _record(1, outcome=Outcome.FAIL, conclusion="failure"),
                _record(2, outcome=Outcome.FAIL, conclusion="failure", created_at=old),
                _record(3, outcome=Outcome.SKIP, conclusion="cancelled"),
                _record(4, outcome=Outcome.FAIL, conclusion="failure", repo="o/b"),
            ]
        )
        since = T0 - dt.timedelta(days=7)
        assert [r.id for r in store.failures("org/alpha", since=since)] == [1]


class TestUpsert:
    def test_same_id_replaces_the_whole_record(self, store: RunStore) -> None:
        store.upsert(
            [
                _record(
                    1,
                    outcome=Outcome.FAIL,
                    conclusion="failure",
                    failed_jobs=(FailedJob("a", "failure", "u"),),
                )
            ]
        )
        rerun = _record(1, outcome=Outcome.PASS, conclusion="success", retried=True)
        assert store.upsert([rerun]) == 1
        assert store.records() == [rerun]
        assert store.count() == 1

    def test_empty_iterable_writes_nothing(self, store: RunStore) -> None:
        assert store.upsert([]) == 0
        assert store.count() == 0

    def test_a_bad_record_fails_the_whole_batch(self, store: RunStore) -> None:
        # Atomic per call: a naive datetime in the batch leaves nothing behind.
        bad = _record(2, created_at=dt.datetime(2026, 3, 1))
        with pytest.raises(ValueError):
            store.upsert([_record(1), bad])
        assert store.count() == 0


class TestHousekeeping:
    def test_prune_removes_only_older_and_reports_count(self, store: RunStore) -> None:
        cutoff = T0 - dt.timedelta(days=90)
        store.upsert(
            [
                _record(1, created_at=cutoff - dt.timedelta(seconds=1)),
                _record(2, created_at=cutoff),
                _record(3, created_at=T0),
            ]
        )
        assert store.prune(before=cutoff) == 1
        assert [r.id for r in store.records()] == [3, 2]
        assert store.prune(before=cutoff) == 0

    def test_forget_drops_one_repo_only(self, store: RunStore) -> None:
        store.upsert([_record(1, repo="org/alpha"), _record(2, repo="org/beta")])
        store.set_sync_state(RepoSyncState(repo="org/alpha", etag='"a"'))
        store.set_sync_state(RepoSyncState(repo="org/beta", etag='"b"'))
        store.forget("org/alpha")
        assert [r.id for r in store.records()] == [2]
        assert store.synced_repos() == ["org/beta"]
        assert store.sync_state("org/alpha") == RepoSyncState(repo="org/alpha")

    def test_clear_drops_everything(self, store: RunStore) -> None:
        store.upsert([_record(1), _record(2, repo="org/beta")])
        store.set_sync_state(RepoSyncState(repo="org/alpha"))
        store.clear()
        assert store.count() == 0
        assert store.synced_repos() == []


class TestSyncState:
    def test_unknown_repo_gets_a_blank_state(self, store: RunStore) -> None:
        assert store.sync_state("org/never") == RepoSyncState(repo="org/never")
        assert store.synced_repos() == []

    def test_round_trip_and_upsert(self, store: RunStore) -> None:
        state = RepoSyncState(
            repo="org/alpha",
            watermark=T0,
            etag='W/"abc"',
            failures_etag='W/"def"',
            oldest=T0 - dt.timedelta(days=400),
            last_sync_at=T0 + dt.timedelta(minutes=5),
        )
        store.set_sync_state(state)
        assert store.sync_state("org/alpha") == state
        newer = replace(state, watermark=T0 + dt.timedelta(hours=1), etag=None)
        store.set_sync_state(newer)
        assert store.sync_state("org/alpha") == newer
        assert store.synced_repos() == ["org/alpha"]

    def test_synced_repos_sorted(self, store: RunStore) -> None:
        for repo in ("org/zeta", "org/alpha", "org/mid"):
            store.set_sync_state(RepoSyncState(repo=repo))
        assert store.synced_repos() == ["org/alpha", "org/mid", "org/zeta"]


class TestSchemaVersion:
    def test_mismatch_drops_the_cache(self, tmp_path: Path) -> None:
        path = tmp_path / "runs.sqlite"
        with RunStore(path) as first:
            first.upsert([_record(1)])
            first.set_sync_state(RepoSyncState(repo="org/alpha", etag='"x"'))
        with closing(sqlite3.connect(path)) as raw:
            raw.execute("PRAGMA user_version = 99")
            raw.commit()
        with RunStore(path) as reopened:
            assert reopened.count() == 0
            assert reopened.synced_repos() == []
            # And it is usable again, stamped with the current version.
            reopened.upsert([_record(2)])
            assert reopened.count() == 1
        with closing(sqlite3.connect(path)) as raw:
            (version,) = raw.execute("PRAGMA user_version").fetchone()
        assert version == 1

    def test_creates_parent_directories(self, tmp_path: Path) -> None:
        path = store_path(tmp_path / "cache", "api.github.com", "org")
        with RunStore(path) as opened:
            assert opened.path.exists()
