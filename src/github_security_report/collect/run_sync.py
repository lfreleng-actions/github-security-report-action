# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Keeping the run store current: one repository's incremental sync.

Every report after the first should cost a repository one conditional
request on a quiet day, so the sync reads newest-first and stops at the
watermark it stored last time, presenting the listing's ETag so an unchanged
listing answers ``304`` for free. A repository never seen before is backfilled
to the configured depth in date slices sized under GitHub's pagination
ceiling. Two things the incremental read cannot see are reconciled after it:
a re-run keeps its ``created_at``, so a stored failure that has since passed
is found by re-reading the window's failure list; and a run stored while still
in progress is re-read until it concludes.
"""

from __future__ import annotations

import datetime as dt
import logging
from dataclasses import dataclass, replace

from github_security_report.client.workflow_runs import RunListing
from github_security_report.collect.protocols import ClientProtocol
from github_security_report.models import Repo
from github_security_report.workflow_runs import (
    Outcome,
    RepoSyncState,
    RunStore,
    WorkflowRunRecord,
)

log = logging.getLogger(__name__)

# Date-sliced backfill: the first slice width, halved whenever a slice still
# hits the listing ceiling, down to a single day. A day that alone exceeds the
# ceiling is read as far as GitHub allows and logged.
_INITIAL_SLICE_DAYS = 7

# Re-reads of individual runs per repository per sync, for the runs whose
# state may have moved (still pending, or a failure no longer listed). A
# repository with more than this many in flight is unusual; the rest wait for
# the next sync rather than cost a request each now.
_REREAD_LIMIT = 50

# The listing's ``status`` filter takes one value, so the reconciliation reads
# plain failures only and compares them against stored runs of that
# conclusion alone: a startup_failure absent from a ``failure`` list has not
# passed, it was never in that list.
_RECONCILED_CONCLUSION = "failure"


@dataclass(frozen=True)
class RunSyncOptions:
    """What to ask GitHub for, and keep, for every repository.

    ``window_days`` is the longest window any surface shows. It bounds the
    reconciliation (a failure outside every window need not be re-checked),
    the enrichment (jobs no table will show are not worth a query) and the
    records handed to aggregation. ``retention_days`` is at least as long;
    ``backfill_days`` is how deep a never-seen repository is read.
    """

    window_days: int = 90
    retention_days: int = 90
    backfill_days: int = 90
    include_dynamic: bool = False
    refresh: bool = False


@dataclass(frozen=True)
class RepoRunSync:
    """What one repository's sync did, for the footer and the run log.

    ``status`` is the listing's HTTP status: 200 or 304 means the repository's
    data is current; anything else means it could not be read this run and
    every window must report it as unknown rather than as having no failures.
    """

    repo: str
    status: int
    written: int = 0
    rereads: int = 0

    @property
    def readable(self) -> bool:
        """Whether the listing could be read (or was unchanged)."""
        return self.status in (200, 304)


def _date(when: dt.datetime) -> str:
    """The calendar date GitHub's ``created`` filter takes."""
    return when.astimezone(dt.timezone.utc).date().isoformat()


def _merge(
    existing: WorkflowRunRecord | None, fresh: WorkflowRunRecord
) -> WorkflowRunRecord:
    """A fresh read of a run, keeping enrichment the read cannot supply.

    The listing never carries failing jobs or the tag flag, so a re-read must
    not erase them; but a failure that failed again on a later attempt has
    possibly different jobs, so enrichment is kept only while the outcome and
    attempt are unchanged. A stored failure re-read as a pass is a retry that
    worked -- the flakiness signal the reconciliation exists to find.
    """
    if existing is None:
        return fresh
    retried = fresh.retried or (
        existing.outcome is Outcome.FAIL and fresh.outcome is Outcome.PASS
    )
    same = existing.outcome is fresh.outcome and existing.attempt == fresh.attempt
    settled = existing.ref_is_tag is not None
    return replace(
        fresh,
        failed_jobs=existing.failed_jobs if same else fresh.failed_jobs,
        jobs_truncated=existing.jobs_truncated if same else fresh.jobs_truncated,
        ref_is_tag=existing.ref_is_tag if settled else fresh.ref_is_tag,
        trigger=existing.trigger if settled else fresh.trigger,
        retried=retried,
    )


class RepoSync:
    """The sync of one repository against the store, step by step."""

    def __init__(
        self,
        client: ClientProtocol,
        store: RunStore,
        org: str,
        repo: Repo,
        *,
        now: dt.datetime,
        options: RunSyncOptions,
    ) -> None:
        self._client = client
        self._store = store
        self._org = org
        self._repo = repo
        self._now = now
        self._options = options
        self._written = 0
        self._rereads = 0

    async def _list(
        self,
        *,
        params: dict[str, object] | None = None,
        stop_before: dt.datetime | None = None,
        etag: str | None = None,
    ) -> RunListing:
        return await self._client.workflow_runs(
            self._org,
            self._repo.name,
            default_branch=self._repo.default_branch,
            params=params,
            stop_before=stop_before,
            etag=etag,
        )

    def _write(self, records: tuple[WorkflowRunRecord, ...]) -> None:
        """Store ``records``, merging each over what is already held."""
        if not records:
            return
        held = self._store.get_many(record.id for record in records)
        merged = [_merge(held.get(record.id), record) for record in records]
        self._written += self._store.upsert(merged)

    async def run(self) -> RepoRunSync:
        """Bring the store current for this repository."""
        state = self._store.sync_state(self._repo.name)
        if self._options.refresh:
            state = RepoSyncState(repo=self._repo.name)
        cold = state.watermark is None
        until = self._now - dt.timedelta(days=self._options.backfill_days)
        if cold:
            status, etag, newest = await self._backfill(until)
            oldest = until if status == 200 else state.oldest
        else:
            assert state.watermark is not None
            status, etag, newest = await self._incremental(state.watermark, state.etag)
            oldest = state.oldest
        if status not in (200, 304):
            return RepoRunSync(self._repo.name, status, self._written, self._rereads)
        failures_etag = state.failures_etag
        # An unchanged first page means no run was created, re-run or
        # concluded among the newest hundred, so the failure list is only
        # re-read when the listing moved. A re-run of a run older than that
        # page waits for the next new run in the repository to be noticed,
        # which for an active repository is the next day at most.
        if not cold and status == 200:
            failures_etag = await self._reconcile_failures(state.failures_etag)
        await self._reread_pending()
        self._store.set_sync_state(
            RepoSyncState(
                repo=self._repo.name,
                watermark=max(filter(None, (state.watermark, newest)), default=None),
                etag=etag if status == 200 else state.etag,
                failures_etag=failures_etag,
                oldest=oldest,
                last_sync_at=self._now,
            )
        )
        return RepoRunSync(self._repo.name, status, self._written, self._rereads)

    async def _incremental(
        self, watermark: dt.datetime, etag: str | None
    ) -> tuple[int, str | None, dt.datetime | None]:
        """Read what is newer than the watermark; ``(status, etag, newest)``."""
        listing = await self._list(stop_before=watermark, etag=etag)
        if listing.status != 200:
            return listing.status, None, None
        self._write(listing.records)
        if listing.capped:
            # More new runs than one listing can show (a bulk-merge week):
            # slice the rest by date down to the watermark.
            oldest_seen = min(r.created_at for r in listing.records)
            await self._slices(oldest_seen, watermark)
        return 200, listing.etag, _newest(listing.records)

    async def _backfill(
        self, until: dt.datetime
    ) -> tuple[int, str | None, dt.datetime | None]:
        """Read the repository's history back to ``until``."""
        listing = await self._list(stop_before=until)
        if listing.status != 200:
            return listing.status, None, None
        self._write(listing.records)
        if listing.capped:
            oldest_seen = min(r.created_at for r in listing.records)
            await self._slices(oldest_seen, until)
        return 200, listing.etag, _newest(listing.records)

    async def _slices(self, end: dt.datetime, until: dt.datetime) -> None:
        """Read ``[until, end]`` in date slices sized under the listing cap.

        Each slice is a closed date range, so consecutive slices share a
        boundary day; the overlap re-reads a few runs, which the id-keyed
        store absorbs. A slice that still caps is halved; a single day that
        caps is kept as read, since GitHub offers no finer filter.
        """
        step = _INITIAL_SLICE_DAYS
        while end > until:
            start = max(until, end - dt.timedelta(days=step))
            listing = await self._list(
                params={"created": f"{_date(start)}..{_date(end)}"}
            )
            if listing.status != 200:
                log.warning(
                    "workflow-run backfill for %s/%s stopped at %s (status %s)",
                    self._org,
                    self._repo.name,
                    _date(end),
                    listing.status,
                )
                return
            if listing.capped and step > 1:
                step = max(1, step // 2)
                continue
            if listing.capped:
                log.warning(
                    "workflow-run backfill for %s/%s: more than %d runs on %s; "
                    "the day is read as far as GitHub lists it",
                    self._org,
                    self._repo.name,
                    len(listing.records),
                    _date(end),
                )
            self._write(listing.records)
            end = start - dt.timedelta(seconds=1)

    async def _reconcile_failures(self, etag: str | None) -> str | None:
        """Find stored failures that a later attempt turned into something else.

        Re-reads the window's failure list (conditionally; a day with no
        change costs nothing) and re-reads each stored failure missing from
        it, since a run leaves the list when a re-run passes and, less often,
        when it is deleted. New entries in the list -- a run stored while
        pending that has since failed -- are written as they are.
        """
        since = self._now - dt.timedelta(days=self._options.window_days)
        listing = await self._list(
            params={"status": "failure", "created": f">={_date(since)}"}, etag=etag
        )
        if listing.status == 304:
            return etag
        if listing.status != 200:
            return None
        self._write(listing.records)
        listed = {record.id for record in listing.records}
        missing = [
            record
            for record in self._store.failures(self._repo.name, since=since)
            if record.conclusion == _RECONCILED_CONCLUSION and record.id not in listed
        ]
        await self._reread(missing)
        return listing.etag

    async def _reread_pending(self) -> None:
        """Re-read the runs stored while still in progress, newest first."""
        since = self._now - dt.timedelta(days=self._options.window_days)
        await self._reread(self._store.pending(self._repo.name, since=since))

    async def _reread(self, records: list[WorkflowRunRecord]) -> None:
        budget = _REREAD_LIMIT - self._rereads
        for record in records[: max(0, budget)]:
            self._rereads += 1
            fresh = await self._client.workflow_run(
                self._org,
                self._repo.name,
                record.id,
                default_branch=self._repo.default_branch,
            )
            if fresh is not None:
                self._write((fresh,))


def _newest(records: tuple[WorkflowRunRecord, ...]) -> dt.datetime | None:
    return max((record.created_at for record in records), default=None)
