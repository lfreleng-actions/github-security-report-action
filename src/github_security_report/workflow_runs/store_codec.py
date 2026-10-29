# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Encoding run records and sync state to and from the store's rows.

Kept apart from :mod:`.store`, which owns the connection and the queries, so
the shape of a row and the shape of a statement can each be read on their
own. Datetimes are fixed-width ISO-8601 UTC text, so SQL text comparison is
chronological order; failing jobs are a JSON list, with ``NULL`` for "not
yet read" distinct from ``[]`` for "none".
"""

from __future__ import annotations

import datetime as dt
import json
import sqlite3
from dataclasses import asdict

from github_security_report.workflow_runs.models import (
    FailedJob,
    Outcome,
    RepoSyncState,
    Trigger,
    WorkflowRunRecord,
)


def _encode_datetime(value: dt.datetime) -> str:
    """ISO-8601 UTC text of fixed width, so text order is time order.

    A naive datetime is rejected rather than guessed at: the callers always
    hold aware UTC values from GitHub, so a naive one is a bug upstream.
    """
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"datetime {value!r} must be timezone-aware")
    return value.astimezone(dt.timezone.utc).isoformat(timespec="microseconds")


def _decode_datetime(text: str | None) -> dt.datetime | None:
    return None if text is None else dt.datetime.fromisoformat(text)


def _encode_optional(value: dt.datetime | None) -> str | None:
    return None if value is None else _encode_datetime(value)


def _encode_failed_jobs(jobs: tuple[FailedJob, ...] | None) -> str | None:
    """``None`` stays NULL; an empty tuple becomes ``[]`` so the two differ."""
    return None if jobs is None else json.dumps([asdict(job) for job in jobs])


def _decode_failed_jobs(text: str | None) -> tuple[FailedJob, ...] | None:
    return None if text is None else tuple(FailedJob(**j) for j in json.loads(text))


def _optional_bool(value: int | None) -> bool | None:
    return None if value is None else bool(value)


def _to_row(record: WorkflowRunRecord) -> tuple[object, ...]:
    return (
        record.id,
        record.node_id,
        record.repo,
        record.workflow_id,
        record.workflow_name,
        record.workflow_path,
        record.event,
        record.trigger.value,
        record.ref_name,
        record.outcome.value,
        record.conclusion,
        record.attempt,
        _encode_datetime(record.created_at),
        record.html_url,
        _encode_failed_jobs(record.failed_jobs),
        None if record.ref_is_tag is None else int(record.ref_is_tag),
        int(record.retried),
        int(record.jobs_truncated),
    )


def _from_row(row: sqlite3.Row) -> WorkflowRunRecord:
    created_at = _decode_datetime(row["created_at"])
    assert created_at is not None  # the column is NOT NULL
    return WorkflowRunRecord(
        id=row["id"],
        node_id=row["node_id"],
        repo=row["repo"],
        workflow_id=row["workflow_id"],
        workflow_name=row["workflow_name"],
        workflow_path=row["workflow_path"],
        event=row["event"],
        trigger=Trigger(row["trigger"]),
        ref_name=row["ref_name"],
        outcome=Outcome(row["outcome"]),
        conclusion=row["conclusion"],
        attempt=row["attempt"],
        created_at=created_at,
        html_url=row["html_url"],
        failed_jobs=_decode_failed_jobs(row["failed_jobs"]),
        ref_is_tag=_optional_bool(row["ref_is_tag"]),
        retried=bool(row["retried"]),
        jobs_truncated=bool(row["jobs_truncated"]),
    )


def _sync_state_from_row(row: sqlite3.Row) -> RepoSyncState:
    return RepoSyncState(
        repo=row["repo"],
        watermark=_decode_datetime(row["watermark"]),
        etag=row["etag"],
        failures_etag=row["failures_etag"],
        oldest=_decode_datetime(row["oldest"]),
        last_sync_at=_decode_datetime(row["last_sync_at"]),
    )
