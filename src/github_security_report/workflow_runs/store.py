# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""The per-organisation SQLite cache of workflow-run records.

A full read of an organisation's run history is far too expensive to repeat
every report, so :class:`RunStore` keeps every :class:`WorkflowRunRecord` seen
so far, plus a :class:`RepoSyncState` per repository saying how far the last
sync got. The next sync then reads only what is newer than the watermark and
re-reads only the runs that were still pending.

It is a cache, not a database of record: everything in it can be rebuilt from
GitHub. That is why a schema-version mismatch simply drops the tables rather
than migrating them, and why the stdlib ``sqlite3`` module and one connection
per organisation are enough. Writes run in explicit transactions so a crash
mid-sync leaves the previous state intact rather than a half-written page.
"""

from __future__ import annotations

import datetime as dt
import re
import sqlite3
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from pathlib import Path
from types import TracebackType

from github_security_report.workflow_runs.models import (
    Outcome,
    RepoSyncState,
    WorkflowRunRecord,
)
from github_security_report.workflow_runs.store_codec import (
    _encode_datetime,
    _encode_optional,
    _from_row,
    _sync_state_from_row,
    _to_row,
)

# Bump to invalidate every existing store: a mismatch drops and recreates the
# tables, since the data is only ever a cache of what GitHub holds.
SCHEMA_VERSION = 2

STORE_FILENAME = "runs.sqlite"

# Anything outside this set is replaced in a path component, so a hostile API
# host or organisation name (``../evil``) cannot escape the cache directory.
_UNSAFE_PATH_CHARS = re.compile(r"[^A-Za-z0-9_.-]")

# One statement per entry, run inside the schema-reset transaction: sqlite3's
# executescript would commit that transaction before running, so a crash
# between statements could leave a half-built schema stamped with no version.
_SCHEMA = (
    "CREATE TABLE runs ("
    " id INTEGER PRIMARY KEY, node_id TEXT, repo TEXT NOT NULL,"
    " workflow_id INTEGER, workflow_name TEXT, workflow_path TEXT, event TEXT,"
    " trigger TEXT, ref_name TEXT, outcome TEXT, conclusion TEXT, attempt INTEGER,"
    " created_at TEXT NOT NULL, html_url TEXT, failed_jobs TEXT,"
    " ref_is_tag INTEGER, retried INTEGER NOT NULL DEFAULT 0,"
    " jobs_truncated INTEGER NOT NULL DEFAULT 0)",
    "CREATE INDEX runs_repo_created_at ON runs (repo, created_at)",
    "CREATE INDEX runs_outcome ON runs (outcome)",
    "CREATE TABLE sync_state ("
    " repo TEXT PRIMARY KEY, watermark TEXT, etag TEXT, failures_etag TEXT,"
    " oldest TEXT, last_sync_at TEXT)",
)

# In the order _to_row emits values.
_RUN_COLUMNS = [
    "id",
    "node_id",
    "repo",
    "workflow_id",
    "workflow_name",
    "workflow_path",
    "event",
    "trigger",
    "ref_name",
    "outcome",
    "conclusion",
    "attempt",
    "created_at",
    "html_url",
    "failed_jobs",
    "ref_is_tag",
    "retried",
    "jobs_truncated",
]
_INSERT_RUN = (
    f"INSERT OR REPLACE INTO runs ({', '.join(_RUN_COLUMNS)}) "
    f"VALUES ({', '.join('?' * len(_RUN_COLUMNS))})"
)


def _safe_component(value: str) -> str:
    """Reduce ``value`` to one path component that cannot climb a directory."""
    cleaned = _UNSAFE_PATH_CHARS.sub("-", value).lstrip(".-")
    return cleaned or "_"


def store_path(cache_dir: Path, api_host: str, org: str) -> Path:
    """``<cache_dir>/<api_host>/<org>/runs.sqlite``.

    Keyed by API host as well as organisation because the same organisation
    name can exist on github.com and on a GHES instance with entirely
    different runs. Both components are sanitised to ``[A-Za-z0-9_.-]`` with
    leading dots and dashes stripped, so a value under an attacker's control
    cannot name a path outside ``cache_dir``.
    """
    return cache_dir / _safe_component(api_host) / _safe_component(org) / STORE_FILENAME


class RunStore:
    """One organisation's run cache, open on a single SQLite connection.

    A context manager; closing it releases the file. Not thread-safe: the
    collector opens one store per organisation and uses it from one thread.
    """

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._path = path
        # isolation_level=None turns off sqlite3's implicit transactions so the
        # explicit BEGIN/COMMIT in _transaction is the only thing that groups
        # statements, making each write method atomic as a whole.
        self._conn = sqlite3.connect(path, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._ensure_schema()

    def __enter__(self) -> RunStore:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        """Close the connection; the store cannot be used afterwards."""
        self._conn.close()

    @property
    def path(self) -> Path:
        """Where the SQLite file lives."""
        return self._path

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        self._conn.execute("BEGIN")
        try:
            yield self._conn
        except BaseException:
            self._conn.execute("ROLLBACK")
            raise
        self._conn.execute("COMMIT")

    def _ensure_schema(self) -> None:
        """Create the tables, dropping any left by a different schema version.

        A fresh file reports ``user_version`` 0, so it takes the same path as
        a stale one: drop what is there (nothing) and create the tables.
        """
        (version,) = self._conn.execute("PRAGMA user_version").fetchone()
        if version == SCHEMA_VERSION:
            return
        with self._transaction() as conn:
            conn.execute("DROP TABLE IF EXISTS runs")
            conn.execute("DROP TABLE IF EXISTS sync_state")
            for statement in _SCHEMA:
                conn.execute(statement)
            conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION:d}")

    # -- sync state ---------------------------------------------------------

    def sync_state(self, repo: str) -> RepoSyncState:
        """The remembered state for ``repo``; a blank one when never synced."""
        row = self._conn.execute(
            "SELECT * FROM sync_state WHERE repo = ?", (repo,)
        ).fetchone()
        return RepoSyncState(repo=repo) if row is None else _sync_state_from_row(row)

    def set_sync_state(self, state: RepoSyncState) -> None:
        """Insert or replace the state for ``state.repo``."""
        with self._transaction() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO sync_state "
                "(repo, watermark, etag, failures_etag, oldest, last_sync_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    state.repo,
                    _encode_optional(state.watermark),
                    state.etag,
                    state.failures_etag,
                    _encode_optional(state.oldest),
                    _encode_optional(state.last_sync_at),
                ),
            )

    def synced_repos(self) -> list[str]:
        """Every repository with a sync-state row, sorted."""
        rows = self._conn.execute("SELECT repo FROM sync_state ORDER BY repo")
        return [row["repo"] for row in rows]

    # -- records ------------------------------------------------------------

    def upsert(self, records: Iterable[WorkflowRunRecord]) -> int:
        """Write ``records``, replacing any stored run with the same id.

        Returns how many were written. A replacement is total: a record that
        arrives without ``failed_jobs`` overwrites one that had them, so the
        caller carries enrichment forward when it re-reads a run.
        """
        rows = [_to_row(record) for record in records]
        if not rows:
            return 0
        with self._transaction() as conn:
            conn.executemany(_INSERT_RUN, rows)
        return len(rows)

    def _select(
        self,
        repo: str | None,
        since: dt.datetime | None,
        outcome: Outcome | None = None,
        *,
        unenriched: bool = False,
    ) -> list[WorkflowRunRecord]:
        """Records matching every given filter, newest first.

        ``since`` is an inclusive lower bound on ``created_at``. Newest first,
        then highest id first, so two runs created in the same instant still
        come back in a stable order.
        """
        clauses: list[str] = []
        params: list[object] = []
        if repo is not None:
            clauses.append("repo = ?")
            params.append(repo)
        if since is not None:
            clauses.append("created_at >= ?")
            params.append(_encode_datetime(since))
        if outcome is not None:
            clauses.append("outcome = ?")
            params.append(outcome.value)
        if unenriched:
            clauses.append("failed_jobs IS NULL")
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = self._conn.execute(
            f"SELECT * FROM runs{where} ORDER BY created_at DESC, id DESC", params
        )
        return [_from_row(row) for row in rows]

    def records(
        self, repo: str | None = None, *, since: dt.datetime | None = None
    ) -> list[WorkflowRunRecord]:
        """All stored records, optionally for one repo and/or since a time."""
        return self._select(repo, since)

    def get_many(self, ids: Iterable[int]) -> dict[int, WorkflowRunRecord]:
        """The stored records among ``ids``, by id; absent ids are omitted."""
        wanted = list(ids)
        out: dict[int, WorkflowRunRecord] = {}
        # SQLite caps the variables one statement may bind, so look up in
        # chunks well under that limit.
        for start in range(0, len(wanted), 500):
            chunk = wanted[start : start + 500]
            marks = ", ".join("?" * len(chunk))
            rows = self._conn.execute(
                f"SELECT * FROM runs WHERE id IN ({marks})", chunk
            )
            out.update((row["id"], _from_row(row)) for row in rows)
        return out

    def needing_enrichment(
        self, repo: str | None = None, *, since: dt.datetime | None = None
    ) -> list[WorkflowRunRecord]:
        """Failed runs whose jobs the GraphQL drill-down has not yet read."""
        return self._select(repo, since, Outcome.FAIL, unenriched=True)

    def pending(
        self, repo: str | None = None, *, since: dt.datetime | None = None
    ) -> list[WorkflowRunRecord]:
        """Runs GitHub had not concluded when last read."""
        return self._select(repo, since, Outcome.PENDING)

    def failures(self, repo: str, *, since: dt.datetime) -> list[WorkflowRunRecord]:
        """The failed runs of ``repo`` created at or after ``since``."""
        return self._select(repo, since, Outcome.FAIL)

    def count(self, repo: str | None = None) -> int:
        """How many records are stored, for one repo or in total."""
        where, params = ("", ()) if repo is None else (" WHERE repo = ?", (repo,))
        (total,) = self._conn.execute(
            f"SELECT COUNT(*) FROM runs{where}", params
        ).fetchone()
        return int(total)

    # -- housekeeping -------------------------------------------------------

    def prune(self, before: dt.datetime) -> int:
        """Delete records created before ``before``; returns how many went.

        Every repository's ``oldest`` coverage advances to ``before`` as well
        where it reached further back: the history those records held is
        gone, so a window later widened past the retention must be marked
        truncated rather than quietly counted from what remains.
        """
        cutoff = _encode_datetime(before)
        with self._transaction() as conn:
            cursor = conn.execute("DELETE FROM runs WHERE created_at < ?", (cutoff,))
            conn.execute(
                "UPDATE sync_state SET oldest = ? WHERE oldest IS NOT NULL AND oldest < ?",
                (cutoff, cutoff),
            )
        return cursor.rowcount

    def forget(self, repo: str) -> None:
        """Drop everything known about ``repo``, records and sync state."""
        with self._transaction() as conn:
            conn.execute("DELETE FROM runs WHERE repo = ?", (repo,))
            conn.execute("DELETE FROM sync_state WHERE repo = ?", (repo,))

    def clear(self) -> None:
        """Drop every record and every sync state."""
        with self._transaction() as conn:
            conn.execute("DELETE FROM runs")
            conn.execute("DELETE FROM sync_state")
