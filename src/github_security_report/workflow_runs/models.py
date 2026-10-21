# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""The compact record kept for every GitHub Actions workflow run.

One :class:`WorkflowRunRecord` per run, built from the REST listing (and
enriched from GraphQL where a run failed), persisted in the run store and
aggregated into the Workflow Failures tables. The classification happens here,
once, so the store, the collector and the aggregation all speak in the same
:class:`Trigger` and :class:`Outcome` vocabulary rather than in GitHub's raw
``event`` and ``conclusion`` strings.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from enum import Enum

# GitHub-managed workflows (Dependabot updates, default-setup CodeQL, Copilot
# review) carry no file in the repository; their ``path`` starts with this.
DYNAMIC_PATH_PREFIX = "dynamic/"


class Trigger(str, Enum):
    """What started a run, folded from GitHub's ``event`` and the ref.

    The merge/tag/branch split is what the report is for: an integration test
    that needs credentials runs only once merged, so it fails on ``merge``
    while every ``pr`` run of the same workflow passes.
    """

    PULL_REQUEST = "pr"  # pull_request, pull_request_target
    MERGE = "merge"  # push to the default branch
    TAG = "tag"  # push of a tag, or the release event
    BRANCH = "branch"  # push to any other branch
    SCHEDULE = "schedule"
    MANUAL = "manual"  # workflow_dispatch
    DYNAMIC = "dynamic"  # GitHub-managed (path dynamic/...)
    OTHER = "other"


class Outcome(str, Enum):
    """A run's conclusion, normalised into the four buckets the tables count."""

    PASS = "pass"  # success
    FAIL = "fail"  # failure, startup_failure, timed_out, action_required
    SKIP = "skip"  # skipped, cancelled, neutral, stale
    PENDING = "pending"  # still running (or queued); re-read next sync


_FAIL_CONCLUSIONS = frozenset(
    {"failure", "startup_failure", "timed_out", "action_required"}
)
# Events whose trigger needs no look at the ref. ``push`` is absent on
# purpose: it is the one event the ref decides (merge, tag or branch).
_EVENT_TRIGGERS = {
    "pull_request": Trigger.PULL_REQUEST,
    "pull_request_target": Trigger.PULL_REQUEST,
    "release": Trigger.TAG,
    "schedule": Trigger.SCHEDULE,
    "workflow_dispatch": Trigger.MANUAL,
    "dynamic": Trigger.DYNAMIC,
}


def classify_outcome(conclusion: str | None) -> Outcome:
    """The :class:`Outcome` bucket for a raw ``conclusion``.

    ``None`` is a run GitHub has not concluded (queued, in progress, waiting
    for approval), so it is pending rather than a pass or a fail. An unknown
    conclusion string is treated as a skip: it is not a success, and counting
    something GitHub did not call a failure as one would overstate the rate.
    """
    if conclusion is None:
        return Outcome.PENDING
    if conclusion == "success":
        return Outcome.PASS
    if conclusion in _FAIL_CONCLUSIONS:
        return Outcome.FAIL
    return Outcome.SKIP


def classify_trigger(
    event: str,
    *,
    head_branch: str | None,
    default_branch: str,
    path: str,
    ref_is_tag: bool | None = None,
) -> Trigger:
    """The :class:`Trigger` for a run, from its event, ref and workflow path.

    The REST listing's ``head_branch`` cannot distinguish a tag push from a
    branch push (a tag run shows ``event: push, head_branch: v0.18.0``), so a
    push to a non-default ref is a ``branch`` until GraphQL settles
    ``ref_is_tag``; the release event is a ``tag`` outright. A push whose ref
    is the default branch is a ``merge`` whatever ``ref_is_tag`` says, since a
    tag named after the default branch is not a thing anyone does on purpose.
    """
    if path.startswith(DYNAMIC_PATH_PREFIX):
        return Trigger.DYNAMIC
    if event == "push":
        if head_branch == default_branch:
            return Trigger.MERGE
        return Trigger.TAG if ref_is_tag else Trigger.BRANCH
    return _EVENT_TRIGGERS.get(event, Trigger.OTHER)


@dataclass(frozen=True)
class FailedJob:
    """One failing check run (job) of a failed workflow run."""

    name: str  # raw check-run name ("Caller / Callee (matrix)")
    conclusion: str
    url: str


@dataclass(frozen=True)
class WorkflowRunRecord:
    """One compact, persisted record per workflow run.

    ``workflow_name`` is the name at run time; display uses the newest seen
    for the workflow. ``failed_jobs`` is ``None`` until the GraphQL drill-down
    has read the run's jobs (and stays ``None`` when it could not), and an
    empty tuple when the drill-down found no failing job to name. ``ref_is_tag``
    is ``None`` until GraphQL settles the ref's prefix. ``retried`` marks a run
    that passed on a later attempt: either the listing said so outright
    (``run_attempt`` above one with a success) or a stored failure was later
    re-read as a pass. Either way it is a direct flakiness signal, and the
    second case would otherwise never be noticed, since a re-run keeps its
    ``created_at`` and so never crosses the incremental watermark.
    """

    id: int
    node_id: str
    repo: str
    workflow_id: int
    workflow_name: str
    workflow_path: str
    event: str
    trigger: Trigger
    ref_name: str
    outcome: Outcome
    conclusion: str  # raw, for report.json; "" while pending
    attempt: int
    created_at: dt.datetime
    html_url: str
    failed_jobs: tuple[FailedJob, ...] | None = None
    ref_is_tag: bool | None = None
    retried: bool = False

    @property
    def is_dynamic(self) -> bool:
        """Whether this is a GitHub-managed workflow with no file in the repo."""
        return self.trigger is Trigger.DYNAMIC

    @property
    def needs_enrichment(self) -> bool:
        """Whether the GraphQL drill-down still has something to add."""
        return self.outcome is Outcome.FAIL and self.failed_jobs is None


@dataclass(frozen=True)
class RepoSyncState:
    """What the store remembers about one repository between syncs.

    ``watermark`` is the newest ``created_at`` stored, where the next
    incremental read stops; ``etag`` the validator of the listing's first page,
    presented so an unchanged listing costs nothing; ``oldest`` the earliest
    ``created_at`` the store has ever been backfilled to, so a window reaching
    further back than that can say its data is truncated.
    """

    repo: str
    watermark: dt.datetime | None = None
    etag: str | None = None
    failures_etag: str | None = None
    oldest: dt.datetime | None = None
    last_sync_at: dt.datetime | None = None
