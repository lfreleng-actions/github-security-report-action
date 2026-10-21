# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""GitHub Actions workflow-run reads: the listing, one run, and failing jobs.

:class:`WorkflowRunReads` adds the three reads behind the Workflow Failures
tables to the per-repository read surface. The REST listing is walked with
the shared paginator so an incremental sync can stop at data it already holds
and present an ETag; a single run is re-read when its state may have changed
since; and the failing jobs of many runs are read in one GraphQL query, since
the REST jobs endpoint would cost a request per run.

Each read returns :class:`~github_security_report.workflow_runs.WorkflowRunRecord`
values (or :class:`RunDrillDown` for the jobs), parsed here, so the collector
never sees GitHub's listing shape.
"""

from __future__ import annotations

import datetime as dt
import logging
from collections.abc import Callable
from dataclasses import dataclass

from github_security_report.client.batch_errors import _batch_response
from github_security_report.client.paging import PageResult
from github_security_report.client.parsers import _parse_iso
from github_security_report.client.queries import _WORKFLOW_RUN_JOBS_QUERY
from github_security_report.client.reads import ReadClient
from github_security_report.workflow_runs import (
    FailedJob,
    Outcome,
    WorkflowRunRecord,
    classify_outcome,
    classify_trigger,
)

log = logging.getLogger(__name__)

# The listing paginates to at most this many runs however many match; a read
# that returns exactly this many was cut short, not finished.
RUN_LISTING_CAP = 1000

# The ref prefix GitHub's check suite reports for a tag push.
_TAG_PREFIX = "refs/tags/"


@dataclass(frozen=True)
class RunListing:
    """One walk of a repository's run listing, parsed.

    ``status`` and ``etag`` are the paginator's; ``records`` the parsed runs
    in listing order (newest first); ``stopped`` whether the caller's stop
    predicate ended the walk; ``capped`` whether GitHub's pagination ceiling
    did, in which case older matching runs exist that this read never saw.
    """

    status: int
    records: tuple[WorkflowRunRecord, ...] = ()
    etag: str | None = None
    stopped: bool = False
    capped: bool = False


@dataclass(frozen=True)
class RunDrillDown:
    """What the GraphQL drill-down learned about one failed run.

    ``failed_jobs`` is ``None`` when the node could not be read, so the caller
    leaves the record awaiting enrichment rather than recording "no failing
    jobs"; ``jobs_truncated`` says the run had more failing jobs than the query
    window carried. ``workflow_name`` is the workflow's current name, or
    ``None`` when GitHub no longer knows the workflow (a deleted file).
    """

    node_id: str
    failed_jobs: tuple[FailedJob, ...] | None
    workflow_name: str | None = None
    ref_is_tag: bool | None = None
    jobs_truncated: bool = False


def _parse_run(
    raw: dict, *, repo: str, default_branch: str
) -> WorkflowRunRecord | None:
    """One listing entry as a record, or ``None`` for an entry missing its keys.

    Every field the tables rely on is read defensively: a run GitHub lists
    without an id or creation time cannot be stored or windowed, so it is
    dropped (and logged) rather than let a malformed entry fail the sync.
    """
    run_id = raw.get("id")
    created_at = _parse_iso(raw.get("created_at"))
    if not isinstance(run_id, int) or created_at is None:
        log.debug("skipping malformed workflow run entry for %s: %r", repo, raw)
        return None
    event = str(raw.get("event") or "")
    path = str(raw.get("path") or "")
    head_branch = raw.get("head_branch")
    conclusion = raw.get("conclusion")
    outcome = classify_outcome(conclusion if isinstance(conclusion, str) else None)
    attempt = int(raw.get("run_attempt") or 1)
    return WorkflowRunRecord(
        id=run_id,
        node_id=str(raw.get("node_id") or ""),
        repo=repo,
        workflow_id=int(raw.get("workflow_id") or 0),
        workflow_name=str(raw.get("name") or ""),
        workflow_path=path,
        event=event,
        trigger=classify_trigger(
            event,
            head_branch=head_branch if isinstance(head_branch, str) else None,
            default_branch=default_branch,
            path=path,
        ),
        ref_name=str(head_branch or ""),
        outcome=outcome,
        conclusion=str(conclusion or ""),
        attempt=attempt,
        created_at=created_at,
        html_url=str(raw.get("html_url") or ""),
        # The listing shows only the latest attempt, so a success on a second
        # attempt is the only trace the earlier failure leaves.
        retried=attempt > 1 and outcome is Outcome.PASS,
    )


def _stop_before(cutoff: dt.datetime | None) -> Callable[[dict], bool] | None:
    """A stop predicate for runs created before ``cutoff``; none without one."""
    if cutoff is None:
        return None

    def stop(raw: dict) -> bool:
        created = _parse_iso(raw.get("created_at"))
        return created is not None and created < cutoff

    return stop


class WorkflowRunReads(ReadClient):
    """The workflow-run reads over the per-repository read surface."""

    def _runs_url(self, org: str, repo: str) -> str:
        return f"{self._api_url}/repos/{org}/{repo}/actions/runs"

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
        """Walk ``repo``'s run listing, newest first, into parsed records.

        ``params`` are GitHub's listing filters (``created``, ``status``,
        ``event``, ``branch``); the paginator adds ``per_page``. ``stop_before``
        ends the walk at the first run created before it -- the incremental
        read's watermark -- and ``etag`` makes the first page conditional, so
        an unchanged listing answers ``304`` with no records and no rate-limit
        cost. The result's ``capped`` flag is set when the walk ran into
        GitHub's pagination ceiling without the stop predicate ending it: the
        caller must then narrow the filters and read the rest.
        """
        result: PageResult = await self._paginate(
            self._runs_url(org, repo),
            params,
            items_key="workflow_runs",
            stop=_stop_before(stop_before),
            etag=etag,
        )
        records = tuple(
            record
            for raw in result.items
            if (record := _parse_run(raw, repo=repo, default_branch=default_branch))
        )
        return RunListing(
            status=result.status,
            records=records,
            etag=result.etag,
            stopped=result.stopped,
            capped=not result.stopped and len(result.items) >= RUN_LISTING_CAP,
        )

    async def workflow_run(
        self, org: str, repo: str, run_id: int, *, default_branch: str
    ) -> WorkflowRunRecord | None:
        """Re-read one run, or ``None`` when it could not be read.

        Used for the runs whose state may have moved since they were stored:
        a run that was still in progress, or a failure that no longer appears
        in the failure list because a re-run passed. Quiet, because a run that
        has since been deleted is not worth a warning.
        """
        resp = await self._request(
            "GET", f"{self._runs_url(org, repo)}/{run_id}", quiet=True
        )
        if resp.status_code != 200:
            await resp.aclose()  # unread body would leak a pooled connection
            return None
        raw = resp.json()
        await resp.aclose()  # release the connection once the body is read
        if not isinstance(raw, dict):
            return None
        return _parse_run(raw, repo=repo, default_branch=default_branch)

    async def workflow_run_jobs(
        self, org: str, node_ids: list[str]
    ) -> dict[str, RunDrillDown]:
        """The failing jobs of many runs in one GraphQL query, by node id.

        Every requested id is answered: a node GitHub returned as ``null``, or
        implicated by an ``errors`` entry, comes back with ``failed_jobs``
        ``None`` so the record stays awaiting enrichment. A query that failed
        as a whole raises :class:`~github_security_report.client.GraphBatchError`
        through the same policy as the prefetch (see ``_batch_response``), so
        the batched driver can halve a query GitHub refused for its size.
        """
        if not node_ids:
            return {}
        result = await self._graphql(_WORKFLOW_RUN_JOBS_QUERY, {"ids": list(node_ids)})
        data, errors = _batch_response(
            org, len(node_ids), result, what="run drill-down", unit="runs"
        )
        unreadable = _errored_indexes(errors, len(node_ids))
        nodes = data.get("nodes")
        nodes = nodes if isinstance(nodes, list) else []
        out = {
            node_id: RunDrillDown(node_id=node_id, failed_jobs=None)
            for node_id in node_ids
        }
        for index, node_id in enumerate(node_ids):
            node = nodes[index] if index < len(nodes) else None
            if index in unreadable or not isinstance(node, dict):
                continue
            out[node_id] = _parse_drill_down(node_id, node)
        if errors:
            log.warning(
                "GraphQL run drill-down for %s returned %d error(s); the "
                "affected runs keep their jobs unread",
                org,
                len(errors),
            )
        return out


def _errored_indexes(errors: list, count: int) -> set[int]:
    """The ``nodes`` positions an ``errors`` array condemns.

    A path of ``["nodes", 3, ...]`` names one node; an error with no usable
    path cannot be attributed, so it condemns every node in the query rather
    than let a failed read pass as "no failing jobs".
    """
    condemned: set[int] = set()
    for entry in errors:
        path = entry.get("path") if isinstance(entry, dict) else None
        index = path[1] if isinstance(path, list) and len(path) > 1 else None
        if path and path[0] == "nodes" and isinstance(index, int):
            condemned.add(index)
        else:
            return set(range(count))
    return condemned


def _parse_drill_down(node_id: str, node: dict) -> RunDrillDown:
    """A ``WorkflowRun`` node as a drill-down result."""
    workflow = node.get("workflow")
    suite = node.get("checkSuite") or {}
    branch = suite.get("branch") or {}
    prefix = branch.get("prefix")
    check_runs = suite.get("checkRuns") or {}
    raw_jobs = check_runs.get("nodes")
    jobs = tuple(
        FailedJob(
            name=str(job.get("name") or ""),
            conclusion=str(job.get("conclusion") or "").lower(),
            url=str(job.get("detailsUrl") or ""),
        )
        for job in (raw_jobs if isinstance(raw_jobs, list) else [])
        if isinstance(job, dict)
    )
    total = check_runs.get("totalCount")
    return RunDrillDown(
        node_id=node_id,
        failed_jobs=jobs,
        workflow_name=(
            str(workflow["name"])
            if isinstance(workflow, dict) and workflow.get("name")
            else None
        ),
        ref_is_tag=(prefix == _TAG_PREFIX) if isinstance(prefix, str) else None,
        jobs_truncated=isinstance(total, int) and total > len(jobs),
    )
