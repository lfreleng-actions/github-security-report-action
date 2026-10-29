# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Tests for the workflow-run reads (no live network: respx)."""

from __future__ import annotations

import datetime as dt
import json
from collections.abc import AsyncIterator

import httpx
import pytest
import respx

from github_security_report.client import GitHubClient, GraphBatchError
from github_security_report.client.workflow_runs import RUN_LISTING_CAP
from github_security_report.workflow_runs import Outcome, Trigger

API = "https://api.github.com"
GRAPHQL = "https://api.github.com/graphql"
RUNS = f"{API}/repos/o/r/actions/runs"


@pytest.fixture
async def client() -> AsyncIterator[GitHubClient]:
    c = GitHubClient("test-token", concurrency=4)
    yield c
    await c.aclose()


def _raw_run(run_id: int, created: str, **overrides: object) -> dict:
    """A listing entry shaped like GitHub's, with the spike's field set."""
    raw: dict = {
        "id": run_id,
        "node_id": f"WFR_{run_id}",
        "name": "Testing",
        "path": ".github/workflows/testing.yaml",
        "workflow_id": 42,
        "event": "push",
        "head_branch": "main",
        "status": "completed",
        "conclusion": "success",
        "run_attempt": 1,
        "created_at": created,
        "html_url": f"https://github.com/o/r/actions/runs/{run_id}",
        "repository": {"name": "r"},
    }
    raw.update(overrides)
    return raw


def _page(runs: list[dict], *, next_page: int | None = None, etag: str | None = None):
    """A listing page in GitHub's envelope, optionally linking to the next."""
    headers: dict[str, str] = {}
    if next_page is not None:
        headers["Link"] = f'<{RUNS}?page={next_page}>; rel="next"'
    if etag:
        headers["ETag"] = etag
    return httpx.Response(
        200, json={"total_count": len(runs), "workflow_runs": runs}, headers=headers
    )


@respx.mock
async def test_workflow_runs_parses_and_classifies(client: GitHubClient) -> None:
    # Each entry becomes a record classified once: a push to the default
    # branch is a merge, a pull_request event a pr, a dynamic path a dynamic
    # workflow, a null conclusion a pending run.
    respx.get(url__startswith=RUNS).mock(
        return_value=_page(
            [
                _raw_run(4, "2026-10-13T08:00:00Z", conclusion=None, status="queued"),
                _raw_run(
                    3, "2026-10-12T08:00:00Z", event="pull_request", head_branch="fix"
                ),
                _raw_run(
                    2,
                    "2026-10-11T08:00:00Z",
                    event="dynamic",
                    path="dynamic/dependabot/dependabot-updates",
                    conclusion="failure",
                ),
                _raw_run(
                    1, "2026-10-10T08:00:00Z", conclusion="cancelled", run_attempt=2
                ),
            ],
            etag='W/"e1"',
        )
    )
    listing = await client.workflow_runs("o", "r", default_branch="main")
    assert listing.status == 200
    assert listing.etag == 'W/"e1"'
    assert listing.capped is False
    by_id = {record.id: record for record in listing.records}
    assert by_id[4].outcome is Outcome.PENDING and by_id[4].conclusion == ""
    assert by_id[3].trigger is Trigger.PULL_REQUEST
    assert by_id[2].trigger is Trigger.DYNAMIC and by_id[2].outcome is Outcome.FAIL
    assert by_id[1].outcome is Outcome.SKIP and by_id[1].attempt == 2
    assert by_id[1].trigger is Trigger.MERGE
    assert by_id[1].created_at == dt.datetime(2026, 10, 10, 8, tzinfo=dt.timezone.utc)


@respx.mock
async def test_workflow_runs_stops_at_the_watermark(client: GitHubClient) -> None:
    # The first run created before the watermark ends the walk, so a second
    # page is never requested and the result says it stopped.
    route = respx.get(url__startswith=RUNS)
    route.side_effect = [
        _page(
            [_raw_run(3, "2026-10-13T00:00:00Z"), _raw_run(2, "2026-10-01T00:00:00Z")],
            next_page=2,
        ),
        httpx.Response(500),
    ]
    listing = await client.workflow_runs(
        "o",
        "r",
        default_branch="main",
        stop_before=dt.datetime(2026, 10, 5, tzinfo=dt.timezone.utc),
    )
    assert [r.id for r in listing.records] == [3]
    assert listing.stopped is True
    assert route.call_count == 1


@respx.mock
async def test_workflow_runs_presents_etag_and_reads_304(client: GitHubClient) -> None:
    route = respx.get(RUNS).mock(return_value=httpx.Response(304))
    listing = await client.workflow_runs("o", "r", default_branch="main", etag='W/"e1"')
    assert listing.status == 304
    assert listing.records == ()
    assert route.calls.last.request.headers["If-None-Match"] == 'W/"e1"'


@respx.mock
async def test_workflow_runs_marks_a_capped_walk(client: GitHubClient) -> None:
    # Exactly the ceiling of runs without the stop predicate firing means
    # GitHub cut the listing short; the caller must narrow its filter.
    runs = [_raw_run(i, "2026-10-10T00:00:00Z") for i in range(RUN_LISTING_CAP)]
    respx.get(url__startswith=RUNS).mock(return_value=_page(runs))
    listing = await client.workflow_runs("o", "r", default_branch="main")
    assert len(listing.records) == RUN_LISTING_CAP
    assert listing.capped is True


@respx.mock
async def test_workflow_runs_drops_malformed_entries(client: GitHubClient) -> None:
    respx.get(url__startswith=RUNS).mock(
        return_value=_page([{"id": "nope"}, _raw_run(1, "2026-10-10T00:00:00Z")])
    )
    listing = await client.workflow_runs("o", "r", default_branch="main")
    assert [r.id for r in listing.records] == [1]


@respx.mock
async def test_workflow_runs_reports_a_forbidden_listing(client: GitHubClient) -> None:
    respx.get(url__startswith=RUNS).mock(return_value=httpx.Response(403))
    listing = await client.workflow_runs("o", "r", default_branch="main")
    assert listing.status == 403
    assert listing.records == ()


@respx.mock
async def test_workflow_run_rereads_one_run(client: GitHubClient) -> None:
    respx.get(f"{RUNS}/7").mock(
        return_value=httpx.Response(
            200, json=_raw_run(7, "2026-10-10T00:00:00Z", run_attempt=2)
        )
    )
    respx.get(f"{RUNS}/8").mock(return_value=httpx.Response(404))
    record = await client.workflow_run("o", "r", 7, default_branch="main")
    assert record is not None and record.attempt == 2
    # A success on a second attempt is the only trace the first failure leaves.
    assert record.retried is True
    assert await client.workflow_run("o", "r", 8, default_branch="main") is None


def _node(
    node_id: str,
    jobs: list[tuple[str, str]],
    *,
    prefix: str | None = None,
    total: int | None = None,
) -> dict:
    """A ``WorkflowRun`` node as the drill-down query returns it."""
    return {
        "id": node_id,
        "workflow": {"name": "Testing 🧪"},
        "checkSuite": {
            "branch": {"prefix": prefix},
            "checkRuns": {
                "totalCount": total if total is not None else len(jobs),
                "nodes": [
                    {"name": name, "conclusion": conclusion, "detailsUrl": f"u/{name}"}
                    for name, conclusion in jobs
                ],
            },
        },
    }


@respx.mock
async def test_workflow_run_jobs_parses_each_node(client: GitHubClient) -> None:
    route = respx.post(GRAPHQL).mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "nodes": [
                        _node("a", [("Build (3.12)", "FAILURE")], prefix="refs/tags/"),
                        None,
                        _node(
                            "c", [("Lint", "CANCELLED")], prefix="refs/heads/", total=5
                        ),
                    ]
                }
            },
        )
    )
    out = await client.workflow_run_jobs("o", ["a", "b", "c"])
    assert json.loads(route.calls.last.request.content)["variables"] == {
        "ids": ["a", "b", "c"]
    }
    assert out["a"].failed_jobs is not None
    assert out["a"].failed_jobs[0].name == "Build (3.12)"
    assert out["a"].failed_jobs[0].conclusion == "failure"
    assert out["a"].ref_is_tag is True
    assert out["a"].workflow_name == "Testing 🧪"
    # A null node is unreadable, not "no failing jobs".
    assert out["b"].failed_jobs is None
    assert out["c"].ref_is_tag is False
    assert out["c"].jobs_truncated is True


@respx.mock
async def test_workflow_run_jobs_condemns_errored_nodes(client: GitHubClient) -> None:
    # A path naming one node condemns that node alone; the others are read.
    respx.post(GRAPHQL).mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {"nodes": [_node("a", []), _node("b", [("X", "FAILURE")])]},
                "errors": [{"path": ["nodes", 0, "checkSuite"], "message": "nope"}],
            },
        )
    )
    out = await client.workflow_run_jobs("o", ["a", "b"])
    assert out["a"].failed_jobs is None
    assert out["b"].failed_jobs is not None and len(out["b"].failed_jobs) == 1


@respx.mock
async def test_workflow_run_jobs_unattributable_error_condemns_all(
    client: GitHubClient,
) -> None:
    respx.post(GRAPHQL).mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {"nodes": [_node("a", []), _node("b", [])]},
                "errors": [{"message": "x"}],
            },
        )
    )
    out = await client.workflow_run_jobs("o", ["a", "b"])
    assert all(d.failed_jobs is None for d in out.values())


@respx.mock
async def test_workflow_run_jobs_timeout_is_splittable(client: GitHubClient) -> None:
    # A gateway timeout is a verdict on the query's size, so the batched
    # driver may halve it; the message names the drill-down, not the prefetch.
    respx.post(GRAPHQL).mock(return_value=httpx.Response(504))
    client._max_retries = 0
    with pytest.raises(GraphBatchError) as info:
        await client.workflow_run_jobs("o", ["a", "b"])
    assert info.value.splittable is True
    assert "run drill-down" in str(info.value)
    assert "2 runs" in str(info.value)


async def test_workflow_run_jobs_empty_issues_no_request(client: GitHubClient) -> None:
    assert await client.workflow_run_jobs("o", []) == {}
