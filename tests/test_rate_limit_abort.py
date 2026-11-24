# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""A primary rate limit spent mid-run stops the run with exit 6."""

from __future__ import annotations

import datetime as dt
import time
from collections import Counter
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
import respx
from typer.testing import CliRunner

from github_security_report.cli import app
from github_security_report.cli.preflight_messages import spent_budget_message
from github_security_report.client import (
    API_MAX_TOTAL_WAIT_SECONDS,
    GitHubClient,
    RateLimitError,
)
from github_security_report.client.events import NullSink
from github_security_report.secret_patterns import PATTERN_CONFIG_PATH

API = "https://api.github.com"
SCORECARD = "https://api.securityscorecards.dev"
REPO_URL = f"{API}/repos/o/r"

cli = CliRunner()


class _Sleeps:
    """Stands in for ``asyncio.sleep``, recording each delay."""

    def __init__(self) -> None:
        self.delays: list[float] = []

    async def __call__(self, delay: float) -> None:
        self.delays.append(delay)


class _RateLimitSink(NullSink):
    """A progress sink that records the rate-limit waits it hears of."""

    def __init__(self) -> None:
        self.waits: list[tuple[float, str | None]] = []

    def on_rate_limited(self, delay: float, resource: str | None) -> None:
        self.waits.append((delay, resource))


@pytest.fixture(autouse=True)
def sleeps(monkeypatch: pytest.MonkeyPatch) -> _Sleeps:
    recorder = _Sleeps()
    monkeypatch.setattr(
        "github_security_report.client.transport.asyncio.sleep", recorder
    )
    return recorder


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    monkeypatch.setenv("GITHUB_OUTPUT", str(tmp_path / "github_output"))
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(tmp_path / "step_summary"))


@pytest.fixture
def sink() -> _RateLimitSink:
    return _RateLimitSink()


@pytest.fixture
async def client(sink: _RateLimitSink) -> AsyncIterator[GitHubClient]:
    c = GitHubClient("test-token", concurrency=4, progress=sink)
    yield c
    await c.aclose()


def _spent(
    status: int = 403,
    *,
    reset_in: float | None = 3600,
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    """A response refused because the primary budget has nothing left."""
    sent = {"x-ratelimit-remaining": "0", "x-ratelimit-resource": "core"}
    sent.update(headers or {})
    if reset_in is not None:
        sent["x-ratelimit-reset"] = str(int(time.time() + reset_in))
    return httpx.Response(
        status, json={"message": "API rate limit exceeded"}, headers=sent
    )


# --------------------------------------------------------------------------- #
# Transport
# --------------------------------------------------------------------------- #
@respx.mock
@pytest.mark.parametrize("status", [403, 429])
async def test_a_reset_beyond_the_budget_raises_on_the_first_response(
    client: GitHubClient, sink: _RateLimitSink, sleeps: _Sleeps, status: int
) -> None:
    route = respx.get(REPO_URL).mock(
        return_value=_spent(status, headers={"retry-after": "5"})
    )
    with pytest.raises(RateLimitError) as excinfo:
        await client._request("GET", REPO_URL)
    assert route.call_count == 1
    assert sleeps.delays == []
    assert sink.waits == []
    error = excinfo.value
    assert (error.method, error.url, error.status) == ("GET", REPO_URL, status)
    assert error.resource == "core"
    assert error.reset is not None and error.reset > time.time()
    assert error.retry_after == 5


@respx.mock
async def test_a_reset_inside_the_budget_is_waited_out_and_the_read_succeeds(
    client: GitHubClient, sink: _RateLimitSink, sleeps: _Sleeps
) -> None:
    route = respx.get(REPO_URL).mock(
        side_effect=[_spent(reset_in=10), httpx.Response(200, json={"ok": True})]
    )
    resp = await client._request("GET", REPO_URL)
    assert resp.status_code == 200
    assert route.call_count == 2
    assert len(sleeps.delays) == 1
    assert 10 <= sleeps.delays[0] <= 12
    assert [resource for _delay, resource in sink.waits] == ["core"]
    assert client.stats.rate_limit_events == 1


@respx.mock
async def test_a_retry_after_later_than_the_reset_sets_the_wait(
    client: GitHubClient, sleeps: _Sleeps
) -> None:
    respx.get(REPO_URL).mock(
        side_effect=[
            _spent(reset_in=2, headers={"retry-after": "20"}),
            httpx.Response(200, json={}),
        ]
    )
    await client._request("GET", REPO_URL)
    assert sleeps.delays == [21]


@respx.mock
async def test_without_a_reset_the_ordinary_schedule_runs_then_raises(
    client: GitHubClient, sleeps: _Sleeps
) -> None:
    route = respx.get(REPO_URL).mock(return_value=_spent(reset_in=None))
    with pytest.raises(RateLimitError) as excinfo:
        await client._request("GET", REPO_URL)
    assert route.call_count == 4
    assert sleeps.delays == [1, 2, 4]
    assert excinfo.value.reset is None


@respx.mock
@pytest.mark.parametrize("retry_after", ["-5", "nan", "-inf", "inf"])
async def test_an_unusable_retry_after_keeps_the_one_minute_advice(
    client: GitHubClient, retry_after: str
) -> None:
    respx.get(REPO_URL).mock(
        return_value=_spent(reset_in=None, headers={"retry-after": retry_after})
    )
    with pytest.raises(RateLimitError) as excinfo:
        await client._request("GET", REPO_URL, max_retries=0)
    assert excinfo.value.retry_after is None
    message = spent_budget_message(excinfo.value, dt.datetime.now(dt.UTC))
    assert "it advises at least one minute" in message
    assert "wait 0 second" not in message


@respx.mock
async def test_a_secondary_limit_is_retried_and_handed_back(
    client: GitHubClient, sleeps: _Sleeps
) -> None:
    route = respx.get(REPO_URL).mock(
        return_value=httpx.Response(
            403,
            headers={
                "retry-after": "3",
                "x-ratelimit-remaining": "4999",
                "x-ratelimit-reset": str(int(time.time() + 3600)),
            },
        )
    )
    resp = await client._request("GET", REPO_URL)
    assert resp.status_code == 403
    assert route.call_count == 4
    assert sleeps.delays == [3, 3, 3]


@respx.mock
async def test_an_external_429_never_raises_the_rate_limit_error(
    client: GitHubClient,
) -> None:
    respx.get(url__startswith=SCORECARD).mock(return_value=_spent(429))
    assert await client.scorecard_score("o", "r") == (429, None)


@respx.mock
async def test_a_refused_remediation_write_returns_its_response(
    client: GitHubClient,
) -> None:
    route = respx.put(f"{REPO_URL}/vulnerability-alerts").mock(return_value=_spent())
    ok, note = await client.enable_dependabot_alerts("o", "r")
    assert not ok
    assert note.startswith("403")
    assert route.call_count == 4


@respx.mock
async def test_a_graphql_query_refused_by_its_spent_budget_raises(
    client: GitHubClient,
) -> None:
    respx.post(f"{API}/graphql").mock(
        return_value=_spent(headers={"x-ratelimit-resource": "graphql"})
    )
    with pytest.raises(RateLimitError) as excinfo:
        await client.repo_graph_batch("o", ["a"])
    assert excinfo.value.resource == "graphql"


@respx.mock
async def test_the_pattern_inventory_read_lets_the_error_through(
    client: GitHubClient,
) -> None:
    respx.get(url__startswith=f"{API}/orgs/o/{PATTERN_CONFIG_PATH}").mock(
        return_value=_spent()
    )
    # Readable, so only the inventory read can raise.
    respx.get(url__startswith=f"{API}/orgs/o/secret-scanning/alerts").mock(
        return_value=httpx.Response(200, json=[])
    )
    with pytest.raises(RateLimitError):
        await client.org_bulk_alerts("o", "secret-scanning")


@respx.mock
async def test_a_reset_just_past_the_wait_budget_is_not_waited_for(
    client: GitHubClient, sleeps: _Sleeps
) -> None:
    respx.get(REPO_URL).mock(
        return_value=_spent(reset_in=API_MAX_TOTAL_WAIT_SECONDS + 5)
    )
    with pytest.raises(RateLimitError):
        await client._request("GET", REPO_URL)
    assert sleeps.delays == []


# --------------------------------------------------------------------------- #
# Command line
# --------------------------------------------------------------------------- #
def _repository(name: str) -> dict:
    return {
        "name": name,
        "full_name": f"o/{name}",
        "html_url": f"https://github.com/o/{name}",
        "size": 10,
        "default_branch": "main",
    }


def _refused_urls() -> Counter[str]:
    return Counter(
        str(call.request.url)
        for call in respx.calls
        if call.response.status_code == 403
    )


@respx.mock
def test_org_report_exits_6_with_nothing_rendered_or_written(tmp_path: Path) -> None:
    respx.get(f"{API}/rate_limit").mock(
        return_value=httpx.Response(
            200,
            json={
                "resources": {
                    "core": {"limit": 5000, "remaining": 5000, "reset": 0},
                    "graphql": {"limit": 5000, "remaining": 5000, "reset": 0},
                }
            },
        )
    )
    respx.get(url__startswith=f"{API}/orgs/o/repos").mock(
        return_value=httpx.Response(200, json=[_repository("a"), _repository("b")])
    )
    respx.route().mock(return_value=_spent())
    site = tmp_path / "site"
    result = cli.invoke(
        app,
        [
            "report",
            "--org",
            "o",
            "--scope",
            "org",
            "--output-dir",
            str(site),
            "--no-color",
        ],
    )
    assert result.exit_code == 6, result.stdout
    text = " ".join(result.stdout.split())
    assert "Rate limit exhausted" in text
    assert "the core rate limit" in text
    assert "UTC (wait 60 minute(s))" in text or "UTC (wait 59 minute(s))" in text
    assert "different token" in text
    assert "Security report" not in result.stdout
    assert not site.exists()
    assert not (tmp_path / "github_output").exists()
    assert not (tmp_path / "step_summary").exists()
    # Refused once each: no URL was retried against a spent budget.
    refused = _refused_urls()
    assert refused
    assert set(refused.values()) == {1}


@respx.mock
def test_repo_report_exits_6_with_no_outputs_written(tmp_path: Path) -> None:
    respx.route().mock(return_value=_spent())
    result = cli.invoke(
        app, ["report", "--repo", "o/r", "--scope", "repo", "--no-color"]
    )
    assert result.exit_code == 6, result.stdout
    assert "Rate limit exhausted" in result.stdout
    assert not (tmp_path / "github_output").exists()
    assert not (tmp_path / "step_summary").exists()
    assert set(_refused_urls().values()) == {1}


@respx.mock
def test_a_graphql_prefetch_refused_for_its_rate_limit_exits_6(
    tmp_path: Path,
) -> None:
    respx.get(f"{API}/rate_limit").mock(return_value=httpx.Response(404))
    respx.get(url__startswith=f"{API}/orgs/o/repos").mock(
        return_value=httpx.Response(200, json=[_repository("a")])
    )
    respx.post(f"{API}/graphql").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": None,
                "errors": [
                    {"type": "RATE_LIMITED", "message": "API rate limit exceeded"}
                ],
            },
        )
    )
    respx.route().mock(return_value=httpx.Response(404, json={}))
    site = tmp_path / "site"
    result = cli.invoke(
        app,
        [
            "report",
            "--org",
            "o",
            "--scope",
            "org",
            "--output-dir",
            str(site),
            "--no-color",
        ],
    )
    assert result.exit_code == 6, result.stdout
    assert "a GraphQL API rate limit is exhausted" in " ".join(result.stdout.split())
    assert not site.exists()
