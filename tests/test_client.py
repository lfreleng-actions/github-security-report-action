# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Transport tests for the async GitHub client (no live network: respx)."""

from __future__ import annotations

import json
import logging
import socket
from collections.abc import AsyncIterator, Callable, Coroutine, Sequence
from typing import Any

import httpx
import pytest
import respx

from github_security_report.client import (
    API_MAX_RETRIES,
    AuthError,
    GitHubClient,
    NetworkError,
    _endpoint_diagnostics,
    _https_endpoint,
    _parse_retry_after,
)
from github_security_report.client import transport as transport_mod
from github_security_report.secret_patterns import (
    EXPLICIT_SECRET_TYPES,
    GENERIC_SECRET_TYPES,
    SECRET_TYPE_FILTER,
)

API = "https://api.github.com"
SCORECARD = "https://api.securityscorecards.dev"


@pytest.fixture
async def client() -> AsyncIterator[GitHubClient]:
    c = GitHubClient("test-token", concurrency=4)
    yield c
    await c.aclose()


@respx.mock
async def test_list_org_repos_skips_disabled_and_empty(client: GitHubClient) -> None:
    respx.get(f"{API}/orgs/o/repos").mock(
        return_value=httpx.Response(
            200,
            json=[
                {"name": "live", "full_name": "o/live", "html_url": "u", "size": 10},
                {"name": "empty", "full_name": "o/empty", "html_url": "u", "size": 0},
                {
                    "name": "dead",
                    "full_name": "o/dead",
                    "html_url": "u",
                    "size": 5,
                    "disabled": True,
                },
            ],
        )
    )
    status, repos = await client.list_org_repos("o")
    assert status == 200
    assert [r.name for r in repos] == ["live"]


@respx.mock
async def test_list_org_repos_reports_incomplete_status(client: GitHubClient) -> None:
    # A first page that succeeds followed by a failing page must surface the
    # failing status so the caller can flag the report as partial.
    page1 = httpx.Response(
        200,
        json=[{"name": "r1", "full_name": "o/r1", "html_url": "u", "size": 10}],
        headers={"Link": f'<{API}/orgs/o/repos?page=2>; rel="next"'},
    )
    page2 = httpx.Response(403)
    route = respx.get(url__startswith=f"{API}/orgs/o/repos")
    route.side_effect = [page1, page2]
    status, repos = await client.list_org_repos("o")
    assert status == 403
    assert [r.name for r in repos] == ["r1"]


@respx.mock
async def test_org_bulk_alerts_paginates(client: GitHubClient) -> None:
    page1 = httpx.Response(
        200,
        json=[{"number": 1}],
        headers={"Link": f'<{API}/orgs/o/code-scanning/alerts?page=2>; rel="next"'},
    )
    page2 = httpx.Response(200, json=[{"number": 2}])
    route = respx.get(url__startswith=f"{API}/orgs/o/code-scanning/alerts")
    route.side_effect = [page1, page2]
    status, alerts = await client.org_bulk_alerts("o", "code-scanning")
    assert status == 200
    assert [a["number"] for a in alerts] == [1, 2]


@respx.mock
async def test_org_bulk_alerts_reports_error_status(client: GitHubClient) -> None:
    # A forbidden sweep must surface its status so callers can degrade affected
    # signals to unknown rather than treating the empty result as clean.
    respx.get(url__startswith=f"{API}/orgs/o/dependabot/alerts").mock(
        return_value=httpx.Response(403)
    )
    status, alerts = await client.org_bulk_alerts("o", "dependabot")
    assert status == 403
    assert alerts == []


@respx.mock
async def test_get_list_later_page_failure_returns_partial_and_status(
    client: GitHubClient,
) -> None:
    # A first page that succeeds followed by a failing page must return the
    # partial items WITH the failing status, so callers know the data is
    # incomplete and do not report a falsely-clean undercount.
    page1 = httpx.Response(
        200,
        json=[{"number": 1}],
        headers={"Link": f'<{API}/orgs/o/dependabot/alerts?page=2>; rel="next"'},
    )
    page2 = httpx.Response(403)
    route = respx.get(url__startswith=f"{API}/orgs/o/dependabot/alerts")
    route.side_effect = [page1, page2]
    status, alerts = await client.org_bulk_alerts("o", "dependabot")
    assert status == 403
    assert [a["number"] for a in alerts] == [1]


@respx.mock
async def test_code_scanning_tools(client: GitHubClient) -> None:
    # Each signal tool is probed via the analyses tool_name filter; CodeQL and
    # Scorecard have analyses, zizmor does not.
    def _side(request: httpx.Request) -> httpx.Response:
        tool = request.url.params.get("tool_name")
        if tool in ("CodeQL", "Scorecard"):
            return httpx.Response(200, json=[{"tool": {"name": tool}}])
        return httpx.Response(200, json=[])

    respx.get(url__startswith=f"{API}/repos/o/r/code-scanning/analyses").mock(
        side_effect=_side
    )
    status, tools = await client.code_scanning_tools("o", "r")
    assert status == 200
    assert tools == {"CodeQL", "Scorecard"}


@respx.mock
async def test_code_scanning_tools_detects_low_frequency_tool(
    client: GitHubClient,
) -> None:
    # A tool the page-by-page scan could have missed (only zizmor present) is
    # detected definitively via its tool_name filter.
    def _side(request: httpx.Request) -> httpx.Response:
        tool = request.url.params.get("tool_name")
        if tool == "zizmor":
            return httpx.Response(200, json=[{"tool": {"name": "zizmor"}}])
        return httpx.Response(200, json=[])

    respx.get(url__startswith=f"{API}/repos/o/r/code-scanning/analyses").mock(
        side_effect=_side
    )
    status, tools = await client.code_scanning_tools("o", "r")
    assert status == 200
    assert tools == {"zizmor"}


@respx.mock
async def test_code_scanning_disabled_returns_404(client: GitHubClient) -> None:
    respx.get(f"{API}/repos/o/r/code-scanning/analyses").mock(
        return_value=httpx.Response(404, json={"message": "no analysis found"})
    )
    status, tools = await client.code_scanning_tools("o", "r")
    assert status == 404
    assert tools == set()


@respx.mock
async def test_secret_scanning_status(client: GitHubClient) -> None:
    respx.get(f"{API}/repos/o/r/secret-scanning/alerts").mock(
        return_value=httpx.Response(404)
    )
    assert await client.secret_scanning_status("o", "r") == 404


# --------------------------------------------------------------------------- #
# Secret scanning: the two-pass sweep over GitHub's three pattern categories
# --------------------------------------------------------------------------- #
PATTERN_CONFIGS = f"{API}/orgs/o/secret-scanning/pattern-configurations"

_GENERIC_ALERT = {
    "number": 2,
    "url": f"{API}/repos/o/r/secret-scanning/alerts/2",
    "secret_type": "generic_private_key",
    "repository": {"name": "r", "full_name": "o/r"},
}
_PASSWORD_ALERT = {
    "number": 4,
    "url": f"{API}/repos/o/r/secret-scanning/alerts/4",
    "secret_type": "password",
    "repository": {"name": "r", "full_name": "o/r"},
}
_DEFAULT_ALERT = {
    "number": 1,
    "url": f"{API}/repos/o/r/secret-scanning/alerts/1",
    "secret_type": "github_personal_access_token",
    "repository": {"name": "r", "full_name": "o/r"},
}


def _mock_pattern_configs(status: int = 404, json: object = None) -> None:
    """Mock the best-effort pattern inventory read every sweep issues first."""
    respx.get(url__startswith=PATTERN_CONFIGS).mock(
        return_value=httpx.Response(status, json=json)
    )


def _secret_type_of(request: httpx.Request) -> str | None:
    """The ``secret_type`` filter one sweep request carried, if any."""
    value = httpx.QueryParams(request.url.query).get("secret_type")
    return str(value) if value is not None else None


def _split_sweep(
    default: httpx.Response, explicit: httpx.Response
) -> Callable[[httpx.Request], httpx.Response]:
    """Answer the unfiltered and secret_type-filtered halves differently.

    Keyed on the request itself rather than on call order, because the two
    halves are issued concurrently.
    """

    def _side(request: httpx.Request) -> httpx.Response:
        return default if _secret_type_of(request) is None else explicit

    return _side


@respx.mock
async def test_secret_scanning_sweep_requests_omitted_patterns(
    client: GitHubClient,
) -> None:
    # The regression guard for issue #146: GitHub's default alert listing
    # excludes the generic and AI-detected patterns, and answers 200 [] rather
    # than an error, so a sweep that drops this filter reports a leaking org as
    # clean. Assert the filter reaches the wire, naming every omitted pattern.
    _mock_pattern_configs()
    route = respx.get(url__startswith=f"{API}/orgs/o/secret-scanning/alerts")
    route.side_effect = _split_sweep(
        httpx.Response(200, json=[]),
        httpx.Response(200, json=[_GENERIC_ALERT, _PASSWORD_ALERT]),
    )
    status, alerts = await client.org_bulk_alerts("o", "secret-scanning")
    assert status == 200
    # The org would otherwise have been reported as clean.
    assert [a["number"] for a in alerts] == [2, 4]
    filters = {_secret_type_of(call.request) for call in route.calls}
    assert filters == {None, SECRET_TYPE_FILTER}
    sent = set(SECRET_TYPE_FILTER.split(","))
    assert sent == set(EXPLICIT_SECRET_TYPES)
    # Both omitted categories must be named; covering only one leaves the other
    # reading as clean, which is the bug in a narrower form.
    assert sent >= set(GENERIC_SECRET_TYPES) and "password" in sent


@respx.mock
async def test_secret_scanning_sweep_merges_both_passes(
    client: GitHubClient,
) -> None:
    # Adding the generic pass must not cost the default patterns their alerts.
    _mock_pattern_configs()
    respx.get(url__startswith=f"{API}/orgs/o/secret-scanning/alerts").mock(
        side_effect=_split_sweep(
            httpx.Response(200, json=[_DEFAULT_ALERT]),
            httpx.Response(200, json=[_GENERIC_ALERT]),
        )
    )
    status, alerts = await client.org_bulk_alerts("o", "secret-scanning")
    assert status == 200
    assert [a["number"] for a in alerts] == [1, 2]


@respx.mock
async def test_secret_scanning_sweep_deduplicates_overlap(
    client: GitHubClient,
) -> None:
    # Should GitHub ever return one alert from both halves, it must be counted
    # once: a doubled count would misreport an offender's severity.
    _mock_pattern_configs()
    respx.get(url__startswith=f"{API}/orgs/o/secret-scanning/alerts").mock(
        side_effect=_split_sweep(
            httpx.Response(200, json=[_GENERIC_ALERT]),
            httpx.Response(200, json=[_GENERIC_ALERT]),
        )
    )
    _status, alerts = await client.org_bulk_alerts("o", "secret-scanning")
    assert [a["number"] for a in alerts] == [2]


@respx.mock
@pytest.mark.parametrize("failing", ["default", "named"])
async def test_secret_scanning_half_failure_degrades_the_sweep(
    client: GitHubClient, failing: str, caplog: pytest.LogCaptureFixture
) -> None:
    # Half a sweep is not an authoritative "clean": whichever pass fails, the
    # status must be non-200 so the signal degrades to unknown rather than
    # reporting the successful pass's answer as the whole truth.
    _mock_pattern_configs()
    ok = httpx.Response(200, json=[])
    forbidden = httpx.Response(403)
    respx.get(url__startswith=f"{API}/orgs/o/secret-scanning/alerts").mock(
        side_effect=_split_sweep(
            forbidden if failing == "default" else ok,
            ok if failing == "default" else forbidden,
        )
    )
    with caplog.at_level(logging.WARNING):
        status, _alerts = await client.org_bulk_alerts("o", "secret-scanning")
    assert status == 403
    assert "completed only one of its two passes" in caplog.text


@respx.mock
async def test_secret_scanning_total_failure_is_not_partial_coverage(
    client: GitHubClient, caplog: pytest.LogCaptureFixture
) -> None:
    # Two passes failing with *different* statuses completed no pass at all.
    # Reporting that as partial coverage would misdirect whoever reads the
    # log; the caller already reports a wholly unreadable sweep.
    _mock_pattern_configs()
    respx.get(url__startswith=f"{API}/orgs/o/secret-scanning/alerts").mock(
        side_effect=_split_sweep(httpx.Response(403), httpx.Response(500))
    )
    with caplog.at_level(logging.WARNING):
        status, _alerts = await client.org_bulk_alerts("o", "secret-scanning")
    assert status == 403
    assert "completed only one of its two passes" not in caplog.text


@respx.mock
async def test_secret_scanning_half_failure_keeps_the_alerts_it_read(
    client: GitHubClient,
) -> None:
    # Positive evidence of a leaked secret is actionable even when the other
    # half of the sweep failed, so the alerts travel with the failing status.
    _mock_pattern_configs()
    respx.get(url__startswith=f"{API}/orgs/o/secret-scanning/alerts").mock(
        side_effect=_split_sweep(
            httpx.Response(500),
            httpx.Response(200, json=[_GENERIC_ALERT]),
        )
    )
    status, alerts = await client.org_bulk_alerts("o", "secret-scanning")
    assert status == 500
    assert [a["number"] for a in alerts] == [2]


@respx.mock
async def test_repo_secret_scanning_counts_omitted_patterns(
    client: GitHubClient,
) -> None:
    # The per-repo path (repo-scope runs) needs the same two-pass read; without
    # it, sigul-sign-docker's two private keys read as a clean repository.
    _mock_pattern_configs()
    route = respx.get(url__startswith=f"{API}/repos/o/r/secret-scanning/alerts")
    route.side_effect = _split_sweep(
        httpx.Response(200, json=[]),
        httpx.Response(
            200,
            json=[
                _GENERIC_ALERT,
                {
                    **_GENERIC_ALERT,
                    "number": 3,
                    "url": f"{API}/repos/o/r/secret-scanning/alerts/3",
                },
            ],
        ),
    )
    enabled_status, read_status, open_count = await client.repo_secret_scanning(
        "o", "r"
    )
    assert (enabled_status, read_status, open_count) == (200, 200, 2)
    assert {_secret_type_of(call.request) for call in route.calls} == {
        None,
        SECRET_TYPE_FILTER,
    }


@respx.mock
@pytest.mark.parametrize("forbidden_half", ["default", "explicit"])
async def test_repo_secret_scanning_separates_its_two_statuses(
    client: GitHubClient, forbidden_half: str
) -> None:
    # Repo scope has no independent enablement probe, so one status used to do
    # both jobs. A 200 from either half proves the endpoint is readable and the
    # feature on, so enablement stays 200 while the read status degrades --
    # otherwise a forbidden half would classify a repository with two known
    # private keys as "insufficient permission" instead of as an offender.
    _mock_pattern_configs()
    with_alerts = httpx.Response(200, json=[_GENERIC_ALERT])
    forbidden = httpx.Response(403)
    respx.get(url__startswith=f"{API}/repos/o/r/secret-scanning/alerts").mock(
        side_effect=_split_sweep(
            forbidden if forbidden_half == "default" else with_alerts,
            with_alerts if forbidden_half == "default" else forbidden,
        )
    )
    enabled_status, read_status, open_count = await client.repo_secret_scanning(
        "o", "r"
    )
    assert enabled_status == 200
    assert read_status == 403
    assert open_count == 1


@respx.mock
async def test_repo_secret_scanning_paginated_failure_keeps_enablement(
    client: GitHubClient,
) -> None:
    # Both halves can end on a failing status and still be holding alerts: a
    # page that fails mid-pagination returns what it already collected. An
    # alert can only have come out of a 200 body, so it proves the endpoint was
    # enabled and readable -- without that, a 403 on page two would classify a
    # repository whose page one listed a leaked private key as "insufficient
    # permission" rather than as an offender.
    _mock_pattern_configs()

    def _paginated(request: httpx.Request) -> httpx.Response:
        if "page=2" in str(request.url):
            return httpx.Response(403)
        return httpx.Response(
            200,
            json=[_GENERIC_ALERT],
            headers={
                "Link": (f'<{API}/repos/o/r/secret-scanning/alerts?page=2>; rel="next"')
            },
        )

    respx.get(url__startswith=f"{API}/repos/o/r/secret-scanning/alerts").mock(
        side_effect=_paginated
    )
    enabled_status, read_status, open_count = await client.repo_secret_scanning(
        "o", "r"
    )
    assert enabled_status == 200  # an alert in hand proves the endpoint answered
    assert read_status == 403  # ...but the list is still incomplete
    assert open_count == 1


@respx.mock
async def test_repo_secret_scanning_disabled_reports_404_enablement(
    client: GitHubClient,
) -> None:
    # Both halves 404: the feature really is off, and must still nag rather
    # than be softened into an unknown by the new two-status split.
    _mock_pattern_configs()
    respx.get(url__startswith=f"{API}/repos/o/r/secret-scanning/alerts").mock(
        return_value=httpx.Response(404)
    )
    assert await client.repo_secret_scanning("o", "r") == (404, 404, 0)


@respx.mock
async def test_unknown_generic_pattern_slug_warns(
    client: GitHubClient, caplog: pytest.LogCaptureFixture
) -> None:
    # A slug GitHub no longer recognises is answered with 200 [], which is
    # indistinguishable from clean, so the rot has to be reported out of band.
    kept = [s for s in GENERIC_SECRET_TYPES if s != "rsa_private_key"]
    _mock_pattern_configs(
        200, {"provider_pattern_overrides": [{"slug": slug} for slug in kept]}
    )
    respx.get(url__startswith=f"{API}/orgs/o/secret-scanning/alerts").mock(
        return_value=httpx.Response(200, json=[])
    )
    with caplog.at_level(logging.WARNING):
        await client.org_bulk_alerts("o", "secret-scanning")
    assert "rsa_private_key" in caplog.text


@respx.mock
async def test_unreadable_pattern_inventory_stays_quiet(
    client: GitHubClient, caplog: pytest.LogCaptureFixture
) -> None:
    # The inventory endpoint needs an org permission the tool does not ask for,
    # and the owner may be a user account, so 404 is the ordinary answer for a
    # correctly-configured run and must not nag. The sweep still happens.
    _mock_pattern_configs(404)
    route = respx.get(url__startswith=f"{API}/orgs/o/secret-scanning/alerts")
    route.mock(return_value=httpx.Response(200, json=[]))
    with caplog.at_level(logging.WARNING):
        status, _alerts = await client.org_bulk_alerts("o", "secret-scanning")
    assert status == 200
    assert len(route.calls) == 2
    assert caplog.text == ""


@respx.mock
@pytest.mark.parametrize(
    "failure",
    [
        pytest.param(httpx.ConnectError("boom"), id="transport-failure"),
        pytest.param(httpx.Response(503), id="retryable-server-error"),
        pytest.param(httpx.Response(429), id="rate-limited"),
    ],
)
async def test_unreadable_pattern_inventory_never_warns_or_aborts(
    client: GitHubClient,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    failure: httpx.Response | Exception,
) -> None:
    # Being best-effort has to include the transport *and* its retry chatter.
    # ``_request`` raises NetworkError once the retry budget is spent, so
    # without a guard a timeout here would abort the run before a single alert
    # was read; and it logs each retry at WARNING, so an optional probe would
    # otherwise fill a healthy run's output with warnings about a signal
    # nothing depends on. Both retryable statuses are covered because they take
    # different paths through the retry planner (server error vs rate limit).
    async def _no_sleep(delay: float) -> None:
        return None

    monkeypatch.setattr(
        "github_security_report.client.transport.asyncio.sleep", _no_sleep
    )
    route = respx.get(url__startswith=PATTERN_CONFIGS)
    if isinstance(failure, httpx.Response):
        route.mock(return_value=failure)
    else:
        route.mock(side_effect=failure)
    respx.get(url__startswith=f"{API}/orgs/o/secret-scanning/alerts").mock(
        side_effect=_split_sweep(
            httpx.Response(200, json=[]),
            httpx.Response(200, json=[_GENERIC_ALERT]),
        )
    )
    with caplog.at_level(logging.WARNING):
        status, alerts = await client.org_bulk_alerts("o", "secret-scanning")
    assert status == 200
    assert [a["number"] for a in alerts] == [2]
    assert caplog.text == ""  # not a single retry warning from the optional read


@respx.mock
async def test_malformed_pattern_inventory_does_not_abort_the_sweep(
    client: GitHubClient, caplog: pytest.LogCaptureFixture
) -> None:
    # A 200 carrying something other than JSON -- a proxy error page, a
    # truncated body -- tells us nothing about the pattern list. Letting
    # resp.json() raise would fail a security report over an optional check,
    # and would leak the pooled connection on the way out.
    respx.get(url__startswith=PATTERN_CONFIGS).mock(
        return_value=httpx.Response(
            200, content=b"<html>502 Bad Gateway</html>", headers={}
        )
    )
    respx.get(url__startswith=f"{API}/orgs/o/secret-scanning/alerts").mock(
        side_effect=_split_sweep(
            httpx.Response(200, json=[]),
            httpx.Response(200, json=[_GENERIC_ALERT]),
        )
    )
    with caplog.at_level(logging.WARNING):
        status, alerts = await client.org_bulk_alerts("o", "secret-scanning")
    assert status == 200
    assert [a["number"] for a in alerts] == [2]
    assert caplog.text == ""  # unverifiable, not a reportable fault


@respx.mock
async def test_rejected_credentials_on_pattern_inventory_still_abort(
    client: GitHubClient,
) -> None:
    # The one failure the optional check must NOT swallow. AuthError subclasses
    # NetworkError, so a bare "except NetworkError" here would turn rejected
    # credentials into a shrug and let the run render every repository as clean
    # out of nothing but 401s.
    respx.get(url__startswith=PATTERN_CONFIGS).mock(
        return_value=httpx.Response(401, json={"message": "Bad credentials"})
    )
    # Deliberately unrealistic -- a rejected token would fail this read too --
    # so that the inventory read is the only thing that can raise, and swallowing
    # its 401 fails as a plain "DID NOT RAISE" rather than as a knock-on error.
    respx.get(url__startswith=f"{API}/orgs/o/secret-scanning/alerts").mock(
        return_value=httpx.Response(200, json=[])
    )
    with pytest.raises(AuthError):
        await client.org_bulk_alerts("o", "secret-scanning")


@respx.mock
async def test_dependabot_enabled_true_false_and_indeterminate(
    client: GitHubClient,
) -> None:
    route = respx.post(f"{API}/graphql")
    route.side_effect = [
        httpx.Response(
            200, json={"data": {"repository": {"hasVulnerabilityAlertsEnabled": True}}}
        ),
        httpx.Response(
            200, json={"data": {"repository": {"hasVulnerabilityAlertsEnabled": False}}}
        ),
        httpx.Response(200, json={"data": {"repository": None}}),
    ]
    assert await client.dependabot_enabled("o", "r") is True
    assert await client.dependabot_enabled("o", "r") is False
    assert await client.dependabot_enabled("o", "r") is None


@respx.mock
async def test_scorecard_score(client: GitHubClient) -> None:
    respx.get(f"{SCORECARD}/projects/github.com/o/good").mock(
        return_value=httpx.Response(200, json={"score": 8.2})
    )
    respx.get(f"{SCORECARD}/projects/github.com/o/none").mock(
        return_value=httpx.Response(404)
    )
    assert await client.scorecard_score("o", "good") == (200, 8.2)
    assert await client.scorecard_score("o", "none") == (404, None)


@respx.mock
async def test_backoff_retries_then_succeeds(
    client: GitHubClient,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    slept: list[float] = []

    async def _fake_sleep(delay: float) -> None:
        slept.append(delay)

    monkeypatch.setattr(
        "github_security_report.client.transport.asyncio.sleep", _fake_sleep
    )
    route = respx.get(f"{API}/repos/o/r/secret-scanning/alerts")
    route.side_effect = [
        httpx.Response(429, headers={"retry-after": "1"}),
        httpx.Response(200, json=[]),
    ]
    with caplog.at_level(logging.WARNING):
        status = await client.secret_scanning_status("o", "r")
    assert status == 200
    assert slept == [1.0]
    # An ordinary read still warns on retry: _request's ``quiet`` mode exists
    # for optional probes only, and must not become the default. Losing this
    # would hide rate limiting and server errors from whoever runs the report.
    assert "rate limited on" in caplog.text


@respx.mock
async def test_429_without_headers_is_retried(
    client: GitHubClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A 429 carries no Retry-After and no x-ratelimit-remaining header. It still
    # means "Too Many Requests", so the client must back off on the shared
    # schedule rather than returning the un-retried 429.
    slept: list[float] = []

    async def _fake_sleep(delay: float) -> None:
        slept.append(delay)

    monkeypatch.setattr(
        "github_security_report.client.transport.asyncio.sleep", _fake_sleep
    )
    route = respx.get(f"{API}/repos/o/r/secret-scanning/alerts")
    route.side_effect = [
        httpx.Response(429),
        httpx.Response(200, json=[]),
    ]
    status = await client.secret_scanning_status("o", "r")
    assert status == 200
    # Backed off once on the default schedule (no Retry-After to honour).
    assert len(slept) == 1 and slept[0] > 0.0


@respx.mock
async def test_403_with_malformed_retry_after_is_retried(
    client: GitHubClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A 403 carrying a Retry-After header is secondary rate limiting even when
    # the value is unparsable. Its mere presence must trigger a backoff on the
    # exponential schedule rather than being mistaken for a permission error.
    slept: list[float] = []

    async def _fake_sleep(delay: float) -> None:
        slept.append(delay)

    monkeypatch.setattr(
        "github_security_report.client.transport.asyncio.sleep", _fake_sleep
    )
    route = respx.get(f"{API}/repos/o/r/secret-scanning/alerts")
    route.side_effect = [
        httpx.Response(403, headers={"retry-after": "not-a-number"}),
        httpx.Response(200, json=[]),
    ]
    status = await client.secret_scanning_status("o", "r")
    assert status == 200
    assert len(slept) == 1 and slept[0] > 0.0


@respx.mock
async def test_genuine_403_not_retried(client: GitHubClient) -> None:
    # A 403 with rate-limit budget remaining is a real permission error.
    respx.get(f"{API}/repos/o/r/code-scanning/analyses").mock(
        return_value=httpx.Response(403, headers={"x-ratelimit-remaining": "4999"})
    )
    status, tools = await client.code_scanning_tools("o", "r")
    assert status == 403


@respx.mock
async def test_github_transport_failure_raises_network_error(
    client: GitHubClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A transport failure (DNS/TLS/connect/read) to the GitHub API that
    # survives every retry must hard-fail with NetworkError rather than
    # fabricating a degraded result: a report built without live data is
    # actively misleading (e.g. empty tables rendered as "all clean").
    slept: list[float] = []

    async def _fake_sleep(delay: float) -> None:
        slept.append(delay)

    monkeypatch.setattr(
        "github_security_report.client.transport.asyncio.sleep", _fake_sleep
    )
    route = respx.get(f"{API}/repos/o/r/secret-scanning/alerts")
    route.mock(side_effect=httpx.ConnectError("boom"))

    with pytest.raises(NetworkError) as excinfo:
        await client.secret_scanning_status("o", "r")

    # The initial attempt plus API_MAX_RETRIES retries were made, with
    # exponential backoff (1s, 2s, 4s) between them.
    assert route.call_count == API_MAX_RETRIES + 1
    assert slept == [1.0, 2.0, 4.0]
    # The message carries the friendly line plus a dedicated host/port line.
    msg = str(excinfo.value)
    assert "GitHub API is unreachable" in msg
    assert "host=api.github.com" in msg
    assert "port=443" in msg


async def test_endpoint_diagnostics_reports_resolved_addresses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The diagnostics line carries the host, the resolved IP(s) and the port so
    # an operator can tell a DNS failure from a host that resolves but will not
    # connect. The resolver runs through the event loop (not blocking
    # socket.getaddrinfo); patch the bounded wait_for to return a fixed answer.
    async def _fake_wait_for(
        awaitable: Coroutine[Any, Any, Any], timeout: float
    ) -> object:
        awaitable.close()  # the real wait_for awaits it; close to avoid a warning
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("140.82.112.3", 443))]

    monkeypatch.setattr(transport_mod.asyncio, "wait_for", _fake_wait_for)
    line = await _endpoint_diagnostics("https://api.github.com/repos/o/r")
    assert line == "host=api.github.com ip=140.82.112.3 port=443"


async def test_endpoint_diagnostics_dns_timeout_falls_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A slow or hanging resolver must not stall the event loop while the run is
    # already aborting: the bounded wait_for gives up and the address falls back
    # to "unresolved (timed out)" rather than blocking on socket.getaddrinfo.
    async def _timeout(awaitable: Coroutine[Any, Any, Any], timeout: float) -> object:
        awaitable.close()  # the real wait_for awaits it; close to avoid a warning
        # asyncio.wait_for raises asyncio.TimeoutError on every supported Python
        # version; on 3.10 it is distinct from the builtin TimeoutError (an
        # OSError subclass), so raise the exact type wait_for would raise.
        raise transport_mod.asyncio.TimeoutError

    monkeypatch.setattr(transport_mod.asyncio, "wait_for", _timeout)
    line = await _endpoint_diagnostics("https://api.github.com/repos/o/r")
    assert line == "host=api.github.com ip=unresolved (timed out) port=443"


def test_parse_retry_after_delta_seconds() -> None:
    # The common GitHub form: an integer number of seconds.
    assert _parse_retry_after("30") == 30.0
    assert _parse_retry_after(" 5 ") == 5.0
    # Absent or empty yields None (not rate limited via this header).
    assert _parse_retry_after(None) is None
    assert _parse_retry_after("") is None


def test_parse_retry_after_http_date_does_not_raise() -> None:
    # RFC 7231 permits an HTTP-date; float() would raise ValueError on it and
    # crash rate-limit handling. A future date yields a positive wait; a past
    # date clamps to 0.0; an unparsable value yields None.
    future = "Wed, 21 Oct 2099 07:28:00 GMT"
    secs = _parse_retry_after(future)
    assert secs is not None and secs > 0.0
    assert _parse_retry_after("Wed, 21 Oct 1999 07:28:00 GMT") == 0.0
    assert _parse_retry_after("not-a-date") is None


@respx.mock
async def test_external_transport_failure_degrades_not_raises(
    client: GitHubClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A transport failure to the third-party Scorecard API must NOT abort the
    # whole run; it degrades that one signal to an indeterminate 503 so a
    # flaky external dependency never blocks the GitHub report.
    async def _fake_sleep(delay: float) -> None:
        return None

    monkeypatch.setattr(
        "github_security_report.client.transport.asyncio.sleep", _fake_sleep
    )
    respx.get(url__startswith=f"{SCORECARD}/projects/github.com/o/r").mock(
        side_effect=httpx.ConnectError("boom")
    )
    status, score = await client.scorecard_score("o", "r")
    assert status == 503
    assert score is None


@respx.mock
async def test_rejected_credentials_raise_auth_error(client: GitHubClient) -> None:
    # A 401 condemns every remaining read, so degrading it would render the
    # whole report as "no data" / "all clean" -- a false negative a scheduled
    # run would publish over a good report.
    respx.get(f"{API}/repos/o/r/secret-scanning/alerts").mock(
        return_value=httpx.Response(401, json={"message": "Bad credentials"})
    )
    with pytest.raises(AuthError) as excinfo:
        await client.secret_scanning_status("o", "r")
    message = str(excinfo.value)
    assert "401" in message
    # The message has to name the remedy: the operator's next action is to
    # check the token, not to retry.
    assert "expired" in message or "revoked" in message


async def test_auth_error_is_a_network_error() -> None:
    # Callers that already abort on an unusable API keep aborting without
    # having to learn about the new type.
    assert issubclass(AuthError, NetworkError)


@respx.mock
async def test_rejected_credentials_are_not_retried(
    client: GitHubClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Retrying rejected credentials cannot help and only delays the abort.
    slept: list[float] = []

    async def _fake_sleep(delay: float) -> None:
        slept.append(delay)

    monkeypatch.setattr(
        "github_security_report.client.transport.asyncio.sleep", _fake_sleep
    )
    route = respx.get(f"{API}/repos/o/r/secret-scanning/alerts").mock(
        return_value=httpx.Response(401)
    )
    with pytest.raises(AuthError):
        await client.secret_scanning_status("o", "r")
    assert route.call_count == 1
    assert slept == []


@respx.mock
async def test_external_401_does_not_abort_the_run(client: GitHubClient) -> None:
    # The Scorecard endpoint is unauthenticated and third-party: whatever it
    # says about credentials tells us nothing about the GitHub token, so it
    # degrades that one signal instead of aborting.
    respx.get(url__startswith=f"{SCORECARD}/projects/github.com/o/r").mock(
        return_value=httpx.Response(401)
    )
    status, score = await client.scorecard_score("o", "r")
    assert status == 401
    assert score is None


@respx.mock
async def test_org_workflow_rulesets(client: GitHubClient) -> None:
    respx.get(url__regex=r"orgs/o/rulesets($|\?)").mock(
        return_value=httpx.Response(
            200,
            json=[
                {
                    "id": 1,
                    "name": "Zizmor scans",
                    "target": "branch",
                    "enforcement": "active",
                },
                {
                    "id": 2,
                    "name": "Evaluate only",
                    "target": "branch",
                    "enforcement": "evaluate",
                },
            ],
        )
    )
    respx.get(f"{API}/orgs/o/rulesets/1").mock(
        return_value=httpx.Response(
            200,
            json={
                "name": "Zizmor scans",
                "enforcement": "active",
                "rules": [{"type": "workflows", "parameters": {"workflows": []}}],
            },
        )
    )
    status, details = await client.org_workflow_rulesets("o")
    assert status == 200
    # Only the active ruleset's detail is fetched; the evaluate-only one is skipped.
    assert [d["name"] for d in details] == ["Zizmor scans"]


@respx.mock
async def test_org_workflow_rulesets_forbidden(client: GitHubClient) -> None:
    respx.get(url__regex=r"orgs/o/rulesets($|\?)").mock(
        return_value=httpx.Response(403, headers={"x-ratelimit-remaining": "4999"})
    )
    status, details = await client.org_workflow_rulesets("o")
    assert status == 403
    assert details == []


@respx.mock
async def test_repo_branch_rules(client: GitHubClient) -> None:
    respx.get(f"{API}/repos/o/r/rules/branches/main").mock(
        return_value=httpx.Response(200, json=[{"type": "workflows", "parameters": {}}])
    )
    status, rules = await client.repo_branch_rules("o", "r", "main")
    assert status == 200
    assert rules[0]["type"] == "workflows"


# --------------------------------------------------------------------------- #
# Dependabot posture + release/tag freshness probes
# --------------------------------------------------------------------------- #
@respx.mock
async def test_automated_security_fixes_enabled(client: GitHubClient) -> None:
    respx.get(f"{API}/repos/o/r/automated-security-fixes").mock(
        return_value=httpx.Response(200, json={"enabled": True, "paused": False})
    )
    assert await client.automated_security_fixes("o", "r") is True


@respx.mock
async def test_automated_security_fixes_404_is_disabled(client: GitHubClient) -> None:
    respx.get(f"{API}/repos/o/r/automated-security-fixes").mock(
        return_value=httpx.Response(404)
    )
    assert await client.automated_security_fixes("o", "r") is False


@respx.mock
async def test_automated_security_fixes_error_is_indeterminate(
    client: GitHubClient,
) -> None:
    respx.get(f"{API}/repos/o/r/automated-security-fixes").mock(
        return_value=httpx.Response(403, headers={"x-ratelimit-remaining": "4999"})
    )
    assert await client.automated_security_fixes("o", "r") is None


@respx.mock
async def test_private_vulnerability_reporting_enabled(client: GitHubClient) -> None:
    respx.get(f"{API}/repos/o/r/private-vulnerability-reporting").mock(
        return_value=httpx.Response(200, json={"enabled": True})
    )
    assert await client.private_vulnerability_reporting("o", "r") is True


@respx.mock
async def test_private_vulnerability_reporting_disabled(client: GitHubClient) -> None:
    respx.get(f"{API}/repos/o/r/private-vulnerability-reporting").mock(
        return_value=httpx.Response(200, json={"enabled": False})
    )
    assert await client.private_vulnerability_reporting("o", "r") is False


@respx.mock
async def test_private_vulnerability_reporting_error_is_indeterminate(
    client: GitHubClient,
) -> None:
    # Any non-200 (e.g. 404 or 422) is treated as indeterminate rather than a
    # confirmed disabled; 422 here is just a representative error status.
    respx.get(f"{API}/repos/o/r/private-vulnerability-reporting").mock(
        return_value=httpx.Response(422, headers={"x-ratelimit-remaining": "4999"})
    )
    assert await client.private_vulnerability_reporting("o", "r") is None


# --------------------------------------------------------------------------- #
# Remediation writes
# --------------------------------------------------------------------------- #
@respx.mock
async def test_enable_dependabot_alerts_ok(client: GitHubClient) -> None:
    route = respx.put(f"{API}/repos/o/r/vulnerability-alerts").mock(
        return_value=httpx.Response(204)
    )
    ok, note = await client.enable_dependabot_alerts("o", "r")
    assert route.called
    assert ok is True
    assert note == ""


@respx.mock
async def test_enable_dependabot_alerts_failure_carries_note(
    client: GitHubClient,
) -> None:
    respx.put(f"{API}/repos/o/r/vulnerability-alerts").mock(
        return_value=httpx.Response(403, json={"message": "Forbidden"})
    )
    ok, note = await client.enable_dependabot_alerts("o", "r")
    assert ok is False
    assert note.startswith("403")
    assert "Forbidden" in note


@respx.mock
async def test_enable_dependabot_security_updates_enables_alerts_first(
    client: GitHubClient,
) -> None:
    alerts = respx.put(f"{API}/repos/o/r/vulnerability-alerts").mock(
        return_value=httpx.Response(204)
    )
    fixes = respx.put(f"{API}/repos/o/r/automated-security-fixes").mock(
        return_value=httpx.Response(204)
    )
    ok, note = await client.enable_dependabot_security_updates("o", "r")
    assert alerts.called and fixes.called
    assert ok is True
    assert note == ""


@respx.mock
async def test_enable_dependabot_security_updates_aborts_when_alerts_fail(
    client: GitHubClient,
) -> None:
    respx.put(f"{API}/repos/o/r/vulnerability-alerts").mock(
        return_value=httpx.Response(403, json={"message": "nope"})
    )
    fixes = respx.put(f"{API}/repos/o/r/automated-security-fixes").mock(
        return_value=httpx.Response(204)
    )
    ok, note = await client.enable_dependabot_security_updates("o", "r")
    assert ok is False
    # The prerequisite failed, so the security-updates write is never attempted.
    assert not fixes.called
    assert note.startswith("vulnerability-alerts -> 403")


@respx.mock
async def test_enable_private_vulnerability_reporting_ok(
    client: GitHubClient,
) -> None:
    route = respx.put(f"{API}/repos/o/r/private-vulnerability-reporting").mock(
        return_value=httpx.Response(204)
    )
    ok, note = await client.enable_private_vulnerability_reporting("o", "r")
    assert route.called
    assert ok is True
    assert note == ""


@respx.mock
async def test_enable_codeql_default_setup_accepts_202(
    client: GitHubClient,
) -> None:
    route = respx.patch(f"{API}/repos/o/r/code-scanning/default-setup").mock(
        return_value=httpx.Response(202, json={"run_id": 1})
    )
    ok, note = await client.enable_codeql_default_setup("o", "r")
    assert route.called
    assert ok is True
    assert note == "accepted (async)"


@respx.mock
async def test_enable_codeql_default_setup_accepts_200(
    client: GitHubClient,
) -> None:
    # A synchronous update returns 200 OK; treat it as success with no
    # async hint.
    route = respx.patch(f"{API}/repos/o/r/code-scanning/default-setup").mock(
        return_value=httpx.Response(200, json={"state": "configured"})
    )
    ok, note = await client.enable_codeql_default_setup("o", "r")
    assert route.called
    assert ok is True
    assert note == ""


@respx.mock
async def test_enable_codeql_default_setup_reports_unsupported(
    client: GitHubClient,
) -> None:
    # A repo with no CodeQL-supported languages returns a 4xx; non-fatal.
    respx.patch(f"{API}/repos/o/r/code-scanning/default-setup").mock(
        return_value=httpx.Response(422, json={"message": "no languages"})
    )
    ok, note = await client.enable_codeql_default_setup("o", "r")
    assert ok is False
    assert note.startswith("422")


@respx.mock
async def test_enable_secret_scanning_ok(client: GitHubClient) -> None:
    route = respx.patch(f"{API}/repos/o/r").mock(
        return_value=httpx.Response(200, json={"name": "r"})
    )
    ok, note = await client.enable_secret_scanning("o", "r")
    assert route.called
    assert ok is True
    assert note == ""


@respx.mock
async def test_enable_secret_scanning_failure_carries_note(
    client: GitHubClient,
) -> None:
    respx.patch(f"{API}/repos/o/r").mock(
        return_value=httpx.Response(403, json={"message": "Forbidden"})
    )
    ok, note = await client.enable_secret_scanning("o", "r")
    assert ok is False
    assert note.startswith("403")


# --------------------------------------------------------------------------- #
# Batched per-repo GraphQL prefetch
# --------------------------------------------------------------------------- #
def _graph_repo_node(
    *,
    enabled: bool | None = True,
    config_text: str | None = None,
    tag_target: dict | None = None,
    # A GraphQL list entry can be null (a sub-object that errored), so the
    # release nodes are deliberately nullable here. Sequence (not list) keeps
    # the parameter covariant, so a list of concretely-typed dicts is accepted.
    releases: Sequence[dict | None] | None = None,
    latest_release: dict | None = None,
    pull_requests: Sequence[dict | str | None] | None = None,
    pull_request_total: int | None = None,
) -> dict:
    """Build one repository alias node as the batched query returns it."""
    return {
        "hasVulnerabilityAlertsEnabled": enabled,
        "dependabotConfig": (
            {"text": config_text} if config_text is not None else None
        ),
        "tags": {"nodes": [{"target": tag_target}] if tag_target else []},
        "latestRelease": latest_release,
        "releases": {"nodes": list(releases or [])},
        "pullRequests": {
            "totalCount": (
                pull_request_total
                if pull_request_total is not None
                else len(pull_requests or [])
            ),
            "nodes": list(pull_requests or []),
        },
    }


@respx.mock
async def test_repo_graph_batch_parses_aliases(client: GitHubClient) -> None:
    # r0: lightweight tag, a config, a latest release plus a newer pre-release;
    # r1: a null alias (unreadable) -> defaults.
    v090 = {
        "tagName": "v0.9.0",
        "isLatest": True,
        "isPrerelease": False,
        "isDraft": False,
        "immutable": False,
        "publishedAt": "2026-01-01T00:00:00Z",
        "createdAt": "2026-01-01T00:00:00Z",
    }
    r0 = _graph_repo_node(
        enabled=True,
        config_text="version: 2\n",
        tag_target={"__typename": "Commit", "committedDate": "2025-12-31T00:00:00Z"},
        latest_release=v090,
        releases=[
            {
                "tagName": "v1.0.0-alpha1",
                "isLatest": False,
                "isPrerelease": True,
                "isDraft": False,
                "immutable": False,
                "publishedAt": "2026-02-01T00:00:00Z",
                "createdAt": "2026-02-01T00:00:00Z",
            },
            v090,
            {
                "tagName": "draft",
                "isLatest": False,
                "isPrerelease": False,
                "isDraft": True,
                "immutable": False,
                "publishedAt": None,
                "createdAt": "2026-03-01T00:00:00Z",
            },
        ],
    )
    respx.post(f"{API}/graphql").mock(
        return_value=httpx.Response(200, json={"data": {"r0": r0, "r1": None}})
    )
    out = await client.repo_graph_batch("o", ["a", "b"])

    a = out["a"]
    assert a.dependabot_alerts_enabled is True
    assert a.dependabot_config == "version: 2\n"
    assert a.latest_tag_at is not None and a.latest_tag_at.year == 2025
    # The latest release carries the (latest) badge; the newer pre-release is the
    # last published. The draft is excluded entirely.
    assert a.latest_release is not None and a.latest_release.tag == "v0.9.0"
    assert a.latest_release.is_latest is True
    assert a.last_published_release is not None
    assert a.last_published_release.tag == "v1.0.0-alpha1"
    assert a.latest_release_at is not None and a.latest_release_at.month == 1

    # A null alias degrades to unreadable defaults rather than being
    # mislabelled with confident negatives (e.g. "never released").
    b = out["b"]
    assert b.unreadable is True
    assert a.unreadable is False
    assert b.dependabot_alerts_enabled is None
    assert b.latest_release is None
    assert b.dependabot_config is None


@respx.mock
async def test_repo_graph_batch_latest_outside_window(client: GitHubClient) -> None:
    # Regression: the bounded releases window is full of newer draft and
    # pre-release entries, none flagged isLatest, so the "Latest" release would
    # be missed if derived from the window alone. The authoritative
    # latestRelease field must still populate latest_release / latest_release_at.
    window = [
        {
            "tagName": f"v2.0.0-rc{i}",
            "isLatest": False,
            "isPrerelease": True,
            "isDraft": False,
            "immutable": False,
            "publishedAt": f"2026-05-{i:02d}T00:00:00Z",
            "createdAt": f"2026-05-{i:02d}T00:00:00Z",
        }
        for i in range(1, 26)
    ]
    latest = {
        "tagName": "v1.5.0",
        "isLatest": True,
        "isPrerelease": False,
        "isDraft": False,
        "immutable": True,
        "publishedAt": "2026-01-15T00:00:00Z",
        "createdAt": "2026-01-15T00:00:00Z",
    }
    node = _graph_repo_node(latest_release=latest, releases=window)
    respx.post(f"{API}/graphql").mock(
        return_value=httpx.Response(200, json={"data": {"r0": node}})
    )
    out = await client.repo_graph_batch("o", ["a"])

    a = out["a"]
    # Latest comes from latestRelease, not the window, and carries the badge.
    assert a.latest_release is not None
    assert a.latest_release.tag == "v1.5.0"
    assert a.latest_release.is_latest is True
    assert a.latest_release.immutable is True
    assert a.latest_release_at is not None and a.latest_release_at.month == 1
    # The newest published entry overall is still surfaced as last-published.
    assert a.last_published_release is not None
    assert a.last_published_release.tag == "v2.0.0-rc25"


@respx.mock
async def test_repo_graph_batch_annotated_tag(client: GitHubClient) -> None:
    node = _graph_repo_node(
        tag_target={
            "__typename": "Tag",
            "target": {"committedDate": "2025-06-01T00:00:00Z"},
        },
    )
    respx.post(f"{API}/graphql").mock(
        return_value=httpx.Response(200, json={"data": {"r0": node}})
    )
    out = await client.repo_graph_batch("o", ["a"])
    assert out["a"].latest_tag_at is not None
    assert out["a"].latest_tag_at.month == 6


@respx.mock
async def test_repo_graph_batch_null_tag_node(client: GitHubClient) -> None:
    # GraphQL connection nodes can be null (e.g. a sub-object errored). A null
    # tag node must degrade to no tag date, not abort the whole collection.
    node = _graph_repo_node()
    node["tags"] = {"nodes": [None]}
    respx.post(f"{API}/graphql").mock(
        return_value=httpx.Response(200, json={"data": {"r0": node}})
    )
    out = await client.repo_graph_batch("o", ["a"])
    assert out["a"].latest_tag_at is None


@respx.mock
async def test_repo_graph_batch_null_release_node(client: GitHubClient) -> None:
    # GraphQL list entries can be null (e.g. a sub-object errored). A null entry
    # among the release nodes must be skipped, not abort the whole collection.
    good = {
        "tagName": "v1.0.0",
        "isLatest": True,
        "isPrerelease": False,
        "isDraft": False,
        "immutable": True,
        "publishedAt": "2026-01-01T00:00:00Z",
        "createdAt": "2026-01-01T00:00:00Z",
    }
    node = _graph_repo_node(releases=[None, good])
    respx.post(f"{API}/graphql").mock(
        return_value=httpx.Response(200, json={"data": {"r0": node}})
    )
    out = await client.repo_graph_batch("o", ["a"])
    assert out["a"].last_published_release is not None
    assert out["a"].last_published_release.tag == "v1.0.0"


@respx.mock
async def test_repo_graph_batch_null_immutable_is_indeterminate(
    client: GitHubClient,
) -> None:
    # GitHub's GraphQL ``immutable`` field is nullable; a null/missing value
    # must parse to None (indeterminate), not be coerced to False (mutable).
    null_immutable = {
        "tagName": "v1.0.0",
        "isLatest": True,
        "isPrerelease": False,
        "isDraft": False,
        "immutable": None,
        "publishedAt": "2026-01-01T00:00:00Z",
        "createdAt": "2026-01-01T00:00:00Z",
    }
    node = _graph_repo_node(latest_release=null_immutable, releases=[null_immutable])
    respx.post(f"{API}/graphql").mock(
        return_value=httpx.Response(200, json={"data": {"r0": node}})
    )
    out = await client.repo_graph_batch("o", ["a"])
    assert out["a"].latest_release is not None
    assert out["a"].latest_release.immutable is None


@respx.mock
async def test_repo_graph_batch_non_200_raises(
    client: GitHubClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The prefetch is load-bearing for whole report sections whose defaults
    # read as confident negatives ("never released"), so a non-200 answer that
    # survives the shared retry/backoff policy must abort the run rather than
    # silently fabricating defaults for the entire batch.
    slept: list[float] = []

    async def _fake_sleep(delay: float) -> None:
        slept.append(delay)

    monkeypatch.setattr(
        "github_security_report.client.transport.asyncio.sleep", _fake_sleep
    )
    route = respx.post(f"{API}/graphql")
    route.mock(return_value=httpx.Response(502))
    with pytest.raises(NetworkError) as excinfo:
        await client.repo_graph_batch("o", ["a", "b"])
    # Exhausted the retry budget with exponential backoff before aborting.
    assert route.call_count == 1 + API_MAX_RETRIES
    assert slept == [1.0, 2.0, 4.0]
    assert "502" in str(excinfo.value)


@respx.mock
async def test_server_error_retried_then_succeeds(
    client: GitHubClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A transient 5xx (GitHub infrastructure trouble) must be retried on the
    # shared backoff schedule rather than returned un-retried: an un-retried
    # 502 silently degraded (or falsified) whole report sections.
    slept: list[float] = []

    async def _fake_sleep(delay: float) -> None:
        slept.append(delay)

    monkeypatch.setattr(
        "github_security_report.client.transport.asyncio.sleep", _fake_sleep
    )
    node = _graph_repo_node(enabled=True)
    route = respx.post(f"{API}/graphql")
    route.side_effect = [
        httpx.Response(502),
        httpx.Response(200, json={"data": {"r0": node}}),
    ]
    out = await client.repo_graph_batch("o", ["a"])
    assert out["a"].dependabot_alerts_enabled is True
    assert out["a"].unreadable is False
    assert slept == [1.0]


@respx.mock
async def test_repo_graph_batch_missing_data_raises(client: GitHubClient) -> None:
    # HTTP 200 with no data object at all is a wholly failed query (e.g. a
    # timed-out batch): same stakes as a non-200, so it must abort the run.
    respx.post(f"{API}/graphql").mock(
        return_value=httpx.Response(
            200, json={"data": None, "errors": [{"message": "timedout"}]}
        )
    )
    with pytest.raises(NetworkError) as excinfo:
        await client.repo_graph_batch("o", ["a"])
    assert "no data" in str(excinfo.value)


async def test_repo_graph_batch_empty_names_no_request(client: GitHubClient) -> None:
    # No names means no HTTP call at all (respx is not even engaged here).
    assert await client.repo_graph_batch("o", []) == {}


def _issue_node(
    number: int,
    title: str,
    *,
    created_at: str | None = "2025-01-01T00:00:00Z",
    # A label connection (and its entries) can be null when a sub-object
    # errored, so both are deliberately nullable here.
    labels: Sequence[dict | None] | None = None,
    label_total: int | None = None,
) -> dict:
    """Build one open-issue node as the batched query returns it.

    ``label_total`` mirrors the ``totalCount`` the real query asks for, which
    defaults to the number of labels supplied; pass a larger value to simulate
    an issue carrying more labels than the window returned.
    """
    entries = list(labels or [])
    return {
        "number": number,
        "title": title,
        "createdAt": created_at,
        "labels": {
            "totalCount": len(entries) if label_total is None else label_total,
            "nodes": entries,
        },
    }


@respx.mock
async def test_repo_graph_batch_parses_open_issues(client: GitHubClient) -> None:
    # The issues connection is ordered oldest-first, so the window's first entry
    # is the oldest open issue and labels arrive as a flat, ordered tuple.
    node = _graph_repo_node()
    node["issues"] = {
        "totalCount": 3,
        "nodes": [
            _issue_node(
                7,
                "Oldest thing",
                created_at="2023-03-04T05:06:07Z",
                labels=[{"name": "bug"}, {"name": "help wanted"}],
            ),
            _issue_node(11, "Middle thing", created_at="2024-06-01T00:00:00Z"),
            _issue_node(
                12,
                "Newest thing",
                created_at="2025-09-09T00:00:00Z",
                labels=[{"name": "enhancement"}],
            ),
        ],
    }
    respx.post(f"{API}/graphql").mock(
        return_value=httpx.Response(200, json={"data": {"r0": node}})
    )
    out = await client.repo_graph_batch("o", ["a"])

    a = out["a"]
    assert a.open_issues == 3
    assert [i.number for i in a.issues] == [7, 11, 12]
    assert [i.title for i in a.issues] == [
        "Oldest thing",
        "Middle thing",
        "Newest thing",
    ]
    # Labels flatten to their names, preserving GraphQL's order.
    assert a.issues[0].labels == ("bug", "help wanted")
    assert a.issues[1].labels == ()
    assert a.issues[2].labels == ("enhancement",)
    oldest = a.issues[0].created_at
    assert oldest is not None
    assert (oldest.year, oldest.month, oldest.day) == (2023, 3, 4)


@respx.mock
async def test_repo_graph_batch_issue_window_is_bounded(client: GitHubClient) -> None:
    # A large backlog exceeds the query's page size: totalCount stays
    # authoritative while the parsed window is capped at what GitHub returned.
    node = _graph_repo_node()
    node["issues"] = {
        "totalCount": 4321,
        "nodes": [_issue_node(i, f"issue {i}") for i in range(1, 101)],
    }
    respx.post(f"{API}/graphql").mock(
        return_value=httpx.Response(200, json={"data": {"r0": node}})
    )
    out = await client.repo_graph_batch("o", ["a"])

    a = out["a"]
    assert a.open_issues == 4321
    assert len(a.issues) == 100


@respx.mock
async def test_repo_graph_batch_null_issues_object(client: GitHubClient) -> None:
    # A null issues connection (a failed sub-object) and a wholly absent one
    # must both read as indeterminate rather than as zero open issues, so a
    # backlog nobody could see is never reported as a clean one.
    null_node = _graph_repo_node()
    null_node["issues"] = None
    missing_node = _graph_repo_node()  # no "issues" key at all
    respx.post(f"{API}/graphql").mock(
        return_value=httpx.Response(
            200, json={"data": {"r0": null_node, "r1": missing_node}}
        )
    )
    out = await client.repo_graph_batch("o", ["a", "b"])

    # An unreadable issues connection is indeterminate, not "zero open issues":
    # GitHub nulls this field for a token lacking Issues: read while serving the
    # rest of the repository, so a 0 here would read as a clean backlog.
    assert out["a"].open_issues is None
    assert out["a"].issues == ()
    assert out["b"].open_issues is None
    assert out["b"].issues == ()


@respx.mock
async def test_repo_graph_batch_malformed_issue_entries(client: GitHubClient) -> None:
    # A null node, a node with no usable number, a null labels connection and a
    # null label entry must each be skipped without aborting the whole parse.
    numberless = _issue_node(0, "numberless")
    numberless["number"] = None
    no_labels = _issue_node(9, "null labels")
    no_labels["labels"] = None
    node = _graph_repo_node()
    node["issues"] = {
        "totalCount": 4,
        "nodes": [
            None,
            numberless,
            no_labels,
            _issue_node(10, "partial labels", labels=[None, {"name": "bug"}]),
        ],
    }
    respx.post(f"{API}/graphql").mock(
        return_value=httpx.Response(200, json={"data": {"r0": node}})
    )
    out = await client.repo_graph_batch("o", ["a"])

    a = out["a"]
    # totalCount is GitHub's, not a count of what survived parsing.
    assert a.open_issues == 4
    assert [i.number for i in a.issues] == [9, 10]
    assert a.issues[0].labels == ()
    # An unreadable labels connection is not an issue without labels: it is
    # indeterminate, so the classifier must treat it as possibly incomplete
    # rather than counting it as a confident triage gap.
    assert a.issues[0].labels_truncated is True
    assert a.issues[1].labels == ("bug",)
    # The two dropped nodes came before any survivor, so the issue now at
    # entry 0 is only the oldest *readable* one -- its age is not the answer
    # the Oldest column asks for.
    assert a.oldest_issue_unreadable is True


@respx.mock
async def test_repo_graph_batch_keeps_oldest_when_a_later_node_is_dropped(
    client: GitHubClient,
) -> None:
    # A gap after the first survivor costs detail, not the oldest-issue answer.
    node = _graph_repo_node()
    node["issues"] = {"totalCount": 2, "nodes": [_issue_node(1, "oldest"), None]}
    respx.post(f"{API}/graphql").mock(
        return_value=httpx.Response(200, json={"data": {"r0": node}})
    )
    out = await client.repo_graph_batch("o", ["a"])

    assert out["a"].oldest_issue_unreadable is False


@respx.mock
async def test_repo_graph_batch_unusable_issue_total_is_unknown(
    client: GitHubClient,
) -> None:
    # A totalCount that is absent, null or the wrong type is no reading at all,
    # not a reading of zero -- degrading it to 0 would report a repository whose
    # nodes plainly came back as having no open issues.
    node = _graph_repo_node()
    node["issues"] = {"nodes": [_issue_node(1, "present")]}
    other = _graph_repo_node()
    other["issues"] = {"totalCount": None, "nodes": []}
    respx.post(f"{API}/graphql").mock(
        return_value=httpx.Response(200, json={"data": {"r0": node, "r1": other}})
    )
    out = await client.repo_graph_batch("o", ["a", "b"])

    assert out["a"].open_issues is None
    assert len(out["a"].issues) == 1
    assert out["b"].open_issues is None


@respx.mock
async def test_repo_graph_batch_unusable_label_total_marks_truncated(
    client: GitHubClient,
) -> None:
    # Without a usable label totalCount there is no evidence the names we got
    # are all of them, so classification must be treated as uncertain.
    node = _graph_repo_node()
    issue = _issue_node(1, "no label total", labels=[{"name": "bug"}])
    del issue["labels"]["totalCount"]
    node["issues"] = {"totalCount": 1, "nodes": [issue]}
    respx.post(f"{API}/graphql").mock(
        return_value=httpx.Response(200, json={"data": {"r0": node}})
    )
    out = await client.repo_graph_batch("o", ["a"])

    assert out["a"].issues[0].labels == ("bug",)
    assert out["a"].issues[0].labels_truncated is True


@respx.mock
async def test_repo_graph_batch_marks_a_truncated_label_window(
    client: GitHubClient,
) -> None:
    # totalCount exceeding the labels returned means the issue carries labels
    # the window did not show, which could change how it is classified.
    node = _graph_repo_node()
    node["issues"] = {
        "totalCount": 1,
        "nodes": [
            _issue_node(1, "many labels", labels=[{"name": "bug"}], label_total=9)
        ],
    }
    respx.post(f"{API}/graphql").mock(
        return_value=httpx.Response(200, json={"data": {"r0": node}})
    )
    out = await client.repo_graph_batch("o", ["a"])

    assert out["a"].issues[0].labels_truncated is True


def _copilot_thread(
    resolved: bool, login: str = "copilot-pull-request-reviewer"
) -> dict:
    """One review thread node, opened by ``login``."""
    return {
        "isResolved": resolved,
        "comments": {"nodes": [{"author": {"__typename": "Bot", "login": login}}]},
    }


def _graph_pull_request(
    number: int = 1,
    *,
    login: str | None = "alice",
    typename: str = "User",
    association: str = "MEMBER",
    draft: bool = False,
    mergeable: str | None = "MERGEABLE",
    rollup: str | None = "SUCCESS",
    assignees: Sequence[str] | None = (),
    review_threads: Sequence[dict] | None = (),
    review_thread_total: int | None = None,
) -> dict:
    """Build one pull-request node as the batched query returns it."""
    threads = (
        None
        if review_threads is None
        else {
            "totalCount": (
                len(review_threads)
                if review_thread_total is None
                else review_thread_total
            ),
            "nodes": list(review_threads),
        }
    )
    return {
        "number": number,
        "isDraft": draft,
        "mergeable": mergeable,
        "authorAssociation": association,
        "author": ({"__typename": typename, "login": login} if login else None),
        "assignees": (
            {"nodes": [{"login": name} for name in assignees]}
            if assignees is not None
            else None
        ),
        "reviewThreads": threads,
        "commits": {
            "nodes": [
                {
                    "commit": {
                        "statusCheckRollup": (
                            {"state": rollup} if rollup is not None else None
                        )
                    }
                }
            ]
        },
    }


@respx.mock
async def test_repo_graph_batch_parses_pull_requests(client: GitHubClient) -> None:
    node = _graph_repo_node(
        pull_requests=[
            _graph_pull_request(
                1,
                login="dependabot",
                typename="Bot",
                association="NONE",
                mergeable="CONFLICTING",
                rollup="FAILURE",
            ),
            _graph_pull_request(2, draft=True, assignees=["Alice", "BOB"], rollup=None),
        ],
        pull_request_total=2,
    )
    respx.post(f"{API}/graphql").mock(
        return_value=httpx.Response(200, json={"data": {"r0": node}})
    )
    out = await client.repo_graph_batch("o", ["a"])
    first, second = out["a"].pull_requests
    assert out["a"].open_pull_requests == 2
    assert first.author is not None
    assert (first.author.login, first.author.typename) == ("dependabot", "Bot")
    assert first.conflicting is True
    assert first.failing is True
    # Assignee logins are lower-cased at the boundary so the "is this mine?"
    # comparison never has to care which casing GitHub returned.
    assert second.assignees == ("alice", "bob")
    assert second.draft is True
    # No rollup at all is not a pass: nothing has run.
    assert second.failing is None
    assert second.conflicting is False


@respx.mock
async def test_repo_graph_batch_pull_requests_absent_is_unknown(
    client: GitHubClient,
) -> None:
    # A null connection is "never read", which must not read as "none open".
    node = _graph_repo_node()
    node["pullRequests"] = None
    respx.post(f"{API}/graphql").mock(
        return_value=httpx.Response(200, json={"data": {"r0": node}})
    )
    out = await client.repo_graph_batch("o", ["a"])
    assert out["a"].open_pull_requests is None
    assert out["a"].pull_requests == ()


@respx.mock
async def test_repo_graph_batch_skips_malformed_pull_request_nodes(
    client: GitHubClient,
) -> None:
    # A null entry, a non-dict and an entry without a usable number are not
    # pull requests we can report on; they are skipped rather than aborting
    # the surrounding parse, and the authoritative total still stands.
    node = _graph_repo_node(
        pull_requests=[None, "nonsense", {"isDraft": True}, _graph_pull_request(7)],
        pull_request_total=4,
    )
    respx.post(f"{API}/graphql").mock(
        return_value=httpx.Response(200, json={"data": {"r0": node}})
    )
    out = await client.repo_graph_batch("o", ["a"])
    assert out["a"].open_pull_requests == 4
    assert [p.number for p in out["a"].pull_requests] == [7]


@respx.mock
async def test_repo_graph_batch_unknown_mergeable_is_not_a_clean_merge(
    client: GitHubClient,
) -> None:
    # GitHub computes mergeability lazily and answers UNKNOWN until it settles,
    # so a cold sweep must report "not established" rather than either answer.
    node = _graph_repo_node(
        pull_requests=[_graph_pull_request(1, mergeable="UNKNOWN")],
        pull_request_total=1,
    )
    respx.post(f"{API}/graphql").mock(
        return_value=httpx.Response(200, json={"data": {"r0": node}})
    )
    out = await client.repo_graph_batch("o", ["a"])
    assert out["a"].pull_requests[0].conflicting is None


@respx.mock
async def test_repo_graph_batch_parses_unresolved_copilot_feedback(
    client: GitHubClient,
) -> None:
    # The reviewer is identified from the thread's *opening* comment: later
    # replies are commonly the human answering the review, so keying on any
    # comment would credit Copilot with threads it did not raise.
    node = _graph_repo_node(
        pull_requests=[
            _graph_pull_request(1, review_threads=[_copilot_thread(resolved=False)]),
            _graph_pull_request(2, review_threads=[_copilot_thread(resolved=True)]),
            _graph_pull_request(
                3, review_threads=[_copilot_thread(resolved=False, login="alice")]
            ),
            _graph_pull_request(4, review_threads=[]),
        ],
        pull_request_total=4,
    )
    respx.post(f"{API}/graphql").mock(
        return_value=httpx.Response(200, json={"data": {"r0": node}})
    )
    out = await client.repo_graph_batch("o", ["a"])
    unresolved, resolved, human, none = out["a"].pull_requests
    assert unresolved.copilot_unresolved is True
    assert resolved.copilot_unresolved is False
    # Another reviewer's open thread is somebody else's backlog.
    assert human.copilot_unresolved is False
    assert none.copilot_unresolved is False


@respx.mock
async def test_repo_graph_batch_truncated_review_threads_are_indeterminate(
    client: GitHubClient,
) -> None:
    # A long review cycle can carry more threads than the window returns. With
    # nothing qualifying inside it, an unresolved thread may sit among the ones
    # never collected, so the run must not claim the pull request is clear --
    # the same rule ``mergeable: UNKNOWN`` follows.
    node = _graph_repo_node(
        pull_requests=[
            _graph_pull_request(
                1,
                review_threads=[_copilot_thread(resolved=True)],
                review_thread_total=40,
            ),
            # A qualifying thread inside the window settles the question, so a
            # truncated window is still a definite answer when it finds one.
            _graph_pull_request(
                2,
                review_threads=[_copilot_thread(resolved=False)],
                review_thread_total=40,
            ),
        ],
        pull_request_total=2,
    )
    respx.post(f"{API}/graphql").mock(
        return_value=httpx.Response(200, json={"data": {"r0": node}})
    )
    out = await client.repo_graph_batch("o", ["a"])
    truncated, found = out["a"].pull_requests
    assert truncated.copilot_unresolved is None
    assert found.copilot_unresolved is True


@respx.mock
async def test_repo_graph_batch_unreadable_review_threads_are_indeterminate(
    client: GitHubClient,
) -> None:
    # A null connection is "never read", which must not read as "nothing
    # outstanding".
    node = _graph_repo_node(
        pull_requests=[_graph_pull_request(1, review_threads=None)],
        pull_request_total=1,
    )
    respx.post(f"{API}/graphql").mock(
        return_value=httpx.Response(200, json={"data": {"r0": node}})
    )
    out = await client.repo_graph_batch("o", ["a"])
    assert out["a"].pull_requests[0].copilot_unresolved is None


@respx.mock
async def test_repo_graph_batch_unusable_thread_total_is_indeterminate(
    client: GitHubClient,
) -> None:
    # Without a usable ``totalCount`` there is no evidence that the returned
    # nodes covered every thread, so "none collected qualified" cannot be
    # promoted to "nothing outstanding".
    absent = _graph_pull_request(1, review_threads=[_copilot_thread(resolved=True)])
    del absent["reviewThreads"]["totalCount"]
    malformed = _graph_pull_request(2, review_threads=[_copilot_thread(resolved=True)])
    malformed["reviewThreads"]["totalCount"] = "lots"
    node = _graph_repo_node(pull_requests=[absent, malformed], pull_request_total=2)
    respx.post(f"{API}/graphql").mock(
        return_value=httpx.Response(200, json={"data": {"r0": node}})
    )
    out = await client.repo_graph_batch("o", ["a"])
    assert [p.copilot_unresolved for p in out["a"].pull_requests] == [None, None]


@respx.mock
async def test_pull_request_permission_error_spares_the_rest_of_the_repo(
    client: GitHubClient,
) -> None:
    # A token that cannot read pull requests must lose only that table. The
    # repository's releases, issues, tags and Dependabot posture were read
    # successfully and failing them too would let one optional, permission-
    # sensitive section take the whole report down with it.
    node = _graph_repo_node(enabled=True, config_text="version: 2")
    node["pullRequests"] = None
    respx.post(f"{API}/graphql").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {"r0": node},
                "errors": [
                    {
                        "path": ["r0", "pullRequests"],
                        "message": "Resource not accessible by integration",
                    }
                ],
            },
        )
    )
    out = await client.repo_graph_batch("o", ["a"])
    assert out["a"].unreadable is False
    assert out["a"].dependabot_alerts_enabled is True
    assert out["a"].dependabot_config == "version: 2"
    # Only the pull-request data is unknown.
    assert out["a"].open_pull_requests is None


@respx.mock
async def test_review_thread_error_fails_the_pull_request_connection(
    client: GitHubClient,
) -> None:
    # ``reviewThreads`` is non-null in GitHub's schema
    # (PullRequestReviewThreadConnection!), so a resolver failure there does not
    # arrive as a populated node with a null connection. It propagates up to the
    # nearest nullable ancestor -- the pull-request node -- which arrives null
    # and carries none of its facts. Ignoring the error would silently drop that
    # pull request from every column while totalCount still counted it, so the
    # connection is failed and the repository reported as unknown instead.
    node = _graph_repo_node(
        enabled=True,
        config_text="version: 2",
        pull_requests=[None, _graph_pull_request(8)],
        pull_request_total=2,
    )
    respx.post(f"{API}/graphql").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {"r0": node},
                "errors": [
                    {
                        "path": ["r0", "pullRequests", "nodes", 0, "reviewThreads"],
                        "message": "Something went wrong",
                    }
                ],
            },
        )
    )
    out = await client.repo_graph_batch("o", ["a"])
    # The isolation still spares everything the error did not touch.
    assert out["a"].unreadable is False
    assert out["a"].dependabot_alerts_enabled is True
    assert out["a"].dependabot_config == "version: 2"
    # The pull-request data is reported as unknown rather than as a breakdown
    # quietly missing the pull request the error erased.
    assert out["a"].open_pull_requests is None
    assert out["a"].pull_requests == ()


@respx.mock
async def test_other_field_error_still_fails_the_whole_alias(
    client: GitHubClient,
) -> None:
    # The isolation is deliberately narrow: a nulled latestRelease is
    # indistinguishable from "never released", so it still condemns the alias.
    respx.post(f"{API}/graphql").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {"r0": _graph_repo_node()},
                "errors": [{"path": ["r0", "latestRelease"], "message": "boom"}],
            },
        )
    )
    out = await client.repo_graph_batch("o", ["a"])
    assert out["a"].unreadable is True


@respx.mock
async def test_viewer_login_ignores_an_automation_account(
    client: GitHubClient,
) -> None:
    # A bot or App has no personal review queue, and its login can legitimately
    # be an assignee, so returning it would populate "Mine" for an account with
    # no inbox -- in exactly the scheduled runs most likely to authenticate
    # this way.
    respx.post(f"{API}/graphql").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "viewer": {"__typename": "Bot", "login": "github-actions[bot]"}
                }
            },
        )
    )
    assert await client.viewer_login() == ""


@respx.mock
async def test_viewer_login_returns_a_human_account(client: GitHubClient) -> None:
    respx.post(f"{API}/graphql").mock(
        return_value=httpx.Response(
            200, json={"data": {"viewer": {"__typename": "User", "login": "Alice"}}}
        )
    )
    assert await client.viewer_login() == "alice"


@respx.mock
async def test_org_members_rejects_an_unusable_member_node(
    client: GitHubClient,
) -> None:
    # A null node or one without a login is a member we cannot name, and a
    # member missing from the set reads as an outsider. Dropping it silently
    # would shorten the list while still returning it as authoritative.
    for nodes in ([{"login": "alice"}, None], [{"login": "alice"}, {}]):
        respx.post(f"{API}/graphql").mock(
            return_value=httpx.Response(
                200,
                json={
                    "data": {
                        "organization": {
                            "viewerIsAMember": True,
                            "membersWithRole": {
                                "totalCount": 2,
                                "pageInfo": {
                                    "hasNextPage": False,
                                    "endCursor": None,
                                },
                                "nodes": nodes,
                            },
                        }
                    }
                },
            )
        )
        assert await client.org_members("o") is None


@respx.mock
async def test_org_members_rejects_a_response_carrying_graphql_errors(
    client: GitHubClient,
) -> None:
    # GraphQL answers a partially-failed query with HTTP 200, populating what
    # it could alongside an errors array. A shortened member list is
    # indistinguishable from a complete one, so any error condemns the read.
    respx.post(f"{API}/graphql").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "organization": {
                        "viewerIsAMember": True,
                        "membersWithRole": {
                            "totalCount": 2,
                            "pageInfo": {"hasNextPage": False, "endCursor": None},
                            "nodes": [{"login": "alice"}],
                        },
                    }
                },
                "errors": [{"message": "something was not readable"}],
            },
        )
    )
    assert await client.org_members("o") is None


@respx.mock
async def test_org_members_outside_viewer_is_unknown_not_partial(
    client: GitHubClient,
) -> None:
    # membersWithRole is visibility-filtered rather than access-controlled: a
    # non-member gets a valid connection holding only the *public* members,
    # with no error and a matching totalCount. Trusting it would report every
    # private member as an outsider.
    respx.post(f"{API}/graphql").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "organization": {
                        "viewerIsAMember": False,
                        "membersWithRole": {
                            "totalCount": 3,
                            "pageInfo": {"hasNextPage": False, "endCursor": None},
                            "nodes": [{"login": "public-person"}],
                        },
                    }
                }
            },
        )
    )
    assert await client.org_members("o") is None


@respx.mock
async def test_org_members_returns_the_set_for_a_member_viewer(
    client: GitHubClient,
) -> None:
    # Members can see each other, so a viewer inside the organisation gets the
    # complete list and it is safe to treat as authoritative.
    respx.post(f"{API}/graphql").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "organization": {
                        "viewerIsAMember": True,
                        "membersWithRole": {
                            "totalCount": 2,
                            "pageInfo": {"hasNextPage": False, "endCursor": None},
                            "nodes": [{"login": "Alice"}, {"login": "Bob"}],
                        },
                    }
                }
            },
        )
    )
    assert await client.org_members("o") == frozenset({"alice", "bob"})


@respx.mock
async def test_org_members_unreadable_organisation_is_unknown(
    client: GitHubClient,
) -> None:
    respx.post(f"{API}/graphql").mock(
        return_value=httpx.Response(
            200,
            json={"data": {"organization": None}, "errors": [{"message": "nope"}]},
        )
    )
    assert await client.org_members("o") is None


@respx.mock
async def test_org_members_failed_later_page_discards_the_partial_set(
    client: GitHubClient,
) -> None:
    # A partial list is worse than none: every member missing from it reads as
    # an outsider, and nothing distinguishes an absent member from a real one.
    first = httpx.Response(
        200,
        json={
            "data": {
                "organization": {
                    "viewerIsAMember": True,
                    "membersWithRole": {
                        "totalCount": 200,
                        "pageInfo": {"hasNextPage": True, "endCursor": "cursor"},
                        "nodes": [{"login": "alice"}],
                    },
                }
            }
        },
    )
    route = respx.post(f"{API}/graphql")
    # 404 rather than 500: a server error is retried on the shared backoff
    # schedule, which is not what this test is about.
    route.side_effect = [first, httpx.Response(404)]
    assert await client.org_members("o") is None


@respx.mock
async def test_repo_graph_batch_pins_the_rate_limit_windows(
    client: GitHubClient,
) -> None:
    # The two window sizes are this category's rate-limit safeguard, not a
    # cosmetic cap: GitHub scores a query by the nodes it could return,
    # multiplied down each level of nesting, so the issue window multiplies by
    # the label window. At 100 x 20 a single 118-repository organisation costs
    # about half the hourly budget; at 25 x 5, about 4%. Nothing else in the
    # suite fails if they are widened, so the request payload is pinned here.
    route = respx.post(f"{API}/graphql").mock(
        return_value=httpx.Response(200, json={"data": {"r0": _graph_repo_node()}})
    )
    await client.repo_graph_batch("o", ["a"])

    query = json.loads(route.calls.last.request.content)["query"]
    assert "issues(states: OPEN, first: 25," in query
    assert "labels(first: 5)" in query


def test_https_endpoint_defaults_when_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("GITHUB_API_URL", raising=False)
    assert _https_endpoint("GITHUB_API_URL", API) == API


def test_https_endpoint_accepts_https_override(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GITHUB_API_URL", "https://ghe.example.com/api/v3")
    assert _https_endpoint("GITHUB_API_URL", API) == "https://ghe.example.com/api/v3"


def test_https_endpoint_rejects_insecure_override(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    # A non-HTTPS override must not be honoured: the token would otherwise be
    # sent in plaintext. The built-in default is used and a warning is logged.
    monkeypatch.setenv("GITHUB_API_URL", "http://attacker.example.com")
    with caplog.at_level("WARNING"):
        assert _https_endpoint("GITHUB_API_URL", API) == API
    assert any("not an https" in r.message for r in caplog.records)


def test_https_endpoint_normalises_whitespace_and_trailing_slash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Surrounding whitespace and a trailing slash are copy/paste artefacts, not
    # a real override: they must be stripped before comparison and validation.
    monkeypatch.setenv("GITHUB_API_URL", f"  {API}/  ")
    assert _https_endpoint("GITHUB_API_URL", API) == API
    monkeypatch.setenv("GITHUB_API_URL", "  https://ghe.example.com/api/v3/  ")
    assert _https_endpoint("GITHUB_API_URL", API) == "https://ghe.example.com/api/v3"


@respx.mock
async def test_repo_graph_batch_field_error_marks_alias_unreadable(
    client: GitHubClient,
) -> None:
    # GitHub reports a field-level failure with HTTP 200: the alias stays a
    # populated dict, the failed field is null, and errors[].path names it.
    # Parsing that node would turn a read failure into a confident negative
    # ("never released"), which is the exact defect this PR exists to fix.
    node = _graph_repo_node(enabled=True)
    node["latestRelease"] = None
    node["releases"] = None
    respx.post(f"{API}/graphql").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {"r0": node},
                "errors": [
                    {"path": ["r0", "latestRelease"], "message": "Something failed"}
                ],
            },
        )
    )
    out = await client.repo_graph_batch("o", ["a"])
    # Unreadable, so the releases table counts it unknown rather than
    # listing it as never released.
    assert out["a"].unreadable is True
    assert out["a"].latest_release_at is None
    # The alias is failed wholesale: no field of it is trusted.
    assert out["a"].dependabot_alerts_enabled is None


@respx.mock
async def test_repo_graph_batch_field_error_does_not_taint_other_aliases(
    client: GitHubClient,
) -> None:
    # An error attributable to one alias must not degrade its neighbours;
    # over-reporting unknowns would hide real findings.
    bad = _graph_repo_node(enabled=True)
    bad["tags"] = None
    good = _graph_repo_node(
        enabled=True,
        tag_target={"__typename": "Commit", "committedDate": "2026-01-01T00:00:00Z"},
    )
    respx.post(f"{API}/graphql").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {"r0": bad, "r1": good},
                "errors": [{"path": ["r0", "tags"], "message": "Something failed"}],
            },
        )
    )
    out = await client.repo_graph_batch("o", ["a", "b"])
    assert out["a"].unreadable is True
    assert out["b"].unreadable is False
    assert out["b"].latest_tag_at is not None


@respx.mock
async def test_repo_graph_batch_unattributable_error_marks_all_unreadable(
    client: GitHubClient,
) -> None:
    # An error carrying no usable path cannot be tied to a repository, so
    # nothing in the batch can be claimed as successfully read.
    node = _graph_repo_node(enabled=True)
    respx.post(f"{API}/graphql").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {"r0": node, "r1": node},
                "errors": [{"message": "Something went wrong"}],
            },
        )
    )
    out = await client.repo_graph_batch("o", ["a", "b"])
    assert [out["a"].unreadable, out["b"].unreadable] == [True, True]
