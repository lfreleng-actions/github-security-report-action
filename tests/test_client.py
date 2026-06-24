# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Transport tests for the async GitHub client (no live network: respx)."""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest
import respx

from github_security_report.client import GitHubClient

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
    client: GitHubClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    slept: list[float] = []

    async def _fake_sleep(delay: float) -> None:
        slept.append(delay)

    monkeypatch.setattr("github_security_report.client.asyncio.sleep", _fake_sleep)
    route = respx.get(f"{API}/repos/o/r/secret-scanning/alerts")
    route.side_effect = [
        httpx.Response(429, headers={"retry-after": "1"}),
        httpx.Response(200, json=[]),
    ]
    status = await client.secret_scanning_status("o", "r")
    assert status == 200
    assert slept == [1.0]


@respx.mock
async def test_genuine_403_not_retried(client: GitHubClient) -> None:
    # A 403 with rate-limit budget remaining is a real permission error.
    respx.get(f"{API}/repos/o/r/code-scanning/analyses").mock(
        return_value=httpx.Response(403, headers={"x-ratelimit-remaining": "4999"})
    )
    status, tools = await client.code_scanning_tools("o", "r")
    assert status == 403


@respx.mock
async def test_transport_error_becomes_indeterminate(client: GitHubClient) -> None:
    # A transport failure (DNS/TLS/connect/read) must not abort the run; it is
    # converted into an indeterminate non-200 status so signals degrade.
    respx.get(f"{API}/repos/o/r/secret-scanning/alerts").mock(
        side_effect=httpx.ConnectError("boom")
    )
    status = await client.secret_scanning_status("o", "r")
    assert status == 503


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


# --------------------------------------------------------------------------- #
# Batched per-repo GraphQL prefetch
# --------------------------------------------------------------------------- #
def _graph_repo_node(
    *,
    enabled: bool | None = True,
    config_text: str | None = None,
    tag_target: dict | None = None,
    releases: list[dict] | None = None,
    latest_release: dict | None = None,
) -> dict:
    """Build one repository alias node as the batched query returns it."""
    return {
        "hasVulnerabilityAlertsEnabled": enabled,
        "dependabotConfig": (
            {"text": config_text} if config_text is not None else None
        ),
        "tags": {"nodes": [{"target": tag_target}] if tag_target else []},
        "latestRelease": latest_release,
        "releases": {"nodes": releases or []},
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

    # A null alias degrades to defaults rather than being mislabelled.
    b = out["b"]
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
async def test_repo_graph_batch_non_200_returns_defaults(client: GitHubClient) -> None:
    respx.post(f"{API}/graphql").mock(return_value=httpx.Response(502))
    out = await client.repo_graph_batch("o", ["a", "b"])
    assert set(out) == {"a", "b"}
    assert out["a"].dependabot_alerts_enabled is None
    assert out["b"].latest_release is None


async def test_repo_graph_batch_empty_names_no_request(client: GitHubClient) -> None:
    # No names means no HTTP call at all (respx is not even engaged here).
    assert await client.repo_graph_batch("o", []) == {}
