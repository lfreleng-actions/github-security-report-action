# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Async GitHub transport: hybrid REST + GraphQL.

Implements the Phase 0 strategy: prefer org-bulk alert sweeps, fall back to
per-repo enabled-probes, with bounded concurrency and backoff that honours
``Retry-After`` and secondary rate limits. Methods return raw parsed JSON (and
HTTP status where the status itself is the signal, e.g. 404 = feature disabled).
See ``docs/BRIEF.md`` sections 9, 13 and ``docs/phase0-findings.md``.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator

import httpx

from github_security_report.models import Repo

log = logging.getLogger(__name__)

GITHUB_API = "https://api.github.com"
GRAPHQL_API = "https://api.github.com/graphql"
SCORECARD_API = "https://api.securityscorecards.dev"

# org-bulk alert endpoints, keyed by signal family.
BULK_KINDS = {
    "code-scanning": "code-scanning/alerts",
    "dependabot": "dependabot/alerts",
    "secret-scanning": "secret-scanning/alerts",
}

_DEPENDABOT_ENABLED_QUERY = """
query($owner: String!, $name: String!) {
  repository(owner: $owner, name: $name) {
    hasVulnerabilityAlertsEnabled
  }
}
"""


class GitHubClient:
    """Thin async client over the GitHub REST + GraphQL APIs."""

    def __init__(
        self,
        token: str,
        *,
        api_url: str = GITHUB_API,
        graphql_url: str = GRAPHQL_API,
        scorecard_url: str = SCORECARD_API,
        concurrency: int = 6,
        max_retries: int = 4,
        timeout: float = 30.0,
    ) -> None:
        self._api_url = api_url.rstrip("/")
        self._graphql_url = graphql_url
        self._scorecard_url = scorecard_url.rstrip("/")
        self._max_retries = max_retries
        self._sem = asyncio.Semaphore(concurrency)
        self._client = httpx.AsyncClient(
            timeout=timeout,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "github-security-report",
            },
        )
        # Separate, UNAUTHENTICATED client for third-party endpoints (the
        # external Scorecard API): the GitHub token must never be sent there.
        self._ext_client = httpx.AsyncClient(
            timeout=timeout, headers={"User-Agent": "github-security-report"}
        )

    async def __aenter__(self) -> GitHubClient:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()
        await self._ext_client.aclose()

    # ------------------------------------------------------------------ #
    # Low-level request with backoff
    # ------------------------------------------------------------------ #
    async def _request(
        self,
        method: str,
        url: str,
        *,
        client: httpx.AsyncClient | None = None,
        **kwargs: object,
    ) -> httpx.Response:
        """Issue a request, retrying on rate-limit responses with backoff.

        ``client`` selects the transport (default: the authenticated GitHub
        client). External calls pass the unauthenticated client so the GitHub
        token is never leaked to third parties.
        """
        http = client or self._client
        attempt = 0
        while True:
            async with self._sem:
                resp = await http.request(method, url, **kwargs)  # type: ignore[arg-type]
            if resp.status_code not in (403, 429):
                return resp
            # Distinguish secondary/primary rate limiting from a genuine 403.
            retry_after = resp.headers.get("retry-after")
            remaining = resp.headers.get("x-ratelimit-remaining")
            rate_limited = retry_after is not None or remaining == "0"
            if not rate_limited or attempt >= self._max_retries:
                return resp
            delay = float(retry_after) if retry_after else min(2**attempt, 60)
            log.warning("rate limited on %s; backing off %.0fs", url, delay)
            # The discarded response must be closed; we are retrying and will
            # not read its body, so leaving it open would leak a pool connection.
            await resp.aclose()
            await asyncio.sleep(delay)
            attempt += 1

    async def _paginate(self, url: str, **params: object) -> AsyncIterator[dict]:
        """Yield items across all pages, following the Link ``next`` relation."""
        next_url: str | None = url
        merged: dict[str, object] | None = {**params, "per_page": 100}
        while next_url:
            resp = await self._request("GET", next_url, params=merged)
            if resp.status_code != 200:
                log.debug("pagination stopped: %s -> %s", next_url, resp.status_code)
                return
            for item in resp.json():
                yield item
            next_url = resp.links.get("next", {}).get("url")
            merged = None  # the next link already encodes the query

    async def _get_list(self, url: str, **params: object) -> tuple[int, list[dict]]:
        """GET a paginated list, returning (first-page status, all items).

        The status is preserved because, for per-repo endpoints, it is itself a
        signal (404 = feature disabled).
        """
        resp = await self._request("GET", url, params={**params, "per_page": 100})
        if resp.status_code != 200:
            return resp.status_code, []
        items = list(resp.json())
        next_url = resp.links.get("next", {}).get("url")
        while next_url:
            resp = await self._request("GET", next_url)
            if resp.status_code != 200:
                break
            items.extend(resp.json())
            next_url = resp.links.get("next", {}).get("url")
        return 200, items

    # ------------------------------------------------------------------ #
    # Repositories
    # ------------------------------------------------------------------ #
    async def list_org_repos(self, org: str) -> list[Repo]:
        """List an organisation's repositories, skipping disabled/empty ones."""
        repos: list[Repo] = []
        async for raw in self._paginate(
            f"{self._api_url}/orgs/{org}/repos", type="all"
        ):
            if raw.get("disabled") or raw.get("size", 0) == 0:
                log.info("skipping %s: disabled or empty", raw.get("full_name"))
                continue
            repos.append(
                Repo(
                    name=raw["name"],
                    full_name=raw["full_name"],
                    html_url=raw["html_url"],
                    archived=raw.get("archived", False),
                    fork=raw.get("fork", False),
                    is_template=raw.get("is_template", False),
                    private=raw.get("private", False),
                )
            )
        return repos

    # ------------------------------------------------------------------ #
    # Org-bulk alert sweeps
    # ------------------------------------------------------------------ #
    async def org_bulk_alerts(self, org: str, kind: str) -> list[dict]:
        """Sweep all open alerts of one kind across the org (one paginated pass)."""
        path = BULK_KINDS[kind]
        return [
            item
            async for item in self._paginate(
                f"{self._api_url}/orgs/{org}/{path}", state="open"
            )
        ]

    # ------------------------------------------------------------------ #
    # Per-repo enabled-probes
    # ------------------------------------------------------------------ #
    async def code_scanning_tools(self, org: str, repo: str) -> tuple[int, set[str]]:
        """Return (status, distinct tool names) from code-scanning analyses.

        Status 404 means code scanning is disabled entirely; 403 indeterminate.
        The tool set drives CodeQL/Scorecard/zizmor enablement.
        """
        resp = await self._request(
            "GET",
            f"{self._api_url}/repos/{org}/{repo}/code-scanning/analyses",
            params={"per_page": 100},
        )
        if resp.status_code != 200:
            return resp.status_code, set()
        tools = {(a.get("tool") or {}).get("name", "") for a in resp.json()}
        tools.discard("")
        return 200, tools

    async def secret_scanning_status(self, org: str, repo: str) -> int:
        """HTTP status of the secret-scanning alerts endpoint (404 = disabled)."""
        resp = await self._request(
            "GET",
            f"{self._api_url}/repos/{org}/{repo}/secret-scanning/alerts",
            params={"per_page": 1, "state": "open"},
        )
        return int(resp.status_code)

    async def dependabot_enabled(self, org: str, repo: str) -> bool | None:
        """Whether Dependabot alerts are enabled (None when indeterminate)."""
        resp = await self._request(
            "POST",
            self._graphql_url,
            json={
                "query": _DEPENDABOT_ENABLED_QUERY,
                "variables": {"owner": org, "name": repo},
            },
        )
        if resp.status_code != 200:
            return None
        node = (resp.json().get("data") or {}).get("repository")
        if not node:
            return None
        return bool(node.get("hasVulnerabilityAlertsEnabled"))

    async def scorecard_score(self, org: str, repo: str) -> tuple[int, float | None]:
        """External OpenSSF Scorecard aggregate score (status, score|None)."""
        url = f"{self._scorecard_url}/projects/github.com/{org}/{repo}"
        try:
            resp = await self._request("GET", url, client=self._ext_client)
        except httpx.HTTPError as exc:  # external service; tolerate failure
            log.debug("scorecard request failed for %s/%s: %s", org, repo, exc)
            return 0, None
        if resp.status_code != 200:
            return resp.status_code, None
        return 200, resp.json().get("score")

    # ------------------------------------------------------------------ #
    # Repository rulesets (workflow-driven tool enablement)
    # ------------------------------------------------------------------ #
    async def org_workflow_rulesets(self, org: str) -> tuple[int, list[dict]]:
        """Active, branch-targeted org rulesets, each with full rule details.

        Returns ``(status, details)``; status is the org-rulesets list status
        (e.g. 403 when the token lacks org access) so coverage can degrade
        gracefully. The list endpoint returns summaries, so each active branch
        ruleset is fetched in detail to expose its rules and conditions.
        """
        status, summaries = await self._get_list(f"{self._api_url}/orgs/{org}/rulesets")
        if status != 200:
            return status, []
        details: list[dict] = []
        for summary in summaries:
            if summary.get("enforcement") != "active":
                continue
            if summary.get("target") not in (None, "branch"):
                continue
            resp = await self._request(
                "GET", f"{self._api_url}/orgs/{org}/rulesets/{summary['id']}"
            )
            if resp.status_code == 200:
                details.append(resp.json())
        return 200, details

    async def repo_branch_rules(
        self, org: str, repo: str, branch: str
    ) -> tuple[int, list[dict]]:
        """Effective branch rules for a repo (includes inherited org rulesets)."""
        resp = await self._request(
            "GET", f"{self._api_url}/repos/{org}/{repo}/rules/branches/{branch}"
        )
        if resp.status_code != 200:
            return resp.status_code, []
        return 200, list(resp.json())

    # ------------------------------------------------------------------ #
    # Per-repo data (repo mode)
    # ------------------------------------------------------------------ #
    async def get_repo(self, org: str, repo: str) -> Repo | None:
        """Fetch a single repository's identity."""
        resp = await self._request("GET", f"{self._api_url}/repos/{org}/{repo}")
        if resp.status_code != 200:
            return None
        raw = resp.json()
        return Repo(
            name=raw["name"],
            full_name=raw["full_name"],
            html_url=raw["html_url"],
            archived=raw.get("archived", False),
            fork=raw.get("fork", False),
            is_template=raw.get("is_template", False),
            private=raw.get("private", False),
            default_branch=raw.get("default_branch", "main"),
        )

    async def repo_code_scanning_alerts(self, org: str, repo: str) -> tuple[int, list[dict]]:
        """Open code-scanning alerts for one repo (status, alerts)."""
        return await self._get_list(
            f"{self._api_url}/repos/{org}/{repo}/code-scanning/alerts", state="open"
        )

    async def repo_secret_scanning(self, org: str, repo: str) -> tuple[int, int]:
        """Open secret-scanning alert (status, open count) for one repo."""
        status, items = await self._get_list(
            f"{self._api_url}/repos/{org}/{repo}/secret-scanning/alerts", state="open"
        )
        return status, len(items)

    async def repo_dependabot_alerts(self, org: str, repo: str) -> tuple[int, list[dict]]:
        """Open Dependabot alerts for one repo (status, alerts)."""
        return await self._get_list(
            f"{self._api_url}/repos/{org}/{repo}/dependabot/alerts", state="open"
        )
