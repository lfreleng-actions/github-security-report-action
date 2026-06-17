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

# The code-scanning-derived signal tools whose enablement we probe per repo.
# Each is checked via the analyses ``tool_name`` filter (a definitive presence
# test) rather than scanning the analysis history, which a busy repo could push
# a low-frequency tool out of.
_CODE_SCANNING_SIGNAL_TOOLS = ("CodeQL", "Scorecard", "zizmor")


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
            try:
                async with self._sem:
                    resp = await http.request(method, url, **kwargs)  # type: ignore[arg-type]
            except httpx.HTTPError as exc:
                # Transport failure (DNS/TLS/connect or read timeout). Signals
                # degrade independently, so convert this into an indeterminate
                # 503 response rather than aborting the whole run; callers treat
                # any non-200 as not-clean/unknown.
                log.warning("request to %s failed: %s", url, exc)
                return httpx.Response(503, request=httpx.Request(method, url))
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

    async def _get_list(self, url: str, **params: object) -> tuple[int, list[dict]]:
        """GET a paginated list, returning (status, items collected).

        The status is itself a signal for these endpoints (404 = feature
        disabled). If a *later* page fails, the partial items gathered so far
        are returned alongside that failing status (not 200): the data is
        incomplete, so callers must be able to degrade to UNKNOWN rather than
        treat an undercount as authoritative. The failed response is closed to
        avoid leaking a pooled connection (its body is never read).
        """
        resp = await self._request("GET", url, params={**params, "per_page": 100})
        if resp.status_code != 200:
            status = resp.status_code
            await resp.aclose()  # unread body would leak a pooled connection
            return status, []
        items = list(resp.json())
        next_url = resp.links.get("next", {}).get("url")
        await resp.aclose()  # release the connection once body/links are read
        while next_url:
            resp = await self._request("GET", next_url)
            if resp.status_code != 200:
                log.warning(
                    "pagination stopped early: %s -> %s (results may be partial)",
                    next_url,
                    resp.status_code,
                )
                await resp.aclose()
                return resp.status_code, items
            items.extend(resp.json())
            next_url = resp.links.get("next", {}).get("url")
            await resp.aclose()
        return 200, items

    # ------------------------------------------------------------------ #
    # Repositories
    # ------------------------------------------------------------------ #
    async def list_org_repos(self, org: str) -> tuple[int, list[Repo]]:
        """List an organisation's repositories, skipping disabled/empty ones.

        Returns the listing status alongside the repos: a non-200 (a failed or
        mid-pagination-truncated listing) means the set is incomplete, so the
        caller can flag a partial report rather than silently omitting repos
        (and their offenders).
        """
        status, raws = await self._get_list(
            f"{self._api_url}/orgs/{org}/repos", type="all"
        )
        repos: list[Repo] = []
        for raw in raws:
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
        return status, repos

    # ------------------------------------------------------------------ #
    # Org-bulk alert sweeps
    # ------------------------------------------------------------------ #
    async def org_bulk_alerts(self, org: str, kind: str) -> tuple[int, list[dict]]:
        """Sweep all open alerts of one kind across the org.

        Returns the first-page HTTP status alongside the alerts so callers can
        tell an authoritative empty result (200 ``[]``) apart from an unreadable
        sweep (403/404/5xx), which must never be reported as "clean".
        """
        path = BULK_KINDS[kind]
        return await self._get_list(
            f"{self._api_url}/orgs/{org}/{path}", state="open"
        )

    # ------------------------------------------------------------------ #
    # Per-repo enabled-probes
    # ------------------------------------------------------------------ #
    async def code_scanning_tools(self, org: str, repo: str) -> tuple[int, set[str]]:
        """Return (status, enabled signal tool names) from code-scanning analyses.

        Each tool in ``_CODE_SCANNING_SIGNAL_TOOLS`` is probed with the analyses
        ``tool_name`` filter, a definitive presence test that does not depend on
        how many analyses a busy repo has accumulated (the previous page-by-page
        scan could miss a low-frequency tool past its page cap and wrongly nag
        it). The first probe's status is authoritative for the endpoint (404 =
        code scanning disabled, 403 = forbidden, 5xx/0 = indeterminate); a later
        per-tool probe that fails is skipped (its tool goes undetected for this
        run) rather than discarding the whole result.
        """
        url = f"{self._api_url}/repos/{org}/{repo}/code-scanning/analyses"
        tools: set[str] = set()
        for index, tool in enumerate(_CODE_SCANNING_SIGNAL_TOOLS):
            resp = await self._request(
                "GET", url, params={"per_page": 1, "tool_name": tool}
            )
            if resp.status_code != 200:
                status = resp.status_code
                await resp.aclose()  # unread body would leak a pooled connection
                if index == 0:
                    return status, set()
                continue
            has_analyses = bool(resp.json())
            await resp.aclose()  # release the connection once the body is read
            if has_analyses:
                tools.add(tool)
        return 200, tools

    async def secret_scanning_status(self, org: str, repo: str) -> int:
        """HTTP status of the secret-scanning alerts endpoint (404 = disabled)."""
        resp = await self._request(
            "GET",
            f"{self._api_url}/repos/{org}/{repo}/secret-scanning/alerts",
            params={"per_page": 1, "state": "open"},
        )
        status = int(resp.status_code)
        await resp.aclose()  # only the status is needed; release the connection
        return status

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
            await resp.aclose()  # unread body would leak a pooled connection
            return None
        node = (resp.json().get("data") or {}).get("repository")
        await resp.aclose()  # release the connection once the body is read
        if not node:
            return None
        return bool(node.get("hasVulnerabilityAlertsEnabled"))

    async def scorecard_score(self, org: str, repo: str) -> tuple[int, float | None]:
        """External OpenSSF Scorecard aggregate score (status, score|None).

        Transport failures to this third-party API are handled centrally by
        ``_request`` (which returns an indeterminate 503), so a network blip
        degrades the Scorecard signal rather than aborting the run.
        """
        url = f"{self._scorecard_url}/projects/github.com/{org}/{repo}"
        resp = await self._request("GET", url, client=self._ext_client)
        if resp.status_code != 200:
            status = resp.status_code
            await resp.aclose()  # unread body would leak a pooled connection
            return status, None
        score = resp.json().get("score")
        await resp.aclose()  # release the connection once the body is read
        return 200, score

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
            await resp.aclose()  # release the connection once the body is read
        return 200, details

    async def repo_branch_rules(
        self, org: str, repo: str, branch: str
    ) -> tuple[int, list[dict]]:
        """Effective branch rules for a repo (includes inherited org rulesets)."""
        resp = await self._request(
            "GET", f"{self._api_url}/repos/{org}/{repo}/rules/branches/{branch}"
        )
        if resp.status_code != 200:
            status = resp.status_code
            await resp.aclose()  # unread body would leak a pooled connection
            return status, []
        rules = list(resp.json())
        await resp.aclose()  # release the connection once the body is read
        return 200, rules

    # ------------------------------------------------------------------ #
    # Per-repo data (repo mode)
    # ------------------------------------------------------------------ #
    async def get_repo(self, org: str, repo: str) -> Repo | None:
        """Fetch a single repository's identity."""
        resp = await self._request("GET", f"{self._api_url}/repos/{org}/{repo}")
        if resp.status_code != 200:
            await resp.aclose()  # unread body would leak a pooled connection
            return None
        raw = resp.json()
        await resp.aclose()  # release the connection once the body is read
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
