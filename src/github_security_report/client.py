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
import datetime as dt
import logging
import socket
from dataclasses import replace
from email.utils import parsedate_to_datetime
from typing import cast

import httpx

from github_security_report.models import ReleaseRef, Repo, RepoGraphData

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

# --------------------------------------------------------------------------- #
# Shared retry / backoff policy
# --------------------------------------------------------------------------- #
# Every API call (GitHub REST + GraphQL, and the external Scorecard endpoint)
# funnels through ``GitHubClient._request``, which applies the single policy
# defined by the constants below -- so retry behaviour is identical everywhere
# and tuning it is a one-line change here.

# Retries attempted after the initial request (total attempts == 1 + this).
API_MAX_RETRIES = 3
# Backoff before the first retry, in seconds; grows by ``API_BACKOFF_FACTOR``
# each subsequent retry to give an exponential 1s, 2s, 4s, ... schedule.
API_BACKOFF_INITIAL_SECONDS = 1.0
# Exponential growth factor applied to the backoff on each successive retry.
API_BACKOFF_FACTOR = 2.0
# Hard ceiling on cumulative time spent sleeping between retries for a single
# request. Once the next backoff would exceed this, retries stop: a GitHub
# transport failure then hard-fails (NetworkError) and a rate-limit gives up
# and degrades. Bounds the worst-case wait one request can add to a run.
API_MAX_TOTAL_WAIT_SECONDS = 60.0
# Upper bound on the best-effort DNS lookup used only to enrich a network-error
# message. Kept short so a slow or failing resolver cannot delay the abort: if
# resolution does not complete within this window the address is reported as
# ``ip=unresolved (timed out)``.
API_DIAGNOSTIC_DNS_TIMEOUT_SECONDS = 2.0


class NetworkError(RuntimeError):
    """The GitHub API was unreachable after exhausting the retry budget.

    Raised for transport-level failures (DNS, connection, TLS, or read
    timeout) against the GitHub API that persist across every retry within
    ``API_MAX_TOTAL_WAIT_SECONDS``. The run aborts rather than rendering a
    report from missing data: when the API itself cannot be reached, an empty
    or "all clean / all unknown" report is actively misleading. Transport
    failures against the third-party Scorecard endpoint do not raise this --
    they degrade that one signal instead.
    """


async def _endpoint_diagnostics(url: str) -> str:
    """A ``host=... ip=... port=...`` line describing a failed endpoint.

    Best-effort and never raises: it re-resolves the URL's host so an operator
    can tell a DNS failure (no address) from a host that resolves but will not
    connect. Appended to the network-error message on its own dedicated line.

    The lookup runs on the event loop's resolver under a short timeout
    (``API_DIAGNOSTIC_DNS_TIMEOUT_SECONDS``) rather than calling the blocking
    ``socket.getaddrinfo`` directly: this routine fires exactly when the network
    is already failing (often DNS itself), so a synchronous resolve could stall
    the event loop and delay the abort. If resolution does not complete promptly
    the address falls back to ``unresolved (...)``.
    """
    try:
        parsed = httpx.URL(url)
        host = parsed.host or "?"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except Exception:  # pragma: no cover - defensive URL parsing
        return f"host=? ip=? port=? ({url})"
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(host, port, type=socket.SOCK_STREAM),
            timeout=API_DIAGNOSTIC_DNS_TIMEOUT_SECONDS,
        )
        ips = sorted({str(info[4][0]) for info in infos})
        addr = ", ".join(ips) if ips else "no addresses"
    except asyncio.TimeoutError:
        addr = "unresolved (timed out)"
    except OSError as exc:
        detail = exc.strerror or str(exc) or "resolution failed"
        addr = f"unresolved ({detail})"
    return f"host={host} ip={addr} port={port}"

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

# Batched per-repo prefetch. One aliased query fetches, for many repositories
# at once: Dependabot-alerts enablement, the most-recent tag's commit date
# (a tag's target is a Commit (lightweight) or a Tag object (annotated) whose
# own target is the Commit -- both branches are read), the authoritative
# latest release plus a window of recent releases with their immutability, and
# the raw .github/dependabot.yml. This replaces the former per-repo
# latest-release (REST), latest-tag (GraphQL), dependabot.yml
# (REST) and Dependabot-enabled (GraphQL) round-trips.
_REPO_GRAPH_FRAGMENT = """\
fragment RepoData on Repository {
  hasVulnerabilityAlertsEnabled
  dependabotConfig: object(expression: "HEAD:.github/dependabot.yml") {
    ... on Blob { text }
  }
  tags: refs(refPrefix: "refs/tags/", first: 1,
       orderBy: {field: TAG_COMMIT_DATE, direction: DESC}) {
    nodes {
      target {
        __typename
        ... on Commit { committedDate }
        ... on Tag { target { ... on Commit { committedDate } } }
      }
    }
  }
  latestRelease {
    tagName isLatest isPrerelease isDraft immutable publishedAt createdAt
  }
  releases(first: 25, orderBy: {field: CREATED_AT, direction: DESC}) {
    nodes {
      tagName isLatest isPrerelease isDraft immutable publishedAt createdAt
    }
  }
}
"""


def _parse_iso(value: object) -> dt.datetime | None:
    """Parse a GitHub ISO-8601 timestamp (``...Z``) into an aware datetime."""
    if not isinstance(value, str) or not value:
        return None
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _parse_retry_after(value: str | None) -> float | None:
    """Seconds to wait from a ``Retry-After`` header, or ``None`` if absent/bad.

    Per RFC 7231 ``Retry-After`` is either delta-seconds (an integer) or an
    HTTP-date. GitHub normally sends delta-seconds, but a proxy or future change
    may send a date, so both forms are parsed: a bare ``float(value)`` would
    raise ``ValueError`` on a date and crash rate-limit handling. A past or
    unparsable date clamps to ``0.0`` / returns ``None`` rather than raising.
    """
    if not value:
        return None
    value = value.strip()
    try:
        return max(0.0, float(value))
    except ValueError:
        pass
    try:
        when = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if when is None:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=dt.timezone.utc)
    return max(0.0, (when - dt.datetime.now(dt.timezone.utc)).total_seconds())


def _tag_committed_date(tags: dict | None) -> dt.datetime | None:
    """Commit date of the most-recent tag from a ``tags`` connection node.

    A tag ref's target is a Commit (lightweight tag) or a Tag object (annotated
    tag) whose own target is the Commit; both branches are read.
    """
    nodes = (tags or {}).get("nodes") or []
    if not nodes:
        return None
    # GraphQL connection nodes may legally be null (or non-dict) when a
    # sub-object errors; guard the node and its target so a bad entry
    # degrades to None instead of aborting the batched collection.
    first = nodes[0]
    if not isinstance(first, dict):
        return None
    target = first.get("target")
    if not isinstance(target, dict):
        return None
    committed = target.get("committedDate")
    if committed is None:  # annotated tag: the Tag's target is the Commit
        inner = target.get("target")
        committed = inner.get("committedDate") if isinstance(inner, dict) else None
    return _parse_iso(committed)


def _release_refs(nodes: list[dict]) -> list[ReleaseRef]:
    """Build :class:`ReleaseRef` objects from release connection nodes.

    Draft releases are skipped (they are never published), as are nodes with no
    tag. ``published_at`` falls back to the creation time when GitHub supplies
    no publish timestamp.
    """
    refs: list[ReleaseRef] = []
    for node in nodes:
        # GraphQL list entries may be null (e.g. when a sub-object errors);
        # skip non-dict nodes so a single bad entry cannot abort collection.
        if not isinstance(node, dict):
            continue
        if node.get("isDraft"):
            continue
        tag = node.get("tagName")
        if not tag:
            continue
        published = _parse_iso(node.get("publishedAt")) or _parse_iso(
            node.get("createdAt")
        )
        # ``immutable`` is nullable in GitHub's GraphQL schema; preserve a
        # missing value as None (indeterminate) rather than coercing it to
        # False, which would misreport an unknown state as mutable.
        raw_immutable = node.get("immutable")
        refs.append(
            ReleaseRef(
                tag=tag,
                immutable=None if raw_immutable is None else bool(raw_immutable),
                published_at=published,
                is_latest=bool(node.get("isLatest")),
                is_prerelease=bool(node.get("isPrerelease")),
            )
        )
    return refs


def _last_published(refs: list[ReleaseRef]) -> ReleaseRef | None:
    """Most recently published release, ignoring those with no publish time."""
    dated = [r for r in refs if r.published_at is not None]
    if not dated:
        return None
    return max(dated, key=lambda r: cast(dt.datetime, r.published_at))


def _parse_repo_node(node: dict) -> RepoGraphData:
    """Map one repository alias from the batched query to ``RepoGraphData``.

    The "Latest" release is taken from GitHub's authoritative ``latestRelease``
    field rather than scanning the bounded ``releases`` window: a repository
    with many newer draft or pre-release entries could otherwise push the
    ``isLatest`` release out of the window, dropping it from staleness and the
    Mutable Releases findings. The window still feeds the last-published
    computation, with the latest ref folded in (deduplicated by tag).
    """
    enabled_raw = node.get("hasVulnerabilityAlertsEnabled")
    enabled = bool(enabled_raw) if enabled_raw is not None else None
    config_obj = node.get("dependabotConfig")
    config_text = config_obj.get("text") if isinstance(config_obj, dict) else None
    window = _release_refs((node.get("releases") or {}).get("nodes") or [])
    latest_node = node.get("latestRelease")
    latest: ReleaseRef | None = None
    if isinstance(latest_node, dict):
        parsed = _release_refs([latest_node])
        if parsed:
            # Force the "Latest" badge: latestRelease is authoritative even
            # when the node's own isLatest flag is absent or stale.
            latest = replace(parsed[0], is_latest=True)
    candidates = list(window)
    if latest is not None and all(r.tag != latest.tag for r in candidates):
        candidates.append(latest)
    return RepoGraphData(
        dependabot_alerts_enabled=enabled,
        latest_tag_at=_tag_committed_date(node.get("tags")),
        latest_release_at=latest.published_at if latest else None,
        latest_release=latest,
        last_published_release=_last_published(candidates),
        dependabot_config=config_text,
    )


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
        max_retries: int = API_MAX_RETRIES,
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
    def _backoff_delay(self, attempt: int) -> float:
        """Exponential backoff (seconds) before retry ``attempt`` (0-based).

        ``API_BACKOFF_INITIAL_SECONDS`` grown by ``API_BACKOFF_FACTOR`` each
        attempt (1s, 2s, 4s, ...), capped so a single sleep never exceeds the
        cumulative wait budget.
        """
        delay = API_BACKOFF_INITIAL_SECONDS * (API_BACKOFF_FACTOR**attempt)
        return min(delay, API_MAX_TOTAL_WAIT_SECONDS)

    async def _request(
        self,
        method: str,
        url: str,
        *,
        client: httpx.AsyncClient | None = None,
        **kwargs: object,
    ) -> httpx.Response:
        """Issue a request under the shared retry/backoff policy.

        ``client`` selects the transport (default: the authenticated GitHub
        client). External calls pass the unauthenticated client so the GitHub
        token is never leaked to third parties.

        Retries follow the shared retry/backoff policy: exponential backoff,
        at most ``max_retries`` retries (the constructor argument, defaulting to
        ``API_MAX_RETRIES``), and at most
        ``API_MAX_TOTAL_WAIT_SECONDS`` of cumulative waiting. A transport
        failure (DNS/TLS/connect or read timeout) to the GitHub API that
        outlives the whole budget raises :class:`NetworkError` to abort the run
        -- a report built without live data would be misleading. The same
        failure against the third-party Scorecard endpoint instead degrades to
        an indeterminate 503, so one flaky external API never aborts the report.
        Rate-limit responses (403/429) back off on the same schedule and, once
        exhausted, return the throttled response for per-signal degradation.
        """
        http = client or self._client
        is_external = http is self._ext_client
        attempt = 0
        waited = 0.0
        while True:
            try:
                async with self._sem:
                    resp = await http.request(method, url, **kwargs)  # type: ignore[arg-type]
            except httpx.HTTPError as exc:
                # Transport failure: the endpoint could not be reached at all
                # (DNS, connection, TLS, or read timeout).
                delay = self._backoff_delay(attempt)
                exhausted = (
                    attempt >= self._max_retries
                    or waited + delay > API_MAX_TOTAL_WAIT_SECONDS
                )
                if exhausted:
                    if is_external:
                        # Third-party (Scorecard) endpoint: degrade this one
                        # signal rather than aborting the whole GitHub report.
                        log.warning(
                            "external request to %s failed after %d attempt(s): "
                            "%s; signal degraded to unknown",
                            url, attempt + 1, exc,
                        )
                        return httpx.Response(
                            503, request=httpx.Request(method, url)
                        )
                    diagnostics = await _endpoint_diagnostics(url)
                    raise NetworkError(
                        "Network error: the GitHub API is unreachable after "
                        f"{attempt + 1} attempt(s) within "
                        f"{API_MAX_TOTAL_WAIT_SECONDS:.0f}s; aborting because a "
                        "security report cannot be produced without live API "
                        "data.\n  "
                        f"endpoint={method} {url} {diagnostics} "
                        f"cause={exc!s}"
                    ) from exc
                log.warning(
                    "request to %s failed: %s; retrying in %.0fs "
                    "(retry %d of %d)",
                    url, exc, delay, attempt + 1, self._max_retries,
                )
                await asyncio.sleep(delay)
                waited += delay
                attempt += 1
                continue
            if resp.status_code not in (403, 429):
                return resp
            # Reachable but possibly rate limited: distinguish secondary/primary
            # rate limiting from a genuine 403, then back off on the shared
            # schedule (honouring Retry-After) within the wait budget.
            retry_after = resp.headers.get("retry-after")
            remaining = resp.headers.get("x-ratelimit-remaining")
            retry_after_secs = _parse_retry_after(retry_after)
            # A 429 is by definition "Too Many Requests", so always back off on
            # it even when GitHub (or an intermediary) omits Retry-After and the
            # x-ratelimit-remaining header; falling through would return the 429
            # un-retried. A 403 is a rate limit only when one of those headers
            # says so (otherwise it is a genuine permission error); the mere
            # *presence* of Retry-After counts, so a malformed/unparsable value
            # still triggers a backoff (falling back to the exponential schedule
            # below) rather than being mistaken for a permission error.
            rate_limited = (
                resp.status_code == 429
                or retry_after is not None
                or remaining == "0"
            )
            delay = (
                retry_after_secs
                if retry_after_secs is not None
                else self._backoff_delay(attempt)
            )
            if (
                not rate_limited
                or attempt >= self._max_retries
                or waited + delay > API_MAX_TOTAL_WAIT_SECONDS
            ):
                return resp
            log.warning("rate limited on %s; backing off %.0fs", url, delay)
            # The discarded response must be closed; we are retrying and will
            # not read its body, so leaving it open would leak a pool connection.
            await resp.aclose()
            await asyncio.sleep(delay)
            waited += delay
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
                    created_at=_parse_iso(raw.get("created_at")),
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

        async def probe(tool: str) -> tuple[int, bool]:
            resp = await self._request(
                "GET", url, params={"per_page": 1, "tool_name": tool}
            )
            status = resp.status_code
            if status != 200:
                await resp.aclose()  # unread body would leak a pooled connection
                return status, False
            has_analyses = bool(resp.json())
            await resp.aclose()  # release the connection once the body is read
            return 200, has_analyses

        first_tool, *rest = _CODE_SCANNING_SIGNAL_TOOLS
        status, has = await probe(first_tool)
        if status != 200:
            # The first probe's status is authoritative for the endpoint
            # (404 = disabled, 403 = forbidden, 5xx/0 = indeterminate).
            return status, set()
        tools: set[str] = {first_tool} if has else set()
        # The endpoint is reachable; probe the remaining tools concurrently. A
        # later probe that fails just leaves its tool undetected for this run.
        results = await asyncio.gather(*(probe(tool) for tool in rest))
        tools.update(
            tool
            for tool, (st, hit) in zip(rest, results, strict=True)
            if st == 200 and hit
        )
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
            created_at=_parse_iso(raw.get("created_at")),
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

    # ------------------------------------------------------------------ #
    # Dependabot posture + release/tag freshness (extra sections)
    # ------------------------------------------------------------------ #
    async def automated_security_fixes(self, org: str, repo: str) -> bool | None:
        """Whether Dependabot security updates are enabled (None = indeterminate).

        ``GET .../automated-security-fixes`` returns ``{enabled, paused}`` (200)
        or 404 when the feature is disabled; any other status is indeterminate.
        """
        resp = await self._request(
            "GET", f"{self._api_url}/repos/{org}/{repo}/automated-security-fixes"
        )
        status = resp.status_code
        if status == 404:
            await resp.aclose()  # release the connection; 404 = disabled
            return False
        if status != 200:
            await resp.aclose()  # unread body would leak a pooled connection
            return None
        data = resp.json()
        await resp.aclose()  # release the connection once the body is read
        return bool(data.get("enabled"))

    async def repo_graph_batch(
        self, org: str, names: list[str]
    ) -> dict[str, RepoGraphData]:
        """Prefetch per-repo data for many repositories in one GraphQL query.

        Returns a ``RepoGraphData`` per requested name. Repositories that cannot
        be read (a ``null`` alias) or a wholly failed query degrade to default
        ``RepoGraphData``, so they drop out of the dependent tables rather than
        being mislabelled. An empty ``names`` issues no request.
        """
        out = {name: RepoGraphData() for name in names}
        if not names:
            return out
        aliases = "\n".join(
            f'  r{i}: repository(owner: $owner, name: $n{i}) {{ ...RepoData }}'
            for i in range(len(names))
        )
        var_decls = "".join(f", $n{i}: String!" for i in range(len(names)))
        query = (
            f"query($owner: String!{var_decls}) {{\n{aliases}\n}}\n"
            f"{_REPO_GRAPH_FRAGMENT}"
        )
        variables: dict[str, str] = {"owner": org}
        for i, name in enumerate(names):
            variables[f"n{i}"] = name
        resp = await self._request(
            "POST",
            self._graphql_url,
            json={"query": query, "variables": variables},
        )
        if resp.status_code != 200:
            await resp.aclose()  # unread body would leak a pooled connection
            return out
        data = (resp.json().get("data") or {})
        await resp.aclose()  # release the connection once the body is read
        for i, name in enumerate(names):
            node = data.get(f"r{i}")
            if isinstance(node, dict):
                out[name] = _parse_repo_node(node)
        return out
