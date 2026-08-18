# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""HTTP transport: connection lifecycle, retry/backoff and pagination.

:class:`Transport` owns the two ``httpx`` clients (authenticated GitHub and
unauthenticated third-party) and funnels every call through ``_request`` so the
shared retry/backoff policy applies uniformly. The read and write layers build
on it.
"""

from __future__ import annotations

import asyncio
import logging
import socket
from typing import TypeVar

import httpx

from github_security_report.client.endpoints import (
    API_BACKOFF_FACTOR,
    API_BACKOFF_INITIAL_SECONDS,
    API_DIAGNOSTIC_DNS_TIMEOUT_SECONDS,
    API_MAX_RETRIES,
    API_MAX_TOTAL_WAIT_SECONDS,
    GITHUB_API,
    GRAPHQL_API,
    SCORECARD_API,
)
from github_security_report.client.parsers import _next_page_url, _parse_retry_after

log = logging.getLogger(__name__)

_TransportT = TypeVar("_TransportT", bound="Transport")


class NetworkError(RuntimeError):
    """The GitHub API was unusable after exhausting the retry budget.

    Raised for transport-level failures (DNS, connection, TLS, or read
    timeout) against the GitHub API that persist across every retry within
    ``API_MAX_TOTAL_WAIT_SECONDS``, and by callers whose data is load-bearing
    for the whole report (the batched GraphQL prefetch) when GitHub keeps
    answering with server errors. The run aborts rather than rendering a
    report from missing data: when the API itself cannot be relied on, an
    empty or "all clean / all unknown" report is actively misleading.
    Transport failures against the third-party Scorecard endpoint do not
    raise this -- they degrade that one signal instead.
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


class Transport:
    """Connection lifecycle plus the shared retry/backoff request primitives."""

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

    async def __aenter__(self: _TransportT) -> _TransportT:
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
        Server errors (5xx) and rate-limit responses (403/429) back off on the
        same schedule and, once exhausted, return the response for the caller
        to handle: per-signal probes degrade to unknown, while callers whose
        data is load-bearing (the GraphQL prefetch) abort the run instead of
        fabricating results.
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
                            url,
                            attempt + 1,
                            exc,
                        )
                        return httpx.Response(503, request=httpx.Request(method, url))
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
                    "request to %s failed: %s; retrying in %.0fs (retry %d of %d)",
                    url,
                    exc,
                    delay,
                    attempt + 1,
                    self._max_retries,
                )
                await asyncio.sleep(delay)
                waited += delay
                attempt += 1
                continue
            if resp.status_code not in (403, 429) and resp.status_code < 500:
                return resp
            # Reachable but degraded: a 5xx (GitHub infrastructure trouble) or
            # a possible rate limit. Distinguish secondary/primary rate
            # limiting from a genuine 403, then back off on the shared
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
                resp.status_code == 429 or retry_after is not None or remaining == "0"
            )
            # Any 5xx is retried: GitHub's infrastructure wobbles produce
            # transient 500/502/503 responses that, if returned un-retried,
            # would silently degrade (or falsify) whole report sections.
            server_error = resp.status_code >= 500
            delay = (
                retry_after_secs
                if retry_after_secs is not None
                else self._backoff_delay(attempt)
            )
            if (
                not (rate_limited or server_error)
                or attempt >= self._max_retries
                or waited + delay > API_MAX_TOTAL_WAIT_SECONDS
            ):
                # Retries exhausted (or a genuine 403): hand the response back
                # so the caller can degrade its signal to unknown -- or, when
                # its data is load-bearing, abort the run.
                return resp
            if server_error:
                log.warning(
                    "server error %d on %s; retrying in %.0fs (retry %d of %d)",
                    resp.status_code,
                    url,
                    delay,
                    attempt + 1,
                    self._max_retries,
                )
            else:
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
        next_url = _next_page_url(resp)
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
            next_url = _next_page_url(resp)
            await resp.aclose()
        return 200, items
