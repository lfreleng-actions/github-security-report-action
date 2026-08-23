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
from dataclasses import dataclass
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


class AuthError(NetworkError):
    """GitHub rejected the credentials (HTTP 401).

    Distinct from the permission-shaped failures the report degrades over. A
    403 usually means "this token cannot see this one feature", which is a
    legitimate per-signal unknown; a 401 means the token itself is invalid,
    expired or revoked, so every remaining read fails the same way. Degrading
    would render a confident "all clean" report out of nothing but rejections
    -- the false negative a security report must never publish, and one that a
    scheduled run would happily push to GitHub Pages over a good report.

    Subclasses :class:`NetworkError` so any caller already aborting on an
    unusable API keeps doing so; the CLI catches it first to report the cause
    and exit with its own status.
    """


def _auth_error(method: str, url: str) -> AuthError:
    """The :class:`AuthError` for credentials GitHub rejected on ``url``.

    Built on the very first 401 rather than retried or degraded, for the
    reasons :class:`AuthError` gives. The message names the remedy, because
    the operator's next action is to check the token, not to retry.
    """
    return AuthError(
        "Authentication error: GitHub rejected the credentials "
        "(HTTP 401); aborting because every subsequent read would "
        "fail the same way and the report would render as "
        "'no data' or 'all clean' rather than as a failure.\n  "
        f"endpoint={method} {url}\n  "
        "Check that the token is set, has not expired, and has not "
        "been revoked or rotated."
    )


async def _transport_failure_result(
    exc: httpx.HTTPError,
    method: str,
    url: str,
    *,
    attempt: int,
    is_external: bool,
) -> httpx.Response:
    """Resolve a transport failure that outlived the whole retry budget.

    A third-party (Scorecard) endpoint degrades to an indeterminate 503 so one
    flaky external API never aborts the GitHub report. The GitHub API instead
    raises :class:`NetworkError`: a report built without live data is actively
    misleading, so the run aborts, carrying a diagnostics line that names the
    endpoint that could not be reached.
    """
    if is_external:
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


class _RetryBudget:
    """Attempts spent and seconds slept so far within one ``_request`` call.

    Holds the state the retry loop carries across iterations, so deciding that
    the budget has run out and spending it (sleep, then count the attempt) stay
    together instead of being open-coded at every backoff site.
    """

    def __init__(self, max_retries: int) -> None:
        self.attempt = 0
        self.waited = 0.0
        self._max_retries = max_retries

    def exhausted(self, delay: float) -> bool:
        """Whether sleeping ``delay`` would exceed the retry or wait budget."""
        return (
            self.attempt >= self._max_retries
            or self.waited + delay > API_MAX_TOTAL_WAIT_SECONDS
        )

    async def sleep(self, delay: float) -> None:
        """Back off for ``delay`` seconds and charge them to the budget."""
        await asyncio.sleep(delay)
        self.waited += delay
        self.attempt += 1


@dataclass(frozen=True)
class _RetryPlan:
    """How a reachable-but-degraded (403/429/5xx) response should be treated.

    ``retriable`` is false for a genuine permission error, which is handed
    straight back to the caller; ``server_error`` only selects the wording of
    the retry warning.
    """

    retriable: bool
    server_error: bool
    delay: float


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
        ``API_MAX_RETRIES``), and at most ``API_MAX_TOTAL_WAIT_SECONDS`` of
        cumulative waiting -- the two ceilings :class:`_RetryBudget` tracks.
        What happens once that budget is spent depends on the failure and lives
        in the helpers below: :func:`_transport_failure_result` for an endpoint
        that could not be reached at all, and :meth:`_plan_degraded_retry` for a
        server error (5xx) or a rate limit (403/429), which ends by returning
        the response for the caller to handle -- per-signal probes degrade to
        unknown, while callers whose data is load-bearing (the GraphQL
        prefetch) abort the run instead of fabricating results. A 401 from the
        GitHub API is never degraded or retried; see :func:`_auth_error`.
        """
        http = client or self._client
        is_external = http is self._ext_client
        budget = _RetryBudget(self._max_retries)
        while True:
            try:
                async with self._sem:
                    resp = await http.request(method, url, **kwargs)  # type: ignore[arg-type]
            except httpx.HTTPError as exc:
                # Transport failure: the endpoint could not be reached at all
                # (DNS, connection, TLS, or read timeout).
                delay = self._backoff_delay(budget.attempt)
                if budget.exhausted(delay):
                    return await _transport_failure_result(
                        exc,
                        method,
                        url,
                        attempt=budget.attempt,
                        is_external=is_external,
                    )
                self._log_transport_retry(url, exc, delay, budget.attempt)
                await budget.sleep(delay)
                continue
            if resp.status_code == 401 and not is_external:
                # Credentials rejected: fail fast on the very first request
                # rather than letting a hundred more rejections accumulate into
                # an empty, plausible-looking report.
                await resp.aclose()  # unread body would leak a pooled connection
                raise _auth_error(method, url)
            if resp.status_code not in (403, 429) and resp.status_code < 500:
                return resp
            # Reachable but degraded: a 5xx (GitHub infrastructure trouble) or
            # a possible rate limit. Distinguish secondary/primary rate
            # limiting from a genuine 403, then back off on the shared
            # schedule (honouring Retry-After) within the wait budget.
            plan = self._plan_degraded_retry(resp, budget.attempt)
            if not plan.retriable or budget.exhausted(plan.delay):
                # Retries exhausted (or a genuine 403): hand the response back
                # so the caller can degrade its signal to unknown -- or, when
                # its data is load-bearing, abort the run.
                return resp
            self._log_degraded_retry(resp, url, plan, budget.attempt)
            # The discarded response must be closed; we are retrying and will
            # not read its body, so leaving it open would leak a pool connection.
            await resp.aclose()
            await budget.sleep(plan.delay)

    def _plan_degraded_retry(self, resp: httpx.Response, attempt: int) -> _RetryPlan:
        """Decide whether a 403/429/5xx response is retriable, and after how long.

        A 429 is by definition "Too Many Requests", so always back off on it
        even when GitHub (or an intermediary) omits Retry-After and the
        x-ratelimit-remaining header; falling through would return the 429
        un-retried. A 403 is a rate limit only when one of those headers
        says so (otherwise it is a genuine permission error); the mere
        *presence* of Retry-After counts, so a malformed/unparsable value
        still triggers a backoff (falling back to the exponential schedule)
        rather than being mistaken for a permission error.

        Any 5xx is retried: GitHub's infrastructure wobbles produce transient
        500/502/503 responses that, if returned un-retried, would silently
        degrade (or falsify) whole report sections.
        """
        retry_after = resp.headers.get("retry-after")
        remaining = resp.headers.get("x-ratelimit-remaining")
        retry_after_secs = _parse_retry_after(retry_after)
        rate_limited = (
            resp.status_code == 429 or retry_after is not None or remaining == "0"
        )
        server_error = resp.status_code >= 500
        return _RetryPlan(
            retriable=rate_limited or server_error,
            server_error=server_error,
            delay=(
                retry_after_secs
                if retry_after_secs is not None
                else self._backoff_delay(attempt)
            ),
        )

    def _log_transport_retry(
        self, url: str, exc: httpx.HTTPError, delay: float, attempt: int
    ) -> None:
        """Warn that an unreachable endpoint will be retried after ``delay``."""
        log.warning(
            "request to %s failed: %s; retrying in %.0fs (retry %d of %d)",
            url,
            exc,
            delay,
            attempt + 1,
            self._max_retries,
        )

    def _log_degraded_retry(
        self, resp: httpx.Response, url: str, plan: _RetryPlan, attempt: int
    ) -> None:
        """Warn that a degraded response will be retried after ``plan.delay``."""
        if plan.server_error:
            log.warning(
                "server error %d on %s; retrying in %.0fs (retry %d of %d)",
                resp.status_code,
                url,
                plan.delay,
                attempt + 1,
                self._max_retries,
            )
        else:
            log.warning("rate limited on %s; backing off %.0fs", url, plan.delay)

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
