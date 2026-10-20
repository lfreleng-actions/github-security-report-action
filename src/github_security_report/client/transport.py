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
import time
from dataclasses import dataclass
from typing import TypeVar

import httpx

from github_security_report.client.accounting import (
    RequestStats,
    RetryKind,
    _RequestTally,
)
from github_security_report.client.endpoints import (
    API_BACKOFF_FACTOR,
    API_BACKOFF_INITIAL_SECONDS,
    API_DEFAULT_CONCURRENCY,
    API_MAX_RETRIES,
    API_MAX_TOTAL_WAIT_SECONDS,
    EXTERNAL_CONCURRENCY,
    GITHUB_API,
    GRAPHQL_API,
    SCORECARD_API,
)
from github_security_report.client.failures import (
    _auth_error,
    _transport_failure_result,
)
from github_security_report.client.parsers import _next_page_url, _parse_retry_after

log = logging.getLogger(__name__)

_TransportT = TypeVar("_TransportT", bound="Transport")


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
        concurrency: int = API_DEFAULT_CONCURRENCY,
        max_retries: int = API_MAX_RETRIES,
        timeout: float = 30.0,
    ) -> None:
        self._api_url = api_url.rstrip("/")
        self._graphql_url = graphql_url
        self._scorecard_url = scorecard_url.rstrip("/")
        self._max_retries = max_retries
        self._sem = asyncio.Semaphore(concurrency)
        self._ext_sem = asyncio.Semaphore(EXTERNAL_CONCURRENCY)
        self._tally = _RequestTally()
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
        if self._tally.finished is None:
            self._tally.finished = time.monotonic()

    @property
    def stats(self) -> RequestStats:
        """What this client's requests have cost so far (see RequestStats).

        Elapsed time runs from construction until :meth:`aclose`, so reading
        it after the client closes gives the whole run.
        """
        return self._tally.snapshot()

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
        quiet: bool = False,
        **kwargs: object,
    ) -> httpx.Response:
        """Issue a request under the shared retry/backoff policy.

        ``client`` selects the transport (default: the authenticated GitHub
        client). External calls pass the unauthenticated client so the GitHub
        token is never leaked to third parties.

        ``quiet`` marks an *optional* read whose failure its caller already
        swallows: its retry notices drop to DEBUG, so a best-effort probe
        cannot fill a healthy run's output with warnings about a signal nothing
        depends on. Log level only; the policy and every result are unchanged.

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
        # Third-party reads queue on their own semaphore, so a slow external
        # API cannot hold the slots GitHub requests are waiting for.
        sem = self._ext_sem if is_external else self._sem
        # Resolved once: an optional read reports its retries at DEBUG so it
        # cannot nag about a signal whose failure the caller already swallows.
        level = logging.DEBUG if quiet else logging.WARNING
        budget = _RetryBudget(self._max_retries)
        # What the next attempt retries, if anything. Counted when that attempt
        # is issued rather than when the backoff begins, so a request cancelled
        # during its backoff (a sibling prefetch batch aborting the run) does
        # not count a retry that never happened.
        retry_of: RetryKind | None = None
        while True:
            try:
                async with sem:
                    # Counted before the request leaves, so an attempt that
                    # never gets an answer is still a request that was made.
                    self._tally.attempt(retry_of=retry_of)
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
                self._log_transport_retry(url, exc, delay, budget.attempt, level)
                retry_of = "transport"
                await budget.sleep(delay)
                continue
            self._tally.record(resp)
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
            self._log_degraded_retry(resp, url, plan, budget.attempt, level)
            # The discarded response must be closed; we are retrying and will
            # not read its body, so leaving it open would leak a pool connection.
            await resp.aclose()
            retry_of = "degraded"
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
        self, url: str, exc: httpx.HTTPError, delay: float, attempt: int, level: int
    ) -> None:
        """Report at ``level`` that an unreachable endpoint will be retried."""
        log.log(
            level,
            "request to %s failed: %s; retrying in %.0fs (retry %d of %d)",
            url,
            exc,
            delay,
            attempt + 1,
            self._max_retries,
        )

    def _log_degraded_retry(
        self, resp: httpx.Response, url: str, plan: _RetryPlan, attempt: int, level: int
    ) -> None:
        """Report at ``level`` that a degraded response will be retried."""
        if plan.server_error:
            log.log(
                level,
                "server error %d on %s; retrying in %.0fs (retry %d of %d)",
                resp.status_code,
                url,
                plan.delay,
                attempt + 1,
                self._max_retries,
            )
        else:
            log.log(level, "rate limited on %s; backing off %.0fs", url, plan.delay)

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
