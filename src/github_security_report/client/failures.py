# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""How the transport fails: the errors raised once a request cannot succeed.

Split from :mod:`~github_security_report.client.transport` so the retry loop
there reads as policy, while the wording and diagnostics of each terminal
failure (a rejected credential, an unreachable endpoint) live together here.
"""

from __future__ import annotations

import asyncio
import logging
import socket

import httpx

from github_security_report.client.endpoints import (
    API_DIAGNOSTIC_DNS_TIMEOUT_SECONDS,
    API_MAX_TOTAL_WAIT_SECONDS,
)
from github_security_report.client.errors import AuthError, NetworkError

log = logging.getLogger(__name__)


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
