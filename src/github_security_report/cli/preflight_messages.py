# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""What the pre-flight prints when it stops a run, and the responses it reads to say it.

Kept apart from :mod:`github_security_report.cli.preflight`, which decides
whether to stop; these only word the abort and read the wait or the reason a
rate-limited response gives.
"""

from __future__ import annotations

import datetime as dt
import math

import httpx

from github_security_report.client.parsers import _parse_retry_after


def reset_text(reset: object, now: dt.datetime) -> str:
    """When a spent resource resets, in UTC, and the whole minutes to wait."""
    at = _reset_at(reset)
    if at is None:
        return "reset time unknown"
    minutes = max(0, math.ceil((at - now).total_seconds() / 60))
    return f"resets at {at:%Y-%m-%d %H:%M:%S} UTC (wait {minutes} minute(s))"


def _reset_at(reset: object) -> dt.datetime | None:
    if not isinstance(reset, int | float) or isinstance(reset, bool):
        return None
    try:
        return dt.datetime.fromtimestamp(reset, dt.UTC)
    except (OverflowError, OSError, ValueError):
        return None


async def error_message(resp: httpx.Response) -> str:
    """The ``message`` of an error response's JSON body, or ``""``; closes it."""
    try:
        body: object = resp.json()
    except ValueError:
        return ""
    finally:
        await resp.aclose()
    message = body.get("message") if isinstance(body, dict) else None
    return message if isinstance(message, str) else ""


def names_a_rate_limit(message: str) -> bool:
    """Whether a 403's message is GitHub's wording for a rate limit.

    Current wording is "You have exceeded a secondary rate limit"; older
    responses said "You have triggered an abuse detection mechanism".
    """
    text = message.lower()
    return "rate limit" in text or "abuse detection" in text


def rate_limit_message(org: str, what: str, url: str, headers: httpx.Headers) -> str:
    lines = [
        f"Rate limit exhausted: the repository listing for {org} {what}; "
        "aborting because every read would be degraded to unknown.",
        f"  endpoint=GET {url}",
    ]
    lines.append(f"  {wait_text(headers, dt.datetime.now(dt.UTC))}")
    lines.append("  Wait for the rate limit to reset, or run with a different token.")
    return "\n".join(lines)


def wait_text(headers: httpx.Headers, now: dt.datetime) -> str:
    """How long a rate-limited response says to wait.

    ``Retry-After`` is the wait a secondary limit sets. ``x-ratelimit-reset``
    is when the primary budget refills, which matters only when that budget
    is spent (``x-ratelimit-remaining: 0``). When both apply the later one
    governs; when neither does, GitHub's guidance is to wait at least a minute.
    """
    waits: list[tuple[dt.datetime, str]] = []
    retry_after = _retry_after_at(headers, now)
    if retry_after is not None:
        at, seconds = retry_after
        waits.append(
            (
                at,
                f"retry after {at:%Y-%m-%d %H:%M:%S} UTC "
                f"(Retry-After: wait {seconds} second(s))",
            )
        )
    if headers.get("x-ratelimit-remaining") == "0":
        try:
            reset: int | None = int(headers.get("x-ratelimit-reset", ""))
        except ValueError:
            reset = None
        reset_at = _reset_at(reset)
        if reset_at is not None:
            waits.append((reset_at, reset_text(reset, now)))
    if waits:
        return max(waits, key=lambda wait: wait[0])[1]
    at = now + dt.timedelta(minutes=1)
    return (
        f"retry no sooner than {at:%Y-%m-%d %H:%M:%S} UTC (GitHub gave no "
        "wait; it advises at least one minute)"
    )


def _retry_after_at(
    headers: httpx.Headers, now: dt.datetime
) -> tuple[dt.datetime, int] | None:
    """When ``Retry-After`` says to retry, and its whole seconds; ``None`` if unusable.

    A number that is negative or not finite (``-5``, ``nan``, ``inf``), or
    that lands past the calendar's end, is treated as absent, so the abort
    advises the one-minute fallback. The raw value is checked first because
    the shared parser clamps such numbers to zero, which would read as
    "wait 0 seconds".
    """
    raw = headers.get("retry-after")
    if _unusable_delta_seconds(raw):
        return None
    seconds = _parse_retry_after(raw)
    if seconds is None:
        return None
    whole = math.ceil(seconds)
    try:
        return now + dt.timedelta(seconds=whole), whole
    except OverflowError:
        return None


def _unusable_delta_seconds(raw: str | None) -> bool:
    """Whether ``raw`` is a number no retry can wait for: negative or not finite.

    A value that is not a number (absent, or an HTTP-date) is left to the parser.
    """
    try:
        value = float(raw or "")
    except ValueError:
        return False
    return not 0 <= value < math.inf


def listing_message(org: str, status: int, url: str, sso: str | None) -> str:
    lines = [
        f"Repository listing unreadable: GitHub answered HTTP {status} for "
        f"the repositories of {org}; aborting because the report would "
        "cover no repositories and read as clean.",
        f"  endpoint=GET {url}",
        "  Check the organisation's name; for a classic PAT, that it is "
        "SSO-authorised for the organisation; for a fine-grained PAT, its "
        "resource owner and repository access.",
    ]
    if sso:
        lines.append(f"  X-GitHub-SSO: {sso}")
    return "\n".join(lines)


def network_message(url: str, answer: str) -> str:
    return (
        f"Network error: the GitHub API answered {answer} after the retry "
        "budget; aborting because a security report cannot be produced "
        f"without live API data.\n  endpoint=GET {url}"
    )
