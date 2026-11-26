# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""What the pre-flight reads from a classic PAT's scope and expiry headers.

Kept apart from :mod:`github_security_report.cli.preflight`, which probes the
token and decides whether to stop; these only compare the headers the probe
returns with what a run needs, and word the warnings.
"""

from __future__ import annotations

import datetime as dt
import logging
from dataclasses import dataclass

log = logging.getLogger(__name__)

# A token expiring sooner than this is worth a warning on every run.
EXPIRY_WARNING = dt.timedelta(days=7)


@dataclass(frozen=True)
class ScopeRequirement:
    """A classic PAT scope requirement: any one of ``any_of`` satisfies it."""

    any_of: tuple[str, ...]
    without: str


# What a classic PAT needs, and what a run without it loses. Warnings only:
# the reads themselves degrade to unknown. ``admin:org`` is deliberately
# absent, since organisation rulesets are optional and reported at INFO.
SCOPE_REQUIREMENTS: tuple[ScopeRequirement, ...] = (
    ScopeRequirement(("repo",), "only public repositories are read"),
    ScopeRequirement(
        ("repo", "public_repo", "security_events"),
        "code scanning, secret scanning and Dependabot alerts are reported as unknown",
    ),
    ScopeRequirement(
        ("read:org", "write:org", "admin:org"),
        "organisation membership is unreadable, so the Ext columns are a lower bound",
    ),
)


def scope_warnings(granted: str) -> list[str]:
    """One warning per unmet row of :data:`SCOPE_REQUIREMENTS`.

    ``granted`` is the ``X-OAuth-Scopes`` value; an empty one is a classic
    PAT with no scopes at all. A token that sends no such header is not
    checked: its absence means "cannot tell", never "no scopes".
    """
    scopes = {part.strip() for part in granted.split(",") if part.strip()}
    warnings: list[str] = []
    for requirement in SCOPE_REQUIREMENTS:
        if scopes.isdisjoint(requirement.any_of):
            names = " or ".join(f"'{scope}'" for scope in requirement.any_of)
            warnings.append(f"lacks the {names} scope: {requirement.without}")
    return warnings


def expiry_warning(value: str | None, now: dt.datetime) -> str | None:
    """A warning when the token expires within :data:`EXPIRY_WARNING`.

    ``value`` is the ``github-authentication-token-expiration`` header, as
    ``2026-01-01 12:00:00 UTC``. An unparsable or out-of-range one is ignored.
    """
    if not value:
        return None
    expires = _parse_expiry(value.strip())
    if expires is None:
        log.debug("token expiry %r not understood; ignored", value)
        return None
    left = expires - now
    if left > EXPIRY_WARNING:
        return None
    days = max(0, left.days)
    return (
        f"expires at {expires:%Y-%m-%d %H:%M:%S} UTC, in {days} day(s); "
        "renew it before scheduled runs start failing"
    )


def _parse_expiry(value: str) -> dt.datetime | None:
    for fmt in ("%Y-%m-%d %H:%M:%S %Z", "%Y-%m-%d %H:%M:%S %z"):
        try:
            parsed = dt.datetime.strptime(value, fmt)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=dt.UTC)
            return parsed.astimezone(dt.UTC)
        except (ValueError, OverflowError):
            continue
    return None
