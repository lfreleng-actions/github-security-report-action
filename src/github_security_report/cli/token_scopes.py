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
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from github_security_report.categories import CategoryKey

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


@dataclass(frozen=True)
class WriteScopeRequirement(ScopeRequirement):
    """A classic PAT scope ``remediate`` writes with; ``fatal`` aborts an apply."""

    fatal: bool = False


# What ``remediate``'s writes need of a classic PAT, broadest loss first; only
# the first unmet row is reported. Meeting them proves nothing: the account
# also needs access to each repository, which only the write itself reveals.
WRITE_SCOPE_REQUIREMENTS: tuple[WriteScopeRequirement, ...] = (
    WriteScopeRequirement(
        ("repo", "public_repo"), "could not apply the changes previewed", fatal=True
    ),
    WriteScopeRequirement(("repo",), "private repositories cannot be changed"),
)


@dataclass(frozen=True)
class PartialWriteScope:
    """Scopes that let a classic PAT make some of a category's writes.

    ``leaves`` names the writes those scopes do not cover, which still need the
    requirement's own scopes.
    """

    scopes: tuple[str, ...]
    leaves: str


# Categories a classic PAT may partly write with another scope. The CodeQL
# cleanup deletes code scanning analyses, which 'security_events' permits on
# public and private repositories alike, or re-enables a workflow, which it
# does not: so that scope keeps the category writable without meeting it.
PARTIAL_WRITE_SCOPES: Mapping[CategoryKey, PartialWriteScope] = {
    CategoryKey.CODEQL_STALE_CONFIGURATIONS: PartialWriteScope(
        ("security_events",), "workflow re-enables"
    ),
}


@dataclass(frozen=True)
class WriteScopeShortfall:
    """The first unmet write requirement, and the selected categories it hits.

    ``categories`` are the categories hit, in selection order; ``partly`` maps
    those that can still make some of their writes to the writes they cannot.
    ``partial`` is whether some selected category can still write, so that a
    run can still write those.
    """

    requirement: WriteScopeRequirement
    categories: tuple[CategoryKey, ...]
    partial: bool
    partly: Mapping[CategoryKey, str] = field(default_factory=dict)

    @property
    def blocks_apply(self) -> bool:
        """Whether an apply could change nothing, so must stop before it starts."""
        return self.requirement.fatal and not self.partial

    @property
    def abort_message(self) -> str:
        """Why an apply stops, after the token's name."""
        return (
            f"lacks the {scope_names(self.requirement)} scope, so --apply could "
            "change no repository; aborting before anything is collected. "
            "Run with a token that holds the 'repo' scope."
        )

    @property
    def warning(self) -> str:
        """The warning, after the token's name.

        It names the categories hit when some selected category can still
        write, and the writes a partly-hit category loses.
        """
        where = ""
        if self.partial:
            where = " in " + ", ".join(
                f"{key.value} ({self.partly[key]})" if key in self.partly else key.value
                for key in self.categories
            )
        return (
            f"lacks the {scope_names(self.requirement)} scope: "
            f"{self.requirement.without}{where}"
        )


def scope_warnings(granted: str) -> list[str]:
    """One warning per unmet row of :data:`SCOPE_REQUIREMENTS`.

    ``granted`` is the ``X-OAuth-Scopes`` value; an empty one is a classic
    PAT with no scopes at all. A token that sends no such header is not
    checked: its absence means "cannot tell", never "no scopes".
    """
    scopes = _granted_scopes(granted)
    return [
        f"lacks the {scope_names(requirement)} scope: {requirement.without}"
        for requirement in SCOPE_REQUIREMENTS
        if scopes.isdisjoint(requirement.any_of)
    ]


def unmet_write_scope(
    granted: str, categories: Sequence[CategoryKey]
) -> WriteScopeShortfall | None:
    """The first row of :data:`WRITE_SCOPE_REQUIREMENTS` some category misses.

    ``granted`` is the ``X-OAuth-Scopes`` value, as for :func:`scope_warnings`;
    ``categories`` are the categories the run selected. A category holding its
    :data:`PARTIAL_WRITE_SCOPES` misses the row all the same, but can still
    write, so it alone never blocks an apply.
    """
    scopes = _granted_scopes(granted)
    for requirement in WRITE_SCOPE_REQUIREMENTS:
        unmet = tuple(
            key for key in categories if scopes.isdisjoint(requirement.any_of)
        )
        if not unmet:
            continue
        partly = {
            key: extra.leaves
            for key in unmet
            if (extra := PARTIAL_WRITE_SCOPES.get(key))
            and not scopes.isdisjoint(extra.scopes)
        }
        writable = len(categories) - len(unmet) + len(partly)
        return WriteScopeShortfall(
            requirement, unmet, partial=writable > 0, partly=partly
        )
    return None


def scope_names(requirement: ScopeRequirement) -> str:
    """The requirement's scopes, quoted and joined with "or"."""
    return " or ".join(f"'{scope}'" for scope in requirement.any_of)


def _granted_scopes(granted: str) -> set[str]:
    return {part.strip() for part in granted.split(",") if part.strip()}


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
