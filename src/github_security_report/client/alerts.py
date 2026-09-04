# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""The org-bulk alert sweeps, and the two-pass secret-scanning read.

:class:`AlertReads` owns the alert reads shared across scopes: one org-bulk
sweep per signal family, and the secret-scanning read that both the org sweep
and the per-repository probe route through.

Secret scanning needs that shared implementation because GitHub's alerts
endpoints return only its *default* provider patterns unless ``secret_type``
names something else, and answer ``200 []`` -- not an error -- for anything
they were not asked about. A single, unfiltered sweep therefore reports a
repository leaking a private key or a password as clean, and no downstream
status handling can tell that empty result from a genuine one. The sweep is
issued twice instead, once unfiltered and once naming the patterns GitHub
leaves out, and the two are merged. The org-bulk and per-repo alert endpoints
take the same parameters, so one implementation covers both scopes.

See :mod:`github_security_report.secret_patterns` for the pattern vocabulary
and why the list has to be checked at runtime.
"""

from __future__ import annotations

import asyncio
import logging
from typing import NamedTuple

from github_security_report.client.endpoints import BULK_KINDS
from github_security_report.client.transport import AuthError, NetworkError, Transport
from github_security_report.secret_patterns import (
    GENERIC_SECRET_TYPES,
    PATTERN_CONFIG_PATH,
    SECRET_TYPE_FILTER,
    merge_alerts,
    unknown_generic_slugs,
)

log = logging.getLogger(__name__)

_SUPPORTED_PATTERNS_DOC = (
    "https://docs.github.com/en/code-security/secret-scanning/introduction/"
    "supported-secret-scanning-patterns"
)


class SecretScanningSweep(NamedTuple):
    """One secret-scanning read: its two distinct statuses, and the alerts.

    The two halves answer two different questions, and collapsing them into one
    status loses an alert the report should have shown.

    ``endpoint_status`` answers "is secret scanning on, and readable here?"
    (404 = disabled, 403 = forbidden). A 200 from *either* half settles it,
    because both halves call the same endpoint with the same credentials, and
    so does holding any alert at all: an alert can only have come out of a 200
    response body, whatever status the read finished on. Only when neither
    half answered and neither collected anything is the unfiltered half's
    status reported, being the plain read's own verdict.

    ``read_status`` answers "was the alert list complete?" and is non-200 when
    either half failed, so a partial sweep can never be reported as clean.

    Repository scope needs them apart. It has no separate enablement probe, so
    one status previously did both jobs -- and a forbidden second half would
    then classify a repository whose *first* half returned alerts as UNKNOWN
    rather than as an offender, hiding a leak behind a permissions error.
    """

    endpoint_status: int
    read_status: int
    alerts: list[dict]


class AlertReads(Transport):
    """The org-bulk sweeps, plus the secret-scanning read both scopes share."""

    async def org_bulk_alerts(self, org: str, kind: str) -> tuple[int, list[dict]]:
        """Sweep all open alerts of one kind across the org.

        Returns the first-page HTTP status alongside the alerts so callers can
        tell an authoritative empty result (200 ``[]``) apart from an unreadable
        sweep (403/404/5xx), which must never be reported as "clean".

        The secret-scanning sweep is issued twice, because GitHub's default
        alert listing excludes whole pattern categories; see
        :meth:`secret_scanning_alerts`. Org scope probes enablement per
        repository, so only the sweep's read status is of interest here.
        """
        url = f"{self._api_url}/orgs/{org}/{BULK_KINDS[kind]}"
        if kind == "secret-scanning":
            sweep = await self.secret_scanning_alerts(org, url)
            return sweep.read_status, sweep.alerts
        return await self._get_list(url, state="open")

    async def secret_scanning_alerts(self, owner: str, url: str) -> SecretScanningSweep:
        """Open secret-scanning alerts from *every* GitHub pattern category.

        ``url`` is an org-bulk or per-repo alerts endpoint. Two reads are
        merged: one unfiltered (the default provider patterns) and one naming
        the generic and AI-detected patterns, which the API omits unless asked
        for. ``secret_type`` filters rather than adds, so a single request
        cannot cover both -- the default set runs to hundreds of patterns and
        cannot be enumerated in a query string.

        Returns both statuses separately; see :class:`SecretScanningSweep` for
        what each one settles. Whatever the halves collected travels with them
        even when one failed, because positive evidence of a leaked secret is
        actionable from an incomplete read.
        """
        await self._warn_on_unknown_generic_patterns(owner)
        (
            (default_status, default_alerts),
            (explicit_status, explicit_alerts),
        ) = await asyncio.gather(
            self._get_list(url, state="open"),
            self._get_list(url, state="open", secret_type=SECRET_TYPE_FILTER),
        )
        # Only a disagreement about *readability* is worth reporting here. Two
        # halves that failed with different statuses (say 403 and 500) made no
        # pass at all, and the caller already reports a wholly unreadable
        # sweep; claiming one pass succeeded would be wrong.
        if (default_status == 200) != (explicit_status == 200):
            log.warning(
                "secret-scanning sweep of %s completed only one of its two "
                "passes (default patterns -> %s, named patterns -> %s); "
                "reported as unreadable rather than as the successful pass's "
                "answer",
                url,
                default_status,
                explicit_status,
            )
        alerts = merge_alerts(default_alerts, explicit_alerts)
        return SecretScanningSweep(
            # Any alert in hand proves the endpoint was enabled and readable,
            # even when both halves ended on a failing status: a page that
            # fails mid-pagination returns the alerts already collected
            # alongside its status. Without this, a 403 on page two would
            # classify a repository whose page one listed leaked keys as
            # "insufficient permission" instead of as an offender.
            endpoint_status=(
                200
                if default_status == 200 or explicit_status == 200 or alerts
                else default_status
            ),
            # Either half failing makes the alert list incomplete. When both
            # failed, one status still has to be chosen: the unfiltered half's
            # is reported, being the read every caller would have made anyway.
            read_status=default_status if default_status != 200 else explicit_status,
            alerts=alerts,
        )

    async def _warn_on_unknown_generic_patterns(self, owner: str) -> None:
        """Check the generic-pattern list against GitHub's own inventory.

        GitHub answers an unrecognised ``secret_type`` with ``200 []`` rather
        than an error, so a renamed or mistyped slug narrows the sweep straight
        back to the bug the second pass exists to fix -- silently. This check is
        the only thing standing between that hardcoded list and a false "clean".

        Strictly best-effort: a classic PAT reads the inventory with the
        ``read:org`` scope the tool already requires, but a fine-grained token
        needs an optional organisation permission, and ``owner`` may be a user
        account rather than an organisation, so an unreadable check passes
        without comment. Only a *readable* inventory that disowns one of the
        slugs warns. The AI-detected patterns are absent from that inventory
        and go unchecked; see :mod:`github_security_report.secret_patterns`.

        Best-effort includes the transport and the payload: an optional check
        must not be able to abort a run whose real reads would have succeeded,
        so a timeout, a connection failure, or a body that is not valid JSON is
        swallowed and the list used unverified. The read is issued ``quiet``
        for the same reason -- its retry notices drop to DEBUG, so a probe
        nothing depends on cannot fill a healthy run's output with warnings.
        Rejected credentials still abort, because every subsequent read would
        fail the same way and the report would render as "all clean".
        """
        url = f"{self._api_url}/orgs/{owner}/{PATTERN_CONFIG_PATH}"
        try:
            resp = await self._request("GET", url, quiet=True)
        except AuthError:
            raise  # a bad credential condemns the whole run, not just this read
        except NetworkError as exc:
            log.debug(
                "secret-scanning pattern inventory for %s unreachable (%s); "
                "the generic-pattern list is used unverified",
                owner,
                exc,
            )
            return
        if resp.status_code != 200:
            await resp.aclose()  # unread body would leak a pooled connection
            log.debug(
                "secret-scanning pattern inventory for %s unavailable (status "
                "%s); the generic-pattern list is used unverified",
                owner,
                resp.status_code,
            )
            return
        try:
            payload = resp.json()
        except ValueError as exc:
            # A 200 carrying something other than JSON (a proxy error page, a
            # truncated body) tells us nothing about the pattern list, and is
            # not worth failing a security report over.
            log.debug(
                "secret-scanning pattern inventory for %s was not valid JSON "
                "(%s); the generic-pattern list is used unverified",
                owner,
                exc,
            )
            return
        finally:
            await resp.aclose()  # release the connection on either path
        unknown = unknown_generic_slugs(payload)
        if not unknown:
            return
        log.warning(
            "GitHub's secret-scanning pattern inventory for %s does not list %d "
            "of the %d generic patterns this build asks for (%s). GitHub "
            "answers an unrecognised secret_type with an empty result rather "
            "than an error, so secrets matching those patterns would be "
            "reported as clean. Check GENERIC_SECRET_TYPES in "
            "secret_patterns.py against %s",
            owner,
            len(unknown),
            len(GENERIC_SECRET_TYPES),
            ", ".join(unknown),
            _SUPPORTED_PATTERNS_DOC,
        )
