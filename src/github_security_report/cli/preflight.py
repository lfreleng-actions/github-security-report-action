# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Checks a run makes of its tokens before it collects anything.

Org-mode ``report`` and ``remediate`` both run them, for every configured
organisation before the first one is collected, so a run that cannot produce
a truthful report stops before it spends a request on collection:

* every organisation's token is set (:func:`resolve_tokens`);
* each distinct token is probed once through ``GET /rate_limit``, which does
  not count against the rate limit: a spent core or GraphQL budget aborts, and
  a classic PAT's granted scopes and expiry date are read for warnings;
* for ``remediate``, a classic PAT's scopes are checked against what its
  writes need: a dry run warns, and an apply that could write nothing aborts;
* each organisation's repository listing is readable, one ``per_page=1``
  page, so a mistyped name or a token that cannot see the organisation aborts
  instead of rendering an empty, confidently clean report.

A check that fails returns the process exit code for the caller to return;
the message has been printed in red by then. A run that passes, with nothing
to warn about, prints nothing.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import logging
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from rich.console import Console

from github_security_report import config
from github_security_report.categories import CategoryKey
from github_security_report.cli.preflight_messages import (
    error_message,
    listing_message,
    names_a_rate_limit,
    network_message,
    rate_limit_message,
    reset_text,
    spent_budget_headers,
)
from github_security_report.cli.token_scopes import (
    SCOPE_REQUIREMENTS as SCOPE_REQUIREMENTS,
)
from github_security_report.cli.token_scopes import (
    expiry_warning,
    unmet_write_scope,
)
from github_security_report.cli.token_scopes import (
    scope_warnings as scope_warnings,
)
from github_security_report.client import (
    AuthError,
    GitHubClient,
    NetworkError,
    RateLimitError,
)
from github_security_report.client.bodies import _read_body
from github_security_report.client.repo_parser import _parse_repo_or_none
from github_security_report.client.transport import Transport
from github_security_report.config import Config

log = logging.getLogger(__name__)

# Exit codes for the two aborts only the pre-flight makes; 2, 3 and 4 keep
# their meanings (usage, unusable API, rejected credentials).
EXIT_LISTING_UNREADABLE = 5
EXIT_RATE_LIMITED = 6
# An apply whose classic token holds no scope to write with is a usage error:
# the run was asked for work this token can never do.
EXIT_CANNOT_WRITE = 2

# The probe is best-effort, so it gets one short attempt: a slow or failing
# /rate_limit must not hold the run up on the retry schedule meant for reads
# the report depends on.
PROBE_TIMEOUT_SECONDS = 10.0

_REPO_IDENTITY = ("name", "full_name", "html_url")


class PreflightAbort(Exception):
    """A pre-flight check that stops the run, with its exit code."""

    def __init__(self, message: str, code: int) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class TokenUse:
    """One distinct token, where it came from, and the orgs it reads."""

    token: str
    label: str
    orgs: tuple[str, ...]


def resolve_tokens(cfg: Config, console: Console) -> list[str] | None:
    """Every organisation's token, in configuration order, or None if any is unset.

    Every missing token is reported together, so an operator fixes them all
    in one pass rather than one run at a time.
    """
    tokens: list[str] = []
    missing: list[str] = []
    for org_cfg in cfg.organizations:
        token = config.resolve_token(org_cfg)
        if token:
            tokens.append(token)
        else:
            missing.append(f"No token in ${org_cfg.token_env} for {org_cfg.name}")
    if missing:
        # markup=False: the variable and organisation names come from the
        # configuration and are printed literally.
        for line in missing:
            console.print(line, style="red", markup=False)
        return None
    return tokens


def org_token_uses(cfg: Config, tokens: Sequence[str]) -> list[TokenUse]:
    """Group the configured organisations by the token each one reads with."""
    labels: dict[str, list[str]] = {}
    orgs: dict[str, list[str]] = {}
    for org_cfg, token in zip(cfg.organizations, tokens, strict=True):
        env = f"${org_cfg.token_env}"
        if env not in labels.setdefault(token, []):
            labels[token].append(env)
        if org_cfg.name not in orgs.setdefault(token, []):
            orgs[token].append(org_cfg.name)
    return [
        TokenUse(token, f"the token in {', '.join(labels[token])}", tuple(orgs[token]))
        for token in labels
    ]


async def check_org_run(cfg: Config, tokens: Sequence[str], console: Console) -> int:
    """Run the pre-flight for an org-mode report; 0 to proceed, else the exit code.

    One short-lived client per distinct token, apart from the collection's
    own, so the collection's request figures stay its own.
    """
    try:
        for use in org_token_uses(cfg, tokens):
            async with GitHubClient(use.token) as client:
                await _check_token(client, use.label, use.orgs)
    except PreflightAbort as exc:
        return _abort(console, exc)
    return 0


async def check_remediate_run(
    client: Transport,
    orgs: Iterable[str],
    console: Console,
    *,
    token_envs: Sequence[str],
    apply: bool,
    categories: Sequence[CategoryKey],
) -> int:
    """Run the pre-flight for ``remediate``'s one token; 0 to proceed, else the code.

    ``token_envs`` names the variables holding the token, so a rejection or a
    warning says which token to rotate, as an org-mode report does. ``apply``
    says whether the run writes, which decides whether a classic token that
    cannot write aborts or only warns, and ``categories`` are the ones the run
    selected, whose writes that check weighs (:func:`check_write_scopes`).
    """
    label = f"the token in {', '.join(f'${env}' for env in token_envs)}"
    try:
        await _check_token(
            client, label, dict.fromkeys(orgs), writes=(apply, categories)
        )
    except PreflightAbort as exc:
        return _abort(console, exc)
    return 0


async def _check_token(
    client: Transport,
    label: str,
    orgs: Iterable[str],
    *,
    writes: tuple[bool, Sequence[CategoryKey]] | None = None,
) -> None:
    """Probe one token and read each of its organisations' listings.

    A 401 still raises :class:`AuthError` (exit 4), now naming the token, so a
    run with several tokens says which one to rotate. ``writes`` is ``None``
    for a report, which writes nothing; for ``remediate`` it is whether the
    run writes and the categories it selected, and a classic token's write
    scopes are checked before any listing is read.
    """
    try:
        granted = await probe_token(client, label)
        if writes is not None and granted is not None:
            apply, categories = writes
            check_write_scopes(granted, label, categories, apply=apply)
        for org in orgs:
            await check_listing(client, org)
    except AuthError as exc:
        raise AuthError(f"{exc}\n  rejected: {label}") from exc


def _abort(console: Console, exc: PreflightAbort) -> int:
    """Print an abort like the network and credential ones, and return its code."""
    console.print(str(exc), style="red", markup=False)
    return exc.code


# --------------------------------------------------------------------------- #
# Token probe
# --------------------------------------------------------------------------- #
async def probe_token(
    client: Transport, label: str, *, now: dt.datetime | None = None
) -> str | None:
    """Read what ``GET /rate_limit`` says about a token, warning or aborting.

    Returns the token's ``X-OAuth-Scopes`` value, or ``None`` when it sent
    none (not a classic PAT) or the probe was skipped: either way its scopes
    cannot be told.

    A ``401`` raises :class:`AuthError` from the transport, as for any read,
    and a spent budget :class:`RateLimitError` (exit ``6``).
    Anything else the probe cannot use skips its checks, logged at DEBUG: the
    probe's own failure never stops a run. GitHub Enterprise Server answers
    ``404`` here when rate limiting is off. It is made once, never retried, and
    bounded by :data:`PROBE_TIMEOUT_SECONDS` per operation and in total.
    """
    url = f"{client._api_url}/rate_limit"
    try:
        async with asyncio.timeout(PROBE_TIMEOUT_SECONDS):
            resp = await client._request(
                "GET", url, quiet=True, max_retries=0, timeout=PROBE_TIMEOUT_SECONDS
            )
    except (AuthError, RateLimitError):
        raise
    except (NetworkError, TimeoutError) as exc:
        log.debug("token probe skipped: %s", str(exc) or "no answer in time")
        return None
    if resp.status_code != 200:
        await resp.aclose()
        log.debug("token probe skipped: GET %s answered %d", url, resp.status_code)
        return None
    headers = resp.headers
    body = await _read_body(resp, dict, quiet=True)
    if body is None:
        log.debug("token probe skipped: GET %s answered an unusable body", url)
        return None
    moment = now if now is not None else dt.datetime.now(dt.UTC)
    _check_rate_limit(body, label, moment)
    granted: str | None = headers.get("x-oauth-scopes")
    if granted is not None:
        for warning in scope_warnings(granted):
            log.warning("%s %s", _capitalise(label), warning)
    expiry = expiry_warning(
        headers.get("github-authentication-token-expiration"), moment
    )
    if expiry is not None:
        log.warning("%s %s", _capitalise(label), expiry)
    return granted


def _capitalise(text: str) -> str:
    return text[:1].upper() + text[1:]


def _check_rate_limit(body: dict, label: str, now: dt.datetime) -> None:
    """Abort when the core or GraphQL budget has nothing left."""
    resources = body.get("resources")
    if not isinstance(resources, dict):
        log.debug("token probe: no resources in the rate-limit body")
        return
    spent: list[str] = []
    for name in ("core", "graphql"):
        resource = resources.get(name)
        if not isinstance(resource, dict):
            continue
        remaining = resource.get("remaining")
        # type() rather than isinstance(): JSON false is not a count.
        if type(remaining) is int and remaining == 0:
            spent.append(f"  {name}: {reset_text(resource.get('reset'), now)}")
    if spent:
        raise PreflightAbort(
            "Rate limit exhausted: GitHub reports no requests remaining for "
            f"{label}; aborting because every read would be degraded to "
            "unknown and the report would read as 'no data' rather than as "
            "a failure.\n" + "\n".join(spent) + "\n  Wait for the reset, or run "
            "with a different token.",
            EXIT_RATE_LIMITED,
        )


def check_write_scopes(
    granted: str, label: str, categories: Sequence[CategoryKey], *, apply: bool
) -> None:
    """Warn, or abort an apply, when a classic PAT cannot make remediate's writes.

    See :func:`~github_security_report.cli.token_scopes.unmet_write_scope`;
    only a shortfall that blocks every selected category aborts an apply.
    """
    shortfall = unmet_write_scope(granted, categories)
    if shortfall is None:
        return
    if apply and shortfall.blocks_apply:
        raise PreflightAbort(
            f"{_capitalise(label)} {shortfall.abort_message}", EXIT_CANNOT_WRITE
        )
    log.warning("%s %s", _capitalise(label), shortfall.warning)


# --------------------------------------------------------------------------- #
# Repository listing
# --------------------------------------------------------------------------- #
async def check_listing(client: Transport, org: str) -> None:
    """Read the first page of ``org``'s repository listing, or abort.

    A readable listing with no repositories is fine; one the token cannot read
    is not, because the run would otherwise report on nothing and call it a
    clean report. An entry without a repository's identity is unreadable, as
    it is to the collection's own listing, and a page that spent the last
    request of the rate limit leaves the collection nothing to read with.
    """
    url = f"{client._api_url}/orgs/{org}/repos"
    try:
        resp = await client._request("GET", url, params={"type": "all", "per_page": 1})
    except RateLimitError as exc:
        raise PreflightAbort(
            rate_limit_message(
                org,
                f"answered HTTP {exc.status} after the retry budget",
                url,
                spent_budget_headers(exc),
            ),
            EXIT_RATE_LIMITED,
        ) from exc
    status = resp.status_code
    headers = resp.headers
    if status == 200:
        body = await _read_body(resp, list)
        if body is None:
            raise PreflightAbort(network_message(url, "an unusable body (HTTP 200)"), 3)
        if not all(_is_repository(raw) for raw in body):
            raise PreflightAbort(
                network_message(url, "an entry that is not a repository (HTTP 200)"),
                3,
            )
        if headers.get("x-ratelimit-remaining") == "0":
            raise PreflightAbort(
                rate_limit_message(
                    org, "spent the last request of the rate limit", url, headers
                ),
                EXIT_RATE_LIMITED,
            )
        return
    if status == 429 or (
        status == 403
        and ("retry-after" in headers or headers.get("x-ratelimit-remaining") == "0")
    ):
        await resp.aclose()
        raise PreflightAbort(
            rate_limit_message(
                org, f"answered HTTP {status} after the retry budget", url, headers
            ),
            EXIT_RATE_LIMITED,
        )
    if status == 403 and names_a_rate_limit(await error_message(resp)):
        # A secondary limit can come with neither header, named only in the
        # message; it is not a permission problem, so exit 5 would mislead.
        raise PreflightAbort(
            rate_limit_message(
                org, "answered HTTP 403: a secondary rate limit", url, headers
            ),
            EXIT_RATE_LIMITED,
        )
    await resp.aclose()
    if status in (403, 404):
        raise PreflightAbort(
            listing_message(org, status, url, headers.get("x-github-sso")),
            EXIT_LISTING_UNREADABLE,
        )
    raise PreflightAbort(network_message(url, f"HTTP {status}"), 3)


def _is_repository(raw: object) -> bool:
    """Whether a listing entry carries a repository's identity, none of it blank.

    Stricter than the collection's :func:`_parse_repo_or_none`, which accepts an
    empty string: such an entry would be skipped there as an empty repository,
    and the run would report on nothing and read as clean.
    """
    return (
        isinstance(raw, dict)
        and _parse_repo_or_none(raw) is not None
        and all(raw[key].strip() for key in _REPO_IDENTITY)
    )
