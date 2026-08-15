# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Endpoint resolution and the shared retry/backoff policy constants.

The endpoint constants are evaluated at import time from the environment, so a
deployment override (e.g. GitHub Enterprise Server) is picked up once, before
any client is constructed.
"""

from __future__ import annotations

import logging
import os

log = logging.getLogger(__name__)

# Deployment endpoints. GitHub Actions exports GITHUB_API_URL and
# GITHUB_GRAPHQL_URL (pointing at the enterprise host on GHES); honouring them
# lets the tool run against GitHub Enterprise Server without code changes.
# aislop-ignore-next-line ai-slop/hardcoded-url -- stable public API default, overridable via SCORECARD_API_URL
_SCORECARD_DEFAULT = "https://api.securityscorecards.dev"


def _https_endpoint(env_var: str, default: str) -> str:
    """Resolve a token-bearing GitHub endpoint from the environment.

    The authenticated client sends the GitHub token on every request, so an
    overridden endpoint must be HTTPS or the token could be leaked in plaintext
    or to an unexpected scheme. A non-HTTPS override is refused (the built-in
    default is used instead) with a warning; an accepted non-default endpoint --
    e.g. a GHES host -- is logged so the target is visible in the run output.
    """
    value = os.environ.get(env_var)
    if value is None:
        return default
    # Normalise copy/paste artefacts (surrounding whitespace, trailing slash)
    # before comparing or validating so a cosmetic variant is not mistaken for
    # a genuine override or wrongly rejected by the scheme check.
    value = value.strip().rstrip("/")
    if not value or value == default:
        return default
    if not value.lower().startswith("https://"):
        log.warning(
            "%s=%r is not an https:// URL; ignoring the override and using %s "
            "so the GitHub token is not sent to an insecure endpoint",
            env_var,
            value,
            default,
        )
        return default
    log.info("%s: using non-default endpoint %s", env_var, value)
    return value


GITHUB_API = _https_endpoint("GITHUB_API_URL", "https://api.github.com")
GRAPHQL_API = _https_endpoint("GITHUB_GRAPHQL_URL", "https://api.github.com/graphql")
SCORECARD_API = os.environ.get("SCORECARD_API_URL", _SCORECARD_DEFAULT)

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
