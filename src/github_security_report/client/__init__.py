# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Async GitHub transport: hybrid REST + GraphQL.

Implements the Phase 0 strategy: prefer org-bulk alert sweeps, fall back to
per-repo enabled-probes, with bounded concurrency and backoff that honours
``Retry-After`` and secondary rate limits. Methods return raw parsed JSON (and
HTTP status where the status itself is the signal, e.g. 404 = feature disabled).
See ``docs/BRIEF.md`` sections 9, 13 and ``docs/phase0-findings.md``.

The implementation is split across ``endpoints`` (environment-resolved API URLs
and the shared retry/backoff policy), ``queries`` (GraphQL documents),
``parsers`` (pure header/node parsing), ``transport`` (connection lifecycle and
the retrying request primitives), ``org_reads`` (the reads issued once per
organisation), ``reads`` (the per-repository reads) and ``writes`` (the
remediation writes plus the public :class:`GitHubClient`). This module
re-exports the public surface, so importing from
``github_security_report.client`` is unchanged.
"""

from __future__ import annotations

from github_security_report.client.endpoints import (
    _SCORECARD_DEFAULT,
    API_BACKOFF_FACTOR,
    API_BACKOFF_INITIAL_SECONDS,
    API_DIAGNOSTIC_DNS_TIMEOUT_SECONDS,
    API_MAX_RETRIES,
    API_MAX_TOTAL_WAIT_SECONDS,
    BULK_KINDS,
    GITHUB_API,
    GRAPHQL_API,
    SCORECARD_API,
    _https_endpoint,
)
from github_security_report.client.org_reads import OrgReadClient
from github_security_report.client.parsers import (
    _last_published,
    _next_page_url,
    _parse_iso,
    _parse_repo_node,
    _parse_retry_after,
    _release_refs,
    _tag_committed_date,
)
from github_security_report.client.queries import (
    _CODE_SCANNING_SIGNAL_TOOLS,
    _DEPENDABOT_ENABLED_QUERY,
    _REPO_GRAPH_FRAGMENT,
)
from github_security_report.client.reads import ReadClient
from github_security_report.client.transport import (
    NetworkError,
    Transport,
    _endpoint_diagnostics,
)
from github_security_report.client.writes import GitHubClient

__all__ = [
    "API_BACKOFF_FACTOR",
    "API_BACKOFF_INITIAL_SECONDS",
    "API_DIAGNOSTIC_DNS_TIMEOUT_SECONDS",
    "API_MAX_RETRIES",
    "API_MAX_TOTAL_WAIT_SECONDS",
    "BULK_KINDS",
    "GITHUB_API",
    "GRAPHQL_API",
    "SCORECARD_API",
    "GitHubClient",
    "NetworkError",
    "OrgReadClient",
    "ReadClient",
    "Transport",
    "_CODE_SCANNING_SIGNAL_TOOLS",
    "_DEPENDABOT_ENABLED_QUERY",
    "_REPO_GRAPH_FRAGMENT",
    "_SCORECARD_DEFAULT",
    "_endpoint_diagnostics",
    "_https_endpoint",
    "_last_published",
    "_next_page_url",
    "_parse_iso",
    "_parse_repo_node",
    "_parse_retry_after",
    "_release_refs",
    "_tag_committed_date",
]
