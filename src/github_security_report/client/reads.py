# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Per-repository GitHub reads: enabled-probes, alerts and posture flags.

:class:`ReadClient` completes the reporting read surface by adding the reads
issued once per repository to the org-scope reads of
:class:`~github_security_report.client.org_reads.OrgReadClient`. Methods return
raw parsed JSON (and HTTP status where the status itself is the signal, e.g.
404 = feature disabled).
"""

from __future__ import annotations

import asyncio
import logging

from github_security_report.client.org_reads import OrgReadClient
from github_security_report.client.parsers import _parse_iso
from github_security_report.client.queries import (
    _CODE_SCANNING_SIGNAL_TOOLS,
    _DEPENDABOT_ENABLED_QUERY,
)
from github_security_report.models import Repo

log = logging.getLogger(__name__)


class ReadClient(OrgReadClient):
    """The reporting reads: org sweeps plus the per-repository probes."""

    # ------------------------------------------------------------------ #
    # Per-repo enabled-probes
    # ------------------------------------------------------------------ #
    async def _analyses_tool_probe(
        self, org: str, repo: str, tool: str
    ) -> tuple[int, bool]:
        """Probe a repo's code-scanning analyses for one tool (status, present).

        A ``per_page=1`` + ``tool_name`` filtered read of the analyses endpoint:
        a definitive, single-request presence test for a SARIF-uploading tool.
        """
        url = f"{self._api_url}/repos/{org}/{repo}/code-scanning/analyses"
        resp = await self._request(
            "GET", url, params={"per_page": 1, "tool_name": tool}
        )
        status = resp.status_code
        if status != 200:
            await resp.aclose()  # unread body would leak a pooled connection
            return status, False
        has_analyses = bool(resp.json())
        await resp.aclose()  # release the connection once the body is read
        return 200, has_analyses

    async def code_scanning_tool_present(self, org: str, repo: str, tool: str) -> bool:
        """Whether ``tool`` has uploaded code-scanning analyses to this repo.

        The lightweight organisation-gating probe: any non-200 (disabled,
        forbidden, indeterminate) simply reports the tool as not present here,
        so a gating sweep degrades to "no evidence" rather than erroring.
        """
        status, present = await self._analyses_tool_probe(org, repo, tool)
        return status == 200 and present

    async def code_scanning_tools(
        self, org: str, repo: str, tools: tuple[str, ...] | None = None
    ) -> tuple[int, set[str]]:
        """Return (status, enabled signal tool names) from code-scanning analyses.

        Each tool in ``tools`` (default: every signal tool) is probed with the
        analyses ``tool_name`` filter, a definitive presence test that does not
        depend on how many analyses a busy repo has accumulated (the previous
        page-by-page scan could miss a low-frequency tool past its page cap and
        wrongly nag it). The first probe's status is authoritative for the
        endpoint (404 = code scanning disabled, 403 = forbidden, 5xx/0 =
        indeterminate); a later per-tool probe that fails is skipped (its tool
        goes undetected for this run) rather than discarding the whole result.
        Callers pass a subset when organisation gating has already ruled some
        tools out, saving one request per repo per skipped tool.
        """
        probe_tools = tools if tools is not None else _CODE_SCANNING_SIGNAL_TOOLS
        if not probe_tools:
            return 200, set()

        first_tool, *rest = probe_tools
        status, has = await self._analyses_tool_probe(org, repo, first_tool)
        if status != 200:
            # The first probe's status is authoritative for the endpoint
            # (404 = disabled, 403 = forbidden, 5xx/0 = indeterminate).
            return status, set()
        tools_found: set[str] = {first_tool} if has else set()
        # The endpoint is reachable; probe the remaining tools concurrently. A
        # later probe that fails just leaves its tool undetected for this run.
        results = await asyncio.gather(
            *(self._analyses_tool_probe(org, repo, tool) for tool in rest)
        )
        tools_found.update(
            tool
            for tool, (st, hit) in zip(rest, results, strict=True)
            if st == 200 and hit
        )
        return 200, tools_found

    async def secret_scanning_status(self, org: str, repo: str) -> int:
        """HTTP status of the secret-scanning alerts endpoint (404 = disabled)."""
        resp = await self._request(
            "GET",
            f"{self._api_url}/repos/{org}/{repo}/secret-scanning/alerts",
            params={"per_page": 1, "state": "open"},
        )
        status = int(resp.status_code)
        await resp.aclose()  # only the status is needed; release the connection
        return status

    async def dependabot_enabled(self, org: str, repo: str) -> bool | None:
        """Whether Dependabot alerts are enabled (None when indeterminate)."""
        resp = await self._request(
            "POST",
            self._graphql_url,
            json={
                "query": _DEPENDABOT_ENABLED_QUERY,
                "variables": {"owner": org, "name": repo},
            },
        )
        if resp.status_code != 200:
            await resp.aclose()  # unread body would leak a pooled connection
            return None
        node = (resp.json().get("data") or {}).get("repository")
        await resp.aclose()  # release the connection once the body is read
        if not node:
            return None
        return bool(node.get("hasVulnerabilityAlertsEnabled"))

    async def scorecard_score(self, org: str, repo: str) -> tuple[int, float | None]:
        """External OpenSSF Scorecard aggregate score (status, score|None).

        Transport failures to this third-party API are handled centrally by
        ``_request`` (which returns an indeterminate 503), so a network blip
        degrades the Scorecard signal rather than aborting the run.
        """
        url = f"{self._scorecard_url}/projects/github.com/{org}/{repo}"
        resp = await self._request("GET", url, client=self._ext_client)
        if resp.status_code != 200:
            status = resp.status_code
            await resp.aclose()  # unread body would leak a pooled connection
            return status, None
        score = resp.json().get("score")
        await resp.aclose()  # release the connection once the body is read
        return 200, score

    async def repo_branch_rules(
        self, org: str, repo: str, branch: str
    ) -> tuple[int, list[dict]]:
        """Effective branch rules for a repo (includes inherited org rulesets)."""
        resp = await self._request(
            "GET", f"{self._api_url}/repos/{org}/{repo}/rules/branches/{branch}"
        )
        if resp.status_code != 200:
            status = resp.status_code
            await resp.aclose()  # unread body would leak a pooled connection
            return status, []
        rules = list(resp.json())
        await resp.aclose()  # release the connection once the body is read
        return 200, rules

    # ------------------------------------------------------------------ #
    # Per-repo data (repo mode)
    # ------------------------------------------------------------------ #
    async def get_repo(self, org: str, repo: str) -> Repo | None:
        """Fetch a single repository's identity."""
        resp = await self._request("GET", f"{self._api_url}/repos/{org}/{repo}")
        if resp.status_code != 200:
            await resp.aclose()  # unread body would leak a pooled connection
            return None
        raw = resp.json()
        await resp.aclose()  # release the connection once the body is read
        return Repo(
            name=raw["name"],
            full_name=raw["full_name"],
            html_url=raw["html_url"],
            archived=raw.get("archived", False),
            fork=raw.get("fork", False),
            is_template=raw.get("is_template", False),
            private=raw.get("private", False),
            default_branch=raw.get("default_branch", "main"),
            created_at=_parse_iso(raw.get("created_at")),
        )

    async def repo_code_scanning_alerts(
        self, org: str, repo: str
    ) -> tuple[int, list[dict]]:
        """Open code-scanning alerts for one repo (status, alerts)."""
        return await self._get_list(
            f"{self._api_url}/repos/{org}/{repo}/code-scanning/alerts", state="open"
        )

    async def repo_secret_scanning(self, org: str, repo: str) -> tuple[int, int]:
        """Open secret-scanning alert (status, open count) for one repo."""
        status, items = await self._get_list(
            f"{self._api_url}/repos/{org}/{repo}/secret-scanning/alerts", state="open"
        )
        return status, len(items)

    async def repo_dependabot_alerts(
        self, org: str, repo: str
    ) -> tuple[int, list[dict]]:
        """Open Dependabot alerts for one repo (status, alerts)."""
        return await self._get_list(
            f"{self._api_url}/repos/{org}/{repo}/dependabot/alerts", state="open"
        )

    # ------------------------------------------------------------------ #
    # Dependabot posture + release/tag freshness (extra sections)
    # ------------------------------------------------------------------ #
    async def automated_security_fixes(self, org: str, repo: str) -> bool | None:
        """Whether Dependabot security updates are enabled (None = indeterminate).

        ``GET .../automated-security-fixes`` returns ``{enabled, paused}`` (200)
        or 404 when the feature is disabled; any other status is indeterminate.
        """
        resp = await self._request(
            "GET", f"{self._api_url}/repos/{org}/{repo}/automated-security-fixes"
        )
        status = resp.status_code
        if status == 404:
            await resp.aclose()  # release the connection; 404 = disabled
            return False
        if status != 200:
            await resp.aclose()  # unread body would leak a pooled connection
            return None
        data = resp.json()
        await resp.aclose()  # release the connection once the body is read
        return bool(data.get("enabled"))

    async def private_vulnerability_reporting(self, org: str, repo: str) -> bool | None:
        """Whether private vulnerability reporting is enabled (None = unknown).

        ``GET .../private-vulnerability-reporting`` returns ``{enabled}`` (200);
        any other status (e.g. 422) is treated as indeterminate. A classic PAT
        needs the ``repo`` scope (``public_repo`` suffices for public repos);
        fine-grained tokens and Apps need only ``Metadata: read``. Org mode
        already grants ``repo``, so it works with the same token used for the
        other read probes -- but GitHub exposes no org-wide or GraphQL
        equivalent, so it is one REST call per repository, gathered alongside
        the automated-security-fixes probe.
        """
        resp = await self._request(
            "GET",
            f"{self._api_url}/repos/{org}/{repo}/private-vulnerability-reporting",
        )
        status = resp.status_code
        if status != 200:
            await resp.aclose()  # unread body would leak a pooled connection
            return None
        data = resp.json()
        await resp.aclose()  # release the connection once the body is read
        return bool(data.get("enabled"))
