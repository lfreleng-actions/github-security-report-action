# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Code-scanning analyses reads, served from one cached page per repository.

Three questions are asked of a repository's code-scanning analyses: which
SARIF-uploading tools have run (the enablement probes), whether one tool has
run anywhere in a sample (organisation gating), and every CodeQL configuration
on the default branch (scan health). Each used to issue its own filtered
requests -- four ``tool_name`` probes per repository, a sampled probe per
gated signal, and a full filtered walk -- so a run spent a third of its
requests re-reading the same short histories.

:class:`AnalysesReads` reads the newest hundred analyses once per repository,
unfiltered, and keeps them for the client's lifetime. A history that fits in
that page answers all three questions outright. A longer one still answers
the first two for every tool it names, and only the tools it does not name,
and the CodeQL walk, cost further requests.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Mapping
from dataclasses import dataclass

from github_security_report.client.codeql_parsers import (
    latest_codeql_configurations,
)
from github_security_report.client.org_reads import OrgReadClient
from github_security_report.client.parsers import _next_page_url
from github_security_report.client.queries import _CODE_SCANNING_SIGNAL_TOOLS
from github_security_report.codeql.facts import CodeQLConfiguration
from github_security_report.models import CODE_SCANNING_TOOLS, SignalType

log = logging.getLogger(__name__)

# Analyses per page, GitHub's maximum. A page holding this many, or linking
# to a next one, may hide older analyses the page does not show.
_ANALYSES_PAGE = 100

# The fields the readers of a cached analysis consult, so a page kept for the
# run costs a few hundred bytes per entry rather than the whole payload.
_KEPT_FIELDS = (
    "id",
    "ref",
    "category",
    "created_at",
    "error",
    "analysis_key",
    "environment",
)


@dataclass(frozen=True)
class AnalysesPage:
    """The newest analyses of one repository, unfiltered.

    ``status`` is the read's HTTP status, authoritative for the endpoint (404
    is code scanning disabled, 403 forbidden); ``analyses`` the entries, each
    reduced to the fields consulted later plus a ``tool`` name; ``complete``
    whether the page holds the repository's whole history, which is when a
    tool's absence from it means the tool never ran.
    """

    status: int
    analyses: tuple[Mapping[str, object], ...] = ()
    complete: bool = False

    @property
    def tools(self) -> frozenset[str]:
        """Every tool name the page's analyses carry."""
        return frozenset(
            name
            for analysis in self.analyses
            if isinstance(name := analysis.get("tool"), str)
        )


def _compact(raw: object) -> Mapping[str, object] | None:
    """One analysis reduced to the fields kept, or ``None`` for a non-object."""
    if not isinstance(raw, dict):
        return None
    tool = raw.get("tool")
    name = tool.get("name") if isinstance(tool, dict) else None
    kept: dict[str, object] = {field: raw.get(field) for field in _KEPT_FIELDS}
    kept["tool"] = name if isinstance(name, str) else None
    return kept


class AnalysesReads(OrgReadClient):
    """The code-scanning analyses reads over the org-scope reads."""

    # Pending or finished first-page reads by (org, repo). Tasks rather than
    # results, so two callers asking at once share one request; the dict is
    # created on first use because the base class owns __init__.
    _analyses_pages: dict[tuple[str, str], asyncio.Task[AnalysesPage]]

    def _analyses_url(self, org: str, repo: str) -> str:
        return f"{self._api_url}/repos/{org}/{repo}/code-scanning/analyses"

    async def _read_analyses_page(self, org: str, repo: str) -> AnalysesPage:
        resp = await self._request(
            "GET", self._analyses_url(org, repo), params={"per_page": _ANALYSES_PAGE}
        )
        status = resp.status_code
        if status != 200:
            await resp.aclose()  # unread body would leak a pooled connection
            return AnalysesPage(status)
        body = resp.json()
        more = _next_page_url(resp) is not None
        await resp.aclose()  # release the connection once body/links are read
        entries = tuple(
            kept
            for raw in (body if isinstance(body, list) else [])
            if (kept := _compact(raw)) is not None
        )
        return AnalysesPage(
            200, entries, complete=not more and len(entries) < _ANALYSES_PAGE
        )

    async def analyses_page(self, org: str, repo: str) -> AnalysesPage:
        """The repository's newest analyses, read once per client."""
        try:
            pages = self._analyses_pages
        except AttributeError:
            pages = self._analyses_pages = {}
        key = (org, repo)
        if key not in pages:
            pages[key] = asyncio.create_task(self._read_analyses_page(org, repo))
        return await pages[key]

    async def _analyses_tool_probe(
        self, org: str, repo: str, tool: str
    ) -> tuple[int, bool]:
        """Probe a repo's analyses for one tool: ``(status, present)``.

        A ``per_page=1`` + ``tool_name`` filtered read, the definitive
        presence test for a tool the cached page could not rule in or out.
        """
        resp = await self._request(
            "GET",
            self._analyses_url(org, repo),
            params={"per_page": 1, "tool_name": tool},
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
        page = await self.analyses_page(org, repo)
        if page.status != 200:
            return False
        if tool in page.tools or page.complete:
            return tool in page.tools
        status, present = await self._analyses_tool_probe(org, repo, tool)
        return status == 200 and present

    async def code_scanning_tools(
        self, org: str, repo: str, tools: tuple[str, ...] | None = None
    ) -> tuple[int, set[str]]:
        """Return (status, enabled signal tool names) from code-scanning analyses.

        The cached page's status is authoritative for the endpoint (404 = code
        scanning disabled, 403 = forbidden, 5xx/0 = indeterminate). Every tool
        the page names is present; a tool it does not name is absent when the
        page is the whole history, and otherwise probed with the ``tool_name``
        filter, which does not depend on how many analyses a busy repository
        has accumulated. A probe that fails leaves its tool undetected for
        this run rather than discarding the whole result. Callers pass a
        subset when organisation gating has already ruled some tools out.
        """
        probe_tools = tools if tools is not None else _CODE_SCANNING_SIGNAL_TOOLS
        if not probe_tools:
            return 200, set()
        page = await self.analyses_page(org, repo)
        if page.status != 200:
            return page.status, set()
        found = {tool for tool in probe_tools if tool in page.tools}
        missing = [tool for tool in probe_tools if tool not in found]
        if page.complete or not missing:
            return 200, found
        results = await asyncio.gather(
            *(self._analyses_tool_probe(org, repo, tool) for tool in missing)
        )
        found.update(
            tool
            for tool, (status, hit) in zip(missing, results, strict=True)
            if status == 200 and hit
        )
        return 200, found

    async def codeql_configurations(
        self, org: str, repo: str, branch: str
    ) -> tuple[int, tuple[CodeQLConfiguration, ...]]:
        """Every CodeQL configuration on ``branch``, as of its latest scan.

        A repository whose whole history fits the cached page is answered
        from it, filtered to CodeQL analyses of the branch. Otherwise the
        history is walked with the tool and ref filters: a stale
        configuration's last upload is by definition buried beneath the live
        ones' newer analyses, and stopping early would miss exactly the
        configurations this read exists to find. A later page failing returns
        that status with the partial result, which callers treat as unknown.
        """
        codeql = CODE_SCANNING_TOOLS[SignalType.CODEQL]
        ref = f"refs/heads/{branch}"
        page = await self.analyses_page(org, repo)
        if page.status != 200:
            return page.status, ()
        if page.complete:
            own = [
                a
                for a in page.analyses
                if a.get("tool") == codeql and a.get("ref") == ref
            ]
            return 200, latest_codeql_configurations(own)
        status, analyses = await self._get_list(
            self._analyses_url(org, repo), tool_name=codeql, ref=ref
        )
        return status, latest_codeql_configurations(analyses)
