# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Org-mode orchestration: gather, classify, and aggregate.

Ties the transport (:mod:`client`), scoping (:mod:`scope`), classification
(:mod:`classify`) and aggregation (:mod:`report`) together for a single
organisation, following the Phase 0 strategy: one org-bulk sweep per signal,
then bounded per-repo enabled-probes. Accepts any object satisfying the client
protocol so it is testable without a live network.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import logging
from collections import defaultdict
from typing import Protocol

from github_security_report import scope
from github_security_report.classify import RepoFacts, classify_repo
from github_security_report.config import OrgConfig, ReportConfig
from github_security_report.models import Repo, RepoSignal
from github_security_report.report import OrgReport, build_org_report

log = logging.getLogger(__name__)

# Per-repo probe tasks are created in batches of this size so very large orgs
# do not allocate every task at once (HTTP concurrency is bounded separately by
# the client semaphore).
_REPO_BATCH = 50


class ClientProtocol(Protocol):
    """The subset of :class:`client.GitHubClient` that orchestration needs."""

    async def list_org_repos(self, org: str) -> list[Repo]: ...
    async def org_bulk_alerts(self, org: str, kind: str) -> list[dict]: ...
    async def code_scanning_tools(self, org: str, repo: str) -> tuple[int, set[str]]: ...
    async def secret_scanning_status(self, org: str, repo: str) -> int: ...
    async def dependabot_enabled(self, org: str, repo: str) -> bool | None: ...
    async def scorecard_score(self, org: str, repo: str) -> tuple[int, float | None]: ...


class RepoClientProtocol(Protocol):
    """Extra per-repo methods needed for repo mode."""

    async def get_repo(self, org: str, repo: str) -> Repo | None: ...
    async def code_scanning_tools(self, org: str, repo: str) -> tuple[int, set[str]]: ...
    async def repo_code_scanning_alerts(self, org: str, repo: str) -> tuple[int, list[dict]]: ...
    async def repo_secret_scanning(self, org: str, repo: str) -> tuple[int, int]: ...
    async def dependabot_enabled(self, org: str, repo: str) -> bool | None: ...
    async def repo_dependabot_alerts(self, org: str, repo: str) -> tuple[int, list[dict]]: ...
    async def scorecard_score(self, org: str, repo: str) -> tuple[int, float | None]: ...


def _group_by_repo(alerts: list[dict]) -> dict[str, list[dict]]:
    """Group org-bulk alerts by repository name (each carries ``repository``)."""
    grouped: dict[str, list[dict]] = defaultdict(list)
    for alert in alerts:
        name = (alert.get("repository") or {}).get("name")
        if name:
            grouped[name].append(alert)
    return grouped


async def _facts_for_repo(
    client: ClientProtocol,
    org: str,
    repo: Repo,
    code_scanning: dict[str, list[dict]],
    dependabot: dict[str, list[dict]],
    secret: dict[str, list[dict]],
) -> RepoFacts:
    cs_status, cs_tools = await client.code_scanning_tools(org, repo.name)
    secret_status = await client.secret_scanning_status(org, repo.name)
    dependabot_on = await client.dependabot_enabled(org, repo.name)
    scorecard_status, score = await client.scorecard_score(org, repo.name)
    return RepoFacts(
        repo=repo,
        code_scanning_status=cs_status,
        code_scanning_tools=cs_tools,
        code_scanning_alerts=code_scanning.get(repo.name, []),
        secret_scanning_status=secret_status,
        secret_scanning_open=len(secret.get(repo.name, [])),
        dependabot_enabled=dependabot_on,
        dependabot_alerts=dependabot.get(repo.name, []),
        scorecard_status=scorecard_status,
        scorecard_score=score,
    )


async def collect_org(
    client: ClientProtocol,
    org_cfg: OrgConfig,
    report_cfg: ReportConfig,
    *,
    generated_at: dt.datetime | None = None,
) -> OrgReport:
    """Collect and build the report for one organisation."""
    org = org_cfg.name
    log.info("collecting %s", org)
    repos = await client.list_org_repos(org)
    in_scope = scope.filter_repos(
        repos,
        include_archived=report_cfg.include_archived,
        include_test=report_cfg.include_test,
        exclude=org_cfg.exclude,
    )

    # One org-bulk sweep per signal (concurrent).
    cs_alerts, dep_alerts, secret_alerts = await asyncio.gather(
        client.org_bulk_alerts(org, "code-scanning"),
        client.org_bulk_alerts(org, "dependabot"),
        client.org_bulk_alerts(org, "secret-scanning"),
    )
    code_scanning = _group_by_repo(cs_alerts)
    dependabot = _group_by_repo(dep_alerts)
    secret = _group_by_repo(secret_alerts)

    # Bounded per-repo probes. The client semaphore caps real HTTP concurrency;
    # chunking the gather also bounds task creation so very large orgs
    # (hundreds/thousands of repos) do not allocate every task at once.
    facts: list[RepoFacts] = []
    for start in range(0, len(in_scope), _REPO_BATCH):
        batch = in_scope[start : start + _REPO_BATCH]
        facts.extend(
            await asyncio.gather(
                *(
                    _facts_for_repo(client, org, repo, code_scanning, dependabot, secret)
                    for repo in batch
                )
            )
        )

    signals = [sig for repo_facts in facts for sig in classify_repo(repo_facts)]
    return build_org_report(
        org, signals, repo_count=len(in_scope), generated_at=generated_at
    )


async def collect_repo(
    client: RepoClientProtocol, owner: str, repo_name: str
) -> tuple[Repo | None, list[RepoSignal]]:
    """Collect and classify a single repository (repo mode, ``GITHUB_TOKEN``).

    Uses only per-repo endpoints -- no org-bulk sweep and no org-level scope.
    Returns the repository identity (None if unreadable) and its classified
    signals.
    """
    repo = await client.get_repo(owner, repo_name)
    if repo is None:
        log.error("cannot read %s/%s (check token and permissions)", owner, repo_name)
        return None, []
    cs_status, cs_tools = await client.code_scanning_tools(owner, repo_name)
    # Skip the alerts call when code scanning is disabled/indeterminate.
    cs_alerts: list[dict] = []
    if cs_status == 200:
        _, cs_alerts = await client.repo_code_scanning_alerts(owner, repo_name)
    secret_status, secret_open = await client.repo_secret_scanning(owner, repo_name)
    dependabot_on = await client.dependabot_enabled(owner, repo_name)
    # Only fetch Dependabot alerts when the feature is enabled.
    dependabot_alerts: list[dict] = []
    if dependabot_on:
        _, dependabot_alerts = await client.repo_dependabot_alerts(owner, repo_name)
    scorecard_status, score = await client.scorecard_score(owner, repo_name)
    facts = RepoFacts(
        repo=repo,
        code_scanning_status=cs_status,
        code_scanning_tools=cs_tools,
        code_scanning_alerts=cs_alerts,
        secret_scanning_status=secret_status,
        secret_scanning_open=secret_open,
        dependabot_enabled=dependabot_on,
        dependabot_alerts=dependabot_alerts,
        scorecard_status=scorecard_status,
        scorecard_score=score,
    )
    return repo, classify_repo(facts)
