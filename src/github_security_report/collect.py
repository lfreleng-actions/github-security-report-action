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

from github_security_report import rulesets, scope
from github_security_report.classify import RepoFacts, classify_repo
from github_security_report.config import (
    DEFAULT_RULESET_WORKFLOWS,
    OrgConfig,
    ReportConfig,
)
from github_security_report.models import Repo, RepoSignal
from github_security_report.report import OrgReport, build_org_report

log = logging.getLogger(__name__)

# Per-repo probe tasks are created in batches of this size so very large orgs
# do not allocate every task at once (HTTP concurrency is bounded separately by
# the client semaphore).
_REPO_BATCH = 50


class ClientProtocol(Protocol):
    """The subset of :class:`client.GitHubClient` that orchestration needs."""

    async def list_org_repos(self, org: str) -> tuple[int, list[Repo]]: ...
    async def org_bulk_alerts(self, org: str, kind: str) -> tuple[int, list[dict]]: ...
    async def org_workflow_rulesets(self, org: str) -> tuple[int, list[dict]]: ...
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
    async def repo_branch_rules(self, org: str, repo: str, branch: str) -> tuple[int, list[dict]]: ...
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
    ruleset_signals: set[str],
    sweep_status: dict[str, int],
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
        code_scanning_alerts_status=sweep_status["code-scanning"],
        secret_scanning_status=secret_status,
        secret_scanning_open=len(secret.get(repo.name, [])),
        secret_scanning_open_status=sweep_status["secret-scanning"],
        dependabot_enabled=dependabot_on,
        dependabot_alerts=dependabot.get(repo.name, []),
        dependabot_alerts_status=sweep_status["dependabot"],
        scorecard_status=scorecard_status,
        scorecard_score=score,
        ruleset_signals=ruleset_signals,
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
    repos_status, repos = await client.list_org_repos(org)
    if repos_status != 200:
        log.warning(
            "repository listing for org %s is incomplete (status %s); the "
            "report may omit repositories and their findings",
            org,
            repos_status,
        )
    in_scope = scope.filter_repos(
        repos,
        include_archived=report_cfg.include_archived,
        include_test=report_cfg.include_test,
        exclude=org_cfg.exclude,
    )

    # One org-bulk sweep per signal, plus the workflow-driven ruleset coverage
    # (concurrent). Each sweep returns its HTTP status so an unreadable sweep
    # (e.g. 403/5xx) degrades affected signals to UNKNOWN rather than CLEAN.
    # Ruleset coverage degrades gracefully if the token cannot read org
    # rulesets (e.g. 403): repos then fall back to per-repo evidence.
    (
        (cs_status, cs_alerts),
        (dep_status, dep_alerts),
        (secret_status, secret_alerts),
    ), (rs_status, rs_details) = await asyncio.gather(
        asyncio.gather(
            client.org_bulk_alerts(org, "code-scanning"),
            client.org_bulk_alerts(org, "dependabot"),
            client.org_bulk_alerts(org, "secret-scanning"),
        ),
        client.org_workflow_rulesets(org),
    )
    sweep_status = {
        "code-scanning": cs_status,
        "dependabot": dep_status,
        "secret-scanning": secret_status,
    }
    for kind, status in sweep_status.items():
        if status != 200:
            log.warning(
                "%s alert sweep for org %s unavailable (status %s); affected "
                "signals reported as unknown rather than clean",
                kind,
                org,
                status,
            )
    code_scanning = _group_by_repo(cs_alerts)
    dependabot = _group_by_repo(dep_alerts)
    secret = _group_by_repo(secret_alerts)

    workflow_rulesets = rulesets.parse_workflow_rulesets(rs_details)
    if rs_status != 200:
        log.warning(
            "org rulesets unavailable for %s (status %s); ruleset-based tool "
            "coverage disabled",
            org,
            rs_status,
        )
    coverage = {
        repo.name: rulesets.signals_covered(
            repo.name, workflow_rulesets, report_cfg.ruleset_workflows
        )
        for repo in in_scope
    }

    # Bounded per-repo probes. The client semaphore caps real HTTP concurrency;
    # chunking the gather also bounds task creation so very large orgs
    # (hundreds/thousands of repos) do not allocate every task at once.
    facts: list[RepoFacts] = []
    for start in range(0, len(in_scope), _REPO_BATCH):
        batch = in_scope[start : start + _REPO_BATCH]
        facts.extend(
            await asyncio.gather(
                *(
                    _facts_for_repo(
                        client, org, repo, code_scanning, dependabot, secret,
                        coverage.get(repo.name, set()), sweep_status,
                    )
                    for repo in batch
                )
            )
        )

    signals = [sig for repo_facts in facts for sig in classify_repo(repo_facts)]
    return build_org_report(
        org,
        signals,
        repo_count=len(in_scope),
        generated_at=generated_at,
        partial=repos_status != 200,
    )


async def collect_repo(
    client: RepoClientProtocol,
    owner: str,
    repo_name: str,
    *,
    ruleset_workflows: dict[str, str] | None = None,
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
    cs_alerts_status = 200
    if cs_status == 200:
        cs_alerts_status, cs_alerts = await client.repo_code_scanning_alerts(
            owner, repo_name
        )
    secret_status, secret_open = await client.repo_secret_scanning(owner, repo_name)
    dependabot_on = await client.dependabot_enabled(owner, repo_name)
    # Only fetch Dependabot alerts when the feature is enabled.
    dependabot_alerts: list[dict] = []
    dependabot_alerts_status = 200
    if dependabot_on:
        dependabot_alerts_status, dependabot_alerts = await client.repo_dependabot_alerts(
            owner, repo_name
        )
    scorecard_status, score = await client.scorecard_score(owner, repo_name)
    # Ruleset coverage from the repo's effective branch rules (includes
    # inherited org rulesets); repo-scoped tokens can read this endpoint.
    rs_status, branch_rules = await client.repo_branch_rules(
        owner, repo_name, repo.default_branch
    )
    ruleset_signals = (
        rulesets.signals_from_branch_rules(
            branch_rules, ruleset_workflows or DEFAULT_RULESET_WORKFLOWS
        )
        if rs_status == 200
        else set()
    )
    facts = RepoFacts(
        repo=repo,
        code_scanning_status=cs_status,
        code_scanning_tools=cs_tools,
        code_scanning_alerts=cs_alerts,
        code_scanning_alerts_status=cs_alerts_status,
        secret_scanning_status=secret_status,
        secret_scanning_open=secret_open,
        secret_scanning_open_status=secret_status,
        dependabot_enabled=dependabot_on,
        dependabot_alerts=dependabot_alerts,
        dependabot_alerts_status=dependabot_alerts_status,
        scorecard_status=scorecard_status,
        scorecard_score=score,
        ruleset_signals=ruleset_signals,
    )
    return repo, classify_repo(facts)
