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
from collections.abc import Mapping
from typing import Protocol

from github_security_report import posture, rulesets, scope
from github_security_report.classify import RepoFacts, classify_repo
from github_security_report.config import (
    DEFAULT_RULESET_WORKFLOWS,
    OrgConfig,
    ReportConfig,
)
from github_security_report.models import Repo, RepoGraphData, RepoSignal, SignalType
from github_security_report.posture import RepoPosture
from github_security_report.report import OrgReport, build_org_report

log = logging.getLogger(__name__)

# Per-repo probe tasks are created in batches of this size so very large orgs
# do not allocate every task at once (HTTP concurrency is bounded separately by
# the client semaphore).
_REPO_BATCH = 50

# Repositories per batched GraphQL prefetch query. Kept smaller than the REST
# probe batch because each aliased sub-query expands the single request's cost.
_GRAPH_BATCH = 25


class ClientProtocol(Protocol):
    """The subset of :class:`client.GitHubClient` that orchestration needs."""

    async def list_org_repos(self, org: str) -> tuple[int, list[Repo]]:
        """List an organisation's repositories with the read status."""
        raise NotImplementedError

    async def org_bulk_alerts(self, org: str, kind: str) -> tuple[int, list[dict]]:
        """Fetch an organisation's alerts of one kind in a single sweep."""
        raise NotImplementedError

    async def org_workflow_rulesets(self, org: str) -> tuple[int, list[dict]]:
        """Fetch the organisation's workflow rulesets."""
        raise NotImplementedError

    async def code_scanning_tools(self, org: str, repo: str) -> tuple[int, set[str]]:
        """Return the code-scanning tools enabled on a repository."""
        raise NotImplementedError

    async def secret_scanning_status(self, org: str, repo: str) -> int:
        """Return the secret-scanning read status for a repository."""
        raise NotImplementedError

    async def scorecard_score(self, org: str, repo: str) -> tuple[int, float | None]:
        """Return a repository's OpenSSF Scorecard score and read status."""
        raise NotImplementedError

    async def automated_security_fixes(self, org: str, repo: str) -> bool | None:
        """Whether Dependabot automated security fixes are enabled."""
        raise NotImplementedError

    async def repo_graph_batch(
        self, org: str, names: list[str]
    ) -> dict[str, RepoGraphData]:
        """Fetch batched per-repo GraphQL data keyed by repository name."""
        raise NotImplementedError


class RepoClientProtocol(Protocol):
    """Extra per-repo methods needed for repo mode."""

    async def get_repo(self, org: str, repo: str) -> Repo | None:
        """Fetch a single repository, or None when it is absent."""
        raise NotImplementedError

    async def code_scanning_tools(self, org: str, repo: str) -> tuple[int, set[str]]:
        """Return the code-scanning tools enabled on a repository."""
        raise NotImplementedError

    async def repo_code_scanning_alerts(
        self, org: str, repo: str
    ) -> tuple[int, list[dict]]:
        """Fetch a repository's code-scanning alerts with the read status."""
        raise NotImplementedError

    async def repo_secret_scanning(self, org: str, repo: str) -> tuple[int, int]:
        """Return a repository's secret-scanning status and open count."""
        raise NotImplementedError

    async def dependabot_enabled(self, org: str, repo: str) -> bool | None:
        """Whether Dependabot alerts are enabled for a repository."""
        raise NotImplementedError

    async def repo_dependabot_alerts(
        self, org: str, repo: str
    ) -> tuple[int, list[dict]]:
        """Fetch a repository's Dependabot alerts with the read status."""
        raise NotImplementedError

    async def repo_branch_rules(
        self, org: str, repo: str, branch: str
    ) -> tuple[int, list[dict]]:
        """Fetch the branch-protection rules for a repository branch."""
        raise NotImplementedError

    async def scorecard_score(self, org: str, repo: str) -> tuple[int, float | None]:
        """Return a repository's OpenSSF Scorecard score and read status."""
        raise NotImplementedError


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
    *,
    dependabot_enabled: bool | None,
) -> RepoFacts:
    # These per-repo probes are independent; gather them so each repo's reads
    # overlap. Real HTTP concurrency stays bounded by the client semaphore.
    # ``dependabot_enabled`` comes from the batched GraphQL prefetch, so it is
    # passed in rather than re-probed here.
    (cs_status, cs_tools), secret_status, (scorecard_status, score) = (
        await asyncio.gather(
            client.code_scanning_tools(org, repo.name),
            client.secret_scanning_status(org, repo.name),
            client.scorecard_score(org, repo.name),
        )
    )
    return RepoFacts(
        repo=repo,
        code_scanning_status=cs_status,
        code_scanning_tools=cs_tools,
        code_scanning_alerts=code_scanning.get(repo.name, []),
        code_scanning_alerts_status=sweep_status["code-scanning"],
        secret_scanning_status=secret_status,
        secret_scanning_open=len(secret.get(repo.name, [])),
        secret_scanning_open_status=sweep_status["secret-scanning"],
        dependabot_enabled=dependabot_enabled,
        dependabot_alerts=dependabot.get(repo.name, []),
        dependabot_alerts_status=sweep_status["dependabot"],
        scorecard_status=scorecard_status,
        scorecard_score=score,
        ruleset_signals=ruleset_signals,
    )


async def _collect_graph(
    client: ClientProtocol, org: str, repos: list[Repo]
) -> dict[str, RepoGraphData]:
    """Prefetch batched GraphQL data for every in-scope repository.

    Issues one aliased query per ``_GRAPH_BATCH`` repositories, folding the
    former per-repo Dependabot-enabled, latest-release, latest-tag and
    ``dependabot.yml`` round-trips into a handful of requests.
    """
    graph: dict[str, RepoGraphData] = {}
    for start in range(0, len(repos), _GRAPH_BATCH):
        batch = repos[start : start + _GRAPH_BATCH]
        graph.update(await client.repo_graph_batch(org, [r.name for r in batch]))
    return graph


async def _posture_for_repo(
    client: ClientProtocol,
    org: str,
    repo: Repo,
    *,
    dependabot_alerts: bool | None,
    graph: RepoGraphData,
) -> RepoPosture:
    """Build one repo's Dependabot posture and release/tag freshness.

    ``dependabot_alerts`` and the release/tag/``dependabot.yml`` data come from
    the batched GraphQL prefetch (:func:`_collect_graph`); only the
    security-updates flag remains a per-repo REST call, since GitHub exposes no
    GraphQL equivalent.
    """
    security_updates = await client.automated_security_fixes(org, repo.name)
    config_text = graph.dependabot_config
    has_config = config_text is not None
    cooldown_missing = (
        posture.cooldown_missing_ecosystems(config_text)
        if config_text is not None
        else ()
    )
    return RepoPosture(
        repo=repo,
        dependabot_alerts=dependabot_alerts,
        security_updates=security_updates,
        cooldown_missing=cooldown_missing,
        has_dependabot_config=has_config,
        latest_release_at=graph.latest_release_at,
        latest_tag_at=graph.latest_tag_at,
        latest_release=graph.latest_release,
        last_published_release=graph.last_published_release,
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
    # Repositories removed specifically by the per-org exclude list (not by
    # fork/template/archived/test filtering) are tracked so the report can show
    # them as explicitly excluded rather than silently dropping them.
    exclude_names = set(org_cfg.exclude)
    excluded_repos = [repo for repo in repos if repo.name in exclude_names]

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

    # One batched GraphQL prefetch per ``_GRAPH_BATCH`` repositories gathers the
    # Dependabot-enabled flag, release immutability, latest tag/release and
    # ``dependabot.yml`` for the whole org in a few requests instead of several
    # round-trips per repository.
    graph = await _collect_graph(client, org, in_scope)

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
                        dependabot_enabled=graph.get(
                            repo.name, RepoGraphData()
                        ).dependabot_alerts_enabled,
                    )
                    for repo in batch
                )
            )
        )

    signals = [sig for repo_facts in facts for sig in classify_repo(repo_facts)]
    report = build_org_report(
        org,
        signals,
        repo_count=len(in_scope),
        generated_at=generated_at,
        partial=repos_status != 200,
        excluded_repos=excluded_repos,
    )

    # Extra reporting categories (outside the four-state model): Dependabot
    # configuration posture and release/tag freshness. The Dependabot alerts
    # enablement flag and the release/tag data are reused from the batched
    # GraphQL prefetch; only the security-updates flag is still a per-repo call.
    when = report.generated_at
    dependabot_on = {f.repo.name: f.dependabot_enabled for f in facts}
    postures: list[RepoPosture] = []
    for start in range(0, len(in_scope), _REPO_BATCH):
        batch = in_scope[start : start + _REPO_BATCH]
        postures.extend(
            await asyncio.gather(
                *(
                    _posture_for_repo(
                        client, org, repo,
                        dependabot_alerts=dependabot_on.get(repo.name),
                        graph=graph.get(repo.name, RepoGraphData()),
                    )
                    for repo in batch
                )
            )
        )

    report.dependabot_tables = posture.build_dependabot_tables(postures)
    report.releases = posture.build_releases_table(
        postures,
        generated_at=when,
        repo_min_age_days=report_cfg.repo_min_age_days,
        release_max_age_days=report_cfg.release_max_age_days,
        exclude=org_cfg.releases_exclude,
    )
    report.mutable_releases = posture.build_mutable_releases_table(postures)
    # The Dependabot alerts enablement sub-table carries the repositories with
    # Dependabot alerts disabled, so drop them from the Dependabot signal
    # section's nag list to avoid listing the same repositories twice under the
    # one heading.
    for section in report.sections:
        if section.signal is SignalType.DEPENDABOT:
            section.nag_repos = []
    return report


async def collect_repo(
    client: RepoClientProtocol,
    owner: str,
    repo_name: str,
    *,
    ruleset_workflows: Mapping[str, str] | None = None,
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
