# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Repo-mode collection: a single repository, using only per-repo endpoints.

The degraded PR-gate path. There is no org-bulk sweep and no org-level scope,
so it works with the ephemeral ``GITHUB_TOKEN`` -- see ``docs/BRIEF.md``
sections 9-12.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping

from github_security_report import rulesets
from github_security_report.classify import RepoFacts, classify_repo
from github_security_report.collect.protocols import RepoClientProtocol
from github_security_report.config import DEFAULT_RULESET_WORKFLOWS
from github_security_report.models import Repo, RepoSignal

log = logging.getLogger(__name__)


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
        (
            dependabot_alerts_status,
            dependabot_alerts,
        ) = await client.repo_dependabot_alerts(owner, repo_name)
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
