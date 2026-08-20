# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Reporting categories outside the four-state per-signal model.

Dependabot configuration posture, release/tag freshness, release mutability and
private vulnerability reporting are rendered as standalone tables rather than
as pass/fail signals, so they are assembled here once the signal report exists.
The Dependabot alerts enablement flag and the release/tag data are reused from
the batched GraphQL prefetch; the security-updates and
private-vulnerability-reporting flags are still per-repo REST calls.
"""

from __future__ import annotations

import asyncio
import logging

from github_security_report import posture
from github_security_report.collect.context import (
    OrgCollectContext,
    gather_in_batches,
)
from github_security_report.config import OrgConfig, ReportConfig
from github_security_report.issues import build_issues_table
from github_security_report.models import Repo, SignalType
from github_security_report.ordering import (
    apply_configured_order,
    apply_configured_signal_order,
    report_tables,
)
from github_security_report.posture import RepoPosture
from github_security_report.report import OrgReport

log = logging.getLogger(__name__)


async def _posture_for_repo(repo: Repo, ctx: OrgCollectContext) -> RepoPosture:
    """Build one repo's Dependabot posture and release/tag freshness.

    The Dependabot-alerts flag and the release/tag/``dependabot.yml`` data come
    from the batched GraphQL prefetch; the security-updates and
    private-vulnerability-reporting flags remain per-repo REST calls, since
    GitHub exposes no GraphQL equivalent. They are independent, so they are
    gathered together and the two reads overlap (bounded by the client
    semaphore); private vulnerability reporting is always probed, like every
    other signal, with the per-category toggle governing only whether the
    resulting table renders.
    """
    graph = ctx.graph_for(repo.name)
    security_updates, pvr = await asyncio.gather(
        ctx.client.automated_security_fixes(ctx.org, repo.name),
        ctx.client.private_vulnerability_reporting(ctx.org, repo.name),
    )
    config_text = graph.dependabot_config
    cooldown_missing = (
        posture.cooldown_missing_ecosystems(config_text)
        if config_text is not None
        else ()
    )
    return RepoPosture(
        repo=repo,
        graph_unreadable=graph.unreadable,
        dependabot_alerts=graph.dependabot_alerts_enabled,
        security_updates=security_updates,
        private_vulnerability_reporting=pvr,
        cooldown_missing=cooldown_missing,
        has_dependabot_config=config_text is not None,
        latest_release_at=graph.latest_release_at,
        latest_tag_at=graph.latest_tag_at,
        latest_release=graph.latest_release,
        last_published_release=graph.last_published_release,
    )


async def attach_extra_tables(
    report: OrgReport,
    in_scope: list[Repo],
    ctx: OrgCollectContext,
    org_cfg: OrgConfig,
    report_cfg: ReportConfig,
) -> None:
    """Probe posture for every repository and attach the derived tables."""
    postures = await gather_in_batches(
        in_scope, lambda repo: _posture_for_repo(repo, ctx)
    )
    report.dependabot_tables = posture.build_dependabot_tables(postures)
    report.releases = posture.build_releases_table(
        postures,
        generated_at=report.generated_at,
        repo_min_age_days=report_cfg.repo_min_age_days,
        release_max_age_days=report_cfg.release_max_age_days,
        exclude=org_cfg.releases_exclude,
    )
    report.mutable_releases = posture.build_mutable_releases_table(postures)
    report.private_vulnerability_reporting = posture.build_pvr_table(postures)
    # Open issues come from the same batched GraphQL prefetch as the release and
    # Dependabot data, so this table costs no extra requests.
    report.issues = build_issues_table(
        ctx.graph,
        in_scope,
        generated_at=report.generated_at,
        label_columns=report_cfg.issue_labels,
    )
    # The Dependabot alerts enablement sub-table carries the repositories with
    # Dependabot alerts disabled, so drop them from the Dependabot signal
    # section's nag list to avoid listing the same repositories twice under the
    # one heading.
    for section in report.sections:
        if section.signal is SignalType.DEPENDABOT:
            section.nag_repos = []
    # Any configured per-category ordering is applied once, here, so every
    # render surface (and report.json) presents the same order.
    apply_configured_order(report_tables(report), report_cfg)
    apply_configured_signal_order(report.sections, report_cfg)
