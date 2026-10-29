# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Reporting categories outside the four-state per-signal model.

Dependabot configuration posture, release/tag freshness, release mutability,
private vulnerability reporting, the auto-merge setting, Dependabot malware
alerts, Code Quality, CodeQL scan health and Workflow Failures are rendered as
tables rather than as pass/fail signals, so they are assembled here once the
signal report exists. The malware alerts come from the Dependabot alert sweep
already made for the signals. The Dependabot alerts enablement flag, the
auto-merge flag, the Linguist languages, the default branch head and the
release/tag data are reused from the batched GraphQL prefetch; the
security-updates, private-vulnerability-reporting, Code Quality setup and
CodeQL reads are still per-repo REST calls.
"""

from __future__ import annotations

import asyncio
import logging

from github_security_report import codeql, layout, malware, posture
from github_security_report.code_quality import CodeQualitySetup, applicable_languages
from github_security_report.collect.codeql import collect_codeql_facts
from github_security_report.collect.context import (
    CollectExtras,
    OrgCollectContext,
    gather_all,
    gather_in_batches,
)
from github_security_report.collect.workflow_runs import attach_workflow_failures
from github_security_report.config import OrgConfig, ReportConfig
from github_security_report.issues import (
    build_assigned_issues_table,
    build_issues_table,
)
from github_security_report.models import Repo, SignalType
from github_security_report.ordering import (
    apply_configured_order,
    apply_configured_signal_order,
    report_tables,
)
from github_security_report.posture import RepoPosture
from github_security_report.pulls import (
    build_assigned_pull_requests_table,
    build_pull_requests_table,
)
from github_security_report.report import OrgReport

log = logging.getLogger(__name__)


async def _code_quality_setup(
    repo: Repo, ctx: OrgCollectContext, languages: frozenset[str] | None
) -> CodeQualitySetup | None:
    """The Code Quality setup, read only where Code Quality applies.

    A repository with no Code Quality language, or whose languages could not
    be read, is never asked: its setup could not change how it is reported.
    """
    if not languages:
        return None
    return await ctx.client.code_quality_setup(ctx.org, repo.name)


async def _security_updates(repo: Repo, ctx: OrgCollectContext) -> bool | None:
    """Whether Dependabot security updates are on, from the listing if it said.

    The repository listing carries the state for a token with admin or
    security-manager rights, so the per-repository probe is spent only when
    the listing left it out.
    """
    if repo.security_updates is not None:
        return repo.security_updates
    return await ctx.client.automated_security_fixes(ctx.org, repo.name)


async def _posture_for_repo(repo: Repo, ctx: OrgCollectContext) -> RepoPosture:
    """Build one repo's Dependabot posture and release/tag freshness.

    The Dependabot-alerts flag, the auto-merge setting, the Linguist languages
    and the release/tag/``dependabot.yml`` data come from the batched GraphQL
    prefetch, and the security-updates state from the repository listing where
    it carried one; the private-vulnerability-reporting and Code Quality setup
    reads remain per-repo REST calls, since GitHub exposes no GraphQL
    equivalent. They are independent, so they are gathered together
    and the reads overlap (bounded by the client semaphore). Private
    vulnerability reporting is always probed, like every other signal, with the
    per-category toggle governing only whether the resulting table renders; the
    Code Quality setup is read only where Code Quality applies.
    """
    graph = ctx.graph_for(repo.name)
    quality_languages = (
        applicable_languages(graph.languages) if graph.languages is not None else None
    )
    security_updates, pvr, quality = await asyncio.gather(
        _security_updates(repo, ctx),
        ctx.client.private_vulnerability_reporting(ctx.org, repo.name),
        _code_quality_setup(repo, ctx, quality_languages),
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
        auto_merge=graph.auto_merge_allowed,
        code_quality_languages=quality_languages,
        code_quality=quality,
        cooldown_missing=cooldown_missing,
        has_dependabot_config=config_text is not None,
        latest_release_at=graph.latest_release_at,
        latest_tag_at=graph.latest_tag_at,
        latest_release=graph.latest_release,
        last_published_release=graph.last_published_release,
    )


async def _attach_author_tables(
    report: OrgReport,
    in_scope: list[Repo],
    ctx: OrgCollectContext,
    report_cfg: ReportConfig,
) -> None:
    """Attach Issues, Pull Requests, both Assigned to Me tables and their reads."""
    # Organisation membership is collected once and reused by both author-aware
    # tables, so classifying contributions costs one query rather than a probe
    # per author. It is the token-independent basis for "outside the
    # organisation"; see ``authors`` for why the per-item association alone is
    # not enough. Why it could not be read, when it could not, travels with
    # the report so the terminal can say so once.
    membership = await ctx.client.org_members(ctx.org)
    members = membership.members
    report.membership_gap = membership.gap
    # "Mine" in the assignment breakdown is the account this run authenticated
    # as, read once here rather than assumed from configuration. Empty when that
    # account is automation or could not be read, which is what confines the
    # viewer-relative output below.
    viewer = await ctx.client.viewer_login()
    # Open issues and pull requests come from the same batched GraphQL prefetch
    # as the release and Dependabot data, so the per-repository data costs no
    # extra request; the two identity reads above are the run's only additions.
    report.issues = build_issues_table(
        ctx.graph,
        in_scope,
        generated_at=report.generated_at,
        label_columns=report_cfg.issue_labels,
        age_warn_days=report_cfg.issue_age_warn_days,
        age_error_days=report_cfg.issue_age_error_days,
        members=members,
    )
    report.pull_requests = build_pull_requests_table(
        ctx.graph,
        in_scope,
        members=members,
        warn_threshold=report_cfg.dependabot_warn_threshold,
        error_threshold=report_cfg.dependabot_error_threshold,
        viewer=viewer,
    )
    # A personal queue needs a person. Without one both tables would be
    # unconditionally empty, and an "Assigned to Me" section reporting every
    # repository clean reassures the reader about an inbox that does not exist,
    # so both categories are left uncollected and no surface renders them.
    if viewer:
        report.assigned_issues = build_assigned_issues_table(
            ctx.graph,
            in_scope,
            generated_at=report.generated_at,
            label_columns=report_cfg.issue_labels,
            age_warn_days=report_cfg.issue_age_warn_days,
            age_error_days=report_cfg.issue_age_error_days,
            members=members,
            viewer=viewer,
        )
        report.assigned_pull_requests = build_assigned_pull_requests_table(
            ctx.graph,
            in_scope,
            members=members,
            warn_threshold=report_cfg.dependabot_warn_threshold,
            error_threshold=report_cfg.dependabot_error_threshold,
            viewer=viewer,
        )


async def attach_extra_tables(
    report: OrgReport,
    in_scope: list[Repo],
    ctx: OrgCollectContext,
    org_cfg: OrgConfig,
    report_cfg: ReportConfig,
    *,
    extras: CollectExtras | None = None,
) -> None:
    """Probe posture for every repository and attach the derived tables.

    ``extras`` (see :class:`CollectExtras`) switches the author tables off,
    which leaves the Issues, Pull Requests and both Assigned to Me tables
    uncollected and with them the membership and viewer reads they alone
    need, and names the run store the Workflow Failures tables sync against.
    """
    wanted = extras if extras is not None else CollectExtras()

    async def nothing() -> None:
        return None

    # The four collections read only the frozen context and each attach to
    # a different part of the report, so they run together; previously they
    # were three sequential passes with the semaphore part-idle between.
    postures, codeql_facts, _authors, _runs = await gather_all(
        gather_in_batches(in_scope, lambda repo: _posture_for_repo(repo, ctx)),
        collect_codeql_facts(in_scope, ctx, stale_days=report_cfg.codeql_stale_days),
        _attach_author_tables(report, in_scope, ctx, report_cfg)
        if wanted.author_tables
        else nothing(),
        attach_workflow_failures(report, in_scope, ctx, report_cfg, wanted)
        if wanted.run_store is not None
        else nothing(),
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
    report.auto_merge = posture.build_auto_merge_table(postures)
    # Malware findings come from the Dependabot sweep already made for the
    # alerts signal, so this table costs no request of its own.
    report.malware_findings = malware.build_malware_findings_table(
        in_scope,
        ctx.dependabot,
        {p.repo.name: p.dependabot_alerts for p in postures},
        sweep_readable=ctx.sweep_status.get("dependabot") == 200,
        generated_at=report.generated_at,
    )
    report.code_quality = posture.build_code_quality_table(postures)
    report.code_quality_writes = posture.code_quality_writes(postures)
    report.codeql_tables = codeql.build_codeql_tables(
        codeql_facts, stale_days=report_cfg.codeql_stale_days
    )
    report.codeql_health = codeql.CodeQLHealth(
        facts=tuple(codeql_facts), stale_days=report_cfg.codeql_stale_days
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
    # The sequence the sections themselves are drawn in, resolved once for the
    # same reason: a table's position is a property of the report, so a Slack
    # digest must not run in a different order from the page it links to. This
    # comes last because the automatic layout demotes empty categories, and the
    # tables above are what decide which ones are empty.
    report.section_order = layout.resolve(report, report_cfg.order)
