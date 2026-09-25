# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""The CodeQL stale-configuration cleanup remediator (see ADR-0005).

Targets come from the report's own collected facts, planned by
:func:`github_security_report.codeql.plan_cleanup`; a pre-write check refuses
any deletion that could close an open alert, judged across the repository's
whole planned deletion set; the write deletes a configuration's analyses or
re-enables its workflow.
"""

from __future__ import annotations

from github_security_report.codeql import CleanupAction, CleanupItem, plan_cleanup
from github_security_report.remediate.model import (
    RemediationClient,
    _AlertHolders,
    _Target,
)
from github_security_report.report import OrgReport


def _cleanup_targets(report: OrgReport) -> list[_Target]:
    """One target per stale configuration with a safe fix, from the report."""
    health = report.codeql_health
    if health is None:
        return []
    items = plan_cleanup(health.facts, stale_days=health.stale_days)
    batches: dict[str, set[str]] = {}
    for item in items:
        if item.action is CleanupAction.DELETE and item.refusal is None:
            batches.setdefault(item.repo.name, set()).add(item.config.category)
    shared: dict[str, _AlertHolders] = {}
    return [
        _Target(
            item.repo,
            item.label,
            verb=item.action.value,
            refusal=item.refusal,
            cleanup=item,
            batch=frozenset(batches.get(item.repo.name, ())),
            alerts=shared.setdefault(item.repo.name, _AlertHolders()),
        )
        for item in items
    ]


def _planned(target: _Target) -> CleanupItem:
    if target.cleanup is None:  # pragma: no cover - registry wiring invariant
        raise ValueError(f"{target.name}: no cleanup plan")
    return target.cleanup


async def _cleanup_precheck(
    client: RemediationClient, org: str, target: _Target
) -> str | None:
    """Refuse a deletion that could help close an open alert, or can't tell.

    Judged against the repository's whole planned deletion set: an alert
    closes when every configuration holding it is being deleted, so two
    configurations can jointly close an alert neither holds alone. Every
    deletion holding such an alert is refused, which keeps all its holders
    rather than choosing one to spare.
    """
    item = _planned(target)
    if item.action is not CleanupAction.DELETE:
        return None
    if not target.alerts.loaded:
        target.alerts.holders = await client.codeql_alert_holders(
            org, item.repo.name, item.repo.default_branch
        )
        target.alerts.loaded = True
    holders = target.alerts.holders
    if holders is None:
        return "open alerts could not be read; nothing deleted"
    category = item.config.category
    closed = sum(
        1 for held_by in holders if category in held_by and held_by <= target.batch
    )
    if closed:
        return (
            f"would close {closed} open alert(s) that no remaining "
            "configuration reports"
        )
    return None


async def _cleanup_write(
    client: RemediationClient, org: str, target: _Target
) -> tuple[bool, str]:
    item = _planned(target)
    if item.action is CleanupAction.DELETE:
        return await client.delete_codeql_analyses(
            org, item.repo.name, item.config.analysis_ids
        )
    path = item.config.workflow_path
    if path is None:  # pragma: no cover - the planner only re-enables workflows
        return False, "no workflow path"
    return await client.enable_workflow(org, item.repo.name, path)
