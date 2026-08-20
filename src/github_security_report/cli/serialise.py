# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""JSON serialisation of a report for machine consumers.

``report.json`` is the complete machine-readable dataset, so -- unlike the
Markdown, HTML, terminal and Slack surfaces -- the per-output category render
toggles deliberately do not filter it.
"""

from __future__ import annotations

from github_security_report.report import OrgReport, TableSection


def _table_to_dict(section: TableSection) -> dict:
    """Serialise a generic posture/freshness table for JSON consumers."""
    return {
        "category": section.category.key.value,
        "title": section.title,
        "columns": list(section.columns),
        "rows": [
            {
                "repo": row.repo.full_name,
                "url": row.repo.html_url,
                "cells": list(row.cells),
            }
            for row in section.rows
        ],
        # Normalised footer counts shared by every render surface.
        "pass_count": section.pass_count,
        "fail_count": section.fail_count,
        "unknown_count": section.unknown_count,
        "description": section.resolved_description(),
    }


def _org_to_dict(org: OrgReport) -> dict:
    return {
        "org": org.org,
        "repo_count": org.repo_count,
        "generated_at": org.generated_at.isoformat(),
        # Surfaced so JSON consumers can distinguish a complete result from a
        # partial one (the repository listing could not be fully read).
        "partial": org.partial,
        # Repositories explicitly excluded from analysis (per-org exclude list).
        "excluded": [r.full_name for r in org.excluded_repos],
        "sections": [
            {
                "signal": s.signal.value,
                "offenders": [
                    {
                        "repo": rs.repo.full_name,
                        "url": rs.repo.html_url,
                        "counts": {
                            "critical": rs.counts.critical,
                            "high": rs.counts.high,
                            "medium": rs.counts.medium,
                            "low": rs.counts.low,
                            "informational": rs.counts.informational,
                            "total": rs.counts.total,
                        },
                        "score": rs.score,
                    }
                    for rs in s.offenders
                ],
                "clean_count": s.clean_count,
                "nag": [r.full_name for r in s.nag_repos],
                "unknown_count": s.unknown_count,
                # True when organisation feature gating skipped this signal
                # (no supporting workflows found), so nothing was collected.
                "skipped": s.skipped,
                "description": s.resolved_description(),
            }
            for s in org.sections
        ],
        # Extra reporting categories outside the four-state per-signal model.
        "dependabot_tables": [_table_to_dict(t) for t in org.dependabot_tables],
        "releases": _table_to_dict(org.releases) if org.releases else None,
        "mutable_releases": (
            _table_to_dict(org.mutable_releases) if org.mutable_releases else None
        ),
        "private_vulnerability_reporting": (
            _table_to_dict(org.private_vulnerability_reporting)
            if org.private_vulnerability_reporting
            else None
        ),
        "issues": _table_to_dict(org.issues) if org.issues else None,
        "pull_requests": (
            _table_to_dict(org.pull_requests) if org.pull_requests else None
        ),
    }
