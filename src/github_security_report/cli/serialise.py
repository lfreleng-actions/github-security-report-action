# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""JSON serialisation of a report for machine consumers.

``report.json`` is the complete machine-readable dataset, so -- unlike the
Markdown, HTML, terminal and Slack surfaces -- the per-output category render
toggles deliberately do not filter it.
"""

from __future__ import annotations

from collections.abc import Collection

from github_security_report import layout
from github_security_report.categories import CategoryKey
from github_security_report.report import OrgReport, TableSection, table_footer_rows


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
        # Aggregate rows beneath the totals, over every row (report.json is the
        # unconditionally complete artifact, so nothing here is truncated).
        # Emitted as label/value rather than the renderers' padded row, since a
        # JSON consumer wants the pair, not the table's column alignment. The
        # viewer-relative rows are still omitted: this file is written into the
        # published Pages directory, where "Mine" names nobody the reader knows.
        "footer_rows": [
            {"label": row[0], "value": row[-1]}
            for row in table_footer_rows(section, section.rows)
        ],
    }


def _org_to_dict(org: OrgReport, hidden: Collection[CategoryKey] = ()) -> dict:
    """One organisation's report as JSON-ready data.

    ``hidden`` names the categories to omit. ``report.json`` is otherwise the
    complete dataset and deliberately ignores the per-surface render toggles,
    so a category merely hidden from one surface is still published in full.
    The caller decides what to suppress; it is written into the published Pages
    directory, so it excludes both an explicit ``--hide`` and any category no
    published surface carries at all.
    """
    suppressed = frozenset(hidden)

    def table(section: TableSection | None) -> dict | None:
        if section is None or section.category.key in suppressed:
            return None
        return _table_to_dict(section)

    return {
        "org": org.org,
        "repo_count": org.repo_count,
        "generated_at": org.generated_at.isoformat(),
        # Surfaced so JSON consumers can distinguish a complete result from a
        # partial one (the repository listing could not be fully read).
        "partial": org.partial,
        # Repositories explicitly excluded from analysis (per-org exclude list).
        "excluded": [r.full_name for r in org.excluded_repos],
        # Every category below, in the order the rendered surfaces drew it.
        # The keyed structure that follows is stable regardless, but a consumer
        # building its own view can reproduce the published layout instead of
        # inventing one. Nested posture tables are listed after the signal they
        # render beneath, so a consumer can place them even when their parent
        # is suppressed and the surfaces promoted them to top level.
        "section_order": [
            key.value for key in layout.drawn_order(org) if key not in suppressed
        ],
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
            if s.signal.category_key not in suppressed
        ],
        # Extra reporting categories outside the four-state per-signal model.
        "dependabot_tables": [
            entry for t in org.dependabot_tables if (entry := table(t)) is not None
        ],
        "releases": table(org.releases),
        "mutable_releases": table(org.mutable_releases),
        "private_vulnerability_reporting": table(org.private_vulnerability_reporting),
        "issues": table(org.issues),
        "pull_requests": table(org.pull_requests),
        "assigned_pull_requests": table(org.assigned_pull_requests),
    }
