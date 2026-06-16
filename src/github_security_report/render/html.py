# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""HTML rendering (Jinja2 + Simple-DataTables).

Renders each organisation to a single scrollable page with sortable/searchable
tables (Simple-DataTables, version-pinned), and a card-grid index linking to
every org -- the GitHub Pages layout. See ``docs/BRIEF.md`` section 11.
"""

from __future__ import annotations

from jinja2 import Environment, PackageLoader, select_autoescape

from github_security_report.models import RepoSignal
from github_security_report.render import markdown
from github_security_report.report import OrgReport, SignalSection

# Pinned, not @latest (a security tool must not load a floating CDN asset).
DATATABLES_VERSION = "9.0.3"

_env = Environment(
    loader=PackageLoader("github_security_report", "templates"),
    autoescape=select_autoescape(["html", "j2"]),
)


def slugify(org: str) -> str:
    return org.strip().lower().replace(" ", "-")


def _row_cells(sig: RepoSignal) -> list[str]:
    # Reuse the Markdown row logic, dropping the leading repository link cell.
    return markdown._row(sig)[1:]


def _section_context(section: SignalSection) -> dict:
    return {
        "title": section.signal.heading,
        "columns": markdown._columns(section.signal),
        "rows": [
            {"name": s.repo.name, "url": s.repo.html_url, "cells": _row_cells(s)}
            for s in section.offenders
        ],
        "clean_count": section.clean_count,
        "nag": [{"name": r.name, "url": r.html_url} for r in section.nag_repos],
        "unknown_count": section.unknown_count,
    }


def render_org_html(org: OrgReport) -> str:
    template = _env.get_template("report.html.j2")
    return str(
        template.render(
            org=org.org,
            repo_count=org.repo_count,
            generated_at=org.generated_at.strftime("%Y-%m-%d %H:%M UTC"),
            sections=[_section_context(s) for s in org.sections],
            datatables_version=DATATABLES_VERSION,
        )
    )


def render_index_html(orgs: list[OrgReport]) -> str:
    template = _env.get_template("index.html.j2")
    generated_at = (
        max(o.generated_at for o in orgs).strftime("%Y-%m-%d %H:%M UTC") if orgs else ""
    )
    return str(
        template.render(
            orgs=[
                {"name": o.org, "slug": slugify(o.org), "repo_count": o.repo_count}
                for o in orgs
            ],
            generated_at=generated_at,
        )
    )
