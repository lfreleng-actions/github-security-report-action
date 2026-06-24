# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""HTML rendering (Jinja2 + Simple-DataTables).

Renders each organisation to a single scrollable page with sortable/searchable
tables (Simple-DataTables, version-pinned), and a card-grid index linking to
every org -- the GitHub Pages layout. See ``docs/BRIEF.md`` section 11.
"""

from __future__ import annotations

import re

from jinja2 import Environment, PackageLoader, select_autoescape

from github_security_report.models import RepoSignal, SignalType
from github_security_report.render import markdown
from github_security_report.report import (
    OrgReport,
    SignalSection,
    TableSection,
    note_sentences,
    truncate,
)

# Pinned, not @latest (a security tool must not load a floating CDN asset).
DATATABLES_VERSION = "9.0.3"
# Subresource Integrity (sha384) for the exact pinned files: the browser
# verifies the fetched bytes against these, so a compromised/substituted CDN
# asset is rejected. Regenerate if DATATABLES_VERSION changes, e.g.:
#   curl -sL <url> | openssl dgst -sha384 -binary | openssl base64 -A
DATATABLES_CSS_SRI = "sha384-xnK68E/OAsSGcbvbeWEOyhjix2K7rBxt8Eytj/Ow9zuPG7WwFGGqMPQ8SbexlsL0"
DATATABLES_JS_SRI = "sha384-JYQd44jQWQbU+FdjWIUlbjzENGRHPdOQcj7dAgjJEvSyt2js5lE85kaPOdC53JVu"

_env = Environment(
    loader=PackageLoader("github_security_report", "templates"),
    autoescape=select_autoescape(["html", "j2"]),
)


# Anything outside this set is replaced; this also strips path separators and
# dots, so a hostile org name (e.g. "../etc") cannot escape the output dir.
_SLUG_UNSAFE = re.compile(r"[^a-z0-9_-]+")


def slugify(org: str) -> str:
    """Lowercase, filesystem- and URL-safe slug for an organisation name.

    The result is used to build on-disk Pages paths (``output_dir / slug``) and
    URLs, so it must never contain path separators or ``..``. Any character
    outside ``[a-z0-9_-]`` (including ``/``, ``.`` and whitespace) collapses to
    a single ``-``; a value that reduces to empty falls back to ``"org"``.
    """
    slug = _SLUG_UNSAFE.sub("-", org.strip().lower()).strip("-")
    return slug or "org"


def _row_cells(sig: RepoSignal) -> list[str]:
    # Reuse the Markdown row shape (public API), dropping the leading repo cell.
    return markdown.row_cells(sig)[1:]


def _table_context(section: TableSection, top_n: int | None = None) -> dict:
    """Context for a generic posture/freshness table (Dependabot, releases)."""
    rows, hidden = truncate(section.rows, top_n)
    return {
        "title": section.title,
        "columns": list(section.columns),
        "rows": [
            {"name": row.repo.name, "url": row.repo.html_url, "cells": list(row.cells)}
            for row in rows
        ],
        "hidden": hidden,
        "empty_note": section.empty_note,
        "note": section.note,
        "note_lines": note_sentences(section.note),
        "summary": section.summary,
    }


def _section_context(section: SignalSection, top_n: int | None = None) -> dict:
    offenders, hidden = truncate(section.offenders, top_n)
    nag, nag_hidden = truncate(section.nag_repos, top_n)
    # A trailing totals row sums the additive severity columns across the shown
    # rows; secret scanning has no such columns, so it gets none.
    total_cells = (
        markdown.total_row_cells(section.signal, offenders)
        if section.signal.uses_severity_columns and offenders
        else None
    )
    return {
        "title": section.signal.heading,
        "columns": markdown.columns(section.signal),
        "rows": [
            {"name": s.repo.name, "url": s.repo.html_url, "cells": _row_cells(s)}
            for s in offenders
        ],
        "hidden": hidden,
        "total_cells": total_cells,
        "clean_count": section.clean_count,
        "nag": [{"name": r.name, "url": r.html_url} for r in nag],
        "nag_hidden": nag_hidden,
        "unknown_count": section.unknown_count,
    }


def render_org_html(org: OrgReport, *, top_n: int | None = None) -> str:
    template = _env.get_template("report.html.j2")
    sections: list[dict] = []
    for section in org.sections:
        ctx = _section_context(section, top_n)
        # The Dependabot posture sub-tables render beneath the Dependabot
        # Alerts section, inside the same card.
        if section.signal is SignalType.DEPENDABOT:
            ctx["extra_tables"] = [
                _table_context(t, top_n) for t in org.dependabot_tables
            ]
        sections.append(ctx)
    excluded_shown, excluded_hidden = truncate(org.excluded_repos, top_n)
    return str(
        template.render(
            org=org.org,
            repo_count=org.repo_count,
            generated_at=org.generated_at.strftime("%Y-%m-%d %H:%M UTC"),
            partial=org.partial,
            excluded=[
                {"name": r.name, "url": r.html_url} for r in excluded_shown
            ],
            excluded_total=len(org.excluded_repos),
            excluded_hidden=excluded_hidden,
            sections=sections,
            releases=_table_context(org.releases, top_n) if org.releases else None,
            mutable_releases=(
                _table_context(org.mutable_releases, top_n)
                if org.mutable_releases
                else None
            ),
            datatables_version=DATATABLES_VERSION,
            datatables_css_sri=DATATABLES_CSS_SRI,
            datatables_js_sri=DATATABLES_JS_SRI,
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
