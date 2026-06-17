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

from github_security_report.models import RepoSignal
from github_security_report.render import markdown
from github_security_report.report import OrgReport, SignalSection

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


def _section_context(section: SignalSection) -> dict:
    return {
        "title": section.signal.heading,
        "columns": markdown.columns(section.signal),
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
            partial=org.partial,
            sections=[_section_context(s) for s in org.sections],
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
