# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""HTML rendering (Jinja2 + Simple-DataTables).

Renders each organisation to a single scrollable page with sortable/searchable
tables (Simple-DataTables, version-pinned), and a card-grid index linking to
every org -- the GitHub Pages layout. As a rich, scrollable surface, the HTML
pages carry the per-category explanatory description and a documentation link
alongside the standardised summary footer. See ``docs/BRIEF.md`` section 11.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping, Sequence

from jinja2 import Environment, PackageLoader, select_autoescape

from github_security_report.categories import CategoryKey
from github_security_report.models import Repo, RepoSignal, SignalType
from github_security_report.render import markdown
from github_security_report.report import (
    SUMMARY_EMOJI,
    OrgReport,
    SignalSection,
    SummaryLine,
    TableSection,
    build_summary,
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

# Summary kinds whose repository names are listed beneath the count line.
_NAME_LIST_LABEL = {"disabled": "Disabled", "excluded": "Excluded"}


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


def _summary_context(
    lines: Sequence[SummaryLine],
    name_to_repo: Mapping[str, Repo],
    *,
    top_n: int | None,
) -> list[dict]:
    """Template context for the standardised footer.

    Each entry carries the glyph and text for its count line, plus -- for the
    disabled and excluded kinds -- the repository name list (linked when a
    :class:`Repo` is known). The template renders the count lines first, then
    the name lists, mirroring the terminal and Markdown surfaces.
    """
    out: list[dict] = []
    for line in lines:
        names: list[dict] = []
        hidden = 0
        if line.kind in _NAME_LIST_LABEL and line.names:
            shown, hidden = truncate(line.names, top_n)
            names = [
                {
                    "name": name,
                    "url": name_to_repo[name].html_url if name in name_to_repo else "",
                }
                for name in shown
            ]
        out.append(
            {
                "kind": line.kind,
                "emoji": SUMMARY_EMOJI[line.kind],
                "text": line.text,
                "label": _NAME_LIST_LABEL.get(line.kind),
                "names": names,
                "names_hidden": hidden,
            }
        )
    return out


def _table_context(
    section: TableSection,
    *,
    excluded: Sequence[Repo] = (),
    top_n: int | None = None,
) -> dict:
    """Context for a generic posture/freshness table (Dependabot, releases)."""
    rows, hidden = truncate(section.rows, top_n)
    name_to_repo = {r.name: r for r in excluded}
    return {
        "title": section.title,
        "url": section.category.url,
        "description": section.resolved_description(),
        # Posture/freshness columns are textual (ecosystem lists, release/tag
        # strings), so they are left-aligned rather than the right-aligned
        # tabular-nums treatment used for the severity-count tables.
        "numeric": False,
        "columns": list(section.columns),
        "rows": [
            {"name": row.repo.name, "url": row.repo.html_url, "cells": list(row.cells)}
            for row in rows
        ],
        "hidden": hidden,
        "summary": _summary_context(
            build_summary(section.summary_counts(excluded)),
            name_to_repo,
            top_n=top_n,
        ),
    }


def _section_context(
    section: SignalSection,
    *,
    excluded: Sequence[Repo] = (),
    top_n: int | None = None,
) -> dict:
    offenders, hidden = truncate(section.offenders, top_n)
    # A trailing totals row sums the additive severity columns across the shown
    # rows; secret scanning has no such columns, so it gets none.
    total_cells = (
        markdown.total_row_cells(section.signal, offenders)
        if section.signal.uses_severity_columns and offenders
        else None
    )
    meta = section.signal.meta
    name_to_repo = {r.name: r for r in (*section.nag_repos, *excluded)}
    return {
        "title": meta.title,
        "url": meta.url,
        "description": meta.description,
        # Severity sections have numeric count columns after the leading
        # repository column, so they are right-aligned with tabular figures.
        "numeric": True,
        "columns": markdown.columns(section.signal),
        "rows": [
            {"name": s.repo.name, "url": s.repo.html_url, "cells": _row_cells(s)}
            for s in offenders
        ],
        "hidden": hidden,
        "total_cells": total_cells,
        "summary": _summary_context(
            build_summary(section.summary_counts(excluded)),
            name_to_repo,
            top_n=top_n,
        ),
    }


def render_org_html(
    org: OrgReport,
    *,
    top_n: int | None = None,
    show: Callable[[CategoryKey], bool] | None = None,
) -> str:
    visible = show or (lambda _key: True)
    template = _env.get_template("report.html.j2")
    excluded = org.excluded_repos
    sections: list[dict] = []
    for section in org.sections:
        parent_visible = visible(section.signal.category_key)
        if parent_visible:
            ctx = _section_context(section, excluded=excluded, top_n=top_n)
            # When the parent Dependabot Alerts signal is shown, its posture
            # sub-tables render beneath it inside the same card.
            if section.signal is SignalType.DEPENDABOT:
                ctx["extra_tables"] = [
                    _table_context(t, excluded=excluded, top_n=top_n)
                    for t in org.dependabot_tables
                    if visible(t.category.key)
                ]
            sections.append(ctx)
        elif section.signal is SignalType.DEPENDABOT:
            # The parent Dependabot Alerts signal is hidden, but the posture
            # tables are toggled independently: surface any enabled ones as
            # their own top-level sections so per-category toggles for
            # dependabot_alerts_enabled / _updates_enabled / _cooldown are
            # honoured on the HTML surface too -- matching the terminal,
            # Markdown and Slack renderers, which decouple them from the
            # parent signal's visibility.
            sections.extend(
                _table_context(t, excluded=excluded, top_n=top_n)
                for t in org.dependabot_tables
                if visible(t.category.key)
            )
    return str(
        template.render(
            org=org.org,
            repo_count=org.repo_count,
            generated_at=org.generated_at.strftime("%Y-%m-%d %H:%M UTC"),
            partial=org.partial,
            sections=sections,
            releases=(
                _table_context(org.releases, excluded=excluded, top_n=top_n)
                if org.releases and visible(org.releases.category.key)
                else None
            ),
            mutable_releases=(
                _table_context(org.mutable_releases, excluded=excluded, top_n=top_n)
                if org.mutable_releases
                and visible(org.mutable_releases.category.key)
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
