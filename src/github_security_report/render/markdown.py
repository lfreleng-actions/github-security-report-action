# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Canonical Markdown rendering.

One heading per category, immediately followed by its table, the explanatory
description (Markdown is a rich surface, so it keeps the guidance text), and the
standardised summary footer shared by every render surface. This is the
canonical artifact; Slack, the terminal and the HTML pages derive from the same
report model and the same :func:`build_summary` footer. See ``docs/BRIEF.md``
sections 4-6, 11.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence

from github_security_report.categories import CategoryKey
from github_security_report.models import Repo, RepoSignal, SignalType
from github_security_report.report import (
    SUMMARY_EMOJI,
    OrgReport,
    Report,
    SignalSection,
    SummaryLine,
    TableSection,
    build_summary,
    offender_column_totals,
    truncate,
)

# Summary kinds whose repository names are listed beneath the count line.
_NAME_LIST_LABEL = {"disabled": "Disabled", "excluded": "Excluded"}


def _link(repo: Repo) -> str:
    return f"[{repo.name}]({repo.html_url})"


def _columns(signal: SignalType) -> list[str]:
    if signal is SignalType.SECRET_SCANNING:
        return ["Repository", "Open"]
    if signal is SignalType.SCORECARD:
        return ["Repository", "Score", "Critical", "High", "Medium", "Low"]
    return ["Repository", "Critical", "High", "Medium", "Low", "Total"]


def _row(sig: RepoSignal) -> list[str]:
    c = sig.counts
    if sig.signal is SignalType.SECRET_SCANNING:
        return [_link(sig.repo), str(c.total)]
    if sig.signal is SignalType.SCORECARD:
        score = f"{sig.score:.1f}" if sig.score is not None else "—"
        return [_link(sig.repo), score, str(c.critical), str(c.high), str(c.medium), str(c.low)]
    return [_link(sig.repo), str(c.critical), str(c.high), str(c.medium), str(c.low), str(c.total)]


def _table(section: SignalSection, top_n: int | None = None) -> list[str]:
    cols = _columns(section.signal)
    aligns = ["---"] + ["---:"] * (len(cols) - 1)
    lines = ["| " + " | ".join(cols) + " |", "| " + " | ".join(aligns) + " |"]
    offenders, hidden = truncate(section.offenders, top_n)
    for sig in offenders:
        lines.append("| " + " | ".join(_row(sig)) + " |")
    # Trailing column-totals row, for signals whose columns are additive
    # severity counts (every offender table except secret scanning).
    if section.signal.uses_severity_columns:
        cells = total_row_cells(section.signal, offenders)
        lines.append("| " + " | ".join(cells) + " |")
    if hidden:
        lines.append("")
        lines.append(f"_… and {hidden} more_")
    return lines


# Public, render-surface-agnostic accessors for the per-signal table shape, so
# other renderers (e.g. HTML) do not reach into this module's private helpers.
def columns(signal: SignalType) -> list[str]:
    """Column headings for a signal's offender table (repository first)."""
    return _columns(signal)


def row_cells(sig: RepoSignal) -> list[str]:
    """Cells for one offender row (the repository link is the first cell)."""
    return _row(sig)


def total_row_cells(
    signal: SignalType, offenders: Sequence[RepoSignal]
) -> list[str]:
    """Cells for a trailing "Total" row summing the severity columns.

    Shared by the Markdown, HTML and terminal surfaces (their offender tables
    have the same column shape). The first cell is the literal ``"Total"`` in
    place of a repository. Scorecard's score is not additive, so that column is
    left blank. Only meaningful for signals that use severity columns.
    """
    totals = offender_column_totals(offenders)
    base = [
        str(totals.critical),
        str(totals.high),
        str(totals.medium),
        str(totals.low),
    ]
    if signal is SignalType.SCORECARD:
        return ["Total", "", *base]
    return ["Total", *base, str(totals.total)]


def _summary_lines(
    lines: Sequence[SummaryLine],
    name_to_repo: Mapping[str, Repo],
    *,
    top_n: int | None,
) -> list[str]:
    """Markdown for the standardised footer: count lines, then any name lists.

    Each count line is its own paragraph so it stands alone regardless of the
    consuming Markdown flavour. The disabled and excluded kinds additionally
    list their repositories (as links when a :class:`Repo` is known), honouring
    the same offender limit the tables use.
    """
    out: list[str] = []
    for line in lines:
        out.append(f"{SUMMARY_EMOJI[line.kind]} {line.text}")
        out.append("")
    for line in lines:
        label = _NAME_LIST_LABEL.get(line.kind)
        if not (label and line.names):
            continue
        shown, hidden = truncate(line.names, top_n)
        linked = ", ".join(
            _link(name_to_repo[name]) if name in name_to_repo else f"`{name}`"
            for name in shown
        )
        if hidden:
            linked += f" … (+{hidden} more)"
        out.append(f"**{label}:** {linked}")
        out.append("")
    return out


def _description_lines(description: str, url: str) -> list[str]:
    """Italic description paragraph plus a reference link (rich surface only)."""
    if not description:
        return []
    text = f"_{description}_"
    if url:
        text += f" — [reference]({url})"
    return [text, ""]


def render_section(
    section: SignalSection,
    *,
    excluded: Sequence[Repo] = (),
    top_n: int | None = None,
) -> str:
    meta = section.signal.meta
    lines = [f"## {meta.title}", ""]
    if section.offenders:
        lines.extend(_table(section, top_n))
        lines.append("")
    summary = build_summary(section.summary_counts(excluded))
    if not (section.offenders or summary):
        lines.append("_No data available._")
        lines.append("")
        return "\n".join(lines).rstrip() + "\n"
    lines.extend(_description_lines(meta.description, meta.url))
    name_to_repo = {r.name: r for r in (*section.nag_repos, *excluded)}
    lines.extend(_summary_lines(summary, name_to_repo, top_n=top_n))
    return "\n".join(lines).rstrip() + "\n"


def render_table_section(
    section: TableSection,
    *,
    level: int = 3,
    excluded: Sequence[Repo] = (),
    top_n: int | None = None,
) -> str:
    """Render a generic posture/freshness table at the given heading level."""
    heading = "#" * level
    meta = section.category
    lines = [f"{heading} {meta.title}", ""]
    summary = build_summary(section.summary_counts(excluded))
    if not (section.rows or summary):
        lines.append("_No data available._")
        lines.append("")
        return "\n".join(lines).rstrip() + "\n"
    rows, hidden = truncate(section.rows, top_n)
    if rows:
        aligns = ["---"] * len(section.columns)
        lines.append("| " + " | ".join(section.columns) + " |")
        lines.append("| " + " | ".join(aligns) + " |")
        for row in rows:
            cells = [_link(row.repo), *row.cells]
            lines.append("| " + " | ".join(cells) + " |")
        lines.append("")
        if hidden:
            lines.append(f"_… and {hidden} more_")
            lines.append("")
    lines.extend(_description_lines(section.resolved_description(), meta.url))
    name_to_repo = {r.name: r for r in excluded}
    lines.extend(
        _summary_lines(
            summary,
            name_to_repo,
            top_n=top_n,
        )
    )
    return "\n".join(lines).rstrip() + "\n"


def render_org(
    org: OrgReport,
    *,
    top_n: int | None = None,
    show: Callable[[CategoryKey], bool] | None = None,
) -> str:
    visible = show or (lambda _key: True)
    when = org.generated_at.strftime("%Y-%m-%d %H:%M UTC")
    parts = [
        f"# Security report: {org.org}",
        "",
        f"_{org.repo_count} repositories analysed · generated {when}_",
        "",
    ]
    if org.partial:
        parts.append(
            "> ⚠️ **Incomplete:** the repository listing could not be fully "
            "read, so some repositories may be missing from this report."
        )
        parts.append("")
    excluded = org.excluded_repos
    for section in org.sections:
        parent_visible = visible(section.signal.category_key)
        if parent_visible:
            parts.append(
                render_section(section, excluded=excluded, top_n=top_n)
            )
        # The Dependabot configuration-posture sub-tables normally nest beneath
        # the Dependabot signal heading as level-3 sub-sections. When the parent
        # signal is hidden they would otherwise become orphaned ### headings
        # under the previous ## section, so promote them to level 2 -- keeping
        # the heading structure correct and consistent with the HTML surface,
        # which likewise promotes them to top-level sections when the parent is
        # hidden.
        if section.signal is SignalType.DEPENDABOT:
            table_level = 3 if parent_visible else 2
            parts.extend(
                render_table_section(
                    table, level=table_level, excluded=excluded, top_n=top_n
                )
                for table in org.dependabot_tables
                if visible(table.category.key)
            )
    if org.releases is not None and visible(org.releases.category.key):
        parts.append(
            render_table_section(
                org.releases, level=2, excluded=excluded, top_n=top_n
            )
        )
    if org.mutable_releases is not None and visible(
        org.mutable_releases.category.key
    ):
        parts.append(
            render_table_section(
                org.mutable_releases, level=2, excluded=excluded, top_n=top_n
            )
        )
    return "\n".join(parts).rstrip() + "\n"


def render_report(report: Report, *, top_n: int | None = None) -> str:
    return (
        "\n\n".join(render_org(org, top_n=top_n) for org in report.orgs).rstrip()
        + "\n"
    )
