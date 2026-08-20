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
    ORG_SETUP_DOC_URL,
    SKIP_MESSAGE,
    SUMMARY_EMOJI,
    LimitFor,
    OrgReport,
    Report,
    SignalSection,
    SummaryLine,
    TableSection,
    build_summary,
    limit_resolver,
    offender_column_totals,
    section_shows_informational,
    table_column_totals,
    table_footer_rows,
    truncate,
)

# Summary kinds whose repository names are listed beneath the count line.
_NAME_LIST_LABEL = {"disabled": "Disabled", "excluded": "Excluded"}


def _link(repo: Repo) -> str:
    return f"[{repo.name}]({repo.html_url})"


def _columns(signal: SignalType, *, informational: bool = False) -> list[str]:
    if signal is SignalType.SECRET_SCANNING:
        return ["Repository", "Open"]
    info = ["Info"] if informational else []
    # Scorecard leads with its aggregate score; every severity table then shares
    # the same severity columns and the same trailing Total. The score is a
    # health rating rather than a finding count, so it sits outside that sum --
    # Total counts findings, which is what remediation effort is sized by.
    score = ["Score"] if signal is SignalType.SCORECARD else []
    return [
        "Repository",
        *score,
        "Critical",
        "High",
        "Medium",
        "Low",
        *info,
        "Total",
    ]


def _row(sig: RepoSignal, *, informational: bool = False) -> list[str]:
    c = sig.counts
    if sig.signal is SignalType.SECRET_SCANNING:
        return [_link(sig.repo), str(c.total)]
    info = [str(c.informational)] if informational else []
    score = (
        [f"{sig.score:.1f}" if sig.score is not None else "—"]
        if sig.signal is SignalType.SCORECARD
        else []
    )
    return [
        _link(sig.repo),
        *score,
        str(c.critical),
        str(c.high),
        str(c.medium),
        str(c.low),
        *info,
        str(c.total),
    ]


def _table(section: SignalSection, top_n: int | None = None) -> list[str]:
    offenders, hidden = truncate(section.offenders, top_n)
    informational = section_shows_informational(offenders)
    cols = _columns(section.signal, informational=informational)
    aligns = ["---"] + ["---:"] * (len(cols) - 1)
    lines = ["| " + " | ".join(cols) + " |", "| " + " | ".join(aligns) + " |"]
    for sig in offenders:
        lines.append("| " + " | ".join(_row(sig, informational=informational)) + " |")
    # Trailing column-totals row, for signals whose columns are additive
    # severity counts (every offender table except secret scanning).
    if section.signal.uses_severity_columns:
        cells = total_row_cells(section.signal, offenders, informational=informational)
        lines.append("| " + " | ".join(cells) + " |")
    if hidden:
        lines.append("")
        lines.append(f"_… and {hidden} more_")
    return lines


# Public, render-surface-agnostic accessors for the per-signal table shape, so
# other renderers (e.g. HTML) do not reach into this module's private helpers.
def columns(signal: SignalType, *, informational: bool = False) -> list[str]:
    """Column headings for a signal's offender table (repository first).

    ``informational`` adds the sub-low Informational column, used only for
    tables that actually carry such findings (see
    :func:`report.section_shows_informational`).
    """
    return _columns(signal, informational=informational)


def row_cells(sig: RepoSignal, *, informational: bool = False) -> list[str]:
    """Cells for one offender row (the repository link is the first cell)."""
    return _row(sig, informational=informational)


def total_row_cells(
    signal: SignalType,
    offenders: Sequence[RepoSignal],
    *,
    informational: bool = False,
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
    info = [str(totals.informational)] if informational else []
    score = [""] if signal is SignalType.SCORECARD else []
    return ["Total", *score, *base, *info, str(totals.total)]


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
    if section.skipped:
        # Feature gating found no organisation support: a single skip line
        # with a pointer at the setup guide, instead of a table and footer.
        lines.append(
            f"{SUMMARY_EMOJI['excluded']} {SKIP_MESSAGE} — see the "
            f"[organisation scan setup guide]({ORG_SETUP_DOC_URL})."
        )
        lines.append("")
        return "\n".join(lines).rstrip() + "\n"
    if section.offenders:
        lines.extend(_table(section, top_n))
        lines.append("")
    summary = build_summary(section.summary_counts(excluded))
    if not (section.offenders or summary):
        lines.append("_No data available._")
        lines.append("")
        return "\n".join(lines).rstrip() + "\n"
    lines.extend(_description_lines(section.resolved_description(), meta.url))
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
        # A trailing totals row sums the numeric columns across the rows shown
        # above, matching the offender tables.
        totals = table_column_totals(section, rows)
        if totals is not None:
            lines.append(
                "| "
                + " | ".join(f"**{cell}**" if cell else "" for cell in totals)
                + " |"
            )
        # Aggregate rows beneath the totals: a breakdown of the same rows,
        # arriving full width with the value under the final column.
        for footer_row in table_footer_rows(section, rows):
            lines.append("| " + " | ".join(footer_row) + " |")
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
    limit: LimitFor | None = None,
) -> str:
    visible = show or (lambda _key: True)
    limit_for = limit_resolver(top_n, limit)
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

    def table(section: TableSection | None, *, level: int = 2) -> None:
        """Append one extra table, honouring its own visibility and limit."""
        if section is None or not visible(section.category.key):
            return
        parts.append(
            render_table_section(
                section,
                level=level,
                excluded=excluded,
                top_n=limit_for(section.category.key),
            )
        )

    for section in org.sections:
        key = section.signal.category_key
        parent_visible = visible(key)
        if parent_visible:
            parts.append(
                render_section(section, excluded=excluded, top_n=limit_for(key))
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
            for dependabot_table in org.dependabot_tables:
                table(dependabot_table, level=table_level)
    table(org.releases)
    table(org.mutable_releases)
    table(org.private_vulnerability_reporting)
    table(org.issues)
    table(org.pull_requests)
    table(org.assigned_pull_requests)
    return "\n".join(parts).rstrip() + "\n"


def render_report(report: Report, *, top_n: int | None = None) -> str:
    return (
        "\n\n".join(render_org(org, top_n=top_n) for org in report.orgs).rstrip() + "\n"
    )
