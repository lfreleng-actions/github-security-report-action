# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Canonical Markdown rendering.

One heading per signal, immediately followed by a table of offenders
(worst-first), then a clean count, a nag list, and an unknown-status footnote.
This is the canonical artifact; Slack and the job summary derive from the same
report model. See ``docs/BRIEF.md`` sections 4-6, 11.
"""

from __future__ import annotations

from github_security_report.models import Repo, RepoSignal, SignalType
from github_security_report.report import (
    OrgReport,
    Report,
    SignalSection,
    TableSection,
    truncate,
)


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


def render_section(section: SignalSection, *, top_n: int | None = None) -> str:
    lines = [f"## {section.signal.heading}", ""]
    if section.offenders:
        lines.extend(_table(section, top_n))
        lines.append("")
    if section.clean_count:
        lines.append(f"✅ {section.clean_count} repositories clean")
        lines.append("")
    if section.nag_repos:
        nag, hidden = truncate(section.nag_repos, top_n)
        lines.append("**Not enabled** — enable to appear in future reports:")
        lines.append("")
        lines.extend(f"- {_link(r)}" for r in nag)
        if hidden:
            lines.append(f"- _… and {hidden} more_")
        lines.append("")
    if section.unknown_count:
        lines.append(
            f"ℹ️ {section.unknown_count} repositories with unknown status "
            "(insufficient permission or a transient read failure)"
        )
        lines.append("")
    if not (
        section.offenders
        or section.clean_count
        or section.nag_repos
        or section.unknown_count
    ):
        lines.append("_No data available._")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_table_section(
    section: TableSection, *, level: int = 3, top_n: int | None = None
) -> str:
    """Render a generic posture/freshness table at the given heading level."""
    heading = "#" * level
    lines = [f"{heading} {section.title}", ""]
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
        if section.note:
            # The note describes a populated table; omit it when empty.
            lines.append(f"_{section.note}_")
            lines.append("")
    elif section.empty_note:
        lines.append(f"✅ {section.empty_note}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_org(org: OrgReport, *, top_n: int | None = None) -> str:
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
    if org.excluded_repos:
        shown, hidden = truncate(org.excluded_repos, top_n)
        names = ", ".join(f"`{r.name}`" for r in shown)
        if hidden:
            names += f" … (+{hidden} more)"
        parts.append(
            f"⏩ **Excluded from analysis ({len(org.excluded_repos)}):** {names}"
        )
        parts.append("")
    for section in org.sections:
        parts.append(render_section(section, top_n=top_n))
        # The Dependabot configuration-posture sub-tables nest beneath the
        # Dependabot signal heading.
        if section.signal is SignalType.DEPENDABOT:
            parts.extend(
                render_table_section(table, level=3, top_n=top_n)
                for table in org.dependabot_tables
            )
    if org.releases is not None:
        parts.append(render_table_section(org.releases, level=2, top_n=top_n))
    return "\n".join(parts).rstrip() + "\n"


def render_report(report: Report, *, top_n: int | None = None) -> str:
    return (
        "\n\n".join(render_org(org, top_n=top_n) for org in report.orgs).rstrip()
        + "\n"
    )
