# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Rich terminal rendering.

The default presentation for local/TTY runs: one coloured table per signal,
worst-first, with clean/nag/unknown summaries beneath. The CLI falls back to a
plain console (no colour) in CI / non-TTY contexts. See ``docs/BRIEF.md``
sections 10-11.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence

from rich.console import Console
from rich.table import Table

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

_SEVERITY_STYLE = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "dim"}

# Rich style per summary-footer kind, shared by signal and table sections.
_SUMMARY_STYLE = {
    "fail": "red",
    "disabled": "yellow",
    "unknown": "dim",
    "pass": "green",
    "excluded": "blue",
}

# Label prefixing the repository-name list printed beneath a summary line.
_NAME_LIST_LABEL = {"disabled": "Disabled", "excluded": "Excluded"}


def _add_columns(table: Table, signal: SignalType) -> None:
    table.add_column("Repository", overflow="fold")
    if signal is SignalType.SECRET_SCANNING:
        table.add_column("Open", justify="right")
        return
    if signal is SignalType.SCORECARD:
        table.add_column("Score", justify="right")
    for name, style in _SEVERITY_STYLE.items():
        table.add_column(name.capitalize(), justify="right", style=style)
    if signal is not SignalType.SCORECARD:
        table.add_column("Total", justify="right")


def _row(sig: RepoSignal) -> list[str]:
    c = sig.counts
    if sig.signal is SignalType.SECRET_SCANNING:
        return [sig.repo.name, str(c.total)]
    base = [str(c.critical), str(c.high), str(c.medium), str(c.low)]
    if sig.signal is SignalType.SCORECARD:
        score = f"{sig.score:.1f}" if sig.score is not None else "—"
        return [sig.repo.name, score, *base]
    return [sig.repo.name, *base, str(c.total)]


def _truncated_names(names: Sequence[str], top_n: int | None) -> str:
    """Comma-joined names limited to ``top_n`` with a '(+N more)' tail."""
    shown, hidden = truncate(names, top_n)
    text = ", ".join(shown)
    if hidden:
        text += f" \u2026 (+{hidden} more)"
    return text


def _render_summary(
    console: Console, lines: Sequence[SummaryLine], *, top_n: int | None
) -> None:
    """Print the standardised footer: count lines, then any name lists.

    Counts come first (failures and not-enabled at the top, the healthy pass
    line lower down), then the repository-name breakdowns for the disabled and
    excluded kinds -- numbers and names are never mixed on one line, and the
    name lists honour the same offender limit as the tables.
    """
    for line in lines:
        style = _SUMMARY_STYLE[line.kind]
        console.print(f"  [{style}]{SUMMARY_EMOJI[line.kind]} {line.text}[/{style}]")
    for line in lines:
        label = _NAME_LIST_LABEL.get(line.kind)
        if label and line.names:
            style = _SUMMARY_STYLE[line.kind]
            console.print(
                f"  [{style}]{label}:[/{style}] "
                f"{_truncated_names(line.names, top_n)}"
            )


def render_section(
    section: SignalSection,
    console: Console,
    *,
    excluded: Sequence[Repo] = (),
    top_n: int | None = None,
) -> None:
    offenders, hidden_offenders = truncate(section.offenders, top_n)
    if offenders:
        table = Table(title=section.signal.heading, title_justify="left", title_style="bold")
        _add_columns(table, section.signal)
        for sig in offenders:
            table.add_row(*_row(sig))
        # A trailing totals row sums the additive severity columns across the
        # rows shown above. Secret scanning has no such columns, so skip it.
        if section.signal.uses_severity_columns:
            table.add_section()
            table.add_row(
                *markdown.total_row_cells(section.signal, offenders),
                style="bold",
            )
        console.print(table)
        if hidden_offenders:
            console.print(f"  [dim]\u2026 and {hidden_offenders} more[/dim]")
    else:
        console.print(f"[bold]{section.signal.heading}[/bold]")
    lines = build_summary(section.summary_counts(excluded))
    if lines:
        _render_summary(console, lines, top_n=top_n)
    elif not offenders:
        console.print("  [dim]No data[/dim]")
    console.print()


def render_table_section(
    section: TableSection,
    console: Console,
    *,
    excluded: Sequence[Repo] = (),
    top_n: int | None = None,
) -> None:
    """Render a generic posture/freshness table to the terminal.

    The explanatory description is deliberately omitted here: the terminal is a
    brevity-first surface, so the guidance text is reserved for the Markdown and
    HTML (GitHub Pages) outputs.
    """
    rows, hidden = truncate(section.rows, top_n)
    console.print(f"[bold]{section.title}[/bold]")
    if rows:
        table = Table(title_justify="left", title_style="bold")
        for i, col in enumerate(section.columns):
            table.add_column(col, overflow="fold", justify="left" if i == 0 else "right")
        for row in rows:
            table.add_row(row.repo.name, *row.cells)
        console.print(table)
        if hidden:
            console.print(f"  [dim]\u2026 and {hidden} more[/dim]")
    lines = build_summary(section.summary_counts(excluded))
    if lines:
        _render_summary(console, lines, top_n=top_n)
    elif not rows:
        console.print("  [dim]No data[/dim]")
    console.print()


def render_org(
    org: OrgReport,
    console: Console,
    *,
    top_n: int | None = None,
    show: Callable[[CategoryKey], bool] | None = None,
) -> None:
    visible = show or (lambda _key: True)
    console.rule(f"[bold]Security report: {org.org}[/bold]")
    console.print(f"[dim]{org.repo_count} repositories analysed[/dim]\n")
    if org.partial:
        console.print(
            "[yellow]\u26a0 Incomplete: the repository listing could not be fully "
            "read; some repositories may be missing.[/yellow]\n"
        )
    for section in org.sections:
        if visible(section.signal.category_key):
            render_section(
                section, console, excluded=org.excluded_repos, top_n=top_n
            )
        if section.signal is SignalType.DEPENDABOT:
            for table in org.dependabot_tables:
                if visible(table.category.key):
                    render_table_section(
                        table, console, excluded=org.excluded_repos, top_n=top_n
                    )
    if org.releases is not None and visible(org.releases.category.key):
        render_table_section(
            org.releases, console, excluded=org.excluded_repos, top_n=top_n
        )
    if org.mutable_releases is not None and visible(
        org.mutable_releases.category.key
    ):
        render_table_section(
            org.mutable_releases, console, excluded=org.excluded_repos, top_n=top_n
        )


def render_orgs(
    orgs: list[OrgReport], console: Console, *, top_n: int | None = None
) -> None:
    for org in orgs:
        render_org(org, console, top_n=top_n)
