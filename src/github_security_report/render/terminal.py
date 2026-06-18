# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Rich terminal rendering.

The default presentation for local/TTY runs: one coloured table per signal,
worst-first, with clean/nag/unknown summaries beneath. The CLI falls back to a
plain console (no colour) in CI / non-TTY contexts. See ``docs/BRIEF.md``
sections 10-11.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

from rich.console import Console
from rich.table import Table

from github_security_report.models import Repo, RepoSignal, SignalType
from github_security_report.report import (
    OrgReport,
    SignalSection,
    TableSection,
    truncate,
)

_SEVERITY_STYLE = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "dim"}


def _split_sentences(text: str) -> list[str]:
    """Split a footnote into one sentence per line for readable terminal output.

    Splits on a sentence-ending period followed by whitespace, keeping the
    period. A semicolon does not end a sentence, so a clause such as
    "mandatory; any value passes." stays on one line. A single-sentence note is
    returned unchanged as one line.
    """
    parts = re.split(r"(?<=\.)\s+", text.strip())
    return [part for part in parts if part]


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


def _names(repos: Sequence[Repo], top_n: int | None) -> str:
    """Comma-joined repo names limited to ``top_n`` with a '(+N more)' tail."""
    shown, hidden = truncate(repos, top_n)
    text = ", ".join(r.name for r in shown)
    if hidden:
        text += f" … (+{hidden} more)"
    return text


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
        console.print(table)
        if hidden_offenders:
            console.print(f"  [dim]… and {hidden_offenders} more[/dim]")
    else:
        console.print(f"[bold]{section.signal.heading}[/bold]")
    # Numerical totals first (each on its own line, always the true total), then
    # the repository-name breakdowns -- numbers and names are never mixed on one
    # line, and the name lists honour the same offender limit as the tables.
    totals: list[str] = []
    if section.clean_count:
        totals.append(f"[green]✅ {section.clean_count} Clean[/green]")
    if section.nag_repos:
        totals.append(f"[yellow]❌ {len(section.nag_repos)} Disabled[/yellow]")
    if excluded:
        totals.append(f"[blue]⏩ {len(excluded)} Excluded[/blue]")
    if section.unknown_count:
        totals.append(f"[dim]❓ {section.unknown_count} Unknown[/dim]")
    if not (offenders or totals):
        totals.append("[dim]No data[/dim]")
    for line in totals:
        console.print("  " + line)
    if section.nag_repos:
        console.print(f"  [yellow]Disabled:[/yellow] {_names(section.nag_repos, top_n)}")
    if excluded:
        console.print(f"  [blue]Excluded:[/blue] {_names(excluded, top_n)}")
    console.print()


def render_table_section(
    section: TableSection, console: Console, *, top_n: int | None = None
) -> None:
    """Render a generic posture/freshness table to the terminal."""
    rows, hidden = truncate(section.rows, top_n)
    if rows:
        table = Table(title=section.title, title_justify="left", title_style="bold")
        for i, col in enumerate(section.columns):
            table.add_column(col, overflow="fold", justify="left" if i == 0 else "right")
        for row in rows:
            table.add_row(row.repo.name, *row.cells)
        console.print(table)
        if hidden:
            console.print(f"  [dim]… and {hidden} more[/dim]")
        if section.note:
            # A long footnote reads better split one sentence per line. It only
            # describes a populated table, so it is omitted when empty.
            for sentence in _split_sentences(section.note):
                console.print(f"  [dim]{sentence}[/dim]")
    else:
        console.print(f"[bold]{section.title}[/bold]")
        if section.empty_note:
            console.print(f"  [green]✅ {section.empty_note}[/green]")
    console.print()


def render_org(org: OrgReport, console: Console, *, top_n: int | None = None) -> None:
    console.rule(f"[bold]Security report: {org.org}[/bold]")
    console.print(f"[dim]{org.repo_count} repositories analysed[/dim]\n")
    if org.partial:
        console.print(
            "[yellow]⚠ Incomplete: the repository listing could not be fully "
            "read; some repositories may be missing.[/yellow]\n"
        )
    for section in org.sections:
        render_section(section, console, excluded=org.excluded_repos, top_n=top_n)
        if section.signal is SignalType.DEPENDABOT:
            for table in org.dependabot_tables:
                render_table_section(table, console, top_n=top_n)
    if org.releases is not None:
        render_table_section(org.releases, console, top_n=top_n)


def render_orgs(
    orgs: list[OrgReport], console: Console, *, top_n: int | None = None
) -> None:
    for org in orgs:
        render_org(org, console, top_n=top_n)
