# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Rich terminal rendering.

The default presentation for local/TTY runs: one coloured table per signal,
worst-first, with clean/nag/unknown summaries beneath. The CLI falls back to a
plain console (no colour) in CI / non-TTY contexts. See ``docs/BRIEF.md``
sections 10-11.
"""

from __future__ import annotations

from rich.console import Console
from rich.table import Table

from github_security_report.models import RepoSignal, SignalType
from github_security_report.report import OrgReport, SignalSection

_SEVERITY_STYLE = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "dim"}


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


def render_section(section: SignalSection, console: Console) -> None:
    if section.offenders:
        table = Table(title=section.signal.heading, title_justify="left", title_style="bold")
        _add_columns(table, section.signal)
        for sig in section.offenders:
            table.add_row(*_row(sig))
        console.print(table)
    else:
        console.print(f"[bold]{section.signal.heading}[/bold]")
    notes = []
    if section.clean_count:
        notes.append(f"[green]✓ {section.clean_count} clean[/green]")
    if section.nag_repos:
        names = ", ".join(r.name for r in section.nag_repos)
        notes.append(f"[yellow]not enabled:[/yellow] {names}")
    if section.unknown_count:
        notes.append(f"[dim]{section.unknown_count} unknown[/dim]")
    if not (section.offenders or notes):
        notes.append("[dim]no data[/dim]")
    if notes:
        console.print("  " + "   ".join(notes))
    console.print()


def render_org(org: OrgReport, console: Console) -> None:
    console.rule(f"[bold]Security report: {org.org}[/bold]")
    console.print(f"[dim]{org.repo_count} repositories analysed[/dim]\n")
    for section in org.sections:
        render_section(section, console)


def render_orgs(orgs: list[OrgReport], console: Console) -> None:
    for org in orgs:
        render_org(org, console)
