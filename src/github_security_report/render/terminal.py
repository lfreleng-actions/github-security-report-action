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
from dataclasses import replace

from rich.console import Console
from rich.markup import escape
from rich.table import Table
from rich.text import Text

from github_security_report.categories import CategoryKey
from github_security_report.models import Repo, RepoSignal, SignalType
from github_security_report.remediate import CategoryRemediation
from github_security_report.render import markdown
from github_security_report.report import (
    CELL_BAD,
    CELL_GOOD,
    CELL_WARN,
    ORG_SETUP_DOC_URL,
    SKIP_MESSAGE,
    SUMMARY_EMOJI,
    LimitFor,
    OrgReport,
    SignalSection,
    SummaryLine,
    TableRow,
    TableSection,
    build_summary,
    limit_resolver,
    section_shows_informational,
    table_column_totals,
    table_footer_rows,
    truncate,
)

_SEVERITY_STYLE = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "dim",
}

# The sub-low Informational column (shown only when a table carries note-level
# findings) is the least urgent, so it is dimmed like the Low column.
_INFORMATIONAL_STYLE = "dim"

# Rich style per summary-footer kind, shared by signal and table sections.
_SUMMARY_STYLE = {
    "fail": "red",
    "disabled": "yellow",
    "unknown": "dim",
    "pass": "green",
    "excluded": "blue",
}

# Rich style per semantic cell level, for the builders that emphasise a cell
# (see ``report.CELL_LEVELS``). The terminal is the only surface that renders
# these: Markdown and Slack have no colour, and the HTML pages style their
# tables from the stylesheet.
_CELL_LEVEL_STYLE = {
    CELL_GOOD: "green",
    CELL_WARN: "yellow",
    CELL_BAD: "red",
}

# Label prefixing the repository-name list printed beneath a summary line.
_NAME_LIST_LABEL = {"disabled": "Disabled", "excluded": "Excluded"}


def _add_columns(
    table: Table, signal: SignalType, *, informational: bool = False
) -> None:
    table.add_column("Repository", overflow="fold")
    if signal is SignalType.SECRET_SCANNING:
        table.add_column("Open", justify="right")
        return
    if signal is SignalType.SCORECARD:
        table.add_column("Score", justify="right")
    for name, style in _SEVERITY_STYLE.items():
        table.add_column(name.capitalize(), justify="right", style=style)
    if informational:
        table.add_column("Info", justify="right", style=_INFORMATIONAL_STYLE)
    table.add_column("Total", justify="right")


def _row(sig: RepoSignal, *, informational: bool = False) -> list[str]:
    c = sig.counts
    if sig.signal is SignalType.SECRET_SCANNING:
        return [sig.repo.name, str(c.total)]
    base = [str(c.critical), str(c.high), str(c.medium), str(c.low)]
    info = [str(c.informational)] if informational else []
    score = (
        [f"{sig.score:.1f}" if sig.score is not None else "—"]
        if sig.signal is SignalType.SCORECARD
        else []
    )
    return [sig.repo.name, *score, *base, *info, str(c.total)]


def _truncated_names(names: Sequence[str], top_n: int | None) -> str:
    """Comma-joined names limited to ``top_n`` with a '(+N more)' tail."""
    shown, hidden = truncate(names, top_n)
    text = ", ".join(shown)
    if hidden:
        text += f" \u2026 (+{hidden} more)"
    return text


def _render_summary(
    console: Console,
    lines: Sequence[SummaryLine],
    *,
    top_n: int | None,
    name_labels: dict[str, str] | None = None,
) -> None:
    """Print the standardised footer: count lines, then any name lists.

    Counts come first (failures and not-enabled at the top, the healthy pass
    line lower down), then the repository-name breakdowns for the kinds in
    ``name_labels`` -- numbers and names are never mixed on one line, and the
    name lists honour the same offender limit as the tables. ``name_labels``
    defaults to the disabled/excluded kinds; a boolean feature table passes an
    extended map so its offenders list inline under the fail line too.
    """
    if name_labels is None:
        name_labels = _NAME_LIST_LABEL
    for line in lines:
        style = _SUMMARY_STYLE[line.kind]
        console.print(f"  [{style}]{SUMMARY_EMOJI[line.kind]} {line.text}[/{style}]")
    for line in lines:
        label = name_labels.get(line.kind)
        if label and line.names:
            style = _SUMMARY_STYLE[line.kind]
            console.print(
                f"  [{style}]{label}:[/{style}] {_truncated_names(line.names, top_n)}"
            )


def render_section(
    section: SignalSection,
    console: Console,
    *,
    excluded: Sequence[Repo] = (),
    top_n: int | None = None,
) -> None:
    if section.skipped:
        # Feature gating found no organisation support: one line, no table, no
        # footer -- plus a dim pointer at the setup guide.
        console.print(f"[bold]{section.signal.heading}[/bold]")
        console.print(f"  [blue]{SUMMARY_EMOJI['excluded']} {SKIP_MESSAGE}[/blue]")
        console.print(f"  [dim]Setup guide: {ORG_SETUP_DOC_URL}[/dim]")
        console.print()
        return
    offenders, hidden_offenders = truncate(section.offenders, top_n)
    if offenders:
        informational = section_shows_informational(offenders)
        table = Table(
            title=section.signal.heading, title_justify="left", title_style="bold"
        )
        _add_columns(table, section.signal, informational=informational)
        for sig in offenders:
            table.add_row(*_row(sig, informational=informational))
        # A trailing totals row sums the additive severity columns across the
        # rows shown above. Secret scanning has no such columns, so skip it.
        if section.signal.uses_severity_columns:
            table.add_section()
            table.add_row(
                *markdown.total_row_cells(
                    section.signal, offenders, informational=informational
                ),
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


def _styled_cells(row: TableRow) -> list[Text | str]:
    """A row's cells, each carrying the emphasis its builder asked for.

    An emphasised cell becomes a :class:`~rich.text.Text`, which Rich renders
    literally, so the style is applied without the cell's own content ever being
    parsed as markup. Unemphasised cells keep the existing escaped-string path.
    """
    out: list[Text | str] = []
    for index, cell in enumerate(row.cells):
        style = _CELL_LEVEL_STYLE.get(row.level(index) or "")
        out.append(Text(cell, style=style) if style else escape(cell))
    return out


def render_table_section(
    section: TableSection,
    console: Console,
    *,
    excluded: Sequence[Repo] = (),
    top_n: int | None = None,
) -> None:
    """Render a generic posture/freshness table to the terminal.

    A section with a single column carries only repository names -- a boolean
    feature check (enabled/not enabled) with no qualitative data -- so it is
    rendered like a signal section: no table, just the standardised footer with
    the offenders listed inline under the fail line (e.g. ``Not enabled:``).
    Tables are reserved for sections whose extra columns carry qualitative data
    that cannot be expressed as a count (release/tag ages, ecosystems, release
    tags). The explanatory description is deliberately omitted either way: the
    terminal is a brevity-first surface, so the guidance text is reserved for
    the Markdown and HTML (GitHub Pages) outputs.
    """
    inline = len(section.columns) == 1
    rows, hidden = truncate(section.rows, top_n)
    console.print(f"[bold]{section.title}[/bold]")
    if not inline and rows:
        table = Table(title_justify="left", title_style="bold")
        for i, col in enumerate(section.columns):
            # Headers and cells are escaped because both carry text from
            # outside this module -- a configured `issue_labels` column name, a
            # release tag -- and Rich would otherwise read a stray '[' as
            # markup and raise mid-render, taking the whole report with it.
            table.add_column(
                escape(col), overflow="fold", justify="left" if i == 0 else "right"
            )
        for row in rows:
            table.add_row(escape(row.repo.name), *_styled_cells(row))
        # A trailing totals row sums the numeric columns across the rows shown
        # above, matching the offender tables.
        totals = table_column_totals(section, rows)
        if totals is not None:
            table.add_section()
            table.add_row(*totals, style="bold")
        # Aggregate rows beneath the totals: a breakdown of the same rows,
        # arriving full width with the value under the final column.
        footer = table_footer_rows(section, rows)
        if footer:
            table.add_section()
            for cells in footer:
                table.add_row(*(escape(cell) for cell in cells))
        console.print(table)
        if hidden:
            console.print(f"  [dim]\u2026 and {hidden} more[/dim]")
    counts = section.summary_counts(excluded)
    name_labels = _NAME_LIST_LABEL
    if inline:
        # Surface the offenders inline under the fail line, labelled with the
        # category's fail wording (e.g. "Not enabled"), instead of a one-column
        # table. The name list honours top_n like every other breakdown.
        fail_label = section.category.fail_label or "Failing"
        counts = [
            replace(c, names=tuple(r.repo.name for r in section.rows))
            if c.kind == "fail"
            else c
            for c in counts
        ]
        name_labels = {**_NAME_LIST_LABEL, "fail": fail_label}
    lines = build_summary(counts)
    if lines:
        _render_summary(console, lines, top_n=top_n, name_labels=name_labels)
    elif not rows:
        console.print("  [dim]No data[/dim]")
    console.print()


def render_org(
    org: OrgReport,
    console: Console,
    *,
    top_n: int | None = None,
    show: Callable[[CategoryKey], bool] | None = None,
    limit: LimitFor | None = None,
) -> None:
    visible = show or (lambda _key: True)
    limit_for = limit_resolver(top_n, limit)

    def table(section: TableSection | None) -> None:
        """Render one extra table, honouring its own visibility and limit."""
        if section is None or not visible(section.category.key):
            return
        render_table_section(
            section,
            console,
            excluded=org.excluded_repos,
            top_n=limit_for(section.category.key),
        )

    console.rule(f"[bold]Security report: {org.org}[/bold]")
    console.print(f"[dim]{org.repo_count} repositories analysed[/dim]\n")
    if org.partial:
        console.print(
            "[yellow]\u26a0 Incomplete: the repository listing could not be fully "
            "read; some repositories may be missing.[/yellow]\n"
        )
    for section in org.sections:
        key = section.signal.category_key
        if visible(key):
            render_section(
                section, console, excluded=org.excluded_repos, top_n=limit_for(key)
            )
        if section.signal is SignalType.DEPENDABOT:
            for dependabot_table in org.dependabot_tables:
                table(dependabot_table)
    table(org.releases)
    table(org.mutable_releases)
    table(org.private_vulnerability_reporting)
    table(org.issues)
    table(org.pull_requests)
    table(org.assigned_pull_requests)


def render_orgs(
    orgs: list[OrgReport], console: Console, *, top_n: int | None = None
) -> None:
    for org in orgs:
        render_org(org, console, top_n=top_n)


def render_remediation(
    org: str,
    results: Sequence[CategoryRemediation],
    console: Console,
    *,
    apply: bool,
    top_n: int | None = None,
) -> None:
    """Render a remediation run: one block per category, with a trailing summary.

    Mirrors the report's inline style rather than a table: each category names
    the repositories it would enable / enabled (honouring ``top_n``) and lists
    any failures one per line with their diagnostic. Dry run prints a leading
    notice; apply mode prints none (the writes finish before this renders), and
    a trailing summary totals the work across categories.
    """
    console.rule(f"[bold]Remediation: {escape(org)}[/bold]")
    # In apply mode the writes have already happened by the time this renders,
    # so a pre-amble banner would be misleading; only the dry-run notice (shown
    # before nothing is changed) is useful.
    if not apply:
        console.print(
            "[bold yellow]DRY RUN[/bold yellow] — no changes made. Re-run with "
            "[bold]--apply[/bold] to enable features.\n"
        )

    planned = 0
    changed = 0
    failed = 0
    for result in results:
        console.print(f"[bold]{result.category.title}[/bold]")
        # Classify by run mode and each outcome's own failed flag rather than
        # by the action string, so the renderer owns no copy of the action
        # vocabulary defined in remediate.py.
        failures = [o for o in result.outcomes if o.failed]
        succeeded = [o for o in result.outcomes if not o.failed]
        would = succeeded if not apply else []
        enabled = succeeded if apply else []
        if not result.outcomes:
            console.print("  [green]Nothing to remediate[/green]")
        if would:
            names = _truncated_names([o.name for o in would], top_n)
            console.print(
                f"  [yellow]→[/yellow] {len(would)} would enable: {escape(names)}"
            )
        if enabled:
            names = _truncated_names([o.name for o in enabled], top_n)
            console.print(
                f"  [green]{SUMMARY_EMOJI['pass']}[/green] {len(enabled)} enabled: "
                f"{escape(names)}"
            )
        for outcome in failures:
            detail = f": {escape(outcome.note)}" if outcome.note else ""
            console.print(
                f"  [red]{SUMMARY_EMOJI['fail']}[/red] {escape(outcome.name)} "
                f"failed{detail}"
            )
        planned += len(would)
        changed += len(enabled)
        failed += len(failures)
        console.print()

    if apply:
        console.print(f"[bold]Summary:[/bold] {changed} enabled, {failed} failed.")
    else:
        console.print(
            f"[bold]Summary:[/bold] {planned} to enable (dry run). Re-run with "
            "[bold]--apply[/bold] to make changes."
        )
