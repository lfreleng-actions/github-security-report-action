# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Slack rendering.

Slack mrkdwn cannot render Markdown tables, so the digest uses fixed-width
code-fenced blocks (the only way to align columns) showing the worst N
offenders per signal, plus a prominent link to the full GitHub Pages report.
Like the terminal, Slack is a brevity-first surface: it carries the
standardised summary footer but omits the per-category explanatory description.
Produces a ``chat.postMessage`` payload. See ``docs/BRIEF.md`` section 11.

Slack validates the payload as a whole and rejects all of it if any structural
limit is breached, so every block built here is sized by
:mod:`~github_security_report.render.slack_limits` before it is emitted.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence

from github_security_report.categories import CategoryKey
from github_security_report.models import Repo, RepoSignal, SignalType
from github_security_report.render.slack_limits import (
    MAX_TEXT_CHARS,
    context_block,
    enforce_block_limit,
    fallback_text,
    fit_section_text,
    header_block,
    text_length,
)
from github_security_report.report import (
    ORG_SETUP_DOC_URL,
    SKIP_MESSAGE,
    SUMMARY_EMOJI,
    LimitFor,
    OrgReport,
    SignalSection,
    SummaryLine,
    TableSection,
    build_summary,
    limit_resolver,
    offender_column_totals,
    section_shows_informational,
    table_column_totals,
    truncate,
)

# Summary kinds whose repository names are listed beneath the count line.
_NAME_LIST_LABEL = {"disabled": "Disabled", "excluded": "Excluded"}


def _plain_columns(signal: SignalType, *, informational: bool = False) -> list[str]:
    if signal is SignalType.SECRET_SCANNING:
        return ["Repository", "Open"]
    info = ["I"] if informational else []
    if signal is SignalType.SCORECARD:
        return ["Repository", "Score", "C", "H", "M", "L", *info]
    return ["Repository", "C", "H", "M", "L", *info]


def _plain_row(sig: RepoSignal, *, informational: bool = False) -> list[str]:
    c = sig.counts
    if sig.signal is SignalType.SECRET_SCANNING:
        return [sig.repo.name, str(c.total)]
    info = [str(c.informational)] if informational else []
    if sig.signal is SignalType.SCORECARD:
        score = f"{sig.score:.1f}" if sig.score is not None else "-"
        return [
            sig.repo.name,
            score,
            str(c.critical),
            str(c.high),
            str(c.medium),
            str(c.low),
            *info,
        ]
    return [
        sig.repo.name,
        str(c.critical),
        str(c.high),
        str(c.medium),
        str(c.low),
        *info,
    ]


def _plain_total_row(
    signal: SignalType, offenders: list[RepoSignal], *, informational: bool = False
) -> list[str]:
    """Trailing "Total" row summing the severity columns for Slack tables.

    Slack's fixed-width columns omit the Total column the other surfaces carry,
    so this matches ``_plain_row``'s shape rather than reusing the shared
    Markdown helper. Scorecard's score is not additive and is left blank.
    """
    totals = offender_column_totals(offenders)
    base = [
        str(totals.critical),
        str(totals.high),
        str(totals.medium),
        str(totals.low),
    ]
    info = [str(totals.informational)] if informational else []
    if signal is SignalType.SCORECARD:
        return ["Total", "", *base, *info]
    return ["Total", *base, *info]


def _fixed_table(section: SignalSection, shown_count: int) -> str:
    """The fenced offender table showing the first ``shown_count`` rows.

    Takes an absolute row count rather than a limit so the character budget in
    :mod:`~github_security_report.render.slack_limits` can shed rows further
    without a second truncation mechanism: the hidden tally is always derived
    from the full offender list, so it stays honest no matter which cap did the
    trimming.
    """
    shown = section.offenders[:shown_count]
    hidden = len(section.offenders) - len(shown)
    informational = section_shows_informational(shown)
    cols = _plain_columns(section.signal, informational=informational)
    rows = [_plain_row(s, informational=informational) for s in shown]
    # A trailing totals row sums the additive severity columns; secret scanning
    # has no such columns, so skip it. Summed over the shown (truncated) rows.
    if section.signal.uses_severity_columns and shown:
        rows.append(
            _plain_total_row(section.signal, shown, informational=informational)
        )
    widths = [len(c) for c in cols]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))

    # First column left-aligned (repo name), numeric columns right-aligned.
    def fmt(row: list[str]) -> str:
        cells = [row[0].ljust(widths[0])]
        cells += [row[i].rjust(widths[i]) for i in range(1, len(row))]
        return "  ".join(cells)

    lines = [fmt(cols)] + [fmt(row) for row in rows]
    if hidden:
        # Match the posture/release tables: surface the hidden count.
        lines.append(f"… and {hidden} more")
    return "\n".join(lines)


def _summary_text(lines: Sequence[SummaryLine], *, names: int) -> str:
    """The standardised footer as Slack mrkdwn: count lines then name lists.

    One line per count (failures first), each prefixed with its shared glyph,
    followed by the disabled/excluded repository name lists. Brevity-first, so
    no per-category description is emitted.

    ``names`` caps each name list at an absolute number of entries. It is
    resolved by :func:`_name_cap` before it gets here, so ``0`` means "list no
    names" -- not ``truncate``'s "no limit" -- and drops the enumerations
    entirely. Nothing is lost by that: every name list has a count line above
    it, and the count lines always survive.
    """
    out: list[str] = []
    for line in lines:
        out.append(f"{SUMMARY_EMOJI[line.kind]} {line.text}")
    if names <= 0:
        return "\n".join(out)
    for line in lines:
        label = _NAME_LIST_LABEL.get(line.kind)
        if not (label and line.names):
            continue
        shown, hidden = truncate(line.names, names)
        names_text = ", ".join(shown)
        if hidden:
            names_text += f" … (+{hidden} more)"
        out.append(f"{label}: {names_text}")
    return "\n".join(out)


def _name_breaks(lines: Sequence[SummaryLine]) -> tuple[int, ...]:
    """Lengths of the rendered name lists, where the allowance stops being
    monotonic.

    A list completing mid-range drops its "… (+N more)" suffix, which can
    shorten the block even as the allowance rises. Handing these to
    :func:`fit_section_text` puts each transition on a search boundary.
    """
    return tuple(
        sorted(
            {
                len(line.names)
                for line in lines
                if line.kind in _NAME_LIST_LABEL and line.names
            }
        )
    )


def _name_cap(lines: Sequence[SummaryLine], top_n: int) -> int:
    """Resolve the configured limit into an absolute name-list allowance.

    ``top_n`` carries the documented "``0`` means no limit" convention, which
    the character budget cannot work with -- it needs to be able to ask for
    *fewer* names, including none. Resolving "no limit" to the longest list
    present makes every allowance an ordinary count.

    The result is bounded by that longest list either way. ``top_n`` is
    operator-supplied with no schema maximum, and an allowance beyond the names
    that exist renders identically to one that stops at them -- so passing the
    raw value through would only make the budget's search probe a wide range of
    indistinguishable outcomes before it could move on to shedding rows.
    """
    longest = max((len(line.names) for line in lines), default=0)
    if top_n > 0:
        return min(top_n, longest)
    return longest


def _fixed_table_generic(columns: tuple[str, ...], rows: list[list[str]]) -> str:
    """Fixed-width text table for a generic posture/freshness table."""
    widths = [len(c) for c in columns]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))

    def fmt(row: list[str]) -> str:
        return "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row))

    lines = [fmt(list(columns))] + [fmt(row) for row in rows]
    return "\n".join(lines)


def _table_block(
    section: TableSection, top_n: int, *, excluded: Sequence[Repo]
) -> dict | None:
    """A Slack section block for a posture/freshness table (None when empty).

    The block is emitted whenever there is something to say -- offender rows or a
    non-empty standardised summary footer -- so a clean category still surfaces
    its "All <pass>" line. A table with neither rows nor any countable state
    (genuinely no data) is skipped, keeping the brevity-first digest tight. The
    explanatory description is omitted: Slack is a brevity-first surface.
    """
    lines = build_summary(section.summary_counts(excluded))
    row_cap = len(truncate(section.rows, top_n)[0])
    name_cap = _name_cap(lines, top_n)
    if not row_cap and not _summary_text(lines, names=name_cap):
        return None

    def build(rows: int, names: int) -> str:
        text = f"*{section.title}*"
        if rows:
            shown = section.rows[:rows]
            cells = [[row.repo.name, *row.cells] for row in shown]
            totals = table_column_totals(section, shown)
            if totals is not None:
                cells.append(list(totals))
            table = _fixed_table_generic(section.columns, cells)
            hidden = len(section.rows) - len(shown)
            if hidden:
                table += f"\n… and {hidden} more"
            text += f"\n```\n{table}\n```"
        summary = _summary_text(lines, names=names)
        if summary:
            text += f"\n{summary}"
        return text

    return {
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": fit_section_text(
                build,
                rows=row_cap,
                names=name_cap,
                name_breaks=_name_breaks(lines),
            ),
        },
    }


def _signal_block(
    section: SignalSection, top_n: int, *, excluded: Sequence[Repo]
) -> dict:
    """A Slack section block for one signal's offender table and footer."""
    lines = build_summary(section.summary_counts(excluded))

    def build(rows: int, names: int) -> str:
        text = f"*{section.signal.heading}*"
        if section.offenders:
            text += f"\n```\n{_fixed_table(section, rows)}\n```"
        summary = _summary_text(lines, names=names)
        if summary:
            text += f"\n{summary}"
        elif not section.offenders:
            # Only genuine absence of data (no rows and no countable state)
            # warrants "no data"; an all-offender table has nothing to add.
            text += "\nno data"
        return text

    row_cap = len(truncate(section.offenders, top_n)[0])
    text = fit_section_text(
        build,
        rows=row_cap,
        names=_name_cap(lines, top_n),
        name_breaks=_name_breaks(lines),
    )
    return {"type": "section", "text": {"type": "mrkdwn", "text": text}}


def render_org_blocks(
    org: OrgReport,
    *,
    top_n: int,
    pages_url: str | None,
    show: Callable[[CategoryKey], bool] | None = None,
    limit: LimitFor | None = None,
) -> list[dict]:
    """Slack blocks for one organisation."""
    visible = show or (lambda _key: True)
    resolve = limit_resolver(top_n, limit)

    def limit_for(key: CategoryKey) -> int:
        # Slack's helpers take a plain int; ``truncate`` treats None and 0
        # identically (both mean "no limit"), so normalise None to 0 here.
        return resolve(key) or 0

    blocks: list[dict] = [header_block(f"🔐 Security report: {org.org}")]
    if org.partial:
        blocks.append(
            context_block(
                "⚠️ Incomplete: the repository listing could not "
                "be fully read; some repositories may be missing."
            )
        )
    excluded = org.excluded_repos

    def add_table(section: TableSection | None) -> None:
        """Append one extra table's block, honouring its visibility and limit."""
        if section is None or not visible(section.category.key):
            return
        block = _table_block(
            section, limit_for(section.category.key), excluded=excluded
        )
        if block is not None:
            blocks.append(block)

    for section in org.sections:
        key = section.signal.category_key
        if visible(key):
            if section.skipped:
                # Feature gating found no organisation support: one skip line
                # linking the setup guide, instead of a table and footer.
                text = (
                    f"*{section.signal.heading}*"
                    f"\n{SUMMARY_EMOJI['excluded']} {SKIP_MESSAGE} — "
                    f"<{ORG_SETUP_DOC_URL}|setup guide>"
                )
                blocks.append(
                    {"type": "section", "text": {"type": "mrkdwn", "text": text}}
                )
                continue
            blocks.append(_signal_block(section, limit_for(key), excluded=excluded))
        # Dependabot posture sub-tables follow the Dependabot signal block.
        if section.signal is SignalType.DEPENDABOT:
            for table_section in org.dependabot_tables:
                add_table(table_section)
    add_table(org.releases)
    add_table(org.mutable_releases)
    add_table(org.private_vulnerability_reporting)
    add_table(org.issues)
    if pages_url:
        link = f"<{pages_url}|View the full report>"
        # Omit the link rather than clamp it: a cut URL resolves elsewhere,
        # which is a wrong answer rather than a missing one.
        if text_length(link) <= MAX_TEXT_CHARS:
            blocks.append(context_block(link))
    return blocks


def render_payload(
    orgs: list[OrgReport],
    *,
    channel: str,
    top_n: int = 10,
    pages_url: str | None = None,
    show: Callable[[CategoryKey], bool] | None = None,
    limit: LimitFor | None = None,
) -> dict:
    """Build a ``chat.postMessage`` payload across one or more organisations."""
    blocks: list[dict] = []
    for org in orgs:
        blocks.extend(
            render_org_blocks(
                org, top_n=top_n, pages_url=pages_url, show=show, limit=limit
            )
        )
    blocks = enforce_block_limit(blocks, pages_url)
    names = ", ".join(o.org for o in orgs)
    return {
        "channel": channel,
        "text": fallback_text(f"🔐 Security report: {names}"),
        "blocks": blocks,
    }
