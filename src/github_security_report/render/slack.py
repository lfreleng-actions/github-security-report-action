# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Slack rendering.

Slack mrkdwn cannot render Markdown tables, so the digest uses fixed-width
code-fenced blocks (the only way to align columns) showing the worst N
offenders per signal, plus a prominent link to the full GitHub Pages report.
Produces a ``chat.postMessage`` payload. See ``docs/BRIEF.md`` section 11.
"""

from __future__ import annotations

from github_security_report.models import RepoSignal, SignalType
from github_security_report.report import (
    OrgReport,
    SignalSection,
    TableSection,
    offender_column_totals,
    truncate,
)

# Slack rejects a chat.postMessage with more than 50 blocks, so a digest
# spanning many orgs must be capped or the whole message fails to deliver.
_SLACK_MAX_BLOCKS = 50


def _plain_columns(signal: SignalType) -> list[str]:
    if signal is SignalType.SECRET_SCANNING:
        return ["Repository", "Open"]
    if signal is SignalType.SCORECARD:
        return ["Repository", "Score", "C", "H", "M", "L"]
    return ["Repository", "C", "H", "M", "L"]


def _plain_row(sig: RepoSignal) -> list[str]:
    c = sig.counts
    if sig.signal is SignalType.SECRET_SCANNING:
        return [sig.repo.name, str(c.total)]
    if sig.signal is SignalType.SCORECARD:
        score = f"{sig.score:.1f}" if sig.score is not None else "-"
        return [sig.repo.name, score, str(c.critical), str(c.high), str(c.medium), str(c.low)]
    return [sig.repo.name, str(c.critical), str(c.high), str(c.medium), str(c.low)]


def _plain_total_row(
    signal: SignalType, offenders: list[RepoSignal]
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
    if signal is SignalType.SCORECARD:
        return ["Total", "", *base]
    return ["Total", *base]


def _fixed_table(section: SignalSection, top_n: int) -> str:
    cols = _plain_columns(section.signal)
    shown, hidden = truncate(section.offenders, top_n)
    rows = [_plain_row(s) for s in shown]
    # A trailing totals row sums the additive severity columns; secret scanning
    # has no such columns, so skip it. Summed over the shown (truncated) rows.
    if section.signal.uses_severity_columns and shown:
        rows.append(_plain_total_row(section.signal, shown))
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


def _summary(section: SignalSection) -> str:
    bits = []
    if section.offenders:
        bits.append(f"{len(section.offenders)} with findings")
    if section.clean_count:
        bits.append(f"{section.clean_count} clean")
    if section.nag_repos:
        bits.append(f"{len(section.nag_repos)} not enabled")
    if section.unknown_count:
        bits.append(f"{section.unknown_count} unknown")
    return ", ".join(bits) or "no data"


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


def _table_block(section: TableSection, top_n: int) -> dict | None:
    """A Slack section block for a posture/freshness table (None when empty).

    Emoji cell glyphs are dropped from the fixed-width rendering so columns stay
    aligned in Slack's monospace block; only the worst ``top_n`` rows are shown.
    """
    if not section.rows:
        return None
    shown, hidden = truncate(section.rows, top_n)
    rows = [
        [row.repo.name, *(cell.replace("✅", "y").replace("❌", "n").replace("❓", "?") for cell in row.cells)]
        for row in shown
    ]
    table = _fixed_table_generic(section.columns, rows)
    if hidden:
        table += f"\n… and {hidden} more"
    # The count summary is placed on its own line beneath the table rather than
    # inline with the title, matching every other category.
    text = f"*{section.title}*\n```\n{table}\n```"
    # Surface the explanatory note outside the code fence, before the summary,
    # so Slack users get the same guidance text as the Markdown/terminal/HTML
    # renderers. The note only describes a populated table, which is always the
    # case here (empty tables return None above).
    if section.note:
        text += f"\n{section.note}"
    if section.summary:
        text += f"\n{section.summary}"
    return {
        "type": "section",
        "text": {"type": "mrkdwn", "text": text},
    }


def render_org_blocks(org: OrgReport, *, top_n: int, pages_url: str | None) -> list[dict]:
    """Slack blocks for one organisation."""
    blocks: list[dict] = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"🔐 Security report: {org.org}"},
        }
    ]
    if org.partial:
        blocks.append(
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": "⚠️ Incomplete: the repository listing could not "
                        "be fully read; some repositories may be missing.",
                    }
                ],
            }
        )
    if org.excluded_repos:
        shown, hidden = truncate(org.excluded_repos, top_n)
        names = ", ".join(r.name for r in shown)
        if hidden:
            names += f" … (+{hidden} more)"
        blocks.append(
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"⏩ Excluded from analysis "
                        f"({len(org.excluded_repos)}): {names}",
                    }
                ],
            }
        )
    for section in org.sections:
        summary = _summary(section)
        text = f"*{section.signal.heading}*"
        if section.offenders:
            table = _fixed_table(section, top_n)
            text += f"\n```\n{table}\n```"
        # The count summary is placed on its own line beneath the table rather
        # than inline with the heading, matching every other category.
        text += f"\n{summary}"
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": text}})
        # Dependabot posture sub-tables follow the Dependabot signal block.
        if section.signal is SignalType.DEPENDABOT:
            for table_section in org.dependabot_tables:
                block = _table_block(table_section, top_n)
                if block is not None:
                    blocks.append(block)
    if org.releases is not None:
        block = _table_block(org.releases, top_n)
        if block is not None:
            blocks.append(block)
    if org.mutable_releases is not None:
        block = _table_block(org.mutable_releases, top_n)
        if block is not None:
            blocks.append(block)
    if pages_url:
        blocks.append(
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": f"<{pages_url}|View the full report>"}
                ],
            }
        )
    return blocks


def _enforce_block_limit(blocks: list[dict], pages_url: str | None) -> list[dict]:
    """Cap blocks at Slack's per-message limit, noting any truncation.

    A digest covering many orgs can exceed 50 blocks, which makes Slack reject
    the entire message (no digest delivered). Keep the first blocks and replace
    the overflow with a single note pointing at the full report.
    """
    if len(blocks) <= _SLACK_MAX_BLOCKS:
        return blocks
    if pages_url:
        note = (
            f"… digest truncated to Slack's {_SLACK_MAX_BLOCKS}-block limit; "
            f"<{pages_url}|view the full report>."
        )
    else:
        note = f"… digest truncated to Slack's {_SLACK_MAX_BLOCKS}-block limit."
    kept = blocks[: _SLACK_MAX_BLOCKS - 1]
    kept.append({"type": "context", "elements": [{"type": "mrkdwn", "text": note}]})
    return kept


def render_payload(
    orgs: list[OrgReport], *, channel: str, top_n: int = 10, pages_url: str | None = None
) -> dict:
    """Build a ``chat.postMessage`` payload across one or more organisations."""
    blocks: list[dict] = []
    for org in orgs:
        blocks.extend(render_org_blocks(org, top_n=top_n, pages_url=pages_url))
    blocks = _enforce_block_limit(blocks, pages_url)
    names = ", ".join(o.org for o in orgs)
    return {
        "channel": channel,
        "text": f"🔐 Security report: {names}",
        "blocks": blocks,
    }
