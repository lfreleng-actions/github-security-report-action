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
from github_security_report.report import OrgReport, SignalSection


def _plain_columns(signal: SignalType) -> list[str]:
    if signal is SignalType.SECRET_SCANNING:
        return ["repo", "open"]
    if signal is SignalType.SCORECARD:
        return ["repo", "score", "C", "H", "M", "L"]
    return ["repo", "C", "H", "M", "L"]


def _plain_row(sig: RepoSignal) -> list[str]:
    c = sig.counts
    if sig.signal is SignalType.SECRET_SCANNING:
        return [sig.repo.name, str(c.total)]
    if sig.signal is SignalType.SCORECARD:
        score = f"{sig.score:.1f}" if sig.score is not None else "-"
        return [sig.repo.name, score, str(c.critical), str(c.high), str(c.medium), str(c.low)]
    return [sig.repo.name, str(c.critical), str(c.high), str(c.medium), str(c.low)]


def _fixed_table(section: SignalSection, top_n: int) -> str:
    cols = _plain_columns(section.signal)
    rows = [_plain_row(s) for s in section.top(top_n)]
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


def render_org_blocks(org: OrgReport, *, top_n: int, pages_url: str | None) -> list[dict]:
    """Slack blocks for one organisation."""
    blocks: list[dict] = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"🔐 Security report: {org.org}"},
        }
    ]
    for section in org.sections:
        summary = _summary(section)
        text = f"*{section.signal.heading}* — {summary}"
        if section.offenders:
            table = _fixed_table(section, top_n)
            text += f"\n```\n{table}\n```"
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": text}})
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


def render_payload(
    orgs: list[OrgReport], *, channel: str, top_n: int = 10, pages_url: str | None = None
) -> dict:
    """Build a ``chat.postMessage`` payload across one or more organisations."""
    blocks: list[dict] = []
    for org in orgs:
        blocks.extend(render_org_blocks(org, top_n=top_n, pages_url=pages_url))
    names = ", ".join(o.org for o in orgs)
    return {
        "channel": channel,
        "text": f"🔐 Security report: {names}",
        "blocks": blocks,
    }
