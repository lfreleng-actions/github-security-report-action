# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""The plain-text pieces of a Slack block: tables, rows and footer lines.

Slack renders no real tables, so an offender or posture table is a
fixed-width text grid inside a code fence, and a footer is a run of
emoji-prefixed lines. These helpers build those strings; the block
assembly and the per-organisation layout stay in :mod:`.slack`.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

from github_security_report.models import RepoSignal, SignalType
from github_security_report.report import (
    SUMMARY_EMOJI,
    SignalSection,
    SummaryLine,
    offender_column_totals,
    section_shows_informational,
    truncate,
)

# The characters Slack's mrkdwn treats as control syntax: ``<...>`` is a link
# or a mention (``<!channel>`` pages everyone) and ``&`` starts an entity.
# Text from the API (workflow names, manifest paths) is escaped as Slack
# documents before it enters a block.
_MRKDWN_ESCAPES = str.maketrans({"&": "&amp;", "<": "&lt;", ">": "&gt;"})

# Line breaks and other control characters in a table cell would split its
# row, and a backtick run could close the code fence the table sits in.
_CELL_CONTROLS = re.compile(r"[\x00-\x1f\x7f\u2028\u2029]+")
# U+02CB MODIFIER LETTER GRAVE ACCENT looks like a backtick but closes no fence.
_FENCE_SAFE = str.maketrans({"`": "\u02cb"})


def _mrkdwn(text: str) -> str:
    """``text`` made inert for a Slack mrkdwn block."""
    return text.translate(_MRKDWN_ESCAPES)


def _fenced_cell(text: str) -> str:
    """A table cell made safe to sit on one line inside a code fence."""
    return _CELL_CONTROLS.sub(" ", text).translate(_FENCE_SAFE)


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
    followed by the name list of every line that names its repositories.
    Brevity-first, so no per-category description is emitted.

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
        if not line.listed:
            continue
        shown, hidden = truncate(line.names, names)
        names_text = ", ".join(shown)
        if hidden:
            names_text += f" … (+{hidden} more)"
        out.append(f"{line.names_label}: {names_text}")
    return "\n".join(out)


def _name_breaks(lines: Sequence[SummaryLine]) -> tuple[int, ...]:
    """Lengths of the rendered name lists, where the allowance stops being
    monotonic.

    A list completing mid-range drops its "… (+N more)" suffix, which can
    shorten the block even as the allowance rises. Handing these to
    :func:`fit_section_text` puts each transition on a search boundary.
    """
    return tuple(sorted({len(line.names) for line in lines if line.listed}))


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
    longest = max((len(line.names) for line in lines if line.listed), default=0)
    if top_n > 0:
        return min(top_n, longest)
    return longest


def _fixed_table_generic(columns: tuple[str, ...], rows: list[list[str]]) -> str:
    """Fixed-width text table for a generic posture/freshness table.

    Cells can carry repository-controlled text (a manifest path), so each is
    kept to one line and unable to close the surrounding code fence, and the
    padded line is mrkdwn-escaped last so the entities keep columns aligned.
    """
    grid = [[_fenced_cell(cell) for cell in row] for row in [list(columns), *rows]]
    widths = [len(c) for c in grid[0]]
    for row in grid[1:]:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))

    def fmt(row: list[str]) -> str:
        line = "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row))
        return _mrkdwn(line)

    return "\n".join(fmt(row) for row in grid)
