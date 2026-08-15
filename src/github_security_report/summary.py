# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""The standardised summary footer shared by every reporting category.

Each category -- signal section or generic table -- ends with the same footer:
ordered count lines (failures first, the healthy pass line lower down, the
neutral excluded line last), with an ``All <pass>`` collapse when nothing needs
attention. Keeping that vocabulary here means the terminal, Slack, Markdown and
HTML surfaces cannot drift apart in wording, ordering or glyph.

This module deliberately depends on nothing else in the package, so both the
report structures and the renderers can import it without a cycle.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass


@dataclass(frozen=True)
class SummaryCount:
    """One labelled count feeding the standardised summary footer.

    ``kind`` selects the glyph, colour and ordering; ``names`` carries the
    repository names listed beneath the count line (used for the disabled and
    excluded kinds, where naming the repositories is actionable). ``render``
    false keeps the bucket out of the visible footer while still letting it
    count towards the "nothing needs attention" test that collapses the pass
    line to ``All <pass>``: a severity signal's offenders live in the table
    (not as a footer line), but they must still suppress a falsely reassuring
    ``All <pass>`` when the section is only partially clean.
    """

    kind: str  # "fail" | "disabled" | "unknown" | "pass" | "excluded"
    count: int
    label: str
    names: tuple[str, ...] = ()
    render: bool = True


@dataclass(frozen=True)
class SummaryLine:
    """A formatted summary footer line, ready for any render surface.

    ``kind`` lets each surface pick its own glyph/colour; ``text`` is the
    surface-agnostic body (e.g. ``"All Clean"`` or ``"1 Mutable"``).
    """

    kind: str
    text: str
    names: tuple[str, ...] = ()


# Footer ordering: actionable items first (failures, then not-enabled, then
# unknown), then the healthy pass line, then the neutral excluded line last.
# This tool drives remediation, so the work to do sits at the top.
_SUMMARY_ORDER = {"fail": 0, "disabled": 1, "unknown": 2, "pass": 3, "excluded": 4}

# Glyph per summary kind, shared by every render surface.
SUMMARY_EMOJI = {
    "fail": "\u274c",
    "disabled": "\u274c",
    "unknown": "\u2753",
    "pass": "\u2705",
    "excluded": "\u23e9",
}


def build_summary(counts: Sequence[SummaryCount]) -> list[SummaryLine]:
    """Turn raw count buckets into ordered, formatted summary lines.

    The single place every surface builds its under-table footer, so the
    wording, ordering and the ``All <pass>`` collapse behave identically
    everywhere. The pass line reads ``All <pass_label>`` -- with no number --
    only when nothing else needs attention (no failures, not-enabled, unknown
    or excluded repositories); otherwise every present bucket shows its count.
    Zero-valued buckets are dropped, as are buckets flagged ``render=False``
    (which still count towards the collapse test but emit no visible line).
    """
    present = [c for c in counts if c.count > 0]
    non_pass = sum(c.count for c in present if c.kind != "pass")
    lines: list[SummaryLine] = []
    for count in sorted(present, key=lambda c: _SUMMARY_ORDER[c.kind]):
        if not count.render:
            continue
        if count.kind == "pass" and non_pass == 0:
            text = f"All {count.label}"
        else:
            text = f"{count.count} {count.label}"
        lines.append(SummaryLine(kind=count.kind, text=text, names=count.names))
    return lines
