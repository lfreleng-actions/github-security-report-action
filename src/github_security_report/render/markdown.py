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
from github_security_report.report import OrgReport, Report, SignalSection


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


def _table(section: SignalSection) -> list[str]:
    cols = _columns(section.signal)
    aligns = ["---"] + ["---:"] * (len(cols) - 1)
    lines = ["| " + " | ".join(cols) + " |", "| " + " | ".join(aligns) + " |"]
    for sig in section.offenders:
        lines.append("| " + " | ".join(_row(sig)) + " |")
    return lines


# Public, render-surface-agnostic accessors for the per-signal table shape, so
# other renderers (e.g. HTML) do not reach into this module's private helpers.
def columns(signal: SignalType) -> list[str]:
    """Column headings for a signal's offender table (repository first)."""
    return _columns(signal)


def row_cells(sig: RepoSignal) -> list[str]:
    """Cells for one offender row (the repository link is the first cell)."""
    return _row(sig)


def render_section(section: SignalSection) -> str:
    lines = [f"## {section.signal.heading}", ""]
    if section.offenders:
        lines.extend(_table(section))
        lines.append("")
    if section.clean_count:
        lines.append(f"✅ {section.clean_count} repositories clean")
        lines.append("")
    if section.nag_repos:
        lines.append("**Not enabled** — enable to appear in future reports:")
        lines.append("")
        lines.extend(f"- {_link(r)}" for r in section.nag_repos)
        lines.append("")
    if section.unknown_count:
        lines.append(
            f"ℹ️ {section.unknown_count} repositories with unknown status "
            "(insufficient permissions)"
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


def render_org(org: OrgReport) -> str:
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
    parts.extend(render_section(section) for section in org.sections)
    return "\n".join(parts).rstrip() + "\n"


def render_report(report: Report) -> str:
    return "\n\n".join(render_org(org) for org in report.orgs).rstrip() + "\n"
