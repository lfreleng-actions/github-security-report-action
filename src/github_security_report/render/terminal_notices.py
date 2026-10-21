# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""The one-line notices printed directly beneath a terminal run's divider.

Each describes the run rather than a category: which configuration file it
auto-discovered, and whether organisation membership could be read. They print
once per organisation, under its heading, so they never land above the divider
among whatever collection logged.
"""

from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.markup import escape

from github_security_report.authors import MembershipGap
from github_security_report.report import OrgReport

# One line per cause: each names a different fix.
_MEMBERSHIP_WARNINGS: dict[MembershipGap, str] = {
    MembershipGap.PERMISSION: "Token lacks read/organisation permission",
    MembershipGap.NOT_MEMBER: "Token's account is not a member of {org}",
    MembershipGap.UNREADABLE: "Organisation membership could not be read",
}


def render_config_path(console: Console, config_path: Path | None) -> None:
    """Name the auto-discovered config file, when there is one."""
    if config_path is not None:
        console.print(f"[dim]Using config: {escape(str(config_path))}[/dim]")


def render_membership_gap(console: Console, org: OrgReport) -> None:
    """Warn that the organisation's author counts are a lower bound, and why.

    Without membership, ``Ext`` in the author-aware tables undercounts. The
    Markdown and HTML tables say so in their descriptions; the terminal omits
    descriptions, so this line is its only signal.
    """
    if org.membership_gap is None:
        return
    name = escape(org.org)
    reason = _MEMBERSHIP_WARNINGS[org.membership_gap].format(org=name)
    console.print(
        f"[yellow]\u26a0\ufe0f {reason}; results incomplete for {name}[/yellow]"
    )
