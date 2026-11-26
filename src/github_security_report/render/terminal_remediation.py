# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Rich terminal rendering of a ``remediate`` run.

Kept apart from :mod:`github_security_report.render.terminal`, which renders
the report; this prints what a remediation run would change or changed.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from rich.console import Console
from rich.markup import escape

from github_security_report.remediate import CategoryRemediation, RepoOutcome
from github_security_report.render.terminal import _truncated_names
from github_security_report.render.terminal_notices import render_config_path
from github_security_report.report import SUMMARY_EMOJI


def _render_not_administered(
    console: Console, group: Sequence[RepoOutcome], top_n: int | None
) -> None:
    """Note, beneath a preview, the targets the account does not administer.

    They stay in the preview and its counts: admin access is sufficient for
    every write but not always required, so an apply still attempts them.
    """
    names = [o.name for o in group if o.admin is False]
    if names:
        console.print(
            f"    [yellow]{SUMMARY_EMOJI['unknown']}[/yellow] {len(names)} not "
            "administered by this account; GitHub may refuse those writes: "
            f"{escape(_truncated_names(names, top_n))}"
        )


def render_remediation(
    org: str,
    results: Sequence[CategoryRemediation],
    console: Console,
    *,
    apply: bool,
    top_n: int | None = None,
    limited_to: Sequence[str] = (),
    config_path: Path | None = None,
) -> None:
    """Render a remediation run: one block per category, with a trailing summary.

    Mirrors the report's inline style rather than a table: each category names
    the repositories it would enable / enabled (honouring ``top_n``) and lists
    refusals, skips and failures one per line with the reason. Dry run prints a
    leading notice; apply mode prints none (the writes finish before this
    renders), and a trailing summary totals the work across categories.
    """
    console.rule(f"[bold]Remediation: {escape(org)}[/bold]")
    render_config_path(console, config_path)
    # A narrowed run says so up front, so its results are not read as the
    # whole organisation's.
    if limited_to:
        console.print(f"[dim]Limited to: {escape(', '.join(limited_to))}[/dim]")
    # In apply mode the writes have already happened by the time this renders,
    # so a pre-amble banner would be misleading; only the dry-run notice (shown
    # before nothing is changed) is useful.
    if not apply:
        console.print(
            "[bold yellow]DRY RUN[/bold yellow] — no changes made. Re-run with "
            "[bold]--apply[/bold] to make changes.\n"
        )

    planned: dict[str, int] = {}
    changed: dict[str, int] = {}
    failed = 0
    withheld: dict[str, int] = {}
    for result in results:
        console.print(f"[bold]{result.category.title}[/bold]")
        # Classify by run mode and each outcome's own flags rather than by the
        # action string, so the renderer owns no copy of the action vocabulary
        # defined in remediate.py.
        failures = [o for o in result.outcomes if o.failed]
        # Refused and skipped targets are withheld alike: named, with the reason.
        held = [o for o in result.outcomes if o.refused or o.skipped]
        succeeded = [
            o for o in result.outcomes if not (o.failed or o.refused or o.skipped)
        ]
        if not result.outcomes:
            console.print("  [green]Nothing to remediate[/green]")
        # One line per verb, in the order the verbs first appear: a category
        # can both delete one configuration and re-enable another's workflow.
        for verb in dict.fromkeys(o.verb for o in succeeded):
            group = [o for o in succeeded if o.verb == verb]
            names = _truncated_names([o.name for o in group], top_n)
            if apply:
                console.print(
                    f"  [green]{SUMMARY_EMOJI['pass']}[/green] {len(group)} "
                    f"{escape(group[0].action)}: {escape(names)}"
                )
            else:
                console.print(
                    f"  [yellow]→[/yellow] {len(group)} would {escape(verb)}: "
                    f"{escape(names)}"
                )
                _render_not_administered(console, group, top_n)
        for outcome in held:
            console.print(
                f"  [yellow]{SUMMARY_EMOJI['unknown']}[/yellow] "
                f"{escape(outcome.name)} {escape(outcome.action)}: "
                f"{escape(outcome.note)}"
            )
            withheld[outcome.action] = withheld.get(outcome.action, 0) + 1
        for outcome in failures:
            detail = f": {escape(outcome.note)}" if outcome.note else ""
            console.print(
                f"  [red]{SUMMARY_EMOJI['fail']}[/red] {escape(outcome.name)} "
                f"failed{detail}"
            )
        tally = changed if apply else planned
        for outcome in succeeded:
            label = outcome.action if apply else outcome.verb
            tally[label] = tally.get(label, 0) + 1
        failed += len(failures)
        console.print()

    withheld_note = "".join(f", {n} {action}" for action, n in withheld.items())
    if apply:
        done = ", ".join(f"{n} {label}" for label, n in changed.items()) or "0 changed"
        console.print(f"[bold]Summary:[/bold] {done}, {failed} failed{withheld_note}.")
    else:
        todo = (
            ", ".join(f"{n} to {verb}" for verb, n in planned.items()) or "no changes"
        )
        console.print(
            f"[bold]Summary:[/bold] {todo} (dry run){withheld_note}. "
            "Re-run with [bold]--apply[/bold] to make changes."
        )
