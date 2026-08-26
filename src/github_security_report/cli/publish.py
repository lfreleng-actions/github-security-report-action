# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""The publish stage of an org-mode run: Pages files, Slack digest, summary.

Everything an org-mode run emits once collection and terminal rendering are
done. Split from the run modes themselves so ``_run_org`` reads as the short
sequence of stages it is -- collect, render, publish -- rather than carrying
each stage's mechanics inline.
"""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

from rich.console import Console

from github_security_report.categories import CategoryKey
from github_security_report.cli.options import OrgPair, OrgRunOptions
from github_security_report.cli.outputs import (
    TopNLimits,
    _safe_component,
    most_generous,
    show,
    slack_limit,
    slack_show,
    write_org_files,
)
from github_security_report.render import html as html_render
from github_security_report.render import markdown as md_render
from github_security_report.render import slack as slack_render


def write_pages(
    pairs: list[OrgPair],
    output_dir: Path,
    *,
    console: Console,
    limits: TopNLimits,
    hidden: frozenset[CategoryKey] = frozenset(),
) -> None:
    """Write the GitHub Pages artifacts: per-org files plus the shared index."""
    for org_cfg, org_report in pairs:
        write_org_files(
            org_report,
            output_dir,
            top_n=limits.resolve(org_cfg.report, "report"),
            limit=limits.resolver(org_cfg.report, "report"),
            report_cfg=org_cfg.report,
            hidden=hidden,
        )
    (output_dir / "index.html").write_text(
        html_render.render_index_html([report for _, report in pairs]),
        encoding="utf-8",
    )
    (output_dir / ".nojekyll").write_text("", encoding="utf-8")
    console.print(f"[green]Wrote reports to {output_dir}[/green]")


def slack_digest(
    pairs: list[OrgPair], options: OrgRunOptions, *, now: dt.datetime
) -> dict[str, str]:
    """Build the Slack payloads and the action outputs describing them.

    An org notifies on its own ``report_day`` (so ``should_notify`` reflects the
    schedule, independent of channel availability). The channel comes from the
    ``--slack-channel`` override (e.g. the ``SLACK_CHANNEL_ID`` variable) when
    given, otherwise the per-org config channel; notifying orgs are grouped by
    channel so each distinct channel gets one digest.
    """
    notifying = [
        (org_cfg, org_report)
        for org_cfg, org_report in pairs
        if org_cfg.slack.report_day.should_notify(
            now=now.date(), force=options.force_notify
        )
    ]
    outputs = {
        "should_notify": "true" if notifying else "false",
        "failed": "false",
        # Always declared so the action output is stable even when no digest is
        # produced (no notifying org or no configured channel).
        "slack_payload": "",
    }

    by_channel: dict[str, list[OrgPair]] = {}
    for org_cfg, org_report in notifying:
        channel = options.slack_channel or org_cfg.slack.channel
        if not channel:
            continue
        by_channel.setdefault(channel, []).append((org_cfg, org_report))

    # The Slack digest uses each org's slack offender limit (category override >
    # shared --top-n > config slack_top_n). Orgs sharing a channel render into
    # one payload, so take the most generous configured value for that channel.
    payloads = [
        slack_render.render_payload(
            [report for _, report in items],
            channel=channel,
            top_n=most_generous(
                [options.limits.resolve(oc.report, "slack") for oc, _ in items]
            ),
            pages_url=options.pages_url,
            # Visibility is resolved per organisation, so each org's rows obey
            # its own Slack toggles. Unlike the row limits above, it is
            # deliberately not pooled: one org's opt-in must never publish
            # another's data into the shared channel.
            show=slack_show(items, options.hidden),
            limit=slack_limit(items, options.limits),
        )
        for channel, items in by_channel.items()
    ]
    if payloads:
        # The single action output carries the first channel's payload (the
        # common single-channel case); every payload is also written to disk.
        outputs["slack_payload"] = json.dumps(payloads[0])
        if options.output_dir:
            _write_slack_payloads(payloads, options.output_dir)
    return outputs


def _write_slack_payloads(payloads: list[dict], output_dir: Path) -> None:
    """Write one ``slack-payload-<channel>.json`` per rendered digest."""
    for payload in payloads:
        dest = output_dir / f"slack-payload-{_safe_component(payload['channel'])}.json"
        dest.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def summary(
    pairs: list[OrgPair],
    limits: TopNLimits,
    hidden: frozenset[CategoryKey] = frozenset(),
) -> str:
    """The job summary, mirroring the GitHub Pages Markdown for every org."""
    return (
        "\n\n".join(
            md_render.render_org(
                org_report,
                top_n=limits.resolve(org_cfg.report, "report"),
                show=show(org_cfg.report, "markdown", hidden),
                limit=limits.resolver(org_cfg.report, "report"),
            )
            for org_cfg, org_report in pairs
        ).rstrip()
        + "\n"
    )
