# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""The three run modes behind the commands: org, repo, and remediate.

Each ``_run_*`` coroutine returns the process exit code. ``_run_org`` reads as a
short sequence of stages -- collect, render, publish -- with each stage a helper
in this module.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import os
from collections.abc import Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import NoReturn

import typer
from rich.console import Console

from github_security_report import collect, config, runner
from github_security_report import remediate as remediate_mod
from github_security_report.categories import CategoryKey
from github_security_report.cli.outputs import (
    TopNLimits,
    _safe_component,
    most_generous,
    repo_outputs,
    show,
    slack_limit,
    slack_show,
    write_org_files,
)
from github_security_report.client import AuthError, GitHubClient, NetworkError
from github_security_report.config import Config, OrgConfig, ReportConfig
from github_security_report.render import html as html_render
from github_security_report.render import markdown as md_render
from github_security_report.render import slack as slack_render
from github_security_report.render import terminal as term_render
from github_security_report.report import OrgReport, build_org_report

log = logging.getLogger(__name__)

# An org config paired with the report collected for it.
OrgPair = tuple[OrgConfig, OrgReport]


# --------------------------------------------------------------------------- #
# Config resolution
# --------------------------------------------------------------------------- #
def _load_config(
    config_file: str | None,
    config_data: str | None,
    org: str | None,
    token_env: str | None = None,
    *,
    console: Console | None = None,
) -> Config | None:
    """Resolve the configuration, applying an explicit ``--token-env`` over it.

    ``token_env`` is ``None`` when the flag was not given, which is what makes
    it usable as an override at all: with an eager ``"GITHUB_TOKEN"`` default
    the code could not tell "the user asked for this" from "unset", so the only
    safe reading was to ignore it wherever a config supplied its own value. A
    value that was actually typed now wins over every organisation's configured
    ``token_env``, which is the one thing an operator can mean by passing it
    alongside ``--config``.
    """
    cfg: Config | None = None
    if config_file:
        cfg = config.load_file(config_file)
    elif config_data:
        cfg = config.loads(config_data)
    elif org:
        cfg = Config(organizations=(OrgConfig(name=org),))
    else:
        # No explicit configuration: fall back to the per-user config file if
        # one exists, so a local run with no flags works instead of erroring.
        default_path = config.find_default_config()
        if default_path is not None:
            if console is not None:
                console.print(f"[dim]Using config: {default_path}[/dim]")
            cfg = config.load_file(str(default_path))
    if cfg is None or token_env is None:
        return cfg
    return replace(
        cfg,
        organizations=tuple(
            replace(org_cfg, token_env=token_env) for org_cfg in cfg.organizations
        ),
    )


def _abort_network(console: Console, exc: NetworkError) -> NoReturn:
    """Abort the run on an unrecoverable network failure.

    Prints the multi-line network diagnostics in red and exits with code 3
    (distinct from 2, used for usage/config errors) so callers can tell a
    connectivity failure from a misconfiguration. ``markup=False`` keeps
    bracketed text in the diagnostics (e.g. an ``[Errno 8]`` cause) literal
    rather than letting Rich parse it as markup.
    """
    console.print(str(exc), style="red", markup=False)
    raise typer.Exit(3)


def _abort_auth(console: Console, exc: AuthError) -> NoReturn:
    """Abort the run on rejected credentials.

    Exits with code 4, distinct from a usage error (2) and a connectivity
    failure (3), so an automated caller can tell "rotate the token" apart from
    "retry later" without parsing the message. Aborting matters most in CI:
    a scheduled run that degraded instead would publish an empty, confidently
    clean report over a good one.
    """
    console.print(str(exc), style="red", markup=False)
    raise typer.Exit(4)


# --------------------------------------------------------------------------- #
# Org mode
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class ReleaseOverrides:
    """Command-line overrides for the Releases/Tagging controls.

    CLI overrides win over config; an unset override leaves the org's own
    configured value in place.
    """

    repo_min_age_days: int | None = None
    release_max_age_days: int | None = None
    releases_exclude: tuple[str, ...] | None = None

    def apply(self, org_cfg: OrgConfig) -> tuple[OrgConfig, ReportConfig]:
        """The org and report configs to collect with, overrides applied.

        The two age thresholds are scalar policy ("expect a release inside N
        days"), so applying one uniformly across every configured organisation
        is what a reader of the flag expects, and matches how ``--top-n``
        already behaves.

        ``releases_exclude`` is not scalar: it is a curated per-organisation
        list, and one flag replacing all of them loses data the config
        deliberately carried. The command line refuses it outright for a
        multi-org run rather than silently flattening them (see cli/app.py), so
        by the time this runs there is only one organisation it could mean.
        """
        report_cfg = org_cfg.report
        if self.repo_min_age_days is not None:
            report_cfg = replace(report_cfg, repo_min_age_days=self.repo_min_age_days)
        if self.release_max_age_days is not None:
            report_cfg = replace(
                report_cfg, release_max_age_days=self.release_max_age_days
            )
        effective_cfg = org_cfg
        if self.releases_exclude is not None:
            effective_cfg = replace(org_cfg, releases_exclude=self.releases_exclude)
        return effective_cfg, report_cfg


@dataclass(frozen=True)
class OrgRunOptions:
    """Everything an org-mode run takes from the command line.

    Bundled into one value so each run stage receives a single options argument
    rather than a dozen individually-threaded parameters.
    """

    output_dir: Path | None = None
    pages_url: str | None = None
    slack_channel: str | None = None
    force_notify: bool = False
    limits: TopNLimits = field(default_factory=TopNLimits)
    releases: ReleaseOverrides = field(default_factory=ReleaseOverrides)
    # Categories the invocation suppressed outright. Outranks the config, so a
    # scheduled run can keep a reader-specific category out of its published
    # artifacts without editing (or contradicting) the shared configuration.
    hidden: frozenset[CategoryKey] = frozenset()


async def _collect_reports(
    cfg: Config,
    *,
    console: Console,
    now: dt.datetime,
    overrides: ReleaseOverrides,
) -> list[OrgPair] | None:
    """Collect every configured org's report, or None if a token is missing."""
    pairs: list[OrgPair] = []
    for org_cfg in cfg.organizations:
        token = config.resolve_token(org_cfg)
        if not token:
            console.print(
                f"[red]No token in ${org_cfg.token_env} for {org_cfg.name}[/red]"
            )
            return None
        effective_cfg, report_cfg = overrides.apply(org_cfg)
        async with GitHubClient(token) as client:
            pairs.append(
                (
                    org_cfg,
                    await collect.collect_org(
                        client, effective_cfg, report_cfg, generated_at=now
                    ),
                )
            )
    return pairs


def _write_pages(
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


def _slack_digest(
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


def _summary(
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


async def _run_org(cfg: Config, options: OrgRunOptions, *, console: Console) -> int:
    """Collect every configured org, then render, publish and notify."""
    now = dt.datetime.now(dt.timezone.utc)
    pairs = await _collect_reports(
        cfg, console=console, now=now, overrides=options.releases
    )
    if pairs is None:
        return 2

    limits = options.limits
    for org_cfg, org_report in pairs:
        term_render.render_org(
            org_report,
            console,
            top_n=limits.resolve(org_cfg.report, "cli"),
            show=show(org_cfg.report, "cli", options.hidden),
            limit=limits.resolver(org_cfg.report, "cli"),
        )
    if options.output_dir:
        _write_pages(
            pairs,
            options.output_dir,
            console=console,
            limits=limits,
            hidden=options.hidden,
        )

    runner.write_github_output(_slack_digest(pairs, options, now=now))
    runner.append_step_summary(_summary(pairs, limits, options.hidden))
    return 0


# --------------------------------------------------------------------------- #
# Repo mode
# --------------------------------------------------------------------------- #
async def _run_repo(
    owner: str,
    repo_name: str,
    *,
    token_env: str,
    console: Console,
    fail_threshold: str,
    report_cfg: ReportConfig | None = None,
    limits: TopNLimits | None = None,
    hidden: frozenset[CategoryKey] = frozenset(),
) -> int:
    # Repo mode has no per-org block, so the report config is whatever a
    # supplied --config carried globally, falling back to the built-in
    # defaults. Threading it through is what makes the per-category toggles,
    # row limits and ruleset keywords mean the same thing in both modes.
    cfg = report_cfg if report_cfg is not None else ReportConfig()
    caps = limits if limits is not None else TopNLimits()
    token = os.environ.get(token_env, "").strip()
    if not token:
        console.print(f"[red]No token in ${token_env}[/red]")
        return 2
    async with GitHubClient(token) as client:
        repo, signals = await collect.collect_repo(
            client, owner, repo_name, ruleset_workflows=cfg.ruleset_workflows
        )
    if repo is None:
        return 2

    now = dt.datetime.now(dt.timezone.utc)
    org = build_org_report(
        f"{owner}/{repo_name}", signals, repo_count=1, generated_at=now
    )
    # Every flag that survives into repo mode is applied here. A flag accepted,
    # validated and then ignored is worse than one rejected, because nothing
    # tells the caller it did nothing; the org-only flags are refused at the
    # boundary instead (see cli/app.py).
    term_render.render_org(
        org,
        console,
        top_n=caps.resolve(cfg, "cli"),
        show=show(cfg, "cli", hidden),
        limit=caps.resolver(cfg, "cli"),
    )

    runner.append_step_summary(
        md_render.render_org(
            org,
            top_n=caps.resolve(cfg, "report"),
            show=show(cfg, "markdown", hidden),
            limit=caps.resolver(cfg, "report"),
        )
    )
    outputs = repo_outputs(signals, fail_threshold)
    # Keep the action's declared outputs stable across modes.
    outputs["should_notify"] = "false"
    outputs["slack_payload"] = ""
    runner.write_github_output(outputs)

    if runner.should_fail(signals, fail_threshold):
        console.print(f"[red]Failing: findings at or above '{fail_threshold}'[/red]")
        return 1
    return 0


# --------------------------------------------------------------------------- #
# Remediation
# --------------------------------------------------------------------------- #
async def _run_remediate(
    cfg: Config,
    *,
    console: Console,
    token: str,
    categories: Sequence[CategoryKey],
    apply: bool,
) -> int:
    """Collect each org's posture and enable (or preview enabling) features.

    A single write-capable token drives both the read (collection) and the
    writes for every configured org, so the per-org read ``token_env`` in the
    config is intentionally bypassed. Returns 1 when any enable failed, else 0.
    """
    now = dt.datetime.now(dt.timezone.utc)
    failures = 0
    async with GitHubClient(token) as client:
        for org_cfg in cfg.organizations:
            report = await collect.collect_org(
                client, org_cfg, org_cfg.report, generated_at=now
            )
            results = await remediate_mod.remediate_org(
                client, report, categories=categories, apply=apply
            )
            # Honour the org's configured terminal offender limit, the same
            # cap the report's CLI output uses, so large orgs stay readable.
            term_render.render_remediation(
                report.org,
                results,
                console,
                apply=apply,
                top_n=org_cfg.report.cli_top_n,
            )
            failures += sum(result.failures for result in results)
    return 1 if failures else 0
