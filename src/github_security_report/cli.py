# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Command-line entry point.

Wires configuration, scope/mode resolution, collection, and rendering into the
``github-security-report`` command. Org mode produces Pages/Slack/terminal
output; repo mode is a degraded PR gate emitting a job summary and outputs.
See ``docs/BRIEF.md`` sections 9-12.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import json
import logging
import os
import re
import sys
from collections.abc import Callable, Mapping
from dataclasses import replace
from pathlib import Path
from typing import NoReturn

import typer
from rich.console import Console

from github_security_report import __version__, collect, config, gitctx, runner
from github_security_report.categories import CategoryKey
from github_security_report.client import GitHubClient, NetworkError
from github_security_report.config import Config, OrgConfig, ReportConfig
from github_security_report.models import RepoSignal
from github_security_report.render import html as html_render
from github_security_report.render import markdown as md_render
from github_security_report.render import slack as slack_render
from github_security_report.render import terminal as term_render
from github_security_report.report import OrgReport, TableSection, build_org_report

app = typer.Typer(
    name="github-security-report",
    help="Security and quality reporting across GitHub organisations.",
    no_args_is_help=True,
    add_completion=False,
)


def _version_callback(value: bool) -> None:
    if value:
        # Match the dependamerge style: a label emoji plus a Rich-highlighted
        # version number (Rich colourises the numeric version automatically).
        Console().print(f"🏷️  github-security-report version {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    _version: bool = typer.Option(
        False, "--version", callback=_version_callback, is_eager=True,
        help="Show the version and exit.",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose logging."),
) -> None:
    """Security and quality reporting across GitHub organisations."""
    logging.basicConfig(
        level=logging.INFO if verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )


# --------------------------------------------------------------------------- #
# JSON serialisation
# --------------------------------------------------------------------------- #
def _table_to_dict(section: TableSection) -> dict:
    """Serialise a generic posture/freshness table for JSON consumers."""
    return {
        "category": section.category.key.value,
        "title": section.title,
        "columns": list(section.columns),
        "rows": [
            {
                "repo": row.repo.full_name,
                "url": row.repo.html_url,
                "cells": list(row.cells),
            }
            for row in section.rows
        ],
        # Normalised footer counts shared by every render surface.
        "pass_count": section.pass_count,
        "fail_count": section.fail_count,
        "unknown_count": section.unknown_count,
        "description": section.resolved_description(),
    }


def _org_to_dict(org: OrgReport) -> dict:
    return {
        "org": org.org,
        "repo_count": org.repo_count,
        "generated_at": org.generated_at.isoformat(),
        # Surfaced so JSON consumers can distinguish a complete result from a
        # partial one (the repository listing could not be fully read).
        "partial": org.partial,
        # Repositories explicitly excluded from analysis (per-org exclude list).
        "excluded": [r.full_name for r in org.excluded_repos],
        "sections": [
            {
                "signal": s.signal.value,
                "offenders": [
                    {
                        "repo": rs.repo.full_name,
                        "url": rs.repo.html_url,
                        "counts": {
                            "critical": rs.counts.critical,
                            "high": rs.counts.high,
                            "medium": rs.counts.medium,
                            "low": rs.counts.low,
                            "total": rs.counts.total,
                        },
                        "score": rs.score,
                    }
                    for rs in s.offenders
                ],
                "clean_count": s.clean_count,
                "nag": [r.full_name for r in s.nag_repos],
                "unknown_count": s.unknown_count,
            }
            for s in org.sections
        ],
        # Extra reporting categories outside the four-state per-signal model.
        "dependabot_tables": [_table_to_dict(t) for t in org.dependabot_tables],
        "releases": _table_to_dict(org.releases) if org.releases else None,
        "mutable_releases": (
            _table_to_dict(org.mutable_releases) if org.mutable_releases else None
        ),
    }


# --------------------------------------------------------------------------- #
# Output writers
# --------------------------------------------------------------------------- #
# Keep filenames within output_dir: a channel value containing "/" or ".."
# (misconfiguration or hostile input) must not escape the directory.
_UNSAFE_COMPONENT = re.compile(r"[^A-Za-z0-9_.-]+")


def _safe_component(value: str) -> str:
    """Sanitise a string for safe use as a single path component."""
    safe = _UNSAFE_COMPONENT.sub("-", value).strip("-.")
    return safe or "channel"


def _show(report_cfg: ReportConfig, output: str) -> Callable[[CategoryKey], bool]:
    """A per-output category-visibility predicate for the render surfaces."""
    return lambda key: report_cfg.shows_category(key, output)


def _slack_show(
    items: list[tuple[OrgConfig, OrgReport]],
) -> Callable[[CategoryKey], bool]:
    """Slack visibility for a channel: show a category if any org would.

    Orgs sharing a Slack channel render into one digest, so a category appears
    when any contributing org would show it on Slack -- mirroring the
    most-generous ``top_n`` rule for the same grouping.
    """
    return lambda key: any(
        oc.report.shows_category(key, "slack") for oc, _ in items
    )


def _write_org_files(
    org: OrgReport,
    output_dir: Path,
    *,
    top_n: int | None = None,
    report_cfg: ReportConfig,
) -> None:
    slug = html_render.slugify(org.org)
    org_dir = output_dir / slug
    org_dir.mkdir(parents=True, exist_ok=True)
    (org_dir / "report.md").write_text(
        md_render.render_org(
            org, top_n=top_n, show=_show(report_cfg, "markdown")
        ),
        encoding="utf-8",
    )
    (org_dir / "report.html").write_text(
        html_render.render_org_html(
            org, top_n=top_n, show=_show(report_cfg, "html")
        ),
        encoding="utf-8",
    )
    # report.json is the complete machine-readable dataset, so the per-output
    # render toggles deliberately do not filter it.
    (org_dir / "report.json").write_text(
        json.dumps(_org_to_dict(org), indent=2) + "\n", encoding="utf-8"
    )


# --------------------------------------------------------------------------- #
# Config resolution
# --------------------------------------------------------------------------- #
def _load_config(
    config_file: str | None,
    config_data: str | None,
    org: str | None,
    token_env: str = "GITHUB_TOKEN",
    *,
    console: Console | None = None,
) -> Config | None:
    if config_file:
        return config.load_file(config_file)
    if config_data:
        return config.loads(config_data)
    if org:
        # Honour the selected token env var so --org works with non-default
        # token environment variable names (e.g. a classic PAT secret).
        return Config(organizations=(OrgConfig(name=org, token_env=token_env),))
    # No explicit configuration: fall back to the per-user config file if one
    # exists, so a local run with no flags works instead of erroring.
    default_path = config.find_default_config()
    if default_path is not None:
        if console is not None:
            console.print(f"[dim]Using config: {default_path}[/dim]")
        return config.load_file(str(default_path))
    return None


# --------------------------------------------------------------------------- #
# Modes
# --------------------------------------------------------------------------- #
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


async def _run_org(cfg: Config, *, console: Console, output_dir: Path | None,
                   pages_url: str | None, top_n: int | None, force_notify: bool,
                   slack_channel: str | None = None,
                   repo_min_age_days: int | None = None,
                   release_max_age_days: int | None = None,
                   releases_exclude: tuple[str, ...] | None = None,
                   top_n_report: int | None = None,
                   top_n_cli: int | None = None,
                   top_n_slack: int | None = None) -> int:
    now = dt.datetime.now(dt.timezone.utc)
    pairs: list[tuple[OrgConfig, OrgReport]] = []
    for org_cfg in cfg.organizations:
        token = config.resolve_token(org_cfg)
        if not token:
            console.print(f"[red]No token in ${org_cfg.token_env} for {org_cfg.name}[/red]")
            return 2
        # CLI overrides win over config for the Releases/Tagging controls.
        report_cfg = org_cfg.report
        if repo_min_age_days is not None:
            report_cfg = replace(report_cfg, repo_min_age_days=repo_min_age_days)
        if release_max_age_days is not None:
            report_cfg = replace(
                report_cfg, release_max_age_days=release_max_age_days
            )
        effective_cfg = org_cfg
        if releases_exclude is not None:
            effective_cfg = replace(org_cfg, releases_exclude=releases_exclude)
        async with GitHubClient(token) as client:
            pairs.append(
                (org_cfg, await collect.collect_org(client, effective_cfg, report_cfg, generated_at=now))
            )
    org_reports = [report for _, report in pairs]

    # Per-output offender limit: a category-specific CLI override wins, then the
    # shared --top-n override, then the org's configured value for that output.
    def _limit(org_cfg: OrgConfig, override: int | None, attr: str) -> int:
        if override is not None:
            return override
        if top_n is not None:
            return top_n
        return int(getattr(org_cfg.report, attr))

    def _most_generous(limits: list[int]) -> int:
        # 0 means "no limit", so it is the most generous value of all; otherwise
        # the largest positive cap wins. Without this, max() would treat 0 as
        # the smallest limit and silently re-impose a cap on an org that asked
        # for everything when it shares a channel with a capped org.
        if any(limit <= 0 for limit in limits):
            return 0
        return max(limits)

    for org_cfg, org_report in pairs:
        term_render.render_org(
            org_report,
            console,
            top_n=_limit(org_cfg, top_n_cli, "cli_top_n"),
            show=_show(org_cfg.report, "cli"),
        )

    if output_dir:
        for org_cfg, org_report in pairs:
            _write_org_files(
                org_report,
                output_dir,
                top_n=_limit(org_cfg, top_n_report, "report_top_n"),
                report_cfg=org_cfg.report,
            )
        (output_dir / "index.html").write_text(
            html_render.render_index_html(org_reports), encoding="utf-8"
        )
        (output_dir / ".nojekyll").write_text("", encoding="utf-8")
        console.print(f"[green]Wrote reports to {output_dir}[/green]")

    # Slack: an org notifies on its own report_day (so should_notify reflects
    # the schedule, independent of channel availability). The channel comes
    # from the --slack-channel override (e.g. the SLACK_CHANNEL_ID variable)
    # when given, otherwise the per-org config channel; notifying orgs are
    # grouped by channel so each distinct channel gets one digest.
    notifying = [
        (org_cfg, org_report)
        for org_cfg, org_report in pairs
        if org_cfg.slack.report_day.should_notify(now=now.date(), force=force_notify)
    ]
    outputs = {
        "should_notify": "true" if notifying else "false",
        "failed": "false",
        # Always declared so the action output is stable even when no digest is
        # produced (no notifying org or no configured channel).
        "slack_payload": "",
    }

    by_channel: dict[str, list[tuple[OrgConfig, OrgReport]]] = {}
    for org_cfg, org_report in notifying:
        channel = slack_channel or org_cfg.slack.channel
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
            top_n=_most_generous(
                [_limit(oc, top_n_slack, "slack_top_n") for oc, _ in items]
            ),
            pages_url=pages_url,
            # A category shows in the channel digest when any contributing org
            # would show it on Slack (mirrors the most-generous top_n rule).
            show=_slack_show(items),
        )
        for channel, items in by_channel.items()
    ]
    if payloads:
        # The single action output carries the first channel's payload (the
        # common single-channel case); every payload is also written to disk.
        outputs["slack_payload"] = json.dumps(payloads[0])
        if output_dir:
            for payload in payloads:
                dest = output_dir / f"slack-payload-{_safe_component(payload['channel'])}.json"
                dest.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    runner.write_github_output(outputs)
    # The job summary mirrors the GitHub Pages Markdown, so it uses the report
    # offender limit per org.
    summary = (
        "\n\n".join(
            md_render.render_org(
                org_report,
                top_n=_limit(org_cfg, top_n_report, "report_top_n"),
                show=_show(org_cfg.report, "markdown"),
            )
            for org_cfg, org_report in pairs
        ).rstrip()
        + "\n"
    )
    runner.append_step_summary(summary)
    return 0


async def _run_repo(owner: str, repo_name: str, *, token_env: str, console: Console,
                    fail_threshold: str,
                    ruleset_workflows: Mapping[str, str] | None = None) -> int:
    token = os.environ.get(token_env, "").strip()
    if not token:
        console.print(f"[red]No token in ${token_env}[/red]")
        return 2
    async with GitHubClient(token) as client:
        repo, signals = await collect.collect_repo(
            client, owner, repo_name, ruleset_workflows=ruleset_workflows
        )
    if repo is None:
        return 2

    now = dt.datetime.now(dt.timezone.utc)
    org = build_org_report(f"{owner}/{repo_name}", signals, repo_count=1, generated_at=now)
    term_render.render_org(org, console)

    runner.append_step_summary(md_render.render_org(org))
    outputs = _repo_outputs(signals, fail_threshold)
    # Keep the action's declared outputs stable across modes.
    outputs["should_notify"] = "false"
    outputs["slack_payload"] = ""
    runner.write_github_output(outputs)

    if runner.should_fail(signals, fail_threshold):
        console.print(f"[red]Failing: findings at or above '{fail_threshold}'[/red]")
        return 1
    return 0


def _repo_outputs(signals: list[RepoSignal], fail_threshold: str) -> dict[str, str]:
    outputs = {s.signal.value + "_open": str(s.counts.total) for s in signals}
    outputs["failed"] = "true" if runner.should_fail(signals, fail_threshold) else "false"
    return outputs


# --------------------------------------------------------------------------- #
# Command
# --------------------------------------------------------------------------- #
@app.command()
def report(
    config_file: str | None = typer.Option(None, "--config", "-c", help="Path to a JSON config file."),
    config_data: str | None = typer.Option(None, "--config-data", help="Raw or base64 JSON config (vars/secrets)."),
    org: str | None = typer.Option(None, "--org", help="Single organisation (shorthand for org mode)."),
    scope: str = typer.Option("auto", "--scope", help="auto | org | repo."),
    repo: str | None = typer.Option(None, "--repo", help="owner/name for repo mode (else git-detected)."),
    token_env: str = typer.Option("GITHUB_TOKEN", "--token-env", help="Env var holding the repo-mode token."),
    output_dir: str | None = typer.Option(None, "--output-dir", "-o", help="Directory for Pages output (org mode)."),
    pages_url: str | None = typer.Option(None, "--pages-url", help="GitHub Pages URL for the Slack link."),
    slack_channel: str | None = typer.Option(None, "--slack-channel", help="Slack channel ID; overrides config slack.channel (e.g. SLACK_CHANNEL_ID)."),
    top_n: int | None = typer.Option(None, "--top-n", help="Offenders shown per signal across all outputs (0 = no limit; default: config, else 10). Overridden per output by the flags below."),
    top_n_report: int | None = typer.Option(None, "--top-n-report", help="Offenders per signal in the GitHub Pages output (0 = no limit; overrides --top-n)."),
    top_n_cli: int | None = typer.Option(None, "--top-n-cli", help="Offenders per signal in the terminal output (0 = no limit; overrides --top-n)."),
    top_n_slack: int | None = typer.Option(None, "--top-n-slack", help="Offenders per signal in the Slack digest (0 = no limit; overrides --top-n)."),
    fail_threshold: str = typer.Option("none", "--fail-threshold", help="none|low|medium|high|critical|any (repo mode)."),
    force_notify: bool = typer.Option(False, "--force-notify", help="Post to Slack regardless of report_day."),
    repo_min_age_days: int | None = typer.Option(None, "--repo-min-age-days", "--release-min-age-days", help="Exclude repos created within N days from Releases/Tagging (0 = include all; default: config, else 28). --release-min-age-days is a deprecated alias."),
    release_max_age_days: int | None = typer.Option(None, "--release-max-age-days", help="Flag a repo in Releases/Tagging only when its newest release or tag is older than N days (0 = flag every eligible repo; default: config, else 60)."),
    releases_exclude: list[str] | None = typer.Option(None, "--releases-exclude", help="Repository name to omit from the Releases/Tagging table (repeatable; overrides config)."),
    no_color: bool = typer.Option(False, "--no-color", help="Disable coloured output."),
) -> None:
    """Generate a security and quality report."""
    plain = no_color or bool(os.environ.get("CI")) or not sys.stdout.isatty()
    console = Console(no_color=plain, highlight=False)

    # Match the config schema (top_n minimum is 0): reject a negative override
    # at the boundary. 0 is permitted and disables the limit (show everything).
    for name, value in (
        ("--top-n", top_n),
        ("--top-n-report", top_n_report),
        ("--top-n-cli", top_n_cli),
        ("--top-n-slack", top_n_slack),
    ):
        if value is not None and value < 0:
            console.print(f"[red]{name} must be 0 or greater (0 = no limit)[/red]")
            raise typer.Exit(2)

    # Match the config schema (minimum is 0): reject negative overrides at the
    # boundary.
    if repo_min_age_days is not None and repo_min_age_days < 0:
        console.print("[red]--repo-min-age-days must be 0 or greater[/red]")
        raise typer.Exit(2)
    if release_max_age_days is not None and release_max_age_days < 0:
        console.print("[red]--release-max-age-days must be 0 or greater[/red]")
        raise typer.Exit(2)

    cfg = _load_config(config_file, config_data, org, token_env, console=console)
    detected: tuple[str, str] | None = None
    if repo:
        # An explicit --repo must be exactly 'owner/name' (one slash, both
        # parts non-empty). A malformed value would otherwise be split
        # incorrectly or fall back to git detection, risking a report against
        # an unintended repository.
        if not re.fullmatch(r"[^/]+/[^/]+", repo):
            console.print("[red]--repo must be in 'owner/name' format[/red]")
            raise typer.Exit(2)
        owner, name = repo.split("/", 1)
        detected = (owner, name)
    elif scope != "org":
        detected = gitctx.detect_repo()

    try:
        mode = runner.resolve_mode(
            scope, has_org_config=cfg is not None, detected_repo=detected
        )
    except runner.ModeError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(2) from exc

    if mode is runner.Mode.ORG:
        assert cfg is not None
        try:
            code = asyncio.run(
                _run_org(
                    cfg, console=console,
                    output_dir=Path(output_dir) if output_dir else None,
                    pages_url=pages_url, top_n=top_n, force_notify=force_notify,
                    slack_channel=slack_channel or None,
                    repo_min_age_days=repo_min_age_days,
                    release_max_age_days=release_max_age_days,
                    releases_exclude=tuple(releases_exclude) if releases_exclude else None,
                    top_n_report=top_n_report,
                    top_n_cli=top_n_cli,
                    top_n_slack=top_n_slack,
                )
            )
        except NetworkError as exc:
            _abort_network(console, exc)
    else:
        assert detected is not None
        # In repo mode there is no per-org config; honour report.ruleset_workflows
        # from a supplied config (e.g. --scope repo with --config) so keyword
        # customisation applies, falling back to the built-in default otherwise.
        rw = cfg.report.ruleset_workflows if cfg is not None else None
        try:
            code = asyncio.run(
                _run_repo(
                    detected[0], detected[1], token_env=token_env,
                    console=console, fail_threshold=fail_threshold,
                    ruleset_workflows=rw,
                )
            )
        except NetworkError as exc:
            _abort_network(console, exc)
    raise typer.Exit(code)


if __name__ == "__main__":  # pragma: no cover
    app()
