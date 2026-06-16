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
import sys
from pathlib import Path

import typer
from rich.console import Console

from github_security_report import __version__, collect, config, gitctx, runner
from github_security_report.client import GitHubClient
from github_security_report.config import Config, OrgConfig
from github_security_report.models import RepoSignal
from github_security_report.render import html as html_render
from github_security_report.render import markdown as md_render
from github_security_report.render import slack as slack_render
from github_security_report.render import terminal as term_render
from github_security_report.report import OrgReport, Report, build_org_report

app = typer.Typer(
    name="github-security-report",
    help="Security and quality reporting across GitHub organisations.",
    no_args_is_help=True,
    add_completion=False,
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"github-security-report {__version__}")
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
def _org_to_dict(org: OrgReport) -> dict:
    return {
        "org": org.org,
        "repo_count": org.repo_count,
        "generated_at": org.generated_at.isoformat(),
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
    }


# --------------------------------------------------------------------------- #
# Output writers
# --------------------------------------------------------------------------- #
def _write_org_files(org: OrgReport, output_dir: Path) -> None:
    slug = html_render.slugify(org.org)
    org_dir = output_dir / slug
    org_dir.mkdir(parents=True, exist_ok=True)
    (org_dir / "report.md").write_text(md_render.render_org(org), encoding="utf-8")
    (org_dir / "report.html").write_text(html_render.render_org_html(org), encoding="utf-8")
    (org_dir / "report.json").write_text(
        json.dumps(_org_to_dict(org), indent=2) + "\n", encoding="utf-8"
    )


# --------------------------------------------------------------------------- #
# Config resolution
# --------------------------------------------------------------------------- #
def _load_config(config_file: str | None, config_data: str | None, org: str | None) -> Config | None:
    if config_file:
        return config.load_file(config_file)
    if config_data:
        return config.loads(config_data)
    if org:
        return Config(organizations=(OrgConfig(name=org),))
    return None


# --------------------------------------------------------------------------- #
# Modes
# --------------------------------------------------------------------------- #
async def _run_org(cfg: Config, *, console: Console, output_dir: Path | None,
                   pages_url: str | None, top_n: int, force_notify: bool) -> int:
    now = dt.datetime.now(dt.timezone.utc)
    org_reports: list[OrgReport] = []
    for org_cfg in cfg.organizations:
        token = config.resolve_token(org_cfg)
        if not token:
            console.print(f"[red]No token in ${org_cfg.token_env} for {org_cfg.name}[/red]")
            return 2
        async with GitHubClient(token) as client:
            org_reports.append(
                await collect.collect_org(client, org_cfg, org_cfg.report, generated_at=now)
            )

    report = Report(orgs=org_reports, generated_at=now)
    term_render.render_orgs(org_reports, console)

    if output_dir:
        for org in org_reports:
            _write_org_files(org, output_dir)
        (output_dir / "index.html").write_text(
            html_render.render_index_html(org_reports), encoding="utf-8"
        )
        (output_dir / ".nojekyll").write_text("", encoding="utf-8")
        console.print(f"[green]Wrote reports to {output_dir}[/green]")

    should_notify = cfg.slack.report_day.should_notify(now=now.date(), force=force_notify)
    outputs = {"should_notify": "true" if should_notify else "false"}
    if should_notify and cfg.slack.channel:
        payload = slack_render.render_payload(
            org_reports, channel=cfg.slack.channel, top_n=top_n, pages_url=pages_url
        )
        if output_dir:
            (output_dir / "slack-payload.json").write_text(
                json.dumps(payload, indent=2) + "\n", encoding="utf-8"
            )
        outputs["slack_payload"] = json.dumps(payload)
    runner.write_github_output(outputs)
    runner.append_step_summary(md_render.render_report(report))
    return 0


async def _run_repo(owner: str, repo_name: str, *, token_env: str, console: Console,
                    fail_threshold: str) -> int:
    token = os.environ.get(token_env, "").strip()
    if not token:
        console.print(f"[red]No token in ${token_env}[/red]")
        return 2
    async with GitHubClient(token) as client:
        repo, signals = await collect.collect_repo(client, owner, repo_name)
    if repo is None:
        return 2

    now = dt.datetime.now(dt.timezone.utc)
    org = build_org_report(f"{owner}/{repo_name}", signals, repo_count=1, generated_at=now)
    term_render.render_org(org, console)

    runner.append_step_summary(md_render.render_org(org))
    runner.write_github_output(_repo_outputs(signals, fail_threshold))

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
    config_file: str = typer.Option(None, "--config", "-c", help="Path to a JSON config file."),
    config_data: str = typer.Option(None, "--config-data", help="Raw or base64 JSON config (vars/secrets)."),
    org: str = typer.Option(None, "--org", help="Single organisation (shorthand for org mode)."),
    scope: str = typer.Option("auto", "--scope", help="auto | org | repo."),
    repo: str = typer.Option(None, "--repo", help="owner/name for repo mode (else git-detected)."),
    token_env: str = typer.Option("GITHUB_TOKEN", "--token-env", help="Env var holding the repo-mode token."),
    output_dir: str = typer.Option(None, "--output-dir", "-o", help="Directory for Pages output (org mode)."),
    pages_url: str = typer.Option(None, "--pages-url", help="GitHub Pages URL for the Slack link."),
    top_n: int = typer.Option(10, "--top-n", help="Offenders shown per signal in Slack."),
    fail_threshold: str = typer.Option("none", "--fail-threshold", help="none|low|medium|high|critical|any (repo mode)."),
    force_notify: bool = typer.Option(False, "--force-notify", help="Post to Slack regardless of report_day."),
    no_color: bool = typer.Option(False, "--no-color", help="Disable coloured output."),
) -> None:
    """Generate a security and quality report."""
    plain = no_color or bool(os.environ.get("CI")) or not sys.stdout.isatty()
    console = Console(no_color=plain, highlight=False)

    cfg = _load_config(config_file, config_data, org)
    detected: tuple[str, str] | None = None
    if repo and "/" in repo:
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
        code = asyncio.run(
            _run_org(
                cfg, console=console,
                output_dir=Path(output_dir) if output_dir else None,
                pages_url=pages_url, top_n=top_n, force_notify=force_notify,
            )
        )
    else:
        assert detected is not None
        code = asyncio.run(
            _run_repo(
                detected[0], detected[1], token_env=token_env,
                console=console, fail_threshold=fail_threshold,
            )
        )
    raise typer.Exit(code)


if __name__ == "__main__":  # pragma: no cover
    app()
