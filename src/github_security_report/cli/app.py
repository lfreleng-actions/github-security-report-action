# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Typer wiring: option parsing, validation, and dispatch to a run mode.

The command bodies here stay thin -- validate the options, resolve the mode,
then hand off to :mod:`cli.modes`.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

import typer
from rich.console import Console

from github_security_report import __version__, runner
from github_security_report import remediate as remediate_mod
from github_security_report.cli import boundary
from github_security_report.cli.modes import (
    _load_config,
    _run_org,
    _run_remediate,
    _run_repo,
)
from github_security_report.cli.options import OrgRunOptions, ReportOverrides
from github_security_report.cli.outputs import TopNLimits

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
        # A single space follows the emoji: terminals that honour the VS16
        # emoji-presentation width (e.g. Ghostty) render it two cells wide, so
        # the extra pad the old double space added now reads as a gap.
        Console().print(f"🏷️ github-security-report version {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    _version: bool = typer.Option(
        False,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show the version and exit.",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose logging."),
) -> None:
    """Security and quality reporting across GitHub organisations."""
    logging.basicConfig(
        level=logging.INFO if verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )


def _console(no_color: bool) -> Console:
    """A console that drops colour in CI, when piped, or on request."""
    plain = no_color or bool(os.environ.get("CI")) or not sys.stdout.isatty()
    return Console(no_color=plain, highlight=False)


@app.command()
def report(
    config_file: str | None = typer.Option(
        None, "--config", "-c", help="Path to a JSON config file."
    ),
    config_data: str | None = typer.Option(
        None, "--config-data", help="Raw or base64 JSON config (vars/secrets)."
    ),
    org: str | None = typer.Option(
        None, "--org", help="Single organisation (shorthand for org mode)."
    ),
    scope: str = typer.Option("auto", "--scope", help="auto | org | repo."),
    repo: str | None = typer.Option(
        None, "--repo", help="owner/name for repo mode (else git-detected)."
    ),
    token_env: str | None = typer.Option(
        None,
        "--token-env",
        help="Env var holding the token (default: GITHUB_TOKEN). When given, overrides every organisation's configured token_env.",
    ),
    output_dir: str | None = typer.Option(
        None, "--output-dir", "-o", help="Directory for Pages output (org mode)."
    ),
    pages_url: str | None = typer.Option(
        None, "--pages-url", help="GitHub Pages URL for the Slack link."
    ),
    slack_channel: str | None = typer.Option(
        None,
        "--slack-channel",
        help="Slack channel ID; overrides config slack.channel (e.g. SLACK_CHANNEL_ID).",
    ),
    top_n: int | None = typer.Option(
        None,
        "--top-n",
        help="Offenders shown per signal across all outputs (0 = no limit; default: config, else 10). Overridden per output by the flags below.",
    ),
    top_n_report: int | None = typer.Option(
        None,
        "--top-n-report",
        help="Offenders per signal in the GitHub Pages output (0 = no limit; overrides --top-n).",
    ),
    top_n_cli: int | None = typer.Option(
        None,
        "--top-n-cli",
        help="Offenders per signal in the terminal output (0 = no limit; overrides --top-n).",
    ),
    top_n_slack: int | None = typer.Option(
        None,
        "--top-n-slack",
        help="Offenders per signal in the Slack digest (0 = no limit; overrides --top-n).",
    ),
    fail_threshold: str = typer.Option(
        "none",
        "--fail-threshold",
        help="none|low|medium|high|critical|any (repo mode).",
    ),
    force_notify: bool = typer.Option(
        False, "--force-notify", help="Post to Slack regardless of report_day."
    ),
    repo_min_age_days: int | None = typer.Option(
        None,
        "--repo-min-age-days",
        "--release-min-age-days",
        help="Exclude repos created within N days from Releases/Tagging (0 = include all; default: config, else 28). --release-min-age-days is a deprecated alias.",
    ),
    release_max_age_days: int | None = typer.Option(
        None,
        "--release-max-age-days",
        help="Flag a repo in Releases/Tagging only when its newest release or tag is older than N days (0 = flag every eligible repo; default: config, else 60).",
    ),
    releases_exclude: list[str] | None = typer.Option(
        None,
        "--releases-exclude",
        help="Repository name to omit from the Releases/Tagging table (repeatable; replaces the configured list, so it is refused when the run covers more than one organisation).",
    ),
    hide: list[str] | None = typer.Option(
        None,
        "--hide",
        help="Category to suppress on every output (repeatable; overrides config, which cannot re-enable it).",
    ),
    no_gating: bool = typer.Option(
        False,
        "--no-gating",
        help="Always probe the workflow-driven signals (Scorecard, zizmor, aislop) instead of skipping those the organisation appears not to support.",
    ),
    include_archived: bool = typer.Option(
        False,
        "--include-archived",
        help="Analyse archived repositories, which are excluded by default.",
    ),
    include_test: bool = typer.Option(
        False,
        "--include-test",
        help="Analyse test repositories, which are excluded by default.",
    ),
    no_color: bool = typer.Option(False, "--no-color", help="Disable coloured output."),
) -> None:
    """Generate a security and quality report."""
    console = _console(no_color)
    boundary.check_limits(
        console,
        [
            ("--top-n", top_n),
            ("--top-n-report", top_n_report),
            ("--top-n-cli", top_n_cli),
            ("--top-n-slack", top_n_slack),
        ],
    )
    boundary.check_non_negative(console, "--repo-min-age-days", repo_min_age_days)
    boundary.check_non_negative(console, "--release-max-age-days", release_max_age_days)
    hidden = boundary.resolve_hidden(console, hide)

    cfg = _load_config(config_file, config_data, org, token_env, console=console)
    detected = boundary.detect_target(console, repo, scope)
    mode = boundary.resolve_mode(console, scope, cfg=cfg, detected=detected)

    if mode is runner.Mode.ORG:
        assert cfg is not None
        boundary.check_releases_exclude(console, cfg, releases_exclude)
        options = OrgRunOptions(
            output_dir=Path(output_dir) if output_dir else None,
            pages_url=pages_url,
            slack_channel=slack_channel or None,
            force_notify=force_notify,
            limits=TopNLimits(
                shared=top_n,
                report=top_n_report,
                cli=top_n_cli,
                slack=top_n_slack,
            ),
            overrides=ReportOverrides(
                repo_min_age_days=repo_min_age_days,
                release_max_age_days=release_max_age_days,
                releases_exclude=tuple(releases_exclude) if releases_exclude else None,
                # One-way: the flags can only loosen what the config asked for,
                # so an unset flag stays None rather than asserting the default.
                gating=False if no_gating else None,
                include_archived=True if include_archived else None,
                include_test=True if include_test else None,
            ),
            hidden=hidden,
        )
        code = boundary.run_guarded(console, _run_org(cfg, options, console=console))
    else:
        assert detected is not None
        # Every organisation-only flag is refused rather than accepted and
        # discarded. The remaining flags (--top-n, --top-n-cli, --top-n-report,
        # --hide) and the config's report block are threaded into the run, so
        # what repo mode accepts is what repo mode applies.
        boundary.reject_org_only(
            console,
            [
                name
                for name, supplied in (
                    ("--output-dir", output_dir is not None),
                    ("--pages-url", pages_url is not None),
                    ("--slack-channel", slack_channel is not None),
                    ("--force-notify", force_notify),
                    ("--top-n-slack", top_n_slack is not None),
                    ("--repo-min-age-days", repo_min_age_days is not None),
                    ("--release-max-age-days", release_max_age_days is not None),
                    ("--releases-exclude", bool(releases_exclude)),
                    ("--no-gating", no_gating),
                    ("--include-archived", include_archived),
                    ("--include-test", include_test),
                )
                if supplied
            ],
        )
        code = boundary.run_guarded(
            console,
            _run_repo(
                detected[0],
                detected[1],
                token_env=token_env or "GITHUB_TOKEN",
                console=console,
                fail_threshold=fail_threshold,
                report_cfg=cfg.report if cfg is not None else None,
                limits=TopNLimits(shared=top_n, report=top_n_report, cli=top_n_cli),
                hidden=hidden,
            ),
        )
    raise typer.Exit(code)


@app.command()
def remediate(
    config_file: str | None = typer.Option(
        None, "--config", "-c", help="Path to a JSON config file."
    ),
    config_data: str | None = typer.Option(
        None, "--config-data", help="Raw or base64 JSON config (vars/secrets)."
    ),
    org: str | None = typer.Option(
        None, "--org", help="Single organisation (shorthand for org mode)."
    ),
    scope: str = typer.Option(
        "org",
        "--scope",
        help="Only 'org' is supported; remediation is organisation-scoped.",
    ),
    category: list[str] | None = typer.Option(
        None,
        "--category",
        help="Remediable category to act on (repeatable; default: all). One of: codeql, secret_scanning, dependabot_alerts_enabled, dependabot_updates_enabled, private_vulnerability_reporting.",
    ),
    token_env: str | None = typer.Option(
        None,
        "--token-env",
        help="Env var holding a WRITE-capable org-admin PAT (default: GITHUB_TOKEN). Used for both reading posture and enabling features across every configured org.",
    ),
    apply: bool = typer.Option(
        False,
        "--apply",
        help="Perform the writes. Without this flag remediate only previews (dry run).",
    ),
    no_color: bool = typer.Option(False, "--no-color", help="Disable coloured output."),
) -> None:
    """Enable security features on repositories that lack them.

    Runs the same collection the report uses, then switches on each selected
    remediable feature wherever a repository has it confirmed off. Dry run by
    default: pass --apply to make changes. Requires a write-capable token
    (org admin), distinct from the read-only reporting PAT.
    """
    console = _console(no_color)

    if scope != "org":
        console.print("[red]remediate supports only --scope org[/red]")
        raise typer.Exit(2)

    keys, unknown = remediate_mod.parse_categories(category or [])
    if unknown:
        valid = ", ".join(key.value for key in remediate_mod.REMEDIABLE)
        # markup=False: the user-supplied --category values are printed
        # literally, so bracketed input cannot be interpreted as Rich markup.
        console.print(
            f"Unknown --category: {', '.join(unknown)}. Valid values: {valid}",
            style="red",
            markup=False,
        )
        raise typer.Exit(2)
    categories = keys or list(remediate_mod.REMEDIABLE)

    cfg = _load_config(config_file, config_data, org, token_env, console=console)
    if cfg is None:
        console.print(
            "[red]No configuration: provide --config, --config-data or --org.[/red]"
        )
        raise typer.Exit(2)

    token_var = token_env or "GITHUB_TOKEN"
    token = os.environ.get(token_var, "").strip()
    if not token:
        # markup=False guards the user-supplied --token-env value.
        console.print(
            f"No token in ${token_var} (a write-capable org-admin PAT is required).",
            style="red",
            markup=False,
        )
        raise typer.Exit(2)

    code = boundary.run_guarded(
        console,
        _run_remediate(
            cfg,
            console=console,
            token=token,
            categories=categories,
            apply=apply,
        ),
    )
    raise typer.Exit(code)
