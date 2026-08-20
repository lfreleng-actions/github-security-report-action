# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Typer wiring: option parsing, validation, and dispatch to a run mode.

The command bodies here stay thin -- validate the options, resolve the mode,
then hand off to :mod:`cli.modes`.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import sys
from pathlib import Path

import typer
from rich.console import Console

from github_security_report import __version__, gitctx, runner
from github_security_report import remediate as remediate_mod
from github_security_report.categories import CategoryKey
from github_security_report.cli.modes import (
    OrgRunOptions,
    ReleaseOverrides,
    _abort_auth,
    _abort_network,
    _load_config,
    _run_org,
    _run_remediate,
    _run_repo,
)
from github_security_report.cli.outputs import TopNLimits
from github_security_report.client import AuthError, NetworkError

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


def _check_non_negative(console: Console, name: str, value: int | None) -> None:
    """Reject a negative numeric override at the CLI boundary.

    Mirrors the config schema, whose minimum for these controls is 0; 0 itself
    is permitted and carries the "no limit" / "no threshold" meaning.
    """
    if value is not None and value < 0:
        console.print(f"[red]{name} must be 0 or greater[/red]")
        raise typer.Exit(2)


def _resolve_hidden(console: Console, hide: list[str] | None) -> frozenset[CategoryKey]:
    """Validate ``--hide`` values into category keys, or abort.

    An unrecognised category is rejected rather than ignored: the point of the
    flag is to keep something off a published surface, so a typo that silently
    published it anyway would be the one failure mode that matters.
    """
    if not hide:
        return frozenset()
    valid = {key.value: key for key in CategoryKey}
    unknown = sorted({name for name in hide if name not in valid})
    if unknown:
        # markup=False: the user-supplied values are printed literally, so
        # bracketed input cannot be interpreted as Rich markup.
        console.print(
            f"Unknown --hide category: {', '.join(unknown)}. "
            f"Valid values: {', '.join(sorted(valid))}",
            style="red",
            markup=False,
        )
        raise typer.Exit(2)
    return frozenset(valid[name] for name in hide)


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
    token_env: str = typer.Option(
        "GITHUB_TOKEN", "--token-env", help="Env var holding the repo-mode token."
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
        help="Repository name to omit from the Releases/Tagging table (repeatable; overrides config).",
    ),
    hide: list[str] | None = typer.Option(
        None,
        "--hide",
        help="Category to suppress on every output (repeatable; overrides config, which cannot re-enable it).",
    ),
    no_color: bool = typer.Option(False, "--no-color", help="Disable coloured output."),
) -> None:
    """Generate a security and quality report."""
    console = _console(no_color)

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

    _check_non_negative(console, "--repo-min-age-days", repo_min_age_days)
    _check_non_negative(console, "--release-max-age-days", release_max_age_days)

    hidden = _resolve_hidden(console, hide)

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
            releases=ReleaseOverrides(
                repo_min_age_days=repo_min_age_days,
                release_max_age_days=release_max_age_days,
                releases_exclude=tuple(releases_exclude) if releases_exclude else None,
            ),
            hidden=hidden,
        )
        try:
            code = asyncio.run(_run_org(cfg, options, console=console))
        except AuthError as exc:
            _abort_auth(console, exc)
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
                    detected[0],
                    detected[1],
                    token_env=token_env,
                    console=console,
                    fail_threshold=fail_threshold,
                    ruleset_workflows=rw,
                    hidden=hidden,
                )
            )
        except AuthError as exc:
            _abort_auth(console, exc)
        except NetworkError as exc:
            _abort_network(console, exc)
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
    token_env: str = typer.Option(
        "GITHUB_TOKEN",
        "--token-env",
        help="Env var holding a WRITE-capable org-admin PAT. Used for both reading posture and enabling features across every configured org.",
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

    token = os.environ.get(token_env, "").strip()
    if not token:
        # markup=False guards the user-supplied --token-env value.
        console.print(
            f"No token in ${token_env} (a write-capable org-admin PAT is required).",
            style="red",
            markup=False,
        )
        raise typer.Exit(2)

    try:
        code = asyncio.run(
            _run_remediate(
                cfg,
                console=console,
                token=token,
                categories=categories,
                apply=apply,
            )
        )
    except AuthError as exc:
        _abort_auth(console, exc)
    except NetworkError as exc:
        _abort_network(console, exc)
    raise typer.Exit(code)
