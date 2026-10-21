# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""The three run modes behind the commands: org, repo, and remediate.

Each ``_run_*`` coroutine returns the process exit code. ``_run_org`` reads as a
short sequence of stages -- collect, render, publish -- with the options they
take in :mod:`~github_security_report.cli.options` and the artifacts they emit
in :mod:`~github_security_report.cli.publish`.
"""

from __future__ import annotations

import datetime as dt
import logging
import os
from dataclasses import replace
from pathlib import Path
from typing import NoReturn

import typer
from rich.console import Console

from github_security_report import collect, config, layout, runner
from github_security_report.categories import CategoryKey
from github_security_report.cli import publish
from github_security_report.cli.options import (
    OrgPair,
    OrgRunOptions,
    ReportOverrides,
)
from github_security_report.cli.outputs import (
    TopNLimits,
    footer,
    repo_outputs,
    show,
    windows,
)
from github_security_report.client import AuthError, GitHubClient, NetworkError
from github_security_report.collect.context import CollectExtras
from github_security_report.collect.workflow_runs import (
    attach_workflow_failures,
    open_run_store,
)
from github_security_report.config import Config, OrgConfig, ReportConfig
from github_security_report.render import markdown as md_render
from github_security_report.render import terminal as term_render
from github_security_report.report import build_org_report

log = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Config resolution
# --------------------------------------------------------------------------- #
def _load_config(
    config_file: str | None,
    config_data: str | None,
    org: str | None,
    token_env: str | None = None,
) -> tuple[Config | None, Path | None]:
    """Resolve the configuration, applying an explicit ``--token-env`` over it.

    Returns the configuration with the path of the per-user config file when
    that file was auto-discovered, else ``None``. The renderers print that
    path under each report's divider rather than here, before collection,
    where it would sit above everything the collection logs.

    ``token_env`` is ``None`` when the flag was not given, which is what makes
    it usable as an override at all: with an eager ``"GITHUB_TOKEN"`` default
    the code could not tell "the user asked for this" from "unset", so the only
    safe reading was to ignore it wherever a config supplied its own value. A
    value that was actually typed now wins over every organisation's configured
    ``token_env``, which is the one thing an operator can mean by passing it
    alongside ``--config``.
    """
    cfg: Config | None = None
    default_path: Path | None = None
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
            cfg = config.load_file(str(default_path))
    if cfg is None or token_env is None:
        return cfg, default_path
    return (
        replace(
            cfg,
            organizations=tuple(
                replace(org_cfg, token_env=token_env) for org_cfg in cfg.organizations
            ),
        ),
        default_path,
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


async def _collect_reports(
    cfg: Config,
    *,
    console: Console,
    now: dt.datetime,
    options: OrgRunOptions,
) -> list[OrgPair] | None:
    """Collect every configured org's report, or None if a token is missing.

    Once each organisation's client closes, what its requests cost is logged
    at INFO: visible with ``--verbose``, which is how a run is measured, and
    silent otherwise. Nothing of it reaches the rendered report. It is logged
    whether or not the collection finished: a run that aborts on a rate limit,
    an outage or a rejected token is exactly the run whose request, retry and
    timing figures are wanted, so the exit path logs them before the error
    propagates. The organisation's run store is opened for the collection and
    closed with the client, so an aborted run still leaves it consistent.
    """
    pairs: list[OrgPair] = []
    for org_cfg in cfg.organizations:
        token = config.resolve_token(org_cfg)
        if not token:
            console.print(
                f"[red]No token in ${org_cfg.token_env} for {org_cfg.name}[/red]"
            )
            return None
        effective_cfg, report_cfg = options.overrides.apply(org_cfg)
        # The pair carries the configuration the collection ran under, so the
        # surfaces render with the same windows and thresholds it was built
        # with rather than the ones a flag overrode.
        effective_cfg = replace(effective_cfg, report=report_cfg)
        client = GitHubClient(token, concurrency=report_cfg.concurrency)
        store = open_run_store(report_cfg.workflow_runs, org_cfg.name)
        try:
            async with client:
                with store:
                    pairs.append(
                        (
                            effective_cfg,
                            await collect.collect_org(
                                client,
                                effective_cfg,
                                report_cfg,
                                generated_at=now,
                                extras=CollectExtras(
                                    run_store=store,
                                    refresh_runs=options.refresh_runs,
                                ),
                            ),
                        )
                    )
        finally:
            # After the context has closed the client, so the elapsed time
            # covers the whole run; the error, if any, carries on from here.
            log.info("GitHub API for %s: %s", org_cfg.name, client.stats.summary())
    return pairs


async def _run_org(cfg: Config, options: OrgRunOptions, *, console: Console) -> int:
    """Collect every configured org, then render, publish and notify."""
    now = dt.datetime.now(dt.timezone.utc)
    pairs = await _collect_reports(cfg, console=console, now=now, options=options)
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
            footer=footer(org_cfg.report),
            windows=windows(org_cfg.report, "cli"),
            config_path=options.config_path,
        )
    if options.output_dir:
        publish.write_pages(
            pairs,
            options.output_dir,
            console=console,
            limits=limits,
            hidden=options.hidden,
        )

    runner.write_github_output(publish.slack_digest(pairs, options, now=now))
    runner.append_step_summary(publish.summary(pairs, limits, options.hidden))
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
    config_path: Path | None = None,
    run_windows: tuple[int, ...] | None = None,
) -> int:
    # Repo mode has no per-org block, so the report config is whatever a
    # supplied --config carried globally, falling back to the built-in
    # defaults. Threading it through is what makes the per-category toggles,
    # row limits and ruleset keywords mean the same thing in both modes.
    cfg = report_cfg if report_cfg is not None else ReportConfig()
    # One repository's runs are read afresh each time rather than cached: a
    # single listing is cheap, and a repo-mode run (a pull request's CI, a
    # developer's shell) should leave nothing behind.
    runs_cfg = ReportOverrides(run_windows=run_windows, run_cache=False).apply_runs(cfg)
    cfg = replace(cfg, workflow_runs=runs_cfg)
    caps = limits if limits is not None else TopNLimits()
    token = os.environ.get(token_env, "").strip()
    if not token:
        console.print(f"[red]No token in ${token_env}[/red]")
        return 2
    now = dt.datetime.now(dt.timezone.utc)
    async with GitHubClient(token, concurrency=cfg.concurrency) as client:
        repo, signals = await collect.collect_repo(
            client, owner, repo_name, ruleset_workflows=cfg.ruleset_workflows
        )
        if repo is None:
            return 2
        org = build_org_report(
            f"{owner}/{repo_name}", signals, repo_count=1, generated_at=now
        )
        with open_run_store(runs_cfg, owner) as store:
            await attach_workflow_failures(
                org,
                [repo],
                collect.repo_context(client, owner),
                cfg,
                CollectExtras(run_store=store),
            )

    # Repo mode renders the same categories, so it resolves the same ordering.
    # The other generic tables are never collected here, and the layout skips
    # keys naming a section this report does not carry.
    org.section_order = layout.resolve(org, cfg.order)
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
        footer=footer(cfg),
        windows=windows(cfg, "cli"),
        config_path=config_path,
    )

    runner.append_step_summary(
        md_render.render_org(
            org,
            top_n=caps.resolve(cfg, "report"),
            show=show(cfg, "markdown", hidden),
            limit=caps.resolver(cfg, "report"),
            footer=footer(cfg),
            windows=windows(cfg, "report"),
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


# The remediate mode lives in its own module; re-exported so the command and
# the tests keep importing it from here.
from github_security_report.cli.remediation import (  # noqa: E402
    _check_selection,
    _run_remediate,
)

__all__ = [
    "_abort_auth",
    "_abort_network",
    "_check_selection",
    "_collect_reports",
    "_load_config",
    "_run_org",
    "_run_remediate",
    "_run_repo",
]
