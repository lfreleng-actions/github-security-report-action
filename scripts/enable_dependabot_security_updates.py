#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = [
#   "httpx>=0.28.1",
#   "rich>=14.0.0",
# ]
# ///
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Bulk-enable Dependabot security updates across an organisation.

The reporting tool flags repositories where "Dependabot: Security Updates" is
supported but not switched on (a *nag*). GitHub exposes the toggle through the
REST API, so the whole nag list can be cleared in one pass instead of clicking
through each repository's settings:

- ``PUT /repos/{owner}/{repo}/vulnerability-alerts``    -> Dependabot *alerts*
  (the prerequisite; idempotent, returns ``204``).
- ``PUT /repos/{owner}/{repo}/automated-security-fixes`` -> Dependabot
  *security updates* (returns ``204``).
- ``GET /repos/{owner}/{repo}/automated-security-fixes`` -> current state
  (``{"enabled": bool, "paused": bool}``).

By default the scope matches the reporting tool (see
``src/github_security_report/scope.py``): forks, templates, archived repos,
explicitly-excluded repos and *test* repositories (a token-delimited ``test``/
``tests`` segment) are skipped. Empty repositories -- those with no code -- are
skipped too (the reporting tool already drops them at the listing stage); the
``--include-empty`` flag overrides this and deliberately acts on repositories
the report never includes. Pass ``--config`` to read the org name and
exclusions straight from the tool's JSON config so the two never drift.

Safety
------
This performs privileged writes with whatever token you supply (typically a
classic "god" PAT with org admin). It is therefore **dry-run by default**: it
prints exactly what it would change and touches nothing. Re-run with ``--apply``
to perform the writes.

Usage
-----
    # Load the org-admin token (exports $GITHUB_TOKEN), then preview:
    . ~/.secrets.github.classic.god
    uv run scripts/enable_dependabot_security_updates.py \
        --config ~/.config/github-security-report/config.json

    # Looks right? Switch them on for real:
    uv run scripts/enable_dependabot_security_updates.py \
        --config ~/.config/github-security-report/config.json --apply

    # Or drive it entirely from flags / a different token variable:
    uv run scripts/enable_dependabot_security_updates.py \
        --org lfreleng-actions --token-env SECURITY_REPORT_PAT \
        --exclude project-reporting-artifacts --apply
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path

import httpx
from rich.console import Console
from rich.table import Table

GITHUB_API = "https://api.github.com"

console = Console()

# Repo-name scoping, kept byte-for-byte aligned with
# ``src/github_security_report/scope.py``: split on these delimiters and treat a
# whole ``test``/``tests`` segment as a test repo (so ``latest`` and
# ``attestation`` are NOT matched).
_SEGMENT_SPLIT = re.compile(r"[-_./]+")
_TEST_SEGMENTS = {"test", "tests"}


def is_test_named(name: str) -> bool:
    """True when a name segment is exactly ``test`` or ``tests``."""
    segments = {seg.lower() for seg in _SEGMENT_SPLIT.split(name) if seg}
    return bool(segments & _TEST_SEGMENTS)


# --------------------------------------------------------------------------- #
# Models
# --------------------------------------------------------------------------- #
@dataclass
class RepoMeta:
    name: str
    archived: bool
    fork: bool
    is_template: bool
    disabled: bool
    size: int


@dataclass
class RepoOutcome:
    name: str
    before: str  # "enabled" | "disabled" | "unknown"
    action: str  # "already on" | "enabled" | "would enable" | "FAILED"
    after: str  # "enabled" | "disabled" | "-"
    note: str = ""

    @property
    def failed(self) -> bool:
        return self.action == "FAILED"


@dataclass
class Plan:
    org: str
    exclude: frozenset[str]
    include_archived: bool
    include_test: bool
    include_empty: bool


# --------------------------------------------------------------------------- #
# HTTP
# --------------------------------------------------------------------------- #
def make_client(token: str) -> httpx.Client:
    return httpx.Client(
        base_url=GITHUB_API,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "gsr-enable-dependabot-security-updates",
        },
        timeout=30.0,
    )


def list_repos(client: httpx.Client, org: str) -> list[RepoMeta]:
    """Every repository in the org (forks included; filtered later)."""
    repos: list[RepoMeta] = []
    page = 1
    while True:
        resp = client.get(
            f"/orgs/{org}/repos",
            params={"per_page": 100, "page": page, "type": "all"},
        )
        if resp.status_code != 200:
            raise SystemExit(
                f"Repo listing failed: {resp.status_code} {resp.text[:200]}"
            )
        batch = resp.json()
        if not batch:
            break
        repos.extend(
            RepoMeta(
                name=r["name"],
                archived=r.get("archived", False),
                fork=r.get("fork", False),
                is_template=r.get("is_template", False),
                disabled=r.get("disabled", False),
                size=r.get("size", 0),
            )
            for r in batch
        )
        if len(batch) < 100:
            break
        page += 1
    return repos


def scope_reason(repo: RepoMeta, plan: Plan) -> str | None:
    """Why a repo is out of scope, or None when it is in scope."""
    if repo.name in plan.exclude:
        return "explicitly excluded"
    if repo.fork:
        return "fork"
    if repo.is_template:
        return "template"
    if repo.archived and not plan.include_archived:
        return "archived"
    if repo.disabled:
        return "disabled"
    if is_test_named(repo.name) and not plan.include_test:
        return "test repository"
    if repo.size == 0 and not plan.include_empty:
        return "empty (no code)"
    return None


def current_state(client: httpx.Client, org: str, repo: str) -> tuple[str, str]:
    """Return (state, note) where state is enabled/disabled/unknown.

    A 404 from this endpoint usually means Dependabot alerts (the prerequisite
    for security updates) are not enabled -- i.e. security updates are off,
    which is exactly what this script remediates. It is therefore treated as
    ``disabled`` so the enable path runs; a genuinely missing or forbidden
    repository will instead surface as a failed write from ``enable()``. A 403
    is a real permission problem (the write would fail too) and stays unknown.
    """
    resp = client.get(f"/repos/{org}/{repo}/automated-security-fixes")
    if resp.status_code == 200:
        body = resp.json()
        enabled = bool(body.get("enabled"))
        paused = bool(body.get("paused"))
        note = "paused" if (enabled and paused) else ""
        return ("enabled" if enabled else "disabled", note)
    if resp.status_code == 404:
        return ("disabled", "no automated-security-fixes (alerts off?)")
    if resp.status_code == 403:
        return ("unknown", "403 (insufficient permission)")
    return ("unknown", f"{resp.status_code} {resp.text[:80]}")


def enable(client: httpx.Client, org: str, repo: str) -> tuple[bool, str]:
    """Enable alerts (prerequisite) then security updates. (ok, note)."""
    alerts = client.put(f"/repos/{org}/{repo}/vulnerability-alerts")
    if alerts.status_code != 204:
        return (
            False,
            f"vulnerability-alerts -> {alerts.status_code} {alerts.text[:80]}",
        )
    fixes = client.put(f"/repos/{org}/{repo}/automated-security-fixes")
    if fixes.status_code != 204:
        return (
            False,
            f"automated-security-fixes -> {fixes.status_code} {fixes.text[:80]}",
        )
    return (True, "")


# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #
def plan_from_config(path: str, org_override: str | None) -> Plan:
    """Build the scope Plan from the reporting tool's JSON config."""
    data = json.loads(Path(path).expanduser().read_text(encoding="utf-8"))
    orgs = data.get("organizations", [])
    if not orgs:
        raise SystemExit(f"No organizations in config: {path}")
    chosen = None
    if org_override:
        chosen = next((o for o in orgs if o.get("name") == org_override), None)
        if chosen is None:
            raise SystemExit(f"Org {org_override!r} not found in config: {path}")
    else:
        chosen = orgs[0]
    report = {**data.get("report", {}), **chosen.get("report", {})}
    return Plan(
        org=chosen["name"],
        exclude=frozenset(chosen.get("exclude", ())),
        include_archived=bool(report.get("include_archived", False)),
        include_test=bool(report.get("include_test", False)),
        include_empty=False,
    )


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
def render(outcomes: list[RepoOutcome], *, apply: bool) -> None:
    table = Table(
        title="Dependabot security updates "
        + ("(APPLIED)" if apply else "(DRY RUN — no changes made)"),
        show_lines=False,
    )
    for col in ("Repository", "Before", "Action", "After", "Note"):
        table.add_column(col, overflow="fold")
    for o in outcomes:
        if o.failed:
            action_style = "red"
        elif o.action in ("enabled", "would enable"):
            action_style = "green"
        else:
            action_style = "dim"
        table.add_row(
            o.name,
            o.before,
            f"[{action_style}]{o.action}[/{action_style}]",
            o.after,
            o.note,
        )
    console.print(table)


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Bulk-enable Dependabot security updates (dry-run by default)."
    )
    p.add_argument(
        "--config",
        help="Reporting-tool JSON config to read org + exclusions from.",
    )
    p.add_argument("--org", help="Target organisation (overrides/!needs config).")
    p.add_argument(
        "--token-env",
        default="GITHUB_TOKEN",
        help="Environment variable holding the token (default: GITHUB_TOKEN).",
    )
    p.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="Repository to skip (repeatable). Merged with any config excludes.",
    )
    p.add_argument(
        "--repo",
        action="append",
        default=[],
        help="Operate only on these repos (repeatable). Skips org listing/scope.",
    )
    p.add_argument(
        "--include-archived", action="store_true", help="Include archived repos."
    )
    p.add_argument(
        "--include-test", action="store_true", help="Include test repositories."
    )
    p.add_argument(
        "--include-empty",
        action="store_true",
        help="Include empty (zero-size, no-code) repos.",
    )
    p.add_argument(
        "--limit", type=int, default=0, help="Process at most N repos (0 = all)."
    )
    p.add_argument(
        "--apply",
        action="store_true",
        help="Perform the writes. Without this flag the script only previews.",
    )
    return p.parse_args(argv)


def build_plan(args: argparse.Namespace) -> Plan:
    if args.config:
        plan = plan_from_config(args.config, args.org)
    elif args.org:
        plan = Plan(
            org=args.org,
            exclude=frozenset(),
            include_archived=False,
            include_test=False,
            include_empty=False,
        )
    else:
        raise SystemExit("Provide --config or --org.")
    return Plan(
        org=plan.org,
        exclude=frozenset(plan.exclude | set(args.exclude)),
        include_archived=plan.include_archived or args.include_archived,
        include_test=plan.include_test or args.include_test,
        include_empty=plan.include_empty or args.include_empty,
    )


def select_repos(
    client: httpx.Client, args: argparse.Namespace, plan: Plan
) -> list[str]:
    if args.repo:
        return list(args.repo)
    all_repos = list_repos(client, plan.org)
    in_scope: list[str] = []
    for repo in all_repos:
        reason = scope_reason(repo, plan)
        if reason is None:
            in_scope.append(repo.name)
        else:
            console.print(f"  [dim]skip {repo.name}: {reason}[/dim]")
    console.print(
        f"[bold]{len(in_scope)}[/bold] in scope of "
        f"[bold]{len(all_repos)}[/bold] total in {plan.org}."
    )
    return in_scope


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    token = os.environ.get(args.token_env, "").strip()
    if not token:
        console.print(
            f"[red]No token in ${args.token_env}.[/red] Export an org-admin "
            "PAT (e.g. 'source ~/.secrets.github.classic.god')."
        )
        return 2

    plan = build_plan(args)
    if not args.apply:
        console.print(
            "[yellow]DRY RUN[/yellow] — previewing only. Re-run with "
            "[bold]--apply[/bold] to make changes."
        )

    outcomes: list[RepoOutcome] = []
    with make_client(token) as client:
        repos = select_repos(client, args, plan)
        if args.limit > 0:
            repos = repos[: args.limit]

        for name in repos:
            before, note = current_state(client, plan.org, name)
            if before == "enabled":
                outcomes.append(
                    RepoOutcome(name, before, "already on", "enabled", note)
                )
                continue
            if before == "unknown":
                # Don't blind-write where we couldn't read the state.
                outcomes.append(RepoOutcome(name, before, "FAILED", "-", note))
                continue
            if not args.apply:
                outcomes.append(RepoOutcome(name, before, "would enable", "-", note))
                continue
            ok, err = enable(client, plan.org, name)
            if ok:
                after, after_note = current_state(client, plan.org, name)
                outcomes.append(RepoOutcome(name, before, "enabled", after, after_note))
            else:
                outcomes.append(RepoOutcome(name, before, "FAILED", "-", err))

    render(outcomes, apply=args.apply)

    enabled = sum(1 for o in outcomes if o.action == "enabled")
    would = sum(1 for o in outcomes if o.action == "would enable")
    already = sum(1 for o in outcomes if o.action == "already on")
    failed = [o for o in outcomes if o.failed]
    console.print(
        f"\n[bold]Summary:[/bold] {already} already on, "
        + (f"{enabled} enabled, " if args.apply else f"{would} to enable (dry run), ")
        + f"{len(failed)} failed."
    )
    if failed:
        console.print("[red]Failures:[/red]")
        for o in failed:
            console.print(f"  {o.name}: {o.note}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
