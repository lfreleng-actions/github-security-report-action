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
"""Phase 0 capability spike for the GitHub Security Report Action.

THROWAWAY. This script exists only to answer the open questions in
``docs/BRIEF.md`` / ``docs/adr/0001-architecture-and-scope.md`` before any
schema, columns, or rendering are committed. It is NOT production code and is
not wired into the package; delete or supersede it once Phase 0 is complete.

What it does
------------
For a target organisation (default ``lfreleng-actions``) it probes each v1
signal and records, per endpoint:

- which transport answers (REST org-bulk / REST per-repo / GraphQL / external);
- the observed HTTP status (so we can pin "enabled-clean vs disabled vs
  insufficient-permission" semantics);
- whether data was returned, and a small scrubbed sample of the shape;
- rate-limit budget consumed.

Outputs
-------
- A capability matrix printed to the terminal (Rich) and written to
  ``phase0-output/capability-matrix.json``.
- Scrubbed sample responses under ``phase0-output/fixtures/<signal>/`` for
  manual review before promotion to ``tests/fixtures/`` as golden fixtures.

``phase0-output/`` is git-ignored: captured data must be reviewed/scrubbed by a
human before anything is committed.

Usage
-----
    export GITHUB_TOKEN=ghp_classic_pat_with_security_events_repo_read_org
    uv run scripts/phase0_capability_spike.py --org lfreleng-actions --sample 5
    # or target specific repos:
    uv run scripts/phase0_capability_spike.py --repo dependamerge --repo project-reporting-tool

A classic PAT with ``security_events``, ``repo`` and ``read:org`` is required
for the org-level security endpoints; ``GITHUB_TOKEN`` (a repo-scoped Actions
token) will 403/404 on them, which is itself a useful result to record.
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import httpx
from rich.console import Console
from rich.table import Table

GITHUB_API = "https://api.github.com"
GRAPHQL_API = "https://api.github.com/graphql"
SCORECARD_API = "https://api.securityscorecards.dev"

OUTPUT_DIR = Path("phase0-output")
FIXTURE_DIR = OUTPUT_DIR / "fixtures"

console = Console()


# --------------------------------------------------------------------------- #
# Result model
# --------------------------------------------------------------------------- #
@dataclass
class ProbeResult:
    """One probe against one endpoint."""

    signal: str
    scope: str  # "org-bulk" | "per-repo" | "graphql" | "external"
    target: str  # org or org/repo
    endpoint: str
    status: int | None = None
    ok: bool = False
    item_count: int | None = None
    enabled_hint: str = ""  # interpretation for the enabled-probe contract
    note: str = ""
    breakdown: str = ""  # e.g. tool/severity mix for code scanning
    rate_remaining: str | None = None


@dataclass
class RepoMeta:
    name: str
    archived: bool
    fork: bool
    is_template: bool
    visibility: str
    language: str | None
    disabled: bool
    size: int

    @property
    def in_default_scope(self) -> bool:
        return not (self.archived or self.fork or self.is_template or self.disabled)


@dataclass
class SpikeReport:
    org: str
    repos_sampled: list[str] = field(default_factory=list)
    results: list[ProbeResult] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Scrubbing
# --------------------------------------------------------------------------- #
# Cap list lengths in saved fixtures: enough to see the tool/severity mix,
# not so many that we hoard live data on disk.
LIST_SAMPLE_CAP = 25

SENSITIVE_KEYS = {
    "secret",
    "token",
    "access_token",
    "password",
    "email",
    "private_key",
}


def scrub(value: Any) -> Any:
    """Recursively redact obviously sensitive values for safe sampling."""
    if isinstance(value, dict):
        return {
            k: ("***REDACTED***" if k.lower() in SENSITIVE_KEYS else scrub(v))
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [scrub(v) for v in value[:LIST_SAMPLE_CAP]]  # keep mix, cap volume
    return value


# --------------------------------------------------------------------------- #
# HTTP helpers
# --------------------------------------------------------------------------- #
def make_client(token: str) -> httpx.Client:
    return httpx.Client(
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "gsr-phase0-spike",
        },
        timeout=30.0,
    )


def get(client: httpx.Client, url: str, **params: Any) -> httpx.Response:
    return client.get(url, params=params or None)


def save_fixture(signal: str, name: str, payload: Any) -> None:
    target = FIXTURE_DIR / signal
    target.mkdir(parents=True, exist_ok=True)
    (target / f"{name}.json").write_text(
        json.dumps(scrub(payload), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


# --------------------------------------------------------------------------- #
# Repo discovery
# --------------------------------------------------------------------------- #
def list_repos(client: httpx.Client, org: str) -> list[RepoMeta]:
    repos: list[RepoMeta] = []
    page = 1
    while True:
        resp = get(
            client,
            f"{GITHUB_API}/orgs/{org}/repos",
            per_page=100,
            page=page,
            type="all",
        )
        if resp.status_code != 200:
            console.print(
                f"[red]Repo listing failed:[/red] {resp.status_code} {resp.text[:200]}"
            )
            break
        batch = resp.json()
        if not batch:
            break
        for r in batch:
            repos.append(
                RepoMeta(
                    name=r["name"],
                    archived=r.get("archived", False),
                    fork=r.get("fork", False),
                    is_template=r.get("is_template", False),
                    visibility=r.get("visibility", "unknown"),
                    language=r.get("language"),
                    disabled=r.get("disabled", False),
                    size=r.get("size", 0),
                )
            )
        if len(batch) < 100:
            break
        page += 1
    return repos


# --------------------------------------------------------------------------- #
# Probes
# --------------------------------------------------------------------------- #
def interpret_status(status: int) -> str:
    return {
        200: "ok",
        403: "forbidden (scope / GHAS not enabled / rate limit)",
        404: "not found (feature disabled or no access)",
        401: "unauthorized (bad token)",
    }.get(status, f"http {status}")


def code_scanning_breakdown(items: list[dict[str, Any]]) -> str:
    """Summarise code-scanning alerts by tool and by severity.

    The single ``/code-scanning/alerts`` feed multiplexes tools (CodeQL,
    Scorecard, zizmor, ...). Partitioning by ``tool.name`` is the whole point
    of this breakdown: it tells us how the org-bulk sweep splits across the v1
    tables. Severity uses ``rule.security_severity_level`` (falling back to
    ``rule.severity``).
    """
    by_tool: collections.Counter[str] = collections.Counter()
    by_tool_sev: collections.Counter[tuple[str, str]] = collections.Counter()
    for a in items:
        tool = (a.get("tool") or {}).get("name") or "unknown"
        rule = a.get("rule") or {}
        sev = rule.get("security_severity_level") or rule.get("severity") or "n/a"
        by_tool[tool] += 1
        by_tool_sev[(tool, sev)] += 1
    tools = " ".join(f"{t}:{n}" for t, n in sorted(by_tool.items()))
    sevs = " ".join(f"{t}/{s}:{n}" for (t, s), n in sorted(by_tool_sev.items()))
    return f"[{tools}] {sevs}"


def probe_org_bulk(client: httpx.Client, org: str) -> list[ProbeResult]:
    results: list[ProbeResult] = []
    matrix = {
        "code-scanning": f"{GITHUB_API}/orgs/{org}/code-scanning/alerts",
        "dependabot": f"{GITHUB_API}/orgs/{org}/dependabot/alerts",
        "secret-scanning": f"{GITHUB_API}/orgs/{org}/secret-scanning/alerts",
    }
    for signal, url in matrix.items():
        # A larger page for code scanning so the tool mix is representative.
        per_page = 100 if signal == "code-scanning" else 30
        resp = get(client, url, per_page=per_page, state="open")
        items = resp.json() if resp.status_code == 200 else None
        count = len(items) if isinstance(items, list) else None
        breakdown = ""
        if isinstance(items, list) and items:
            save_fixture(signal, f"org-bulk-{org}", items)
            if signal == "code-scanning":
                breakdown = code_scanning_breakdown(items)
        results.append(
            ProbeResult(
                signal=signal,
                scope="org-bulk",
                target=org,
                endpoint=url.replace(GITHUB_API, ""),
                status=resp.status_code,
                ok=resp.status_code == 200,
                item_count=count,
                enabled_hint=interpret_status(resp.status_code),
                note="org-level bulk alert sweep"
                + (" (first page only)" if count == per_page else ""),
                breakdown=breakdown,
                rate_remaining=resp.headers.get("x-ratelimit-remaining"),
            )
        )
    return results


def probe_code_scanning(client: httpx.Client, org: str, repo: str) -> list[ProbeResult]:
    results: list[ProbeResult] = []
    slug = f"{org}/{repo}"

    setup = get(client, f"{GITHUB_API}/repos/{slug}/code-scanning/default-setup")
    state = ""
    if setup.status_code == 200:
        state = setup.json().get("state", "")
    results.append(
        ProbeResult(
            signal="code-scanning",
            scope="per-repo",
            target=slug,
            endpoint=f"/repos/{slug}/code-scanning/default-setup",
            status=setup.status_code,
            ok=setup.status_code == 200,
            enabled_hint=(
                f"default-setup={state}"
                if state
                else interpret_status(setup.status_code)
            ),
            note="enabled-probe candidate",
            rate_remaining=setup.headers.get("x-ratelimit-remaining"),
        )
    )

    # CodeQL can run via *advanced* setup (a workflow) even when default-setup
    # reports not-configured, and code scanning can carry other tools' SARIF
    # regardless. The authoritative "is CodeQL enabled" probe is therefore the
    # presence of CodeQL analyses, not the default-setup state.
    analyses = get(
        client,
        f"{GITHUB_API}/repos/{slug}/code-scanning/analyses",
        tool_name="CodeQL",
        per_page=1,
    )
    has_codeql = analyses.status_code == 200 and bool(analyses.json())
    results.append(
        ProbeResult(
            signal="code-scanning",
            scope="per-repo",
            target=slug,
            endpoint=f"/repos/{slug}/code-scanning/analyses?tool_name=CodeQL",
            status=analyses.status_code,
            ok=analyses.status_code == 200,
            enabled_hint=(
                f"CodeQL analyses present={has_codeql}"
                if analyses.status_code == 200
                else interpret_status(analyses.status_code)
            ),
            note="authoritative CodeQL enabled-probe",
            rate_remaining=analyses.headers.get("x-ratelimit-remaining"),
        )
    )

    alerts = get(
        client,
        f"{GITHUB_API}/repos/{slug}/code-scanning/alerts",
        per_page=100,
        state="open",
    )
    items = alerts.json() if alerts.status_code == 200 else None
    count = len(items) if isinstance(items, list) else None
    breakdown = ""
    if isinstance(items, list) and items:
        save_fixture("code-scanning", f"{org}-{repo}", items)
        breakdown = code_scanning_breakdown(items)
    results.append(
        ProbeResult(
            signal="code-scanning",
            scope="per-repo",
            target=slug,
            endpoint=f"/repos/{slug}/code-scanning/alerts",
            status=alerts.status_code,
            ok=alerts.status_code == 200,
            item_count=count,
            enabled_hint=interpret_status(alerts.status_code)
            + (" (empty list is ambiguous)" if count == 0 else ""),
            breakdown=breakdown,
            rate_remaining=alerts.headers.get("x-ratelimit-remaining"),
        )
    )
    return results


def probe_secret_scanning(client: httpx.Client, org: str, repo: str) -> ProbeResult:
    slug = f"{org}/{repo}"
    resp = get(
        client,
        f"{GITHUB_API}/repos/{slug}/secret-scanning/alerts",
        per_page=5,
        state="open",
    )
    items = resp.json() if resp.status_code == 200 else None
    count = len(items) if isinstance(items, list) else None
    if isinstance(items, list) and items:
        save_fixture("secret-scanning", f"{org}-{repo}", items)
    hint = interpret_status(resp.status_code)
    if resp.status_code == 404:
        hint = "404 => feature disabled (enabled-probe signal)"
    elif count == 0:
        hint = "200 [] => enabled, clean"
    return ProbeResult(
        signal="secret-scanning",
        scope="per-repo",
        target=slug,
        endpoint=f"/repos/{slug}/secret-scanning/alerts",
        status=resp.status_code,
        ok=resp.status_code == 200,
        item_count=count,
        enabled_hint=hint,
        rate_remaining=resp.headers.get("x-ratelimit-remaining"),
    )


DEPENDABOT_QUERY = """
query($owner: String!, $name: String!) {
  repository(owner: $owner, name: $name) {
    hasVulnerabilityAlertsEnabled
    vulnerabilityAlerts(first: 5, states: OPEN) {
      totalCount
      nodes {
        securityVulnerability { severity package { name ecosystem } }
      }
    }
  }
}
"""


def probe_dependabot_graphql(client: httpx.Client, org: str, repo: str) -> ProbeResult:
    slug = f"{org}/{repo}"
    resp = client.post(
        GRAPHQL_API,
        json={"query": DEPENDABOT_QUERY, "variables": {"owner": org, "name": repo}},
    )
    hint = interpret_status(resp.status_code)
    count: int | None = None
    if resp.status_code == 200:
        body = resp.json()
        repo_node = (body.get("data") or {}).get("repository")
        if repo_node is None:
            hint = "graphql data.repository=null (check errors)"
        else:
            enabled = repo_node.get("hasVulnerabilityAlertsEnabled")
            alerts = repo_node.get("vulnerabilityAlerts") or {}
            count = alerts.get("totalCount")
            hint = f"hasVulnerabilityAlertsEnabled={enabled}"
            if alerts.get("nodes"):
                save_fixture("dependabot", f"{org}-{repo}", body)
    return ProbeResult(
        signal="dependabot",
        scope="graphql",
        target=slug,
        endpoint="POST /graphql repository.vulnerabilityAlerts",
        status=resp.status_code,
        ok=resp.status_code == 200,
        item_count=count,
        enabled_hint=hint,
        rate_remaining=resp.headers.get("x-ratelimit-remaining"),
    )


def probe_scorecard(org: str, repo: str) -> ProbeResult:
    slug = f"{org}/{repo}"
    url = f"{SCORECARD_API}/projects/github.com/{org}/{repo}"
    try:
        resp = httpx.get(url, timeout=30.0, headers={"User-Agent": "gsr-phase0-spike"})
    except httpx.HTTPError as exc:  # external service; tolerate failure
        return ProbeResult(
            signal="scorecard",
            scope="external",
            target=slug,
            endpoint=url.replace(SCORECARD_API, "securityscorecards.dev"),
            ok=False,
            enabled_hint=f"request failed: {exc}",
        )
    score: Any = None
    if resp.status_code == 200:
        body = resp.json()
        score = body.get("score")
        save_fixture("scorecard", f"{org}-{repo}", body)
    return ProbeResult(
        signal="scorecard",
        scope="external",
        target=slug,
        endpoint=url.replace(SCORECARD_API, "securityscorecards.dev"),
        status=resp.status_code,
        ok=resp.status_code == 200,
        enabled_hint=(
            f"score={score}"
            if score is not None
            else "no published scorecard (=> nag, not clean)"
            if resp.status_code == 404
            else interpret_status(resp.status_code)
        ),
    )


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
def render_matrix(report: SpikeReport) -> None:
    table = Table(title=f"Capability matrix — {report.org}", show_lines=False)
    for col in (
        "Signal",
        "Scope",
        "Target",
        "Status",
        "Items",
        "Interpretation",
        "Tool/severity mix",
        "RL",
    ):
        table.add_column(col, overflow="fold")
    for r in report.results:
        status_style = (
            "green" if r.ok else "yellow" if r.status in (None, 404) else "red"
        )
        table.add_row(
            r.signal,
            r.scope,
            r.target,
            f"[{status_style}]{r.status}[/{status_style}]",
            "" if r.item_count is None else str(r.item_count),
            r.enabled_hint,
            r.breakdown,
            r.rate_remaining or "",
        )
    console.print(table)


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Phase 0 capability spike (throwaway).")
    p.add_argument("--org", default="lfreleng-actions", help="Target organisation.")
    p.add_argument(
        "--repo",
        action="append",
        default=[],
        help="Specific repo to probe (repeatable). Overrides --sample.",
    )
    p.add_argument(
        "--sample",
        type=int,
        default=5,
        help="Number of in-scope repos to sample when --repo is not given.",
    )
    p.add_argument(
        "--token-env",
        default="GITHUB_TOKEN",
        help="Environment variable holding the token.",
    )
    return p.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    token = os.environ.get(args.token_env, "").strip()
    if not token:
        console.print(
            f"[red]No token in ${args.token_env}.[/red] "
            "Export a classic PAT (security_events, repo, read:org)."
        )
        return 2

    OUTPUT_DIR.mkdir(exist_ok=True)
    report = SpikeReport(org=args.org)

    with make_client(token) as client:
        # 1. org-level bulk endpoints (the strategy we prefer)
        console.print("[bold]Probing org-bulk endpoints…[/bold]")
        report.results.extend(probe_org_bulk(client, args.org))

        # 2. choose sample repos
        if args.repo:
            sample = list(args.repo)
        else:
            console.print("[bold]Listing repositories…[/bold]")
            all_repos = list_repos(client, args.org)
            in_scope = [r for r in all_repos if r.in_default_scope]
            console.print(
                f"  {len(all_repos)} total, {len(in_scope)} in default scope "
                f"(non-archived/fork/template/disabled)."
            )
            sample = [r.name for r in in_scope[: args.sample]]
        report.repos_sampled = sample
        console.print(f"[bold]Sampling repos:[/bold] {', '.join(sample) or '(none)'}")

        # 3. per-repo / graphql / external probes
        for repo in sample:
            console.print(f"  → {repo}")
            report.results.extend(probe_code_scanning(client, args.org, repo))
            report.results.append(probe_secret_scanning(client, args.org, repo))
            report.results.append(probe_dependabot_graphql(client, args.org, repo))
            report.results.append(probe_scorecard(args.org, repo))

    render_matrix(report)

    matrix_path = OUTPUT_DIR / "capability-matrix.json"
    matrix_path.write_text(
        json.dumps(
            {
                "org": report.org,
                "repos_sampled": report.repos_sampled,
                "results": [asdict(r) for r in report.results],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    console.print(f"\n[green]Wrote[/green] {matrix_path}")
    console.print(
        f"[green]Scrubbed samples under[/green] {FIXTURE_DIR}/ "
        "(review before promoting to tests/fixtures/)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
