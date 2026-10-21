# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""End-to-end CLI tests (respx-mocked GitHub, no live network)."""

from __future__ import annotations

import json
import logging
import re
import subprocess
import sys
from pathlib import Path
from typing import ClassVar

import httpx
import pytest
import respx
import yaml
from rich.console import Console
from typer.testing import CliRunner

from github_security_report import scope
from github_security_report.categories import CategoryKey
from github_security_report.cli import _safe_component, app
from github_security_report.cli.modes import _check_selection, _load_config
from github_security_report.cli.options import ReportOverrides
from github_security_report.cli.outputs import (
    TopNLimits,
    most_generous,
    slack_footer,
    slack_limit,
    slack_show,
)
from github_security_report.client import RequestStats
from github_security_report.config import (
    CategoryToggle,
    Config,
    OrgConfig,
    OutputToggles,
    ReportConfig,
)
from github_security_report.models import Repo
from github_security_report.report import OrgReport, RepoList, build_org_report

API = "https://api.github.com"
SCORECARD = "https://api.securityscorecards.dev"


def _mock_pattern_inventory() -> None:
    """Register the best-effort secret-scanning pattern inventory read.

    Every secret-scanning read validates its generic-pattern list against this
    endpoint before sweeping. It needs an org permission the tool does not
    otherwise ask for, so 404 is the ordinary answer for the tokens the README
    recommends, and the one these end-to-end tests exercise.
    """
    respx.get(
        url__startswith=f"{API}/orgs/o/secret-scanning/pattern-configurations"
    ).mock(return_value=httpx.Response(404))


cli = CliRunner()


def _org_graphql_side(request: httpx.Request) -> httpx.Response:
    """Answer the batched org-mode prefetch query for each ``n{idx}`` variable.

    Returns a minimal repository node per alias (alerts enabled, no config, no
    tags, no releases), mirroring the shape :func:`client.repo_graph_batch`
    expects so org-mode tests need no per-repo dependabot.yml/releases mocks.

    The viewer query is answered with a human account, since that is the
    ordinary case: a run authenticated as a person is what makes the personal
    review queue meaningful, and therefore what the visibility rules around it
    are worth exercising.
    """
    payload = json.loads(request.content)
    if "viewer {" in payload.get("query", ""):
        return httpx.Response(
            200, json={"data": {"viewer": {"__typename": "User", "login": "alice"}}}
        )
    variables = payload.get("variables", {})
    data: dict[str, object] = {}
    for key in variables:
        if not key.startswith("n"):
            continue
        idx = key[1:]
        data[f"r{idx}"] = {
            "hasVulnerabilityAlertsEnabled": True,
            "dependabotConfig": None,
            "tags": {"nodes": []},
            "releases": {"nodes": []},
        }
    return httpx.Response(200, json={"data": data})


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    monkeypatch.delenv("GITHUB_OUTPUT", raising=False)
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)


def test_version() -> None:
    result = cli.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "github-security-report version" in result.stdout


def test_safe_component_blocks_path_traversal() -> None:
    # A channel value used to build a filename must not escape output_dir.
    assert _safe_component("C0123ABC") == "C0123ABC"  # normal Slack ID preserved
    for hostile in ("../etc", "a/b", "..", "../../x"):
        safe = _safe_component(hostile)
        assert "/" not in safe
        assert ".." not in safe
    assert _safe_component("///") == "channel"


@respx.mock
def test_org_mode_writes_pages(tmp_path: Path) -> None:
    respx.get(url__startswith=f"{API}/orgs/o/repos").mock(
        return_value=httpx.Response(
            200,
            json=[
                {
                    "name": "r",
                    "full_name": "o/r",
                    "html_url": "https://github.com/o/r",
                    "size": 10,
                }
            ],
        )
    )
    for kind in ("code-scanning", "dependabot", "secret-scanning"):
        respx.get(url__startswith=f"{API}/orgs/o/{kind}/alerts").mock(
            return_value=httpx.Response(200, json=[])
        )
    _mock_pattern_inventory()
    respx.get(url__startswith=f"{API}/orgs/o/rulesets").mock(
        return_value=httpx.Response(200, json=[])
    )
    respx.get(url__startswith=f"{API}/repos/o/r/code-scanning/analyses").mock(
        return_value=httpx.Response(200, json=[{"tool": {"name": "CodeQL"}}])
    )
    respx.get(url__startswith=f"{API}/repos/o/r/secret-scanning/alerts").mock(
        return_value=httpx.Response(200, json=[])
    )
    respx.post(f"{API}/graphql").mock(side_effect=_org_graphql_side)
    respx.get(url__startswith=f"{SCORECARD}/projects/github.com/o/r").mock(
        return_value=httpx.Response(404)
    )

    # Dependabot posture: only the security-updates flag remains a REST call;
    # alerts/config/releases all come from the batched GraphQL prefetch.
    respx.get(url__startswith=f"{API}/repos/o/r/automated-security-fixes").mock(
        return_value=httpx.Response(200, json={"enabled": True, "paused": False})
    )
    # Private vulnerability reporting is probed per repo, always.
    respx.get(url__startswith=f"{API}/repos/o/r/private-vulnerability-reporting").mock(
        return_value=httpx.Response(200, json={"enabled": True})
    )
    respx.get(f"{API}/repos/o/r/code-scanning/default-setup").mock(
        return_value=httpx.Response(200, json={"state": "not-configured"})
    )

    out = tmp_path / "site"
    result = cli.invoke(
        app,
        [
            "report",
            "--org",
            "o",
            "--output-dir",
            str(out),
            "--no-color",
            "--force-notify",
            "--slack-channel",
            "CTEST123",
        ],
    )
    assert result.exit_code == 0, result.stdout
    assert (out / "index.html").exists()
    assert (out / "o" / "report.html").exists()
    assert (out / "o" / "report.md").exists()
    assert (out / "o" / "report.json").exists()
    # The whole pipeline resolves a section order and publishes it, so a JSON
    # consumer can reproduce the layout the rendered surfaces used.
    payload = json.loads((out / "o" / "report.json").read_text())
    assert payload["section_order"], payload
    # Nothing is invented or lost by the reordering.
    assert len(set(payload["section_order"])) == len(payload["section_order"])
    # This org is entirely clean, so every priority band member demotes and
    # the BAU categories still hold the bottom. "Assigned to Me" is not built
    # at all here (the run did not authenticate as a personal account), so the
    # band's last *present* member trails instead -- which also pins that a key
    # naming an uncollected category is skipped rather than invented.
    assert payload["section_order"][-1] == CategoryKey.PULL_REQUESTS.value
    assert CategoryKey.PULL_REQUESTS_ASSIGNED.value not in payload["section_order"]
    # --slack-channel supplies the channel even though the config has none,
    # so a payload is written for that channel.
    assert (out / "slack-payload-CTEST123.json").exists()


def _mock_org_o_r() -> None:
    """Register the standard org-mode endpoint mocks for org ``o`` / repo ``r``."""
    respx.get(url__startswith=f"{API}/orgs/o/repos").mock(
        return_value=httpx.Response(
            200,
            json=[
                {
                    "name": "r",
                    "full_name": "o/r",
                    "html_url": "https://github.com/o/r",
                    "size": 10,
                }
            ],
        )
    )
    for kind in ("code-scanning", "dependabot", "secret-scanning"):
        respx.get(url__startswith=f"{API}/orgs/o/{kind}/alerts").mock(
            return_value=httpx.Response(200, json=[])
        )
    _mock_pattern_inventory()
    respx.get(url__startswith=f"{API}/orgs/o/rulesets").mock(
        return_value=httpx.Response(200, json=[])
    )
    respx.get(url__startswith=f"{API}/repos/o/r/code-scanning/analyses").mock(
        return_value=httpx.Response(200, json=[{"tool": {"name": "CodeQL"}}])
    )
    respx.get(url__startswith=f"{API}/repos/o/r/secret-scanning/alerts").mock(
        return_value=httpx.Response(200, json=[])
    )
    respx.post(f"{API}/graphql").mock(side_effect=_org_graphql_side)
    respx.get(url__startswith=f"{SCORECARD}/projects/github.com/o/r").mock(
        return_value=httpx.Response(404)
    )
    respx.get(url__startswith=f"{API}/repos/o/r/automated-security-fixes").mock(
        return_value=httpx.Response(200, json={"enabled": True, "paused": False})
    )
    respx.get(url__startswith=f"{API}/repos/o/r/private-vulnerability-reporting").mock(
        return_value=httpx.Response(200, json={"enabled": True})
    )
    respx.get(f"{API}/repos/o/r/code-scanning/default-setup").mock(
        return_value=httpx.Response(200, json={"state": "not-configured"})
    )


def _write_default_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Place a per-user config for org ``o`` where discovery will find it."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    cfg_dir = tmp_path / "github-security-report"
    cfg_dir.mkdir()
    path = cfg_dir / "config.json"
    path.write_text(
        json.dumps({"organizations": [{"name": "o", "token_env": "GITHUB_TOKEN"}]}),
        encoding="utf-8",
    )
    return path


def _line_after(stdout: str, marker: str) -> str:
    """The line printed directly beneath the first line containing ``marker``."""
    lines = stdout.splitlines()
    index = next(i for i, line in enumerate(lines) if marker in line)
    return lines[index + 1]


@respx.mock
def test_org_mode_uses_default_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # With no --config/--config-data/--org, a per-user config file under
    # $XDG_CONFIG_HOME is discovered and used (org mode), rather than erroring.
    _write_default_config(tmp_path, monkeypatch)
    _mock_org_o_r()

    result = cli.invoke(app, ["report", "--scope", "org", "--no-color"])
    assert result.exit_code == 0, result.stdout
    # Named under the divider, not above it with the collection's own output.
    assert result.stdout.count("Using config") == 1
    assert _line_after(result.stdout, "Security report: o").startswith("Using config:")


def _graphql_without_read_org(request: httpx.Request) -> httpx.Response:
    """The org-mode GraphQL answers for a classic token lacking ``read:org``."""
    if "membersWithRole" in json.loads(request.content).get("query", ""):
        return httpx.Response(
            200,
            json={
                "data": {"organization": None},
                "errors": [
                    {
                        "type": "INSUFFICIENT_SCOPES",
                        "message": "The 'viewerIsAMember' field requires one of "
                        "the following scopes: ['read:org']",
                    }
                ],
            },
        )
    return _org_graphql_side(request)


@respx.mock
def test_missing_read_org_warns_once_under_the_divider(
    caplog: pytest.LogCaptureFixture,
) -> None:
    _mock_org_o_r()
    respx.post(f"{API}/graphql").mock(side_effect=_graphql_without_read_org)
    with caplog.at_level(logging.INFO):
        result = cli.invoke(app, ["report", "--org", "o", "--no-color"])
    assert result.exit_code == 0, result.stdout
    assert result.stdout.count("\u26a0\ufe0f") == 1
    assert _line_after(result.stdout, "Security report: o") == (
        "\u26a0\ufe0f Token lacks read/organisation permission; "
        "results incomplete for o"
    )
    # The cause stays visible with --verbose, but nothing warns about it.
    assert not [
        r
        for r in caplog.records
        if r.levelno >= logging.WARNING and "membership" in r.getMessage()
    ]


@respx.mock
def test_explicit_config_prints_no_config_line(tmp_path: Path) -> None:
    _mock_org_o_r()
    path = tmp_path / "c.json"
    path.write_text(
        json.dumps({"organizations": [{"name": "o", "token_env": "GITHUB_TOKEN"}]}),
        encoding="utf-8",
    )
    result = cli.invoke(app, ["report", "--config", str(path), "--no-color"])
    assert result.exit_code == 0, result.stdout
    assert "Using config" not in result.stdout


@respx.mock
def test_hide_suppresses_a_category_the_config_enables() -> None:
    # The suppression is a decision about this run, so it outranks the shared
    # configuration -- a scheduled job can keep a reader-specific table out of
    # its published artifacts without editing the config every org shares.
    _mock_org_o_r()
    data = json.dumps(
        {
            "report": {
                "categories": {
                    "pull_requests_assigned": {
                        "enabled": True,
                        "outputs": {"cli": True},
                    }
                }
            },
            "organizations": [{"name": "o", "token_env": "GITHUB_TOKEN"}],
        }
    )
    shown = cli.invoke(app, ["report", "--config-data", data, "--no-color"])
    assert shown.exit_code == 0, shown.stdout
    assert "Assigned to Me" in shown.stdout

    hidden = cli.invoke(
        app,
        [
            "report",
            "--config-data",
            data,
            "--hide",
            "pull_requests_assigned",
            "--no-color",
        ],
    )
    assert hidden.exit_code == 0, hidden.stdout
    assert "Assigned to Me" not in hidden.stdout


@respx.mock
def test_hide_cannot_re_enable_a_disabled_category() -> None:
    # One-way by design: naming a category can only ever suppress it, so a
    # caller cannot accidentally publish something the config switched off.
    _mock_org_o_r()
    data = json.dumps(
        {
            "report": {"categories": {"pull_requests_assigned": {"enabled": False}}},
            "organizations": [{"name": "o", "token_env": "GITHUB_TOKEN"}],
        }
    )
    result = cli.invoke(app, ["report", "--config-data", data, "--no-color"])
    assert result.exit_code == 0, result.stdout
    assert "Assigned to Me" not in result.stdout


def test_unknown_hide_category_is_rejected() -> None:
    # A typo that silently published the category anyway would be the one
    # failure mode this flag exists to prevent.
    result = cli.invoke(
        app, ["report", "--org", "o", "--hide", "pull_requests_assigne", "--no-color"]
    )
    assert result.exit_code == 2
    assert "Unknown --hide category" in result.stdout
    # The message must name the valid values, since the keys are not guessable.
    assert "pull_requests_assigned" in result.stdout


@respx.mock
def test_hide_keeps_a_category_out_of_report_json(tmp_path: Path) -> None:
    # report.json is written into the published Pages directory, so ignoring an
    # explicit --hide there would publish exactly what the operator asked to
    # keep out of shared output -- however the rendered pages behave.
    _mock_org_o_r()
    data = json.dumps({"organizations": [{"name": "o", "token_env": "GITHUB_TOKEN"}]})
    result = cli.invoke(
        app,
        [
            "report",
            "--config-data",
            data,
            "--output-dir",
            str(tmp_path),
            "--hide",
            "pull_requests_assigned",
            "--no-color",
        ],
    )
    assert result.exit_code == 0, result.stdout
    payload = json.loads((tmp_path / "o" / "report.json").read_text())
    assert payload["assigned_pull_requests"] is None
    # Everything else is still the complete dataset: --hide is the only thing
    # that removes data, and only what it names.
    assert payload["pull_requests"] is not None
    assert payload["issues"] is not None


@respx.mock
def test_report_json_omits_terminal_only_categories(tmp_path: Path) -> None:
    # report.json is written into the published Pages directory, so a category
    # no published surface carries has no business in it either -- serialising
    # the terminal-only personal queue would publish one account's review
    # backlog through the back door while every rendered surface omitted it.
    _mock_org_o_r()
    data = json.dumps({"organizations": [{"name": "o", "token_env": "GITHUB_TOKEN"}]})
    result = cli.invoke(
        app,
        ["report", "--config-data", data, "--output-dir", str(tmp_path), "--no-color"],
    )
    assert result.exit_code == 0, result.stdout
    payload = json.loads((tmp_path / "o" / "report.json").read_text())
    assert payload["assigned_pull_requests"] is None
    # Everything a published surface does carry is still there in full: the
    # per-surface toggles do not otherwise filter the JSON.
    assert payload["pull_requests"] is not None
    assert payload["issues"] is not None


@respx.mock
def test_report_json_keeps_a_category_any_published_surface_shows(
    tmp_path: Path,
) -> None:
    # Opting the personal queue into one published surface puts it back in the
    # JSON: the exclusion is "nothing published carries this", not "the
    # terminal shows it".
    _mock_org_o_r()
    data = json.dumps(
        {
            "report": {
                "categories": {"pull_requests_assigned": {"outputs": {"html": True}}}
            },
            "organizations": [{"name": "o", "token_env": "GITHUB_TOKEN"}],
        }
    )
    result = cli.invoke(
        app,
        ["report", "--config-data", data, "--output-dir", str(tmp_path), "--no-color"],
    )
    assert result.exit_code == 0, result.stdout
    payload = json.loads((tmp_path / "o" / "report.json").read_text())
    assert payload["assigned_pull_requests"] is not None


@respx.mock
def test_rejected_credentials_abort_instead_of_reporting_no_data() -> None:
    # A rotated, expired or revoked token used to produce a full report saying
    # "0 repositories analysed" with every section "No data" / "All Clean".
    # In CI that renders a confidently clean report and publishes it over a
    # good one, so the run must abort and print nothing resembling a report.
    respx.get(url__startswith=f"{API}/orgs/o").mock(
        return_value=httpx.Response(401, json={"message": "Bad credentials"})
    )
    respx.post(f"{API}/graphql").mock(
        return_value=httpx.Response(401, json={"message": "Bad credentials"})
    )

    result = cli.invoke(app, ["report", "--org", "o", "--no-color"])

    # Exit 4 is authentication, distinct from usage (2) and connectivity (3),
    # so a caller can tell "rotate the token" from "retry later".
    assert result.exit_code == 4, result.stdout
    assert "401" in result.stdout
    assert "Security report:" not in result.stdout
    assert "All Clean" not in result.stdout
    assert "No data" not in result.stdout


@respx.mock
def test_repo_mode_fail_threshold(tmp_path: Path) -> None:
    respx.get(f"{API}/repos/o/r").mock(
        return_value=httpx.Response(
            200,
            json={
                "name": "r",
                "full_name": "o/r",
                "html_url": "https://github.com/o/r",
            },
        )
    )
    respx.get(url__startswith=f"{API}/repos/o/r/code-scanning/analyses").mock(
        return_value=httpx.Response(200, json=[{"tool": {"name": "CodeQL"}}])
    )
    respx.get(url__startswith=f"{API}/repos/o/r/code-scanning/alerts").mock(
        return_value=httpx.Response(
            200,
            json=[
                {
                    "tool": {"name": "CodeQL"},
                    "rule": {"security_severity_level": "critical"},
                }
            ],
        )
    )
    respx.get(url__startswith=f"{API}/repos/o/r/secret-scanning/alerts").mock(
        return_value=httpx.Response(404)
    )
    _mock_pattern_inventory()
    respx.post(f"{API}/graphql").mock(
        return_value=httpx.Response(
            200, json={"data": {"repository": {"hasVulnerabilityAlertsEnabled": False}}}
        )
    )
    respx.get(url__startswith=f"{API}/repos/o/r/dependabot/alerts").mock(
        return_value=httpx.Response(200, json=[])
    )
    respx.get(url__startswith=f"{API}/repos/o/r/rules/branches").mock(
        return_value=httpx.Response(200, json=[])
    )
    respx.get(url__startswith=f"{SCORECARD}/projects/github.com/o/r").mock(
        return_value=httpx.Response(404)
    )

    # A critical CodeQL alert with --fail-threshold high must fail the run.
    result = cli.invoke(
        app,
        [
            "report",
            "--repo",
            "o/r",
            "--scope",
            "repo",
            "--fail-threshold",
            "high",
            "--no-color",
        ],
    )
    assert result.exit_code == 1, result.stdout

    # The same findings with threshold none must pass.
    ok = cli.invoke(
        app,
        [
            "report",
            "--repo",
            "o/r",
            "--scope",
            "repo",
            "--fail-threshold",
            "none",
            "--no-color",
        ],
    )
    assert ok.exit_code == 0, ok.stdout

    # --hide promises suppression on "every output", so it has to reach repo
    # mode too. A flag accepted and validated but then ignored is worse than
    # one rejected: nothing tells the caller it did nothing.
    assert "CodeQL" in ok.stdout
    hidden = cli.invoke(
        app,
        [
            "report",
            "--repo",
            "o/r",
            "--scope",
            "repo",
            "--hide",
            "codeql",
            "--no-color",
        ],
    )
    assert hidden.exit_code == 0, hidden.stdout
    assert "CodeQL" not in hidden.stdout
    # Only the named category goes; the rest of the report is untouched.
    assert "Secret Scanning" in hidden.stdout

    # A config's per-category toggles reach repo mode too. They were collected,
    # validated and then never consulted: the run rendered with bare defaults,
    # so every report.categories.* switch was inert here.
    configured = cli.invoke(
        app,
        [
            "report",
            "--repo",
            "o/r",
            "--scope",
            "repo",
            "--config-data",
            json.dumps(
                {
                    "organizations": [{"name": "o"}],
                    "report": {"categories": {"codeql": {"enabled": False}}},
                }
            ),
            "--no-color",
        ],
    )
    assert configured.exit_code == 0, configured.stdout
    assert "CodeQL" not in configured.stdout
    assert "Secret Scanning" in configured.stdout


def test_unresolvable_scope_errors() -> None:
    # No config and an explicit org scope -> mode error, exit 2.
    result = cli.invoke(app, ["report", "--scope", "org", "--no-color"])
    assert result.exit_code == 2


def test_negative_top_n_rejected() -> None:
    # --top-n must match the config schema minimum of 0 (0 = no limit).
    result = cli.invoke(app, ["report", "--org", "o", "--top-n=-1", "--no-color"])
    assert result.exit_code == 2
    assert "top-n" in result.stdout


@pytest.mark.parametrize("flag", ["--top-n-report", "--top-n-cli", "--top-n-slack"])
def test_negative_per_category_top_n_rejected(flag: str) -> None:
    result = cli.invoke(app, ["report", "--org", "o", f"{flag}=-1", "--no-color"])
    assert result.exit_code == 2
    assert flag in result.stdout


@pytest.mark.parametrize("value", ["0", "-1"])
def test_graph_batch_below_one_rejected(value: str) -> None:
    # Unlike a row limit, a batch size has no "unlimited" reading of 0: a query
    # carrying no repositories is not a query. The floor is 1, matching the
    # config schema.
    result = cli.invoke(
        app, ["report", "--org", "o", f"--graph-batch={value}", "--no-color"]
    )
    assert result.exit_code == 2
    assert "--graph-batch must be 1 or greater" in result.stdout


@pytest.mark.parametrize("bad", ["justaname", "o/r/extra", "/r", "o/"])
def test_malformed_repo_rejected(bad: str) -> None:
    # An explicit --repo that is not exactly 'owner/name' must error, not
    # silently fall back to git detection or target an unintended repository.
    result = cli.invoke(app, ["report", "--repo", bad, "--scope", "repo", "--no-color"])
    assert result.exit_code == 2
    assert "owner/name" in result.stdout


@pytest.mark.parametrize(
    "flag",
    [
        ["--output-dir", "out"],
        ["--pages-url", "https://example.invalid"],
        ["--slack-channel", "C123"],
        ["--force-notify"],
        ["--top-n-slack", "3"],
        ["--repo-min-age-days", "7"],
        ["--release-max-age-days", "7"],
        ["--releases-exclude", "r"],
        ["--graph-batch", "5"],
    ],
)
def test_org_only_flags_rejected_in_repo_mode(flag: list[str]) -> None:
    # Each of these shapes an organisation-wide run only. Repo mode publishes
    # no Pages directory, posts no digest and builds no Releases table, so
    # accepting one and discarding it would leave the caller no signal that the
    # run ignored what they asked for.
    result = cli.invoke(
        app, ["report", "--repo", "o/r", "--scope", "repo", "--no-color", *flag]
    )
    assert result.exit_code == 2, result.stdout
    assert flag[0] in result.stdout
    assert "organisation mode only" in result.stdout


@pytest.mark.parametrize("flag", ["--top-n", "--top-n-cli", "--top-n-report"])
def test_repo_mode_accepts_the_limits_it_applies(flag: str) -> None:
    # The counterpart of the rejection above: a limit repo mode can act on is
    # not refused. Resolution stops at the missing token, which is enough to
    # show the flag cleared validation rather than being rejected as org-only.
    result = cli.invoke(
        app,
        ["report", "--repo", "o/r", "--scope", "repo", "--no-color", flag, "3"],
    )
    assert "organisation mode only" not in result.stdout


def test_releases_exclude_refused_across_many_orgs(tmp_path: Path) -> None:
    # One flag would replace the curated list of every configured org, so a
    # three-org config would lose all three lists. Refuse rather than flatten.
    config = tmp_path / "c.json"
    config.write_text(
        json.dumps(
            {
                "organizations": [
                    {"name": "one", "releases_exclude": ["a"]},
                    {"name": "two", "releases_exclude": ["b"]},
                ]
            }
        ),
        encoding="utf-8",
    )
    result = cli.invoke(
        app,
        [
            "report",
            "--config",
            str(config),
            "--scope",
            "org",
            "--releases-exclude",
            "c",
            "--no-color",
        ],
    )
    assert result.exit_code == 2, result.stdout
    assert "--releases-exclude" in result.stdout
    assert "one, two" in result.stdout


def test_releases_exclude_allowed_for_a_single_org(tmp_path: Path) -> None:
    # With one organisation there is no ambiguity about which list it replaces,
    # so the flag stays usable for the case it was written for. Resolution
    # stops at the missing token, past the validation under test.
    config = tmp_path / "c.json"
    config.write_text(
        json.dumps({"organizations": [{"name": "one", "releases_exclude": ["a"]}]}),
        encoding="utf-8",
    )
    result = cli.invoke(
        app,
        [
            "report",
            "--config",
            str(config),
            "--scope",
            "org",
            "--releases-exclude",
            "c",
            "--no-color",
        ],
    )
    assert "--releases-exclude replaces" not in result.stdout


class TestTokenEnvOverride:
    """``--token-env`` is an override, not an eager default.

    It used to default to the string ``"GITHUB_TOKEN"``, so nothing could tell
    "the user asked for this" from "unset" and the flag was consulted only on
    the ``--org`` shorthand path. Alongside ``--config`` the per-org
    ``token_env`` always won and the flag did nothing.
    """

    def _config(self, tmp_path: Path) -> str:
        path = tmp_path / "c.json"
        path.write_text(
            json.dumps(
                {"organizations": [{"name": "o", "token_env": "CONFIGURED_PAT"}]}
            ),
            encoding="utf-8",
        )
        return str(path)

    def test_unset_leaves_the_configured_value(self, tmp_path: Path) -> None:
        cfg, _ = _load_config(self._config(tmp_path), None, None)
        assert cfg is not None
        assert cfg.organizations[0].token_env == "CONFIGURED_PAT"

    def test_explicit_value_overrides_the_configured_one(self, tmp_path: Path) -> None:
        cfg, _ = _load_config(self._config(tmp_path), None, None, "FLAG_PAT")
        assert cfg is not None
        assert cfg.organizations[0].token_env == "FLAG_PAT"

    def test_override_reaches_every_organisation(self) -> None:
        data = json.dumps(
            {
                "organizations": [
                    {"name": "one", "token_env": "A"},
                    {"name": "two", "token_env": "B"},
                ]
            }
        )
        cfg, _ = _load_config(None, data, None, "FLAG_PAT")
        assert cfg is not None
        assert [o.token_env for o in cfg.organizations] == ["FLAG_PAT", "FLAG_PAT"]

    def test_org_shorthand_still_honours_the_flag(self) -> None:
        cfg, _ = _load_config(None, None, "o", "FLAG_PAT")
        assert cfg is not None
        assert cfg.organizations[0].token_env == "FLAG_PAT"

    def test_org_shorthand_defaults_to_github_token(self) -> None:
        cfg, _ = _load_config(None, None, "o")
        assert cfg is not None
        assert cfg.organizations[0].token_env == "GITHUB_TOKEN"


class TestReportOverrides:
    """The run-scoped booleans reach every organisation's report config.

    Each was reachable only by writing a JSON config file to set a single
    boolean, which is a debugging switch wearing a config file's clothes.
    ``docs/BRIEF.md`` already documented two of them as flags that had never
    been implemented.
    """

    def _org(self) -> OrgConfig:
        return OrgConfig(name="o")

    def test_unset_leaves_the_configured_values(self) -> None:
        _, report_cfg = ReportOverrides().apply(self._org())
        assert report_cfg.gating is True
        assert report_cfg.include_archived is False
        assert report_cfg.include_test is False

    def test_each_override_is_applied(self) -> None:
        overrides = ReportOverrides(
            gating=False, include_archived=True, include_test=True
        )
        _, report_cfg = overrides.apply(self._org())
        assert report_cfg.gating is False
        assert report_cfg.include_archived is True
        assert report_cfg.include_test is True

    def test_overrides_beat_a_configured_value(self) -> None:
        org = OrgConfig(name="o", report=ReportConfig(gating=True))
        _, report_cfg = ReportOverrides(gating=False).apply(org)
        assert report_cfg.gating is False

    def test_release_levers_still_apply(self) -> None:
        overrides = ReportOverrides(
            repo_min_age_days=1,
            release_max_age_days=2,
            releases_exclude=("skip-me",),
        )
        org_cfg, report_cfg = overrides.apply(self._org())
        assert report_cfg.repo_min_age_days == 1
        assert report_cfg.release_max_age_days == 2
        assert org_cfg.releases_exclude == ("skip-me",)

    def test_graph_batch_moves_in_either_direction(self) -> None:
        # An operational lever rather than report policy, so unlike the
        # one-way booleans it may both raise and lower the configured value.
        org = OrgConfig(name="o", report=ReportConfig(graph_batch=10))
        _, lowered = ReportOverrides(graph_batch=4).apply(org)
        _, raised = ReportOverrides(graph_batch=20).apply(org)
        _, untouched = ReportOverrides().apply(org)
        assert lowered.graph_batch == 4
        assert raised.graph_batch == 20
        assert untouched.graph_batch == 10


@pytest.mark.parametrize(
    "flag", ["--no-gating", "--include-archived", "--include-test", "--graph-batch=5"]
)
def test_new_flags_are_accepted_in_org_mode(flag: str) -> None:
    # Resolution stops at the missing token, which is past option parsing:
    # enough to show the flag exists and was not rejected as unknown.
    result = cli.invoke(app, ["report", "--org", "o", flag, "--no-color"])
    assert "No such option" not in result.stdout
    assert result.exit_code != 2 or "No token" in result.stdout


def test_org_to_dict_includes_partial_flag() -> None:
    # The JSON artifact must expose whether the org report is partial so
    # downstream consumers can distinguish complete from incomplete results.
    from github_security_report.cli import _org_to_dict
    from github_security_report.report import build_org_report

    complete = _org_to_dict(build_org_report("o", [], repo_count=1))
    partial = _org_to_dict(build_org_report("o", [], repo_count=1, partial=True))
    assert complete["partial"] is False
    assert partial["partial"] is True


def test_org_shorthand_honours_token_env() -> None:
    # --org with a custom --token-env must build an OrgConfig that reads the
    # token from that env var, not the default GITHUB_TOKEN.
    from github_security_report.cli import _load_config

    cfg, _ = _load_config(None, None, "myorg", "SECURITY_REPORT_PAT")
    assert cfg is not None
    assert cfg.organizations[0].token_env == "SECURITY_REPORT_PAT"


@respx.mock
def test_org_mode_top_n_from_config(tmp_path: Path) -> None:
    # Two repos are CodeQL offenders; report.top_n=1 from config must limit the
    # Slack code fence to a single offender (no --top-n override on the CLI).
    respx.get(url__startswith=f"{API}/orgs/o/repos").mock(
        return_value=httpx.Response(
            200,
            json=[
                {
                    "name": n,
                    "full_name": f"o/{n}",
                    "html_url": f"https://github.com/o/{n}",
                    "size": 10,
                }
                for n in ("r1", "r2")
            ],
        )
    )
    respx.get(url__startswith=f"{API}/orgs/o/code-scanning/alerts").mock(
        return_value=httpx.Response(
            200,
            json=[
                {
                    "repository": {"name": n},
                    "tool": {"name": "CodeQL"},
                    "rule": {"security_severity_level": "critical"},
                }
                for n in ("r1", "r2")
            ],
        )
    )
    for kind in ("dependabot", "secret-scanning"):
        respx.get(url__startswith=f"{API}/orgs/o/{kind}/alerts").mock(
            return_value=httpx.Response(200, json=[])
        )
    _mock_pattern_inventory()
    respx.get(url__startswith=f"{API}/orgs/o/rulesets").mock(
        return_value=httpx.Response(200, json=[])
    )
    respx.get(url__regex=rf"{re.escape(API)}/repos/o/r\d/code-scanning/analyses").mock(
        return_value=httpx.Response(200, json=[{"tool": {"name": "CodeQL"}}])
    )
    respx.get(url__regex=rf"{re.escape(API)}/repos/o/r\d/secret-scanning/alerts").mock(
        return_value=httpx.Response(200, json=[])
    )
    respx.post(f"{API}/graphql").mock(side_effect=_org_graphql_side)
    respx.get(url__regex=rf"{re.escape(SCORECARD)}/projects/github.com/o/r\d").mock(
        return_value=httpx.Response(404)
    )

    # Dependabot posture: only the security-updates flag remains a REST call.
    respx.get(
        url__regex=rf"{re.escape(API)}/repos/o/r\d/automated-security-fixes"
    ).mock(return_value=httpx.Response(404))
    respx.get(
        url__regex=rf"{re.escape(API)}/repos/o/r\d/private-vulnerability-reporting"
    ).mock(return_value=httpx.Response(200, json={"enabled": True}))
    respx.get(
        url__regex=rf"{re.escape(API)}/repos/o/r\d/code-scanning/default-setup"
    ).mock(return_value=httpx.Response(200, json={"state": "not-configured"}))

    cfg = (
        '{"report": {"top_n": 1}, '
        '"slack": {"channel": "CHAN", "report_day": "always"}, '
        '"organizations": [{"name": "o"}]}'
    )
    out = tmp_path / "site"
    result = cli.invoke(
        app,
        ["report", "--config-data", cfg, "--output-dir", str(out), "--no-color"],
    )
    assert result.exit_code == 0, result.stdout

    payload = json.loads((out / "slack-payload-CHAN.json").read_text())
    codeql = next(
        b for b in payload["blocks"] if "CodeQL" in b.get("text", {}).get("text", "")
    )
    text = codeql["text"]["text"]
    # r1 sorts ahead of r2 on the tie, so top_n=1 keeps only r1 in the fence.
    assert "r1" in text
    assert "r2" not in text


def _mock_offender_org() -> None:
    """Register org ``o`` / repo ``r`` with every remediable feature OFF.

    The single repo is an offender in all five remediable categories: CodeQL
    (no analyses), secret scanning (404), Dependabot alerts (GraphQL reports
    disabled), Dependabot security updates (automated-security-fixes off) and
    private vulnerability reporting (off). Read routes only -- write routes are
    added per test so a dry run can assert none were called.
    """
    respx.get(url__startswith=f"{API}/orgs/o/repos").mock(
        return_value=httpx.Response(
            200,
            json=[
                {
                    "name": "r",
                    "full_name": "o/r",
                    "html_url": "https://github.com/o/r",
                    "size": 10,
                }
            ],
        )
    )
    for kind in ("code-scanning", "dependabot", "secret-scanning"):
        respx.get(url__startswith=f"{API}/orgs/o/{kind}/alerts").mock(
            return_value=httpx.Response(200, json=[])
        )
    _mock_pattern_inventory()
    respx.get(url__startswith=f"{API}/orgs/o/rulesets").mock(
        return_value=httpx.Response(200, json=[])
    )
    # No CodeQL analyses -> CodeQL NAG (confirmed off).
    respx.get(url__startswith=f"{API}/repos/o/r/code-scanning/analyses").mock(
        return_value=httpx.Response(200, json=[])
    )
    # 404 on secret scanning alerts -> secret scanning NAG (confirmed off).
    respx.get(url__startswith=f"{API}/repos/o/r/secret-scanning/alerts").mock(
        return_value=httpx.Response(404)
    )

    def _graphql_off(request: httpx.Request) -> httpx.Response:
        variables = json.loads(request.content).get("variables", {})
        data: dict[str, object] = {}
        for key in variables:
            if not key.startswith("n"):
                continue
            idx = key[1:]
            data[f"r{idx}"] = {
                "hasVulnerabilityAlertsEnabled": False,
                "dependabotConfig": None,
                "tags": {"nodes": []},
                "releases": {"nodes": []},
            }
        return httpx.Response(200, json={"data": data})

    respx.post(f"{API}/graphql").mock(side_effect=_graphql_off)
    respx.get(url__startswith=f"{SCORECARD}/projects/github.com/o/r").mock(
        return_value=httpx.Response(404)
    )
    respx.get(url__startswith=f"{API}/repos/o/r/automated-security-fixes").mock(
        return_value=httpx.Response(200, json={"enabled": False, "paused": False})
    )
    respx.get(url__startswith=f"{API}/repos/o/r/private-vulnerability-reporting").mock(
        return_value=httpx.Response(200, json={"enabled": False})
    )
    respx.get(f"{API}/repos/o/r/code-scanning/default-setup").mock(
        return_value=httpx.Response(200, json={"state": "not-configured"})
    )


@respx.mock
def test_remediate_dry_run_makes_no_writes() -> None:
    _mock_offender_org()
    # Register write routes so we can assert they are never called in a dry run.
    codeql = respx.patch(f"{API}/repos/o/r/code-scanning/default-setup").mock(
        return_value=httpx.Response(202, json={})
    )
    secret = respx.patch(f"{API}/repos/o/r").mock(
        return_value=httpx.Response(200, json={})
    )
    alerts = respx.put(url__startswith=f"{API}/repos/o/r/vulnerability-alerts").mock(
        return_value=httpx.Response(204)
    )
    fixes = respx.put(url__startswith=f"{API}/repos/o/r/automated-security-fixes").mock(
        return_value=httpx.Response(204)
    )
    pvr = respx.put(
        url__startswith=f"{API}/repos/o/r/private-vulnerability-reporting"
    ).mock(return_value=httpx.Response(204))

    result = cli.invoke(app, ["remediate", "--org", "o", "--no-color"])
    assert result.exit_code == 0, result.stdout
    assert "DRY RUN" in result.stdout
    assert "would enable" in result.stdout
    for route in (codeql, secret, alerts, fixes, pvr):
        assert route.call_count == 0, result.stdout
    # The destructive cleanup is never part of the default run.
    assert "CodeQL: Stale Configurations" not in result.stdout


@respx.mock
def test_remediate_names_the_default_config_under_its_divider(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_default_config(tmp_path, monkeypatch)
    _mock_offender_org()
    result = cli.invoke(app, ["remediate", "--no-color"])
    assert result.exit_code == 0, result.stdout
    assert result.stdout.count("Using config") == 1
    assert _line_after(result.stdout, "Remediation: o").startswith("Using config:")


@respx.mock
def test_remediate_never_reads_membership_or_the_viewer() -> None:
    _mock_offender_org()
    result = cli.invoke(app, ["remediate", "--org", "o", "--no-color"])
    assert result.exit_code == 0, result.stdout
    queries = [
        json.loads(call.request.content)["query"]
        for call in respx.calls
        if str(call.request.url) == f"{API}/graphql"
    ]
    assert queries, "the posture prefetch should still run"
    assert not [q for q in queries if "membersWithRole" in q or "viewer {" in q]
    assert "results incomplete" not in result.stdout


@respx.mock
def test_remediate_runs_the_codeql_cleanup_only_when_named() -> None:
    # Named explicitly, the cleanup category is accepted and reported. This
    # org has no CodeQL at all, so there is nothing to clean up -- and any
    # delete it attempted would hit an unmocked route and fail the run.
    _mock_offender_org()
    result = cli.invoke(
        app,
        [
            "remediate",
            "--org",
            "o",
            "--category",
            "codeql_stale_configurations",
            "--apply",
            "--no-color",
        ],
    )
    assert result.exit_code == 0, result.stdout
    assert "CodeQL: Stale Configurations" in result.stdout
    assert "Nothing to remediate" in result.stdout


@respx.mock
def test_remediate_apply_enables_every_category() -> None:
    _mock_offender_org()
    codeql = respx.patch(f"{API}/repos/o/r/code-scanning/default-setup").mock(
        return_value=httpx.Response(202, json={})
    )
    secret = respx.patch(f"{API}/repos/o/r").mock(
        return_value=httpx.Response(200, json={})
    )
    alerts = respx.put(url__startswith=f"{API}/repos/o/r/vulnerability-alerts").mock(
        return_value=httpx.Response(204)
    )
    fixes = respx.put(url__startswith=f"{API}/repos/o/r/automated-security-fixes").mock(
        return_value=httpx.Response(204)
    )
    pvr = respx.put(
        url__startswith=f"{API}/repos/o/r/private-vulnerability-reporting"
    ).mock(return_value=httpx.Response(204))

    result = cli.invoke(app, ["remediate", "--org", "o", "--apply", "--no-color"])
    assert result.exit_code == 0, result.stdout
    assert "DRY RUN" not in result.stdout
    assert "enabled: r" in result.stdout
    for route in (codeql, secret, alerts, fixes, pvr):
        assert route.called, result.stdout


@respx.mock
@pytest.mark.parametrize("repos", ["r", "o/R", "elsewhere/x,r"])
def test_remediate_limited_to_named_repositories(repos: str) -> None:
    # --repos narrows every category, not just one: a bare name, an owner-
    # qualified one (matched case-insensitively), or a list mixing a name
    # for another org. The narrowed run says so above its results.
    _mock_offender_org()
    pvr = respx.put(
        url__startswith=f"{API}/repos/o/r/private-vulnerability-reporting"
    ).mock(return_value=httpx.Response(204))
    result = cli.invoke(
        app,
        [
            "remediate",
            "--org",
            "o",
            "--repos",
            repos,
            "--category",
            "private_vulnerability_reporting",
            "--apply",
            "--no-color",
        ],
    )
    if "elsewhere" in repos:
        # elsewhere/x names a repository in no configured org: refused.
        assert result.exit_code == 2, result.stdout
        assert "no repository named elsewhere/x in o" in result.stdout
        assert not pvr.called
        return
    assert result.exit_code == 0, result.stdout
    assert "Limited to:" in result.stdout
    assert "enabled: r" in result.stdout
    assert pvr.called


@respx.mock
@pytest.mark.parametrize(
    ("repos", "message"),
    [
        ("nope", "--repos: no repository named nope in o"),
        ("a/b/c", "--repos: not a repository name or owner/name: 'a/b/c'"),
    ],
)
def test_remediate_rejects_a_bad_selection_before_any_work(
    repos: str, message: str
) -> None:
    # A typo must not quietly do nothing, and no write may happen: every write
    # route is left unmocked, so any attempt would fail the run differently.
    _mock_offender_org()
    result = cli.invoke(
        app, ["remediate", "--org", "o", "--repos", repos, "--apply", "--no-color"]
    )
    assert result.exit_code == 2, result.stdout
    assert message in result.stdout


@respx.mock
def test_remediate_refuses_to_act_on_an_excluded_repository() -> None:
    # Naming a repository must not bypass the config's exclude list.
    _mock_offender_org()
    data = json.dumps(
        {
            "organizations": [
                {"name": "o", "token_env": "GITHUB_TOKEN", "exclude": ["r"]}
            ]
        }
    )
    result = cli.invoke(
        app,
        ["remediate", "--config-data", data, "--repos", "r", "--apply", "--no-color"],
    )
    assert result.exit_code == 2, result.stdout
    assert "--repos: o/r is excluded (explicitly excluded)" in result.stdout


class TestTopNLimits:
    """Per-output offender-limit resolution, extracted from ``_run_org``."""

    def _org(
        self,
        *,
        top_n_report: int | None = None,
        top_n_cli: int | None = None,
        top_n_slack: int | None = None,
    ) -> ReportConfig:
        return ReportConfig(
            top_n_report=top_n_report,
            top_n_cli=top_n_cli,
            top_n_slack=top_n_slack,
        )

    def test_config_value_used_when_no_override(self) -> None:
        org = self._org(top_n_slack=3)
        assert TopNLimits().resolve(org, "slack") == 3

    def test_shared_override_beats_config(self) -> None:
        org = self._org(top_n_slack=3)
        assert TopNLimits(shared=7).resolve(org, "slack") == 7

    def test_category_override_beats_shared(self) -> None:
        org = self._org(top_n_slack=3)
        assert TopNLimits(shared=7, slack=1).resolve(org, "slack") == 1

    def test_zero_override_is_honoured_as_no_limit(self) -> None:
        # 0 disables the limit, so it must not be mistaken for "unset".
        org = self._org(top_n_slack=3)
        assert TopNLimits(shared=0).resolve(org, "slack") == 0

    def test_each_output_reads_its_own_config_attribute(self) -> None:
        org = self._org(top_n_report=1, top_n_cli=2, top_n_slack=3)
        limits = TopNLimits()
        assert [limits.resolve(org, out) for out in ("report", "cli", "slack")] == [
            1,
            2,
            3,
        ]


class TestMostGenerous:
    """Channel-sharing limit reconciliation, extracted from ``_run_org``."""

    def test_largest_cap_wins(self) -> None:
        assert most_generous([5, 10, 2]) == 10

    def test_no_limit_beats_any_cap(self) -> None:
        # 0 means "show everything", so a capped org sharing the channel must
        # not silently re-impose its cap on the org that asked for everything.
        assert most_generous([5, 0, 20]) == 0


def test_module_form_entry_point_still_runs() -> None:
    # `python -m github_security_report.cli` worked while the CLI was a single
    # module. A package cannot be executed through the __init__ guard, so it
    # needs a __main__.py; this pins that the invocation keeps working.
    result = subprocess.run(
        [sys.executable, "-m", "github_security_report.cli", "--version"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "github-security-report version" in result.stdout


class TestPerCategoryLimits:
    """CLI/config precedence for a category's own row limit."""

    def _org(self, categories: dict, *, top_n_cli: int) -> ReportConfig:
        toggles = {
            key: CategoryToggle(top_n=value) for key, value in categories.items()
        }
        return ReportConfig(categories=toggles, top_n_cli=top_n_cli)

    def test_category_config_beats_output_config(self) -> None:
        org = self._org({"releases": 0}, top_n_cli=10)
        limits = TopNLimits()
        assert limits.resolve(org, "cli", CategoryKey.RELEASES) == 0
        assert limits.resolve(org, "cli", CategoryKey.CODEQL) == 10

    def test_shared_cli_flag_beats_category_config(self) -> None:
        # A flag is a decision about this run, so it caps even an uncapped
        # category configured with top_n 0.
        org = self._org({"releases": 0}, top_n_cli=10)
        assert TopNLimits(shared=5).resolve(org, "cli", CategoryKey.RELEASES) == 5

    def test_output_flag_beats_category_config(self) -> None:
        org = self._org({"releases": 0}, top_n_cli=10)
        assert TopNLimits(cli=2).resolve(org, "cli", CategoryKey.RELEASES) == 2

    def test_resolve_without_category_keeps_output_behaviour(self) -> None:
        org = self._org({"releases": 0}, top_n_cli=10)
        assert TopNLimits().resolve(org, "cli") == 10

    def test_resolver_returns_per_category_lookup(self) -> None:
        org = self._org({"releases": 0}, top_n_cli=7)
        resolver = TopNLimits().resolver(org, "cli")
        assert resolver(CategoryKey.RELEASES) == 0
        assert resolver(CategoryKey.CODEQL) == 7


class TestSlackLimit:
    """Channel-sharing reconciliation happens per category."""

    def _pair(self, top_n: int) -> tuple[OrgConfig, OrgReport]:
        org = OrgConfig(
            name="o",
            report=ReportConfig(
                top_n_slack=5, categories={"releases": CategoryToggle(top_n=top_n)}
            ),
        )
        return (org, build_org_report("o", [], repo_count=0))

    def test_most_generous_category_limit_wins_for_channel(self) -> None:
        items = [self._pair(3), self._pair(0)]
        limit = slack_limit(items, TopNLimits())
        # 0 (no limit) is the most generous, so the shared channel is uncapped.
        assert limit(CategoryKey.RELEASES) == 0
        # A category neither org overrode still uses the per-output value.
        assert limit(CategoryKey.CODEQL) == 5


class TestSlackShow:
    """Channel visibility stays attached to the report that produced it."""

    def _pair(self, *, shows: bool) -> tuple[OrgConfig, OrgReport]:
        org = OrgConfig(
            name="o",
            report=ReportConfig(
                categories={
                    "pull_requests_assigned": CategoryToggle(
                        outputs=OutputToggles(slack=shows)
                    )
                }
            ),
        )
        return (org, build_org_report("o", [], repo_count=0))

    def test_duplicate_org_names_keep_their_own_toggles(self) -> None:
        # Nothing in the schema makes organisation names unique, so a run can
        # carry two entries called "o". A name-keyed lookup would collapse them
        # onto the last configuration and publish the opted-out report's
        # reader-specific queue under its namesake's opt-in.
        opted_out = self._pair(shows=False)
        opted_in = self._pair(shows=True)
        visible = slack_show([opted_out, opted_in])
        key = CategoryKey.PULL_REQUESTS_ASSIGNED
        assert visible(opted_in[1], key) is True
        assert visible(opted_out[1], key) is False

    def test_hidden_categories_are_suppressed_for_every_report(self) -> None:
        opted_in = self._pair(shows=True)
        visible = slack_show([opted_in], [CategoryKey.PULL_REQUESTS_ASSIGNED])
        assert visible(opted_in[1], CategoryKey.PULL_REQUESTS_ASSIGNED) is False

    def test_unconfigured_report_falls_back_to_visible(self) -> None:
        stranger = build_org_report("other", [], repo_count=0)
        visible = slack_show([self._pair(shows=False)])
        assert visible(stranger, CategoryKey.CODEQL) is True


class TestSlackFooter:
    """Channel footers follow the configuration of the report they belong to."""

    def _pair(self, repo_list: RepoList) -> tuple[OrgConfig, OrgReport]:
        org = OrgConfig(name="o", report=ReportConfig(repo_list=repo_list))
        return (org, build_org_report("o", [], repo_count=0))

    def test_duplicate_org_names_keep_their_own_setting(self) -> None:
        enabled = self._pair(RepoList.ENABLED)
        disabled = self._pair(RepoList.DISABLED)
        resolve = slack_footer([enabled, disabled])
        key = CategoryKey.AUTO_MERGE
        assert resolve(enabled[1]).repo_list(key) is RepoList.ENABLED
        assert resolve(disabled[1]).repo_list(key) is RepoList.DISABLED

    def test_unconfigured_report_gets_the_defaults(self) -> None:
        stranger = build_org_report("other", [], repo_count=0)
        resolve = slack_footer([self._pair(RepoList.DISABLED)])
        assert resolve(stranger).repo_list(CategoryKey.AUTO_MERGE) is RepoList.AUTO


def test_remediate_repos_naming_nothing_does_not_widen_to_everything() -> None:
    # "--repos ," is an explicit narrowing that parses to nothing; running
    # it as "no selection" would act on every repository.
    result = cli.invoke(
        app, ["remediate", "--org", "o", "--repos", " , ", "--apply", "--no-color"]
    )
    assert result.exit_code == 2, result.stdout
    assert "--repos: names no repository" in result.stdout


class _TwoOrgClient:
    """Org "a" has "shared" in scope; org "b" has an archived "shared"."""

    async def list_org_repos(self, org: str) -> tuple[int, list[Repo]]:
        archived = org == "b"
        return 200, [Repo("shared", f"{org}/shared", "u", archived=archived)]


async def test_a_name_usable_in_one_org_is_not_refused_for_another() -> None:
    # A bare name excluded in org b is fine while org a has it in scope: the
    # run acts on a's repository only, so nothing excluded is touched.
    cfg = Config(organizations=(OrgConfig(name="a"), OrgConfig(name="b")))
    console = Console(record=True, no_color=True)
    touched = await _check_selection(
        _TwoOrgClient(),  # type: ignore[arg-type]
        cfg,
        scope.parse_repo_selection(["shared"]),
        console=console,
    )
    # Keyed by configuration entry: entry 0 is org "a".
    assert {
        index: [r.full_name for r in repos] for index, repos in (touched or {}).items()
    } == {0: ["a/shared"]}
    assert console.export_text() == ""


async def test_a_name_excluded_everywhere_is_refused() -> None:
    cfg = Config(organizations=(OrgConfig(name="b"),))
    console = Console(record=True, no_color=True, width=200)
    touched = await _check_selection(
        _TwoOrgClient(),  # type: ignore[arg-type]
        cfg,
        scope.parse_repo_selection(["shared"]),
        console=console,
    )
    assert touched is None
    assert "--repos: b/shared is excluded (archived)" in console.export_text()


async def test_duplicate_org_entries_keep_their_own_exclusions() -> None:
    # One org listed twice: the first entry excludes "shared", the second
    # does not. Each entry must act only on what its own configuration
    # allows, so the selection is kept per entry, not per organisation name.
    cfg = Config(
        organizations=(
            OrgConfig(name="a", exclude=("shared",)),
            OrgConfig(name="a"),
        )
    )
    console = Console(record=True, no_color=True)
    touched = await _check_selection(
        _TwoOrgClient(),  # type: ignore[arg-type]
        cfg,
        scope.parse_repo_selection(["shared"]),
        console=console,
    )
    assert touched is not None
    assert sorted(touched) == [1]


async def test_an_exclusion_holds_whatever_its_capitalisation() -> None:
    # GitHub names match case-insensitively, and so does --repos, so an
    # exclude entry must too, or "--repos shared" could reach "Shared".
    cfg = Config(organizations=(OrgConfig(name="a", exclude=("SHARED",)),))
    console = Console(record=True, no_color=True, width=200)
    touched = await _check_selection(
        _TwoOrgClient(),  # type: ignore[arg-type]
        cfg,
        scope.parse_repo_selection(["shared"]),
        console=console,
    )
    assert touched is None
    assert "a/shared is excluded (explicitly excluded)" in console.export_text()


@respx.mock
def test_remediate_limited_to_names_only_the_orgs_own_repositories() -> None:
    # A selector for another org must not appear under this one: the line is
    # an audit of what this org's run actually covered.
    _mock_offender_org()
    respx.put(url__startswith=f"{API}/repos/o/r/private-vulnerability-reporting").mock(
        return_value=httpx.Response(204)
    )
    data = json.dumps(
        {
            "organizations": [
                {"name": "o", "token_env": "GITHUB_TOKEN"},
            ]
        }
    )
    result = cli.invoke(
        app,
        [
            "remediate",
            "--config-data",
            data,
            "--repos",
            "O/R",
            "--category",
            "private_vulnerability_reporting",
            "--no-color",
        ],
    )
    assert result.exit_code == 0, result.stdout
    # The repository's own name as GitHub lists it, not the typed selector.
    assert "Limited to: r\n" in result.stdout


class _PartialListingClient(_TwoOrgClient):
    """Org "a" lists "shared" completely; org "b"'s listing is incomplete."""

    async def list_org_repos(self, org: str) -> tuple[int, list[Repo]]:
        if org == "b":
            return 502, []  # pagination failed before "b/shared"
        return await super().list_org_repos(org)


async def test_an_incomplete_listing_stops_a_narrowed_run() -> None:
    # "shared" matches in org a, but org b's listing failed and may hold its
    # own "shared": proceeding would silently skip it, so the run stops.
    cfg = Config(organizations=(OrgConfig(name="a"), OrgConfig(name="b")))
    console = Console(record=True, no_color=True, width=200)
    touched = await _check_selection(
        _PartialListingClient(),  # type: ignore[arg-type]
        cfg,
        scope.parse_repo_selection(["shared"]),
        console=console,
    )
    assert touched is None
    assert "the repository listing for b was incomplete" in console.export_text()


# --------------------------------------------------------------------------- #
# Request accounting
# --------------------------------------------------------------------------- #
class _RecordingClient:
    """Stand-in for ``GitHubClient`` that records how it was constructed."""

    built: ClassVar[list[dict[str, object]]] = []

    def __init__(self, token: str, **kwargs: object) -> None:
        type(self).built.append(kwargs)

    async def __aenter__(self) -> _RecordingClient:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        return None

    @property
    def stats(self) -> RequestStats:
        return RequestStats(requests=3, by_status={200: 3}, elapsed=1.5)


@pytest.fixture
def recording_client(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, object]]:
    """Run org mode against :class:`_RecordingClient` and an empty collection."""
    from github_security_report import collect
    from github_security_report.cli import modes

    async def fake_collect(
        _client: object, org_cfg: OrgConfig, *_args: object, **_kwargs: object
    ) -> OrgReport:
        return build_org_report(org_cfg.name, [], repo_count=0)

    built: list[dict[str, object]] = []
    monkeypatch.setattr(_RecordingClient, "built", built)
    monkeypatch.setattr(modes, "GitHubClient", _RecordingClient)
    monkeypatch.setattr(collect, "collect_org", fake_collect)
    return built


def test_verbose_org_run_logs_the_request_accounting_once_per_org(
    recording_client: list[dict[str, object]], caplog: pytest.LogCaptureFixture
) -> None:
    config_data = json.dumps({"organizations": [{"name": "o"}, {"name": "p"}]})
    with caplog.at_level(logging.INFO, logger="github_security_report.cli.modes"):
        result = cli.invoke(
            app, ["--verbose", "report", "--config-data", config_data, "--no-color"]
        )
    assert result.exit_code == 0, result.stdout
    lines = [r.getMessage() for r in caplog.records if "GitHub API for" in r.message]
    assert lines == [
        f"GitHub API for {org}: 3 requests (0 retries), 0.0 MiB received, 1.5 s"
        for org in ("o", "p")
    ]


def test_verbose_org_run_logs_the_request_accounting_when_collection_aborts(
    recording_client: list[dict[str, object]],
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    # A run that aborts -- here on a rejected token, exit code 4 -- is exactly
    # the run whose request, retry and timing figures are wanted, so the line
    # is logged on the way out, once, before the abort is reported.
    from github_security_report import collect
    from github_security_report.client import AuthError

    async def failing_collect(*_args: object, **_kwargs: object) -> OrgReport:
        raise AuthError("GitHub rejected the credentials (HTTP 401)")

    monkeypatch.setattr(collect, "collect_org", failing_collect)
    config_data = json.dumps({"organizations": [{"name": "o"}, {"name": "p"}]})
    with caplog.at_level(logging.INFO, logger="github_security_report.cli.modes"):
        result = cli.invoke(
            app, ["--verbose", "report", "--config-data", config_data, "--no-color"]
        )
    assert result.exit_code == 4, result.stdout
    lines = [r.getMessage() for r in caplog.records if "GitHub API for" in r.message]
    # Only the first organisation was reached before the abort.
    assert lines == [
        "GitHub API for o: 3 requests (0 retries), 0.0 MiB received, 1.5 s"
    ]


# --------------------------------------------------------------------------- #
# Client concurrency
# --------------------------------------------------------------------------- #
_CONCURRENCY_CONFIG = json.dumps(
    {
        "report": {"concurrency": 5},
        "organizations": [{"name": "o"}, {"name": "p", "report": {"concurrency": 7}}],
    }
)


def _concurrency(built: list[dict[str, object]]) -> list[object]:
    return [kwargs.get("concurrency") for kwargs in built]


def test_concurrency_reaches_each_org_client_from_config(
    recording_client: list[dict[str, object]],
) -> None:
    result = cli.invoke(
        app, ["report", "--config-data", _CONCURRENCY_CONFIG, "--no-color"]
    )
    assert result.exit_code == 0, result.stdout
    assert _concurrency(recording_client) == [5, 7]


def test_concurrency_flag_wins_over_config(
    recording_client: list[dict[str, object]],
) -> None:
    result = cli.invoke(
        app,
        ["report", "--config-data", _CONCURRENCY_CONFIG, "--no-color"]
        + ["--concurrency", "12"],
    )
    assert result.exit_code == 0, result.stdout
    assert _concurrency(recording_client) == [12, 12]


def test_concurrency_defaults_to_nine(
    recording_client: list[dict[str, object]],
) -> None:
    result = cli.invoke(app, ["report", "--org", "o", "--no-color"])
    assert result.exit_code == 0, result.stdout
    assert _concurrency(recording_client) == [9]


@pytest.mark.parametrize(
    ("value", "message"),
    [
        ("0", "--concurrency must be 1 or greater"),
        ("-1", "--concurrency must be 1 or greater"),
        ("33", "--concurrency must be 32 or less"),
    ],
)
def test_concurrency_out_of_range_rejected(value: str, message: str) -> None:
    # The same bounds as the config schema, so a flag cannot ask GitHub for
    # more parallelism than a configuration file could.
    result = cli.invoke(
        app, ["report", "--org", "o", f"--concurrency={value}", "--no-color"]
    )
    assert result.exit_code == 2
    assert message in result.stdout


def test_concurrency_flag_is_org_mode_only() -> None:
    result = cli.invoke(
        app,
        ["report", "--repo", "o/r", "--scope", "repo", "--no-color"]
        + ["--concurrency", "4"],
    )
    assert result.exit_code == 2, result.stdout
    assert "--concurrency" in result.stdout
    assert "organisation mode only" in result.stdout


def test_concurrency_moves_in_either_direction() -> None:
    # An operational lever, like the batch size: it may raise or lower the
    # configured value.
    org = OrgConfig(name="o", report=ReportConfig(concurrency=9))
    _, lowered = ReportOverrides(concurrency=4).apply(org)
    _, raised = ReportOverrides(concurrency=16).apply(org)
    _, untouched = ReportOverrides().apply(org)
    assert lowered.concurrency == 4
    assert raised.concurrency == 16
    assert untouched.concurrency == 9


def test_action_passes_the_concurrency_input_to_the_flag() -> None:
    # Empty by default, so a pinned release predating the flag is not handed
    # one; passed through only when set. The bundled workflow feeds it from a
    # repository variable, beside GSR_GRAPH_BATCH.
    root = Path(__file__).resolve().parents[1]
    action = yaml.safe_load((root / "action.yaml").read_text())
    assert action["inputs"]["concurrency"]["default"] == ""
    step = next(
        s for s in action["runs"]["steps"] if "INPUT_GRAPH_BATCH" in s.get("env", {})
    )
    assert step["env"]["INPUT_CONCURRENCY"] == "${{ inputs.concurrency }}"
    assert (
        '[ -n "$INPUT_CONCURRENCY" ] && args+=(--concurrency "$INPUT_CONCURRENCY")'
        in step["run"]
    )
    workflow = (root / ".github" / "workflows" / "reporting.yaml").read_text()
    assert 'concurrency: "${{ vars.GSR_CONCURRENCY }}"' in workflow
