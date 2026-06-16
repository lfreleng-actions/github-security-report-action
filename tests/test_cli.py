# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""End-to-end CLI tests (respx-mocked GitHub, no live network)."""

from __future__ import annotations

import httpx
import pytest
import respx
from typer.testing import CliRunner

from github_security_report.cli import app

API = "https://api.github.com"
SCORECARD = "https://api.securityscorecards.dev"
cli = CliRunner()


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    monkeypatch.delenv("GITHUB_OUTPUT", raising=False)
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)


def test_version() -> None:
    result = cli.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "github-security-report" in result.stdout


@respx.mock
def test_org_mode_writes_pages(tmp_path: object) -> None:
    respx.get(url__startswith=f"{API}/orgs/o/repos").mock(
        return_value=httpx.Response(200, json=[{"name": "r", "full_name": "o/r", "html_url": "https://github.com/o/r", "size": 10}])
    )
    for kind in ("code-scanning", "dependabot", "secret-scanning"):
        respx.get(url__startswith=f"{API}/orgs/o/{kind}/alerts").mock(return_value=httpx.Response(200, json=[]))
    respx.get(url__startswith=f"{API}/repos/o/r/code-scanning/analyses").mock(
        return_value=httpx.Response(200, json=[{"tool": {"name": "CodeQL"}}])
    )
    respx.get(url__startswith=f"{API}/repos/o/r/secret-scanning/alerts").mock(return_value=httpx.Response(200, json=[]))
    respx.post(f"{API}/graphql").mock(
        return_value=httpx.Response(200, json={"data": {"repository": {"hasVulnerabilityAlertsEnabled": True}}})
    )
    respx.get(url__startswith=f"{SCORECARD}/projects/github.com/o/r").mock(return_value=httpx.Response(404))

    out = tmp_path / "site"
    result = cli.invoke(app, ["report", "--org", "o", "--output-dir", str(out), "--no-color"])
    assert result.exit_code == 0, result.stdout
    assert (out / "index.html").exists()
    assert (out / "o" / "report.html").exists()
    assert (out / "o" / "report.md").exists()
    assert (out / "o" / "report.json").exists()


@respx.mock
def test_repo_mode_fail_threshold(tmp_path: object) -> None:
    respx.get(f"{API}/repos/o/r").mock(
        return_value=httpx.Response(200, json={"name": "r", "full_name": "o/r", "html_url": "https://github.com/o/r"})
    )
    respx.get(url__startswith=f"{API}/repos/o/r/code-scanning/analyses").mock(
        return_value=httpx.Response(200, json=[{"tool": {"name": "CodeQL"}}])
    )
    respx.get(url__startswith=f"{API}/repos/o/r/code-scanning/alerts").mock(
        return_value=httpx.Response(200, json=[{"tool": {"name": "CodeQL"}, "rule": {"security_severity_level": "critical"}}])
    )
    respx.get(url__startswith=f"{API}/repos/o/r/secret-scanning/alerts").mock(return_value=httpx.Response(404))
    respx.post(f"{API}/graphql").mock(
        return_value=httpx.Response(200, json={"data": {"repository": {"hasVulnerabilityAlertsEnabled": False}}})
    )
    respx.get(url__startswith=f"{API}/repos/o/r/dependabot/alerts").mock(return_value=httpx.Response(200, json=[]))
    respx.get(url__startswith=f"{SCORECARD}/projects/github.com/o/r").mock(return_value=httpx.Response(404))

    # A critical CodeQL alert with --fail-threshold high must fail the run.
    result = cli.invoke(app, ["report", "--repo", "o/r", "--scope", "repo", "--fail-threshold", "high", "--no-color"])
    assert result.exit_code == 1, result.stdout

    # The same findings with threshold none must pass.
    ok = cli.invoke(app, ["report", "--repo", "o/r", "--scope", "repo", "--fail-threshold", "none", "--no-color"])
    assert ok.exit_code == 0, ok.stdout


def test_unresolvable_scope_errors() -> None:
    # No config and an explicit org scope -> mode error, exit 2.
    result = cli.invoke(app, ["report", "--scope", "org", "--no-color"])
    assert result.exit_code == 2
