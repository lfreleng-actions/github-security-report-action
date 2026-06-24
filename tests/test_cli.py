# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""End-to-end CLI tests (respx-mocked GitHub, no live network)."""

from __future__ import annotations

import json
import re
from pathlib import Path

import httpx
import pytest
import respx
from typer.testing import CliRunner

from github_security_report.cli import _safe_component, app

API = "https://api.github.com"
SCORECARD = "https://api.securityscorecards.dev"
cli = CliRunner()


def _org_graphql_side(request: httpx.Request) -> httpx.Response:
    """Answer the batched org-mode prefetch query for each ``n{idx}`` variable.

    Returns a minimal repository node per alias (alerts enabled, no config, no
    tags, no releases), mirroring the shape :func:`client.repo_graph_batch`
    expects so org-mode tests need no per-repo dependabot.yml/releases mocks.
    """
    variables = json.loads(request.content).get("variables", {})
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
def test_org_mode_writes_pages(tmp_path: object) -> None:
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


@respx.mock
def test_org_mode_uses_default_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # With no --config/--config-data/--org, a per-user config file under
    # $XDG_CONFIG_HOME is discovered and used (org mode), rather than erroring.
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    cfg_dir = tmp_path / "github-security-report"
    cfg_dir.mkdir()
    (cfg_dir / "config.json").write_text(
        json.dumps({"organizations": [{"name": "o", "token_env": "GITHUB_TOKEN"}]}),
        encoding="utf-8",
    )
    _mock_org_o_r()

    result = cli.invoke(app, ["report", "--scope", "org", "--no-color"])
    assert result.exit_code == 0, result.stdout
    assert "Using config" in result.stdout


@respx.mock
def test_repo_mode_fail_threshold(tmp_path: object) -> None:
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


@pytest.mark.parametrize("bad", ["justaname", "o/r/extra", "/r", "o/"])
def test_malformed_repo_rejected(bad: str) -> None:
    # An explicit --repo that is not exactly 'owner/name' must error, not
    # silently fall back to git detection or target an unintended repository.
    result = cli.invoke(app, ["report", "--repo", bad, "--scope", "repo", "--no-color"])
    assert result.exit_code == 2
    assert "owner/name" in result.stdout


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

    cfg = _load_config(None, None, "myorg", "SECURITY_REPORT_PAT")
    assert cfg is not None
    assert cfg.organizations[0].token_env == "SECURITY_REPORT_PAT"


@respx.mock
def test_org_mode_top_n_from_config(tmp_path: object) -> None:
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
