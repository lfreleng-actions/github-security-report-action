# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""An unexpected error exits 7 with a short message, never a bare traceback."""

from __future__ import annotations

import importlib
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest
import respx
import typer
from test_cli import API, _mock_org_o_r
from typer.testing import CliRunner

from github_security_report.cli import app, boundary, config_cmd
from github_security_report.client import AuthError

# The package re-exports the Typer object as ``app``, hiding the module.
app_mod = importlib.import_module("github_security_report.cli.app")
cli = CliRunner()

PENDING = pytest.mark.xfail(strict=True, reason="unexpected errors not yet handled")

# Built at run time so the source line a traceback quotes cannot carry it.
SENTINEL = "-".join(("token", "sentinel", "4f2a"))


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    monkeypatch.delenv("GITHUB_OUTPUT", raising=False)
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)


@pytest.fixture
def github() -> Iterator[None]:
    """The mocked organisation ``o`` with one clean repository ``r``."""
    with respx.mock:
        respx.get(f"{API}/rate_limit").mock(
            return_value=httpx.Response(
                200,
                json={
                    "resources": {
                        "core": {"limit": 5000, "used": 0, "remaining": 5000},
                        "graphql": {"limit": 5000, "used": 0, "remaining": 5000},
                    }
                },
            )
        )
        _mock_org_o_r()
        yield


def _scenario_args(tmp_path: Path, flag: str) -> list[str]:
    """A ``report`` run whose ``flag`` names a path beneath a regular file."""
    blocker = tmp_path / "file"
    blocker.write_text("", encoding="utf-8")
    return ["report", "--org", "o", "--scope", "org", "--no-color", flag]


def _raise_with_secret(exc: BaseException) -> None:
    secret = SENTINEL  # noqa: F841 -- a local a traceback must not show
    raise exc


SCENARIOS = [
    pytest.param("--output-dir", "site", id="output-dir"),
    pytest.param("--run-cache-dir", "cache", id="run-cache-dir"),
]


@PENDING
@pytest.mark.parametrize(("flag", "leaf"), SCENARIOS)
def test_uncreatable_path_exits_7_without_traceback(
    github: None, tmp_path: Path, flag: str, leaf: str
) -> None:
    args = [*_scenario_args(tmp_path, flag), str(tmp_path / "file" / leaf)]
    result = cli.invoke(app, args)
    assert result.exit_code == 7, result.output
    assert "Internal error: NotADirectoryError: " in result.output
    assert "not a finding" in result.output
    assert "--verbose" in result.output
    assert "Traceback" not in result.output


@PENDING
@pytest.mark.parametrize(("flag", "leaf"), SCENARIOS)
def test_uncreatable_path_with_verbose_prints_traceback(
    github: None, tmp_path: Path, flag: str, leaf: str
) -> None:
    args = [*_scenario_args(tmp_path, flag), str(tmp_path / "file" / leaf)]
    result = cli.invoke(app, ["--verbose", *args])
    assert result.exit_code == 7, result.output
    out = result.output
    assert "Traceback (most recent call last)" in out
    assert out.index("Traceback") < out.index("Internal error: NotADirectoryError")
    assert "Re-run with --verbose" not in out


@PENDING
def test_error_in_mode_coroutine_is_handled(monkeypatch: pytest.MonkeyPatch) -> None:
    async def run_org(*_args: object, **_kwargs: object) -> int:
        _raise_with_secret(RuntimeError("mode broke"))
        return 0

    monkeypatch.setattr(app_mod, "_run_org", run_org)
    result = cli.invoke(app, ["report", "--org", "o", "--no-color"])
    assert result.exit_code == 7, result.output
    assert "Internal error: RuntimeError: mode broke" in result.output
    assert "Traceback" not in result.output


@PENDING
def test_verbose_traceback_shows_no_locals(monkeypatch: pytest.MonkeyPatch) -> None:
    async def run_org(*_args: object, **_kwargs: object) -> int:
        _raise_with_secret(RuntimeError("mode broke"))
        return 0

    monkeypatch.setattr(app_mod, "_run_org", run_org)
    result = cli.invoke(app, ["--verbose", "report", "--org", "o", "--no-color"])
    assert result.exit_code == 7, result.output
    assert "_raise_with_secret" in result.output
    assert SENTINEL not in result.output


@PENDING
def test_error_in_command_body_is_handled(monkeypatch: pytest.MonkeyPatch) -> None:
    def detect_target(*_args: object) -> None:
        raise ValueError("body broke")

    monkeypatch.setattr(boundary, "detect_target", detect_target)
    result = cli.invoke(app, ["report", "--org", "o", "--no-color"])
    assert result.exit_code == 7, result.output
    assert "Internal error: ValueError: body broke" in result.output
    assert "Traceback" not in result.output


@PENDING
def test_remediate_error_says_earlier_changes_stand(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def run_remediate(*_args: object, **_kwargs: object) -> int:
        raise RuntimeError("write broke")

    monkeypatch.setattr(app_mod, "_run_remediate", run_remediate)
    result = cli.invoke(app, ["remediate", "--org", "o", "--no-color"])
    assert result.exit_code == 7, result.output
    assert "Internal error: RuntimeError: write broke" in result.output
    assert "made before the error stand" in result.output


@pytest.mark.parametrize(
    ("exc", "code"),
    [
        pytest.param(typer.Exit(2), 2, id="typer-exit"),
        pytest.param(AuthError("HTTP 401: Bad credentials"), 4, id="auth"),
    ],
)
def test_errors_with_a_meaning_keep_their_code(
    monkeypatch: pytest.MonkeyPatch, exc: BaseException, code: int
) -> None:
    async def run_org(*_args: object, **_kwargs: object) -> int:
        raise exc

    monkeypatch.setattr(app_mod, "_run_org", run_org)
    result = cli.invoke(app, ["report", "--org", "o", "--no-color"])
    assert result.exit_code == code, result.output
    assert "Internal error" not in result.output


@PENDING
def test_config_command_error_exits_7(monkeypatch: pytest.MonkeyPatch) -> None:
    def keys_under(_prefix: str) -> None:
        raise KeyError("dictionary broke")

    monkeypatch.setattr(config_cmd, "keys_under", keys_under)
    result = cli.invoke(app, ["config", "keys", "--no-color"])
    assert result.exit_code == 7, result.output
    assert "Internal error: KeyError: 'dictionary broke'" in result.output
    assert "Traceback" not in result.output
