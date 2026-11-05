# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""CLI tests for configuration errors and the ``config`` command."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner, Result

from github_security_report.cli import app
from github_security_report.config import default_config_path
from github_security_report.config.dictionary import config_keys

cli = CliRunner()

_UNKNOWN = {
    "organizations": [{"name": "o"}],
    "report": {"categories": {"code_quality": {"exclude_forks": True}}},
}


def _write(path: Path, data: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _default_config(data: object) -> Path:
    return _write(default_config_path(), data)


def _deny_default_config(monkeypatch: pytest.MonkeyPatch) -> Path:
    """Make checking the per-user file fail as an unsearchable parent does.

    Before Python 3.14 ``Path.is_file`` raises ``PermissionError`` when a
    parent directory denies search permission; patching it keeps the test
    meaningful on every version and for a user who can read any directory.
    """
    target = default_config_path()
    is_file = Path.is_file

    def deny(self: Path, *args: object, **kwargs: object) -> bool:
        if self == target:
            raise PermissionError(13, "Permission denied", str(self))
        return is_file(self, *args, **kwargs)

    monkeypatch.setattr(Path, "is_file", deny)
    return target


def _refused(result: Result) -> str:
    """Assert a clean exit 2 with no traceback, and return the output."""
    assert result.exit_code == 2, result.output
    assert isinstance(result.exception, SystemExit)
    assert "Traceback" not in result.output
    return result.output


class TestConfigErrorBoundary:
    def test_unknown_key_names_the_file_and_path(self, tmp_path: Path) -> None:
        path = _write(tmp_path / "config.json", _UNKNOWN)
        output = _refused(cli.invoke(app, ["report", "--config", str(path)]))
        assert f"Configuration {path} is invalid:" in output
        assert 'report.categories.code_quality: unknown key "exclude_forks"' in output
        assert "a key added in a later release needs an upgrade" in output

    def test_auto_discovered_file_is_named(self) -> None:
        path = _default_config(_UNKNOWN)
        output = _refused(cli.invoke(app, ["report", "--no-color"]))
        assert f"Configuration {path} is invalid:" in output

    def test_config_data_is_named_as_the_source(self) -> None:
        result = cli.invoke(app, ["report", "--config-data", "{oops"])
        output = _refused(result)
        assert "Configuration --config-data is invalid:" in output
        assert "neither valid JSON" in output

    def test_invalid_base64_is_reported(self) -> None:
        data = base64.b64encode(b"{not json").decode()
        output = _refused(cli.invoke(app, ["report", "--config-data", data]))
        assert "Configuration --config-data is invalid:" in output

    def test_missing_file_is_reported(self, tmp_path: Path) -> None:
        path = tmp_path / "absent.json"
        output = _refused(cli.invoke(app, ["report", "--config", str(path)]))
        assert f"Configuration {path} could not be read:" in output

    def test_unreadable_path_is_reported(self, tmp_path: Path) -> None:
        output = _refused(cli.invoke(app, ["report", "--config", str(tmp_path)]))
        assert f"Configuration {tmp_path} could not be read:" in output

    def test_non_utf8_file_is_reported(self, tmp_path: Path) -> None:
        path = tmp_path / "config.json"
        path.write_bytes(b"\xff\xfe{}")
        output = _refused(cli.invoke(app, ["report", "--config", str(path)]))
        assert f"Configuration {path} could not be read:" in output

    def test_malformed_non_ascii_json_is_reported(self) -> None:
        data = '{"organizations": [{"name": "café"}]'
        output = _refused(cli.invoke(app, ["report", "--config-data", data]))
        assert "Configuration --config-data is invalid:" in output
        assert "neither valid JSON" in output

    def test_oversized_integer_is_reported(self, tmp_path: Path) -> None:
        path = tmp_path / "config.json"
        path.write_text('{"report": {"top_n": ' + "1" * 4301 + "}}", encoding="utf-8")
        output = _refused(cli.invoke(app, ["report", "--config", str(path)]))
        assert f"Configuration {path} is invalid:" in output
        assert "could not be decoded" in output

    def test_non_object_root_is_reported(self, tmp_path: Path) -> None:
        path = _write(tmp_path / "config.json", [])
        output = _refused(cli.invoke(app, ["report", "--config", str(path)]))
        assert "must be a JSON object" in output

    def test_bad_pattern_names_its_path(self, tmp_path: Path) -> None:
        data = {
            "organizations": [{"name": "o"}],
            "report": {"categories": {"code_quality": {"exclude": ["["]}}},
        }
        path = _write(tmp_path / "config.json", data)
        output = _refused(cli.invoke(app, ["report", "--config", str(path)]))
        assert "report.categories.code_quality.exclude: pattern '['" in output

    def test_remediate_reports_the_same_way(self, tmp_path: Path) -> None:
        path = _write(tmp_path / "config.json", _UNKNOWN)
        output = _refused(cli.invoke(app, ["remediate", "--config", str(path)]))
        assert f"Configuration {path} is invalid:" in output

    @pytest.mark.parametrize("command", ["report", "remediate"])
    def test_undiscoverable_per_user_file_is_reported(
        self, command: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = _deny_default_config(monkeypatch)
        output = _refused(cli.invoke(app, [command]))
        assert f"Configuration {path} could not be read: Permission denied" in output


class TestConfigCommand:
    def test_check_accepts_a_valid_file(self, tmp_path: Path) -> None:
        path = _write(tmp_path / "config.json", {"organizations": [{"name": "o"}]})
        result = cli.invoke(app, ["config", "check", str(path)])
        assert result.exit_code == 0, result.output
        assert f"Configuration {path} is valid" in result.output

    def test_check_reports_every_finding(self, tmp_path: Path) -> None:
        data = {
            "organizations": [{"name": "o", "exclde": []}],
            "report": {"top_n": "ten", "excluded_display": "hide"},
        }
        path = _write(tmp_path / "config.json", data)
        output = _refused(cli.invoke(app, ["config", "check", str(path)]))
        assert 'organizations[0]: unknown key "exclde"' in output
        assert 'report.excluded_display: "hide" is not one of' in output
        assert 'report.top_n: expected an integer, got "ten"' in output

    def test_check_reads_config_data(self) -> None:
        data = json.dumps({"organizations": []})
        result = cli.invoke(app, ["config", "check", "--config-data", data])
        output = _refused(result)
        assert "Configuration --config-data is invalid:" in output
        assert "organizations: needs at least 1 entry" in output

    def test_check_rejects_empty_config_data(self) -> None:
        _default_config({"organizations": [{"name": "o"}]})
        result = cli.invoke(app, ["config", "check", "--config-data", ""])
        output = _refused(result)
        assert "Configuration --config-data is invalid:" in output

    def test_check_discovers_the_per_user_file(self) -> None:
        path = _default_config({"organizations": [{"name": "o"}]})
        result = cli.invoke(app, ["config", "check"])
        assert result.exit_code == 0, result.output
        assert f"Configuration {path} is valid" in result.output

    def test_check_without_a_configuration_says_so(self) -> None:
        output = _refused(cli.invoke(app, ["config", "check"]))
        assert "No configuration to check" in output

    def test_check_reports_an_undiscoverable_per_user_file(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = _deny_default_config(monkeypatch)
        output = _refused(cli.invoke(app, ["config", "check"]))
        assert f"Configuration {path} could not be read: Permission denied" in output

    def test_check_names_deprecated_keys_without_failing(self, tmp_path: Path) -> None:
        data = {"organizations": [{"name": "o", "report": {"release_min_age_days": 3}}]}
        path = _write(tmp_path / "config.json", data)
        result = cli.invoke(app, ["config", "check", str(path)])
        assert result.exit_code == 0, result.output
        assert "organizations[0].report.release_min_age_days" in result.output
        assert '"repo_min_age_days"' in result.output

    def test_keys_lists_every_key_exactly_once(self) -> None:
        result = cli.invoke(app, ["config", "keys"], env={"COLUMNS": "400"})
        assert result.exit_code == 0, result.output
        first = [line.split()[0] for line in result.output.splitlines() if line.strip()]
        for entry in config_keys():
            assert first.count(entry.path) == 1, entry.path

    def test_keys_filters_by_prefix(self) -> None:
        result = cli.invoke(
            app,
            ["config", "keys", "report.categories.code_quality"],
            env={"COLUMNS": "400"},
        )
        assert result.exit_code == 0, result.output
        assert "report.categories.code_quality.exclude" in result.output
        assert "report.top_n " not in result.output

    def test_keys_marks_a_deprecated_key(self) -> None:
        result = cli.invoke(
            app,
            ["config", "keys", "report.release_min_age_days"],
            env={"COLUMNS": "400"},
        )
        assert result.exit_code == 0, result.output
        assert "deprecated; use report.repo_min_age_days" in result.output

    def test_keys_rejects_an_unknown_prefix(self) -> None:
        output = _refused(cli.invoke(app, ["config", "keys", "report.nope"]))
        assert "No configuration key matches 'report.nope'" in output
