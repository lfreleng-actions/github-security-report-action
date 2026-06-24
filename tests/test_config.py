# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Tests for configuration loading, validation, and Slack-day gating."""

from __future__ import annotations

import base64
import datetime as dt
import json
from pathlib import Path

import pytest

from github_security_report import config
from github_security_report.config import ConfigError

TUESDAY = dt.date(2026, 6, 16)
WEDNESDAY = dt.date(2026, 6, 17)

MINIMAL = {"organizations": [{"name": "lfreleng-actions"}]}


class TestReportDay:
    def test_default_is_tuesday(self) -> None:
        rd = config.parse_report_day(None)
        assert rd.should_notify(now=TUESDAY)
        assert not rd.should_notify(now=WEDNESDAY)

    def test_single_day(self) -> None:
        rd = config.parse_report_day("Wednesday")
        assert rd.should_notify(now=WEDNESDAY)
        assert not rd.should_notify(now=TUESDAY)

    def test_list_of_days(self) -> None:
        rd = config.parse_report_day(["monday", "tuesday"])
        assert rd.should_notify(now=TUESDAY)
        assert not rd.should_notify(now=WEDNESDAY)

    def test_always_and_never(self) -> None:
        assert config.parse_report_day("always").should_notify(now=WEDNESDAY)
        assert not config.parse_report_day("never").should_notify(now=TUESDAY)

    def test_force_overrides_never(self) -> None:
        assert config.parse_report_day("never").should_notify(now=TUESDAY, force=True)

    def test_invalid_day(self) -> None:
        with pytest.raises(ConfigError):
            config.parse_report_day("funday")

    def test_special_cannot_combine_with_weekday(self) -> None:
        with pytest.raises(ConfigError):
            config.parse_report_day(["always", "monday"])


class TestBuildConfig:
    def test_defaults(self) -> None:
        cfg = config.build_config(MINIMAL)
        assert len(cfg.organizations) == 1
        org = cfg.organizations[0]
        assert org.name == "lfreleng-actions"
        assert org.token_env == "GITHUB_TOKEN"
        assert cfg.report.top_n == 10
        assert org.slack.report_day.should_notify(now=TUESDAY)

    def test_global_defaults_inherited_by_org(self) -> None:
        data = {
            "slack": {"channel": "releng-scm", "report_day": "monday"},
            "report": {"top_n": 5},
            "organizations": [{"name": "org-a"}],
        }
        org = config.build_config(data).organizations[0]
        assert org.slack.channel == "releng-scm"
        assert org.report.top_n == 5
        assert org.slack.report_day.should_notify(now=dt.date(2026, 6, 15))  # Monday

    def test_per_org_override_wins(self) -> None:
        data = {
            "report": {"top_n": 5},
            "organizations": [
                {"name": "org-a", "report": {"top_n": 20}, "exclude": ["x"]},
            ],
        }
        org = config.build_config(data).organizations[0]
        assert org.report.top_n == 20
        assert org.exclude == ("x",)

    def test_repo_min_age_days_default_and_override(self) -> None:
        assert config.build_config(MINIMAL).report.repo_min_age_days == 28
        data = {
            "report": {"repo_min_age_days": 0},
            "organizations": [
                {"name": "o", "report": {"repo_min_age_days": 14}},
            ],
        }
        org = config.build_config(data).organizations[0]
        assert org.report.repo_min_age_days == 14

    def test_release_min_age_days_is_deprecated_alias(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        # The old key still maps to repo_min_age_days, emitting a warning.
        data = {
            "report": {"release_min_age_days": 14},
            "organizations": [{"name": "o"}],
        }
        org = config.build_config(data).organizations[0]
        assert org.report.repo_min_age_days == 14
        assert any("deprecated" in r.message for r in caplog.records)

    def test_release_min_age_days_warns_only_once(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        # The legacy key in both the global block and an org override must warn
        # exactly once, not once per block, so users are not alarmed.
        data = {
            "report": {"release_min_age_days": 30},
            "organizations": [
                {"name": "a", "report": {"release_min_age_days": 14}},
                {"name": "b", "report": {"release_min_age_days": 7}},
            ],
        }
        config.build_config(data)
        warnings = [r for r in caplog.records if "deprecated" in r.message]
        assert len(warnings) == 1

    def test_repo_min_age_days_wins_over_legacy_alias(self) -> None:
        # An explicit new key takes precedence over the deprecated alias.
        data = {
            "report": {"repo_min_age_days": 14, "release_min_age_days": 99},
            "organizations": [{"name": "o"}],
        }
        org = config.build_config(data).organizations[0]
        assert org.report.repo_min_age_days == 14

    def test_release_max_age_days_default_and_override(self) -> None:
        assert config.build_config(MINIMAL).report.release_max_age_days == 0
        data = {
            "report": {"release_max_age_days": 60},
            "organizations": [
                {"name": "o", "report": {"release_max_age_days": 90}},
            ],
        }
        org = config.build_config(data).organizations[0]
        assert org.report.release_max_age_days == 90

    def test_releases_exclude_parsed(self) -> None:
        data = {
            "organizations": [
                {"name": "o", "releases_exclude": ["internal-a", "internal-b"]},
            ],
        }
        org = config.build_config(data).organizations[0]
        assert org.releases_exclude == ("internal-a", "internal-b")

    def test_rejects_negative_repo_min_age_days(self) -> None:
        with pytest.raises(ConfigError):
            config.build_config(
                {
                    "report": {"repo_min_age_days": -1},
                    "organizations": [{"name": "o"}],
                }
            )

    def test_rejects_negative_release_max_age_days(self) -> None:
        with pytest.raises(ConfigError):
            config.build_config(
                {
                    "report": {"release_max_age_days": -1},
                    "organizations": [{"name": "o"}],
                }
            )

    def test_literal_token_warns(self, caplog: pytest.LogCaptureFixture) -> None:
        data = {"organizations": [{"name": "o", "token_env": "ghp_secretvalue"}]}
        config.build_config(data)
        assert any("literal token" in r.message for r in caplog.records)

    def test_rejects_unknown_keys(self) -> None:
        with pytest.raises(ConfigError):
            config.build_config({"organizations": [{"name": "o"}], "bogus": 1})

    def test_top_n_shared_default_applies_to_all_outputs(self) -> None:
        data = {
            "report": {"top_n": 7},
            "organizations": [{"name": "o"}],
        }
        rc = config.build_config(data).organizations[0].report
        assert (rc.report_top_n, rc.cli_top_n, rc.slack_top_n) == (7, 7, 7)

    def test_top_n_per_category_overrides(self) -> None:
        data = {
            "report": {
                "top_n": 10,
                "top_n_report": 25,
                "top_n_cli": 5,
                "top_n_slack": 3,
            },
            "organizations": [{"name": "o"}],
        }
        rc = config.build_config(data).organizations[0].report
        assert rc.report_top_n == 25
        assert rc.cli_top_n == 5
        assert rc.slack_top_n == 3

    def test_top_n_partial_override_falls_back_to_shared(self) -> None:
        data = {
            "report": {"top_n": 10, "top_n_slack": 3},
            "organizations": [{"name": "o"}],
        }
        rc = config.build_config(data).organizations[0].report
        assert rc.report_top_n == 10  # falls back to shared
        assert rc.cli_top_n == 10
        assert rc.slack_top_n == 3

    def test_zero_top_n_category_disables_limit(self) -> None:
        rc = (
            config.build_config(
                {
                    "report": {"top_n_cli": 0},
                    "organizations": [{"name": "o"}],
                }
            )
            .organizations[0]
            .report
        )
        assert rc.cli_top_n == 0  # 0 = no limit (show every offender)

    def test_requires_organizations(self) -> None:
        with pytest.raises(ConfigError):
            config.build_config({"slack": {}})

    def test_zero_top_n_disables_limit(self) -> None:
        rc = config.build_config(
            {"organizations": [{"name": "o"}], "report": {"top_n": 0}}
        ).report
        assert rc.top_n == 0  # 0 = no limit (show every offender)

    def test_rejects_negative_top_n(self) -> None:
        with pytest.raises(ConfigError):
            config.build_config(
                {"organizations": [{"name": "o"}], "report": {"top_n": -1}}
            )


class TestLoads:
    def test_raw_json(self) -> None:
        cfg = config.loads(json.dumps(MINIMAL))
        assert cfg.organizations[0].name == "lfreleng-actions"

    def test_base64_json(self) -> None:
        encoded = base64.b64encode(json.dumps(MINIMAL).encode()).decode()
        cfg = config.loads(encoded)
        assert cfg.organizations[0].name == "lfreleng-actions"

    def test_garbage(self) -> None:
        with pytest.raises(ConfigError):
            config.loads("not json or base64 @@@")

    def test_non_object_json(self) -> None:
        with pytest.raises(ConfigError):
            config.loads("[1, 2, 3]")


class TestResolveToken:
    def test_resolves_by_env_name(self) -> None:
        org = config.OrgConfig(name="o", token_env="MY_PAT")
        assert config.resolve_token(org, {"MY_PAT": "ghp_abc"}) == "ghp_abc"

    def test_missing_returns_none(self) -> None:
        org = config.OrgConfig(name="o", token_env="MY_PAT")
        assert config.resolve_token(org, {}) is None


class TestDefaultConfig:
    def test_default_path_honours_xdg(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: object
    ) -> None:
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        path = config.default_config_path()
        assert path.parent.name == "github-security-report"
        assert path.name == "config.json"
        assert str(path).startswith(str(tmp_path))

    def test_default_path_falls_back_to_home_config(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
        path = config.default_config_path()
        assert path.parts[-3:] == (
            ".config",
            "github-security-report",
            "config.json",
        )

    def test_find_default_config_missing(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: object
    ) -> None:
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        assert config.find_default_config() is None

    def test_find_default_config_present(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        cfg_dir = tmp_path / "github-security-report"
        cfg_dir.mkdir()
        (cfg_dir / "config.json").write_text(json.dumps(MINIMAL), encoding="utf-8")
        found = config.find_default_config()
        assert found == cfg_dir / "config.json"
        # And it loads as a valid config.
        assert config.load_file(str(found)).organizations[0].name == (
            "lfreleng-actions"
        )
