# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Tests for configuration loading, validation, and Slack-day gating."""

from __future__ import annotations

import base64
import datetime as dt
import json

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

    def test_literal_token_warns(self, caplog: pytest.LogCaptureFixture) -> None:
        data = {"organizations": [{"name": "o", "token_env": "ghp_secretvalue"}]}
        config.build_config(data)
        assert any("literal token" in r.message for r in caplog.records)

    def test_rejects_unknown_keys(self) -> None:
        with pytest.raises(ConfigError):
            config.build_config({"organizations": [{"name": "o"}], "bogus": 1})

    def test_requires_organizations(self) -> None:
        with pytest.raises(ConfigError):
            config.build_config({"slack": {}})

    def test_rejects_zero_top_n(self) -> None:
        with pytest.raises(ConfigError):
            config.build_config(
                {"organizations": [{"name": "o"}], "report": {"top_n": 0}}
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
