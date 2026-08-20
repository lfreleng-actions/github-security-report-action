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
from github_security_report.categories import CategoryKey
from github_security_report.config import ConfigError
from github_security_report.severity import Severity

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
        assert config.build_config(MINIMAL).report.release_max_age_days == 60
        data = {
            "report": {"release_max_age_days": 60},
            "organizations": [
                {"name": "o", "report": {"release_max_age_days": 90}},
            ],
        }
        org = config.build_config(data).organizations[0]
        assert org.report.release_max_age_days == 90

    def test_dependabot_thresholds_default_and_override(self) -> None:
        report = config.build_config(MINIMAL).report
        assert report.dependabot_warn_threshold == 12
        # 15 is GitHub's default per-repository open-PR cap for Dependabot.
        assert report.dependabot_error_threshold == 15
        data = {
            "report": {
                "dependabot_warn_threshold": 8,
                "dependabot_error_threshold": 10,
            },
            "organizations": [
                {"name": "o", "report": {"dependabot_warn_threshold": 5}},
            ],
        }
        org = config.build_config(data).organizations[0]
        assert org.report.dependabot_warn_threshold == 5
        assert org.report.dependabot_error_threshold == 10

    def test_error_threshold_below_warn_is_rejected(self) -> None:
        # Unsatisfiable as written: every value that would warn has already
        # errored, so the warning colour could never appear. Rejecting beats
        # silently ignoring one of the two knobs the operator set.
        data = {
            "report": {
                "dependabot_warn_threshold": 20,
                "dependabot_error_threshold": 10,
            },
            "organizations": [{"name": "o"}],
        }
        with pytest.raises(ConfigError, match="dependabot_error_threshold"):
            config.build_config(data)

    def test_org_override_cannot_invert_the_thresholds(self) -> None:
        # The check runs on the merged result, so an org block that raises warn
        # above an inherited error is caught rather than silently disabling the
        # warning level for that one organisation.
        data = {
            "report": {
                "dependabot_warn_threshold": 12,
                "dependabot_error_threshold": 15,
            },
            "organizations": [
                {"name": "o", "report": {"dependabot_warn_threshold": 30}},
            ],
        }
        with pytest.raises(ConfigError, match="dependabot_error_threshold"):
            config.build_config(data)

    def test_releases_exclude_parsed(self) -> None:
        data = {
            "organizations": [
                {"name": "o", "releases_exclude": ["internal-a", "internal-b"]},
            ],
        }
        org = config.build_config(data).organizations[0]
        assert org.releases_exclude == ("internal-a", "internal-b")

    def test_gating_default_and_override(self) -> None:
        # Organisation feature gating defaults on; a per-org report block can
        # switch it off (always probing every workflow-driven signal).
        assert config.build_config(MINIMAL).report.gating is True
        data = {
            "organizations": [
                {"name": "o", "report": {"gating": False}},
            ],
        }
        org = config.build_config(data).organizations[0]
        assert org.report.gating is False

    def test_default_ruleset_workflows_include_aislop(self) -> None:
        # The built-in ruleset keyword map covers both workflow-gated scanners.
        workflows = config.build_config(MINIMAL).report.ruleset_workflows
        assert workflows["zizmor"] == "zizmor"
        assert workflows["aislop"] == "aislop"

    def test_issue_labels_replace_rather_than_merge(self) -> None:
        # The mapping defines the Issues table's column set, so a configured one
        # must not leave behind default columns the operator dropped.
        columns = config.build_config(
            {
                "report": {"issue_labels": {"Regression": ["regression"]}},
                "organizations": [{"name": "o"}],
            }
        ).report.issue_labels
        assert dict(columns) == {"Regression": ("regression",)}

    @pytest.mark.parametrize(
        "column",
        ["Other", "Untriaged", "other", "UNTRIAGED", "Repository", "Total", "Oldest"],
    )
    def test_rejects_issue_label_columns_reserved_by_the_table(
        self, column: str
    ) -> None:
        # The Issues table supplies these headers itself. Reusing one either
        # shares a counter with the implicit column (so the class columns stop
        # summing to Total) or duplicates a header, which would also make
        # `sort: ["repository"]` resolve to a count column.
        with pytest.raises(ConfigError, match="collides"):
            config.build_config(
                {
                    "report": {"issue_labels": {column: ["bug"]}},
                    "organizations": [{"name": "o"}],
                }
            )

    def test_rejects_issue_label_columns_differing_only_in_case(self) -> None:
        # Two columns but one sort target: `ordering.resolve_terms` matches
        # column names case-insensitively.
        with pytest.raises(ConfigError, match="differing only in case"):
            config.build_config(
                {
                    "report": {"issue_labels": {"Bug": ["bug"], "bug": ["defect"]}},
                    "organizations": [{"name": "o"}],
                }
            )

    def test_rejects_blank_issue_label_column(self) -> None:
        with pytest.raises(ConfigError, match="blank"):
            config.build_config(
                {
                    "report": {"issue_labels": {"  ": ["bug"]}},
                    "organizations": [{"name": "o"}],
                }
            )

    def test_rejects_padded_issue_label_column(self) -> None:
        # `sort` terms are stripped before matching, so a padded column name
        # could never be selected for sorting.
        with pytest.raises(ConfigError, match="whitespace"):
            config.build_config(
                {
                    "report": {"issue_labels": {" Bug ": ["bug"]}},
                    "organizations": [{"name": "o"}],
                }
            )

    @pytest.mark.parametrize("column", ["Bug|Feature", "Bug`s", "Bug\nFeature"])
    def test_rejects_structurally_unsafe_issue_label_column(self, column: str) -> None:
        # Headers reach Markdown tables and Slack code fences verbatim.
        with pytest.raises(ConfigError, match="corrupt"):
            config.build_config(
                {
                    "report": {"issue_labels": {column: ["bug"]}},
                    "organizations": [{"name": "o"}],
                }
            )

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


class TestCategoryToggles:
    def test_default_shows_every_category_on_every_output(self) -> None:
        rc = config.build_config(MINIMAL).report
        for output in config.REPORT_OUTPUTS:
            assert rc.shows_category(CategoryKey.CODEQL, output)
            assert rc.shows_category(CategoryKey.MUTABLE_RELEASES, output)

    def test_global_enabled_false_hides_on_all_outputs(self) -> None:
        data = {
            "report": {"categories": {"zizmor": {"enabled": False}}},
            "organizations": [{"name": "o"}],
        }
        rc = config.build_config(data).organizations[0].report
        for output in config.REPORT_OUTPUTS:
            assert not rc.shows_category(CategoryKey.ZIZMOR, output)
        # Other categories are untouched.
        assert rc.shows_category(CategoryKey.CODEQL, "cli")

    def test_per_output_toggle_is_lower_precedence(self) -> None:
        data = {
            "report": {
                "categories": {"releases": {"outputs": {"cli": False, "slack": False}}}
            },
            "organizations": [{"name": "o"}],
        }
        rc = config.build_config(data).organizations[0].report
        assert not rc.shows_category(CategoryKey.RELEASES, "cli")
        assert not rc.shows_category(CategoryKey.RELEASES, "slack")
        # Outputs left unset stay enabled.
        assert rc.shows_category(CategoryKey.RELEASES, "markdown")
        assert rc.shows_category(CategoryKey.RELEASES, "html")

    def test_global_enabled_overrides_per_output(self) -> None:
        # enabled=false wins even when an output is explicitly true.
        data = {
            "report": {
                "categories": {"codeql": {"enabled": False, "outputs": {"html": True}}}
            },
            "organizations": [{"name": "o"}],
        }
        rc = config.build_config(data).organizations[0].report
        assert not rc.shows_category(CategoryKey.CODEQL, "html")

    def test_org_override_merges_per_output(self) -> None:
        # An org override that flips one output leaves the inherited enabled
        # switch and the other outputs intact.
        data = {
            "report": {"categories": {"secret_scanning": {"outputs": {"cli": False}}}},
            "organizations": [
                {
                    "name": "o",
                    "report": {
                        "categories": {"secret_scanning": {"outputs": {"slack": False}}}
                    },
                }
            ],
        }
        rc = config.build_config(data).organizations[0].report
        assert not rc.shows_category(CategoryKey.SECRET_SCANNING, "cli")
        assert not rc.shows_category(CategoryKey.SECRET_SCANNING, "slack")
        assert rc.shows_category(CategoryKey.SECRET_SCANNING, "markdown")

    def test_rejects_unknown_category_key(self) -> None:
        with pytest.raises(ConfigError):
            config.build_config(
                {
                    "report": {"categories": {"bogus": {"enabled": False}}},
                    "organizations": [{"name": "o"}],
                }
            )

    def test_rejects_unknown_output_key(self) -> None:
        with pytest.raises(ConfigError):
            config.build_config(
                {
                    "report": {"categories": {"codeql": {"outputs": {"email": False}}}},
                    "organizations": [{"name": "o"}],
                }
            )

    def test_fail_severity_default_is_none_override(self) -> None:
        # With no override the resolver returns None (classifier uses the
        # category default).
        rc = config.build_config(MINIMAL).report
        assert rc.fail_severity_for(CategoryKey.CODEQL) is None

    def test_fail_severity_override_parsed(self) -> None:
        data = {
            "report": {
                "categories": {
                    "codeql": {"fail_severity": "low"},
                    "zizmor": {"fail_severity": "informational"},
                }
            },
            "organizations": [{"name": "o"}],
        }
        rc = config.build_config(data).organizations[0].report
        assert rc.fail_severity_for(CategoryKey.CODEQL) is Severity.LOW
        assert rc.fail_severity_for(CategoryKey.ZIZMOR) is Severity.INFORMATIONAL

    def test_fail_severity_merges_with_other_category_keys(self) -> None:
        # Setting fail_severity does not disturb a separately-set toggle.
        data = {
            "report": {
                "categories": {"zizmor": {"enabled": False, "fail_severity": "medium"}}
            },
            "organizations": [{"name": "o"}],
        }
        rc = config.build_config(data).organizations[0].report
        assert rc.fail_severity_for(CategoryKey.ZIZMOR) is Severity.MEDIUM
        assert not rc.shows_category(CategoryKey.ZIZMOR, "cli")

    def test_rejects_unknown_fail_severity(self) -> None:
        with pytest.raises(ConfigError):
            config.build_config(
                {
                    "report": {"categories": {"codeql": {"fail_severity": "bogus"}}},
                    "organizations": [{"name": "o"}],
                }
            )

    def test_fail_severity_on_non_signal_category_warns(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        # `fail_severity` only governs the severity-ranked signals; on a binary
        # category (here releases) it is silently ignored, so the build warns
        # rather than letting the dead override pass unnoticed.
        data = {
            "report": {"categories": {"releases": {"fail_severity": "low"}}},
            "organizations": [{"name": "o"}],
        }
        with caplog.at_level("WARNING"):
            config.build_config(data)
        assert any(
            "fail_severity" in r.message and "releases" in r.message
            for r in caplog.records
        )

    def test_fail_severity_on_signal_category_does_not_warn(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        data = {
            "report": {"categories": {"codeql": {"fail_severity": "low"}}},
            "organizations": [{"name": "o"}],
        }
        with caplog.at_level("WARNING"):
            config.build_config(data)
        assert not any("fail_severity" in r.message for r in caplog.records)


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
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
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
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
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


class TestPerCategoryTopN:
    """A category may cap its own table independently of the output limit."""

    def _report(self, categories: dict) -> config.ReportConfig:
        return (
            config.build_config(
                {
                    "report": {"top_n": 10, "categories": categories},
                    "organizations": [{"name": "o"}],
                }
            )
            .organizations[0]
            .report
        )

    def test_unset_category_falls_back_to_output_limit(self) -> None:
        rc = self._report({})
        assert rc.category_top_n(CategoryKey.RELEASES, "cli") == 10

    def test_category_top_n_overrides_output_limit(self) -> None:
        rc = self._report({"releases": {"top_n": 3}})
        assert rc.category_top_n(CategoryKey.RELEASES, "cli") == 3
        # Other categories are untouched by one category's override.
        assert rc.category_top_n(CategoryKey.CODEQL, "cli") == 10

    def test_zero_means_no_limit_for_that_category_only(self) -> None:
        rc = self._report({"releases": {"top_n": 0}})
        assert rc.category_top_n(CategoryKey.RELEASES, "cli") == 0
        assert rc.category_top_n(CategoryKey.CODEQL, "cli") == 10

    def test_applies_across_every_output(self) -> None:
        rc = self._report({"releases": {"top_n": 0}})
        assert [
            rc.category_top_n(CategoryKey.RELEASES, out)
            for out in ("report", "cli", "slack")
        ] == [0, 0, 0]

    def test_org_override_inherits_other_category_keys(self) -> None:
        # An org that overrides only top_n must keep the inherited enabled flag.
        cfg = config.build_config(
            {
                "report": {"categories": {"releases": {"enabled": False}}},
                "organizations": [
                    {"name": "o", "report": {"categories": {"releases": {"top_n": 0}}}}
                ],
            }
        )
        toggle = cfg.organizations[0].report.categories["releases"]
        assert toggle.top_n == 0
        assert toggle.enabled is False

    def test_negative_top_n_rejected(self) -> None:
        with pytest.raises(ConfigError):
            config.build_config(
                {
                    "report": {"categories": {"releases": {"top_n": -1}}},
                    "organizations": [{"name": "o"}],
                }
            )
