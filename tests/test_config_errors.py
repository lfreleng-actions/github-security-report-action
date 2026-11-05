# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Tests for how configuration errors are found, located and worded."""

from __future__ import annotations

import base64
from types import MappingProxyType

import pytest

from github_security_report import config
from github_security_report.config import ConfigError
from github_security_report.config import errors as config_errors
from github_security_report.config.errors import (
    deprecation_findings,
    schema_findings,
    version_note,
)


def _findings(data: object) -> tuple[str, ...]:
    with pytest.raises(ConfigError) as caught:
        config.build_config(data)  # type: ignore[arg-type]
    findings: tuple[str, ...] = caught.value.findings
    return findings


class TestSchemaFindings:
    def test_unknown_key_lists_valid_keys_and_the_version(self) -> None:
        data = {
            "organizations": [{"name": "o"}],
            "report": {"categories": {"code_quality": {"exclude_forks": True}}},
        }
        found = _findings(data)
        assert found[0].startswith(
            'report.categories.code_quality: unknown key "exclude_forks"'
        )
        assert "valid keys: enabled, outputs, fail_severity, top_n, sort" in found[0]
        assert found[-1] == version_note()

    def test_a_close_match_is_suggested(self) -> None:
        found = _findings({"organizations": [{"name": "o", "exclde": []}]})
        assert found[0].startswith(
            'organizations[0]: unknown key "exclde" (did you mean "exclude"?)'
        )

    def test_a_key_valid_elsewhere_names_its_block(self) -> None:
        found = _findings({"top_n": 5, "organizations": [{"name": "o"}]})
        assert '"top_n" belongs under report' in found[0]
        assert found[0].startswith("(top level): ")

    def test_every_mistake_is_reported_in_path_order(self) -> None:
        data = {
            "report": {
                "top_n": "ten",
                "excluded_display": "hide",
                "categories": {"code_quality": {"exclude_forks": True}},
            },
            "organizations": [{"name": "o", "exclde": []}],
        }
        found = _findings(data)
        assert [line.split(":")[0] for line in found[:4]] == [
            "organizations[0]",
            "report.categories.code_quality",
            "report.excluded_display",
            "report.top_n",
        ]
        assert found[2] == (
            'report.excluded_display: "hide" is not one of '
            "always-show, always-hide, conditional-hide"
        )
        assert found[3] == 'report.top_n: expected an integer, got "ten"'
        assert found[4] == version_note()
        assert len(found) == 5

    def test_no_version_note_without_an_unknown_key(self) -> None:
        found = _findings({"organizations": [{"name": "o"}], "report": {"top_n": -1}})
        assert found == ("report.top_n: expected at least 0, got -1",)

    @pytest.mark.parametrize(
        ("data", "expected"),
        [
            ({"organizations": []}, "organizations: needs at least 1 entry"),
            (
                {"organizations": [{"token_env": "X"}]},
                "organizations[0].name: required key is missing",
            ),
            (
                {"organizations": [{"name": "o"}], "slack": {"report_day": 5}},
                "slack.report_day: expected string or list of string, got 5",
            ),
            (
                {"organizations": [{"name": ""}]},
                "organizations[0].name: cannot be empty",
            ),
            (
                {
                    "organizations": [{"name": "o"}],
                    "report": {"workflow_runs": {"windows": {"cli": [7, 7]}}},
                },
                "report.workflow_runs.windows.cli: lists a value more than once",
            ),
        ],
    )
    def test_each_rule_is_worded_with_its_path(
        self, data: dict[str, object], expected: str
    ) -> None:
        assert expected in _findings(data)

    def test_org_overrides_are_located_under_the_org(self) -> None:
        data = {"organizations": [{"name": "o", "report": {"top_n": "x"}}]}
        assert _findings(data) == (
            'organizations[0].report.top_n: expected an integer, got "x"',
        )

    def test_a_valid_configuration_has_no_findings(self) -> None:
        assert schema_findings({"organizations": [{"name": "o"}]}) == []

    def test_a_removed_key_says_what_replaced_it(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        removed = MappingProxyType({"report.old_knob": ("0.9.0", "new_knob")})
        monkeypatch.setattr(config_errors, "REMOVED", removed)
        found = _findings({"organizations": [{"name": "o"}], "report": {"old_knob": 1}})
        assert found == (
            'report: key "old_knob" was removed in 0.9.0; use "new_knob" instead',
        )


class TestSemanticFindings:
    def test_semantic_checks_lead_with_their_path(self) -> None:
        data = {
            "organizations": [{"name": "o"}],
            "report": {"categories": {"code_quality": {"exclude": ["["]}}},
        }
        (finding,) = _findings(data)
        assert finding.startswith("report.categories.code_quality.exclude: pattern")

    def test_every_failing_block_is_reported(self) -> None:
        data = {
            "slack": {"report_day": "funday"},
            "report": {"dependabot_warn_threshold": 9},
            "organizations": [
                {
                    "name": "o",
                    "report": {"issue_age_warn_days": 30, "issue_age_error_days": 10},
                }
            ],
        }
        found = _findings(data)
        assert [line.split(":")[0] for line in found] == [
            "organizations[0].report.issue_age_error_days",
            "report.dependabot_error_threshold",
            "slack.report_day",
        ]

    @pytest.mark.parametrize(
        ("parent", "override"),
        [
            (
                {"dependabot_error_threshold": 200},
                {"dependabot_warn_threshold": 100},
            ),
            (
                {"workflow_runs": {"windows": {"report": [7]}}},
                {"workflow_runs": {"retention_days": 30}},
            ),
            (
                {"order": {"style": "dual", "priority": ["codeql"]}},
                {"order": {"priority": ["secret_scanning"]}},
            ),
        ],
        ids=["threshold", "retention", "order-style"],
    )
    def test_a_failed_parent_raises_no_inherited_finding(
        self, parent: dict, override: dict
    ) -> None:
        bad_pattern = {"categories": {"code_quality": {"exclude": ["("]}}}
        data = {
            "report": {**parent, **bad_pattern},
            "organizations": [{"name": "o", "report": override}],
        }
        (finding,) = _findings(data)
        assert finding.startswith("report.categories.code_quality.exclude:")

    def test_a_failed_parent_still_checks_a_self_contained_override(self) -> None:
        data = {
            "report": {"categories": {"code_quality": {"exclude": ["("]}}},
            "organizations": [
                {
                    "name": "o",
                    "report": {"issue_age_warn_days": 30, "issue_age_error_days": 10},
                }
            ],
        }
        assert [line.split(":")[0] for line in _findings(data)] == [
            "organizations[0].report.issue_age_error_days",
            "report.categories.code_quality.exclude",
        ]

    @pytest.mark.parametrize(
        ("override", "expected"),
        [
            (
                {"workflow_runs": {"retention_days": 30, "windows": {"cli": [60]}}},
                "organizations[0].report.workflow_runs.retention_days: 30 is "
                "shorter than the longest configured window (60 days)",
            ),
            (
                {"order": {"priority": ["codeql", "codeql"]}},
                "organizations[0].report.order.priority: lists 'codeql' more than once",
            ),
            (
                {"order": {"priority": ["codeql"], "bau": ["codeql"]}},
                "organizations[0].report.order: lists 'codeql' in both "
                "'priority' and 'bau'",
            ),
        ],
        ids=["retention", "duplicate", "overlap"],
    )
    def test_a_failed_parent_still_checks_what_the_override_sets(
        self, override: dict, expected: str
    ) -> None:
        data = {
            "report": {"categories": {"code_quality": {"exclude": ["("]}}},
            "organizations": [{"name": "o", "report": override}],
        }
        found = _findings(data)
        assert len(found) == 2
        assert found[0].startswith(expected)
        assert found[1].startswith("report.categories.code_quality.exclude:")

    def test_every_failing_check_in_one_block_is_reported(self) -> None:
        data = {
            "organizations": [{"name": "o"}],
            "report": {
                "dependabot_warn_threshold": 5,
                "dependabot_error_threshold": 4,
                "issue_age_warn_days": 30,
                "issue_age_error_days": 10,
                "issue_labels": {"Other": ["x"]},
                "categories": {"code_quality": {"exclude": ["(", "["]}},
                "order": {
                    "style": "dual",
                    "priority": ["codeql", "codeql"],
                    "bau": ["scorecard", "scorecard"],
                },
                "workflow_runs": {"retention_days": 1},
            },
        }
        assert [line.split(":")[0] for line in _findings(data)] == [
            "report.categories.code_quality.exclude",
            "report.categories.code_quality.exclude",
            "report.dependabot_error_threshold",
            "report.issue_age_error_days",
            "report.issue_labels",
            "report.order.bau",
            "report.order.priority",
            "report.workflow_runs.retention_days",
        ]

    def test_every_invalid_issue_label_column_is_reported(self) -> None:
        data = {
            "organizations": [{"name": "o"}],
            "report": {"issue_labels": {"Other": ["x"], "Total": ["y"], " ": ["z"]}},
        }
        found = _findings(data)
        assert len(found) == 3
        assert all(line.startswith("report.issue_labels: column ") for line in found)
        assert any("'Other' collides" in line for line in found)
        assert any("'Total' collides" in line for line in found)
        assert any("names cannot be blank" in line for line in found)

    def test_org_slack_report_day_is_located(self) -> None:
        data = {
            "organizations": [
                {"name": "o", "slack": {"report_day": ["always", "monday"]}}
            ]
        }
        assert _findings(data) == (
            "organizations[0].slack.report_day: 'always' cannot be combined "
            "with weekdays",
        )

    def test_order_style_list_and_sequence_findings_are_reported_together(
        self,
    ) -> None:
        data = {
            "organizations": [{"name": "o"}],
            "report": {
                "order": {
                    "style": "single",
                    "priority": ["codeql", "codeql"],
                    "sequence": [],
                }
            },
        }
        found = _findings(data)
        assert [line.split(":")[0] for line in found] == [
            "report.order.priority",
            "report.order.style",
            "report.order.style",
        ]
        assert "does not read 'priority'" in "\n".join(found)
        assert "needs a non-empty 'sequence'" in "\n".join(found)

    def test_order_overlap_is_skipped_when_a_list_fails_to_parse(self) -> None:
        data = {
            "organizations": [{"name": "o"}],
            "report": {
                "order": {
                    "style": "dual",
                    "priority": ["codeql", "codeql"],
                    "bau": ["codeql"],
                }
            },
        }
        assert [line.split(":")[0] for line in _findings(data)] == [
            "report.order.priority"
        ]

    def test_auto_style_still_checks_the_lists_it_ignores(self) -> None:
        data = {
            "organizations": [{"name": "o"}],
            "report": {"order": {"style": "auto", "bau": ["codeql", "codeql"]}},
        }
        assert [line.split(":")[0] for line in _findings(data)] == [
            "report.order.bau",
            "report.order.style",
        ]


class TestMixedFindings:
    def test_semantic_checks_run_beside_schema_errors_in_other_blocks(
        self,
    ) -> None:
        data = {
            "organizations": [{"name": "o"}],
            "report": {"top_n": "ten"},
            "slack": {"report_day": "funday"},
        }
        assert _findings(data) == (
            'report.top_n: expected an integer, got "ten"',
            "slack.report_day: 'funday' is not a weekday, 'always' or 'never'",
        )

    def test_mixed_findings_merge_in_path_order_with_the_version_note_last(
        self,
    ) -> None:
        data = {
            "report": {"top_n": "ten"},
            "organizations": [
                {"name": "o", "exclde": [], "releases_exclude": ["["]},
                {
                    "name": "p",
                    "report": {"order": {"priority": ["codeql", "codeql"]}},
                },
            ],
        }
        found = _findings(data)
        assert [line.split(":")[0] for line in found[:-1]] == [
            "organizations[0]",
            "organizations[0].releases_exclude",
            "organizations[1].report.order.priority",
            "report.top_n",
        ]
        assert found[-1] == version_note()

    def test_a_block_with_a_schema_error_is_not_parsed(self) -> None:
        data = {
            "organizations": [{"name": "o"}],
            "report": {
                "top_n": "ten",
                "dependabot_warn_threshold": 5,
                "dependabot_error_threshold": 4,
            },
        }
        assert _findings(data) == ('report.top_n: expected an integer, got "ten"',)

    def test_an_override_of_a_schema_rejected_report_skips_inherited_checks(
        self,
    ) -> None:
        data = {
            "report": {"top_n": "ten", "dependabot_error_threshold": 50},
            "organizations": [
                {"name": "o", "report": {"dependabot_warn_threshold": 60}},
                {
                    "name": "p",
                    "report": {
                        "issue_age_warn_days": 30,
                        "issue_age_error_days": 10,
                    },
                },
            ],
        }
        assert [line.split(":")[0] for line in _findings(data)] == [
            "organizations[1].report.issue_age_error_days",
            "report.top_n",
        ]

    def test_a_non_object_organisation_is_reported_once(self) -> None:
        data = {"organizations": ["o", {"name": "p", "slack": {"report_day": "x"}}]}
        assert [line.split(":")[0] for line in _findings(data)] == [
            "organizations[0]",
            "organizations[1].slack.report_day",
        ]


class TestDeprecations:
    def test_each_deprecated_key_is_named_by_path(self) -> None:
        data = {
            "report": {"release_min_age_days": 5},
            "organizations": [{"name": "o", "report": {"release_min_age_days": 3}}],
        }
        assert deprecation_findings(data) == [
            'report.release_min_age_days: deprecated; use "repo_min_age_days" instead',
            "organizations[0].report.release_min_age_days: deprecated; use "
            '"repo_min_age_days" instead',
        ]

    def test_the_warning_names_the_path(self, caplog: pytest.LogCaptureFixture) -> None:
        data = {"organizations": [{"name": "o", "report": {"release_min_age_days": 3}}]}
        with caplog.at_level("WARNING"):
            config.build_config(data)
        assert any(
            "organizations[0].report.release_min_age_days" in record.message
            for record in caplog.records
        )


class TestLoads:
    def test_invalid_json_names_the_position(self) -> None:
        with pytest.raises(ConfigError, match=r"line 1 column 2"):
            config.loads("{oops")

    def test_invalid_base64_is_rejected(self) -> None:
        bad = base64.b64encode(b"{not json").decode()
        with pytest.raises(ConfigError, match="neither valid JSON"):
            config.loads(bad)

    def test_malformed_non_ascii_json_is_a_config_error(self) -> None:
        with pytest.raises(ConfigError, match="neither valid JSON"):
            config.loads('{"organizations": [{"name": "café"}]')

    def test_a_non_object_root_names_its_type(self) -> None:
        with pytest.raises(ConfigError, match="must be a JSON object, not list"):
            config.loads("[]")

    # The decoder's own wording differs between interpreter versions, so these
    # tests match only text this package writes and check the cause's type.
    def test_an_oversized_integer_is_a_config_error(self) -> None:
        raw = '{"report": {"top_n": ' + "1" * 4301 + "}}"
        with pytest.raises(
            ConfigError, match="^configuration could not be decoded: "
        ) as excinfo:
            config.loads(raw)
        assert type(excinfo.value.__cause__) is ValueError

    def test_over_deep_nesting_is_a_config_error(self) -> None:
        with pytest.raises(
            ConfigError,
            match="^configuration could not be decoded: nesting is too deep$",
        ) as excinfo:
            config.loads("[" * 200_000)
        assert isinstance(excinfo.value.__cause__, RecursionError)

    def test_over_deep_base64_nesting_is_a_config_error(self) -> None:
        with pytest.raises(
            ConfigError, match="^configuration is neither valid JSON "
        ) as excinfo:
            config.loads(base64.b64encode(b"[" * 200_000).decode())
        assert isinstance(excinfo.value.__cause__, RecursionError)
