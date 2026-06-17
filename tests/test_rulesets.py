# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Tests for org-ruleset coverage of workflow-driven tools."""

from __future__ import annotations

from github_security_report import rulesets

# Mirrors the live "Zizmor scans" ruleset shape.
ZIZMOR_RULESET = {
    "name": "Zizmor scans",
    "enforcement": "active",
    "target": "branch",
    "conditions": {
        "ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []},
        "repository_name": {
            "include": ["*"],
            "exclude": ["project-reporting-artifacts", "test-tags-calver"],
        },
    },
    "rules": [
        {
            "type": "workflows",
            "parameters": {
                "workflows": [
                    {
                        "path": ".github/workflows/zizmor.yaml",
                        "ref": "refs/heads/main",
                        "repository_id": 1185150290,
                    }
                ]
            },
        }
    ],
}


class TestParse:
    def test_extracts_active_workflow_ruleset(self) -> None:
        parsed = rulesets.parse_workflow_rulesets([ZIZMOR_RULESET])
        assert len(parsed) == 1
        rs = parsed[0]
        assert rs.workflow_paths == (".github/workflows/zizmor.yaml",)
        assert rs.include == ("*",)
        assert "project-reporting-artifacts" in rs.exclude

    def test_skips_inactive(self) -> None:
        inactive = {**ZIZMOR_RULESET, "enforcement": "evaluate"}
        assert rulesets.parse_workflow_rulesets([inactive]) == []

    def test_skips_non_workflow_rules(self) -> None:
        other = {
            "enforcement": "active",
            "target": "branch",
            "conditions": {"repository_name": {"include": ["*"], "exclude": []}},
            "rules": [{"type": "pull_request", "parameters": {}}],
        }
        assert rulesets.parse_workflow_rulesets([other]) == []


class TestCoverage:
    def setup_method(self) -> None:
        self.rs = rulesets.parse_workflow_rulesets([ZIZMOR_RULESET])

    def test_included_repo_covered(self) -> None:
        assert rulesets.signals_covered(
            "dependamerge", self.rs, {"zizmor": "zizmor"}
        ) == {"zizmor"}

    def test_excluded_repo_not_covered(self) -> None:
        assert (
            rulesets.signals_covered(
                "project-reporting-artifacts", self.rs, {"zizmor": "zizmor"}
            )
            == set()
        )

    def test_keyword_must_match_workflow_path(self) -> None:
        # No signal whose keyword matches the zizmor.yaml path.
        assert (
            rulesets.signals_covered("dependamerge", self.rs, {"trivy": "trivy"})
            == set()
        )

    def test_empty_keyword_does_not_match_everything(self) -> None:
        # A misconfigured empty keyword must not substring-match every path and
        # mark all repos as covered (which would wrongly suppress nags).
        assert (
            rulesets.signals_covered("dependamerge", self.rs, {"zizmor": ""}) == set()
        )


class TestGlobMatching:
    def test_glob_include(self) -> None:
        rs = [
            rulesets.WorkflowRuleset(
                name="x",
                workflow_paths=(".github/workflows/zizmor.yaml",),
                include=("python-*",),
                exclude=(),
            )
        ]
        assert rulesets.repo_covered("python-build-action", rs[0])
        assert not rulesets.repo_covered("gerrit-action", rs[0])

    def test_tilde_all(self) -> None:
        rs = rulesets.WorkflowRuleset("x", (".../zizmor.yaml",), ("~ALL",), ())
        assert rulesets.repo_covered("anything", rs)


class TestBranchRules:
    def test_signals_from_branch_rules(self) -> None:
        rules = [
            {"type": "pull_request", "parameters": {}},
            {
                "type": "workflows",
                "parameters": {
                    "workflows": [{"path": ".github/workflows/zizmor.yaml"}]
                },
            },
        ]
        assert rulesets.signals_from_branch_rules(rules, {"zizmor": "zizmor"}) == {
            "zizmor"
        }

    def test_no_workflow_rule(self) -> None:
        rules = [{"type": "deletion", "parameters": {}}]
        assert rulesets.signals_from_branch_rules(rules, {"zizmor": "zizmor"}) == set()
