# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Tests for CLI support helpers."""

from __future__ import annotations

from pathlib import Path

import pytest

from github_security_report import runner
from github_security_report.models import (
    Repo,
    RepoSignal,
    RepoState,
    SeverityCounts,
    SignalType,
)
from github_security_report.runner import Mode, ModeError


def _sig(state: RepoState, **counts: int) -> RepoSignal:
    repo = Repo("r", "o/r", "https://github.com/o/r")
    return RepoSignal(repo, SignalType.CODEQL, state, SeverityCounts(**counts))


class TestResolveMode:
    def test_explicit_org(self) -> None:
        assert (
            runner.resolve_mode("org", has_org_config=True, detected_repo=None)
            is Mode.ORG
        )

    def test_explicit_org_without_config_errors(self) -> None:
        with pytest.raises(ModeError):
            runner.resolve_mode("org", has_org_config=False, detected_repo=None)

    def test_explicit_repo(self) -> None:
        assert (
            runner.resolve_mode("repo", has_org_config=False, detected_repo=("o", "r"))
            is Mode.REPO
        )

    def test_explicit_repo_without_detection_errors(self) -> None:
        with pytest.raises(ModeError):
            runner.resolve_mode("repo", has_org_config=False, detected_repo=None)

    def test_auto_prefers_org(self) -> None:
        assert (
            runner.resolve_mode("auto", has_org_config=True, detected_repo=("o", "r"))
            is Mode.ORG
        )

    def test_auto_falls_back_to_repo(self) -> None:
        assert (
            runner.resolve_mode("auto", has_org_config=False, detected_repo=("o", "r"))
            is Mode.REPO
        )

    def test_auto_errors_when_nothing(self) -> None:
        with pytest.raises(ModeError):
            runner.resolve_mode("auto", has_org_config=False, detected_repo=None)


class TestShouldFail:
    def test_none_never_fails(self) -> None:
        assert not runner.should_fail([_sig(RepoState.OFFENDER, critical=5)], "none")

    def test_any_fails_on_offender(self) -> None:
        assert runner.should_fail([_sig(RepoState.OFFENDER, low=1)], "any")
        assert not runner.should_fail([_sig(RepoState.CLEAN)], "any")

    def test_severity_floor(self) -> None:
        signals = [_sig(RepoState.OFFENDER, high=1)]
        assert runner.should_fail(signals, "high")
        assert runner.should_fail(signals, "medium")  # high >= medium
        assert not runner.should_fail(signals, "critical")  # high < critical

    def test_clean_never_fails(self) -> None:
        assert not runner.should_fail(
            [_sig(RepoState.CLEAN), _sig(RepoState.NAG)], "low"
        )

    def test_clean_signal_with_a_sub_cutoff_finding(self) -> None:
        # A low finding under a medium cutoff leaves the signal clean, but the
        # threshold judges the finding, not the classification.
        signals = [_sig(RepoState.CLEAN, low=1)]
        assert runner.should_fail(signals, "low")
        assert runner.should_fail(signals, "any")
        assert not runner.should_fail(signals, "medium")
        assert not runner.should_fail(signals, "none")

    def test_unknown_signal_with_findings_in_hand(self) -> None:
        signals = [_sig(RepoState.UNKNOWN, low=1)]
        assert runner.should_fail(signals, "low")
        assert not runner.should_fail(signals, "medium")

    def test_informational_offender_fails_at_any_alone(self) -> None:
        signals = [_sig(RepoState.OFFENDER, informational=2)]
        assert runner.should_fail(signals, "any")
        for threshold in ("low", "medium", "high", "critical", "none"):
            assert not runner.should_fail(signals, threshold)


class TestFailOnUnknown:
    def test_unknown_signal_fails_only_with_the_flag(self) -> None:
        signals = [_sig(RepoState.UNKNOWN)]
        assert not runner.should_fail(signals, "low")
        assert runner.should_fail(signals, "low", fail_on_unknown=True)

    def test_disabled_and_not_applicable_pass_with_the_flag(self) -> None:
        signals = [_sig(RepoState.NAG), _sig(RepoState.NOT_APPLICABLE)]
        assert not runner.should_fail(signals, "any", fail_on_unknown=True)

    def test_flag_fails_the_gate_at_threshold_none(self) -> None:
        signals = [_sig(RepoState.UNKNOWN)]
        assert runner.should_fail(signals, "none", fail_on_unknown=True)

    def test_each_cause_is_named(self) -> None:
        repo = Repo("r", "o/r", "https://github.com/o/r")
        signals = [
            RepoSignal(
                repo,
                SignalType.SECRET_SCANNING,
                RepoState.UNKNOWN,
                detail="insufficient permission",
            ),
            RepoSignal(
                repo, SignalType.DEPENDABOT, RepoState.CLEAN, SeverityCounts(low=1)
            ),
        ]
        decision = runner.gate(signals, "low", fail_on_unknown=True)
        assert decision.failed
        assert len(decision.reasons) == 2
        assert "Dependabot" in decision.reasons[0]
        assert "'low'" in decision.reasons[0]
        assert "Secret Scanning" in decision.reasons[1]
        assert "insufficient permission" in decision.reasons[1]


class TestActionsIO:
    def test_write_github_output(self, tmp_path: Path) -> None:
        out = tmp_path / "out.txt"
        runner.write_github_output({"should_notify": "true", "count": "3"}, str(out))
        content = out.read_text()
        assert "should_notify=true" in content
        assert "count=3" in content

    def test_write_github_output_multiline(self, tmp_path: Path) -> None:
        out = tmp_path / "out.txt"
        runner.write_github_output({"body": "line1\nline2"}, str(out))
        content = out.read_text()
        assert "body<<ghadelim_" in content  # unique per-value delimiter
        assert "line1\nline2" in content

    def test_write_github_output_rejects_unsafe_key(self, tmp_path: Path) -> None:
        # A non-identifier key (newline / '=' / '<<') must not be written, so it
        # cannot corrupt the output file or inject extra outputs.
        out = tmp_path / "out.txt"
        runner.write_github_output(
            {"ok": "1", "bad\nkey=x<<EOF": "2", "with space": "3"}, str(out)
        )
        content = out.read_text()
        assert "ok=1" in content
        assert "bad" not in content
        assert "with space" not in content

    def test_append_step_summary(self, tmp_path: Path) -> None:
        summary = tmp_path / "summary.md"
        runner.append_step_summary("## Hi", str(summary))
        assert "## Hi" in summary.read_text()

    def test_io_noop_without_target(self) -> None:
        # No path and no env var -> silently does nothing.
        runner.write_github_output({"x": "y"}, None)
        runner.append_step_summary("x", None)
