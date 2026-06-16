# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Tests for CLI support helpers."""

from __future__ import annotations

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


class TestActionsIO:
    def test_write_github_output(self, tmp_path: object) -> None:
        out = tmp_path / "out.txt"
        runner.write_github_output({"should_notify": "true", "count": "3"}, str(out))
        content = out.read_text()
        assert "should_notify=true" in content
        assert "count=3" in content

    def test_write_github_output_multiline(self, tmp_path: object) -> None:
        out = tmp_path / "out.txt"
        runner.write_github_output({"body": "line1\nline2"}, str(out))
        content = out.read_text()
        assert "body<<ghadelim_" in content  # unique per-value delimiter
        assert "line1\nline2" in content

    def test_append_step_summary(self, tmp_path: object) -> None:
        summary = tmp_path / "summary.md"
        runner.append_step_summary("## Hi", str(summary))
        assert "## Hi" in summary.read_text()

    def test_io_noop_without_target(self) -> None:
        # No path and no env var -> silently does nothing.
        runner.write_github_output({"x": "y"}, None)
        runner.append_step_summary("x", None)
