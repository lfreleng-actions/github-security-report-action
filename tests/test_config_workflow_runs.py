# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Tests for the ``workflow_runs`` configuration block and its CLI flags."""

from __future__ import annotations

from pathlib import Path

import pytest
import typer
from rich.console import Console
from typer.testing import CliRunner

from github_security_report import config
from github_security_report.categories import CategoryKey
from github_security_report.cli import app, boundary
from github_security_report.cli.options import ReportOverrides
from github_security_report.config import (
    ConfigError,
    OrgConfig,
    ReportConfig,
    WorkflowRunsConfig,
)
from github_security_report.config.models import DEFAULT_CATEGORIES

cli = CliRunner()


def _cfg(block: dict, *, org_block: dict | None = None) -> config.Config:
    """A config with a global ``workflow_runs`` block, optionally an org one."""
    org: dict = {"name": "o"}
    if org_block is not None:
        org["report"] = {"workflow_runs": org_block}
    return config.build_config(
        {"report": {"workflow_runs": block}, "organizations": [org, {"name": "p"}]}
    )


class TestDefaults:
    def test_windows_per_surface(self) -> None:
        # The week everywhere; the published report adds month and quarter.
        runs = ReportConfig().workflow_runs
        assert runs.windows_for("cli") == (7,)
        assert runs.windows_for("report") == (7, 30, 90)
        assert runs.windows_for("slack") == (7,)
        assert runs.windows_for("other") == ()
        assert runs.all_windows == (90, 30, 7)
        assert runs.longest_window == 90

    def test_retention_and_backfill_follow_the_longest_window(self) -> None:
        runs = ReportConfig().workflow_runs
        assert runs.retention == 90
        assert runs.backfill == 90

    def test_retention_can_exceed_the_longest_window(self) -> None:
        # A longer retention is the backfill depth too, unless one is given.
        runs = WorkflowRunsConfig(retention_days=120)
        assert runs.retention == 120
        assert runs.backfill == 120

    def test_backfill_is_capped_by_retention(self) -> None:
        # Reading further back than the store keeps would be pruned at once.
        runs = WorkflowRunsConfig(backfill_days=200, retention_days=120)
        assert runs.backfill == 120


class TestBuildConfig:
    def test_windows_merge_per_surface(self) -> None:
        # Emptying the Slack list leaves the report's windows in place.
        runs = _cfg({"windows": {"slack": []}}).report.workflow_runs
        assert runs.windows_for("slack") == ()
        assert runs.windows_for("report") == (7, 30, 90)
        assert runs.windows_for("cli") == (7,)

    def test_org_block_overrides_the_global_for_that_org_only(self) -> None:
        cfg = _cfg({"min_runs": 5}, org_block={"min_runs": 2, "windows": {"cli": [14]}})
        own, other = (org.report.workflow_runs for org in cfg.organizations)
        assert own.min_runs == 2
        assert own.windows_for("cli") == (14,)
        assert own.windows_for("report") == (7, 30, 90)
        assert other.min_runs == 5
        assert other.windows_for("cli") == (7,)

    def test_retention_shorter_than_a_window_is_rejected(self) -> None:
        # The store would prune records the 90-day table still shows.
        with pytest.raises(ConfigError, match="retention_days"):
            _cfg({"retention_days": 30})

    def test_retention_matching_the_longest_window_is_accepted(self) -> None:
        assert _cfg({"retention_days": 90}).report.workflow_runs.retention == 90

    @pytest.mark.parametrize(
        "block",
        [
            {"persistent_threshold": 0},
            {"persistent_threshold": 1.5},
            {"windows": {"cli": [7, 7]}},
            {"windows": {"cli": [0]}},
            {"min_runs": 0},
            {"no_such_key": True},
        ],
        ids=["zero-rate", "rate-over-one", "repeat", "zero-day", "no-runs", "unknown"],
    )
    def test_schema_rejects_an_invalid_block(self, block: dict) -> None:
        with pytest.raises(ConfigError):
            _cfg(block)

    def test_schema_accepts_every_tuning_key(self) -> None:
        runs = _cfg(
            {
                "exclude_workflows": [".github/workflows/x-*.yaml"],
                "include_dynamic": True,
                "cache": False,
                "cache_dir": "/tmp/x",
                "persistent_threshold": 1,
                "collapse_matrix": False,
            }
        ).report.workflow_runs
        assert runs.exclude_workflows == (".github/workflows/x-*.yaml",)
        assert runs.include_dynamic is True
        assert runs.cache is False
        assert runs.cache_dir == "/tmp/x"
        assert runs.persistent_threshold == 1
        assert runs.collapse_matrix is False


class TestCategoryDefaults:
    def test_detail_table_stays_off_slack(self) -> None:
        # Too wide for a chat digest; the per-repository ranking carries the
        # headline there.
        toggle = DEFAULT_CATEGORIES[CategoryKey.WORKFLOW_FAILURES_DETAIL.value]
        assert toggle.shows_on("slack") is False
        assert toggle.shows_on("html") is True
        cfg = ReportConfig()
        assert cfg.shows_category(CategoryKey.WORKFLOW_FAILURES, "slack") is True
        assert (
            cfg.shows_category(CategoryKey.WORKFLOW_FAILURES_DETAIL, "slack") is False
        )


class TestParseWindows:
    def _parse(self, value: str | None) -> tuple[int, ...] | None:
        parsed: tuple[int, ...] | None = boundary.parse_windows(
            Console(record=True), value
        )
        return parsed

    def test_unset_is_none(self) -> None:
        assert self._parse(None) is None

    def test_sorted_longest_first(self) -> None:
        # Comma- or space-separated, normalised to one longest-first tuple.
        assert self._parse("7,30,90") == (90, 30, 7)
        assert self._parse("7 30") == (30, 7)

    @pytest.mark.parametrize("value", ["0", "x", "7,7", ""])
    def test_invalid_values_exit_two(self, value: str) -> None:
        with pytest.raises(typer.Exit) as exc:
            self._parse(value)
        assert exc.value.exit_code == 2


class TestOverrides:
    def test_run_windows_replace_every_surface(self) -> None:
        # One list for the whole run, the shape an investigation wants.
        runs = ReportOverrides(run_windows=(14,)).apply_runs(ReportConfig())
        assert dict(runs.windows) == {"cli": (14,), "report": (14,), "slack": (14,)}

    def test_cache_flags_reach_the_run_store(self) -> None:
        runs = ReportOverrides(run_cache=False, run_cache_dir="x").apply_runs(
            ReportConfig()
        )
        assert runs.cache is False
        assert runs.cache_dir == "x"

    def test_unset_overrides_keep_the_config(self) -> None:
        base = ReportConfig()
        assert ReportOverrides().apply_runs(base) == base.workflow_runs

    def test_apply_threads_the_runs_into_the_report_config(self) -> None:
        overrides = ReportOverrides(run_windows=(14,), run_cache=False)
        _, report_cfg = overrides.apply(OrgConfig(name="o"))
        assert report_cfg.workflow_runs.windows_for("slack") == (14,)
        assert report_cfg.workflow_runs.cache is False


@pytest.fixture
def _env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """A token, and no per-user config for discovery to pick up."""
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))


@pytest.mark.usefixtures("_env")
@pytest.mark.parametrize(
    "flag",
    [["--no-run-cache"], ["--refresh-runs"], ["--run-cache-dir", "x"]],
    ids=["no-cache", "refresh", "cache-dir"],
)
def test_run_store_flags_rejected_in_repo_mode(flag: list[str]) -> None:
    # Repo mode reads one repository's week afresh each time, so the run-store
    # flags would be accepted and do nothing; they are refused by name.
    result = cli.invoke(
        app, ["report", "--repo", "o/r", "--scope", "repo", "--no-color", *flag]
    )
    assert result.exit_code == 2, result.stdout
    assert flag[0] in result.stdout
    assert "organisation mode only" in result.stdout


@pytest.mark.usefixtures("_env")
def test_malformed_run_windows_rejected() -> None:
    result = cli.invoke(
        app, ["report", "--repo", "o/r", "--run-windows", "7,abc", "--no-color"]
    )
    assert result.exit_code == 2, result.stdout
    assert "--run-windows" in result.stdout
