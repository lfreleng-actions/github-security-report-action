# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Tests for the GitHub Issues reporting category."""

from __future__ import annotations

import datetime as dt
from collections.abc import Mapping

from github_security_report import issues
from github_security_report.categories import CategoryKey
from github_security_report.config import DEFAULT_ISSUE_LABELS
from github_security_report.models import IssueRef, Repo, RepoGraphData
from github_security_report.report import TableSection

WHEN = dt.datetime(2026, 6, 16, 9, 0, tzinfo=dt.timezone.utc)


def _repo(name: str) -> Repo:
    return Repo(name, f"o/{name}", f"https://github.com/o/{name}")


def _issue(number: int, *labels: str, age_days: int = 0) -> IssueRef:
    return IssueRef(
        number=number,
        title=f"issue {number}",
        labels=labels,
        created_at=WHEN - dt.timedelta(days=age_days),
    )


def _graph(**repos: RepoGraphData) -> dict[str, RepoGraphData]:
    return dict(repos)


def _build(
    graph: dict[str, RepoGraphData],
    names: list[str],
    label_columns: Mapping[str, tuple[str, ...]] = DEFAULT_ISSUE_LABELS,
) -> TableSection:
    return issues.build_issues_table(
        graph,
        [_repo(n) for n in names],
        generated_at=WHEN,
        label_columns=label_columns,
    )


class TestClassifyIssue:
    def test_unlabelled_is_untriaged(self) -> None:
        assert (
            issues.classify_issue(_issue(1), DEFAULT_ISSUE_LABELS)
            == issues.UNTRIAGED_COLUMN
        )

    def test_labelled_but_unmatched_is_other(self) -> None:
        assert (
            issues.classify_issue(_issue(1, "code-quality"), DEFAULT_ISSUE_LABELS)
            == issues.OTHER_COLUMN
        )

    def test_matches_configured_label(self) -> None:
        assert issues.classify_issue(_issue(1, "bug"), DEFAULT_ISSUE_LABELS) == "Bug"

    def test_matching_is_case_insensitive(self) -> None:
        assert issues.classify_issue(_issue(1, "BuG"), DEFAULT_ISSUE_LABELS) == "Bug"

    def test_alias_labels_share_a_column(self) -> None:
        assert (
            issues.classify_issue(_issue(1, "enhancement"), DEFAULT_ISSUE_LABELS)
            == "Feature"
        )

    def test_first_declared_column_wins(self) -> None:
        # An issue labelled both bug and feature counts once, under whichever
        # column is declared first -- so the columns always sum correctly.
        assert (
            issues.classify_issue(_issue(1, "feature", "bug"), DEFAULT_ISSUE_LABELS)
            == "Bug"
        )

    def test_whole_label_match_not_substring(self) -> None:
        # "docs" must not swallow an unrelated "docs-needed" label, which would
        # silently misclassify a triage label as documentation.
        assert (
            issues.classify_issue(_issue(1, "docs-needed"), DEFAULT_ISSUE_LABELS)
            == issues.OTHER_COLUMN
        )


class TestBuildIssuesTable:
    def test_repos_without_issues_count_as_clean(self) -> None:
        table = _build(
            _graph(a=RepoGraphData(), b=RepoGraphData(open_issues=0)), ["a", "b"]
        )
        assert table.rows == []
        assert table.pass_count == 2
        assert table.fail_count == 0

    def test_counts_split_across_columns(self) -> None:
        graph = _graph(
            a=RepoGraphData(
                open_issues=4,
                issues=(
                    _issue(1, "bug"),
                    _issue(2, "enhancement"),
                    _issue(3, "code-quality"),
                    _issue(4),
                ),
            )
        )
        table = _build(graph, ["a"])
        assert table.columns == (
            "Repository",
            "Bug",
            "Feature",
            "Docs",
            "Other",
            "Untriaged",
            "Total",
            "Oldest",
        )
        # Bug, Feature, Docs, Other, Untriaged, Total
        assert table.rows[0].cells[:6] == ("1", "1", "0", "1", "1", "4")

    def test_ranked_by_total_then_untriaged(self) -> None:
        graph = _graph(
            small=RepoGraphData(open_issues=1, issues=(_issue(1),)),
            big=RepoGraphData(
                open_issues=3, issues=(_issue(1, "bug"), _issue(2), _issue(3))
            ),
            tied=RepoGraphData(
                open_issues=3,
                issues=(_issue(1, "bug"), _issue(2, "bug"), _issue(3, "bug")),
            ),
        )
        table = _build(graph, ["small", "big", "tied"])
        # Largest backlog first; the two 3-issue repos are split by Untriaged.
        assert [r.repo.name for r in table.rows] == ["big", "tied", "small"]

    def test_oldest_column_uses_first_window_entry(self) -> None:
        # The window is ordered oldest-first, so entry 0 is the oldest issue.
        graph = _graph(
            a=RepoGraphData(
                open_issues=2, issues=(_issue(1, age_days=30), _issue(2, age_days=2))
            )
        )
        table = _build(graph, ["a"])
        assert table.rows[0].cells[-1] == "30 days"

    def test_truncated_window_is_marked_and_total_stays_exact(self) -> None:
        # 40 open issues but only 2 collected: Total must still report 40, and
        # the row must be marked so the partial breakdown is visible as partial.
        graph = _graph(
            a=RepoGraphData(
                open_issues=40, issues=(_issue(1, age_days=90), _issue(2, "bug"))
            )
        )
        table = _build(graph, ["a"])
        assert table.rows[0].cells[-2] == "40"
        assert table.rows[0].cells[-1].endswith(issues.TRUNCATED_MARKER)
        assert issues.TRUNCATED_MARKER in table.resolved_description()

    def test_untruncated_row_is_not_marked(self) -> None:
        graph = _graph(a=RepoGraphData(open_issues=1, issues=(_issue(1),)))
        table = _build(graph, ["a"])
        assert not table.rows[0].cells[-1].endswith(issues.TRUNCATED_MARKER)
        assert issues.TRUNCATED_MARKER not in table.resolved_description()

    def test_custom_label_columns_replace_defaults(self) -> None:
        table = _build(
            _graph(a=RepoGraphData(open_issues=1, issues=(_issue(1, "regression"),))),
            ["a"],
            label_columns={"Regression": ("regression",)},
        )
        assert table.columns == (
            "Repository",
            "Regression",
            "Other",
            "Untriaged",
            "Total",
            "Oldest",
        )
        assert table.rows[0].cells[:4] == ("1", "0", "0", "1")

    def test_missing_repo_in_graph_counts_as_clean(self) -> None:
        # A repository absent from the prefetch (unreadable alias) must not be
        # reported as having issues; it degrades to the clean count.
        table = _build(_graph(), ["ghost"])
        assert table.rows == []
        assert table.pass_count == 1

    def test_unknown_created_at_does_not_crash(self) -> None:
        graph = _graph(
            a=RepoGraphData(
                open_issues=1, issues=(IssueRef(number=1, title="t", labels=()),)
            )
        )
        table = _build(graph, ["a"])
        assert table.rows[0].cells[-1] == "unknown"

    def test_sum_columns_cover_every_count_column(self) -> None:
        table = _build(
            _graph(a=RepoGraphData(open_issues=1, issues=(_issue(1),))), ["a"]
        )
        # Every column except the repository (0) and the trailing age is summed.
        assert table.sum_columns == frozenset(range(1, len(table.columns) - 1))
        assert table.category.key is CategoryKey.GITHUB_ISSUES
