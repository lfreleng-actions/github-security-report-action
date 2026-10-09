# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Tests for the GitHub Issues reporting category."""

from __future__ import annotations

import datetime as dt
from collections.abc import Mapping

from github_security_report import issues
from github_security_report.categories import CategoryKey
from github_security_report.config import DEFAULT_ISSUE_LABELS, ReportConfig
from github_security_report.models import AuthorRef, IssueRef, Repo, RepoGraphData
from github_security_report.report import (
    CELL_BAD,
    CELL_GOOD,
    CELL_WARN,
    TableSection,
    table_column_totals,
)

WHEN = dt.datetime(2026, 6, 16, 9, 0, tzinfo=dt.timezone.utc)
_DEFAULTS = ReportConfig()


def _repo(name: str) -> Repo:
    return Repo(name, f"o/{name}", f"https://github.com/o/{name}")


def _issue(number: int, *labels: str, age_days: int = 0) -> IssueRef:
    return IssueRef(
        number=number,
        title=f"issue {number}",
        labels=labels,
        created_at=WHEN - dt.timedelta(days=age_days),
    )


def _authored(
    number: int,
    login: str,
    *,
    association: str = "NONE",
    typename: str = "User",
) -> IssueRef:
    return IssueRef(
        number=number,
        title=f"issue {number}",
        labels=("bug",),
        created_at=WHEN,
        author=AuthorRef(login=login, typename=typename, association=association),
    )


def _graph(**repos: RepoGraphData) -> dict[str, RepoGraphData]:
    return dict(repos)


def _build(
    graph: dict[str, RepoGraphData],
    names: list[str],
    label_columns: Mapping[str, tuple[str, ...]] = DEFAULT_ISSUE_LABELS,
    members: frozenset[str] | None = frozenset(),
    age_warn_days: int = _DEFAULTS.issue_age_warn_days,
    age_error_days: int = _DEFAULTS.issue_age_error_days,
) -> TableSection:
    return issues.build_issues_table(
        graph,
        [_repo(n) for n in names],
        generated_at=WHEN,
        label_columns=label_columns,
        age_warn_days=age_warn_days,
        age_error_days=age_error_days,
        members=members,
    )


def _ext_cell(table: TableSection) -> str:
    """The Ext cell of the first row (cells omit the leading repository)."""
    cell: str = table.rows[0].cells[table.columns.index(issues.EXTERNAL_COLUMN) - 1]
    return cell


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


class TestExternalColumn:
    def _one(self, issue: IssueRef, members: frozenset[str] = frozenset()) -> str:
        graph = _graph(a=RepoGraphData(open_issues=1, issues=(issue,)))
        return _ext_cell(_build(graph, ["a"], members=members))

    def test_outsider_is_counted(self) -> None:
        assert self._one(_authored(1, "drive-by", association="NONE")) == "1"

    def test_organisation_member_is_not_counted(self) -> None:
        assert self._one(_authored(1, "staffer", association="MEMBER")) == "0"

    def test_collected_membership_overrides_the_association(self) -> None:
        # An organisation whose members keep their membership private has them
        # reported as outsiders by the per-item association, so the collected
        # membership has to win or the column counts the whole org as external.
        assert (
            self._one(
                _authored(1, "Staffer", association="NONE"),
                members=frozenset({"staffer"}),
            )
            == "0"
        )

    def test_automation_is_never_external(self) -> None:
        # Bots really do report CONTRIBUTOR/NONE, so counting on the association
        # alone would file every automated issue as an outside contribution.
        assert (
            self._one(
                _authored(1, "dependabot[bot]", association="NONE", typename="Bot")
            )
            == "0"
        )

    def test_unclassifiable_author_is_not_counted(self) -> None:
        # Indeterminate must understate rather than invent an outsider.
        assert self._one(_authored(1, "mystery", association="")) == "0"

    def test_missing_author_does_not_raise(self) -> None:
        # GitHub renders the author null for a deleted account.
        assert self._one(_issue(1, "bug")) == "0"

    def test_counts_only_the_outsiders(self) -> None:
        graph = _graph(
            a=RepoGraphData(
                open_issues=3,
                issues=(
                    _authored(1, "outsider", association="CONTRIBUTOR"),
                    _authored(2, "staffer", association="MEMBER"),
                    _authored(3, "another-outsider", association="NONE"),
                ),
            )
        )
        assert _ext_cell(_build(graph, ["a"])) == "2"

    def test_a_truncated_window_marks_ext_as_partial(self) -> None:
        # Ext is computed from the collected window, so on a large backlog it
        # is a lower bound. Rendering it as a bare number would present an
        # undercount as exact -- 25 internal issues ahead of the external ones
        # would read as a confident zero.
        graph = _graph(
            a=RepoGraphData(
                open_issues=40,
                issues=(_authored(1, "staffer", association="MEMBER"),),
            )
        )
        table = _build(graph, ["a"])
        assert _ext_cell(table).endswith(issues.TRUNCATED_MARKER)
        # The marked cell must still sum: the totals row reads a cell's
        # leading numeric token rather than requiring the whole string.
        totals = table_column_totals(table, table.rows)
        assert totals is not None
        assert totals[table.columns.index(issues.EXTERNAL_COLUMN)] == "0"

    def test_unknown_membership_is_declared_in_the_description(self) -> None:
        # An Ext of 0 that only means "we could not tell" must say so, or a
        # reader will take it for a clean result.
        graph = _graph(
            a=RepoGraphData(
                open_issues=1,
                issues=(_authored(1, "mystery", association="NONE"),),
            )
        )
        table = _build(graph, ["a"], members=None)
        assert _ext_cell(table).startswith("0")
        assert "lower bound" in table.resolved_description()


class TestBuildIssuesTable:
    def test_repos_without_issues_count_as_clean(self) -> None:
        table = _build(_graph(b=RepoGraphData(open_issues=0)), ["b"])
        assert table.rows == []
        assert table.pass_count == 1
        assert table.fail_count == 0
        assert table.unknown_count == 0

    def test_unreadable_issues_count_as_unknown_not_clean(self) -> None:
        # GitHub serves a token lacking Issues: read with HTTP 200, the rest of
        # the repository populated and this field null. Counting that as clean
        # would render a confident "no open issues" for an unreadable backlog.
        table = _build(
            _graph(a=RepoGraphData(), b=RepoGraphData(open_issues=0)), ["a", "b"]
        )
        assert table.rows == []
        assert table.unknown_count == 1
        assert table.pass_count == 1

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
            "Ext",
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
        assert table.rows[0].cells[-3] == "40"
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
            "Ext",
            "Oldest",
        )
        assert table.rows[0].cells[:4] == ("1", "0", "0", "1")

    def test_missing_repo_in_graph_counts_as_unknown(self) -> None:
        # A repository absent from the prefetch (unreadable alias) must not be
        # reported as having no issues; its backlog was never seen.
        table = _build(_graph(), ["ghost"])
        assert table.rows == []
        assert table.pass_count == 0
        assert table.unknown_count == 1

    def test_unknown_created_at_does_not_crash(self) -> None:
        graph = _graph(
            a=RepoGraphData(
                open_issues=1, issues=(IssueRef(number=1, title="t", labels=()),)
            )
        )
        table = _build(graph, ["a"])
        assert table.rows[0].cells[-1] == issues.UNKNOWN_AGE

    def test_unknown_age_is_explained_and_never_called_exact(self) -> None:
        graph = _graph(
            a=RepoGraphData(
                open_issues=1, issues=(IssueRef(number=1, title="t", labels=()),)
            )
        )
        description = _build(graph, ["a"]).resolved_description()
        assert issues.UNKNOWN_AGE in description
        assert "Oldest remain exact" not in description

    def test_unknown_age_still_marks_a_truncated_window(self) -> None:
        # The label breakdown is partial whether or not a date came back, so
        # dropping the marker here would present it as complete.
        graph = _graph(
            a=RepoGraphData(
                open_issues=40, issues=(IssueRef(number=1, title="t", labels=()),)
            )
        )
        table = _build(graph, ["a"])
        assert table.rows[0].cells[-1] == (
            f"{issues.UNKNOWN_AGE} {issues.TRUNCATED_MARKER}"
        )
        assert issues.TRUNCATED_MARKER in table.resolved_description()

    def test_truncated_label_window_marks_the_row(self) -> None:
        # An issue with more labels than were fetched, none of which matched a
        # configured column, could have been classified differently.
        graph = _graph(
            a=RepoGraphData(
                open_issues=1,
                issues=(
                    IssueRef(
                        number=1,
                        title="t",
                        labels=("wontfix",),
                        labels_truncated=True,
                        created_at=WHEN,
                    ),
                ),
            )
        )
        table = _build(graph, ["a"])
        assert table.rows[0].cells[-1].endswith(issues.TRUNCATED_MARKER)

    def test_matched_issue_is_not_marked_despite_label_truncation(self) -> None:
        # A match on the *first* configured column is immune: no unseen label
        # can belong to an earlier column, because there is no earlier column.
        graph = _graph(
            a=RepoGraphData(
                open_issues=1,
                issues=(
                    IssueRef(
                        number=1,
                        title="t",
                        labels=("bug",),
                        labels_truncated=True,
                        created_at=WHEN,
                    ),
                ),
            )
        )
        table = _build(graph, ["a"])
        assert not table.rows[0].cells[-1].endswith(issues.TRUNCATED_MARKER)

    def test_match_on_a_later_column_is_marked_when_labels_truncated(self) -> None:
        # Classification walks the configured columns, not the fetched labels,
        # so a Feature match could still be outranked by an unseen `bug` label.
        graph = _graph(
            a=RepoGraphData(
                open_issues=1,
                issues=(
                    IssueRef(
                        number=1,
                        title="t",
                        labels=("feature",),
                        labels_truncated=True,
                        created_at=WHEN,
                    ),
                ),
            )
        )
        table = _build(graph, ["a"])
        assert table.rows[0].cells[-1].endswith(issues.TRUNCATED_MARKER)

    def test_untriaged_with_unreadable_labels_is_marked(self) -> None:
        # An unreadable labels connection parses as no labels but truncated.
        # The issue must not be counted at all: calling it Untriaged would
        # invent a triage gap from data the run never saw.
        graph = _graph(
            a=RepoGraphData(
                open_issues=1,
                issues=(
                    IssueRef(
                        number=1,
                        title="t",
                        labels=(),
                        labels_truncated=True,
                        created_at=WHEN,
                    ),
                ),
            )
        )
        table = _build(graph, ["a"])
        assert table.rows[0].cells[-1].endswith(issues.TRUNCATED_MARKER)
        untriaged = table.columns.index(issues.UNTRIAGED_COLUMN)
        assert table.rows[0].cells[untriaged - 1] == "0"
        # Total stays authoritative even though nothing could be classified.
        assert table.rows[0].cells[-3] == "1"

    def test_undated_oldest_entry_is_unknown_not_the_next_issue(self) -> None:
        # The window is ordered oldest-first, so entry 0 is the only evidence of
        # which issue is oldest. Falling through to entry 1 would report a newer
        # issue's age as the oldest.
        graph = _graph(
            a=RepoGraphData(
                open_issues=2,
                issues=(
                    IssueRef(number=1, title="t", labels=("bug",)),
                    _issue(2, "bug", age_days=3),
                ),
            )
        )
        table = _build(graph, ["a"])
        assert table.rows[0].cells[-1] == issues.UNKNOWN_AGE

    def test_dropped_oldest_node_is_unknown_not_the_next_issue(self) -> None:
        # Same hazard one level up: when parsing drops the leading node, the
        # surviving entry 0 is only the oldest *readable* issue.
        graph = _graph(
            a=RepoGraphData(
                open_issues=2,
                issues=(_issue(2, "bug", age_days=3),),
                oldest_issue_unreadable=True,
            )
        )
        table = _build(graph, ["a"])
        assert table.rows[0].cells[-1].startswith(issues.UNKNOWN_AGE)

    def test_sum_columns_cover_every_count_column(self) -> None:
        table = _build(
            _graph(a=RepoGraphData(open_issues=1, issues=(_issue(1),))), ["a"]
        )
        # Every column except the repository (0) and the trailing age is summed.
        assert table.sum_columns == frozenset(range(1, len(table.columns) - 1))
        assert table.category.key is CategoryKey.GITHUB_ISSUES


class TestAgeLevel:
    @staticmethod
    def _level(age: int | None) -> str | None:
        """Emphasis under the shipped 30/60-day defaults."""
        level: str | None = issues.age_level(
            age,
            warn_days=_DEFAULTS.issue_age_warn_days,
            error_days=_DEFAULTS.issue_age_error_days,
        )
        return level

    def test_the_defaults_are_thirty_and_sixty_days(self) -> None:
        assert _DEFAULTS.issue_age_warn_days == 30
        assert _DEFAULTS.issue_age_error_days == 60

    def test_young_backlog_is_good(self) -> None:
        assert self._level(0) == CELL_GOOD
        # Both thresholds read "older than", so the boundary day is still green.
        assert self._level(30) == CELL_GOOD

    def test_ageing_backlog_warns(self) -> None:
        assert self._level(31) == CELL_WARN
        assert self._level(60) == CELL_WARN

    def test_stale_backlog_is_bad(self) -> None:
        assert self._level(61) == CELL_BAD
        assert self._level(400) == CELL_BAD

    def test_unknown_age_is_never_coloured(self) -> None:
        assert self._level(None) is None

    def test_zero_thresholds_disable_each_level(self) -> None:
        # 0 means "off", as for the automation thresholds, rather than "every
        # age exceeds zero, so colour everything".
        assert issues.age_level(99, warn_days=0, error_days=0) is None
        assert issues.age_level(99, warn_days=30, error_days=0) == CELL_WARN
        assert issues.age_level(99, warn_days=0, error_days=60) == CELL_BAD
        assert issues.age_level(45, warn_days=0, error_days=60) == CELL_GOOD


class TestCellLevels:
    @staticmethod
    def _levels(table: TableSection, row: int = 0) -> dict[str, str | None]:
        """One row's emphasis keyed by column (repository excluded)."""
        cells = table.rows[row]
        return {
            column: cells.level(index) for index, column in enumerate(table.columns[1:])
        }

    def test_bug_and_untriaged_are_bad_docs_good(self) -> None:
        graph = _graph(
            a=RepoGraphData(
                open_issues=4,
                issues=(
                    _issue(1, "bug"),
                    _issue(2, "enhancement"),
                    _issue(3, "docs"),
                    _issue(4),
                ),
            )
        )
        levels = self._levels(_build(graph, ["a"]))
        assert levels["Bug"] == CELL_BAD
        assert levels["Docs"] == CELL_GOOD
        assert levels[issues.UNTRIAGED_COLUMN] == CELL_BAD
        assert levels["Feature"] is None
        assert levels[issues.TOTAL_COLUMN] is None
        assert levels[issues.EXTERNAL_COLUMN] is None

    def test_only_non_zero_counts_are_emphasised(self) -> None:
        # A column of red zeros trains the reader to ignore the colour.
        graph = _graph(a=RepoGraphData(open_issues=1, issues=(_issue(1, "bug"),)))
        levels = self._levels(_build(graph, ["a"]))
        assert levels["Bug"] == CELL_BAD
        assert levels["Docs"] is None
        assert levels[issues.UNTRIAGED_COLUMN] is None

    def test_column_emphasis_follows_the_header_case_insensitively(self) -> None:
        table = _build(
            _graph(
                a=RepoGraphData(open_issues=2, issues=(_issue(1, "x"), _issue(2, "y")))
            ),
            ["a"],
            label_columns={"BUG": ("x",), "Regression": ("y",)},
        )
        levels = self._levels(table)
        assert levels["BUG"] == CELL_BAD
        assert levels["Regression"] is None

    def test_oldest_is_coloured_by_the_default_thresholds(self) -> None:
        def _oldest(age: int) -> str | None:
            graph = _graph(
                a=RepoGraphData(open_issues=1, issues=(_issue(1, age_days=age),))
            )
            return self._levels(_build(graph, ["a"]))[issues.OLDEST_COLUMN]

        assert _oldest(10) == CELL_GOOD
        assert _oldest(45) == CELL_WARN
        assert _oldest(90) == CELL_BAD

    def test_oldest_uses_the_configured_thresholds(self) -> None:
        graph = _graph(a=RepoGraphData(open_issues=1, issues=(_issue(1, age_days=45),)))
        table = _build(graph, ["a"], age_warn_days=50, age_error_days=100)
        assert self._levels(table)[issues.OLDEST_COLUMN] == CELL_GOOD

    def test_unknown_oldest_is_not_coloured(self) -> None:
        # Alongside a dated row, so the plain cell is the unknown age's doing.
        graph = _graph(
            a=RepoGraphData(open_issues=1, issues=(_issue(1, age_days=5),)),
            b=RepoGraphData(
                open_issues=1, issues=(IssueRef(number=1, title="t", labels=()),)
            ),
        )
        table = _build(graph, ["a", "b"])
        assert self._levels(table, 0)[issues.OLDEST_COLUMN] == CELL_GOOD
        assert self._levels(table, 1)[issues.OLDEST_COLUMN] is None
