# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Tests for the Pull Requests reporting category."""

from __future__ import annotations

import functools
from collections.abc import Set

from github_security_report import config, pulls
from github_security_report.categories import CategoryKey
from github_security_report.models import (
    AuthorRef,
    PullRequestRef,
    Repo,
    RepoGraphData,
)
from github_security_report.report import (
    CELL_BAD,
    CELL_GOOD,
    CELL_WARN,
    TableRow,
    TableSection,
    table_column_totals,
    table_footer_rows,
)

# The unremarkable case every helper defaults to: a human who is an
# organisation member, so a plain `_pull()` exercises no classification edge.
INSIDER = AuthorRef(login="insider", typename="User", association="MEMBER")


def _repo(name: str) -> Repo:
    return Repo(name, f"o/{name}", f"https://github.com/o/{name}")


def _author(
    login: str, *, typename: str = "User", association: str = "MEMBER"
) -> AuthorRef:
    return AuthorRef(login=login, typename=typename, association=association)


def _pull(
    number: int,
    author: AuthorRef | None = INSIDER,
    *,
    draft: bool = False,
    conflicting: bool | None = None,
    failing: bool | None = None,
    assignees: tuple[str, ...] = (),
) -> PullRequestRef:
    return PullRequestRef(
        number=number,
        author=author,
        draft=draft,
        assignees=assignees,
        conflicting=conflicting,
        failing=failing,
    )


def _graph(**repos: RepoGraphData) -> dict[str, RepoGraphData]:
    return dict(repos)


def _build(
    graph: dict[str, RepoGraphData],
    names: list[str],
    members: Set[str] | None = frozenset(),
    warn_threshold: int = 0,
    error_threshold: int = 0,
    viewer: str = "",
) -> TableSection:
    return pulls.build_pull_requests_table(
        graph,
        [_repo(n) for n in names],
        members=members,
        warn_threshold=warn_threshold,
        error_threshold=error_threshold,
        viewer=viewer,
    )


def _build_assigned(
    graph: dict[str, RepoGraphData],
    names: list[str],
    viewer: str = "",
) -> TableSection:
    return pulls.build_assigned_pull_requests_table(
        graph, [_repo(n) for n in names], viewer=viewer
    )


def _count(
    collected: tuple[PullRequestRef, ...], members: Set[str] = frozenset()
) -> dict[str, int]:
    # Annotated rather than returned directly: the pre-commit mypy sandbox
    # sees only the changed files, so the package import degrades to Any and a
    # bare return trips no-any-return depending on what else is staged.
    counts: dict[str, int] = pulls.count_pull_requests(collected, members)
    return counts


def _cell(row: TableRow, column: str) -> str:
    # `cells` excludes the leading repository cell each renderer supplies from
    # `row.repo`, so a column's table index is one ahead of its cell index.
    cell: str = row.cells[pulls.ALL_COLUMNS.index(column) - 1]
    return cell


class TestCountPullRequests:
    def test_human_and_automation_partition_every_pull_request(self) -> None:
        collected = (
            _pull(1),
            _pull(2, _author("dependabot[bot]", typename="Bot", association="NONE")),
            _pull(3, _author("outsider", association="NONE")),
            _pull(4, None),
        )
        counts = _count(collected)
        # The two columns are a partition, never overlapping and never leaving a
        # pull request uncounted, so they always sum to the collected window.
        assert counts[pulls.HUMAN_COLUMN] + counts[pulls.AUTOMATION_COLUMN] == len(
            collected
        )
        assert counts[pulls.HUMAN_COLUMN] == 3
        assert counts[pulls.AUTOMATION_COLUMN] == 1

    def test_bot_suffixed_login_counts_as_automation(self) -> None:
        counts = _count((_pull(1, _author("dependabot[bot]", typename="Bot")),))
        assert counts[pulls.AUTOMATION_COLUMN] == 1
        assert counts[pulls.HUMAN_COLUMN] == 0

    def test_bot_typename_counts_as_automation_whatever_the_login(self) -> None:
        # GraphQL returns an App actor's login bare on some surfaces, so the
        # typename is the only marker that a plain-looking login is a bot.
        counts = _count((_pull(1, _author("some-app", typename="Bot")),))
        assert counts[pulls.AUTOMATION_COLUMN] == 1
        assert counts[pulls.HUMAN_COLUMN] == 0

    def test_outside_bot_is_automation_and_never_external(self) -> None:
        # The real-world Dependabot case, and the whole reason automation is
        # tested before association: GitHub reports `dependabot[bot]` as NONE or
        # CONTRIBUTOR, so classifying on association alone would file every
        # routine dependency update as an outside contribution and bury the
        # genuine ones the column exists to surface.
        for association in ("NONE", "CONTRIBUTOR"):
            counts = _count(
                (
                    _pull(
                        1,
                        _author(
                            "dependabot[bot]",
                            typename="Bot",
                            association=association,
                        ),
                    ),
                )
            )
            assert counts[pulls.AUTOMATION_COLUMN] == 1
            assert counts[pulls.EXTERNAL_COLUMN] == 0
            assert counts[pulls.HUMAN_COLUMN] == 0

    def test_unrecognised_bot_is_still_kept_out_of_external(self) -> None:
        # A future bot carries neither a known login nor, on some surfaces, a
        # Bot typename; the `[bot]` suffix must still keep it out of Ext.
        counts = _count((_pull(1, _author("mystery[bot]", association="NONE")),))
        assert counts[pulls.AUTOMATION_COLUMN] == 1
        assert counts[pulls.EXTERNAL_COLUMN] == 0

    def test_external_counts_outside_humans_and_stays_within_human(self) -> None:
        collected = (
            _pull(1),
            _pull(2, _author("outsider", association="NONE")),
            _pull(3, _author("drive-by", association="CONTRIBUTOR")),
            _pull(4, _author("renovate", association="NONE")),
        )
        counts = _count(collected)
        assert counts[pulls.EXTERNAL_COLUMN] == 2
        # Ext is a subset of Human, never a separate bucket, so it can never
        # exceed it -- an Ext above Human would mean a bot leaked into it.
        assert counts[pulls.EXTERNAL_COLUMN] <= counts[pulls.HUMAN_COLUMN]

    def test_collaborator_association_is_not_external(self) -> None:
        counts = _count((_pull(1, _author("helper", association="COLLABORATOR")),))
        assert counts[pulls.EXTERNAL_COLUMN] == 0

    def test_collected_member_is_not_external_despite_none_association(self) -> None:
        # Private organisation membership (the default) is reported as NONE to a
        # token without organisation visibility. The collected membership is the
        # token-independent evidence, so it must win over the association.
        counts = _count(
            (_pull(1, _author("alice", association="NONE")),),
            members=frozenset({"alice"}),
        )
        assert counts[pulls.EXTERNAL_COLUMN] == 0
        assert counts[pulls.HUMAN_COLUMN] == 1

    def test_unclassifiable_association_is_not_counted_as_external(self) -> None:
        # An empty or newly introduced association cannot be placed either side
        # of the fence. Reporting it as external would invent an outsider and
        # inflate exactly the column the report is read for.
        for association in ("", "SPONSOR"):
            counts = _count((_pull(1, _author("stranger", association=association)),))
            assert counts[pulls.EXTERNAL_COLUMN] == 0
            assert counts[pulls.HUMAN_COLUMN] == 1

    def test_missing_author_counts_as_human_and_not_external(self) -> None:
        # GitHub renders a deleted account's `author` as null. It still occupies
        # review capacity, so it is counted -- but nothing is known about where
        # it came from, and the lookup must not raise on the None.
        counts = _count((_pull(1, None),))
        assert counts[pulls.HUMAN_COLUMN] == 1
        assert counts[pulls.EXTERNAL_COLUMN] == 0

    def test_only_established_check_failures_count(self) -> None:
        # None means no checks ran at all and False means they passed; neither
        # is a failure, and treating the absent rollup as one would report a
        # repository without CI as entirely blocked.
        collected = (
            _pull(1, failing=None),
            _pull(2, failing=False),
            _pull(3, failing=True),
        )
        assert _count(collected)[pulls.FAILING_COLUMN] == 1

    def test_only_established_conflicts_count(self) -> None:
        # GitHub computes mergeability lazily and answers UNKNOWN until it has,
        # so a cold sweep must not read "not yet computed" as conflicting.
        collected = (
            _pull(1, conflicting=None),
            _pull(2, conflicting=False),
            _pull(3, conflicting=True),
        )
        assert _count(collected)[pulls.CONFLICT_COLUMN] == 1

    def test_one_pull_request_counts_once_in_every_axis_it_matches(self) -> None:
        counts = _count((_pull(1, draft=True, conflicting=True, failing=True),))
        # Conflict, Fail and Draft are independent axes overlapping the author
        # split and each other, so a single stuck draft appears in all three and
        # once in Human. They are not meant to sum to the total.
        assert counts[pulls.DRAFT_COLUMN] == 1
        assert counts[pulls.FAILING_COLUMN] == 1
        assert counts[pulls.CONFLICT_COLUMN] == 1
        assert counts[pulls.HUMAN_COLUMN] == 1
        assert counts[pulls.AUTOMATION_COLUMN] == 0

    def test_empty_window_reports_a_zero_for_every_column(self) -> None:
        assert _count(()) == dict.fromkeys(pulls.BREAKDOWN_COLUMNS, 0)


class TestBuildPullRequestsTable:
    def test_columns_are_repository_breakdown_then_total(self) -> None:
        table = _build(_graph(a=RepoGraphData(open_pull_requests=0)), ["a"])
        assert table.columns == pulls.ALL_COLUMNS
        assert table.columns == (
            "Repository",
            "Human",
            "Ext",
            "Auto",
            "Conflict",
            "Fail",
            "Draft",
            "Total",
        )

    def test_repos_without_pull_requests_count_as_clean(self) -> None:
        table = _build(_graph(b=RepoGraphData(open_pull_requests=0)), ["b"])
        assert table.rows == []
        assert table.pass_count == 1
        assert table.fail_count == 0
        assert table.unknown_count == 0

    def test_unreadable_pull_requests_count_as_unknown_not_clean(self) -> None:
        # A null connection means the backlog was never seen. Counting it as
        # clean would render a confident "no open pull requests" for it.
        table = _build(
            _graph(a=RepoGraphData(), b=RepoGraphData(open_pull_requests=0)),
            ["a", "b"],
        )
        assert table.rows == []
        assert table.unknown_count == 1
        assert table.pass_count == 1

    def test_missing_repo_in_graph_counts_as_unknown(self) -> None:
        # A repository absent from the prefetch (an unreadable alias) is in the
        # same position as a null connection, not in the healthy total.
        table = _build(_graph(), ["ghost"])
        assert table.rows == []
        assert table.pass_count == 0
        assert table.unknown_count == 1

    def test_fail_count_matches_the_listed_rows(self) -> None:
        graph = _graph(
            a=RepoGraphData(open_pull_requests=1, pull_requests=(_pull(1),)),
            b=RepoGraphData(open_pull_requests=2, pull_requests=(_pull(1), _pull(2))),
            c=RepoGraphData(open_pull_requests=0),
        )
        table = _build(graph, ["a", "b", "c"])
        assert table.fail_count == len(table.rows) == 2

    def test_counts_split_across_columns(self) -> None:
        # Every column gets a distinct count, so this pins the column *order*
        # as well as the arithmetic: with all-equal counts, swapping two
        # columns would leave the assertion passing.
        graph = _graph(
            a=RepoGraphData(
                open_pull_requests=6,
                pull_requests=(
                    _pull(1),
                    _pull(2, _author("outsider", association="NONE"), draft=True),
                    _pull(
                        3,
                        _author("outsider", association="NONE"),
                        draft=True,
                        failing=True,
                    ),
                    _pull(
                        4,
                        _author("outsider", association="NONE"),
                        draft=True,
                        failing=True,
                        conflicting=True,
                    ),
                    _pull(
                        5,
                        _author("dependabot[bot]", typename="Bot", association="NONE"),
                    ),
                    _pull(
                        6,
                        _author("renovate[bot]", typename="Bot", association="NONE"),
                    ),
                ),
            )
        )
        table = _build(graph, ["a"])
        # Human, Ext, Auto, Conflict, Fail, Draft, Total
        assert table.rows[0].cells == ("4", "3", "2", "1", "2", "3", "6")

    def test_collected_members_change_the_external_count(self) -> None:
        graph = _graph(
            a=RepoGraphData(
                open_pull_requests=1,
                pull_requests=(_pull(1, _author("alice", association="NONE")),),
            )
        )
        with_membership = _build(graph, ["a"], members=frozenset({"alice"}))
        without_membership = _build(graph, ["a"])
        assert _cell(with_membership.rows[0], pulls.EXTERNAL_COLUMN) == "0"
        # Without the membership the same author reads as an outsider, which is
        # the token-dependence the collected membership exists to remove.
        assert _cell(without_membership.rows[0], pulls.EXTERNAL_COLUMN) == "1"

    def test_ranked_by_total_then_by_blocked(self) -> None:
        graph = _graph(
            calm=RepoGraphData(
                open_pull_requests=2, pull_requests=(_pull(1), _pull(2))
            ),
            small=RepoGraphData(open_pull_requests=1, pull_requests=(_pull(1),)),
            stuck=RepoGraphData(
                open_pull_requests=2,
                pull_requests=(_pull(1, failing=True), _pull(2, conflicting=True)),
            ),
        )
        table = _build(graph, ["calm", "small", "stuck"])
        # Largest backlog first; the two 2-pull repos tie on total and are split
        # by Fail+Conflict, so the more stuck one surfaces first.
        assert [r.repo.name for r in table.rows] == ["stuck", "calm", "small"]

    def test_blocked_tiebreaker_counts_each_pull_request_once(self) -> None:
        # Fail and Conflict overlap, so summing the two columns would count a
        # pull request that is both as two -- letting one stuck pull request
        # outrank two separately stuck ones. The ranking has to agree with the
        # table's own statement that the columns overlap.
        graph = _graph(
            two_stuck=RepoGraphData(
                open_pull_requests=3,
                pull_requests=(
                    _pull(1, failing=True),
                    _pull(2, conflicting=True),
                    _pull(3),
                ),
            ),
            one_doubly_stuck=RepoGraphData(
                open_pull_requests=3,
                pull_requests=(
                    _pull(1, failing=True, conflicting=True),
                    _pull(2),
                    _pull(3),
                ),
            ),
        )
        table = _build(graph, ["one_doubly_stuck", "two_stuck"])
        # Both total 3. two_stuck has two affected pull requests against one,
        # so it must rank first however many flags that one carries.
        assert [r.repo.name for r in table.rows] == ["two_stuck", "one_doubly_stuck"]

    def test_tie_on_total_and_blocked_is_broken_by_name(self) -> None:
        graph = _graph(
            zeta=RepoGraphData(open_pull_requests=2, pull_requests=(_pull(1),)),
            alpha=RepoGraphData(open_pull_requests=2, pull_requests=(_pull(1),)),
            alphax=RepoGraphData(open_pull_requests=2, pull_requests=(_pull(1),)),
        )
        table = _build(graph, ["zeta", "alpha", "alphax"])
        # The numeric keys are negated so the whole sort runs ascending; the
        # name tiebreaker must stay ascending even where one name prefixes
        # another, which a reversed sort would invert.
        assert [r.repo.name for r in table.rows] == ["alpha", "alphax", "zeta"]

    def test_truncated_window_is_marked_and_total_stays_exact(self) -> None:
        # 40 open pull requests but only 2 collected: Total comes from
        # totalCount so it must still read 40, while the breakdown only saw the
        # window and the row must say so.
        graph = _graph(
            a=RepoGraphData(
                open_pull_requests=40, pull_requests=(_pull(1), _pull(2, draft=True))
            )
        )
        table = _build(graph, ["a"])
        assert _cell(table.rows[0], pulls.TOTAL_COLUMN) == "40 +"
        assert pulls.TRUNCATED_MARKER in table.resolved_description()

    def test_truncated_total_still_sums_into_the_totals_row(self) -> None:
        # The marker is separated by a space so the leading integer still parses
        # for the footer; a marker glued to the digits would sum the row as 0
        # and silently under-report the whole organisation's backlog.
        graph = _graph(
            a=RepoGraphData(open_pull_requests=40, pull_requests=(_pull(1),))
        )
        table = _build(graph, ["a"])
        totals = table_column_totals(table, table.rows)
        assert totals is not None
        assert totals[table.columns.index(pulls.TOTAL_COLUMN)] == "40"

    def test_untruncated_row_is_not_marked(self) -> None:
        graph = _graph(a=RepoGraphData(open_pull_requests=1, pull_requests=(_pull(1),)))
        table = _build(graph, ["a"])
        assert not _cell(table.rows[0], pulls.TOTAL_COLUMN).endswith(
            pulls.TRUNCATED_MARKER
        )
        # A report whose windows all covered their backlogs must carry no
        # unexplained qualification about partial breakdowns.
        assert pulls.TRUNCATED_MARKER not in table.resolved_description()

    def test_sum_columns_cover_every_count_column(self) -> None:
        table = _build(
            _graph(a=RepoGraphData(open_pull_requests=1, pull_requests=(_pull(1),))),
            ["a"],
        )
        # Every column except the repository (0) is an additive count, the
        # marked total included.
        assert table.sum_columns == frozenset(range(1, len(table.columns)))
        assert table.numeric_columns == frozenset(range(1, len(table.columns)))
        assert table.category.key is CategoryKey.PULL_REQUESTS


class TestAutomationLevel:
    def _level(self, value: int) -> str | None:
        """Emphasis under an explicit 12/15 policy, not the shipped defaults."""
        level: str | None = pulls.automation_level(
            value, warn_threshold=12, error_threshold=15
        )
        return level

    def test_the_default_thresholds_track_githubs_own_limit(self) -> None:
        # GitHub's open-pull-requests-limit defaults to 5, so the shipped
        # defaults put red at the limit and yellow on the approach to it.
        # Pinned here because the boundaries are the whole feature: an
        # off-by-one silently moves where the report raises its voice.
        defaults = config.ReportConfig()
        level = functools.partial(
            pulls.automation_level,
            warn_threshold=defaults.dependabot_warn_threshold,
            error_threshold=defaults.dependabot_error_threshold,
        )
        assert [level(n) for n in range(0, 7)] == [
            None,  # 0
            None,  # 1
            None,  # 2
            CELL_WARN,  # 3
            CELL_WARN,  # 4
            CELL_BAD,  # 5 -- GitHub's default limit
            CELL_BAD,  # 6
        ]

    def test_below_the_warn_threshold_is_unemphasised(self) -> None:
        assert self._level(0) is None
        # The warn threshold is exclusive: it takes strictly more to warn.
        assert self._level(12) is None

    def test_above_the_warn_threshold_warns(self) -> None:
        assert self._level(13) == CELL_WARN
        assert self._level(14) == CELL_WARN

    def test_at_the_error_threshold_is_an_error(self) -> None:
        # The error threshold is inclusive, so the configured value itself
        # errors rather than warning.
        assert self._level(15) == CELL_BAD
        assert self._level(40) == CELL_BAD

    def test_zero_thresholds_disable_each_level(self) -> None:
        # 0 means "off", matching the row-limit idiom, rather than "every value
        # is at or above zero, so colour everything".
        assert pulls.automation_level(99, warn_threshold=0, error_threshold=0) is None
        assert (
            pulls.automation_level(99, warn_threshold=12, error_threshold=0)
            == CELL_WARN
        )


class TestCellLevels:
    def _levels(self, table: TableSection) -> dict[str, str | None]:
        row = table.rows[0]
        return {
            column: row.level(index) for index, column in enumerate(table.columns[1:])
        }

    def test_human_and_external_counts_read_as_good(self) -> None:
        graph = _graph(
            a=RepoGraphData(
                open_pull_requests=1,
                pull_requests=(_pull(1, _author("outsider", association="NONE")),),
            )
        )
        levels = self._levels(_build(graph, ["a"]))
        assert levels[pulls.HUMAN_COLUMN] == CELL_GOOD
        assert levels[pulls.EXTERNAL_COLUMN] == CELL_GOOD

    def test_blocked_counts_read_as_bad(self) -> None:
        graph = _graph(
            a=RepoGraphData(
                open_pull_requests=1,
                pull_requests=(_pull(1, conflicting=True, failing=True),),
            )
        )
        levels = self._levels(_build(graph, ["a"]))
        assert levels[pulls.CONFLICT_COLUMN] == CELL_BAD
        assert levels[pulls.FAILING_COLUMN] == CELL_BAD

    def test_zero_counts_are_never_emphasised(self) -> None:
        # A table of red zeros teaches the reader to ignore the colour, which
        # costs exactly the signal the colour exists to carry.
        graph = _graph(a=RepoGraphData(open_pull_requests=1, pull_requests=(_pull(1),)))
        levels = self._levels(_build(graph, ["a"]))
        assert levels[pulls.CONFLICT_COLUMN] is None
        assert levels[pulls.FAILING_COLUMN] is None
        assert levels[pulls.EXTERNAL_COLUMN] is None

    def test_draft_and_total_carry_no_emphasis(self) -> None:
        # A draft is not blocked, just unfinished; the total sums columns that
        # disagree about what good looks like, so no one colour is true of it.
        graph = _graph(
            a=RepoGraphData(open_pull_requests=1, pull_requests=(_pull(1, draft=True),))
        )
        levels = self._levels(_build(graph, ["a"]))
        assert levels[pulls.DRAFT_COLUMN] is None
        assert levels[pulls.TOTAL_COLUMN] is None

    def test_automation_backlog_uses_the_configured_thresholds(self) -> None:
        def _auto(count: int) -> RepoGraphData:
            bots = tuple(
                _pull(i, _author("dependabot[bot]", typename="Bot", association="NONE"))
                for i in range(count)
            )
            return RepoGraphData(open_pull_requests=count, pull_requests=bots)

        for count, expected in ((4, None), (13, CELL_WARN), (15, CELL_BAD)):
            table = _build(
                _graph(a=_auto(count)), ["a"], warn_threshold=12, error_threshold=15
            )
            assert self._levels(table)[pulls.AUTOMATION_COLUMN] == expected

    def test_thresholds_default_to_off(self) -> None:
        # A caller that never configured thresholds gets a plainly rendered
        # table rather than one coloured against numbers it did not choose.
        bots = tuple(
            _pull(i, _author("dependabot[bot]", typename="Bot", association="NONE"))
            for i in range(40)
        )
        graph = _graph(a=RepoGraphData(open_pull_requests=40, pull_requests=bots))
        assert self._levels(_build(graph, ["a"]))[pulls.AUTOMATION_COLUMN] is None


class TestAssignmentBreakdown:
    def _mixed(self) -> dict[str, RepoGraphData]:
        return _graph(
            a=RepoGraphData(
                open_pull_requests=4,
                pull_requests=(
                    _pull(1),
                    _pull(2, assignees=("me",)),
                    _pull(3, assignees=("someone-else",)),
                    _pull(4, assignees=("someone-else", "me")),
                ),
            )
        )

    def test_the_three_buckets_partition_the_backlog(self) -> None:
        # Every collected pull request lands in exactly one bucket, so the
        # three always reconcile against the total the table already shows.
        counts = pulls.assignment_counts(self._mixed()["a"].pull_requests, "me")
        assert counts == {
            pulls.UNASSIGNED_ROW: 1,
            pulls.OTHERS_ROW: 1,
            pulls.MINE_ROW: 2,
        }
        assert sum(counts.values()) == 4

    def test_shared_assignment_still_counts_as_mine(self) -> None:
        # It is in my queue regardless of who else is on it.
        assert pulls.is_mine(_pull(1, assignees=("someone-else", "me")), "me")

    def test_unknown_viewer_claims_nothing(self) -> None:
        # A bot or App token has no personal queue; assigning another person's
        # backlog to "mine" would be worse than reporting none.
        counts = pulls.assignment_counts(self._mixed()["a"].pull_requests, "")
        assert counts[pulls.MINE_ROW] == 0
        assert counts[pulls.OTHERS_ROW] == 3
        assert counts[pulls.UNASSIGNED_ROW] == 1

    def test_footer_rows_are_declared_and_populated(self) -> None:
        table = _build(self._mixed(), ["a"], viewer="me")
        assert table.footer_labels == pulls.ASSIGNMENT_ROWS
        rows = table_footer_rows(table, table.rows)
        # Full width, so every renderer places the value under the final
        # column. Anything narrower lands it under Human, which would file an
        # unassigned bot pull request as a human one.
        assert all(len(r) == len(table.columns) for r in rows)
        assert [(r[0], r[-1]) for r in rows] == [
            (pulls.UNASSIGNED_ROW, "1"),
            (pulls.OTHERS_ROW, "1"),
            (pulls.MINE_ROW, "2"),
        ]
        # The cells between are blank: the partition totals the row, it does
        # not break down by column.
        assert all(set(r[1:-1]) == {""} for r in rows)

    def test_the_value_aligns_under_the_total_column(self) -> None:
        # The buckets partition every collected pull request, automation
        # included, so Total is the only column they are a breakdown of.
        table = _build(self._mixed(), ["a"], viewer="me")
        row = table_footer_rows(table, table.rows)[0]
        assert table.columns[-1] == pulls.TOTAL_COLUMN
        assert row[-1] == "1"
        assert row[table.columns.index(pulls.HUMAN_COLUMN)] == ""

    def test_footer_sums_only_the_displayed_rows(self) -> None:
        # Like the totals row: a footer the reader cannot reconcile against the
        # rows above it is worse than no footer.
        graph = _graph(
            big=RepoGraphData(
                open_pull_requests=2,
                pull_requests=(
                    _pull(1, assignees=("me",)),
                    _pull(2, assignees=("me",)),
                ),
            ),
            small=RepoGraphData(
                open_pull_requests=1, pull_requests=(_pull(3, assignees=("me",)),)
            ),
        )
        table = _build(graph, ["big", "small"], viewer="me")
        shown = table.rows[:1]
        assert [(r[0], r[-1]) for r in table_footer_rows(table, shown)] == [
            (pulls.UNASSIGNED_ROW, "0"),
            (pulls.OTHERS_ROW, "0"),
            (pulls.MINE_ROW, "2"),
        ]


class TestBuildAssignedPullRequestsTable:
    def _graph(self) -> dict[str, RepoGraphData]:
        return _graph(
            mine=RepoGraphData(
                open_pull_requests=3,
                pull_requests=(
                    _pull(1, assignees=("me",)),
                    _pull(2, assignees=("someone-else",)),
                    _pull(3),
                ),
            ),
            theirs=RepoGraphData(
                open_pull_requests=2,
                pull_requests=(
                    _pull(4, assignees=("someone-else",)),
                    _pull(5),
                ),
            ),
        )

    def test_counts_only_the_viewers_pull_requests(self) -> None:
        table = _build_assigned(self._graph(), ["mine", "theirs"], viewer="me")
        assert [r.repo.name for r in table.rows] == ["mine"]
        # The total is the viewer's own count, not the repository's backlog.
        assert table.rows[0].cells[-1] == "1"

    def test_repos_with_nothing_assigned_count_as_clean(self) -> None:
        # A row of zeros for a repository the reader has no stake in would be
        # noise; the point of the table is their own inbox.
        table = _build_assigned(self._graph(), ["mine", "theirs"], viewer="me")
        assert table.pass_count == 1
        assert table.fail_count == 1

    def test_unknown_viewer_yields_an_empty_table(self) -> None:
        table = _build_assigned(self._graph(), ["mine", "theirs"], viewer="")
        assert table.rows == []
        assert table.pass_count == 2

    def test_unknown_viewer_stays_clean_on_a_truncated_window(self) -> None:
        # With no account to match, the selector cannot match anything
        # anywhere, so an empty result is certain rather than merely
        # unobserved. A bot or App run must get the documented empty table, not
        # a wall of unknowns as soon as a repository exceeds the window.
        graph = _graph(
            busy=RepoGraphData(
                open_pull_requests=40,
                pull_requests=(_pull(1, assignees=("someone-else",)),),
            )
        )
        table = _build_assigned(graph, ["busy"], viewer="")
        assert table.unknown_count == 0
        assert table.pass_count == 1

    def test_unknown_viewer_stays_clean_on_an_unreadable_backlog(self) -> None:
        # Same certainty, and for the same reason: an unreadable connection
        # cannot be hiding a match for an account that does not exist. Without
        # this, a bot run on a token lacking Pull requests access reports every
        # repository as unknown instead of the documented empty queue.
        table = _build_assigned(_graph(ghost=RepoGraphData()), ["ghost"], viewer="")
        assert table.unknown_count == 0
        assert table.pass_count == 1

    def test_shares_the_column_shape_of_the_main_table(self) -> None:
        # The two tables sit next to each other, so they must read alike.
        table = _build_assigned(self._graph(), ["mine"], viewer="me")
        assert table.columns == pulls.ALL_COLUMNS

    def test_carries_no_assignment_footer(self) -> None:
        # Every row is already "mine", so the breakdown would say nothing.
        table = _build_assigned(self._graph(), ["mine"], viewer="me")
        assert table.footer_labels == ()
        assert table_footer_rows(table, table.rows) == ()

    def test_unreadable_backlog_is_unknown_not_clean(self) -> None:
        table = _build_assigned(_graph(ghost=RepoGraphData()), ["ghost"], viewer="me")
        assert table.unknown_count == 1
        assert table.pass_count == 0

    def test_no_match_in_a_truncated_window_is_unknown_not_clean(self) -> None:
        # None of the collected pull requests is the viewer's, but the window
        # did not cover the backlog, so one of the uncollected ones may be.
        # "Nothing of yours here" is a claim this run cannot support.
        graph = _graph(
            busy=RepoGraphData(
                open_pull_requests=40,
                pull_requests=(_pull(1, assignees=("someone-else",)),),
            )
        )
        table = _build_assigned(graph, ["busy"], viewer="me")
        assert table.rows == []
        assert table.unknown_count == 1
        assert table.pass_count == 0

    def test_no_match_in_a_complete_window_is_clean(self) -> None:
        graph = _graph(
            quiet=RepoGraphData(
                open_pull_requests=1,
                pull_requests=(_pull(1, assignees=("someone-else",)),),
            )
        )
        table = _build_assigned(graph, ["quiet"], viewer="me")
        assert table.pass_count == 1
        assert table.unknown_count == 0


class TestTruncationAndMembershipCaveats:
    def test_truncated_rows_qualify_the_assignment_breakdown(self) -> None:
        # The footer sums the collected window while Total stays exact, so a
        # breakdown that cannot reconcile must say why rather than looking
        # like arithmetic that does not add up.
        graph = _graph(
            busy=RepoGraphData(
                open_pull_requests=40,
                pull_requests=(_pull(1, assignees=("me",)),),
            )
        )
        described = _build(graph, ["busy"], viewer="me").resolved_description()
        assert pulls.TRUNCATED_MARKER in described
        assert "assignment breakdown" in described

    def test_unknown_membership_is_declared_in_the_description(self) -> None:
        graph = _graph(
            a=RepoGraphData(
                open_pull_requests=1,
                pull_requests=(_pull(1, _author("mystery", association="NONE")),),
            )
        )
        table = _build(graph, ["a"], members=None)
        assert "lower bound" in table.resolved_description()

    def test_the_assigned_table_calls_its_own_total_a_lower_bound(self) -> None:
        # The filtered table's Total is len(selected) from the window, not the
        # authoritative totalCount, so the unfiltered table's "Total stays
        # exact" would be false here -- and it has no assignment breakdown to
        # qualify either.
        graph = _graph(
            busy=RepoGraphData(
                open_pull_requests=40,
                pull_requests=(_pull(1, assignees=("me",)),),
            )
        )
        described = _build_assigned(graph, ["busy"], viewer="me").resolved_description()
        assert "lower bound" in described
        assert "Total itself stays exact" not in described
        assert "assignment breakdown" not in described
