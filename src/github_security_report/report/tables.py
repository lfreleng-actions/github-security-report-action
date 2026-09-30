# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Generic repository-keyed tables, and the emphasis a cell can carry.

The structures behind every reporting category that falls outside the
four-state per-signal model -- Dependabot posture, Releases / Tagging, GitHub
Issues and Pull Requests. A :class:`TableSection` carries its
:class:`CategoryMeta` and the normalised counts that feed the shared footer;
:class:`TableRow` carries one repository's pre-formatted cells.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from github_security_report.categories import REPO_LIST_CATEGORIES, CategoryMeta
from github_security_report.models import Repo
from github_security_report.summary import RepoList, SummaryCount

# Semantic emphasis a builder can attach to a table cell, mapped to a concrete
# presentation by each render surface. Deliberately meaning rather than colour:
# a builder knows a repository is at its automation cap, not that the terminal
# should print yellow, and a surface with no colour (Markdown, Slack) can ignore
# the levels entirely rather than being handed escape codes it cannot use.
CELL_GOOD = "good"
CELL_WARN = "warn"
CELL_BAD = "bad"
CELL_LEVELS = (CELL_GOOD, CELL_WARN, CELL_BAD)


@dataclass
class TableRow:
    """A generic, repository-keyed table row with pre-formatted cells.

    Used by the Dependabot posture, Releases/Tagging and GitHub Issues tables,
    which do not fit the four-state :class:`SignalSection` model. ``cells``
    excludes the leading repository link cell (each renderer supplies that from
    ``repo``).

    ``sort_values`` carries the typed value behind each cell, parallel to
    ``cells``, so a configured column ordering sorts on the number rather than
    its rendering -- "16 days" and "9 days" compare correctly as 16 and 9, but
    backwards as strings. Empty means the builder published no sort values, in
    which case ordering falls back to the displayed text. ``None`` for one entry
    means that cell has no value to sort on (an unknown age, say); the ordering
    layer keeps such rows last whichever direction the column is sorted in,
    since missing is not the same as small.

    ``cell_levels`` is the optional semantic emphasis for each cell, again
    parallel to ``cells`` (one of :data:`CELL_LEVELS`, or ``None`` for no
    emphasis). Empty means the builder published none and every cell renders
    plainly.
    """

    repo: Repo
    cells: tuple[str, ...]
    sort_values: tuple[float | str | None, ...] = ()
    cell_levels: tuple[str | None, ...] = ()
    # This row's contribution to each of its table's ``footer_labels``, in the
    # same order. Summed over the *displayed* rows at render time, exactly like
    # the column totals, so a truncated table's footer describes what is on
    # screen rather than a total the reader cannot reconcile.
    footer_values: tuple[int, ...] = ()

    def level(self, index: int) -> str | None:
        """The emphasis for cell ``index``, or ``None`` when it has none."""
        if index < len(self.cell_levels):
            return self.cell_levels[index]
        return None


@dataclass
class TableSection:
    """A generic titled table rendered as a sub-section under a heading.

    Carries its :class:`CategoryMeta` (title, pass/fail labels, docs URL,
    description) plus the normalised pass/fail/unknown counts that feed the
    shared :func:`build_summary` footer, so every category presents its results
    in the same standardised form. The **first** column is always the
    repository column -- every renderer puts the repository link/name there
    (from each :class:`TableRow`'s ``repo``). Its header *label* is free-form
    (usually ``"Repository"``); downstream consumers treat column 0 as the
    repository regardless of the label.
    """

    category: CategoryMeta
    columns: tuple[str, ...]  # column 0 is the repository column (label varies)
    rows: list[TableRow] = field(default_factory=list)
    # Column indices (into ``columns``) whose cells are numeric and should be
    # summed into a trailing totals row. Empty means the table has no summable
    # columns and renders without one -- the case for every qualitative table
    # (release ages, ecosystems, release tags).
    sum_columns: frozenset[int] = frozenset()
    # Normalised footer counts. ``fail_count`` is the number of listed (rows)
    # offenders; ``pass_count`` the healthy repositories; ``unknown_count`` the
    # repositories whose state could not be determined.
    pass_count: int = 0
    fail_count: int = 0
    unknown_count: int = 0
    # Column indices whose values are numeric, declared by the builder so a
    # configured sort resolves its default direction from the table's schema
    # rather than from whatever rows this particular run produced (an empty or
    # all-unknown column would otherwise be judged text). Empty means the
    # builder declared nothing and ordering falls back to inspecting values.
    numeric_columns: frozenset[int] = frozenset()
    # Resolved explanatory description (Markdown/HTML only). Empty falls back to
    # the category's default description at render time.
    description: str = ""
    # Labels for aggregate rows drawn beneath the totals row, each summing one
    # slice of the table that is not a column -- a breakdown *of* the rows
    # rather than *within* them. Empty means the table has none.
    footer_labels: tuple[str, ...] = ()
    # The subset of ``footer_labels`` whose meaning is relative to the account
    # the report authenticated as ("Mine" and, by implication, "Others").
    # Those rows answer a question only that account can ask, so they are
    # rendered solely on the surface that account reads -- the terminal -- and
    # dropped from every published artifact, where "mine" would name the token
    # owner rather than the reader. See :func:`table_footer_rows`.
    personal_footer_labels: frozenset[str] = frozenset()
    # The repositories counted in ``pass_count``, for the boolean feature
    # categories only (see :data:`REPO_LIST_CATEGORIES`), where the passing side
    # is a plain repository list that can be named in place of the rows. Empty
    # everywhere else: a qualitative table's passing repositories carry nothing
    # a reader would act on.
    pass_repos: tuple[Repo, ...] = ()

    @property
    def title(self) -> str:
        return self.category.title

    @property
    def lists_repos(self) -> bool:
        """Whether this is a boolean feature table, named inline not tabulated.

        Such a table has no column beyond the repository, so drawing one would
        only restate the name list -- and could not say which side it lists
        once :class:`RepoList` may pick the enabled side. Every surface renders
        these as a name list beneath the matching count line instead.
        """
        return self.category.key in REPO_LIST_CATEGORIES

    def listed_kind(self, repo_list: RepoList = RepoList.AUTO) -> str | None:
        """The footer bucket (``"fail"`` or ``"pass"``) whose repos are named.

        ``None`` for a table that is not a boolean feature table. ``auto``
        names the shorter list, with two deliberate exceptions that keep the
        actionable side in view: a tie names the offenders, and an empty
        passing list never displaces them -- "list the zero repositories that
        have it" would print nothing where a reader wants the ones to fix.
        """
        if not self.lists_repos:
            return None
        if repo_list is RepoList.ENABLED:
            return "pass"
        if repo_list is RepoList.DISABLED:
            return "fail"
        return "pass" if 0 < len(self.pass_repos) < len(self.rows) else "fail"

    def resolved_description(self) -> str:
        """The description to show, falling back to the category default."""
        return self.description or self.category.description

    def repos_by_name(self) -> dict[str, Repo]:
        """Every repository this table can name, keyed by name, for linking."""
        return {
            repo.name: repo
            for repo in (*(row.repo for row in self.rows), *self.pass_repos)
        }

    def summary_counts(
        self,
        excluded: Sequence[Repo] = (),
        *,
        repo_list: RepoList = RepoList.AUTO,
    ) -> list[SummaryCount]:
        """Footer count buckets for this table (failure, unknown, pass, excluded).

        A boolean feature table also names one side's repositories, chosen by
        ``repo_list`` (see :meth:`listed_kind`); both sides are always counted.
        """
        fail_label = self.category.fail_label or "Failing"
        listed = self.listed_kind(repo_list)
        fail_names = (
            tuple(row.repo.name for row in self.rows) if listed == "fail" else ()
        )
        pass_names = (
            tuple(repo.name for repo in self.pass_repos) if listed == "pass" else ()
        )
        return [
            SummaryCount("fail", self.fail_count, fail_label, fail_names),
            SummaryCount("unknown", self.unknown_count, "Unknown"),
            SummaryCount(
                "pass",
                self.pass_count,
                self.category.pass_label,
                pass_names,
                all_label=self.category.pass_all_label,
            ),
            SummaryCount(
                "excluded",
                len(excluded),
                "Excluded",
                tuple(r.name for r in excluded),
            ),
        ]
