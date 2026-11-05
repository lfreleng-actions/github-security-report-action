# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Per-category exclusions, applied as each table or section is built.

Beyond the organisation's ``exclude`` list, which removes a repository from
analysis altogether, the configuration carries two classes of name pattern
that leave a repository out of a category while every other still reports
it: ``exclude`` for the general case and ``exclude_tests`` for test
repositories and fixtures. Both exist report-wide and per category, and
every table and signal section is built from an input the
:class:`CategoryScope` has narrowed, so the row, the counts and the
remediation plan all agree on which repositories the category covers.

Nothing is dropped silently: each class is recorded on the report, so the
category's footer counts it and ``report.json`` lists it. A repository the
run was asked for by name (``remediate --repos``) is never excluded here --
naming it is the opt-in -- while the organisation's own list still holds.
"""

from __future__ import annotations

from collections.abc import Callable, Collection, Sequence
from typing import TypeVar

from github_security_report.categories import CategoryKey
from github_security_report.config import ReportConfig
from github_security_report.matching import Pattern, matches
from github_security_report.models import Repo
from github_security_report.report import OrgReport

_T = TypeVar("_T")


class CategoryScope:
    """Which repositories each category covers, and what it leaves out.

    Built before the report exists, since the signal sections are narrowed
    on their way into it; :meth:`attach` then hands the report the lists,
    which later narrowing keeps writing into.
    """

    def __init__(
        self,
        report_cfg: ReportConfig,
        in_scope: Sequence[Repo],
        *,
        excluded_repos: Sequence[Repo] = (),
        opted_in: Collection[str] = (),
    ) -> None:
        self._cfg = report_cfg
        self._repos = tuple(in_scope)
        self._excluded_repos = tuple(excluded_repos)
        self._opted_in = frozenset(opted_in)
        self.category_excluded: dict[CategoryKey, list[Repo]] = {}
        self.category_excluded_tests: dict[CategoryKey, list[Repo]] = {}
        # The report-wide lists give every category its baseline; a category
        # is recorded only where its own lists make it differ.
        self.excluded_tests_default = self._matching(report_cfg.exclude_tests)
        general = self._matching(report_cfg.exclude, less=self.excluded_tests_default)
        self.excluded_default = _sorted((*excluded_repos, *general))

    def attach(self, report: OrgReport) -> None:
        """Give ``report`` the baselines and the per-category lists."""
        report.excluded_default = self.excluded_default
        report.excluded_tests_default = self.excluded_tests_default
        report.category_excluded = self.category_excluded
        report.category_excluded_tests = self.category_excluded_tests

    def _matching(
        self, patterns: Sequence[Pattern], *, less: Collection[Repo] = ()
    ) -> list[Repo]:
        """The in-scope repositories ``patterns`` drop, less those in ``less``."""
        skip = {r.name for r in less}
        return _sorted(
            r
            for r in self._repos
            if r.name not in self._opted_in
            and r.name not in skip
            and matches(r.name, patterns)
        )

    def dropped(self, key: CategoryKey) -> frozenset[str]:
        """The names category ``key`` leaves out, recording what differs.

        A repository matching both classes is a test exclusion: the more
        specific classification wins, so it is counted once.
        """
        tests = self._matching(self._cfg.exclude_tests_for(key))
        general = self._matching(self._cfg.exclude_for(key), less=tests)
        if _names(tests) != _names(self.excluded_tests_default):
            self.category_excluded_tests[key] = tests
        own = _sorted((*self._excluded_repos, *general))
        if _names(own) != _names(self.excluded_default):
            self.category_excluded[key] = own
        return frozenset(r.name for r in (*tests, *general))

    def narrow(
        self, key: CategoryKey, items: Sequence[_T], repo_of: Callable[[_T], Repo]
    ) -> list[_T]:
        """``items`` less those whose repository category ``key`` leaves out."""
        dropped = self.dropped(key)
        return [item for item in items if repo_of(item).name not in dropped]

    def repos(self, key: CategoryKey) -> list[Repo]:
        """The in-scope repositories category ``key`` covers."""
        return self.narrow(key, self._repos, lambda r: r)


def _sorted(repos) -> list[Repo]:
    return sorted(repos, key=lambda r: r.name)


def _names(repos: Collection[Repo]) -> frozenset[str]:
    return frozenset(r.full_name for r in repos)
