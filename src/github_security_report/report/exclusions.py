# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""What a category's footer says about the repositories it left out.

Two classes of exclusion reach a footer: the general exclusions (the
organisation's ``exclude`` list plus any ``exclude`` patterns), and the test
repositories (``exclude_tests``), each on a count line of its own. A render
surface receives one :class:`Exclusions` per category, already resolved by
:class:`~github_security_report.report.display.FooterOptions` against the
configured display modes, so every surface states the same thing.

The repositories themselves are carried, not just their names, so the
Markdown and HTML surfaces can link a listed name.
"""

from __future__ import annotations

from dataclasses import dataclass

from github_security_report.models import Repo
from github_security_report.summary import SummaryCount

TESTS_LABEL = "Test repositories excluded"


@dataclass(frozen=True)
class Exclusions:
    """The excluded repositories a footer shows, per class.

    An empty class is a hidden line. ``excluded_names`` and ``tests_names``
    say whether that class lists its repositories beneath the count or
    counts them alone.
    """

    excluded: tuple[Repo, ...] = ()
    tests: tuple[Repo, ...] = ()
    excluded_names: bool = True
    tests_names: bool = False

    @property
    def repos(self) -> tuple[Repo, ...]:
        """Every repository either class may name, for linking."""
        return (*self.tests, *self.excluded)

    def counts(self) -> list[SummaryCount]:
        """The two footer buckets, test repositories first."""
        return [
            SummaryCount(
                "tests",
                len(self.tests),
                TESTS_LABEL,
                tuple(r.name for r in self.tests) if self.tests_names else (),
            ),
            SummaryCount(
                "excluded",
                len(self.excluded),
                "Excluded",
                tuple(r.name for r in self.excluded) if self.excluded_names else (),
            ),
        ]


NO_EXCLUSIONS = Exclusions()
