# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Typed configuration objects and their defaults.

Frozen dataclasses describing the whole configuration tree, plus the built-in
defaults they fall back to. Construction from raw JSON lives in
:mod:`github_security_report.config.loader`.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

from github_security_report.categories import CategoryKey
from github_security_report.severity import Severity


@dataclass(frozen=True)
class ReportDay:
    """When to post the Slack digest. Owned and evaluated by the tool."""

    always: bool = False
    never: bool = False
    days: frozenset[str] = field(default_factory=frozenset)

    def should_notify(self, *, now: dt.date | None = None, force: bool = False) -> bool:
        if force or self.always:
            return True
        if self.never:
            return False
        today = (now or dt.date.today()).strftime("%A").lower()
        return today in self.days


@dataclass(frozen=True)
class SlackConfig:
    channel: str = ""
    report_day: ReportDay = field(
        default_factory=lambda: ReportDay(days=frozenset({"tuesday"}))
    )


# Default mapping of signal value -> required-workflow path keyword. A repo
# covered by an active org ruleset whose required workflow path contains the
# keyword is treated as having that tool enabled (see :mod:`rulesets`).
DEFAULT_RULESET_WORKFLOWS = {"zizmor": "zizmor", "aislop": "aislop"}

# Default column -> issue-label mapping for the GitHub Issues table. Each key
# becomes a column, in this order; an open issue counts towards the first column
# whose labels it carries (matched case-insensitively against the whole label
# name). Issues matching no column count as Other, and issues with no labels at
# all count as Untriaged -- both columns are implicit and always present.
DEFAULT_ISSUE_LABELS: Mapping[str, tuple[str, ...]] = MappingProxyType(
    {
        "Bug": ("bug", "defect"),
        "Feature": ("feature", "enhancement"),
        "Docs": ("documentation", "docs"),
    }
)


@dataclass(frozen=True)
class OutputToggles:
    """Per-output render switches for a single category (all default on).

    Lower precedence than :attr:`CategoryToggle.enabled`: an output toggle only
    matters when the category is globally enabled.
    """

    cli: bool = True
    slack: bool = True
    markdown: bool = True
    html: bool = True


@dataclass(frozen=True)
class CategoryToggle:
    """Render switches and pass/fail tuning for one reporting category.

    ``enabled`` is the highest-precedence switch: when false the category is
    hidden on every surface. ``outputs`` is the lower-precedence per-surface
    map, consulted only when the category is enabled. The data is always
    collected regardless of these toggles; they govern presentation alone.
    ``fail_severity`` overrides the category's default failure cutoff (severity
    signals only); ``None`` keeps the category default. ``top_n`` overrides how
    many rows this one category shows before an "and N more" tally, so a
    high-volume category can be uncapped (``0``) while the rest stay limited;
    ``None`` falls back to the per-output limit. ``sort`` overrides the row
    ordering of a generic table with a list of column names; ``None`` keeps the
    ordering the table's builder chose.
    """

    enabled: bool = True
    outputs: OutputToggles = field(default_factory=OutputToggles)
    fail_severity: Severity | None = None
    top_n: int | None = None
    sort: tuple[str, ...] | None = None

    def shows_on(self, output: str) -> bool:
        """Whether this category renders on ``output`` (cli/slack/markdown/html)."""
        return self.enabled and getattr(self.outputs, output)


# Surfaces a personal, reader-specific category belongs on. "Assigned to Me"
# is one account's review queue -- whichever account the run authenticated as --
# so it belongs on that reader's own terminal and nowhere that is published. A
# Pages site, a Markdown artifact and a Slack digest are all read by the whole
# organisation, where one person's inbox is at best noise and at worst a
# statement about an individual's workload.
_TERMINAL_ONLY = OutputToggles(cli=True, slack=False, markdown=False, html=False)

# Categories whose default visibility is narrower than "every surface". Merged
# under any configured block key-by-key, so an operator who sets, say, a `top_n`
# for one of these keeps the restricted surfaces rather than silently
# publishing it everywhere.
DEFAULT_CATEGORIES: Mapping[str, CategoryToggle] = MappingProxyType(
    {
        CategoryKey.PULL_REQUESTS_ASSIGNED.value: CategoryToggle(
            outputs=_TERMINAL_ONLY
        ),
    }
)


@dataclass(frozen=True)
class ReportConfig:
    # Shared default number of offenders shown per signal; per-output overrides
    # below take precedence when set. report = GitHub Pages (Markdown + HTML),
    # cli = terminal, slack = the Slack digest. A value of 0 disables the limit
    # for that output (every offender is shown).
    top_n: int = 10
    top_n_report: int | None = None
    top_n_cli: int | None = None
    top_n_slack: int | None = None
    include_archived: bool = False
    include_test: bool = False
    # Repositories created within this many days are excluded from the
    # Releases/Tagging requirement, giving brand-new repositories a grace
    # period before a release or tag is expected (0 = include all repositories).
    repo_min_age_days: int = 28
    # A repository is flagged in the Releases/Tagging table only when its most
    # recent release or tag is older than this many days; a repository with
    # neither a release nor a tag is always flagged. 0 disables the threshold,
    # so every eligible repository is listed (ranked by staleness). The default
    # gives every repository a 60-day window: one tagged or released inside that
    # window is treated as recently maintained and omitted from the table.
    release_max_age_days: int = 60
    # Open-automation thresholds for the Pull Requests table's Auto column,
    # which colour a repository's automation backlog on the terminal. Named for
    # Dependabot because the limit that matters is its own: an organisation
    # caps how many pull requests Dependabot may hold open per repository, and
    # once that cap is reached it stops raising them, so the repository silently
    # stops receiving dependency updates. The column counts every automation
    # author, which is the number to watch against that cap.
    # Warn (yellow) above this many; the default leaves headroom below the cap.
    dependabot_warn_threshold: int = 12
    # Error (red) at or above this many: GitHub's own default per-repository
    # limit, and the point at which new Dependabot pull requests stop arriving.
    dependabot_error_threshold: int = 15
    # Organisation feature gating for the workflow-driven signals (Scorecard,
    # zizmor, aislop): when true, each is collected only after a cheap check
    # finds organisation support (an org ruleset requiring the workflow,
    # existing code-scanning alerts, or analyses on a sample of repositories);
    # otherwise the signal's section reports a single "Skipping feature" line.
    # False disables the check and always probes every signal.
    gating: bool = True
    # Read-only mapping (frozen dataclasses do not deep-freeze a plain dict, so a
    # MappingProxyType prevents in-place mutation of a shared config).
    ruleset_workflows: Mapping[str, str] = field(
        default_factory=lambda: MappingProxyType(dict(DEFAULT_RULESET_WORKFLOWS))
    )
    # Column -> issue labels for the GitHub Issues table. Unlike
    # ``ruleset_workflows`` a configured value *replaces* the default rather
    # than merging into it: the mapping defines a coherent set of table columns,
    # so merging would leave behind default columns the operator did not ask
    # for.
    issue_labels: Mapping[str, tuple[str, ...]] = field(
        default_factory=lambda: DEFAULT_ISSUE_LABELS
    )
    # Per-category render toggles, keyed by category-key value. Absent keys fall
    # back to a fully-enabled default; the seeded entries in DEFAULT_CATEGORIES
    # are the categories that are deliberately not shown everywhere.
    categories: Mapping[str, CategoryToggle] = field(
        default_factory=lambda: DEFAULT_CATEGORIES
    )

    def shows_category(self, key: CategoryKey, output: str) -> bool:
        """Whether category ``key`` renders on ``output`` under this config.

        Defaults to visible: an unconfigured category (or one with no override
        for this output) is shown. The global ``enabled`` switch takes
        precedence over the per-output toggle.
        """
        toggle = self.categories.get(key.value)
        return toggle.shows_on(output) if toggle is not None else True

    def fail_severity_for(self, key: CategoryKey) -> Severity | None:
        """The configured fail-severity override for ``key``, or ``None``.

        ``None`` means "use the category's own default cutoff"; the classifier
        resolves that fallback, so the config only carries explicit overrides.
        """
        toggle = self.categories.get(key.value)
        return toggle.fail_severity if toggle is not None else None

    @property
    def report_top_n(self) -> int:
        """Offenders shown per signal in the GitHub Pages output."""
        return self.top_n_report if self.top_n_report is not None else self.top_n

    @property
    def cli_top_n(self) -> int:
        """Offenders shown per signal in the terminal output."""
        return self.top_n_cli if self.top_n_cli is not None else self.top_n

    @property
    def slack_top_n(self) -> int:
        """Offenders shown per signal in the Slack digest."""
        return self.top_n_slack if self.top_n_slack is not None else self.top_n

    def output_top_n(self, output: str) -> int:
        """The configured row limit for one output (``report``/``cli``/``slack``)."""
        return int(getattr(self, f"{output}_top_n"))

    def category_top_n(self, key: CategoryKey, output: str) -> int:
        """The configured row limit for one category on one output.

        A category's own ``top_n`` is the most specific configured value, so it
        wins over the per-output limit; ``0`` means "no limit" here as it does
        everywhere else. An unconfigured category falls back to the per-output
        limit, so the default behaviour is unchanged.
        """
        toggle = self.categories.get(key.value)
        if toggle is not None and toggle.top_n is not None:
            return toggle.top_n
        return self.output_top_n(output)

    def category_sort(self, key: CategoryKey) -> tuple[str, ...] | None:
        """The configured row ordering for ``key``, or ``None`` for the default.

        ``None`` means "keep the ordering the table's builder chose", which is
        not always expressible as a column list: the Releases table ranks on
        missing release/tag signals that it never displays as a column.
        """
        toggle = self.categories.get(key.value)
        return toggle.sort if toggle is not None else None


@dataclass(frozen=True)
class OrgConfig:
    name: str
    token_env: str = "GITHUB_TOKEN"
    exclude: tuple[str, ...] = ()
    # Repositories excluded from the Releases/Tagging table only (e.g. repos
    # that are never released/consumed externally).
    releases_exclude: tuple[str, ...] = ()
    slack: SlackConfig = field(default_factory=SlackConfig)
    report: ReportConfig = field(default_factory=ReportConfig)


@dataclass(frozen=True)
class Config:
    organizations: tuple[OrgConfig, ...]
    slack: SlackConfig = field(default_factory=SlackConfig)
    report: ReportConfig = field(default_factory=ReportConfig)
