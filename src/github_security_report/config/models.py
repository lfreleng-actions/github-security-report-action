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
from github_security_report.config.order import OrderConfig
from github_security_report.severity import Severity
from github_security_report.summary import ExcludedDisplay, RepoList


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
    ordering the table's builder chose. ``repo_list`` overrides which side of a
    boolean feature category is named (see :class:`RepoList`); ``None`` falls
    back to the report-wide ``repo_list``.
    """

    enabled: bool = True
    outputs: OutputToggles = field(default_factory=OutputToggles)
    fail_severity: Severity | None = None
    top_n: int | None = None
    sort: tuple[str, ...] | None = None
    repo_list: RepoList | None = None

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

# Surfaces for a table too wide and too long for a chat digest: the per-workflow
# detail of the Workflow Failures category runs to several rows per repository
# and a dozen columns, so it stays off Slack even once enabled, while the
# per-repository ranking carries the headline there.
_NO_SLACK = OutputToggles(cli=True, slack=False, markdown=True, html=True)

# Categories whose default visibility is narrower than "every surface". Merged
# under any configured block key-by-key, so an operator who sets, say, a `top_n`
# for one of these keeps the restricted surfaces rather than silently
# publishing it everywhere.
#
# The Workflow Failures detail table is collected but rendered nowhere by
# default (and so, like any category no published surface shows, left out of
# report.json): its shape (which jobs to list, how wide a row may run) is still
# being settled against real data, and the per-repository ranking carries the
# actionable headline meanwhile. Setting
# `categories.workflow_failures_detail.enabled: true` switches it on.
DEFAULT_CATEGORIES: Mapping[str, CategoryToggle] = MappingProxyType(
    {
        CategoryKey.PULL_REQUESTS_ASSIGNED.value: CategoryToggle(
            outputs=_TERMINAL_ONLY
        ),
        CategoryKey.WORKFLOW_FAILURES_DETAIL.value: CategoryToggle(
            enabled=False, outputs=_NO_SLACK
        ),
    }
)


# Default time windows, in days, for the Workflow Failures tables per surface.
# The terminal and Slack get the week; the published report adds the month
# and the quarter, where a reader has room to compare them.
DEFAULT_RUN_WINDOWS: Mapping[str, tuple[int, ...]] = MappingProxyType(
    {"cli": (7,), "report": (7, 30, 90), "slack": (7,)}
)


@dataclass(frozen=True)
class WorkflowRunsConfig:
    """How the Workflow Failures tables are collected and judged.

    ``windows`` maps each surface (``cli``, ``report``, ``slack``) to the
    windows it shows, in days. ``retention_days`` is how long the run store
    keeps records and ``backfill_days`` how deep a never-seen repository is
    read; both default to the longest configured window, which is the most
    any table can use. ``cache`` off keeps the store in memory for the run,
    so every report re-reads the windows from GitHub; ``cache_dir`` overrides
    the XDG cache location.
    """

    windows: Mapping[str, tuple[int, ...]] = field(
        default_factory=lambda: DEFAULT_RUN_WINDOWS
    )
    retention_days: int | None = None
    backfill_days: int | None = None
    # GitHub-managed workflows (Dependabot updates, default-setup CodeQL,
    # Copilot review) have no file in the repository to fix, so they are
    # left out of the tables unless asked for.
    include_dynamic: bool = False
    # Globs matched against the workflow path, for workflows whose failures
    # are expected (an experiment, a deliberately failing canary).
    exclude_workflows: tuple[str, ...] = ()
    # Fold "Build (ubuntu-22.04)" and "Build (ubuntu-24.04)" into one job.
    collapse_matrix: bool = True
    # A workflow failing at or above this rate is persistent; below it,
    # intermittent. Fewer than ``min_runs`` concluded runs is too few to say.
    persistent_threshold: float = 0.9
    min_runs: int = 3
    cache: bool = True
    cache_dir: str | None = None

    def windows_for(self, output: str) -> tuple[int, ...]:
        """The windows ``output`` (``cli``/``report``/``slack``) shows."""
        return self.windows.get(output, ())

    @property
    def all_windows(self) -> tuple[int, ...]:
        """Every configured window once, longest first."""
        return tuple(
            sorted({d for days in self.windows.values() for d in days}, reverse=True)
        )

    @property
    def longest_window(self) -> int:
        """The longest window any surface shows; what the store must hold."""
        return max(self.all_windows, default=7)

    @property
    def retention(self) -> int:
        """Days the store keeps, never shorter than the longest window."""
        return max(self.retention_days or 0, self.longest_window)

    @property
    def backfill(self) -> int:
        """Days a never-seen repository is read back, bounded by retention."""
        return min(self.backfill_days or self.retention, self.retention)


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
    # A CodeQL configuration is reported stale once its last scan trails the
    # default branch's newest commit by more than this many days. GitHub does
    # not publish the threshold behind its own "results may be out of date"
    # warning; healthy configurations measured within five days of their head
    # and abandoned ones beyond eighty, so thirty sits well clear of both.
    codeql_stale_days: int = 30
    # Open-automation thresholds colouring the Pull Requests table's Auto
    # column. The defaults track GitHub's own behaviour: Dependabot's
    # ``open-pull-requests-limit`` defaults to 5, so 5 is where updates stop
    # arriving and 3-4 is the approach to it. An organisation that raises that
    # limit should raise these to match -- they describe your policy, and the
    # defaults are only the most useful guess in the absence of one.
    #
    # One deliberate imprecision, since the column is a proxy rather than a
    # measurement: GitHub applies its limit per package ecosystem, while Auto
    # counts every automation author across all of them. A repository can
    # therefore be stalled in one ecosystem below the threshold, or sit above
    # it on Renovate pull requests alone. The count is still the right thing to
    # watch -- a large automation backlog is worth attention however it
    # accumulated -- but the colour is a prompt to look, not a verdict.
    # Warn (yellow) above this many: 3 or 4 open, approaching the default limit.
    dependabot_warn_threshold: int = 2
    # Error (red) at or above this many: GitHub's default open-pull-requests
    # limit, at which no further updates arrive for that ecosystem.
    dependabot_error_threshold: int = 5
    # Age thresholds, in days, colouring the GitHub Issues table's Oldest
    # column: green at or below the warn threshold, yellow once the oldest open
    # issue is older than it, red once it is older than the error threshold.
    # 0 switches that level off.
    issue_age_warn_days: int = 30
    issue_age_error_days: int = 60
    # Organisation feature gating for the workflow-driven signals (Scorecard,
    # zizmor, aislop): when true, each is collected only after a cheap check
    # finds organisation support (an org ruleset requiring the workflow,
    # existing code-scanning alerts, or analyses on a sample of repositories);
    # otherwise the signal's section reports a single "Skipping feature" line.
    # False disables the check and always probes every signal.
    gating: bool = True
    # Repositories per batched GraphQL prefetch query (the releases/tags,
    # Dependabot-enablement, open-issues and pull-request data). GitHub caps
    # the work one GraphQL query may do at roughly ten seconds of execution
    # and reports a breach as a 502/504 gateway timeout, a 200 with no data,
    # or a 200 whose errors say the resource limits were exceeded (see
    # client/batch_errors.py). Each aliased repository adds a few hundred
    # milliseconds, so the ceiling is a matter of latency, not node cost: 25
    # repositories measured at ~9 s and failed intermittently; 10 measured at
    # ~3.5 s, leaving headroom for GitHub having a slow day. The collector
    # halves a batch that fails any of those ways, so this is a starting point
    # rather than a hard limit -- but a larger value buys nothing except a
    # longer first failure.
    graph_batch: int = 10
    # Concurrent GitHub API requests per organisation's client. 9 is a
    # deliberate halfway point: 12 measured safe against lfreleng-actions,
    # but the project has hit GitHub's secondary rate limits before, so it
    # can be raised from configuration or repository settings without a
    # release. The schema caps it at CONCURRENCY_MAX. Kept equal to
    # client.endpoints.API_DEFAULT_CONCURRENCY.
    concurrency: int = 9
    # Which side of each boolean feature category (Dependabot alerts/updates
    # enabled, private vulnerability reporting, auto-merge) is named beneath its
    # counts, on every surface. ``auto`` names the shorter list; a category's
    # own ``repo_list`` overrides this.
    repo_list: RepoList = RepoList.AUTO
    # When each category's footer shows the organisation's excluded
    # repositories: always (the default), never, or only for a category whose
    # exclusions differ from the organisation's own list.
    excluded_display: ExcludedDisplay = ExcludedDisplay.ALWAYS_SHOW
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
    # Where each category sits in the rendered output. Defaults to the automatic
    # three-band layout; see :mod:`github_security_report.layout`.
    order: OrderConfig = field(default_factory=OrderConfig)
    # How the Workflow Failures tables are collected and judged.
    workflow_runs: WorkflowRunsConfig = field(default_factory=WorkflowRunsConfig)

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

    def repo_list_for(self, key: CategoryKey) -> RepoList:
        """Which side of category ``key`` to name: its own setting, else ours."""
        toggle = self.categories.get(key.value)
        if toggle is not None and toggle.repo_list is not None:
            return toggle.repo_list
        return self.repo_list


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
