# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Per-repository and per-workflow statistics over one window of run records.

Pure functions over :class:`~.models.WorkflowRunRecord` sequences: the store
hands over everything it holds for an organisation, and the report asks, for
each configured window, which workflows failed, how often, on which trigger and
in which jobs. The one interpretive step is the *reading*: a workflow whose
merge and tag runs fail while every pull-request run passes (or that never ran
on a pull request) is the shape the Workflow Failures table exists to surface,
since it points at a post-merge-only dependency -- credentials, a publish step,
a protected environment -- rather than at the code under review.
"""

from __future__ import annotations

import datetime as dt
import fnmatch
import operator
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

from github_security_report.workflow_runs.models import (
    Outcome,
    Trigger,
    WorkflowRunRecord,
)

PATTERN_INSUFFICIENT = "insufficient"
PATTERN_PERSISTENT = "persistent"
PATTERN_INTERMITTENT = "intermittent"
READING_POST_MERGE_ONLY = "post-merge only"  # fails on merge/tag; every pr run passed
READING_NO_PR_RUNS = "no PR runs"  # fails on merge/tag; never ran on a pr
READING_EVERYWHERE = "everywhere"  # fails on pr too (or on pr only)
READING_OTHER = "other"  # fails only on schedule/manual/branch/other
DEFAULT_MIN_RUNS = 3
DEFAULT_PERSISTENT_THRESHOLD = 0.9

# Failures on these triggers are what the reading calls "post-merge".
_POST_MERGE_TRIGGERS = frozenset({Trigger.MERGE, Trigger.TAG})
# Nesting depth each bracket adds when a job name is walked back from its end.
_DEPTH = {")": 1, "(": -1}
# Chronological order, with the run id settling equal timestamps.
_ORDER = operator.attrgetter("created_at", "id")


@dataclass(frozen=True)
class WindowOptions:
    """How one window is cut and classified.

    ``days`` anchors the window at ``generated_at - days``; ``min_runs`` and
    ``persistent_threshold`` feed :func:`pattern`; ``collapse_matrix`` folds
    matrix legs (``Build (ubuntu-22.04)``) into one job. GitHub-managed
    workflows are left out unless asked for, since their failures are not
    fixable in a workflow file. ``exclude_workflows`` are
    :func:`fnmatch.fnmatchcase` globs on the workflow path.
    """

    days: int
    min_runs: int = DEFAULT_MIN_RUNS
    persistent_threshold: float = DEFAULT_PERSISTENT_THRESHOLD
    collapse_matrix: bool = True
    include_dynamic: bool = False
    exclude_workflows: tuple[str, ...] = ()


@dataclass(frozen=True)
class JobFailures:
    """How often one (normalised) job failed across a workflow's failed runs.

    ``count`` is the number of failing check runs carrying the name, so a run
    whose three matrix legs all fail contributes three once collapsed.
    ``last_url`` is the check run's own details URL from the newest failed run
    that carried the job: the log itself, one click nearer than the run page.
    """

    name: str
    count: int
    last_url: str


def _rate(failed: int, passed: int) -> float:
    """``failed`` over the runs that passed or failed; 0.0 when there were none.

    Skips stay out of the denominator: a cancelled or skipped run says nothing
    about whether the workflow works, and would only dilute the rate.
    """
    concluded = failed + passed
    return failed / concluded if concluded else 0.0


@dataclass(frozen=True)
class WorkflowWindowStats:
    """One workflow's record over the window, listed only if it failed at all.

    ``runs`` counts concluded runs (pass, fail and skip). ``workflow_name`` and
    ``workflow_path`` are the newest seen, so a renamed workflow appears under
    its current name. ``jobs_unreadable`` says how many failures the drill-down
    could not read, and ``jobs_truncated`` how many had more failing jobs than
    it carried, so the table can mark ``failing_jobs`` as partial. The
    trigger mappings are read-only and hold only non-zero entries. The two
    thresholds are carried so :attr:`pattern` needs no options re-supplied.
    """

    repo: str
    workflow_id: int
    workflow_name: str
    workflow_path: str
    runs: int
    failed: int
    passed: int
    skipped: int
    retried: int
    runs_by_trigger: Mapping[Trigger, int]
    failures_by_trigger: Mapping[Trigger, int]
    failing_jobs: tuple[JobFailures, ...]
    jobs_unreadable: int
    last_failure: WorkflowRunRecord | None
    min_runs: int = DEFAULT_MIN_RUNS
    jobs_truncated: int = 0
    persistent_threshold: float = DEFAULT_PERSISTENT_THRESHOLD

    @property
    def fail_rate(self) -> float:
        """Failures over pass-or-fail runs (skips excluded; see :func:`_rate`)."""
        return _rate(self.failed, self.passed)

    @property
    def pattern(self) -> str:
        """Persistent, intermittent or insufficient, per :func:`pattern`."""
        return pattern(
            self.failed,
            self.passed,
            min_runs=self.min_runs,
            persistent_threshold=self.persistent_threshold,
        )

    @property
    def reading(self) -> str:
        """Where the failures sit relative to the pull-request runs.

        A single pull-request failure makes it ``everywhere``: the code under
        review can break this workflow, whatever happened on merge. Otherwise
        merge or tag failures are the signal, and the two post-merge readings
        differ only in whether there was a pull-request run to compare against.
        """
        pr_runs = self.runs_by_trigger.get(Trigger.PULL_REQUEST, 0)
        if self.failures_by_trigger.get(Trigger.PULL_REQUEST, 0):
            return READING_EVERYWHERE
        if not any(self.failures_by_trigger.get(t, 0) for t in _POST_MERGE_TRIGGERS):
            return READING_OTHER
        return READING_NO_PR_RUNS if pr_runs == 0 else READING_POST_MERGE_ONLY


@dataclass(frozen=True)
class RepoWindowStats:
    """One repository's record over the window, failures or not.

    Every repository with a concluded run gets an entry, so the caller decides
    whether a clean one is worth a row. ``workflows`` counts distinct workflows
    that failed at least once; ``worst`` is the one of those with the most
    failures (ties: higher fail rate, then name), or ``None`` if nothing failed.
    """

    repo: str
    runs: int
    failed: int
    passed: int
    skipped: int
    retried: int
    workflows: int
    failures_by_trigger: Mapping[Trigger, int]
    last_failure: WorkflowRunRecord | None
    worst: WorkflowWindowStats | None

    @property
    def fail_rate(self) -> float:
        """Failures over pass-or-fail runs (skips excluded; see :func:`_rate`)."""
        return _rate(self.failed, self.passed)


def pattern(
    failed: int, passed: int, *, min_runs: int, persistent_threshold: float
) -> str:
    """Classify a failure count as persistent, intermittent or insufficient.

    Judged on the runs that reached a verdict, as the rate is. Below
    ``min_runs`` of those the sample is too small to call either way; with
    none at all it is insufficient whatever ``min_runs`` says.
    """
    concluded = failed + passed
    if concluded == 0 or concluded < min_runs:
        return PATTERN_INSUFFICIENT
    if failed / concluded >= persistent_threshold:
        return PATTERN_PERSISTENT
    return PATTERN_INTERMITTENT


def normalise_job_name(name: str, *, collapse_matrix: bool) -> str:
    """The job name the failing-jobs table groups by.

    With ``collapse_matrix`` the one trailing parenthesised group goes, folding
    ``Build (ubuntu-22.04)`` and ``Build (ubuntu-24.04)`` into ``Build``, which
    is how GitHub names matrix legs. Only a group at the very end counts, so
    ``Test (x) / Audit`` keeps its leg; the group may be nested (``Job ((a))``
    is ``Job``). A name that is nothing but a group, or whose brackets do not
    balance, is left alone rather than reduced to nothing.
    """
    name = name.strip()
    if not collapse_matrix or not name.endswith(")"):
        return name
    depth = 0
    for index in range(len(name) - 1, -1, -1):
        depth += _DEPTH.get(name[index], 0)
        if depth == 0:
            return name[:index].rstrip() or name
    return name


def in_window(
    record: WorkflowRunRecord, *, generated_at: dt.datetime, days: int
) -> bool:
    """Whether a run was created within the last ``days`` before ``generated_at``.

    Both ends are inclusive; a run created after ``generated_at`` is out,
    since it would sit in a window the report says had closed.
    """
    return generated_at - dt.timedelta(days=days) <= record.created_at <= generated_at


def window_records(
    records: Iterable[WorkflowRunRecord],
    *,
    generated_at: dt.datetime,
    options: WindowOptions,
) -> list[WorkflowRunRecord]:
    """The records one window counts, in their original order: in the window,
    concluded, GitHub-managed only if ``include_dynamic``, and not excluded.
    """
    return [
        record
        for record in records
        if in_window(record, generated_at=generated_at, days=options.days)
        and record.outcome is not Outcome.PENDING
        and (options.include_dynamic or not record.is_dynamic)
        and not any(
            fnmatch.fnmatchcase(record.workflow_path, glob)
            for glob in options.exclude_workflows
        )
    ]


def _by_trigger(counts: Counter[Trigger]) -> Mapping[Trigger, int]:
    """A read-only mapping of the non-zero counts, in :class:`Trigger` order."""
    return MappingProxyType(
        {trigger: counts[trigger] for trigger in Trigger if counts[trigger]}
    )


@dataclass
class _Tally:
    """Running counts shared by the workflow and repository statistics."""

    outcomes: Counter[Outcome] = field(default_factory=Counter)
    retried: int = 0
    runs_by_trigger: Counter[Trigger] = field(default_factory=Counter)
    failures_by_trigger: Counter[Trigger] = field(default_factory=Counter)
    last_failure: WorkflowRunRecord | None = None

    def add(self, record: WorkflowRunRecord) -> None:
        """Count one record; fed oldest first, so the newest failure sticks."""
        self.outcomes[record.outcome] += 1
        self.retried += int(record.retried)
        self.runs_by_trigger[record.trigger] += 1
        if record.outcome is Outcome.FAIL:
            self.failures_by_trigger[record.trigger] += 1
            self.last_failure = record


def _workflow(
    runs: list[WorkflowRunRecord], options: WindowOptions
) -> WorkflowWindowStats:
    """Statistics for one workflow from its window records, oldest first."""
    tally = _Tally()
    counts: Counter[str] = Counter()
    last_url: dict[str, str] = {}
    unreadable = 0
    truncated = 0
    for record in runs:
        tally.add(record)
        if record.outcome is not Outcome.FAIL:
            continue
        if record.failed_jobs is None:
            unreadable += 1
            continue
        truncated += record.jobs_truncated
        for job in record.failed_jobs:
            name = normalise_job_name(job.name, collapse_matrix=options.collapse_matrix)
            counts[name] += 1
            last_url[name] = job.url
    jobs = sorted(
        (JobFailures(name, count, last_url[name]) for name, count in counts.items()),
        key=lambda job: (-job.count, job.name),
    )
    newest = runs[-1]
    return WorkflowWindowStats(
        repo=newest.repo,
        workflow_id=newest.workflow_id,
        workflow_name=newest.workflow_name,
        workflow_path=newest.workflow_path,
        runs=sum(tally.outcomes.values()),
        failed=tally.outcomes[Outcome.FAIL],
        passed=tally.outcomes[Outcome.PASS],
        skipped=tally.outcomes[Outcome.SKIP],
        retried=tally.retried,
        runs_by_trigger=_by_trigger(tally.runs_by_trigger),
        failures_by_trigger=_by_trigger(tally.failures_by_trigger),
        failing_jobs=tuple(jobs),
        jobs_unreadable=unreadable,
        last_failure=tally.last_failure,
        min_runs=options.min_runs,
        persistent_threshold=options.persistent_threshold,
        jobs_truncated=truncated,
    )


def _failing_workflows(
    admitted: list[WorkflowRunRecord], options: WindowOptions
) -> list[WorkflowWindowStats]:
    """Sorted statistics for every workflow among ``admitted`` that failed."""
    groups: defaultdict[tuple[str, int], list[WorkflowRunRecord]] = defaultdict(list)
    for record in sorted(admitted, key=_ORDER):
        groups[(record.repo, record.workflow_id)].append(record)
    stats = [
        _workflow(runs, options)
        for runs in groups.values()
        if any(record.outcome is Outcome.FAIL for record in runs)
    ]
    stats.sort(key=lambda s: (-s.failed, -s.fail_rate, s.repo, s.workflow_name))
    return stats


def workflow_stats(
    records: Iterable[WorkflowRunRecord],
    *,
    generated_at: dt.datetime,
    options: WindowOptions,
) -> list[WorkflowWindowStats]:
    """One entry per (repo, workflow) with at least one failure in the window.

    A workflow that never failed is not listed -- the table is about failures
    -- though its runs still count towards :func:`repo_stats`. Sorted by
    failures descending, then fail rate descending, then repository and name.
    """
    admitted = window_records(records, generated_at=generated_at, options=options)
    return _failing_workflows(admitted, options)


def _repo(
    repo: str, runs: list[WorkflowRunRecord], worst: WorkflowWindowStats | None
) -> RepoWindowStats:
    """Statistics for one repository from its window records, oldest first."""
    tally = _Tally()
    for record in runs:
        tally.add(record)
    return RepoWindowStats(
        repo=repo,
        runs=sum(tally.outcomes.values()),
        failed=tally.outcomes[Outcome.FAIL],
        passed=tally.outcomes[Outcome.PASS],
        skipped=tally.outcomes[Outcome.SKIP],
        retried=tally.retried,
        workflows=len({r.workflow_id for r in runs if r.outcome is Outcome.FAIL}),
        failures_by_trigger=_by_trigger(tally.failures_by_trigger),
        last_failure=tally.last_failure,
        worst=worst,
    )


def repo_stats(
    records: Iterable[WorkflowRunRecord],
    *,
    generated_at: dt.datetime,
    options: WindowOptions,
) -> list[RepoWindowStats]:
    """One entry per repository with a concluded run in the window.

    Repositories with no failures are included, so the caller decides whether
    a clean repository is worth a row. Sorted by failures descending, then
    fail rate descending, then repository.
    """
    admitted = window_records(records, generated_at=generated_at, options=options)
    # The workflow list is already worst-first, so the first entry seen for a
    # repository is its worst.
    worst: dict[str, WorkflowWindowStats] = {}
    for stats in _failing_workflows(admitted, options):
        worst.setdefault(stats.repo, stats)
    groups: defaultdict[str, list[WorkflowRunRecord]] = defaultdict(list)
    for record in sorted(admitted, key=_ORDER):
        groups[record.repo].append(record)
    out = [_repo(repo, runs, worst.get(repo)) for repo, runs in groups.items()]
    out.sort(key=lambda s: (-s.failed, -s.fail_rate, s.repo))
    return out
