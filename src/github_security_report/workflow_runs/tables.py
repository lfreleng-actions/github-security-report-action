# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""The Workflow Failures tables, one pair per configured window.

Turns the per-window statistics of :mod:`.aggregate` into the two
:class:`~github_security_report.report.TableSection` shapes the surfaces draw:
a per-repository ranking (which repositories' workflows fail, how much) and a
per-workflow detail (which workflow, which job, on which trigger, and whether
it fails only after merge). Every surface shows the same tables; which
windows each shows is the surface's choice, not the builder's.
"""

from __future__ import annotations

import datetime as dt
import posixpath
from collections.abc import Iterable, Mapping, Sequence
from urllib.parse import quote

from github_security_report.categories import CategoryKey, category_meta
from github_security_report.models import Repo
from github_security_report.report import (
    CELL_BAD,
    CELL_WARN,
    TableRow,
    TableSection,
)
from github_security_report.workflow_runs.aggregate import (
    PATTERN_INTERMITTENT,
    PATTERN_PERSISTENT,
    READING_NO_PR_RUNS,
    READING_POST_MERGE_ONLY,
    RepoWindowStats,
    WindowOptions,
    WorkflowWindowStats,
    repo_stats,
    workflow_stats,
)
from github_security_report.workflow_runs.models import Trigger, WorkflowRunRecord

REPO_COLUMNS = (
    "Repository",
    "Failed",
    "Runs",
    "Fail %",
    "Skipped",
    "Retried",
    "Workflows",
    "Worst workflow",
)
DETAIL_COLUMNS = (
    "Repository",
    "Workflow",
    "File",
    "Failing job",
    "Failed",
    "Runs",
    "Fail %",
    "Pattern",
    "Triggers",
    "Reading",
    "Last failure",
)

# Short trigger labels for the detail table's Triggers cell.
_TRIGGER_LABELS = {
    Trigger.PULL_REQUEST: "PR",
    Trigger.MERGE: "Merge",
    Trigger.TAG: "Tag",
    Trigger.BRANCH: "Branch",
    Trigger.SCHEDULE: "Sched",
    Trigger.MANUAL: "Manual",
    Trigger.DYNAMIC: "Dynamic",
    Trigger.OTHER: "Other",
}

_PATTERN_LEVELS = {PATTERN_PERSISTENT: CELL_BAD, PATTERN_INTERMITTENT: CELL_WARN}
# The readings that single a workflow out as failing where a pull request
# could not have caught it: the case the category exists to isolate.
_POST_MERGE_READINGS = frozenset({READING_POST_MERGE_ONLY, READING_NO_PR_RUNS})


def _percent(rate: float) -> str:
    return f"{round(rate * 100)}%"


def _rate_level(rate: float, threshold: float) -> str | None:
    if rate >= threshold:
        return CELL_BAD
    return CELL_WARN if rate > 0 else None


def _triggers(counts: Mapping[Trigger, int]) -> str:
    return " ".join(f"{_TRIGGER_LABELS[t]}:{n}" for t, n in counts.items()) or "-"


def _jobs_cell(stats: WorkflowWindowStats) -> str:
    """The failing jobs with their counts, or why none are named.

    A run whose failing jobs outnumbered the drill-down's window contributes
    the first of them; the cell says so rather than present them as all.
    """
    named = [f"{job.name} ({job.count})" for job in stats.failing_jobs]
    if stats.jobs_unreadable and not named:
        return "jobs unreadable"
    if stats.jobs_unreadable:
        named.append(f"{stats.jobs_unreadable} unread")
    if stats.jobs_truncated:
        named.append(f"more in {stats.jobs_truncated} run(s)")
    return ", ".join(named) or "-"


def _workflow_url(repo: Repo, path: str) -> str | None:
    """The workflow's run history page; none for a GitHub-managed workflow.

    The file name is one path segment, encoded as such: a name holding ``#``
    or ``?`` would otherwise read as a fragment or a query.
    """
    if not path.startswith(".github/workflows/"):
        return None
    name = quote(posixpath.basename(path), safe="")
    return f"{repo.html_url}/actions/workflows/{name}"


def _digest(repo: Repo, stats: RepoWindowStats) -> str:
    """One line for the brevity-first surface: the headline and the worst."""
    rate = _percent(stats.fail_rate)
    line = f"{repo.name} — {stats.failed}/{stats.runs} failed ({rate})"
    worst = stats.worst
    if worst is not None:
        line += (
            f" · worst: {worst.workflow_name} "
            f"({worst.failed}/{worst.runs}, {worst.pattern})"
        )
    return line


def _repo_row(repo: Repo, stats: RepoWindowStats, threshold: float) -> TableRow:
    worst = stats.worst
    worst_text = (
        f"{worst.workflow_name} ({worst.failed}/{worst.runs})" if worst else "-"
    )
    return TableRow(
        repo=repo,
        cells=(
            str(stats.failed),
            str(stats.runs),
            _percent(stats.fail_rate),
            str(stats.skipped),
            str(stats.retried),
            str(stats.workflows),
            worst_text,
        ),
        sort_values=(
            stats.failed,
            stats.runs,
            stats.fail_rate,
            stats.skipped,
            stats.retried,
            stats.workflows,
            worst.workflow_name if worst else None,
        ),
        cell_levels=(
            None,
            None,
            _rate_level(stats.fail_rate, threshold),
            None,
            None,
            None,
            None,
        ),
        cell_urls=(None,) * 6
        + (_workflow_url(repo, worst.workflow_path) if worst else None,),
        digest=_digest(repo, stats),
    )


def _detail_row(repo: Repo, stats: WorkflowWindowStats) -> TableRow:
    last = stats.last_failure
    top_job = stats.failing_jobs[0] if stats.failing_jobs else None
    reading = stats.reading
    return TableRow(
        repo=repo,
        cells=(
            stats.workflow_name or stats.workflow_path,
            posixpath.basename(stats.workflow_path) or "-",
            _jobs_cell(stats),
            str(stats.failed),
            str(stats.runs),
            _percent(stats.fail_rate),
            stats.pattern,
            _triggers(stats.failures_by_trigger),
            reading,
            last.created_at.date().isoformat() if last else "-",
        ),
        sort_values=(
            stats.workflow_name,
            stats.workflow_path,
            top_job.name if top_job else None,
            stats.failed,
            stats.runs,
            stats.fail_rate,
            stats.pattern,
            sum(stats.failures_by_trigger.values()),
            reading,
            last.created_at.timestamp() if last else None,
        ),
        cell_levels=(
            None,
            None,
            None,
            None,
            None,
            None,
            _PATTERN_LEVELS.get(stats.pattern),
            None,
            CELL_WARN if reading in _POST_MERGE_READINGS else None,
            None,
        ),
        cell_urls=(
            _workflow_url(repo, stats.workflow_path),
            None,
            top_job.last_url if top_job else None,
            None,
            None,
            None,
            None,
            None,
            None,
            last.html_url if last else None,
        ),
    )


def _notes(
    days: int,
    repo_count: int,
    runs: int,
    truncated: int,
) -> tuple[str, ...]:
    """Footer lines that qualify the window's counts."""
    notes = [f"{runs:,} runs across {repo_count} repositories in {days} days"]
    if truncated:
        notes.append(
            f"{truncated} repositories hold less than {days} days of run history"
        )
    return tuple(notes)


def build_workflow_failure_tables(
    records: Iterable[WorkflowRunRecord],
    in_scope: Sequence[Repo],
    *,
    generated_at: dt.datetime,
    windows: Sequence[int],
    options: WindowOptions,
    unknown: frozenset[str] = frozenset(),
    oldest: Mapping[str, dt.datetime | None] | None = None,
) -> tuple[tuple[TableSection, ...], tuple[TableSection, ...]]:
    """Both tables for every window, shortest window first.

    ``options.days`` is replaced per window; the judgement settings carry.
    ``unknown`` names the repositories whose runs could not be read, counted
    as unreadable rather than as failure-free on every window; ``oldest``
    says how far back each repository's stored history reaches, so a window
    reaching further is noted as truncated in the footer.
    """
    by_name = {repo.name: repo for repo in in_scope}
    held = list(records)
    reach = oldest or {}
    repo_tables: list[TableSection] = []
    detail_tables: list[TableSection] = []
    for days in sorted(windows):
        window = WindowOptions(
            days=days,
            min_runs=options.min_runs,
            persistent_threshold=options.persistent_threshold,
            collapse_matrix=options.collapse_matrix,
            include_dynamic=options.include_dynamic,
            exclude_workflows=options.exclude_workflows,
        )
        start = generated_at - dt.timedelta(days=days)
        per_repo = [
            s
            for s in repo_stats(held, generated_at=generated_at, options=window)
            if s.repo in by_name and s.repo not in unknown
        ]
        per_workflow = [
            s
            for s in workflow_stats(held, generated_at=generated_at, options=window)
            if s.repo in by_name and s.repo not in unknown
        ]
        failing = [s for s in per_repo if s.failed]
        readable = [r for r in in_scope if r.name not in unknown]
        truncated = sum(
            1
            for repo in readable
            if (edge := reach.get(repo.name)) is not None and edge > start
        )
        notes = _notes(days, len(readable), sum(s.runs for s in per_repo), truncated)
        unknown_count = sum(1 for repo in in_scope if repo.name in unknown)
        pass_count = len(readable) - len(failing)
        repo_tables.append(
            TableSection(
                category=category_meta(CategoryKey.WORKFLOW_FAILURES),
                columns=REPO_COLUMNS,
                rows=[
                    _repo_row(by_name[s.repo], s, options.persistent_threshold)
                    for s in failing
                ],
                sum_columns=frozenset({1, 2, 4, 5, 6}),
                numeric_columns=frozenset({1, 2, 3, 4, 5, 6}),
                pass_count=pass_count,
                fail_count=len(failing),
                unknown_count=unknown_count,
                notes=notes,
                window_days=days,
            )
        )
        detail_tables.append(
            TableSection(
                category=category_meta(CategoryKey.WORKFLOW_FAILURES_DETAIL),
                columns=DETAIL_COLUMNS,
                rows=[_detail_row(by_name[s.repo], s) for s in per_workflow],
                sum_columns=frozenset({4, 5}),
                numeric_columns=frozenset({4, 5, 6}),
                pass_count=pass_count,
                fail_count=len(per_workflow),
                unknown_count=unknown_count,
                notes=notes,
                window_days=days,
            )
        )
    return tuple(repo_tables), tuple(detail_tables)
