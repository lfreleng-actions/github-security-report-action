# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Workflow-run records, their persistent store and their aggregation.

The data behind the Workflow Failures tables: which GitHub Actions workflows
failed, where, how often and on which trigger, over configurable time windows.
:mod:`.models` is the vocabulary, :mod:`.store` the per-organisation SQLite
cache that makes every run after the first incremental, and :mod:`.aggregate`
the pure functions that turn a window of records into per-repository and
per-workflow statistics.
"""

from __future__ import annotations

from github_security_report.workflow_runs.aggregate import (
    PATTERN_INSUFFICIENT,
    PATTERN_INTERMITTENT,
    PATTERN_PERSISTENT,
    READING_EVERYWHERE,
    READING_NO_PR_RUNS,
    READING_OTHER,
    READING_POST_MERGE_ONLY,
    JobFailures,
    RepoWindowStats,
    WindowOptions,
    WorkflowWindowStats,
    in_window,
    normalise_job_name,
    pattern,
    repo_stats,
    window_records,
    workflow_stats,
)
from github_security_report.workflow_runs.models import (
    DYNAMIC_PATH_PREFIX,
    FailedJob,
    Outcome,
    RepoSyncState,
    Trigger,
    WorkflowRunRecord,
    classify_outcome,
    classify_trigger,
)
from github_security_report.workflow_runs.store import RunStore, store_path

__all__ = [
    "DYNAMIC_PATH_PREFIX",
    "PATTERN_INSUFFICIENT",
    "PATTERN_INTERMITTENT",
    "PATTERN_PERSISTENT",
    "READING_EVERYWHERE",
    "READING_NO_PR_RUNS",
    "READING_OTHER",
    "READING_POST_MERGE_ONLY",
    "FailedJob",
    "JobFailures",
    "Outcome",
    "RepoSyncState",
    "RepoWindowStats",
    "RunStore",
    "Trigger",
    "WindowOptions",
    "WorkflowRunRecord",
    "WorkflowWindowStats",
    "classify_outcome",
    "classify_trigger",
    "in_window",
    "normalise_job_name",
    "pattern",
    "repo_stats",
    "store_path",
    "window_records",
    "workflow_stats",
]
