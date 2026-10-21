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
    "FailedJob",
    "Outcome",
    "RepoSyncState",
    "RunStore",
    "Trigger",
    "WorkflowRunRecord",
    "classify_outcome",
    "classify_trigger",
    "store_path",
]
