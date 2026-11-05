# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""What the JSON Schema cannot say about each configuration key.

:mod:`~github_security_report.config.dictionary` walks ``CONFIG_SCHEMA`` for
every key's path, type and allowed values, and the dataclass defaults for its
default. This table adds the rest: a one-line description, a default where the
dataclass holds ``None`` meaning "inherit", and the status of keys that are
deprecated or removed. A test asserts every schema key has a note here and
every note names a schema key, so the two cannot drift.

Paths are dotted. ``<category>`` stands for any key under
``report.categories``; ``organizations[]`` for any organisation entry.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType


@dataclass(frozen=True)
class KeyNote:
    """A key's description, and its default when the dataclass cannot say."""

    description: str
    default: str | None = None


_NOTES: dict[str, KeyNote] = {
    "slack.channel": KeyNote("Slack channel ID the digest is posted to.", "unset"),
    "slack.report_day": KeyNote(
        "Weekday(s) the Slack digest posts on, or 'always' / 'never'."
    ),
    "report.top_n": KeyNote("Offenders shown per signal (0 = no limit)."),
    "report.top_n_report": KeyNote(
        "Offenders per signal on GitHub Pages (0 = no limit).", "report.top_n"
    ),
    "report.top_n_cli": KeyNote(
        "Offenders per signal in the terminal (0 = no limit).", "report.top_n"
    ),
    "report.top_n_slack": KeyNote(
        "Offenders per signal in the Slack digest (0 = no limit).", "report.top_n"
    ),
    "report.include_archived": KeyNote("Analyse archived repositories."),
    "report.include_test": KeyNote("Analyse test repositories."),
    "report.repo_min_age_days": KeyNote(
        "Omit repositories younger than this from Releases/Tagging (0 = none)."
    ),
    "report.release_min_age_days": KeyNote(
        "Former name of report.repo_min_age_days.", "28"
    ),
    "report.release_max_age_days": KeyNote(
        "Flag a repository once its newest release or tag is this old."
    ),
    "report.codeql_stale_days": KeyNote(
        "Days a CodeQL scan may trail the default branch before it is stale."
    ),
    "report.dependabot_warn_threshold": KeyNote(
        "Open automation pull requests above which Auto shows a warning."
    ),
    "report.dependabot_error_threshold": KeyNote(
        "Open automation pull requests at which Auto shows an error (0 = off)."
    ),
    "report.issue_age_warn_days": KeyNote(
        "Oldest open issue age that shows a warning (0 = off)."
    ),
    "report.issue_age_error_days": KeyNote(
        "Oldest open issue age that shows an error (0 = off)."
    ),
    "report.gating": KeyNote(
        "Probe workflow-driven signals only where the organisation supports them."
    ),
    "report.graph_batch": KeyNote("Repositories per batched GraphQL query."),
    "report.concurrency": KeyNote("Concurrent GitHub API requests per organisation."),
    "report.repo_list": KeyNote(
        "Which repositories a feature category names beneath its counts."
    ),
    "report.exclude": KeyNote(
        "Name patterns every category leaves out; still analysed."
    ),
    "report.exclude_tests": KeyNote(
        "Name patterns for test repositories, counted on their own footer line."
    ),
    "report.excluded_display": KeyNote(
        "When a category footer shows the excluded repositories."
    ),
    "report.excluded_names": KeyNote(
        "Name the excluded repositories on the footer, not only count them."
    ),
    "report.excluded_tests_display": KeyNote(
        "When a category footer shows the excluded test repositories."
    ),
    "report.excluded_tests_names": KeyNote(
        "Name the excluded test repositories on the footer, not only count them."
    ),
    "report.ruleset_workflows": KeyNote(
        "Signal -> required-workflow path keyword that counts as enabled."
    ),
    "report.issue_labels": KeyNote(
        "Issues table columns and the labels each counts (replaces the default)."
    ),
    "report.order.style": KeyNote("How categories are ordered in the output."),
    "report.order.priority": KeyNote("Categories shown first (dual style)."),
    "report.order.bau": KeyNote("Categories shown last (dual style)."),
    "report.order.sequence": KeyNote("Explicit category order (single style)."),
    "report.workflow_runs.windows.cli": KeyNote("Workflow Failures windows, terminal."),
    "report.workflow_runs.windows.report": KeyNote(
        "Workflow Failures windows, GitHub Pages."
    ),
    "report.workflow_runs.windows.slack": KeyNote("Workflow Failures windows, Slack."),
    "report.workflow_runs.retention_days": KeyNote(
        "Days the run store keeps records.", "longest window"
    ),
    "report.workflow_runs.backfill_days": KeyNote(
        "Days a never-seen repository's runs are read back.", "retention"
    ),
    "report.workflow_runs.include_dynamic": KeyNote(
        "Include GitHub-managed workflows (Dependabot, default-setup CodeQL)."
    ),
    "report.workflow_runs.exclude_workflows": KeyNote(
        "Workflow path globs whose failures are expected and left out."
    ),
    "report.workflow_runs.collapse_matrix": KeyNote(
        "Fold matrix variants of a job into one row."
    ),
    "report.workflow_runs.persistent_threshold": KeyNote(
        "Failure rate at or above which a workflow counts as persistent."
    ),
    "report.workflow_runs.min_runs": KeyNote(
        "Concluded runs needed before a workflow is judged."
    ),
    "report.workflow_runs.fail_rate_error_threshold": KeyNote(
        "Repository failure rate above which Fail % shows an error."
    ),
    "report.workflow_runs.cache": KeyNote("Keep the run store in the per-user cache."),
    "report.workflow_runs.cache_dir": KeyNote(
        "Directory for the run store.", "$XDG_CACHE_HOME/github-security-report"
    ),
    "report.categories.<category>.enabled": KeyNote(
        "Show the category at all (off hides it on every output)."
    ),
    "report.categories.<category>.outputs.cli": KeyNote(
        "Show the category in the terminal."
    ),
    "report.categories.<category>.outputs.slack": KeyNote(
        "Show the category in the Slack digest."
    ),
    "report.categories.<category>.outputs.markdown": KeyNote(
        "Show the category in the Markdown report."
    ),
    "report.categories.<category>.outputs.html": KeyNote(
        "Show the category in the HTML report."
    ),
    "report.categories.<category>.fail_severity": KeyNote(
        "Lowest finding severity that counts as a failure.", "category default"
    ),
    "report.categories.<category>.top_n": KeyNote(
        "Rows shown before an 'and N more' tally (0 = no limit).",
        "per-output limit",
    ),
    "report.categories.<category>.sort": KeyNote(
        "Row order: column names, most significant first ('-' descending).",
        "table default",
    ),
    "report.categories.<category>.repo_list": KeyNote(
        "Which repositories this category names beneath its counts.",
        "report.repo_list",
    ),
    "report.categories.<category>.exclude": KeyNote(
        "Name patterns this category leaves out (replaces report.exclude).",
        "report.exclude",
    ),
    "report.categories.<category>.exclude_tests": KeyNote(
        "Test-repository patterns for this category (replaces report.exclude_tests).",
        "report.exclude_tests",
    ),
    "organizations[].name": KeyNote("GitHub organisation login.", "required"),
    "organizations[].token_env": KeyNote(
        "Name of the environment variable holding the token."
    ),
    "organizations[].exclude": KeyNote(
        "Name patterns for repositories removed from analysis altogether."
    ),
    "organizations[].releases_exclude": KeyNote(
        "Name patterns for repositories left out of the Releases/Tagging table."
    ),
    "organizations[].slack": KeyNote(
        "Per-organisation override of the slack block (same keys).", "slack"
    ),
    "organizations[].report": KeyNote(
        "Per-organisation override of the report block (same keys).", "report"
    ),
}

NOTES: Mapping[str, KeyNote] = MappingProxyType(_NOTES)

# Keys still accepted but superseded: path -> the key to use instead.
DEPRECATED: Mapping[str, str] = MappingProxyType(
    {"report.release_min_age_days": "report.repo_min_age_days"}
)

# Keys no longer accepted: path -> (release that removed it, replacement or
# None). A configuration naming one gets this explanation rather than the
# generic unknown-key message.
REMOVED: Mapping[str, tuple[str, str | None]] = MappingProxyType({})
