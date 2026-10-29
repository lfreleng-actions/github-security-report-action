# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Building the ``report`` block and its nested blocks from raw JSON.

The ``report`` block is the configuration's largest, with nested blocks for
the per-category toggles, the Issues table's columns and the Workflow
Failures settings, and each nested block has rules JSON Schema cannot state
with a usable error. Those parsers live here; the top-level loader in
:mod:`~github_security_report.config.loader` calls :func:`_report_from`.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from types import MappingProxyType

from github_security_report.config.models import (
    CategoryToggle,
    ReportConfig,
    WorkflowRunsConfig,
)
from github_security_report.config.order import order_from
from github_security_report.config.schema import REPORT_OUTPUTS, ConfigError
from github_security_report.issues import RESERVED_COLUMNS
from github_security_report.severity import Severity, from_name
from github_security_report.summary import ExcludedDisplay, RepoList

# Characters that would break the surfaces a column header is rendered into:
# a pipe ends a Markdown table cell, a backtick can close the Slack code fence.
_UNSAFE_COLUMN = ("|", "`")


def _issue_labels_from(data: Mapping[str, list[str]]) -> Mapping[str, tuple[str, ...]]:
    """Validate and convert the ``issue_labels`` column -> labels mapping.

    Three ways a column name can break the Issues table, none of which JSON
    Schema can express as a useful error:

    * **Reusing a fixed header.** The table supplies five of its own
      (:data:`~github_security_report.issues.RESERVED_COLUMNS`). A configured
      ``Other`` shares the implicit column's counter, so those issues are shown
      twice and the class columns stop summing to ``Total``; a configured
      ``Repository`` is worse, because ``sort: ["repository"]`` would then
      resolve to a count column rather than the repository name.
    * **Differing only by case.** ``Bug`` and ``bug`` are two columns but one
      sort target, and ``ordering.resolve_terms`` matches case-insensitively.
    * **Being blank, padded, or structurally unsafe.** A blank name renders a
      column nothing can refer to; a padded one such as ``" Bug "`` could never
      be named in ``sort``, whose terms are stripped before matching; and a
      name carrying ``|``, a backtick or a control character would corrupt the
      Markdown table or Slack code fence it is rendered into, since headers go
      out verbatim.
    """
    reserved = {column.casefold(): column for column in RESERVED_COLUMNS}
    seen: set[str] = set()
    for column in data:
        folded = column.casefold()
        if not column.strip():
            raise ConfigError("issue_labels column names cannot be blank")
        if column != column.strip():
            raise ConfigError(
                f"issue_labels column {column!r} has leading or trailing "
                "whitespace; sort terms are stripped before matching, so this "
                "column could never be named in a `sort` list"
            )
        if not column.isprintable() or any(ch in column for ch in _UNSAFE_COLUMN):
            raise ConfigError(
                f"issue_labels column {column!r} contains a character that "
                "would corrupt the rendered tables; column names go into "
                "Markdown headers and Slack code fences verbatim, so they must "
                "be printable single-line text without '|' or backticks"
            )
        if folded in reserved:
            raise ConfigError(
                f"issue_labels column {column!r} collides with {reserved[folded]!r}, "
                "one of the columns the Issues table always supplies "
                f"({', '.join(RESERVED_COLUMNS)}); choose a different name"
            )
        if folded in seen:
            raise ConfigError(
                f"issue_labels column {column!r} duplicates an earlier column "
                "differing only in case; column names must be distinct "
                "case-insensitively so they can be sorted on unambiguously"
            )
        seen.add(folded)
    return MappingProxyType({column: tuple(labels) for column, labels in data.items()})


def _report_from(data: dict, base: ReportConfig) -> ReportConfig:
    data = dict(data)
    # Back-compat: `release_min_age_days` was the original (misleading) name for
    # the repository-age grace period now called `repo_min_age_days`. Accept it
    # as an alias and let an explicit new key win if both appear. The (single)
    # deprecation warning is emitted by build_config, which sees every block.
    if "release_min_age_days" in data:
        legacy = data.pop("release_min_age_days")
        data.setdefault("repo_min_age_days", legacy)
    result = replace(
        base,
        **{
            k: v
            for k, v in data.items()
            if k
            in {
                "top_n",
                "top_n_report",
                "top_n_cli",
                "top_n_slack",
                "include_archived",
                "include_test",
                "repo_min_age_days",
                "release_max_age_days",
                "codeql_stale_days",
                "dependabot_warn_threshold",
                "dependabot_error_threshold",
                "issue_age_warn_days",
                "issue_age_error_days",
                "gating",
                "graph_batch",
                "concurrency",
            }
        },
    )
    if "ruleset_workflows" in data:
        # Merge so the built-in defaults (e.g. zizmor) survive unless overridden.
        merged = {**base.ruleset_workflows, **data["ruleset_workflows"]}
        result = replace(result, ruleset_workflows=MappingProxyType(merged))
    if "issue_labels" in data:
        # Replace rather than merge: the mapping defines the Issues table's
        # column set, so merging would keep default columns the operator
        # deliberately left out.
        result = replace(result, issue_labels=_issue_labels_from(data["issue_labels"]))
    if "categories" in data:
        result = replace(
            result,
            categories=_categories_from(data["categories"], base.categories),
        )
    if "order" in data:
        result = replace(result, order=order_from(data["order"], base.order))
    if "workflow_runs" in data:
        result = replace(
            result,
            workflow_runs=_workflow_runs_from(
                data["workflow_runs"], base.workflow_runs
            ),
        )
    if "repo_list" in data:
        # The schema constrains the value to a RepoList member.
        result = replace(result, repo_list=RepoList(data["repo_list"]))
    if "excluded_display" in data:
        result = replace(
            result, excluded_display=ExcludedDisplay(data["excluded_display"])
        )
    _require_reachable_warning(
        result, "dependabot_warn_threshold", "dependabot_error_threshold"
    )
    _require_reachable_warning(result, "issue_age_warn_days", "issue_age_error_days")
    return result


def _workflow_runs_from(data: dict, base: WorkflowRunsConfig) -> WorkflowRunsConfig:
    """Merge a ``workflow_runs`` block over the inherited settings.

    ``windows`` merges per surface, so an organisation that narrows the Slack
    windows keeps the inherited report ones. A retention shorter than the
    longest window is rejected: the store would prune records a table still
    needs, and the window would quietly show less than it claims.
    """
    scalars = {
        k: v
        for k, v in data.items()
        if k
        in {
            "retention_days",
            "backfill_days",
            "include_dynamic",
            "collapse_matrix",
            "persistent_threshold",
            "min_runs",
            "cache",
            "cache_dir",
        }
    }
    result = replace(base, **scalars)
    if "windows" in data:
        merged = {
            **base.windows,
            **{surface: tuple(days) for surface, days in data["windows"].items()},
        }
        result = replace(result, windows=MappingProxyType(merged))
    if "exclude_workflows" in data:
        result = replace(result, exclude_workflows=tuple(data["exclude_workflows"]))
    if (
        result.retention_days is not None
        and result.retention_days < result.longest_window
    ):
        raise ConfigError(
            f"report.workflow_runs.retention_days ({result.retention_days}) is "
            f"shorter than the longest configured window "
            f"({result.longest_window} days); the store would prune records a "
            "table still shows"
        )
    return result


def _require_reachable_warning(
    report: ReportConfig, warn_name: str, error_name: str
) -> None:
    """Reject an error threshold that leaves its warning level unreachable.

    The error level is checked first, so a warning threshold at or above it
    can never be reached: every value that would warn has already errored.
    Rejecting beats silently ignoring one of the two knobs the operator
    deliberately set. A zero error threshold is exempt -- that is the
    documented way to turn the error level off, leaving a warning-only
    configuration.
    """
    warn = getattr(report, warn_name)
    error = getattr(report, error_name)
    if error and error <= warn:
        raise ConfigError(
            f"report.{error_name} ({error}) must be greater than "
            f"report.{warn_name} ({warn}), or 0 to disable the error level; "
            "otherwise the warning level can never be reached"
        )


def _categories_from(
    data: dict, base: Mapping[str, CategoryToggle]
) -> Mapping[str, CategoryToggle]:
    """Merge a ``categories`` block over the inherited toggles.

    Each category is merged independently and key-by-key, so an org override
    that flips a single output leaves the inherited ``enabled`` switch and the
    other outputs untouched.
    """
    merged: dict[str, CategoryToggle] = dict(base)
    for key, raw in data.items():
        current = merged.get(key, CategoryToggle())
        outputs = current.outputs
        if "outputs" in raw:
            outputs = replace(
                outputs,
                **{
                    output: value
                    for output, value in raw["outputs"].items()
                    if output in REPORT_OUTPUTS
                },
            )
        fail_severity = current.fail_severity
        if "fail_severity" in raw:
            # The schema constrains the value to a known severity name, so
            # from_name resolves it; informational is handled explicitly as it
            # is below the security-severity scale from_name covers.
            name = raw["fail_severity"]
            fail_severity = (
                Severity.INFORMATIONAL if name == "informational" else from_name(name)
            )
        merged[key] = CategoryToggle(
            enabled=raw.get("enabled", current.enabled),
            outputs=outputs,
            fail_severity=fail_severity,
            top_n=raw.get("top_n", current.top_n),
            sort=tuple(raw["sort"]) if "sort" in raw else current.sort,
            repo_list=(
                RepoList(raw["repo_list"]) if "repo_list" in raw else current.repo_list
            ),
        )
    return MappingProxyType(merged)
