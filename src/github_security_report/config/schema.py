# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Configuration vocabulary and the JSON Schema the config is validated against.

Holds the constants the schema is built from (render surfaces, severity names,
weekdays), the error raised on invalid input, and ``CONFIG_SCHEMA`` itself.
"""

from __future__ import annotations

from github_security_report.categories import all_categories

# The render surfaces a category can be toggled on or off for, independently of
# whether the data is collected (collection is always exhaustive). ``cli`` is
# the terminal, ``slack`` the digest, and ``markdown``/``html`` the two GitHub
# Pages artifacts (treated separately so each can be tuned on its own).
REPORT_OUTPUTS = ("cli", "slack", "markdown", "html")

# Severity names accepted for a category's ``fail_severity`` cutoff, lowest to
# highest. ``informational`` is the new sub-low rung.
SEVERITY_NAMES = ("informational", "low", "medium", "high", "critical")

WEEKDAYS = (
    "monday",
    "tuesday",
    "wednesday",
    "thursday",
    "friday",
    "saturday",
    "sunday",
)

# Output-ordering styles, plus the "automatic" spelling of the default. See
# :mod:`github_security_report.layout` for what each one does.
ORDER_STYLES = ("auto", "automatic", "dual", "single", "fixed")

# Every category key, as the ordering lists may name them.
CATEGORY_KEYS = [meta.key.value for meta in all_categories()]

# Heuristic to warn when a token value, rather than an env-var name, is given.
_TOKEN_PREFIXES = ("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_")


class ConfigError(ValueError):
    """Raised when configuration is malformed or fails validation."""


CONFIG_SCHEMA: dict = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "slack": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "channel": {"type": "string"},
                "report_day": {
                    "oneOf": [
                        {"type": "string"},
                        {"type": "array", "items": {"type": "string"}},
                    ]
                },
            },
        },
        "report": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                # 0 disables the per-signal offender limit (show everything);
                # any positive value caps each table/list at that many rows.
                "top_n": {"type": "integer", "minimum": 0},
                "top_n_report": {"type": "integer", "minimum": 0},
                "top_n_cli": {"type": "integer", "minimum": 0},
                "top_n_slack": {"type": "integer", "minimum": 0},
                "include_archived": {"type": "boolean"},
                "include_test": {"type": "boolean"},
                # Repository-age grace period: repos created within this many
                # days are omitted from Releases/Tagging (0 = include all).
                # `release_min_age_days` is the deprecated former name for this
                # same control and is still accepted for backward compatibility.
                "repo_min_age_days": {"type": "integer", "minimum": 0},
                "release_min_age_days": {"type": "integer", "minimum": 0},
                # Release-staleness threshold: a repo is flagged in
                # Releases/Tagging only when its newest release or tag is older
                # than this many days (0 = flag every eligible repository).
                "release_max_age_days": {"type": "integer", "minimum": 0},
                # Automation-backlog thresholds colouring the Pull Requests
                # table's Auto column: warn above the first, error at or above
                # the second. The defaults track GitHub's own
                # open-pull-requests-limit (5), which it applies per package
                # ecosystem while Auto counts every automation author.
                "dependabot_warn_threshold": {"type": "integer", "minimum": 0},
                "dependabot_error_threshold": {"type": "integer", "minimum": 0},
                # Organisation feature gating: when true (the default) the
                # workflow-driven signals (Scorecard, zizmor, aislop) are
                # probed only after a cheap support check (org ruleset,
                # existing alerts, or sampled analyses); an unsupported signal
                # is reported as skipped with a setup-guide pointer instead of
                # nagging every repository. Set false to always probe.
                "gating": {"type": "boolean"},
                "ruleset_workflows": {
                    "type": "object",
                    "additionalProperties": {"type": "string"},
                },
                # Column -> issue labels for the GitHub Issues table. Each key
                # becomes a table column, in declaration order; the value lists
                # the issue labels that count towards it. A configured mapping
                # replaces the built-in default rather than merging with it.
                # The loader rejects names the table supplies itself (all five
                # of RESERVED_COLUMNS) plus blank, padded, case-duplicate and
                # markup-breaking ones: JSON Schema cannot express those with a
                # usable error message.
                "issue_labels": {
                    "type": "object",
                    "additionalProperties": {
                        "type": "array",
                        "items": {"type": "string", "minLength": 1},
                    },
                },
                # Where each category sits in the rendered output. `style`
                # picks the algorithm; the list keys supply membership for the
                # styles that take it. The loader rejects a list key paired
                # with a style that does not read it, and a `single` style with
                # no sequence: JSON Schema can express neither with a usable
                # error message.
                "order": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "style": {"enum": list(ORDER_STYLES)},
                        "priority": {
                            "type": "array",
                            "items": {"enum": CATEGORY_KEYS},
                        },
                        "bau": {
                            "type": "array",
                            "items": {"enum": CATEGORY_KEYS},
                        },
                        "sequence": {
                            "type": "array",
                            "items": {"enum": CATEGORY_KEYS},
                        },
                    },
                },
                # Per-category render toggles. Each known category may set a
                # global `enabled` switch (highest precedence: off hides the
                # category on every surface) and, beneath it, a lower-precedence
                # per-output map. A category is rendered on output X only when
                # `enabled` is true AND `outputs.X` is true. Everything defaults
                # to true, so an omitted category or key stays fully enabled.
                # Data is always collected regardless of these toggles.
                "categories": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        meta.key.value: {
                            "type": "object",
                            "additionalProperties": False,
                            "properties": {
                                "enabled": {"type": "boolean"},
                                "outputs": {
                                    "type": "object",
                                    "additionalProperties": False,
                                    "properties": {
                                        output: {"type": "boolean"}
                                        for output in REPORT_OUTPUTS
                                    },
                                },
                                # The lowest finding severity that counts as a
                                # failure for this category (severity signals
                                # only). Overrides the category default.
                                "fail_severity": {"enum": list(SEVERITY_NAMES)},
                                # Rows this category shows before an "and N
                                # more" tally, overriding the per-output limit
                                # (0 = no limit, show every row).
                                "top_n": {"type": "integer", "minimum": 0},
                                # Row ordering for a table: column names, most
                                # significant first. A leading '-' forces
                                # descending and '+' forces ascending; bare
                                # names take the direction implied by the
                                # column's type. The severity signal tables
                                # resolve these against a fixed vocabulary
                                # (repository/score/critical/high/medium/low/
                                # info/total) rather than rendered headings.
                                "sort": {
                                    "type": "array",
                                    "items": {"type": "string", "minLength": 1},
                                },
                            },
                        }
                        for meta in all_categories()
                    },
                },
            },
        },
        "organizations": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["name"],
                "properties": {
                    "name": {"type": "string", "minLength": 1},
                    "token_env": {"type": "string"},
                    "exclude": {"type": "array", "items": {"type": "string"}},
                    "releases_exclude": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                    "slack": {"$ref": "#/properties/slack"},
                    "report": {"$ref": "#/properties/report"},
                },
            },
        },
    },
    "required": ["organizations"],
}
