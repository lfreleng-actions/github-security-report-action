# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Configuration: schema, loading, token resolution, and Slack-day gating.

The tool's configuration is JSON, supplied either as a CLI file, a plain
GitHub ``vars.`` entry, or base64 inside a ``secrets.`` entry (base64 only to
stop raw JSON braces tripping GitHub's log redaction -- it is encoding, not
encryption). Tokens are referenced by environment-variable name, never embedded
literally. See ``docs/BRIEF.md`` sections 8-9.

Split across three modules -- :mod:`~github_security_report.config.schema`
(vocabulary and JSON Schema), :mod:`~github_security_report.config.models`
(typed objects and defaults), and :mod:`~github_security_report.config.loader`
(construction from raw JSON, on-disk lookup) -- and re-exported here, so
``github_security_report.config`` stays the single import surface.
"""

from __future__ import annotations

from github_security_report.config.loader import (
    DEFAULT_CONFIG_DIR,
    DEFAULT_CONFIG_FILE,
    _categories_from,
    _report_from,
    _slack_from,
    build_config,
    default_config_path,
    find_default_config,
    load_file,
    loads,
    parse_report_day,
    resolve_token,
)
from github_security_report.config.models import (
    DEFAULT_RULESET_WORKFLOWS,
    CategoryToggle,
    Config,
    OrgConfig,
    OutputToggles,
    ReportConfig,
    ReportDay,
    SlackConfig,
)
from github_security_report.config.schema import (
    _TOKEN_PREFIXES,
    CONFIG_SCHEMA,
    REPORT_OUTPUTS,
    SEVERITY_NAMES,
    WEEKDAYS,
    ConfigError,
)

__all__ = [
    "CONFIG_SCHEMA",
    "DEFAULT_CONFIG_DIR",
    "DEFAULT_CONFIG_FILE",
    "DEFAULT_RULESET_WORKFLOWS",
    "REPORT_OUTPUTS",
    "SEVERITY_NAMES",
    "WEEKDAYS",
    "CategoryToggle",
    "Config",
    "ConfigError",
    "OrgConfig",
    "OutputToggles",
    "ReportConfig",
    "ReportDay",
    "SlackConfig",
    "_TOKEN_PREFIXES",
    "_categories_from",
    "_report_from",
    "_slack_from",
    "build_config",
    "default_config_path",
    "find_default_config",
    "load_file",
    "loads",
    "parse_report_day",
    "resolve_token",
]
