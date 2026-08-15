# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Command-line entry point.

Wires configuration, scope/mode resolution, collection, and rendering into the
``github-security-report`` command. Org mode produces Pages/Slack/terminal
output; repo mode is a degraded PR gate emitting a job summary and outputs.
See ``docs/BRIEF.md`` sections 9-12.

The command surface is split across:

- :mod:`cli.app` -- the Typer application, options and validation
- :mod:`cli.modes` -- the org, repo and remediate run modes
- :mod:`cli.outputs` -- offender limits, category visibility, file writing
- :mod:`cli.serialise` -- the machine-readable ``report.json`` shape
"""

from __future__ import annotations

from github_security_report.cli.app import (
    _version_callback,
    app,
    main,
    remediate,
    report,
)
from github_security_report.cli.modes import (
    OrgRunOptions,
    ReleaseOverrides,
    _abort_network,
    _load_config,
    _run_org,
    _run_remediate,
    _run_repo,
)
from github_security_report.cli.outputs import (
    TopNLimits,
    _safe_component,
    repo_outputs,
    write_org_files,
)
from github_security_report.cli.serialise import _org_to_dict, _table_to_dict

# The package façade: every name previously importable from
# ``github_security_report.cli`` still is, including the private helpers the
# tests reach for, so splitting the module changed no caller's import path.
__all__ = [
    "OrgRunOptions",
    "ReleaseOverrides",
    "TopNLimits",
    "_abort_network",
    "_load_config",
    "_org_to_dict",
    "_run_org",
    "_run_remediate",
    "_run_repo",
    "_safe_component",
    "_table_to_dict",
    "_version_callback",
    "app",
    "main",
    "remediate",
    "repo_outputs",
    "report",
    "write_org_files",
]


if __name__ == "__main__":  # pragma: no cover
    app()
