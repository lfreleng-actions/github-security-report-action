# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Dependabot configuration posture and release/tag staleness.

These reporting categories sit outside the four-state per-signal model: they are
configuration-posture and freshness checks rendered as plain tables.

- **Dependabot** (beneath the open-alert table): three plain tables -- repos
  with vulnerability **alerts** not enabled, repos with **security updates** not
  enabled (two separate single-feature tables, not a combined matrix), and
  configured ecosystems that set no update *cooldown* (a mandatory requirement
  here -- any cooldown value passes). Only the two features GitHub exposes a
  public per-repository API for are checked.
- **Releases / Tagging**: repositories that have gone too long without a release
  or tag. Repositories younger than a configurable age are excluded (0 = none
  excluded); specific repositories can also be excluded on demand. Releases and
  tags are reported in separate columns and the rows are ranked by release/tag
  staleness alone (repository age only gates scope): a missing release or tag
  counts as the worst possible signal, so a repo with neither ranks first. The
  ranking key itself is never displayed.

The implementation is split across ``facts`` (the :class:`RepoPosture` record
every table reads), ``enablement`` (the boolean feature checks and the
Dependabot cooldown check) and ``releases`` (the release/tag freshness and
release-immutability tables). This module re-exports the public surface, so
importing from ``github_security_report.posture`` is unchanged.
"""

from __future__ import annotations

from github_security_report.posture.enablement import (
    build_alerts_table,
    build_cooldown_table,
    build_dependabot_tables,
    build_pvr_table,
    build_security_updates_table,
    cooldown_missing_ecosystems,
)
from github_security_report.posture.facts import RepoPosture
from github_security_report.posture.releases import (
    build_mutable_releases_table,
    build_releases_table,
    is_release_excluded,
)

__all__ = [
    "RepoPosture",
    "is_release_excluded",
    "cooldown_missing_ecosystems",
    "build_dependabot_tables",
    "build_releases_table",
    "build_mutable_releases_table",
    "build_alerts_table",
    "build_security_updates_table",
    "build_cooldown_table",
    "build_pvr_table",
]
