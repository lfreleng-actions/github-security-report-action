# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""The per-repository facts the posture and freshness tables are built from."""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

from github_security_report.models import ReleaseRef, Repo


@dataclass
class RepoPosture:
    """Per-repository configuration/freshness facts for the extra sections."""

    repo: Repo
    # True when the batched GraphQL prefetch could not read this repository at
    # all: the release/tag and dependabot.yml facts below are then unknown, not
    # absent, and the tables must count the repository as unknown rather than
    # render confident negatives such as "never released".
    graph_unreadable: bool = False
    # Dependabot repo-level feature flags (None = indeterminate).
    dependabot_alerts: bool | None = None
    security_updates: bool | None = None
    # GitHub "private vulnerability reporting" enablement (None = indeterminate).
    private_vulnerability_reporting: bool | None = None
    # Ecosystems declared in .github/dependabot.yml that set no cooldown.
    cooldown_missing: tuple[str, ...] = ()
    # True when .github/dependabot.yml exists and declares version updates.
    has_dependabot_config: bool = False
    # Releases / tagging (UTC; None = none found).
    latest_release_at: dt.datetime | None = None
    latest_tag_at: dt.datetime | None = None
    # Release identities for the immutability check (None = absent).
    latest_release: ReleaseRef | None = None
    last_published_release: ReleaseRef | None = None
