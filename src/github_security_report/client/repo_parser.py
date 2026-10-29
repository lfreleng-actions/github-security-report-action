# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Mapping a REST repository object onto :class:`~github_security_report.models.Repo`.

The organisation listing and the single-repository read return the same
object, so both build their :class:`Repo` here, including the two feature
states the object carries under ``security_and_analysis`` that spare a probe
each per repository.
"""

from __future__ import annotations

from github_security_report.client.parsers import _parse_iso
from github_security_report.models import Repo


def _feature_status(raw: dict, feature: str) -> bool | None:
    """One ``security_and_analysis`` feature's state, or ``None`` when absent.

    GitHub includes the block only for a token with admin or security-manager
    rights on the repository, so its absence says nothing about the feature;
    the caller then probes the feature's own endpoint as before.
    """
    block = raw.get("security_and_analysis")
    entry = block.get(feature) if isinstance(block, dict) else None
    status = entry.get("status") if isinstance(entry, dict) else None
    if status not in ("enabled", "disabled"):
        return None
    return bool(status == "enabled")


def _parse_repo(raw: dict) -> Repo:
    """A :class:`Repo` from a repository object of the REST API.

    Every per-branch read (the CodeQL analyses, the head it is measured
    against) follows ``default_branch``, so a repository whose default branch
    is not "main" must not inherit that default from the model.
    """
    return Repo(
        name=raw["name"],
        full_name=raw["full_name"],
        html_url=raw["html_url"],
        archived=raw.get("archived", False),
        fork=raw.get("fork", False),
        is_template=raw.get("is_template", False),
        private=raw.get("private", False),
        default_branch=raw.get("default_branch") or "main",
        created_at=_parse_iso(raw.get("created_at")),
        secret_scanning=_feature_status(raw, "secret_scanning"),
        security_updates=_feature_status(raw, "dependabot_security_updates"),
    )
