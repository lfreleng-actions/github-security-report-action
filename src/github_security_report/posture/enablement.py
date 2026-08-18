# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Configuration-posture tables: feature enablement and update cooldowns.

Every table here is built from the boolean (or indeterminate) configuration
facts on :class:`RepoPosture`: the two Dependabot features GitHub exposes a
public per-repository API for, the private-vulnerability-reporting flag, and
the per-ecosystem cooldown declared in a repository's ``dependabot.yml``.
"""

from __future__ import annotations

import logging
from collections.abc import Callable

import yaml

from github_security_report.categories import CategoryKey, category_meta
from github_security_report.posture.facts import RepoPosture
from github_security_report.report import TableRow, TableSection

log = logging.getLogger(__name__)


def cooldown_missing_ecosystems(dependabot_yaml: str) -> tuple[str, ...]:
    """Ecosystems in a ``dependabot.yml`` that declare no ``cooldown``.

    Any ``cooldown`` value passes. Returns the ``package-ecosystem`` of each
    ``updates`` entry that omits a cooldown, de-duplicated and ordered. A
    malformed document yields an empty tuple (treated as "nothing to flag").
    """
    try:
        data = yaml.safe_load(dependabot_yaml)
    except yaml.YAMLError as exc:  # malformed config; do not crash the run
        log.warning("could not parse dependabot.yml: %s", exc)
        return ()
    if not isinstance(data, dict):
        return ()
    updates = data.get("updates")
    if not isinstance(updates, list):
        return ()
    missing: list[str] = []
    for entry in updates:
        if not isinstance(entry, dict):
            continue
        ecosystem = entry.get("package-ecosystem")
        if not isinstance(ecosystem, str) or not ecosystem:
            continue
        if "cooldown" not in entry and ecosystem not in missing:
            missing.append(ecosystem)
    return tuple(missing)


def _build_feature_table(
    postures: list[RepoPosture],
    *,
    category_key: CategoryKey,
    columns: tuple[str, ...],
    enabled_of: Callable[[RepoPosture], bool | None],
) -> TableSection:
    """A single-feature enablement table (offenders = feature confirmed off).

    Shared by the Dependabot alerts and security-updates checks: both list the
    repositories where one boolean feature is explicitly disabled and report the
    enabled/not-enabled/indeterminate split as the standardised footer counts.
    An indeterminate (``None``) reading counts towards neither pass nor fail; it
    becomes the unknown count, so an empty table never over-claims that every
    repository is enabled.
    """
    rows = [
        TableRow(repo=p.repo, cells=())
        for p in sorted(postures, key=lambda p: p.repo.name)
        if enabled_of(p) is False
    ]
    not_enabled = sum(1 for p in postures if enabled_of(p) is False)
    enabled = sum(1 for p in postures if enabled_of(p) is True)
    indeterminate = sum(1 for p in postures if enabled_of(p) is None)
    return TableSection(
        category=category_meta(category_key),
        columns=columns,
        rows=rows,
        pass_count=enabled,
        fail_count=not_enabled,
        unknown_count=indeterminate,
    )


def build_alerts_table(postures: list[RepoPosture]) -> TableSection:
    """Repositories where Dependabot vulnerability alerts are not enabled."""
    return _build_feature_table(
        postures,
        category_key=CategoryKey.DEPENDABOT_ALERTS_ENABLED,
        columns=("Repository",),
        enabled_of=lambda p: p.dependabot_alerts,
    )


def build_security_updates_table(postures: list[RepoPosture]) -> TableSection:
    """Repositories where Dependabot security updates are not enabled."""
    return _build_feature_table(
        postures,
        category_key=CategoryKey.DEPENDABOT_UPDATES_ENABLED,
        columns=("Repository",),
        enabled_of=lambda p: p.security_updates,
    )


def build_cooldown_table(postures: list[RepoPosture]) -> TableSection:
    """A table of repositories/ecosystems that configure no update cooldown."""
    rows = [
        TableRow(repo=p.repo, cells=(joined,), sort_values=(joined,))
        for p in sorted(postures, key=lambda p: p.repo.name)
        if p.cooldown_missing and (joined := ", ".join(p.cooldown_missing))
    ]
    missing = sum(1 for p in postures if p.cooldown_missing)
    with_cooldown = sum(
        1 for p in postures if p.has_dependabot_config and not p.cooldown_missing
    )
    # An unreadable prefetch means the dependabot.yml itself is unknown, not
    # absent -- count it as unknown rather than silently dropping the repo.
    indeterminate = sum(1 for p in postures if p.graph_unreadable)
    return TableSection(
        category=category_meta(CategoryKey.DEPENDABOT_COOLDOWN),
        columns=("Repository", "Ecosystems without cooldown"),
        rows=rows,
        pass_count=with_cooldown,
        fail_count=missing,
        unknown_count=indeterminate,
    )


def build_dependabot_tables(postures: list[RepoPosture]) -> list[TableSection]:
    """All extra Dependabot posture tables, in render order.

    The alerts and security-updates enablement checks are deliberately two
    separate single-feature tables (rather than one multi-column matrix): with
    only two public-API features the matrix read as contradictory.
    """
    return [
        build_alerts_table(postures),
        build_security_updates_table(postures),
        build_cooldown_table(postures),
    ]


def build_pvr_table(postures: list[RepoPosture]) -> TableSection:
    """Repositories where private vulnerability reporting is not enabled.

    Like the Dependabot enablement tables this is a single-boolean feature
    check, so it reuses :func:`_build_feature_table`: offenders are repositories
    where the feature is confirmed off; an indeterminate (``None``) reading
    counts towards neither side of the standardised summary footer. The table is
    always built (the flag is probed for every repository); the per-category
    render toggle governs whether it is shown.
    """
    return _build_feature_table(
        postures,
        category_key=CategoryKey.PRIVATE_VULNERABILITY_REPORTING,
        columns=("Repository",),
        enabled_of=lambda p: p.private_vulnerability_reporting,
    )
