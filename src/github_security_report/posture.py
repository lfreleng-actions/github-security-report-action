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
  tags are reported in separate columns; a hidden compound sort score (the sum
  of the release-staleness and tag-staleness day counts, so a repo with neither
  counts its age twice) ranks the worst offenders first but is never displayed.
"""

from __future__ import annotations

import datetime as dt
import logging
from dataclasses import dataclass

import yaml

from github_security_report.models import ReleaseRef, Repo
from github_security_report.report import TableRow, TableSection

log = logging.getLogger(__name__)

# Aware sentinel so releases lacking a publish timestamp sort oldest (last) when
# ordering most-recent-first, without ever comparing a naive and aware value.
_MIN_AWARE = dt.datetime.min.replace(tzinfo=dt.timezone.utc)


@dataclass
class RepoPosture:
    """Per-repository configuration/freshness facts for the extra sections."""

    repo: Repo
    # Dependabot repo-level feature flags (None = indeterminate).
    dependabot_alerts: bool | None = None
    security_updates: bool | None = None
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


def is_release_excluded(
    repo: Repo,
    *,
    generated_at: dt.datetime,
    repo_min_age_days: int,
    exclude: frozenset[str] | set[str] | tuple[str, ...],
) -> bool:
    """Whether a repository is ineligible for the Releases / Tagging table.

    A repository is excluded when its name is in ``exclude`` (never released /
    not consumed externally) or when it was created within ``repo_min_age_days``
    (``0`` disables the age hold, so every repository is eligible). This is the
    repository-eligibility gate; the separate release-staleness threshold is
    applied later, once each repository's release/tag ages are known.
    """
    if repo.name in exclude:
        return True
    repo_age = _age_days(repo.created_at, generated_at)
    return (
        repo_min_age_days > 0
        and repo_age is not None
        and repo_age < repo_min_age_days
    )


def _age_days(when: dt.datetime | None, now: dt.datetime) -> int | None:
    """Whole days between ``when`` and ``now`` (>= 0), or None when absent."""
    if when is None:
        return None
    delta = (now - when).days
    return max(delta, 0)


def _release_is_current(
    release_age: int | None, tag_age: int | None, release_max_age_days: int
) -> bool:
    """Whether a repository's newest release/tag is recent enough to omit it.

    With ``release_max_age_days`` > 0, a repository counts as *current* (and is
    left out of the table) when its most recent release **or** tag is no older
    than that many days. A repository with neither a release nor a tag is never
    current. ``0`` disables the threshold, so nothing is treated as current and
    every eligible repository is listed.
    """
    if release_max_age_days <= 0:
        return False
    freshest = min(
        (age for age in (release_age, tag_age) if age is not None),
        default=None,
    )
    return freshest is not None and freshest <= release_max_age_days


def _age_cell(age: int | None) -> str:
    if age is None:
        return "never"
    if age == 0:
        return "today"
    if age == 1:
        return "1 day ago"
    return f"{age} days ago"


def _posture_summary(bad: int, bad_label: str, good: int, good_label: str) -> str:
    """Heading summary for a posture table with one bad/good axis.

    When the bad count is zero there is no negative worth showing, so only the
    positive (good) count is reported (e.g. ``"84 enabled"`` rather than
    ``"0 not enabled, 84 enabled"``).
    """
    if bad == 0:
        return f"{good} {good_label}"
    return f"{bad} {bad_label}, {good} {good_label}"


def build_alerts_table(postures: list[RepoPosture]) -> TableSection:
    """Repositories where Dependabot vulnerability alerts are not enabled."""
    rows = [
        TableRow(repo=p.repo, cells=())
        for p in sorted(postures, key=lambda p: p.repo.name)
        if p.dependabot_alerts is False
    ]
    not_enabled = sum(1 for p in postures if p.dependabot_alerts is False)
    enabled = sum(1 for p in postures if p.dependabot_alerts is True)
    indeterminate = sum(1 for p in postures if p.dependabot_alerts is None)
    return TableSection(
        title="Dependabot: Alerts",
        columns=("Repository",),
        rows=rows,
        empty_note=(
            "All in-scope repositories have Dependabot alerts enabled."
            if indeterminate == 0
            else "No in-scope repository has Dependabot alerts confirmed "
            "disabled."
        ),
        note=(
            "Dependabot security alerts are disabled on these repositories; "
            "enable them so vulnerable dependencies are reported."
        ),
        summary=_posture_summary(not_enabled, "not enabled", enabled, "enabled"),
    )


def build_security_updates_table(postures: list[RepoPosture]) -> TableSection:
    """Repositories where Dependabot security updates are not enabled."""
    rows = [
        TableRow(repo=p.repo, cells=())
        for p in sorted(postures, key=lambda p: p.repo.name)
        if p.security_updates is False
    ]
    not_enabled = sum(1 for p in postures if p.security_updates is False)
    enabled = sum(1 for p in postures if p.security_updates is True)
    indeterminate = sum(1 for p in postures if p.security_updates is None)
    return TableSection(
        title="Dependabot: Security Updates",
        columns=("Repositories NOT Enabled",),
        rows=rows,
        empty_note=(
            "All in-scope repositories have Dependabot security updates "
            "enabled."
            if indeterminate == 0
            else "No in-scope repository has Dependabot security updates "
            "confirmed disabled."
        ),
        note=(
            "Dependabot security updates are disabled on these repositories; "
            "enable them so fixes for vulnerable dependencies are proposed "
            "automatically."
        ),
        summary=_posture_summary(not_enabled, "not enabled", enabled, "enabled"),
    )


def build_cooldown_table(postures: list[RepoPosture]) -> TableSection:
    """A table of repositories/ecosystems that configure no update cooldown."""
    rows = [
        TableRow(repo=p.repo, cells=(", ".join(p.cooldown_missing),))
        for p in sorted(postures, key=lambda p: p.repo.name)
        if p.cooldown_missing
    ]
    missing = sum(1 for p in postures if p.cooldown_missing)
    with_cooldown = sum(
        1 for p in postures if p.has_dependabot_config and not p.cooldown_missing
    )
    return TableSection(
        title="Dependabot: Cooldown Settings",
        columns=("Repository", "Ecosystems without cooldown"),
        rows=rows,
        empty_note=(
            "Every configured Dependabot ecosystem sets an update cooldown."
        ),
        note=(
            "A cooldown is mandatory; any cooldown value passes. Repositories "
            "with no Dependabot configuration are not listed here."
        ),
        summary=_posture_summary(
            missing, "without cooldown", with_cooldown, "with cooldown"
        ),
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


def build_releases_table(
    postures: list[RepoPosture],
    *,
    generated_at: dt.datetime,
    repo_min_age_days: int = 28,
    release_max_age_days: int = 0,
    exclude: tuple[str, ...] = (),
) -> TableSection:
    """The Releases / Tagging table, oldest-overall first.

    Repositories created within ``repo_min_age_days`` are excluded (0 = none
    excluded), as are any whose name is in ``exclude``. When
    ``release_max_age_days`` is greater than 0, a repository is only listed when
    its newest release or tag is older than that many days (or it has neither),
    so actively released repositories drop out. Ranking uses a hidden compound
    score = release-staleness-days + tag-staleness-days, where an absent release
    or tag contributes the full repository age (so a repository with neither
    effectively counts its age twice).
    """
    excluded = frozenset(exclude)
    ranked: list[tuple[int, RepoPosture, int | None, int | None]] = []
    for posture in postures:
        repo = posture.repo
        if is_release_excluded(
            repo,
            generated_at=generated_at,
            repo_min_age_days=repo_min_age_days,
            exclude=excluded,
        ):
            continue
        repo_age = _age_days(repo.created_at, generated_at)
        release_age = _age_days(posture.latest_release_at, generated_at)
        tag_age = _age_days(posture.latest_tag_at, generated_at)
        if _release_is_current(release_age, tag_age, release_max_age_days):
            continue
        # Absent release/tag contributes the full repository age; an unknown
        # creation date falls back to the staleness we do know (or zero).
        fallback = repo_age if repo_age is not None else 0
        compound = (release_age if release_age is not None else fallback) + (
            tag_age if tag_age is not None else fallback
        )
        ranked.append((compound, posture, release_age, tag_age))
    ranked.sort(key=lambda item: (-item[0], item[1].repo.name))
    rows = [
        TableRow(
            repo=posture.repo,
            cells=(_age_cell(release_age), _age_cell(tag_age)),
        )
        for _compound, posture, release_age, tag_age in ranked
    ]
    if repo_min_age_days > 0:
        age_note = (
            f"Repositories created within {repo_min_age_days} day(s) are excluded. "
        )
    else:
        age_note = "All repositories are included (no minimum age). "
    if release_max_age_days > 0:
        stale_note = (
            "Only repositories whose newest release or tag is older than "
            f"{release_max_age_days} day(s) (or have neither) are shown. "
        )
    else:
        stale_note = ""
    return TableSection(
        title="Releases / Tagging",
        columns=("Repository", "Last release", "Last tag"),
        rows=rows,
        empty_note=(
            "No repositories to report (all were excluded by the minimum age, "
            "the release-age threshold, or the exclusion list)."
        ),
        note=(
            age_note
            + stale_note
            + "Ranked by combined release and tag staleness (oldest first). "
            "A repository with neither a release nor a tag ranks highest."
        ),
    )


def build_mutable_releases_table(postures: list[RepoPosture]) -> TableSection:
    """Repositories whose "Latest" or last-published release is not immutable.

    Both the release carrying GitHub's "Latest" badge and the most recently
    published release are checked; whichever are mutable are listed (a repo can
    have a newer mutable pre-release ahead of a mutable "Latest" release, so
    more than one entry may appear). Duplicate tags are collapsed and the
    "Latest" entry is annotated ``(latest)``. The heading summary counts
    repositories with findings against those whose checked releases are all
    immutable; repositories with no releases to check are counted as neither.
    """
    flagged: list[tuple[RepoPosture, list[ReleaseRef]]] = []
    checked = 0
    for posture in postures:
        seen: set[str] = set()
        candidates: list[ReleaseRef] = []
        for ref in (posture.latest_release, posture.last_published_release):
            if ref is not None and ref.tag not in seen:
                seen.add(ref.tag)
                candidates.append(ref)
        if not candidates:
            continue  # no releases to check: neither a finding nor clean
        checked += 1
        mutable = [ref for ref in candidates if not ref.immutable]
        if mutable:
            flagged.append((posture, mutable))

    rows: list[TableRow] = []
    for posture, mutable in sorted(flagged, key=lambda item: item[0].repo.name):
        ordered = sorted(
            mutable,
            key=lambda ref: ref.published_at or _MIN_AWARE,
            reverse=True,  # most recent first
        )
        labels = [
            f"{ref.tag} (latest)" if ref.is_latest else ref.tag for ref in ordered
        ]
        rows.append(TableRow(repo=posture.repo, cells=(", ".join(labels),)))

    finding_count = len(flagged)
    clean_count = checked - finding_count
    return TableSection(
        title="Mutable Releases",
        columns=("Repository", "Releases"),
        rows=rows,
        empty_note=(
            "Every checked repository's latest and last-published releases are "
            "immutable."
        ),
        note="Recent releases in the repositories above are not immutable.",
        summary=_posture_summary(
            finding_count, "with findings", clean_count, "clean"
        ),
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
]
