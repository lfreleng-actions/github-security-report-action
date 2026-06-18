# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Tests for the Dependabot-posture and Releases/Tagging report tables."""

from __future__ import annotations

import datetime as dt

from github_security_report import posture
from github_security_report.models import Repo

NOW = dt.datetime(2026, 6, 18, 12, 0, tzinfo=dt.timezone.utc)


def _repo(name: str, *, age_days: int | None = 365) -> Repo:
    created = NOW - dt.timedelta(days=age_days) if age_days is not None else None
    return Repo(name, f"o/{name}", f"https://github.com/o/{name}", created_at=created)


def _ago(days: int) -> dt.datetime:
    return NOW - dt.timedelta(days=days)


# --------------------------------------------------------------------------- #
# cooldown_missing_ecosystems
# --------------------------------------------------------------------------- #
def test_cooldown_missing_flags_only_ecosystems_without_cooldown() -> None:
    yaml = """
version: 2
updates:
  - package-ecosystem: pip
    directory: /
    schedule:
      interval: weekly
  - package-ecosystem: github-actions
    directory: /
    cooldown:
      default-days: 7
    schedule:
      interval: weekly
"""
    assert posture.cooldown_missing_ecosystems(yaml) == ("pip",)


def test_cooldown_missing_any_cooldown_value_passes() -> None:
    yaml = """
version: 2
updates:
  - package-ecosystem: npm
    cooldown:
      default-days: 1
"""
    assert posture.cooldown_missing_ecosystems(yaml) == ()


def test_cooldown_missing_dedupes_ecosystems() -> None:
    yaml = """
version: 2
updates:
  - package-ecosystem: pip
    directory: /a
  - package-ecosystem: pip
    directory: /b
"""
    assert posture.cooldown_missing_ecosystems(yaml) == ("pip",)


def test_cooldown_missing_malformed_yaml_is_empty() -> None:
    assert posture.cooldown_missing_ecosystems("::: not yaml :::") == ()
    assert posture.cooldown_missing_ecosystems("just a string") == ()


# --------------------------------------------------------------------------- #
# Dependabot tables
# --------------------------------------------------------------------------- #
def test_alerts_table_lists_disabled_sorted() -> None:
    postures = [
        posture.RepoPosture(repo=_repo("zeta"), dependabot_alerts=False),
        posture.RepoPosture(repo=_repo("alpha"), dependabot_alerts=False),
        posture.RepoPosture(repo=_repo("on"), dependabot_alerts=True),
        posture.RepoPosture(repo=_repo("dunno"), dependabot_alerts=None),
    ]
    table = posture.build_alerts_table(postures)
    assert table.title == "Alerts Not Enabled"
    assert table.columns == ("Repository",)
    assert [r.repo.name for r in table.rows] == ["alpha", "zeta"]


def test_alerts_table_empty_has_note_only() -> None:
    table = posture.build_alerts_table(
        [posture.RepoPosture(repo=_repo("on"), dependabot_alerts=True)]
    )
    assert table.rows == []
    assert table.empty_note


def test_security_updates_table_lists_disabled_sorted() -> None:
    postures = [
        posture.RepoPosture(repo=_repo("b"), security_updates=False),
        posture.RepoPosture(repo=_repo("a"), security_updates=False),
        posture.RepoPosture(repo=_repo("on"), security_updates=True),
    ]
    table = posture.build_security_updates_table(postures)
    assert table.title == "Dependabot: Security Updates"
    assert table.columns == ("Repositories NOT Enabled",)
    assert [r.repo.name for r in table.rows] == ["a", "b"]


def test_cooldown_table_lists_repos_missing_cooldown() -> None:
    postures = [
        posture.RepoPosture(repo=_repo("a"), cooldown_missing=("pip", "npm")),
        posture.RepoPosture(repo=_repo("b"), cooldown_missing=()),
    ]
    table = posture.build_cooldown_table(postures)
    assert [r.repo.name for r in table.rows] == ["a"]
    assert table.rows[0].cells == ("pip, npm",)


def test_dependabot_tables_order_and_titles() -> None:
    postures = [
        posture.RepoPosture(
            repo=_repo("x"),
            dependabot_alerts=False,
            security_updates=False,
            cooldown_missing=("pip",),
        )
    ]
    tables = posture.build_dependabot_tables(postures)
    assert [t.title for t in tables] == [
        "Alerts Not Enabled",
        "Dependabot: Security Updates",
        "Dependabot: Cooldown Settings",
    ]


# --------------------------------------------------------------------------- #
# is_release_excluded
# --------------------------------------------------------------------------- #
def test_release_excluded_by_name() -> None:
    assert posture.is_release_excluded(
        _repo("tooling"), generated_at=NOW, min_age_days=28, exclude=("tooling",)
    )


def test_release_excluded_when_young() -> None:
    assert posture.is_release_excluded(
        _repo("fresh", age_days=5), generated_at=NOW, min_age_days=28, exclude=()
    )


def test_release_not_excluded_when_old_enough() -> None:
    assert not posture.is_release_excluded(
        _repo("mature", age_days=400), generated_at=NOW, min_age_days=28, exclude=()
    )


def test_release_min_age_zero_includes_everything() -> None:
    assert not posture.is_release_excluded(
        _repo("brand-new", age_days=0), generated_at=NOW, min_age_days=0, exclude=()
    )


# --------------------------------------------------------------------------- #
# Releases / Tagging table + hidden compound score
# --------------------------------------------------------------------------- #
def test_releases_table_excludes_young_and_named_repos() -> None:
    postures = [
        posture.RepoPosture(repo=_repo("young", age_days=10)),
        posture.RepoPosture(repo=_repo("skipme", age_days=400)),
        posture.RepoPosture(
            repo=_repo("kept", age_days=400),
            latest_release_at=_ago(50),
            latest_tag_at=_ago(40),
        ),
    ]
    table = posture.build_releases_table(
        postures, generated_at=NOW, min_age_days=28, exclude=("skipme",)
    )
    assert [r.repo.name for r in table.rows] == ["kept"]


def test_releases_table_ranks_by_hidden_compound_score() -> None:
    postures = [
        # release+tag both recent -> low compound (10 + 5 = 15)
        posture.RepoPosture(
            repo=_repo("fresh-ish", age_days=400),
            latest_release_at=_ago(10),
            latest_tag_at=_ago(5),
        ),
        # neither release nor tag -> age counted twice (200 + 200 = 400)
        posture.RepoPosture(repo=_repo("never", age_days=200)),
        # release recent, no tag -> 5 + age(300) = 305
        posture.RepoPosture(
            repo=_repo("no-tag", age_days=300), latest_release_at=_ago(5)
        ),
    ]
    table = posture.build_releases_table(
        postures, generated_at=NOW, min_age_days=28, exclude=()
    )
    # never (400) > no-tag (305) > fresh-ish (15)
    assert [r.repo.name for r in table.rows] == ["never", "no-tag", "fresh-ish"]
    # The compound score is never displayed: only the two age columns appear.
    never = table.rows[0]
    assert never.cells == ("never", "never")


def test_releases_table_age_cells_humanise() -> None:
    postures = [
        posture.RepoPosture(
            repo=_repo("r", age_days=400),
            latest_release_at=NOW,
            latest_tag_at=_ago(1),
        ),
    ]
    table = posture.build_releases_table(
        postures, generated_at=NOW, min_age_days=28, exclude=()
    )
    assert table.rows[0].cells == ("today", "1 day ago")
