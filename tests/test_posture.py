# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Tests for the Dependabot-posture and Releases/Tagging report tables."""

from __future__ import annotations

import datetime as dt

from github_security_report import posture
from github_security_report.models import ReleaseRef, Repo

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
    assert table.title == "Dependabot: Security Alerts"
    assert table.columns == ("Repository",)
    assert [r.repo.name for r in table.rows] == ["alpha", "zeta"]
    # The indeterminate (None) repo counts towards neither side of the summary.
    assert table.summary == "2 not enabled, 1 enabled"
    assert table.note


def test_alerts_table_empty_has_note_only() -> None:
    table = posture.build_alerts_table(
        [posture.RepoPosture(repo=_repo("on"), dependabot_alerts=True)]
    )
    assert table.rows == []
    # With nothing disabled the summary drops the zero negative count and the
    # note reads positively.
    assert table.summary == "1 enabled"
    assert table.empty_note == ("All in-scope repositories have this feature enabled.")


def test_alerts_table_empty_with_indeterminate_is_not_assertive() -> None:
    # No repo is explicitly disabled, so the table is empty -- but an
    # indeterminate (None) repo means we cannot claim every repo is enabled.
    table = posture.build_alerts_table(
        [
            posture.RepoPosture(repo=_repo("on"), dependabot_alerts=True),
            posture.RepoPosture(repo=_repo("dunno"), dependabot_alerts=None),
        ]
    )
    assert table.rows == []
    assert table.summary == "1 enabled"
    assert table.empty_note == (
        "No in-scope repository has this feature confirmed disabled."
    )


def test_alerts_table_all_indeterminate_has_no_summary() -> None:
    # Every repo is indeterminate (None), so neither the negative nor the
    # positive count has data. The summary must be empty so renderers omit it
    # rather than printing a misleading "0 enabled".
    table = posture.build_alerts_table(
        [
            posture.RepoPosture(repo=_repo("dunno"), dependabot_alerts=None),
            posture.RepoPosture(repo=_repo("unknown"), dependabot_alerts=None),
        ]
    )
    assert table.rows == []
    assert table.summary == ""


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
    assert table.summary == "2 not enabled, 1 enabled"
    assert table.note


def test_security_updates_table_all_enabled_summary() -> None:
    table = posture.build_security_updates_table(
        [
            posture.RepoPosture(repo=_repo("a"), security_updates=True),
            posture.RepoPosture(repo=_repo("b"), security_updates=True),
        ]
    )
    assert table.rows == []
    assert table.summary == "2 enabled"
    assert table.empty_note == ("All in-scope repositories have this feature enabled.")


def test_security_updates_table_empty_with_indeterminate() -> None:
    # An indeterminate (None) repo with nothing explicitly disabled must not
    # claim that every repo has security updates enabled.
    table = posture.build_security_updates_table(
        [
            posture.RepoPosture(repo=_repo("a"), security_updates=True),
            posture.RepoPosture(repo=_repo("dunno"), security_updates=None),
        ]
    )
    assert table.rows == []
    assert table.summary == "1 enabled"
    assert table.empty_note == (
        "No in-scope repository has this feature confirmed disabled."
    )


def test_cooldown_table_lists_repos_missing_cooldown() -> None:
    postures = [
        posture.RepoPosture(repo=_repo("a"), cooldown_missing=("pip", "npm")),
        posture.RepoPosture(
            repo=_repo("b"), cooldown_missing=(), has_dependabot_config=True
        ),
        # No config at all: counts as neither missing nor with-cooldown.
        posture.RepoPosture(repo=_repo("c"), cooldown_missing=()),
    ]
    table = posture.build_cooldown_table(postures)
    assert [r.repo.name for r in table.rows] == ["a"]
    assert table.rows[0].cells == ("pip, npm",)
    assert table.summary == "1 without cooldown, 1 with cooldown"


def test_cooldown_table_all_with_cooldown_summary() -> None:
    # With nothing missing a cooldown, the zero negative is dropped.
    postures = [
        posture.RepoPosture(
            repo=_repo("a"), cooldown_missing=(), has_dependabot_config=True
        ),
        posture.RepoPosture(
            repo=_repo("b"), cooldown_missing=(), has_dependabot_config=True
        ),
    ]
    table = posture.build_cooldown_table(postures)
    assert table.rows == []
    assert table.summary == "2 with cooldown"
    assert table.empty_note


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
        "Dependabot: Security Alerts",
        "Dependabot: Security Updates",
        "Dependabot: Cooldown Settings",
    ]


# --------------------------------------------------------------------------- #
# is_release_excluded
# --------------------------------------------------------------------------- #
def test_release_excluded_by_name() -> None:
    assert posture.is_release_excluded(
        _repo("tooling"), generated_at=NOW, repo_min_age_days=28, exclude=("tooling",)
    )


def test_release_excluded_when_young() -> None:
    assert posture.is_release_excluded(
        _repo("fresh", age_days=5), generated_at=NOW, repo_min_age_days=28, exclude=()
    )


def test_release_not_excluded_when_old_enough() -> None:
    assert not posture.is_release_excluded(
        _repo("mature", age_days=400),
        generated_at=NOW,
        repo_min_age_days=28,
        exclude=(),
    )


def test_release_min_age_zero_includes_everything() -> None:
    assert not posture.is_release_excluded(
        _repo("brand-new", age_days=0),
        generated_at=NOW,
        repo_min_age_days=0,
        exclude=(),
    )


# --------------------------------------------------------------------------- #
# Releases / Tagging table + staleness ranking
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
        postures, generated_at=NOW, repo_min_age_days=28, exclude=("skipme",)
    )
    assert [r.repo.name for r in table.rows] == ["kept"]


def test_releases_table_ranks_by_staleness_missing_worst() -> None:
    postures = [
        # release + tag both present -> no missing signals (ranks lowest).
        posture.RepoPosture(
            repo=_repo("fresh-ish", age_days=400),
            latest_release_at=_ago(10),
            latest_tag_at=_ago(5),
        ),
        # neither release nor tag -> two missing signals (ranks highest).
        posture.RepoPosture(repo=_repo("never", age_days=200)),
        # release present, no tag -> one missing signal (ranks in the middle).
        posture.RepoPosture(
            repo=_repo("no-tag", age_days=300), latest_release_at=_ago(5)
        ),
    ]
    table = posture.build_releases_table(
        postures, generated_at=NOW, repo_min_age_days=28, exclude=()
    )
    # Ordered by number of missing signals: never (2) > no-tag (1) > fresh-ish.
    assert [r.repo.name for r in table.rows] == ["never", "no-tag", "fresh-ish"]
    # The ranking key is never displayed: only the two age columns appear.
    never = table.rows[0]
    assert never.cells == ("never", "never")


def test_releases_table_never_ranks_top_regardless_of_repo_age() -> None:
    # Regression: a repo with no release and no tag is the worst offender and
    # must rank at the very top, even when it is far younger than repos that do
    # have (old) releases and tags. Repository age gates scope only, never the
    # row ordering.
    postures = [
        posture.RepoPosture(
            repo=_repo("old-but-released", age_days=800),
            latest_release_at=_ago(400),
            latest_tag_at=_ago(400),
        ),
        posture.RepoPosture(repo=_repo("young-never", age_days=40)),
    ]
    table = posture.build_releases_table(
        postures, generated_at=NOW, repo_min_age_days=28, exclude=()
    )
    assert [r.repo.name for r in table.rows] == [
        "young-never",
        "old-but-released",
    ]


def test_releases_table_never_repos_sorted_by_name() -> None:
    # Several repos with neither a release nor a tag all rank at the top and,
    # being tied, fall back to a stable alphabetical order.
    postures = [
        posture.RepoPosture(repo=_repo("zulu", age_days=300)),
        posture.RepoPosture(repo=_repo("alpha", age_days=100)),
        posture.RepoPosture(
            repo=_repo("dated", age_days=400),
            latest_release_at=_ago(90),
            latest_tag_at=_ago(90),
        ),
    ]
    table = posture.build_releases_table(
        postures, generated_at=NOW, repo_min_age_days=28, exclude=()
    )
    assert [r.repo.name for r in table.rows] == ["alpha", "zulu", "dated"]


def test_releases_table_age_cells_humanise() -> None:
    postures = [
        posture.RepoPosture(
            repo=_repo("r", age_days=400),
            latest_release_at=NOW,
            latest_tag_at=_ago(1),
        ),
    ]
    table = posture.build_releases_table(
        postures, generated_at=NOW, repo_min_age_days=28, exclude=()
    )
    assert table.rows[0].cells == ("today", "1 day ago")


def test_releases_table_release_max_age_omits_current_repos() -> None:
    # With a release-age threshold, repos whose newest release OR tag is within
    # the window drop out; stale repos and those with neither remain.
    postures = [
        # newest signal (tag, 20d) within the 60d window -> omitted
        posture.RepoPosture(
            repo=_repo("current", age_days=400),
            latest_release_at=_ago(120),
            latest_tag_at=_ago(20),
        ),
        # newest signal (release, 90d) older than the window -> flagged
        posture.RepoPosture(
            repo=_repo("stale", age_days=400),
            latest_release_at=_ago(90),
            latest_tag_at=_ago(200),
        ),
        # neither a release nor a tag -> always flagged
        posture.RepoPosture(repo=_repo("never", age_days=400)),
    ]
    table = posture.build_releases_table(
        postures,
        generated_at=NOW,
        repo_min_age_days=28,
        release_max_age_days=60,
        exclude=(),
    )
    assert sorted(r.repo.name for r in table.rows) == ["never", "stale"]
    assert "older than 60 day(s)" in table.note


def test_releases_table_release_max_age_boundary_is_inclusive() -> None:
    # A repo whose newest signal is exactly at the threshold counts as current
    # (within the window) and is omitted.
    postures = [
        posture.RepoPosture(
            repo=_repo("edge", age_days=400), latest_release_at=_ago(60)
        ),
    ]
    table = posture.build_releases_table(
        postures,
        generated_at=NOW,
        repo_min_age_days=28,
        release_max_age_days=60,
        exclude=(),
    )
    assert table.rows == []


def test_releases_table_release_max_age_zero_keeps_all_eligible() -> None:
    # The threshold disabled (0) preserves the original behaviour: every
    # eligible repo is listed regardless of how recent its release/tag is.
    postures = [
        posture.RepoPosture(
            repo=_repo("fresh", age_days=400), latest_release_at=_ago(1)
        ),
    ]
    table = posture.build_releases_table(
        postures,
        generated_at=NOW,
        repo_min_age_days=28,
        release_max_age_days=0,
        exclude=(),
    )
    assert [r.repo.name for r in table.rows] == ["fresh"]
    assert "older than" not in table.note


# --------------------------------------------------------------------------- #
# Mutable Releases table
# --------------------------------------------------------------------------- #
def _release(
    tag: str,
    *,
    immutable: bool | None,
    published: int = 0,
    latest: bool = False,
    prerelease: bool = False,
) -> ReleaseRef:
    return ReleaseRef(
        tag=tag,
        immutable=immutable,
        published_at=_ago(published),
        is_latest=latest,
        is_prerelease=prerelease,
    )


def test_mutable_releases_flags_mutable_latest() -> None:
    postures = [
        posture.RepoPosture(
            repo=_repo("docker-save-images-action"),
            latest_release=_release("v0.1.0", immutable=False, latest=True),
            last_published_release=_release("v0.1.0", immutable=False, latest=True),
        ),
    ]
    table = posture.build_mutable_releases_table(postures)
    assert table.title == "Mutable Releases"
    assert table.columns == ("Repository", "Releases")
    assert [r.repo.name for r in table.rows] == ["docker-save-images-action"]
    # The duplicate tag is collapsed and annotated with the latest badge.
    assert table.rows[0].cells == ("v0.1.0 (latest)",)
    assert table.summary == "1 with findings, 0 clean"
    assert table.note == "Recent releases in the repositories above are not immutable."


def test_mutable_releases_lists_newer_prerelease_first() -> None:
    # A newer mutable pre-release ahead of a mutable "Latest" release: both are
    # listed, most-recent first, with only the latest annotated.
    postures = [
        posture.RepoPosture(
            repo=_repo("packer-build-action"),
            latest_release=_release(
                "v0.9.0", immutable=False, published=30, latest=True
            ),
            last_published_release=_release(
                "v1.0.0-alpha1", immutable=False, published=5, prerelease=True
            ),
        ),
    ]
    table = posture.build_mutable_releases_table(postures)
    assert table.rows[0].cells == ("v1.0.0-alpha1, v0.9.0 (latest)",)
    assert table.summary == "1 with findings, 0 clean"


def test_mutable_releases_immutable_latest_is_clean() -> None:
    # An immutable latest with no newer mutable release is not flagged, and is
    # counted as clean.
    postures = [
        posture.RepoPosture(
            repo=_repo("safe"),
            latest_release=_release("v2.0.0", immutable=True, latest=True),
            last_published_release=_release("v2.0.0", immutable=True, latest=True),
        ),
    ]
    table = posture.build_mutable_releases_table(postures)
    assert table.rows == []
    assert table.summary == "1 clean"
    # With no indeterminate repositories the assertive empty note is accurate.
    assert table.empty_note == (
        "Every checked repository's latest and last-published releases are immutable."
    )


def test_mutable_releases_flags_only_mutable_of_the_pair() -> None:
    # An immutable "Latest" with a newer mutable pre-release: only the mutable
    # pre-release is listed, but the repo still counts as a finding.
    postures = [
        posture.RepoPosture(
            repo=_repo("mixed"),
            latest_release=_release(
                "v1.0.0", immutable=True, published=20, latest=True
            ),
            last_published_release=_release(
                "v1.1.0-rc1", immutable=False, published=2, prerelease=True
            ),
        ),
    ]
    table = posture.build_mutable_releases_table(postures)
    assert table.rows[0].cells == ("v1.1.0-rc1",)
    assert table.summary == "1 with findings, 0 clean"


def test_mutable_releases_repo_without_releases_is_neither() -> None:
    # A repo with no releases is counted as neither a finding nor clean.
    postures = [
        posture.RepoPosture(repo=_repo("no-releases")),
        posture.RepoPosture(
            repo=_repo("flagged"),
            latest_release=_release("v1.0.0", immutable=False, latest=True),
        ),
    ]
    table = posture.build_mutable_releases_table(postures)
    assert [r.repo.name for r in table.rows] == ["flagged"]
    assert table.summary == "1 with findings, 0 clean"


def test_mutable_releases_rows_sorted_by_repo_name() -> None:
    postures = [
        posture.RepoPosture(
            repo=_repo("zeta"),
            latest_release=_release("v1", immutable=False, latest=True),
        ),
        posture.RepoPosture(
            repo=_repo("alpha"),
            latest_release=_release("v2", immutable=False, latest=True),
        ),
    ]
    table = posture.build_mutable_releases_table(postures)
    assert [r.repo.name for r in table.rows] == ["alpha", "zeta"]
    assert table.summary == "2 with findings, 0 clean"


def test_mutable_releases_indeterminate_immutable_is_neither() -> None:
    # GitHub's GraphQL ``immutable`` field is nullable; an unknown state
    # (None) must not be coerced into a mutable finding, nor counted clean.
    postures = [
        posture.RepoPosture(
            repo=_repo("unknown"),
            latest_release=_release("v1", immutable=None, latest=True),
        ),
    ]
    table = posture.build_mutable_releases_table(postures)
    assert table.rows == []
    # Neither a finding nor clean -> both counts zero -> no summary rendered.
    assert table.summary == ""
    # The empty note must not over-claim immutability when a checked repo's
    # state is indeterminate; it is softened to a non-assertive statement.
    assert table.empty_note == (
        "No checked repository has a confirmed-mutable latest or "
        "last-published release."
    )


def test_mutable_releases_confirmed_mutable_alongside_unknown_is_flagged() -> None:
    # A confirmed mutable (False) release is still a finding even when the
    # other checked release has an indeterminate immutability state.
    postures = [
        posture.RepoPosture(
            repo=_repo("mixed"),
            latest_release=_release("v2", immutable=False, latest=True),
            last_published_release=_release("v1", immutable=None),
        ),
    ]
    table = posture.build_mutable_releases_table(postures)
    assert [r.repo.name for r in table.rows] == ["mixed"]
    # Only the confirmed-mutable tag is listed; the unknown one is not.
    assert table.rows[0].cells == ("v2 (latest)",)
    assert table.summary == "1 with findings, 0 clean"
