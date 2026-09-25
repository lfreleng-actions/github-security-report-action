# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Tests for repository scoping and exclusions."""

from __future__ import annotations

import pytest

from github_security_report import scope
from github_security_report.models import Repo


def _repo(name: str, **flags: bool) -> Repo:
    return Repo(
        name=name,
        full_name=f"lfreleng-actions/{name}",
        html_url=f"https://github.com/lfreleng-actions/{name}",
        archived=flags.get("archived", False),
        fork=flags.get("fork", False),
        is_template=flags.get("is_template", False),
    )


class TestIsTestNamed:
    def test_matches_delimited_test_segment(self) -> None:
        assert scope.is_test_named("test-action")
        assert scope.is_test_named("my-test-repo")
        assert scope.is_test_named("foo_test")
        assert scope.is_test_named("tags-tests")
        assert scope.is_test_named("a.test.b")

    def test_does_not_match_substring(self) -> None:
        # The crucial anti-false-positive cases.
        assert not scope.is_test_named("latest-tag-action")
        assert not scope.is_test_named("attestation-action")
        assert not scope.is_test_named("contest")
        assert not scope.is_test_named("testify")  # no delimiter


class TestDecide:
    def test_plain_repo_in_scope(self) -> None:
        assert scope.decide(_repo("dependamerge")).included

    def test_fork_excluded(self) -> None:
        d = scope.decide(_repo("x", fork=True))
        assert not d.included and d.reason == "fork"

    def test_template_excluded(self) -> None:
        d = scope.decide(_repo("actions-template", is_template=True))
        assert not d.included and d.reason == "template"

    def test_archived_excluded_by_default_includable(self) -> None:
        assert not scope.decide(_repo("old", archived=True)).included
        assert scope.decide(_repo("old", archived=True), include_archived=True).included

    def test_test_repo_excluded_by_default_includable(self) -> None:
        assert not scope.decide(_repo("test-http-api-tool")).included
        assert scope.decide(_repo("test-http-api-tool"), include_test=True).included

    def test_explicit_exclude(self) -> None:
        d = scope.decide(_repo("noisy"), exclude={"noisy"})
        assert not d.included and d.reason == "explicitly excluded"


class TestFilterRepos:
    def test_filters_and_logs(self, caplog: pytest.LogCaptureFixture) -> None:
        repos = [
            _repo("dependamerge"),
            _repo("a-fork", fork=True),
            _repo("test-tags-semantic"),
            _repo("latest-tag-action"),
        ]
        kept = scope.filter_repos(repos, exclude=())
        assert [r.name for r in kept] == ["dependamerge", "latest-tag-action"]


class TestNagScope:
    def test_archived_and_test_never_nagged(self) -> None:
        assert not scope.in_nag_scope(_repo("old", archived=True))
        assert not scope.in_nag_scope(_repo("test-thing"))

    def test_normal_repo_nagged(self) -> None:
        assert scope.in_nag_scope(_repo("dependamerge"))


# --------------------------------------------------------------------------- #
# Named repository selection (remediate --repos)
# --------------------------------------------------------------------------- #
def test_parse_repo_selection_takes_commas_and_repeats() -> None:
    # Comma-separated, repeatable, whitespace-tolerant, trailing commas
    # ignored, and duplicates (case-insensitively) collapsed in first order.
    refs = scope.parse_repo_selection(["a, b,", " o/c ", "A", "O/C,d"])
    assert [str(ref) for ref in refs] == ["a", "b", "o/c", "d"]
    assert refs[2] == scope.RepoRef(name="c", owner="o")


@pytest.mark.parametrize("bad", ["a/b/c", "/name", "owner/"])
def test_parse_repo_selection_rejects_malformed_names(bad: str) -> None:
    with pytest.raises(scope.RepoSelectionError, match="not a repository name"):
        scope.parse_repo_selection([bad])


def test_parse_repo_selection_of_nothing_selects_nothing() -> None:
    assert scope.parse_repo_selection([]) == ()
    assert scope.parse_repo_selection([" , "]) == ()


def test_repo_ref_matches_case_insensitively_and_by_owner() -> None:
    bare, owned = scope.RepoRef("Dependamerge"), scope.RepoRef("x", owner="LFReleng")
    assert bare.matches("any-org", "dependamerge")
    assert owned.matches("lfreleng", "X")
    assert not owned.matches("other-org", "x")


def test_select_named_keeps_only_the_named_repositories() -> None:
    repos = [_repo("a"), _repo("b"), _repo("c")]
    refs = scope.parse_repo_selection(["c,a,elsewhere/b"])
    assert [r.name for r in scope.select_named("o", repos, refs)] == ["a", "c"]


def test_exclude_matches_case_insensitively() -> None:
    decision = scope.decide(_repo("MyRepo"), exclude=("myrepo",))
    assert (decision.included, decision.reason) == (False, "explicitly excluded")
