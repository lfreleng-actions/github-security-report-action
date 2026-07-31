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
