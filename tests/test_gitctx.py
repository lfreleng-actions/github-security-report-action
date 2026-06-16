# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Tests for git context detection."""

from __future__ import annotations

from github_security_report import gitctx


class TestParseRemoteUrl:
    def test_ssh(self) -> None:
        assert gitctx.parse_remote_url(
            "git@github.com:lfreleng-actions/dependamerge.git"
        ) == (
            "lfreleng-actions",
            "dependamerge",
        )

    def test_ssh_without_suffix(self) -> None:
        assert gitctx.parse_remote_url("git@github.com:o/r") == ("o", "r")

    def test_https(self) -> None:
        assert gitctx.parse_remote_url("https://github.com/o/r.git") == ("o", "r")

    def test_https_without_suffix_trailing_slash(self) -> None:
        assert gitctx.parse_remote_url("https://github.com/o/r/") == ("o", "r")

    def test_non_github_returns_none(self) -> None:
        assert gitctx.parse_remote_url("git@gitlab.com:o/r.git") is None
        assert gitctx.parse_remote_url("https://example.com/o/r") is None
        assert gitctx.parse_remote_url("not a url") is None


class TestDetectRepo:
    def test_prefers_upstream(self) -> None:
        remotes = {
            "upstream": "git@github.com:lfreleng-actions/dependamerge.git",
            "origin": "git@github.com:modeseven/dependamerge.git",
        }
        assert gitctx.detect_repo(remotes.get) == ("lfreleng-actions", "dependamerge")

    def test_falls_back_to_origin(self) -> None:
        remotes = {"origin": "https://github.com/o/r.git"}
        assert gitctx.detect_repo(remotes.get) == ("o", "r")

    def test_skips_non_github_remote(self) -> None:
        remotes = {
            "upstream": "git@gitlab.com:o/r.git",
            "origin": "git@github.com:o/r.git",
        }
        assert gitctx.detect_repo(remotes.get) == ("o", "r")

    def test_none_when_no_qualifying_remote(self) -> None:
        assert gitctx.detect_repo(lambda _name: None) is None
        assert gitctx.detect_repo({"origin": "git@gitlab.com:o/r"}.get) is None
