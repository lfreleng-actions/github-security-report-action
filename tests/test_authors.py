# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Tests for author classification: automation vs human, insider vs outsider."""

from __future__ import annotations

import pytest

from github_security_report import authors


class TestNormaliseLogin:
    @pytest.mark.parametrize(
        ("login", "expected"),
        [
            ("dependabot[bot]", "dependabot"),
            ("dependabot", "dependabot"),
            ("Dependabot[Bot]", "dependabot"),
            ("ModeSevenIndustrialSolutions", "modesevenindustrialsolutions"),
            # Only a *trailing* marker is stripped, so a login that merely
            # contains the text keeps it.
            ("bot[bot]user", "bot[bot]user"),
            (None, ""),
            ("", ""),
        ],
    )
    def test_lower_cases_and_strips_a_trailing_bot_marker(
        self, login: str | None, expected: str
    ) -> None:
        assert authors.normalise_login(login) == expected

    def test_both_api_surfaces_of_one_bot_compare_equal(self) -> None:
        # GraphQL returns the bare login and REST the suffixed one; the whole
        # point of normalising is that the two forms collapse to one key.
        assert authors.normalise_login("dependabot[bot]") == authors.normalise_login(
            "dependabot"
        )


class TestIsAutomationAuthor:
    @pytest.mark.parametrize(
        "login",
        [
            "dependabot[bot]",
            "renovate[bot]",
            "pre-commit-ci[bot]",
            "github-actions[bot]",
            "allcontributors[bot]",
            "copilot-swe-agent[bot]",
        ],
    )
    def test_known_tools_are_automation(self, login: str) -> None:
        assert authors.is_automation_author(login) is True

    @pytest.mark.parametrize(
        "login",
        ["dependabot", "renovate", "github-actions", "pre-commit-ci"],
    )
    def test_bare_graphql_logins_are_automation(self, login: str) -> None:
        # GraphQL reports an App actor's login without the "[bot]" marker, so
        # the suffix fallthrough alone would miss these entirely.
        assert authors.is_automation_author(login) is True

    def test_an_unknown_bot_is_caught_by_the_suffix(self) -> None:
        # A tool nobody has added to the known set must not be mistaken for an
        # outside human contributor.
        assert authors.is_automation_author("some-future-bot[bot]") is True

    def test_the_graphql_typename_is_authoritative(self) -> None:
        # An App actor whose login carries neither a known name nor the marker
        # is still automation when the API says its type is Bot.
        assert authors.is_automation_author("mystery-app", typename="Bot") is True

    @pytest.mark.parametrize("login", ["Dependabot[Bot]", "DEPENDABOT"])
    def test_matching_ignores_case(self, login: str) -> None:
        assert authors.is_automation_author(login) is True

    @pytest.mark.parametrize("login", ["john-doe", "ModeSevenIndustrialSolutions"])
    def test_humans_are_not_automation(self, login: str) -> None:
        assert authors.is_automation_author(login) is False

    @pytest.mark.parametrize("login", [None, ""])
    def test_a_missing_login_is_not_automation(self, login: str | None) -> None:
        assert authors.is_automation_author(login) is False


class TestIsExternalAuthor:
    @pytest.mark.parametrize("login", [None, ""])
    def test_a_missing_login_is_indeterminate(self, login: str | None) -> None:
        # Nothing to classify, and False would quietly count the author as an
        # insider.
        assert authors.is_external_author(login, association="NONE") is None

    @pytest.mark.parametrize("association", ["NONE", "CONTRIBUTOR"])
    def test_automation_is_never_external_whatever_its_association(
        self, association: str
    ) -> None:
        # Dependabot genuinely reports these associations. Trusting the field
        # here would file every bot pull request as an outside contribution and
        # swamp the column that exists to surface real outside contributors.
        assert (
            authors.is_external_author("dependabot[bot]", association=association)
            is False
        )

    def test_automation_identified_only_by_typename_is_not_external(self) -> None:
        assert (
            authors.is_external_author(
                "mystery-app", association="NONE", typename="Bot"
            )
            is False
        )

    def test_collected_membership_beats_a_contradicting_association(self) -> None:
        # An organisation with private membership reports its own members as
        # NONE to a token without organisation visibility, so the collected
        # membership has to win or the report would depend on the token used.
        assert (
            authors.is_external_author(
                "alice", association="NONE", members=frozenset({"alice"})
            )
            is False
        )

    def test_membership_matching_ignores_case(self) -> None:
        assert (
            authors.is_external_author(
                "ALICE", association="NONE", members=frozenset({"alice"})
            )
            is False
        )

    @pytest.mark.parametrize("association", ["OWNER", "MEMBER", "COLLABORATOR"])
    def test_insider_associations_are_not_external_without_membership(
        self, association: str
    ) -> None:
        # The fallback earns its place here: a repository-level collaborator
        # holds no organisation membership but is still an insider.
        assert authors.is_external_author("alice", association=association) is False

    @pytest.mark.parametrize(
        "association",
        ["CONTRIBUTOR", "FIRST_TIMER", "FIRST_TIME_CONTRIBUTOR", "MANNEQUIN", "NONE"],
    )
    def test_outsider_associations_are_external(self, association: str) -> None:
        assert (
            authors.is_external_author(
                "outsider", association=association, members=frozenset({"alice"})
            )
            is True
        )

    @pytest.mark.parametrize("association", ["SOMETHING_NEW", None, ""])
    def test_an_unrecognised_association_is_indeterminate(
        self, association: str | None
    ) -> None:
        # Guessing which side of the fence a newly introduced association value
        # belongs on would silently mis-count contributions in one direction.
        assert authors.is_external_author("alice", association=association) is None


class TestNormaliseMembers:
    def test_entries_are_normalised_and_lower_cased(self) -> None:
        assert authors.normalise_members(["Dependabot[bot]", "Alice"]) == frozenset(
            {"dependabot", "alice"}
        )

    def test_unusable_entries_are_dropped_rather_than_raising(self) -> None:
        # One malformed entry costs that member's insider status; it must not
        # fail the whole run.
        assert authors.normalise_members(["alice", None, 42, "", "[bot]"]) == frozenset(
            {"alice"}
        )

    @pytest.mark.parametrize("logins", [None, 42, "alice", {"a": 1}])
    def test_a_non_collection_yields_an_empty_set(self, logins: object) -> None:
        # A bare string is iterable but is not a membership list; treating it as
        # one would turn "alice" into five single-character members.
        assert authors.normalise_members(logins) == frozenset()

    @pytest.mark.parametrize("logins", [[], (), set(), frozenset()])
    def test_every_collection_type_is_accepted(self, logins: object) -> None:
        assert authors.normalise_members(logins) == frozenset()

    def test_a_tuple_of_logins_is_accepted(self) -> None:
        assert authors.normalise_members(("Alice", "BOB")) == frozenset(
            {"alice", "bob"}
        )
