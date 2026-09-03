# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Tests for the generic secret-scanning pattern vocabulary and its guard."""

from __future__ import annotations

from github_security_report.secret_patterns import (
    AI_DETECTED_SECRET_TYPES,
    EXPLICIT_SECRET_TYPES,
    GENERIC_SECRET_TYPES,
    SECRET_TYPE_FILTER,
    merge_alerts,
    unknown_generic_slugs,
)


def _inventory(*slugs: str) -> dict[str, object]:
    """A pattern-configurations payload listing exactly ``slugs``."""
    return {"provider_pattern_overrides": [{"slug": slug} for slug in slugs]}


class TestSecretTypeVocabulary:
    def test_filter_names_every_pattern(self) -> None:
        # The filter string is what actually reaches GitHub; a pattern named in
        # the tuples but missing from it would go unswept.
        assert SECRET_TYPE_FILTER.split(",") == list(EXPLICIT_SECRET_TYPES)

    def test_documented_generic_patterns_are_all_present(self) -> None:
        # Pinned against GitHub's published list of supported generic patterns.
        # Dropping one silently narrows every sweep, which is the bug this
        # module exists to prevent, so the list is asserted rather than trusted.
        assert set(GENERIC_SECRET_TYPES) == {
            "ec_private_key",
            "generic_private_key",
            "http_basic_authentication_header",
            "http_bearer_authentication_header",
            "mongodb_connection_string",
            "mysql_connection_url",
            "openssh_private_key",
            "pgp_private_key",
            "postgres_connection_string",
            "rsa_private_key",
        }

    def test_ai_detected_patterns_are_requested_too(self) -> None:
        # AI-detected passwords are a category of their own and are excluded
        # from an unfiltered sweep just as the generic patterns are, so a
        # repository leaking only a password would otherwise read as clean.
        assert set(AI_DETECTED_SECRET_TYPES) == {"password"}
        assert set(EXPLICIT_SECRET_TYPES) == set(GENERIC_SECRET_TYPES) | {"password"}


class TestMergeAlerts:
    def test_concatenates_disjoint_batches(self) -> None:
        default = [{"url": "https://api.github.com/a", "number": 1}]
        generic = [{"url": "https://api.github.com/b", "number": 2}]
        assert [a["number"] for a in merge_alerts(default, generic)] == [1, 2]

    def test_deduplicates_an_alert_seen_in_both_sweeps(self) -> None:
        # secret_type filters rather than adds, so the two sweeps should be
        # disjoint -- but that is GitHub's classification to change, and a
        # double-counted alert would inflate an offender's count.
        alert = {"url": "https://api.github.com/a", "number": 1}
        assert merge_alerts([alert], [dict(alert)]) == [alert]

    def test_falls_back_to_repository_and_number(self) -> None:
        # Alert numbers are per repository, so the repository must be part of
        # the key: two repos' alert #1 are different alerts.
        one = {"number": 1, "repository": {"full_name": "o/a"}}
        two = {"number": 1, "repository": {"full_name": "o/b"}}
        assert merge_alerts([one], [two, dict(one)]) == [one, two]

    def test_keeps_alerts_with_no_stable_identity(self) -> None:
        # Dropping a possible leak to tidy the output is the worse failure.
        nameless = [{"secret_type": "generic_private_key"}]
        assert merge_alerts(nameless, [dict(nameless[0])]) == [
            nameless[0],
            nameless[0],
        ]


class TestUnknownGenericSlugs:
    def test_intact_list_reports_nothing(self) -> None:
        assert unknown_generic_slugs(_inventory(*GENERIC_SECRET_TYPES)) == ()

    def test_renamed_pattern_is_reported(self) -> None:
        # GitHub answers an unrecognised secret_type with 200 [], so a rename
        # would silently reinstate the missed-alerts bug. This is the only
        # thing that catches it.
        kept = [s for s in GENERIC_SECRET_TYPES if s != "openssh_private_key"]
        assert unknown_generic_slugs(_inventory(*kept)) == ("openssh_private_key",)

    def test_compares_against_slug_not_token_type(self) -> None:
        # An alert's token_type differs from its filter slug
        # (ec_private_key -> EC_SSH_PRIVATE_KEY), so matching the wrong field
        # would report all ten patterns as unknown.
        payload = {
            "provider_pattern_overrides": [
                {"slug": slug, "token_type": slug.upper() + "_SSH"}
                for slug in GENERIC_SECRET_TYPES
            ]
        }
        assert unknown_generic_slugs(payload) == ()

    def test_unreadable_payloads_report_none(self) -> None:
        # An unreadable check is neither a clean bill of health nor evidence of
        # ten renamed patterns; it must say "cannot tell".
        assert unknown_generic_slugs(None) is None
        assert unknown_generic_slugs({"message": "Not Found"}) is None
        assert unknown_generic_slugs({"provider_pattern_overrides": []}) is None
        assert unknown_generic_slugs({"provider_pattern_overrides": [{"x": 1}]}) is None

    def test_ai_detected_patterns_are_not_checked(self) -> None:
        # They are model-detected, not provider patterns, so they never appear
        # in this inventory. Checking them would warn about a rename on every
        # single run and train operators to ignore the warning.
        assert unknown_generic_slugs(_inventory(*GENERIC_SECRET_TYPES)) == ()
        assert not set(AI_DETECTED_SECRET_TYPES) & set(GENERIC_SECRET_TYPES)
