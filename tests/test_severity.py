# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Tests for severity parsing and normalisation."""

from __future__ import annotations

from github_security_report import severity
from github_security_report.severity import Severity


class TestOrdering:
    def test_severity_is_ordered_worst_highest(self) -> None:
        assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW

    def test_label(self) -> None:
        assert Severity.CRITICAL.label == "critical"
        assert Severity.LOW.label == "low"


class TestFromName:
    def test_security_names(self) -> None:
        assert severity.from_name("critical") is Severity.CRITICAL
        assert severity.from_name("HIGH") is Severity.HIGH
        assert severity.from_name(" medium ") is Severity.MEDIUM
        assert severity.from_name("low") is Severity.LOW

    def test_dependabot_moderate_maps_to_medium(self) -> None:
        assert severity.from_name("moderate") is Severity.MEDIUM

    def test_unknown_and_empty(self) -> None:
        assert severity.from_name("bogus") is None
        assert severity.from_name("") is None
        assert severity.from_name(None) is None


class TestSarifFallback:
    def test_sarif_levels(self) -> None:
        assert severity.from_sarif_level("error") is Severity.HIGH
        assert severity.from_sarif_level("warning") is Severity.MEDIUM
        assert severity.from_sarif_level("note") is Severity.LOW

    def test_unknown(self) -> None:
        assert severity.from_sarif_level("bogus") is None
        assert severity.from_sarif_level(None) is None


class TestFromCodeScanning:
    def test_prefers_security_severity(self) -> None:
        # zizmor-style: only severity present
        assert severity.from_code_scanning(None, "error") is Severity.HIGH
        # CodeQL/Scorecard-style: security_severity_level wins over severity
        assert severity.from_code_scanning("critical", "warning") is Severity.CRITICAL

    def test_defaults_to_low_when_unrecognised(self) -> None:
        assert severity.from_code_scanning(None, None) is Severity.LOW
        assert severity.from_code_scanning("bogus", "bogus") is Severity.LOW
