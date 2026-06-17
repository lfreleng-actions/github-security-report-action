# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Tests for four-state classification, modelled on the Phase 0 captures."""

from __future__ import annotations

from github_security_report import classify
from github_security_report.classify import RepoFacts
from github_security_report.models import Repo, RepoState, SignalType


def _repo(name: str = "r") -> Repo:
    return Repo(
        name, f"lfreleng-actions/{name}", f"https://github.com/lfreleng-actions/{name}"
    )


def _cs_alert(
    tool: str, security_severity: str | None = None, sarif: str | None = None
) -> dict:
    return {
        "tool": {"name": tool},
        "rule": {"security_severity_level": security_severity, "severity": sarif},
    }


def _by_signal(facts: RepoFacts) -> dict[SignalType, object]:
    return {s.signal: s for s in classify.classify_repo(facts)}


class TestCodeScanningPartition:
    def test_dependamerge_codeql_clean_scorecard_offender(self) -> None:
        # Real shape: 4 Scorecard alerts, 0 CodeQL, CodeQL enabled, score 8.2.
        facts = RepoFacts(
            repo=_repo("dependamerge"),
            code_scanning_status=200,
            code_scanning_tools={"CodeQL", "Scorecard"},
            code_scanning_alerts=[
                _cs_alert("Scorecard", "high"),
                _cs_alert("Scorecard", "medium"),
                _cs_alert("Scorecard", "medium"),
                _cs_alert("Scorecard", "low"),
            ],
            scorecard_status=200,
            scorecard_score=8.2,
        )
        signals = _by_signal(facts)
        # CodeQL enabled but no CodeQL alerts -> clean (not branded an offender).
        assert signals[SignalType.CODEQL].state is RepoState.CLEAN
        # Scorecard has findings + score < 10 -> offender.
        assert signals[SignalType.SCORECARD].state is RepoState.OFFENDER
        assert signals[SignalType.SCORECARD].score == 8.2

    def test_zizmor_uses_sarif_severity_fallback(self) -> None:
        facts = RepoFacts(
            repo=_repo("openstack-cron-action"),
            code_scanning_status=200,
            code_scanning_tools={"Scorecard", "zizmor"},
            code_scanning_alerts=[
                _cs_alert("zizmor", None, "error"),
                _cs_alert("zizmor", None, "warning"),
            ],
        )
        zizmor = _by_signal(facts)[SignalType.ZIZMOR]
        assert zizmor.state is RepoState.OFFENDER
        assert zizmor.counts.high == 1  # error -> high
        assert zizmor.counts.medium == 1  # warning -> medium
        # CodeQL not in tools -> nag.
        assert _by_signal(facts)[SignalType.CODEQL].state is RepoState.NAG


class TestEnabledProbes:
    def test_code_scanning_disabled_is_nag(self) -> None:
        facts = RepoFacts(repo=_repo(), code_scanning_status=404)
        signals = _by_signal(facts)
        assert signals[SignalType.CODEQL].state is RepoState.NAG
        assert signals[SignalType.ZIZMOR].state is RepoState.NAG

    def test_code_scanning_forbidden_is_unknown(self) -> None:
        facts = RepoFacts(repo=_repo(), code_scanning_status=403)
        assert _by_signal(facts)[SignalType.CODEQL].state is RepoState.UNKNOWN

    def test_codeql_enabled_clean(self) -> None:
        facts = RepoFacts(
            repo=_repo(), code_scanning_status=200, code_scanning_tools={"CodeQL"}
        )
        assert _by_signal(facts)[SignalType.CODEQL].state is RepoState.CLEAN

    def test_codeql_offender(self) -> None:
        facts = RepoFacts(
            repo=_repo(),
            code_scanning_status=200,
            code_scanning_tools={"CodeQL"},
            code_scanning_alerts=[_cs_alert("CodeQL", "critical")],
        )
        sig = _by_signal(facts)[SignalType.CODEQL]
        assert sig.state is RepoState.OFFENDER
        assert sig.counts.critical == 1


class TestSecretScanning:
    def test_disabled_404_is_nag(self) -> None:
        facts = RepoFacts(repo=_repo(), secret_scanning_status=404)
        assert _by_signal(facts)[SignalType.SECRET_SCANNING].state is RepoState.NAG

    def test_enabled_clean(self) -> None:
        facts = RepoFacts(
            repo=_repo(), secret_scanning_status=200, secret_scanning_open=0
        )
        assert _by_signal(facts)[SignalType.SECRET_SCANNING].state is RepoState.CLEAN

    def test_offender(self) -> None:
        facts = RepoFacts(
            repo=_repo(), secret_scanning_status=200, secret_scanning_open=3
        )
        sig = _by_signal(facts)[SignalType.SECRET_SCANNING]
        assert sig.state is RepoState.OFFENDER
        assert sig.counts.total == 3

    def test_partial_read_with_open_secrets_is_offender(self) -> None:
        # A non-200 (incomplete) read that still found open secrets is
        # actionable evidence -> offender, not unknown.
        facts = RepoFacts(
            repo=_repo(),
            secret_scanning_status=503,
            secret_scanning_open=2,
            secret_scanning_open_status=503,
        )
        sig = _by_signal(facts)[SignalType.SECRET_SCANNING]
        assert sig.state is RepoState.OFFENDER
        assert sig.counts.total == 2


class TestDependabot:
    def test_disabled_is_nag(self) -> None:
        facts = RepoFacts(repo=_repo(), dependabot_enabled=False)
        assert _by_signal(facts)[SignalType.DEPENDABOT].state is RepoState.NAG

    def test_indeterminate_is_unknown(self) -> None:
        facts = RepoFacts(repo=_repo(), dependabot_enabled=None)
        assert _by_signal(facts)[SignalType.DEPENDABOT].state is RepoState.UNKNOWN

    def test_offender_counts_by_advisory_severity(self) -> None:
        facts = RepoFacts(
            repo=_repo(),
            dependabot_enabled=True,
            dependabot_alerts=[
                {"security_advisory": {"severity": "high"}},
                {"security_advisory": {"severity": "moderate"}},
            ],
        )
        sig = _by_signal(facts)[SignalType.DEPENDABOT]
        assert sig.state is RepoState.OFFENDER
        assert sig.counts.high == 1
        assert sig.counts.medium == 1  # moderate -> medium


class TestForkMixedState:
    def test_dependamerge_fork(self) -> None:
        # CodeQL + Scorecard on (advanced setup), secret scanning + Dependabot off.
        facts = RepoFacts(
            repo=_repo("dependamerge"),
            code_scanning_status=200,
            code_scanning_tools={"CodeQL", "Scorecard"},
            code_scanning_alerts=[_cs_alert("Scorecard", "high")],
            secret_scanning_status=404,
            dependabot_enabled=False,
            scorecard_status=200,
            scorecard_score=6.1,
        )
        signals = _by_signal(facts)
        assert signals[SignalType.CODEQL].state is RepoState.CLEAN
        assert signals[SignalType.SCORECARD].state is RepoState.OFFENDER
        assert signals[SignalType.SECRET_SCANNING].state is RepoState.NAG
        assert signals[SignalType.DEPENDABOT].state is RepoState.NAG


class TestScorecardSources:
    def test_no_scorecard_anywhere_is_nag(self) -> None:
        facts = RepoFacts(
            repo=_repo(),
            code_scanning_status=200,
            code_scanning_tools={"CodeQL"},
            scorecard_status=404,
        )
        assert _by_signal(facts)[SignalType.SCORECARD].state is RepoState.NAG

    def test_falls_back_to_code_scanning_findings(self) -> None:
        facts = RepoFacts(
            repo=_repo(),
            code_scanning_status=200,
            code_scanning_tools={"Scorecard"},
            code_scanning_alerts=[_cs_alert("Scorecard", "medium")],
            scorecard_status=404,
        )
        sig = _by_signal(facts)[SignalType.SCORECARD]
        assert sig.state is RepoState.OFFENDER
        assert sig.score is None

    def test_transient_external_failure_is_unknown(self) -> None:
        # A transport failure to the external Scorecard API surfaces as a 503
        # (via the client's _request); with no code-scanning Scorecard data
        # this is indeterminate, not a nag.
        facts = RepoFacts(
            repo=_repo(),
            code_scanning_status=200,
            code_scanning_tools={"CodeQL"},
            scorecard_status=503,
        )
        assert _by_signal(facts)[SignalType.SCORECARD].state is RepoState.UNKNOWN

    def test_external_403_is_unknown_not_nag(self) -> None:
        # A 403 (forbidden/blocked external Scorecard API) is indeterminate per
        # the module contract, not a definitive "no results" nag.
        facts = RepoFacts(
            repo=_repo(),
            code_scanning_status=200,
            code_scanning_tools={"CodeQL"},
            scorecard_status=403,
        )
        assert _by_signal(facts)[SignalType.SCORECARD].state is RepoState.UNKNOWN


class TestRulesetCoverage:
    def test_covered_with_no_findings_is_clean_not_nag(self) -> None:
        # zizmor isn't in the analyses tools, but a ruleset enforces it -> the
        # repo is enabled (clean), not nagged.
        facts = RepoFacts(
            repo=_repo(),
            code_scanning_status=200,
            code_scanning_tools={"CodeQL"},
            ruleset_signals={"zizmor"},
        )
        assert _by_signal(facts)[SignalType.ZIZMOR].state is RepoState.CLEAN

    def test_covered_with_findings_is_offender(self) -> None:
        facts = RepoFacts(
            repo=_repo(),
            code_scanning_status=200,
            code_scanning_tools={"CodeQL"},
            code_scanning_alerts=[_cs_alert("zizmor", None, "error")],
            ruleset_signals={"zizmor"},
        )
        sig = _by_signal(facts)[SignalType.ZIZMOR]
        assert sig.state is RepoState.OFFENDER
        assert sig.counts.high == 1

    def test_not_covered_and_absent_is_nag(self) -> None:
        facts = RepoFacts(
            repo=_repo(),
            code_scanning_status=200,
            code_scanning_tools={"CodeQL"},
            ruleset_signals=set(),
        )
        assert _by_signal(facts)[SignalType.ZIZMOR].state is RepoState.NAG

    def test_covered_overrides_code_scanning_disabled(self) -> None:
        # Code scanning entirely off, but the ruleset still enforces zizmor.
        facts = RepoFacts(
            repo=_repo(), code_scanning_status=404, ruleset_signals={"zizmor"}
        )
        assert _by_signal(facts)[SignalType.ZIZMOR].state is RepoState.CLEAN
        # CodeQL (not ruleset-covered) is still nagged when code scanning is off.
        assert _by_signal(facts)[SignalType.CODEQL].state is RepoState.NAG


class TestUnreadableAlertSweep:
    """An enabled signal with an unreadable alert read is unknown, not clean."""

    def test_code_scanning_sweep_failure_is_unknown(self) -> None:
        # CodeQL is enabled (analyses present) but the alert sweep returned a
        # non-200 status, so a zero count must not be reported as clean.
        facts = RepoFacts(
            repo=_repo(),
            code_scanning_status=200,
            code_scanning_tools={"CodeQL"},
            code_scanning_alerts=[],
            code_scanning_alerts_status=403,
        )
        assert _by_signal(facts)[SignalType.CODEQL].state is RepoState.UNKNOWN

    def test_code_scanning_sweep_failure_with_findings_is_offender(self) -> None:
        # Partial data (some alerts present) is still actionable evidence.
        facts = RepoFacts(
            repo=_repo(),
            code_scanning_status=200,
            code_scanning_tools={"CodeQL"},
            code_scanning_alerts=[_cs_alert("CodeQL", "high")],
            code_scanning_alerts_status=403,
        )
        assert _by_signal(facts)[SignalType.CODEQL].state is RepoState.OFFENDER

    def test_secret_scanning_sweep_failure_is_unknown(self) -> None:
        facts = RepoFacts(
            repo=_repo(),
            secret_scanning_status=200,
            secret_scanning_open=0,
            secret_scanning_open_status=403,
        )
        assert _by_signal(facts)[SignalType.SECRET_SCANNING].state is RepoState.UNKNOWN

    def test_dependabot_sweep_failure_is_unknown(self) -> None:
        facts = RepoFacts(
            repo=_repo(),
            dependabot_enabled=True,
            dependabot_alerts=[],
            dependabot_alerts_status=502,
        )
        assert _by_signal(facts)[SignalType.DEPENDABOT].state is RepoState.UNKNOWN

    def test_successful_empty_sweep_is_clean(self) -> None:
        # The default status (200) keeps the existing enabled-clean behaviour.
        facts = RepoFacts(
            repo=_repo(),
            code_scanning_status=200,
            code_scanning_tools={"CodeQL"},
            dependabot_enabled=True,
            secret_scanning_status=200,
        )
        signals = _by_signal(facts)
        assert signals[SignalType.CODEQL].state is RepoState.CLEAN
        assert signals[SignalType.DEPENDABOT].state is RepoState.CLEAN
        assert signals[SignalType.SECRET_SCANNING].state is RepoState.CLEAN


class TestIndeterminateProbeStatus:
    """A failed probe (5xx / synthetic 0) is unknown, never a nag or clean."""

    def test_code_scanning_5xx_is_unknown_not_nag(self) -> None:
        facts = RepoFacts(repo=_repo(), code_scanning_status=503)
        assert _by_signal(facts)[SignalType.CODEQL].state is RepoState.UNKNOWN

    def test_code_scanning_zero_is_unknown(self) -> None:
        facts = RepoFacts(repo=_repo(), code_scanning_status=0)
        assert _by_signal(facts)[SignalType.ZIZMOR].state is RepoState.UNKNOWN

    def test_code_scanning_disabled_still_nags(self) -> None:
        # A genuine 404 (feature off) remains a nag, not unknown.
        facts = RepoFacts(repo=_repo(), code_scanning_status=404)
        assert _by_signal(facts)[SignalType.CODEQL].state is RepoState.NAG

    def test_secret_scanning_5xx_is_unknown(self) -> None:
        facts = RepoFacts(repo=_repo(), secret_scanning_status=503)
        assert _by_signal(facts)[SignalType.SECRET_SCANNING].state is RepoState.UNKNOWN
