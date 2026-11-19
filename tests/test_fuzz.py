# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Tests for the fuzzing category (ADR-0009)."""

from __future__ import annotations

import datetime as dt

import pytest
from test_collect import FakeClient

from github_security_report import classify, collect, config, report
from github_security_report.classify import RepoFacts
from github_security_report.config import OrgConfig, ReportConfig
from github_security_report.models import Repo, RepoSignal, RepoState, SignalType
from github_security_report.severity import Severity

WHEN = dt.datetime(2026, 6, 16, 9, 0, tzinfo=dt.UTC)


def _repo(name: str = "r") -> Repo:
    return Repo(name, f"o/{name}", f"https://github.com/o/{name}")


def _section(org: report.OrgReport, signal: SignalType) -> report.SignalSection:
    return next(s for s in org.sections if s.signal is signal)


def _fuzz_alert(level: str) -> dict:
    return {
        "tool": {"name": "fuzz"},
        "rule": {"security_severity_level": None, "severity": level},
    }


def _fuzz(
    *,
    tools: frozenset[str] = frozenset(),
    alerts: tuple[dict, ...] = (),
    applicable: bool | None = True,
    status: int = 200,
    alerts_status: int = 200,
    unread: frozenset[str] = frozenset(),
) -> RepoSignal:
    facts = RepoFacts(
        repo=_repo(),
        code_scanning_status=status,
        code_scanning_tools=set(tools),
        code_scanning_unread=unread,
        code_scanning_alerts=list(alerts),
        code_scanning_alerts_status=alerts_status,
        fuzz_applicable=applicable,
    )
    return classify.classify_fuzz(facts)


class TestApplicability:
    def test_matches_linguist_names_case_insensitively(self) -> None:
        from github_security_report.fuzz import fuzz_applicable

        assert fuzz_applicable(("Shell", "Python"), ("python",)) is True
        assert fuzz_applicable(("Shell",), ("Python", "Go")) is False

    def test_unreadable_languages_are_undecided(self) -> None:
        from github_security_report.fuzz import fuzz_applicable

        assert fuzz_applicable(None, ("Python",)) is None


class TestClassify:
    def test_failing_target_is_an_offender(self) -> None:
        # Every fuzz failure is a SARIF error, which sits above the cutoff.
        signal = _fuzz(
            tools=frozenset({"fuzz"}),
            alerts=(_fuzz_alert("error"),),
        )
        assert signal.state is RepoState.OFFENDER
        assert signal.counts.high == 1

    def test_analysis_without_alerts_is_clean(self) -> None:
        assert _fuzz(tools=frozenset({"fuzz"})).state is RepoState.CLEAN

    def test_applicable_repo_without_analysis_is_nagged(self) -> None:
        assert _fuzz(applicable=True).state is RepoState.NAG

    def test_no_fuzzable_language_is_not_applicable(self) -> None:
        signal = _fuzz(applicable=False)
        assert signal.state is RepoState.NOT_APPLICABLE

    def test_unreadable_languages_are_unknown_not_nagged(self) -> None:
        assert _fuzz(applicable=None).state is RepoState.UNKNOWN

    def test_coverage_outranks_the_language_rule(self) -> None:
        # A fuzz analysis proves the job ran, whatever Linguist reports.
        signal = _fuzz(
            applicable=False,
            tools=frozenset({"fuzz"}),
            alerts=(_fuzz_alert("error"),),
        )
        assert signal.state is RepoState.OFFENDER

    @pytest.mark.parametrize("applicable", [True, False, None])
    @pytest.mark.parametrize("status", [200, 403, 503])
    def test_known_failure_outranks_missing_analysis(
        self, applicable: bool | None, status: int
    ) -> None:
        # An alert in hand is a failure whatever the analyses read returned.
        signal = _fuzz(
            applicable=applicable,
            status=status,
            alerts=(_fuzz_alert("error"),),
        )
        assert signal.state is RepoState.OFFENDER
        assert signal.counts.high == 1

    @pytest.mark.parametrize("status", [403, 503, 0])
    def test_unreadable_analyses_are_unknown_not_inapplicable(
        self, status: int
    ) -> None:
        assert _fuzz(applicable=False, status=status).state is RepoState.UNKNOWN

    def test_disabled_code_scanning_is_still_not_applicable(self) -> None:
        signal = _fuzz(applicable=False, status=404)
        assert signal.state is RepoState.NOT_APPLICABLE

    @pytest.mark.parametrize("applicable", [True, False])
    def test_failed_fuzz_probe_is_unknown(self, applicable: bool) -> None:
        # The page omitted fuzz and its filtered probe failed: coverage is
        # unread, so neither Not enabled nor Not applicable may be claimed.
        signal = _fuzz(applicable=applicable, unread=frozenset({"fuzz"}))
        assert signal.state is RepoState.UNKNOWN

    def test_another_tools_failed_probe_leaves_fuzz_alone(self) -> None:
        signal = _fuzz(applicable=False, unread=frozenset({"aislop"}))
        assert signal.state is RepoState.NOT_APPLICABLE

    @pytest.mark.parametrize("applicable", [True, False, None])
    @pytest.mark.parametrize(
        ("alerts_status", "state"),
        [(200, RepoState.CLEAN), (403, RepoState.UNKNOWN), (503, RepoState.UNKNOWN)],
    )
    def test_sub_cutoff_alert_proves_coverage(
        self, applicable: bool | None, alerts_status: int, state: RepoState
    ) -> None:
        # A fuzz alert below the cutoff still shows the job ran here, so the
        # repository is classified from its alert read, never nagged or
        # dismissed as Not applicable.
        signal = _fuzz(
            applicable=applicable,
            alerts=(_fuzz_alert("note"),),
            alerts_status=alerts_status,
        )
        assert signal.state is state
        assert signal.counts.total == 1

    def test_classify_repo_emits_a_fuzz_signal(self) -> None:
        facts = RepoFacts(repo=_repo(), code_scanning_status=200)
        signals = {s.signal for s in classify.classify_repo(facts)}
        assert SignalType.FUZZ in signals


class TestReport:
    def test_section_sits_after_codeql(self) -> None:
        order = list(report.SIGNAL_ORDER)
        assert order.index(SignalType.FUZZ) == order.index(SignalType.CODEQL) + 1

    def test_footer_counts_not_applicable_repositories(self) -> None:
        signals = [
            RepoSignal(_repo("a"), SignalType.FUZZ, RepoState.CLEAN),
            RepoSignal(_repo("b"), SignalType.FUZZ, RepoState.NOT_APPLICABLE),
            RepoSignal(_repo("c"), SignalType.FUZZ, RepoState.NOT_APPLICABLE),
        ]
        org = report.build_org_report("o", signals, repo_count=3, generated_at=WHEN)
        fuzz = _section(org, SignalType.FUZZ)
        assert fuzz.not_applicable_count == 2
        assert fuzz.nag_repos == []
        lines = report.build_summary(fuzz.summary_counts())
        assert [(line.kind, line.text) for line in lines] == [
            ("pass", "1 Clean"),
            ("na", "2 Not applicable"),
        ]

    def test_other_sections_show_no_not_applicable_line(self) -> None:
        section = report.SignalSection(signal=SignalType.AISLOP, clean_count=3)
        lines = report.build_summary(section.summary_counts())
        assert [line.text for line in lines] == ["All Clean"]


class TestConfig:
    def test_fuzz_languages_default_and_override(self) -> None:
        minimal = {"organizations": [{"name": "o"}]}
        assert config.build_config(minimal).report.fuzz_languages == ("Python", "Go")
        data = {
            "report": {"fuzz_languages": ["Rust"]},
            "organizations": [
                {"name": "o", "report": {"fuzz_languages": ["Go"]}},
                {"name": "p"},
            ],
        }
        cfg = config.build_config(data)
        assert cfg.organizations[0].report.fuzz_languages == ("Go",)
        assert cfg.organizations[1].report.fuzz_languages == ("Rust",)

    def test_rejects_an_empty_language_name(self) -> None:
        with pytest.raises(config.ConfigError) as caught:
            config.build_config(
                {"report": {"fuzz_languages": [""]}, "organizations": [{"name": "o"}]}
            )
        assert "unknown key" not in str(caught.value)

    def test_fuzz_takes_per_category_keys(self) -> None:
        from github_security_report.categories import CategoryKey

        data = {
            "report": {"categories": {"fuzz": {"fail_severity": "low"}}},
            "organizations": [{"name": "o"}],
        }
        rc = config.build_config(data).organizations[0].report
        assert rc.fail_severity_for(CategoryKey.FUZZ) is Severity.LOW


class TestCollect:
    async def test_unsupported_fuzz_is_gated(self) -> None:
        # No fuzz evidence anywhere, so the section is skipped.
        org = await collect.collect_org(
            FakeClient(), OrgConfig(name="o"), ReportConfig(), generated_at=WHEN
        )
        assert _section(org, SignalType.FUZZ).skipped is True

    async def test_applicability_follows_languages(self) -> None:
        # A repository with no fuzzable language is Not applicable, and one
        # with a fuzzable language but no analysis is nagged.
        client = FakeClient()
        client.languages = {
            "dependamerge": ("Python", "Shell"),
            "git-configure-action": ("Shell",),
        }
        org = await collect.collect_org(
            client, OrgConfig(name="o"), ReportConfig(gating=False), generated_at=WHEN
        )
        fuzz = _section(org, SignalType.FUZZ)
        assert [r.name for r in fuzz.nag_repos] == ["dependamerge"]
        assert fuzz.not_applicable_count == 1

    async def test_failed_fuzz_probe_is_unknown_not_inapplicable(self) -> None:
        client = FakeClient()
        client.languages = {
            "dependamerge": ("Python",),
            "git-configure-action": ("Shell",),
        }
        client.unread_tools = {
            "dependamerge": frozenset({"fuzz"}),
            "git-configure-action": frozenset({"fuzz"}),
        }
        org = await collect.collect_org(
            client, OrgConfig(name="o"), ReportConfig(gating=False), generated_at=WHEN
        )
        fuzz = _section(org, SignalType.FUZZ)
        assert fuzz.nag_repos == []
        assert fuzz.not_applicable_count == 0
        assert fuzz.unknown_count == 2

    async def test_unreadable_languages_are_unknown(self) -> None:
        org = await collect.collect_org(
            FakeClient(),
            OrgConfig(name="o"),
            ReportConfig(gating=False),
            generated_at=WHEN,
        )
        fuzz = _section(org, SignalType.FUZZ)
        assert fuzz.nag_repos == []
        assert fuzz.unknown_count == 2


class TestMalformedProbe:
    def test_malformed_fuzz_probe_leaves_other_tools_alone(self) -> None:
        # Only the tool whose probe was malformed is unknown; CodeQL, which
        # the page settled, is still classified from its alerts.
        facts = RepoFacts(
            repo=_repo(),
            code_scanning_tools={"CodeQL"},
            code_scanning_unread=frozenset({"fuzz"}),
            code_scanning_malformed=frozenset({"fuzz"}),
            code_scanning_alerts=[
                {
                    "tool": {"name": "CodeQL"},
                    "rule": {"security_severity_level": "high"},
                }
            ],
            fuzz_applicable=True,
        )
        by_signal = {s.signal: s for s in classify.classify_repo(facts)}
        assert by_signal[SignalType.CODEQL].state is RepoState.OFFENDER
        assert by_signal[SignalType.FUZZ].state is RepoState.UNKNOWN

    def test_malformed_probe_is_unknown_for_its_own_tool(self) -> None:
        facts = RepoFacts(
            repo=_repo(),
            code_scanning_unread=frozenset({"zizmor"}),
            code_scanning_malformed=frozenset({"zizmor"}),
        )
        signal = classify.classify_zizmor(facts)
        assert signal.state is RepoState.UNKNOWN

    def test_malformed_scorecard_probe_is_unknown(self) -> None:
        # The page showed only CodeQL and the external API has no score, so
        # the malformed Scorecard probe is the only evidence left: unknown.
        facts = RepoFacts(
            repo=_repo(),
            code_scanning_tools={"CodeQL"},
            code_scanning_unread=frozenset({"Scorecard"}),
            code_scanning_malformed=frozenset({"Scorecard"}),
            scorecard_status=404,
        )
        signal = classify.classify_scorecard(facts)
        assert signal.state is RepoState.UNKNOWN

    def test_external_score_outranks_malformed_scorecard_probe(self) -> None:
        facts = RepoFacts(
            repo=_repo(),
            code_scanning_unread=frozenset({"Scorecard"}),
            code_scanning_malformed=frozenset({"Scorecard"}),
            scorecard_status=200,
            scorecard_score=10.0,
        )
        signal = classify.classify_scorecard(facts)
        assert signal.state is RepoState.CLEAN
