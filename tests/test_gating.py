# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Tests for organisation feature gating of the workflow-driven signals."""

from __future__ import annotations

from github_security_report import gating
from github_security_report.config import DEFAULT_RULESET_WORKFLOWS
from github_security_report.models import Repo, SignalType
from github_security_report.rulesets import WorkflowRuleset


def _repo(name: str) -> Repo:
    return Repo(name, f"o/{name}", f"https://github.com/o/{name}")


def _cs_alert(tool: str) -> dict:
    return {"repository": {"name": "r"}, "tool": {"name": tool}}


def _zizmor_ruleset() -> WorkflowRuleset:
    return WorkflowRuleset(
        name="Zizmor scans",
        workflow_paths=(".github/workflows/zizmor.yaml",),
        include=("*",),
        exclude=(),
    )


class GateClient:
    """In-memory gate probe client."""

    def __init__(
        self,
        analyses: dict[str, set[str]] | None = None,
        scores: dict[str, float] | None = None,
    ) -> None:
        self.analyses = analyses or {}
        self.scores = scores or {}
        self.tool_probes: list[tuple[str, str]] = []
        self.score_probes: list[str] = []

    async def code_scanning_tool_present(self, org: str, repo: str, tool: str) -> bool:
        self.tool_probes.append((repo, tool))
        return tool in self.analyses.get(repo, set())

    async def scorecard_score(self, org: str, repo: str) -> tuple[int, float | None]:
        self.score_probes.append(repo)
        if repo in self.scores:
            return 200, self.scores[repo]
        return 404, None


async def _gate(
    client: GateClient,
    repos: list[Repo],
    *,
    rulesets: list[WorkflowRuleset] | None = None,
    alerts: list[dict] | None = None,
) -> dict[SignalType, gating.GateResult]:
    return await gating.gate_signals(
        client,
        "o",
        repos,
        workflow_rulesets=rulesets or [],
        code_scanning_alerts=alerts or [],
        ruleset_workflows=DEFAULT_RULESET_WORKFLOWS,
    )


async def test_alert_evidence_supports_without_probing() -> None:
    client = GateClient()
    alerts = [_cs_alert("aislop"), _cs_alert("zizmor"), _cs_alert("fuzz")]
    results = await _gate(client, [_repo("a")], alerts=alerts)
    assert results[SignalType.AISLOP].supported
    assert results[SignalType.ZIZMOR].supported
    assert results[SignalType.FUZZ].supported
    # zizmor/aislop/fuzz were decided for free; only Scorecard needed a probe.
    assert all(tool == "Scorecard" for _, tool in client.tool_probes)


async def test_ruleset_evidence_supports_zizmor() -> None:
    client = GateClient()
    results = await _gate(client, [_repo("a")], rulesets=[_zizmor_ruleset()])
    assert results[SignalType.ZIZMOR].supported
    assert results[SignalType.ZIZMOR].evidence == "org ruleset"
    # No aislop evidence anywhere -> skipped.
    assert not results[SignalType.AISLOP].supported


async def test_sampled_analyses_evidence_supports() -> None:
    client = GateClient(analyses={"b": {"aislop"}})
    results = await _gate(client, [_repo("a"), _repo("b")])
    assert results[SignalType.AISLOP].supported
    assert results[SignalType.AISLOP].evidence == "analyses on b"


async def test_external_scorecard_evidence_supports() -> None:
    client = GateClient(scores={"a": 7.5})
    results = await _gate(client, [_repo("a")])
    assert results[SignalType.SCORECARD].supported
    assert results[SignalType.SCORECARD].evidence == "external score for a"
    # The external API is a Scorecard-only fallback; aislop stays unsupported.
    assert not results[SignalType.AISLOP].supported


async def test_no_evidence_skips_every_gated_signal() -> None:
    results = await _gate(GateClient(), [_repo("a")])
    assert {s for s, r in results.items() if not r.supported} == set(
        gating.GATED_SIGNALS
    )


async def test_no_repos_means_no_probes_and_unsupported() -> None:
    client = GateClient()
    results = await _gate(client, [])
    assert client.tool_probes == []
    assert client.score_probes == []
    assert not any(r.supported for r in results.values())


async def test_sample_is_bounded() -> None:
    client = GateClient()
    repos = [_repo(f"r{i}") for i in range(50)]
    await _gate(client, repos)
    probed = {name for name, _ in client.tool_probes}
    assert len(probed) <= gating.SAMPLE_SIZE


async def test_sample_spans_later_repos() -> None:
    # r49 is the last repo; a first-N (or tail-excluding) sample would miss it,
    # but the endpoint-inclusive spread sample probes it and finds the tool.
    client = GateClient(analyses={"r49": {"aislop"}})
    repos = [_repo(f"r{i}") for i in range(50)]
    results = await _gate(client, repos)
    assert results[SignalType.AISLOP].supported
    assert results[SignalType.AISLOP].evidence == "analyses on r49"


def test_spread_sample_is_evenly_spaced_and_bounded() -> None:
    repos = [_repo(f"r{i}") for i in range(50)]
    sample = gating._spread_sample(repos, 10)
    # Endpoint-inclusive spacing always spans the first and last repo.
    assert [r.name for r in sample] == [
        f"r{i}" for i in (0, 5, 11, 16, 22, 27, 33, 38, 44, 49)
    ]
    assert sample[0].name == "r0"
    assert sample[-1].name == "r49"
    # Fewer repos than the sample size returns them all unchanged.
    assert gating._spread_sample(repos[:3], 10) == repos[:3]
    assert gating._spread_sample(repos, 0) == []
