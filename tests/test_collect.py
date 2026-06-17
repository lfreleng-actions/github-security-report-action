# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Tests for org-mode orchestration, using a fake (in-memory) client."""

from __future__ import annotations

import datetime as dt

from github_security_report import collect
from github_security_report.config import OrgConfig, ReportConfig
from github_security_report.models import Repo, RepoState, SignalType

WHEN = dt.datetime(2026, 6, 16, 9, 0, tzinfo=dt.timezone.utc)


def _repo(name: str, **flags: bool) -> Repo:
    return Repo(
        name,
        f"o/{name}",
        f"https://github.com/o/{name}",
        archived=flags.get("archived", False),
        fork=flags.get("fork", False),
    )


def _cs_alert(repo: str, tool: str, sev: str) -> dict:
    return {
        "repository": {"name": repo},
        "tool": {"name": tool},
        "rule": {"security_severity_level": sev},
    }


class FakeClient:
    """In-memory stand-in satisfying ClientProtocol."""

    def __init__(self) -> None:
        self.repos = [
            _repo("dependamerge"),
            _repo("a-fork", fork=True),
            _repo("git-configure-action"),
        ]
        self.bulk = {
            "code-scanning": [
                _cs_alert("dependamerge", "Scorecard", "high"),
                _cs_alert("dependamerge", "CodeQL", "critical"),
            ],
            "dependabot": [],
            "secret-scanning": [],
        }
        self.tools = {
            "dependamerge": {"CodeQL", "Scorecard"},
            "git-configure-action": {"CodeQL"},
        }
        self.scores = {"dependamerge": 8.2}

    async def list_org_repos(self, org: str) -> list[Repo]:
        return self.repos

    async def org_bulk_alerts(self, org: str, kind: str) -> list[dict]:
        return self.bulk[kind]

    async def org_workflow_rulesets(self, org: str) -> tuple[int, list[dict]]:
        # A zizmor ruleset enforcing the central workflow on every repo.
        return 200, [
            {
                "name": "Zizmor scans",
                "enforcement": "active",
                "target": "branch",
                "conditions": {"repository_name": {"include": ["*"], "exclude": []}},
                "rules": [
                    {
                        "type": "workflows",
                        "parameters": {
                            "workflows": [
                                {
                                    "path": ".github/workflows/zizmor.yaml",
                                    "ref": "refs/heads/main",
                                }
                            ]
                        },
                    }
                ],
            }
        ]

    async def code_scanning_tools(self, org: str, repo: str) -> tuple[int, set[str]]:
        return 200, self.tools.get(repo, set())

    async def secret_scanning_status(self, org: str, repo: str) -> int:
        return 200

    async def dependabot_enabled(self, org: str, repo: str) -> bool | None:
        return True

    async def scorecard_score(self, org: str, repo: str) -> tuple[int, float | None]:
        if repo in self.scores:
            return 200, self.scores[repo]
        return 404, None


def _sections(org_report: object) -> dict[SignalType, object]:
    return {s.signal: s for s in org_report.sections}


async def test_collect_org_end_to_end() -> None:
    report = await collect.collect_org(
        FakeClient(),
        OrgConfig(name="o"),
        ReportConfig(),
        generated_at=WHEN,
    )
    # The fork is excluded; two repos remain in scope.
    assert report.repo_count == 2
    sections = _sections(report)

    # dependamerge has a critical CodeQL alert -> CodeQL offender.
    codeql = sections[SignalType.CODEQL]
    assert [s.repo.name for s in codeql.offenders] == ["dependamerge"]
    assert codeql.offenders[0].counts.critical == 1
    # git-configure-action has CodeQL enabled, no alerts -> contributes to clean.
    assert codeql.clean_count == 1

    # dependamerge has scorecard 8.2 -> offender; git-configure-action 404 -> nag.
    scorecard = sections[SignalType.SCORECARD]
    assert scorecard.offenders[0].score == 8.2
    assert "git-configure-action" in [r.name for r in scorecard.nag_repos]

    # The zizmor ruleset covers both repos, so neither is nagged for zizmor
    # even though zizmor is not in their per-repo analyses tools.
    zizmor = sections[SignalType.ZIZMOR]
    assert zizmor.nag_repos == []
    assert zizmor.clean_count == 2


async def test_collect_org_groups_alerts_by_repo() -> None:
    report = await collect.collect_org(
        FakeClient(), OrgConfig(name="o"), ReportConfig(), generated_at=WHEN
    )
    scorecard = _sections(report)[SignalType.SCORECARD]
    # dependamerge Scorecard offender carries its high finding.
    dep = next(s for s in scorecard.offenders if s.repo.name == "dependamerge")
    assert dep.counts.high == 1
    assert dep.state is RepoState.OFFENDER


class FakeRepoClient:
    """Per-repo client stand-in modelling the dependamerge fork mixed state."""

    async def get_repo(self, org: str, repo: str) -> Repo | None:
        if repo == "missing":
            return None
        return _repo(repo)

    async def code_scanning_tools(self, org: str, repo: str) -> tuple[int, set[str]]:
        return 200, {"CodeQL", "Scorecard"}

    async def repo_code_scanning_alerts(
        self, org: str, repo: str
    ) -> tuple[int, list[dict]]:
        return 200, [_cs_alert(repo, "CodeQL", "high")]

    async def repo_secret_scanning(self, org: str, repo: str) -> tuple[int, int]:
        return 404, 0  # disabled on the fork

    async def dependabot_enabled(self, org: str, repo: str) -> bool | None:
        return False  # disabled on the fork

    async def repo_dependabot_alerts(
        self, org: str, repo: str
    ) -> tuple[int, list[dict]]:
        return 200, []

    async def repo_branch_rules(
        self, org: str, repo: str, branch: str
    ) -> tuple[int, list[dict]]:
        # zizmor is enforced for this repo via an inherited org ruleset.
        return 200, [
            {
                "type": "workflows",
                "parameters": {
                    "workflows": [{"path": ".github/workflows/zizmor.yaml"}]
                },
            }
        ]

    async def scorecard_score(self, org: str, repo: str) -> tuple[int, float | None]:
        return 200, 6.1


async def test_collect_repo_mixed_state() -> None:
    repo, signals = await collect.collect_repo(FakeRepoClient(), "o", "dependamerge")
    assert repo is not None
    by_signal = {s.signal: s for s in signals}
    assert (
        by_signal[SignalType.CODEQL].state is RepoState.OFFENDER
    )  # a high CodeQL alert
    assert by_signal[SignalType.SECRET_SCANNING].state is RepoState.NAG  # 404 disabled
    assert by_signal[SignalType.DEPENDABOT].state is RepoState.NAG  # disabled
    assert by_signal[SignalType.SCORECARD].score == 6.1
    # zizmor is enforced via the branch ruleset, so it is clean (enabled, no
    # zizmor findings) rather than nagged.
    assert by_signal[SignalType.ZIZMOR].state is RepoState.CLEAN


async def test_collect_repo_unreadable_returns_none() -> None:
    repo, signals = await collect.collect_repo(FakeRepoClient(), "o", "missing")
    assert repo is None
    assert signals == []
