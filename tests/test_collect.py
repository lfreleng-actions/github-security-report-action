# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Tests for org-mode orchestration, using a fake (in-memory) client."""

from __future__ import annotations

import datetime as dt
import logging

import pytest

from github_security_report import collect, pulls
from github_security_report.config import OrgConfig, ReportConfig
from github_security_report.models import Repo, RepoGraphData, RepoState, SignalType
from github_security_report.report import OrgReport, SignalSection

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
        self.members: set[str] = {"insider"}
        self.viewer: str = "insider"

    async def list_org_repos(self, org: str) -> tuple[int, list[Repo]]:
        return 200, self.repos

    async def org_members(self, org: str) -> frozenset[str]:
        return frozenset(self.members)

    async def viewer_login(self) -> str:
        return self.viewer

    async def org_bulk_alerts(self, org: str, kind: str) -> tuple[int, list[dict]]:
        return 200, self.bulk[kind]

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

    async def code_scanning_tools(
        self, org: str, repo: str, tools: tuple[str, ...] | None = None
    ) -> tuple[int, set[str]]:
        found = self.tools.get(repo, set())
        if tools is not None:
            found = found & set(tools)
        return 200, found

    async def code_scanning_tool_present(self, org: str, repo: str, tool: str) -> bool:
        return tool in self.tools.get(repo, set())

    async def secret_scanning_status(self, org: str, repo: str) -> int:
        return 200

    async def dependabot_enabled(self, org: str, repo: str) -> bool | None:
        return True

    async def scorecard_score(self, org: str, repo: str) -> tuple[int, float | None]:
        if repo in self.scores:
            return 200, self.scores[repo]
        return 404, None

    async def automated_security_fixes(self, org: str, repo: str) -> bool | None:
        return True

    async def private_vulnerability_reporting(self, org: str, repo: str) -> bool | None:
        return True

    async def dependabot_config(self, org: str, repo: str) -> tuple[int, str]:
        return 404, ""  # no Dependabot configuration by default

    async def latest_release_at(self, org: str, repo: str) -> dt.datetime | None:
        return None

    async def latest_tag_at(self, org: str, repo: str) -> dt.datetime | None:
        return None

    async def repo_graph_batch(
        self, org: str, names: list[str]
    ) -> dict[str, RepoGraphData]:
        # Assemble the batched prefetch result from the per-repo helper methods
        # above, so subclasses overriding those helpers flow through unchanged.
        out: dict[str, RepoGraphData] = {}
        for name in names:
            cfg_status, cfg_text = await self.dependabot_config(org, name)
            out[name] = RepoGraphData(
                dependabot_alerts_enabled=await self.dependabot_enabled(org, name),
                latest_tag_at=await self.latest_tag_at(org, name),
                latest_release_at=await self.latest_release_at(org, name),
                dependabot_config=cfg_text if cfg_status == 200 else None,
            )
        return out


def _sections(org_report: OrgReport) -> dict[SignalType, SignalSection]:
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


async def test_collect_org_gates_unsupported_aislop() -> None:
    # The default fake has no aislop evidence anywhere (no alerts, no ruleset,
    # no analyses), so feature gating skips the signal: its section is marked
    # skipped, and no repository is classified (or nagged) for it.
    report = await collect.collect_org(
        FakeClient(), OrgConfig(name="o"), ReportConfig(), generated_at=WHEN
    )
    aislop = _sections(report)[SignalType.AISLOP]
    assert aislop.skipped is True
    assert aislop.offenders == []
    assert aislop.nag_repos == []
    assert aislop.clean_count == 0
    # Supported signals are untouched.
    assert _sections(report)[SignalType.ZIZMOR].skipped is False


async def test_collect_org_gating_disabled_probes_everything() -> None:
    # report.gating=false restores the old behaviour: aislop is probed per
    # repo, found nowhere, and every in-scope repo is nagged.
    report = await collect.collect_org(
        FakeClient(),
        OrgConfig(name="o"),
        ReportConfig(gating=False),
        generated_at=WHEN,
    )
    aislop = _sections(report)[SignalType.AISLOP]
    assert aislop.skipped is False
    assert {r.name for r in aislop.nag_repos} == {
        "dependamerge",
        "git-configure-action",
    }


async def test_collect_org_aislop_supported_via_alert_evidence() -> None:
    # One aislop alert in the org sweep is support evidence: the signal is
    # collected normally and the alerting repo becomes an offender.
    class AislopClient(FakeClient):
        def __init__(self) -> None:
            super().__init__()
            self.bulk["code-scanning"].append(
                {
                    "repository": {"name": "dependamerge"},
                    "tool": {"name": "aislop"},
                    "rule": {"security_severity_level": None, "severity": "note"},
                }
            )
            self.tools["dependamerge"] = {"CodeQL", "Scorecard", "aislop"}

    report = await collect.collect_org(
        AislopClient(), OrgConfig(name="o"), ReportConfig(), generated_at=WHEN
    )
    aislop = _sections(report)[SignalType.AISLOP]
    assert aislop.skipped is False
    assert [s.repo.name for s in aislop.offenders] == ["dependamerge"]
    assert aislop.offenders[0].counts.low == 1  # note -> low


async def test_collect_org_groups_alerts_by_repo() -> None:
    report = await collect.collect_org(
        FakeClient(), OrgConfig(name="o"), ReportConfig(), generated_at=WHEN
    )
    scorecard = _sections(report)[SignalType.SCORECARD]
    # dependamerge Scorecard offender carries its high finding.
    dep = next(s for s in scorecard.offenders if s.repo.name == "dependamerge")
    assert dep.counts.high == 1
    assert dep.state is RepoState.OFFENDER


async def test_collect_org_degrades_failed_sweep_to_unknown() -> None:
    # When the dependabot org-bulk sweep is unreadable (403), enabled repos
    # with a zero count must be reported as unknown rather than clean.
    class DegradedClient(FakeClient):
        async def org_bulk_alerts(self, org: str, kind: str) -> tuple[int, list[dict]]:
            if kind == "dependabot":
                return 403, []
            return 200, self.bulk[kind]

        async def dependabot_enabled(self, org: str, repo: str) -> bool | None:
            return True  # enabled everywhere, so only the sweep status matters

    report = await collect.collect_org(
        DegradedClient(), OrgConfig(name="o"), ReportConfig(), generated_at=WHEN
    )
    dependabot = _sections(report)[SignalType.DEPENDABOT]
    assert dependabot.offenders == []
    assert dependabot.clean_count == 0  # nothing is asserted clean
    assert dependabot.unknown_count > 0


async def test_collect_org_flags_incomplete_repo_listing() -> None:
    # A non-200 repository listing must mark the org report partial so the
    # renderers can warn that repositories may be missing.
    class PartialListClient(FakeClient):
        async def list_org_repos(self, org: str) -> tuple[int, list[Repo]]:
            return 403, self.repos  # truncated/forbidden listing

    report = await collect.collect_org(
        PartialListClient(), OrgConfig(name="o"), ReportConfig(), generated_at=WHEN
    )
    assert report.partial is True


async def test_collect_org_complete_listing_is_not_partial() -> None:
    report = await collect.collect_org(
        FakeClient(), OrgConfig(name="o"), ReportConfig(), generated_at=WHEN
    )
    assert report.partial is False


async def test_collect_org_tracks_explicitly_excluded_repos() -> None:
    # A repo named in the org exclude list is removed from scope but tracked as
    # explicitly excluded (distinct from the fork dropped by default scoping).
    report = await collect.collect_org(
        FakeClient(),
        OrgConfig(name="o", exclude=("git-configure-action",)),
        ReportConfig(),
        generated_at=WHEN,
    )
    assert [r.name for r in report.excluded_repos] == ["git-configure-action"]
    # It is out of scope, so it is not analysed or nagged.
    assert report.repo_count == 1  # only dependamerge remains (fork also dropped)
    for section in report.sections:
        assert "git-configure-action" not in [r.name for r in section.nag_repos]


class UnreadableRulesetClient(FakeClient):
    """An organisation whose rulesets the token cannot read."""

    ruleset_status = 404

    async def org_workflow_rulesets(self, org: str) -> tuple[int, list[dict]]:
        return self.ruleset_status, []


def _ruleset_logs(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [r for r in caplog.records if "org rulesets" in r.getMessage()]


async def test_collect_org_missing_ruleset_permission_is_not_a_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # Reading org rulesets needs an org-admin permission that the documented
    # minimal tokens deliberately omit, and GitHub answers 404 (not 403) for a
    # token without it. That is the expected, supported configuration, so it
    # must not be reported as a WARNING implying a broken deployment.
    with caplog.at_level(logging.INFO, logger="github_security_report.collect.org"):
        await collect.collect_org(
            UnreadableRulesetClient(),
            OrgConfig(name="o"),
            ReportConfig(),
            generated_at=WHEN,
        )
    records = _ruleset_logs(caplog)
    assert [r.levelno for r in records] == [logging.INFO]
    assert "optional org-admin permission" in records[0].getMessage()


@pytest.mark.parametrize("status", [401, 500])
async def test_collect_org_unexpected_ruleset_failure_still_warns(
    status: int, caplog: pytest.LogCaptureFixture
) -> None:
    # Neither a bad or expired credential (401) nor a server error (5xx) is the
    # documented "token lacks the optional permission" path, so both keep
    # warning: each is a genuine fault worth surfacing.
    class ServerErrorClient(UnreadableRulesetClient):
        ruleset_status = status

    with caplog.at_level(logging.INFO, logger="github_security_report.collect.org"):
        await collect.collect_org(
            ServerErrorClient(),
            OrgConfig(name="o"),
            ReportConfig(),
            generated_at=WHEN,
        )
    records = _ruleset_logs(caplog)
    assert [r.levelno for r in records] == [logging.WARNING]
    assert "unexpectedly" in records[0].getMessage()


async def test_collect_org_readable_rulesets_log_nothing(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.INFO, logger="github_security_report.collect.org"):
        await collect.collect_org(
            FakeClient(), OrgConfig(name="o"), ReportConfig(), generated_at=WHEN
        )
    assert _ruleset_logs(caplog) == []


class FakeRepoClient:
    """Per-repo client stand-in modelling the dependamerge fork mixed state."""

    async def get_repo(self, org: str, repo: str) -> Repo | None:
        if repo == "missing":
            return None
        return _repo(repo)

    async def code_scanning_tools(
        self, org: str, repo: str, tools: tuple[str, ...] | None = None
    ) -> tuple[int, set[str]]:
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


async def test_collect_repo_secret_read_failure_is_unknown() -> None:
    # A non-200 secret-scanning read that returns an empty count must not be
    # reported as an authoritative zero (clean); it degrades to unknown.
    class SecretFailClient(FakeRepoClient):
        async def repo_secret_scanning(self, org: str, repo: str) -> tuple[int, int]:
            return 500, 0  # transient failure, empty count

    repo, signals = await collect.collect_repo(SecretFailClient(), "o", "dependamerge")
    assert repo is not None
    by_signal = {s.signal: s for s in signals}
    assert by_signal[SignalType.SECRET_SCANNING].state is RepoState.UNKNOWN


async def test_collect_repo_honours_custom_ruleset_workflows() -> None:
    # A custom keyword mapping that does not match the ruleset's zizmor.yaml
    # path means the ruleset no longer counts as enabling zizmor, so the repo
    # is nagged instead of clean. Confirms report.ruleset_workflows is honoured
    # in repo mode (not just the built-in default).
    repo, signals = await collect.collect_repo(
        FakeRepoClient(),
        "o",
        "dependamerge",
        ruleset_workflows={"zizmor": "no-such-keyword"},
    )
    assert repo is not None
    by_signal = {s.signal: s for s in signals}
    assert by_signal[SignalType.ZIZMOR].state is RepoState.NAG


class PostureClient(FakeClient):
    """A fake whose Dependabot posture and release/tag probes vary by repo."""

    def __init__(self) -> None:
        super().__init__()
        # git-configure-action has Dependabot alerts disabled; the others on.
        self._alerts = {"dependamerge": True, "git-configure-action": False}
        self._security_updates = {"dependamerge": True, "git-configure-action": False}
        # Private vulnerability reporting: on for dependamerge, off for
        # git-configure-action (so the PVR table has exactly one offender).
        self._pvr = {"dependamerge": True, "git-configure-action": False}
        self._configs = {
            "dependamerge": (
                200,
                "version: 2\nupdates:\n  - package-ecosystem: pip\n",
            ),
        }

    async def dependabot_enabled(self, org: str, repo: str) -> bool | None:
        return self._alerts.get(repo, True)

    async def automated_security_fixes(self, org: str, repo: str) -> bool | None:
        return self._security_updates.get(repo, True)

    async def private_vulnerability_reporting(self, org: str, repo: str) -> bool | None:
        return self._pvr.get(repo, True)

    async def dependabot_config(self, org: str, repo: str) -> tuple[int, str]:
        return self._configs.get(repo, (404, ""))

    async def latest_release_at(self, org: str, repo: str) -> dt.datetime | None:
        return WHEN - dt.timedelta(days=100)

    async def latest_tag_at(self, org: str, repo: str) -> dt.datetime | None:
        return None


async def test_collect_org_attaches_dependabot_tables_and_releases() -> None:
    # Mark the repos old enough to qualify for the Releases/Tagging table.
    class AgedPostureClient(PostureClient):
        def __init__(self) -> None:
            super().__init__()
            old = WHEN - dt.timedelta(days=400)
            self.repos = [
                _repo("dependamerge"),
                _repo("git-configure-action"),
            ]
            self.repos = [
                Repo(r.name, r.full_name, r.html_url, created_at=old)
                for r in self.repos
            ]

    report = await collect.collect_org(
        AgedPostureClient(), OrgConfig(name="o"), ReportConfig(), generated_at=WHEN
    )
    titles = [t.title for t in report.dependabot_tables]
    assert titles == [
        "Dependabot: Alerts Enabled",
        "Dependabot: Security Updates",
        "Dependabot: Cooldown Settings",
    ]

    alerts = report.dependabot_tables[0]
    assert [r.repo.name for r in alerts.rows] == ["git-configure-action"]

    security_updates = report.dependabot_tables[1]
    assert [r.repo.name for r in security_updates.rows] == ["git-configure-action"]

    cooldown = report.dependabot_tables[2]
    assert [r.repo.name for r in cooldown.rows] == ["dependamerge"]  # pip, no cooldown

    # The Dependabot signal nag is moved into the alerts enablement sub-table.
    dependabot = _sections(report)[SignalType.DEPENDABOT]
    assert dependabot.nag_repos == []

    assert report.releases is not None
    # Both repos qualify (old, no tag, stale release) and appear.
    assert {r.repo.name for r in report.releases.rows} == {
        "dependamerge",
        "git-configure-action",
    }

    # The Mutable Releases section is attached (no release data in this fake, so
    # it reports nothing flagged).
    assert report.mutable_releases is not None
    assert report.mutable_releases.title == "Mutable Releases"
    assert report.mutable_releases.rows == []

    # Private Vulnerability Reporting is always collected and attached; the
    # PostureClient fake reports it disabled for git-configure-action only, so
    # that repository is the single offender.
    pvr = report.private_vulnerability_reporting
    assert pvr is not None
    assert pvr.title == "Private Vulnerability Reporting"
    assert [r.repo.name for r in pvr.rows] == ["git-configure-action"]
    assert (pvr.fail_count, pvr.pass_count) == (1, 1)


async def test_collect_org_omits_the_personal_queue_without_a_person() -> None:
    # A bot or App token has no inbox, so an "Assigned to Me" section reporting
    # every repository clean would reassure the reader about a queue that does
    # not exist. The category is left uncollected instead, and no surface has to
    # know why it is missing.
    client = FakeClient()
    client.viewer = ""
    report = await collect.collect_org(
        client, OrgConfig(name="o"), ReportConfig(), generated_at=WHEN
    )
    assert report.assigned_pull_requests is None
    # The objective table survives, keeping only the assignment row such a run
    # can stand behind. The assigned count remains readable as the totals row
    # minus that figure.
    assert report.pull_requests is not None
    assert report.pull_requests.footer_labels == (pulls.UNASSIGNED_ROW,)


async def test_collect_org_attaches_the_personal_queue_for_a_person() -> None:
    report = await collect.collect_org(
        FakeClient(), OrgConfig(name="o"), ReportConfig(), generated_at=WHEN
    )
    assert report.assigned_pull_requests is not None
    assert report.pull_requests is not None
    assert report.pull_requests.footer_labels == pulls.ASSIGNMENT_ROWS


async def test_collect_org_releases_exclude_and_min_age() -> None:
    class AgedPostureClient(PostureClient):
        def __init__(self) -> None:
            super().__init__()
            old = WHEN - dt.timedelta(days=400)
            young = WHEN - dt.timedelta(days=5)
            self.repos = [
                Repo("dependamerge", "o/dependamerge", "u", created_at=old),
                Repo(
                    "git-configure-action",
                    "o/git-configure-action",
                    "u",
                    created_at=young,
                ),
            ]

    report = await collect.collect_org(
        AgedPostureClient(),
        OrgConfig(name="o", releases_exclude=("dependamerge",)),
        ReportConfig(repo_min_age_days=28),
        generated_at=WHEN,
    )
    assert report.releases is not None
    # dependamerge is name-excluded; git-configure-action is too young -> empty.
    assert report.releases.rows == []
