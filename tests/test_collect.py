# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Tests for org-mode orchestration, using a fake (in-memory) client."""

from __future__ import annotations

import datetime as dt
import logging

import pytest

from github_security_report import collect, layout, pulls
from github_security_report.categories import CategoryKey
from github_security_report.client import GraphBatchError
from github_security_report.codeql import CodeQLConfiguration, DefaultSetup
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
        # "Allow auto-merge" per repository; absent names default to enabled.
        # Unlike the other posture flags this one rides the GraphQL prefetch,
        # so it is set here rather than behind a per-repo helper method.
        self.auto_merge: dict[str, bool] = {}
        # CodeQL scan health: per-repo configurations, default-setup state and
        # the Actions state of each workflow path. Every repository defaults to
        # no CodeQL configurations, so the scan-health tables stay empty unless
        # a test opts in. ``workflow_reads`` records each workflow lookup.
        self.codeql: dict[str, tuple[CodeQLConfiguration, ...]] = {}
        self.default_setup: dict[str, DefaultSetup] = {}
        self.workflows: dict[tuple[str, str], str] = {}
        self.workflow_reads: list[tuple[str, str]] = []
        self.head: dict[str, dt.datetime] = {}

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

    async def codeql_configurations(
        self, org: str, repo: str, branch: str
    ) -> tuple[int, tuple[CodeQLConfiguration, ...]]:
        return 200, self.codeql.get(repo, ())

    async def codeql_default_setup(self, org: str, repo: str) -> DefaultSetup | None:
        return self.default_setup.get(repo, DefaultSetup(configured=False))

    async def workflow_state(self, org: str, repo: str, path: str) -> str | None:
        self.workflow_reads.append((repo, path))
        return self.workflows.get((repo, path))

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
                auto_merge_allowed=self.auto_merge.get(name, True),
                head_committed_at=self.head.get(name, WHEN),
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

    async def repo_secret_scanning(self, org: str, repo: str) -> tuple[int, int, int]:
        return 404, 404, 0  # disabled on the fork

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
        async def repo_secret_scanning(
            self, org: str, repo: str
        ) -> tuple[int, int, int]:
            return 200, 500, 0  # enabled, transient read failure, empty count

    repo, signals = await collect.collect_repo(SecretFailClient(), "o", "dependamerge")
    assert repo is not None
    by_signal = {s.signal: s for s in signals}
    assert by_signal[SignalType.SECRET_SCANNING].state is RepoState.UNKNOWN


async def test_collect_repo_partial_secret_read_with_alerts_is_offender() -> None:
    # Repo scope has no separate enablement probe, so the secret-scanning read
    # reports its two statuses apart. Conflating them would let the forbidden
    # half of a two-pass sweep classify a repository whose other half found
    # alerts as "insufficient permission" -- hiding a known leak behind a
    # permissions error, which is the worst possible way to be wrong here.
    class PartialSecretClient(FakeRepoClient):
        async def repo_secret_scanning(
            self, org: str, repo: str
        ) -> tuple[int, int, int]:
            return 200, 403, 2  # readable endpoint, forbidden half, 2 alerts

    repo, signals = await collect.collect_repo(
        PartialSecretClient(), "o", "dependamerge"
    )
    assert repo is not None
    by_signal = {s.signal: s for s in signals}
    assert by_signal[SignalType.SECRET_SCANNING].state is RepoState.OFFENDER


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
        # Auto-merge: same split, so the Auto-merge table has one offender too.
        self.auto_merge = {"dependamerge": True, "git-configure-action": False}
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

    # Auto-merge rides the batched GraphQL prefetch rather than a probe of its
    # own, so this also confirms the flag survives that route into the table.
    auto_merge = report.auto_merge
    assert auto_merge is not None
    assert auto_merge.title == "Auto-merge"
    assert [r.repo.name for r in auto_merge.rows] == ["git-configure-action"]
    assert (auto_merge.fail_count, auto_merge.pass_count) == (1, 1)


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


# --------------------------------------------------------------------------- #
# Adaptive GraphQL prefetch batching
# --------------------------------------------------------------------------- #
class BatchLimitedClient(FakeClient):
    """A GitHub whose GraphQL endpoint cannot finish a query above ``limit``.

    Models the real failure mode: GitHub bounds per-query execution time, so a
    query carrying too many aliased repositories fails as a whole (a 502 from
    the edge, after the transport's own retries) while the same repositories
    read fine in smaller batches. ``batches`` records the size of every query
    issued, in order, so a test can see the batching policy rather than only
    its outcome. ``splittable`` is what the client would have decided from the
    response; it defaults to the size-failure reading.
    """

    def __init__(
        self,
        repo_count: int,
        *,
        limit: int,
        status: int = 502,
        splittable: bool = True,
        reason: str | None = None,
    ) -> None:
        super().__init__()
        self.repos = [_repo(f"repo-{i:02d}") for i in range(repo_count)]
        self.limit = limit
        self.status = status
        self.splittable = splittable
        self.reason = reason
        self.batches: list[int] = []

    async def repo_graph_batch(
        self, org: str, names: list[str]
    ) -> dict[str, RepoGraphData]:
        self.batches.append(len(names))
        if len(names) > self.limit:
            raise GraphBatchError(
                f"GraphQL prefetch for {org} failed with HTTP {self.status}",
                status=self.status,
                splittable=self.splittable,
                reason=self.reason,
            )
        return await super().repo_graph_batch(org, names)


async def _collect_graph(
    client: BatchLimitedClient, *, batch_size: int
) -> dict[str, RepoGraphData]:
    return await collect.org._collect_graph(
        client, "o", client.repos, batch_size=batch_size
    )


async def test_graph_batch_size_comes_from_the_report_config() -> None:
    client = BatchLimitedClient(10, limit=100)
    await collect.collect_org(
        client, OrgConfig(name="o"), ReportConfig(graph_batch=4), generated_at=WHEN
    )
    assert client.batches == [4, 4, 2]


def test_graph_batch_module_constant_still_importable() -> None:
    # ``collect.GRAPH_BATCH`` was exported before the size became a setting.
    # Kept as a deprecated alias for the built-in default so existing
    # importers keep working, and pinned to the config default so the two
    # cannot drift apart.
    assert collect.GRAPH_BATCH == ReportConfig().graph_batch == 10
    assert "GRAPH_BATCH" in collect.__all__


async def test_graph_batch_halves_on_a_server_error_and_stays_halved(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # GitHub can finish a query of 5 repositories but not 10. The first batch
    # fails and is re-queued at half the size; the rest of this organisation's
    # collection also uses the smaller size, since a slow day at GitHub is a
    # property of the collection rather than of the one batch that happened to
    # hit it first.
    client = BatchLimitedClient(23, limit=5)
    with caplog.at_level(logging.WARNING, logger="github_security_report.collect.org"):
        graph = await _collect_graph(client, batch_size=10)
    assert client.batches == [10, 5, 5, 5, 5, 3]
    assert sorted(graph) == sorted(repo.name for repo in client.repos)
    assert not any(data.unreadable for data in graph.values())
    messages = [r.getMessage() for r in caplog.records]
    assert len(messages) == 1
    assert "HTTP 502" in messages[0]
    assert "batch of 10" in messages[0] and "batches of 5" in messages[0]


async def test_graph_batch_halves_repeatedly_down_to_one() -> None:
    # Only single-repository queries succeed: 8 -> 4 -> 2 -> 1, then every
    # repository is read one at a time rather than the run aborting.
    client = BatchLimitedClient(6, limit=1)
    graph = await _collect_graph(client, batch_size=8)
    assert client.batches == [6, 3, 1, 1, 1, 1, 1, 1]
    assert len(graph) == 6


async def test_graph_batch_of_one_that_still_fails_aborts() -> None:
    # A single-repository query GitHub still cannot answer is not a size
    # problem: the API is unusable, and aborting beats fabricating defaults.
    client = BatchLimitedClient(3, limit=0)
    with pytest.raises(GraphBatchError) as excinfo:
        await _collect_graph(client, batch_size=2)
    assert excinfo.value.status == 502
    assert client.batches == [2, 1]


@pytest.mark.parametrize(
    ("status", "reason"), [(403, None), (429, None), (200, "rate limited")]
)
async def test_graph_batch_does_not_split_on_a_non_size_failure(
    status: int, reason: str | None
) -> None:
    # A permission error or an exhausted rate limit would fail identically at
    # any batch size, so splitting would only multiply the requests: the error
    # propagates from the first batch untouched. The client marks these as
    # not splittable, whatever HTTP status they arrived with -- a GraphQL rate
    # limit is an HTTP 200.
    client = BatchLimitedClient(
        6, limit=1, status=status, splittable=False, reason=reason
    )
    with pytest.raises(GraphBatchError) as excinfo:
        await _collect_graph(client, batch_size=3)
    assert excinfo.value.status == status
    assert client.batches == [3]


async def test_graph_batch_splits_on_a_200_without_data() -> None:
    # GitHub also reports a timed-out query as HTTP 200 with a null ``data``
    # object, which the client surfaces with status 200: that is a size
    # failure too and must be split rather than aborted.
    client = BatchLimitedClient(4, limit=2, status=200)
    graph = await _collect_graph(client, batch_size=4)
    assert client.batches == [4, 2, 2]
    assert len(graph) == 4


async def test_graph_batch_log_names_the_reason_the_client_gave(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # A resource-limit failure arrives as HTTP 200, so "HTTP 200" in the log
    # would read as a success; the client's own phrase is used instead.
    client = BatchLimitedClient(
        4, limit=2, status=200, reason="resource limits exceeded"
    )
    with caplog.at_level(logging.WARNING, logger="github_security_report.collect.org"):
        await _collect_graph(client, batch_size=4)
    assert "failed (resource limits exceeded)" in caplog.records[0].getMessage()


async def test_graph_batch_treats_a_zero_size_as_one() -> None:
    # The CLI and schema both refuse 0, so this is defence in depth: a batch of
    # nothing would otherwise loop forever without reading anything.
    client = BatchLimitedClient(2, limit=5)
    graph = await _collect_graph(client, batch_size=0)
    assert client.batches == [1, 1]
    assert len(graph) == 2


# --------------------------------------------------------------------------- #
# CodeQL scan health
# --------------------------------------------------------------------------- #
_DEFAULT_KEY = "dynamic/github-code-scanning/codeql:analyze"
_ADVANCED_KEY = ".github/workflows/codeql.yml:analyze"


def _codeql_config(language: str, key: str, days_behind: int) -> CodeQLConfiguration:
    prefix = "" if key == _DEFAULT_KEY else f"{key}/build-mode:none"
    return CodeQLConfiguration(
        category=f"{prefix}/language:{language}",
        analysis_key=key,
        last_scan_at=WHEN - dt.timedelta(days=days_behind),
        language=language,
    )


class CodeQLHealthClient(FakeClient):
    """dependamerge swapped default setup for a Python-only workflow.

    git-configure-action went the other way: default setup is live and the old
    advanced workflow, now disabled, left its configuration behind.
    """

    def __init__(self) -> None:
        super().__init__()
        self.codeql = {
            "dependamerge": (
                _codeql_config("python", _ADVANCED_KEY, 0),
                _codeql_config("python", _DEFAULT_KEY, 91),
                _codeql_config("actions", _DEFAULT_KEY, 91),
            ),
            "git-configure-action": (
                _codeql_config("python", _ADVANCED_KEY, 101),
                _codeql_config("python", _DEFAULT_KEY, 1),
            ),
        }
        self.default_setup = {
            "dependamerge": DefaultSetup(
                configured=False, languages=frozenset({"actions", "python"})
            ),
            "git-configure-action": DefaultSetup(
                configured=True, languages=frozenset({"python"})
            ),
        }
        self.workflows = {
            ("git-configure-action", ".github/workflows/codeql.yml"): (
                "disabled_manually"
            ),
        }


async def test_collect_org_attaches_codeql_tables_beneath_the_codeql_signal() -> None:
    client = CodeQLHealthClient()
    report = await collect.collect_org(
        client, OrgConfig(name="o"), ReportConfig(), generated_at=WHEN
    )
    stale, coverage = report.codeql_tables
    assert stale.category.key is CategoryKey.CODEQL_STALE_CONFIGURATIONS
    assert [(r.repo.name, r.cells[-1]) for r in stale.rows] == [
        ("git-configure-action", "Superseded by default setup; workflow disabled"),
        ("dependamerge", "Default setup disabled; orphaned"),
        ("dependamerge", "Default setup disabled; orphaned"),
    ]
    assert [(r.repo.name, r.cells[1]) for r in coverage.rows] == [
        ("dependamerge", "actions")
    ]
    # Workflow state is read only for a stale advanced configuration: never
    # for dependamerge's live workflow, never for a default configuration.
    assert client.workflow_reads == [
        ("git-configure-action", ".github/workflows/codeql.yml")
    ]
    # Both tables travel with the CodeQL signal rather than floating free.
    by_key = {item.key: item for item in layout.plan(report)}
    assert [t.category.key for t in by_key[CategoryKey.CODEQL].children] == [
        CategoryKey.CODEQL_STALE_CONFIGURATIONS,
        CategoryKey.CODEQL_LANGUAGE_COVERAGE,
    ]
    assert CategoryKey.CODEQL_STALE_CONFIGURATIONS not in by_key


async def test_collect_org_codeql_threshold_comes_from_the_report_config() -> None:
    # At 120 days nothing in the fake is stale, so no workflow is looked up.
    client = CodeQLHealthClient()
    report = await collect.collect_org(
        client,
        OrgConfig(name="o"),
        ReportConfig(codeql_stale_days=120),
        generated_at=WHEN,
    )
    stale, _coverage = report.codeql_tables
    assert stale.rows == []
    assert client.workflow_reads == []
