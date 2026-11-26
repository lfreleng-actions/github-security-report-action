# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Tests for the remediation orchestration (offender extraction + writes)."""

from __future__ import annotations

import dataclasses
import datetime as dt
from collections.abc import Callable, Sequence
from types import MappingProxyType

import httpx
import pytest
import respx

from github_security_report import classify, models, remediate
from github_security_report.categories import CategoryKey, category_meta
from github_security_report.classify import RepoFacts
from github_security_report.client import GitHubClient
from github_security_report.codeql import (
    CodeQLConfiguration,
    CodeQLFacts,
    CodeQLHealth,
    DefaultSetup,
)
from github_security_report.models import Repo, SignalType
from github_security_report.report import (
    OrgReport,
    SignalSection,
    TableRow,
    TableSection,
    build_org_report,
)

WHEN = dt.datetime(2026, 6, 16, 9, 0, tzinfo=dt.UTC)


def _repo(name: str) -> Repo:
    return Repo(name, f"o/{name}", f"https://github.com/o/{name}")


def _table(key: CategoryKey, names: list[str]) -> TableSection:
    return TableSection(
        category=category_meta(key),
        columns=("Repository",),
        rows=[TableRow(repo=_repo(n), cells=()) for n in names],
        fail_count=len(names),
    )


def _report() -> OrgReport:
    """An org report with offenders in every remediable category."""
    return OrgReport(
        org="o",
        sections=[
            SignalSection(
                signal=SignalType.CODEQL,
                nag_repos=[_repo("cq-a"), _repo("cq-b")],
            ),
            SignalSection(
                signal=SignalType.SECRET_SCANNING,
                nag_repos=[_repo("ss-a")],
            ),
        ],
        repo_count=6,
        generated_at=WHEN,
        dependabot_tables=[
            _table(CategoryKey.DEPENDABOT_ALERTS_ENABLED, ["da-a"]),
            _table(CategoryKey.DEPENDABOT_UPDATES_ENABLED, ["du-a", "du-b"]),
            _table(CategoryKey.DEPENDABOT_COOLDOWN, ["cd-a"]),  # not remediable
        ],
        private_vulnerability_reporting=_table(
            CategoryKey.PRIVATE_VULNERABILITY_REPORTING, ["pvr-a"]
        ),
        auto_merge=_table(CategoryKey.AUTO_MERGE, ["am-a"]),
    )


class FakeClient:
    """Records every enable call; fails for names in ``fail``."""

    def __init__(self, fail: set[str] | None = None) -> None:
        self.calls: list[tuple[str, str, str]] = []
        self.fail = set(fail or ())

    async def _do(self, kind: str, org: str, repo: str) -> tuple[bool, str]:
        self.calls.append((kind, org, repo))
        if repo in self.fail:
            return False, "boom"
        return True, ""

    async def enable_dependabot_alerts(self, o: str, r: str) -> tuple[bool, str]:
        return await self._do("alerts", o, r)

    async def enable_dependabot_security_updates(
        self, o: str, r: str
    ) -> tuple[bool, str]:
        return await self._do("updates", o, r)

    async def enable_private_vulnerability_reporting(
        self, o: str, r: str
    ) -> tuple[bool, str]:
        return await self._do("pvr", o, r)

    async def enable_codeql_default_setup(self, o: str, r: str) -> tuple[bool, str]:
        return await self._do("codeql", o, r)

    async def enable_secret_scanning(self, o: str, r: str) -> tuple[bool, str]:
        return await self._do("secret", o, r)

    async def enable_auto_merge(self, o: str, r: str) -> tuple[bool, str]:
        return await self._do("auto_merge", o, r)

    async def enable_code_quality(
        self, o: str, r: str, languages: Sequence[str]
    ) -> tuple[bool, str]:
        return await self._do("code_quality", o, f"{r}:{','.join(languages)}")

    # CodeQL cleanup. ``holders`` maps a repository to each open alert's
    # holding categories; a repository mapped to None models an unreadable
    # alert list, and an absent one has no open alerts.
    holders: dict[str, list[frozenset[str]] | None] = {}

    async def delete_codeql_analyses(
        self, o: str, r: str, analysis_ids: tuple[int, ...]
    ) -> tuple[bool, str]:
        self.calls.append(("delete", o, f"{r}:{','.join(map(str, analysis_ids))}"))
        return True, f"{len(analysis_ids)} analyses deleted"

    async def enable_workflow(self, o: str, r: str, path: str) -> tuple[bool, str]:
        self.calls.append(("workflow", o, f"{r}:{path}"))
        return True, ""

    async def codeql_alert_holders(
        self, o: str, r: str, branch: str
    ) -> list[frozenset[str]] | None:
        self.calls.append(("cq-alerts", o, f"{r}@{branch}"))
        return self.holders.get(r, [])


def _by_key(results: list[remediate.CategoryRemediation]) -> dict:
    return {r.category.key: r for r in results}


def test_remediable_set_excludes_qualitative_categories() -> None:
    toggles = (
        CategoryKey.CODEQL,
        CategoryKey.SECRET_SCANNING,
        CategoryKey.DEPENDABOT_ALERTS_ENABLED,
        CategoryKey.DEPENDABOT_UPDATES_ENABLED,
        CategoryKey.PRIVATE_VULNERABILITY_REPORTING,
        CategoryKey.AUTO_MERGE,
    )
    remediable, default, explicit = (
        remediate.REMEDIABLE,
        remediate.DEFAULT_REMEDIABLE,
        remediate.EXPLICIT_ONLY,
    )
    named_only = (CategoryKey.CODE_QUALITY, CategoryKey.CODEQL_STALE_CONFIGURATIONS)
    assert remediable == (*toggles, *named_only)
    # The destructive cleanup and billed Code Quality run only when named.
    assert default == toggles
    assert explicit == named_only
    for excluded in (
        CategoryKey.SCORECARD,
        CategoryKey.ZIZMOR,
        CategoryKey.DEPENDABOT_ALERTS,
        CategoryKey.DEPENDABOT_COOLDOWN,
        CategoryKey.RELEASES,
        CategoryKey.MUTABLE_RELEASES,
        # Coverage gaps need a workflow change, which remediate cannot make.
        CategoryKey.CODEQL_LANGUAGE_COVERAGE,
    ):
        assert excluded not in remediate.REMEDIABLE


async def test_dry_run_previews_every_offender_without_writing() -> None:
    client = FakeClient()
    results = await remediate.remediate_org(client, _report(), apply=False)
    assert client.calls == []  # nothing written in a dry run
    by_key = _by_key(results)
    # Offenders surface in the canonical registry order, each "would enable".
    assert [o.name for o in by_key[CategoryKey.CODEQL].outcomes] == ["cq-a", "cq-b"]
    assert all(
        o.action == "would enable" for result in results for o in result.outcomes
    )
    # The non-remediable cooldown table is never turned into offenders.
    assert CategoryKey.DEPENDABOT_COOLDOWN not in by_key


async def test_apply_enables_each_offender_via_the_right_endpoint() -> None:
    client = FakeClient()
    results = await remediate.remediate_org(client, _report(), apply=True)
    assert set(client.calls) == {
        ("codeql", "o", "cq-a"),
        ("codeql", "o", "cq-b"),
        ("secret", "o", "ss-a"),
        ("alerts", "o", "da-a"),
        ("updates", "o", "du-a"),
        ("updates", "o", "du-b"),
        ("pvr", "o", "pvr-a"),
        ("auto_merge", "o", "am-a"),
    }
    assert all(o.action == "enabled" for result in results for o in result.outcomes)
    assert sum(r.failures for r in results) == 0


async def test_apply_records_failures_with_their_note() -> None:
    client = FakeClient(fail={"du-b"})
    results = await remediate.remediate_org(client, _report(), apply=True)
    updates = _by_key(results)[CategoryKey.DEPENDABOT_UPDATES_ENABLED]
    outcomes = {o.name: o for o in updates.outcomes}
    assert outcomes["du-a"].action == "enabled"
    assert outcomes["du-b"].failed
    assert outcomes["du-b"].note == "boom"
    assert updates.failures == 1
    assert sum(r.failures for r in results) == 1


async def test_category_selection_limits_the_work() -> None:
    client = FakeClient()
    results = await remediate.remediate_org(
        client, _report(), categories=[CategoryKey.CODEQL], apply=True
    )
    assert [r.category.key for r in results] == [CategoryKey.CODEQL]
    assert {c[0] for c in client.calls} == {"codeql"}


async def test_failed_codeql_probe_is_not_a_codeql_target() -> None:
    # A repository whose CodeQL probe failed may have older CodeQL analyses,
    # so default setup must not be switched on there.
    signals = [
        classify.classify_codeql(
            RepoFacts(
                repo=_repo("probe-failed"), code_scanning_unread=frozenset({"CodeQL"})
            )
        ),
        classify.classify_codeql(RepoFacts(repo=_repo("no-codeql"))),
    ]
    org = build_org_report("o", signals, repo_count=2, generated_at=WHEN)
    client = FakeClient()
    await remediate.remediate_org(
        client, org, categories=[CategoryKey.CODEQL], apply=True
    )
    assert client.calls == [("codeql", "o", "no-codeql")]


async def test_duplicate_categories_are_collapsed() -> None:
    # A repeated key must not enable the same feature twice.
    client = FakeClient()
    results = await remediate.remediate_org(
        client,
        _report(),
        categories=[CategoryKey.CODEQL, CategoryKey.CODEQL],
        apply=True,
    )
    assert [r.category.key for r in results] == [CategoryKey.CODEQL]
    # cq-a and cq-b are each enabled exactly once, not twice.
    assert sorted(client.calls) == [("codeql", "o", "cq-a"), ("codeql", "o", "cq-b")]


async def test_selected_category_with_no_offenders_is_still_reported() -> None:
    report = _report()
    # Clear the PVR offenders; the category should still appear, empty.
    report.private_vulnerability_reporting = _table(
        CategoryKey.PRIVATE_VULNERABILITY_REPORTING, []
    )
    client = FakeClient()
    results = await remediate.remediate_org(
        client,
        report,
        categories=[CategoryKey.PRIVATE_VULNERABILITY_REPORTING],
        apply=True,
    )
    assert len(results) == 1
    assert results[0].outcomes == ()
    assert client.calls == []


async def test_uncollected_standalone_table_yields_no_offenders() -> None:
    # Repo mode never builds the standalone posture tables, so a category whose
    # table is absent must remediate nothing rather than fail looking for it.
    report = _report()
    report.auto_merge = None
    client = FakeClient()
    results = await remediate.remediate_org(
        client, report, categories=[CategoryKey.AUTO_MERGE], apply=True
    )
    assert results[0].outcomes == ()
    assert client.calls == []


def test_parse_categories_maps_and_flags_unknown() -> None:
    keys, unknown = remediate.parse_categories(
        ["codeql", "private_vulnerability_reporting", "codeql", "bogus"]
    )
    # De-duplicated, input order preserved.
    assert keys == [
        CategoryKey.CODEQL,
        CategoryKey.PRIVATE_VULNERABILITY_REPORTING,
    ]
    assert unknown == ["bogus"]


def test_parse_categories_rejects_non_remediable_report_categories() -> None:
    # A real category that is reported but not remediable is "unknown" here.
    keys, unknown = remediate.parse_categories(["scorecard", "dependabot_cooldown"])
    assert keys == []
    assert unknown == ["scorecard", "dependabot_cooldown"]


async def test_remediate_org_rejects_a_non_remediable_category() -> None:
    # A non-remediable key would otherwise KeyError deep in the sort; the guard
    # turns it into a clear ValueError naming the offending category.
    client = FakeClient()
    with pytest.raises(ValueError, match="scorecard"):
        await remediate.remediate_org(
            client, _report(), categories=[CategoryKey.SCORECARD], apply=False
        )
    assert client.calls == []


# --------------------------------------------------------------------------- #
# GitHub Code Quality
# --------------------------------------------------------------------------- #
def _quality_report() -> OrgReport:
    report = _report()
    report.code_quality = _table(CategoryKey.CODE_QUALITY, ["off", "partial", "lost"])
    report.code_quality_writes = {
        "off": ("python",),
        # Partial: go is configured, python applies too; both are sent.
        "partial": ("python", "go"),
    }
    return report


async def test_default_run_never_enables_code_quality() -> None:
    # Code Quality is billed, so the no-argument run never switches it on.
    client = FakeClient()
    results = await remediate.remediate_org(client, _quality_report(), apply=True)
    assert CategoryKey.CODE_QUALITY not in {r.category.key for r in results}
    assert not any(kind == "code_quality" for kind, _, _ in client.calls)


async def test_code_quality_dry_run_names_the_languages() -> None:
    client = FakeClient()
    (result,) = await remediate.remediate_org(
        client,
        _quality_report(),
        categories=[CategoryKey.CODE_QUALITY],
        apply=False,
    )
    assert client.calls == []
    outcomes = [(o.name, o.action, o.note) for o in result.outcomes]
    assert outcomes == [
        ("off (python)", "would enable", ""),
        ("partial (python, go)", "would enable", ""),
        ("lost", "refused", "languages unknown; nothing written"),
    ]


async def test_code_quality_apply_sends_the_full_language_list() -> None:
    client = FakeClient()
    (result,) = await remediate.remediate_org(
        client,
        _quality_report(),
        categories=[CategoryKey.CODE_QUALITY],
        apply=True,
    )
    assert client.calls == [
        ("code_quality", "o", "off:python"),
        ("code_quality", "o", "partial:python,go"),
    ]
    assert result.failures == 0


async def test_code_quality_without_its_table_has_nothing_to_do() -> None:
    client = FakeClient()
    (result,) = await remediate.remediate_org(
        client, _report(), categories=[CategoryKey.CODE_QUALITY], apply=True
    )
    assert result.outcomes == ()
    assert client.calls == []


# --------------------------------------------------------------------------- #
# CodeQL stale-configuration cleanup
# --------------------------------------------------------------------------- #
_HEAD = dt.datetime(2026, 9, 24, tzinfo=dt.UTC)
_DEFAULT_KEY = "dynamic/github-code-scanning/codeql:analyze"
_WORKFLOW_KEY = ".github/workflows/codeql.yml:analyze"


def _cq(language: str, key: str, days_behind: int, *ids: int) -> CodeQLConfiguration:
    prefix = "" if key == _DEFAULT_KEY else f"{key}/build-mode:none"
    return CodeQLConfiguration(
        category=f"{prefix}/language:{language}",
        analysis_key=key,
        last_scan_at=_HEAD - dt.timedelta(days=days_behind),
        language=language,
        analysis_ids=ids,
    )


def _health() -> CodeQLHealth:
    """dependamerge before its fix, plus a workflow disabled for inactivity."""
    dependamerge = CodeQLFacts(
        repo=_repo("dependamerge"),
        configurations=(
            _cq("python", _WORKFLOW_KEY, 0, 100),
            _cq("python", _DEFAULT_KEY, 91, 12, 11),
            _cq("actions", _DEFAULT_KEY, 91, 10),
        ),
        head_committed_at=_HEAD,
        default_setup=DefaultSetup(
            configured=False, languages=frozenset({"actions", "python"})
        ),
    )
    quiet = CodeQLFacts(
        repo=_repo("quiet"),
        configurations=(_cq("python", _WORKFLOW_KEY, 70, 5),),
        head_committed_at=_HEAD,
        default_setup=DefaultSetup(configured=False, languages=frozenset({"python"})),
        workflow_states=MappingProxyType(
            {".github/workflows/codeql.yml": "disabled_inactivity"}
        ),
    )
    return CodeQLHealth(facts=(dependamerge, quiet), stale_days=30)


def _cleanup_report() -> OrgReport:
    report = _report()
    report.codeql_health = _health()
    return report


async def test_default_run_never_touches_the_codeql_cleanup() -> None:
    # Destructive work must be asked for by name: the no-argument run acts on
    # the feature toggles only, and issues no cleanup read or write at all.
    client = FakeClient()
    results = await remediate.remediate_org(client, _cleanup_report(), apply=True)
    keys = [r.category.key for r in results]
    assert CategoryKey.CODEQL_STALE_CONFIGURATIONS not in keys
    assert not any(
        kind in {"delete", "workflow", "cq-alerts"} for kind, _, _ in client.calls
    )


async def test_cleanup_dry_run_previews_refuses_and_writes_nothing() -> None:
    client = FakeClient()
    (result,) = await remediate.remediate_org(
        client,
        _cleanup_report(),
        categories=[CategoryKey.CODEQL_STALE_CONFIGURATIONS],
        apply=False,
    )
    outcomes = [(o.name, o.action, o.note) for o in result.outcomes]
    assert outcomes == [
        (
            "dependamerge: /language:actions",
            "refused",
            "no current configuration scans actions; add scanning for it first",
        ),
        ("dependamerge: /language:python", "would delete", ""),
        # A re-enable acts on the workflow, so it is named by the workflow.
        ("quiet: .github/workflows/codeql.yml", "would re-enable", ""),
    ]
    # The alert guard is a read, so it runs in a dry run too -- but only for
    # a deletion the plan has not already refused.
    kinds = [(kind, detail) for kind, _, detail in client.calls]
    assert kinds == [("cq-alerts", "dependamerge@main")]


async def test_cleanup_apply_deletes_newest_first_and_reenables() -> None:
    client = FakeClient()
    (result,) = await remediate.remediate_org(
        client,
        _cleanup_report(),
        categories=[CategoryKey.CODEQL_STALE_CONFIGURATIONS],
        apply=True,
    )
    assert [(o.action, o.verb) for o in result.outcomes] == [
        ("refused", "delete"),
        ("deleted", "delete"),
        ("re-enabled", "re-enable"),
    ]
    writes = [(k, d) for k, _, d in client.calls if k != "cq-alerts"]
    assert writes == [
        ("delete", "dependamerge:12,11"),
        ("workflow", "quiet:.github/workflows/codeql.yml"),
    ]
    # A refusal is not a failure: nothing broke, the work is simply withheld.
    assert result.failures == 0


@pytest.mark.parametrize(
    ("holders", "note"),
    [
        (
            [frozenset({"/language:python"})] * 2,
            "would close 2 open alert(s) that no remaining configuration reports",
        ),
        (None, "open alerts could not be read; nothing deleted"),
    ],
)
async def test_cleanup_refuses_to_close_open_alerts(
    holders: list[frozenset[str]] | None, note: str
) -> None:
    client = FakeClient()
    client.holders = {"dependamerge": holders}
    (result,) = await remediate.remediate_org(
        client,
        _cleanup_report(),
        categories=[CategoryKey.CODEQL_STALE_CONFIGURATIONS],
        apply=True,
    )
    python = next(o for o in result.outcomes if o.name.endswith("/language:python"))
    assert (python.action, python.note) == ("refused", note)
    assert not any(kind == "delete" for kind, _, _ in client.calls)


def _twin_report() -> OrgReport:
    """Two orphaned Python configurations in one repository, beside a live one."""
    renamed = ".github/workflows/codeql.yaml:analyze"
    twin = CodeQLFacts(
        repo=_repo("twin"),
        configurations=(
            _cq("python", _WORKFLOW_KEY, 0, 100),
            _cq("python", _DEFAULT_KEY, 91, 21),
            _cq("python", renamed, 120, 31),
        ),
        head_committed_at=_HEAD,
        default_setup=DefaultSetup(configured=False, languages=frozenset({"python"})),
        workflow_states=MappingProxyType({".github/workflows/codeql.yaml": "missing"}),
    )
    report = _report()
    report.codeql_health = CodeQLHealth(facts=(twin,), stale_days=30)
    return report


async def test_cleanup_guard_judges_the_batch_not_each_deletion() -> None:
    # One alert is held by both orphans: neither alone closes it, but deleting
    # the pair would. Another is held by an orphan and the live configuration,
    # so it survives any deletion. The batch must spare the first alert's
    # holders, and read the repository's alerts once for both targets.
    default = "/language:python"
    renamed = ".github/workflows/codeql.yaml:analyze/build-mode:none/language:python"
    live = f"{_WORKFLOW_KEY}/build-mode:none/language:python"
    client = FakeClient()
    client.holders = {
        "twin": [frozenset({default, renamed}), frozenset({default, live})]
    }
    (result,) = await remediate.remediate_org(
        client,
        _twin_report(),
        categories=[CategoryKey.CODEQL_STALE_CONFIGURATIONS],
        apply=True,
    )
    assert [(o.action, o.note) for o in result.outcomes] == [
        (
            "refused",
            "would close 1 open alert(s) that no remaining configuration reports",
        ),
    ] * 2
    assert not any(kind == "delete" for kind, _, _ in client.calls)
    assert [d for k, _, d in client.calls if k == "cq-alerts"] == ["twin@main"]


async def test_cleanup_proceeds_when_a_live_configuration_keeps_every_alert() -> None:
    live = f"{_WORKFLOW_KEY}/build-mode:none/language:python"
    client = FakeClient()
    client.holders = {"twin": [frozenset({"/language:python", live})]}
    (result,) = await remediate.remediate_org(
        client,
        _twin_report(),
        categories=[CategoryKey.CODEQL_STALE_CONFIGURATIONS],
        apply=True,
    )
    assert [o.action for o in result.outcomes] == ["deleted", "deleted"]


async def test_cleanup_without_collected_codeql_data_has_nothing_to_do() -> None:
    (result,) = await remediate.remediate_org(
        FakeClient(),
        _report(),
        categories=[CategoryKey.CODEQL_STALE_CONFIGURATIONS],
        apply=True,
    )
    assert result.outcomes == ()


async def test_cleanup_lists_the_configurations_it_leaves_with_their_cause() -> None:
    # A configuration remediate will not touch is still named, with the
    # cause the Stale Configurations table gives it, so an operator can see
    # what remains for a person. Listing it writes and reads nothing.
    idle = CodeQLFacts(
        repo=_repo("idle"),
        configurations=(_cq("python", _WORKFLOW_KEY, 60, 7),),
        head_committed_at=_HEAD,
        default_setup=DefaultSetup(configured=False, languages=frozenset({"python"})),
        workflow_states=MappingProxyType({".github/workflows/codeql.yml": "active"}),
    )
    report = _cleanup_report()
    health = report.codeql_health
    assert health is not None
    report.codeql_health = CodeQLHealth(
        facts=(*health.facts, idle), stale_days=health.stale_days
    )
    client = FakeClient()
    (result,) = await remediate.remediate_org(
        client,
        report,
        categories=[CategoryKey.CODEQL_STALE_CONFIGURATIONS],
        apply=True,
    )
    skipped = [(o.name, o.action, o.note) for o in result.outcomes if o.skipped]
    assert skipped == [
        (
            f"idle: {_WORKFLOW_KEY}/build-mode:none/language:python",
            "skipped",
            "Workflow active, not uploading",
        )
    ]
    assert result.failures == 0
    assert not any(detail.startswith("idle") for _, _, detail in client.calls)


# --------------------------------------------------------------------------- #
# Stopping a category after repeated identical refusals
# --------------------------------------------------------------------------- #
_NAMES = [f"r{i:02d}" for i in range(12)]
_FORBIDDEN = '403 {"message":"Resource not accessible by personal access token"}'


def _everywhere(names: list[str]) -> OrgReport:
    """Every default category targets every one of ``names``."""
    repos = [_repo(n) for n in names]
    return OrgReport(
        org="o",
        sections=[
            SignalSection(signal=SignalType.CODEQL, nag_repos=repos),
            SignalSection(signal=SignalType.SECRET_SCANNING, nag_repos=repos),
        ],
        repo_count=len(names),
        generated_at=WHEN,
        dependabot_tables=[
            _table(CategoryKey.DEPENDABOT_ALERTS_ENABLED, names),
            _table(CategoryKey.DEPENDABOT_UPDATES_ENABLED, names),
        ],
        private_vulnerability_reporting=_table(
            CategoryKey.PRIVATE_VULNERABILITY_REPORTING, names
        ),
        auto_merge=_table(CategoryKey.AUTO_MERGE, names),
    )


class ScriptedClient(FakeClient):
    """Answers each write from ``answer(repo)``: ``None`` succeeds."""

    def __init__(self, answer: Callable[[str], tuple[int, str] | None]) -> None:
        super().__init__()
        self.answer = answer

    async def _do(self, kind: str, org: str, repo: str) -> tuple[bool, str]:
        self.calls.append((kind, org, repo))
        refusal = self.answer(repo.split(":")[0])
        if refusal is None:
            return True, ""
        status, text = refusal
        return False, models.WriteNote(text, status)


def _refused(status: int = 403, text: str = _FORBIDDEN) -> tuple[int, str]:
    return status, text


async def _codeql(client: FakeClient) -> remediate.CategoryRemediation:
    (result,) = await remediate.remediate_org(
        client, _everywhere(_NAMES), categories=[CategoryKey.CODEQL], apply=True
    )
    return result


@pytest.mark.parametrize("status", [403, 404])
async def test_three_identical_refusals_stop_the_category(status: int) -> None:
    client = ScriptedClient(lambda _repo: _refused(status, f"{status} nope"))
    result = await _codeql(client)
    assert [repo for _, _, repo in client.calls] == _NAMES[:3]
    assert remediate.STOP_AFTER_REFUSALS == 3
    assert [o.failed for o in result.outcomes] == [True] * 3 + [False] * 9
    skipped = result.outcomes[3:]
    assert all(o.skipped for o in skipped)
    assert all(f"{status} nope" in o.note for o in skipped)
    # Skipped targets are neither changed nor failed; the run still fails.
    assert result.failures == 3


async def test_a_success_between_refusals_resets_the_count() -> None:
    succeeds = {"r02"}
    client = ScriptedClient(lambda repo: None if repo in succeeds else _refused())
    result = await _codeql(client)
    # r00, r01 refused; r02 succeeds; r03-r05 refused, which stops the rest.
    assert [repo for _, _, repo in client.calls] == _NAMES[:6]
    assert sum(o.skipped for o in result.outcomes) == 6


@pytest.mark.parametrize(
    "answer",
    [
        # 422 and 409 describe one repository, never the token.
        lambda _repo: _refused(422, "422 no CodeQL language"),
        lambda _repo: _refused(409, "409 an update is already in progress"),
        # Refusals that differ are not a pattern.
        lambda repo: _refused(403, f"403 {repo}"),
        # A failure of another kind between refusals resets the count.
        # Every third write here is a 422, so no three refusals run together.
        lambda repo: _refused(422, "422 x") if int(repo[1:]) % 3 == 2 else _refused(),
    ],
    ids=["422", "409", "different-notes", "other-failure-resets"],
)
async def test_other_failures_never_stop_the_category(
    answer: Callable[[str], tuple[int, str] | None],
) -> None:
    client = ScriptedClient(answer)
    result = await _codeql(client)
    assert len(client.calls) == len(_NAMES)
    assert not any(o.skipped for o in result.outcomes)


async def test_a_plain_note_carries_no_status_and_never_stops() -> None:
    client = FakeClient(fail=set(_NAMES))  # "boom", with no status
    result = await _codeql(client)
    assert len(client.calls) == len(_NAMES)
    assert result.failures == len(_NAMES)


async def test_each_category_starts_afresh() -> None:
    client = ScriptedClient(lambda _repo: _refused())
    results = await remediate.remediate_org(client, _everywhere(_NAMES), apply=True)
    assert len(results) == len(remediate.DEFAULT_REMEDIABLE)
    for result in results:
        assert [o.failed for o in result.outcomes[:3]] == [True] * 3
        assert all(o.skipped for o in result.outcomes[3:])
    assert len(client.calls) == 3 * len(results)


async def test_a_guard_refusal_neither_counts_nor_resets() -> None:
    report = _report()
    names = ["a", "b", "lost", "c", "d"]
    report.code_quality = _table(CategoryKey.CODE_QUALITY, names)
    report.code_quality_writes = {n: ("python",) for n in names if n != "lost"}
    client = ScriptedClient(lambda _repo: _refused())
    (result,) = await remediate.remediate_org(
        client, report, categories=[CategoryKey.CODE_QUALITY], apply=True
    )
    actions = [o.action for o in result.outcomes]
    assert actions == ["FAILED", "FAILED", "refused", "FAILED", "skipped"]


async def test_a_dry_run_never_stops() -> None:
    client = ScriptedClient(lambda _repo: _refused())
    (result,) = await remediate.remediate_org(
        client, _everywhere(_NAMES), categories=[CategoryKey.CODEQL], apply=False
    )
    assert client.calls == []
    assert all(o.action == "would enable" for o in result.outcomes)


@respx.mock
async def test_a_token_refused_everywhere_makes_three_writes_per_category() -> None:
    # The scenario of issue #328: twelve repositories in every default
    # category and a token GitHub refuses every write from.
    refused = httpx.Response(
        403, json={"message": "Resource not accessible by personal access token"}
    )
    writes = respx.route(method__in=["PATCH", "PUT"]).mock(return_value=refused)
    async with GitHubClient("t") as client:
        results = await remediate.remediate_org(client, _everywhere(_NAMES), apply=True)
    assert writes.call_count == 18
    assert sum(r.failures for r in results) == 18
    assert sum(o.skipped for r in results for o in r.outcomes) == 54


def _stale_python(name: str, *ids: int) -> CodeQLFacts:
    """A repository whose default-setup Python configuration is stale."""
    return CodeQLFacts(
        repo=_repo(name),
        configurations=(
            _cq("python", _WORKFLOW_KEY, 0, 1000),
            _cq("python", _DEFAULT_KEY, 91, *ids),
        ),
        head_committed_at=_HEAD,
        default_setup=DefaultSetup(configured=False, languages=frozenset({"python"})),
    )


@respx.mock
@pytest.mark.parametrize(
    ("status", "readback"),
    [(403, None), (404, httpx.Response(200, json={}))],
    ids=["403", "404-still-there"],
)
async def test_cleanup_refusals_stop_whatever_each_configuration_holds(
    status: int, readback: httpx.Response | None
) -> None:
    # Each configuration holds a different number of analyses, so each
    # refused walk reports a different "stopped after 0 of N"; the refusal
    # is the same all the same, and three of them stop the category.
    report = _report()
    report.codeql_health = CodeQLHealth(
        facts=tuple(
            _stale_python(f"r{size}", *range(size * 10 + size, size * 10, -1))
            for size in range(1, 6)
        ),
        stale_days=30,
    )
    respx.get(url__regex=r"/code-scanning/alerts").mock(
        return_value=httpx.Response(200, json=[])
    )
    if readback is not None:
        respx.get(url__regex=r"/code-scanning/analyses/\d+$").mock(
            return_value=readback
        )
    deletes = respx.delete(url__regex=r"/code-scanning/analyses/").mock(
        return_value=httpx.Response(status, json={"message": "Must have admin rights"})
    )
    async with GitHubClient("t") as client:
        client.mutation_interval_seconds = 0
        (result,) = await remediate.remediate_org(
            client,
            report,
            categories=[CategoryKey.CODEQL_STALE_CONFIGURATIONS],
            apply=True,
        )
    assert deletes.call_count == 3
    assert [o.action for o in result.outcomes] == ["FAILED"] * 3 + ["skipped"] * 2
    assert all("stopped after" not in o.note for o in result.outcomes[3:])
    assert result.failures == 3


@respx.mock
async def test_a_success_inside_a_two_step_write_resets_the_count() -> None:
    # Each target enables alerts, then is refused security updates: the
    # alerts write succeeded in between, so no three refusals run together.
    respx.put(url__regex=r"/vulnerability-alerts$").mock(
        return_value=httpx.Response(204)
    )
    fixes = respx.put(url__regex=r"/automated-security-fixes$").mock(
        return_value=httpx.Response(403, json={"message": "Must have admin rights"})
    )
    async with GitHubClient("t") as client:
        (result,) = await remediate.remediate_org(
            client,
            _everywhere(_NAMES),
            categories=[CategoryKey.DEPENDABOT_UPDATES_ENABLED],
            apply=True,
        )
    assert fixes.call_count == len(_NAMES)
    assert not any(o.skipped for o in result.outcomes)


@respx.mock
async def test_a_deletion_before_a_cleanup_refusal_resets_the_count() -> None:
    # Each configuration's newest analysis deletes, the next is refused.
    report = _report()
    report.codeql_health = CodeQLHealth(
        facts=tuple(_stale_python(f"r{i}", 2 * i + 2, 2 * i + 1) for i in range(5)),
        stale_days=30,
    )
    respx.get(url__regex=r"/code-scanning/alerts").mock(
        return_value=httpx.Response(200, json=[])
    )

    def delete(request: httpx.Request) -> httpx.Response:
        analysis_id = int(request.url.path.rsplit("/", 1)[1])
        if analysis_id % 2 == 0:
            return httpx.Response(200, json={})
        return httpx.Response(403, json={"message": "Must have admin rights"})

    deletes = respx.delete(url__regex=r"/code-scanning/analyses/").mock(
        side_effect=delete
    )
    async with GitHubClient("t") as client:
        client.mutation_interval_seconds = 0
        (result,) = await remediate.remediate_org(
            client,
            report,
            categories=[CategoryKey.CODEQL_STALE_CONFIGURATIONS],
            apply=True,
        )
    assert deletes.call_count == 10
    assert [o.action for o in result.outcomes] == ["FAILED"] * 5


# --------------------------------------------------------------------------- #
# The account's admin right, carried to the preview
# --------------------------------------------------------------------------- #
async def test_each_outcome_carries_its_repositorys_admin_right() -> None:
    rights = {"own": True, "member": False, "unknown": None}
    report = OrgReport(
        org="o",
        sections=[
            SignalSection(
                signal=SignalType.CODEQL,
                nag_repos=[
                    dataclasses.replace(_repo(name), admin=admin)
                    for name, admin in rights.items()
                ],
            )
        ],
        repo_count=3,
        generated_at=WHEN,
    )
    (result,) = await remediate.remediate_org(
        FakeClient(), report, categories=[CategoryKey.CODEQL], apply=False
    )
    assert {o.name: o.admin for o in result.outcomes} == rights
