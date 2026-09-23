# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Tests for the remediation orchestration (offender extraction + writes)."""

from __future__ import annotations

import datetime as dt

import pytest

from github_security_report import remediate
from github_security_report.categories import CategoryKey, category_meta
from github_security_report.models import Repo, SignalType
from github_security_report.report import (
    OrgReport,
    SignalSection,
    TableRow,
    TableSection,
)

WHEN = dt.datetime(2026, 6, 16, 9, 0, tzinfo=dt.timezone.utc)


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


def _by_key(results: list[remediate.CategoryRemediation]) -> dict:
    return {r.category.key: r for r in results}


def test_remediable_set_excludes_qualitative_categories() -> None:
    assert remediate.REMEDIABLE == (
        CategoryKey.CODEQL,
        CategoryKey.SECRET_SCANNING,
        CategoryKey.DEPENDABOT_ALERTS_ENABLED,
        CategoryKey.DEPENDABOT_UPDATES_ENABLED,
        CategoryKey.PRIVATE_VULNERABILITY_REPORTING,
        CategoryKey.AUTO_MERGE,
    )
    for excluded in (
        CategoryKey.SCORECARD,
        CategoryKey.ZIZMOR,
        CategoryKey.DEPENDABOT_ALERTS,
        CategoryKey.DEPENDABOT_COOLDOWN,
        CategoryKey.RELEASES,
        CategoryKey.MUTABLE_RELEASES,
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
