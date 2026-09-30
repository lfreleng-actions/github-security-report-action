# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Remediation: switch on security features that repositories lack.

The report identifies repositories where a remediable security feature is off.
This module turns those features on via the GitHub REST API, acting only on the
confirmed-off, in-scope offenders the report already surfaced -- never on
repositories whose state could not be read (those are counted as *unknown* and
never appear as offenders, so the collection step doubles as the "read state"
that the never-blind-write rule requires). It is dry-run oriented: the CLI
previews the work by default and writes only when asked to apply.

The set of remediable categories is deliberately narrower than the report. Only
categories that are a simple on/off feature with a documented enablement
endpoint are here; qualitative findings (Scorecard, zizmor, open alerts,
cooldown, release freshness/mutability) are reported but not auto-remediated.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Iterable, Sequence
from dataclasses import dataclass
from typing import Protocol

from github_security_report.categories import (
    CategoryKey,
    CategoryMeta,
    category_meta,
)
from github_security_report.models import Repo, SignalType
from github_security_report.report import OrgReport, TableSection


class RemediationClient(Protocol):
    """The write surface a remediator needs (a subset of ``GitHubClient``).

    Each method enables one feature on one repository and returns
    ``(ok, note)``: ``ok`` is whether the write succeeded, and ``note`` carries
    a short diagnostic (an error status/body on failure, or a hint such as
    ``"accepted (async)"`` on success). Tests supply an in-memory fake.
    """

    async def enable_dependabot_alerts(
        self, org: str, repo: str
    ) -> tuple[bool, str]: ...

    async def enable_dependabot_security_updates(
        self, org: str, repo: str
    ) -> tuple[bool, str]: ...

    async def enable_private_vulnerability_reporting(
        self, org: str, repo: str
    ) -> tuple[bool, str]: ...

    async def enable_codeql_default_setup(
        self, org: str, repo: str
    ) -> tuple[bool, str]: ...

    async def enable_secret_scanning(self, org: str, repo: str) -> tuple[bool, str]: ...

    async def enable_auto_merge(self, org: str, repo: str) -> tuple[bool, str]: ...


# Actions a repository outcome can carry. "would enable" is the dry-run preview;
# "enabled" and "FAILED" are the two terminal states after an apply.
_WOULD_ENABLE = "would enable"
_ENABLED = "enabled"
_FAILED = "FAILED"


@dataclass(frozen=True)
class RepoOutcome:
    """The result of (planning to) enable one feature on one repository."""

    name: str
    action: str  # "would enable" | "enabled" | "FAILED"
    note: str = ""

    @property
    def failed(self) -> bool:
        return self.action == _FAILED


@dataclass(frozen=True)
class CategoryRemediation:
    """Every repository outcome for one remediated category."""

    category: CategoryMeta
    outcomes: tuple[RepoOutcome, ...]

    @property
    def failures(self) -> int:
        return sum(1 for o in self.outcomes if o.failed)


# --------------------------------------------------------------------------- #
# Offender extraction
# --------------------------------------------------------------------------- #
def _nag_offenders(signal: SignalType) -> Callable[[OrgReport], list[Repo]]:
    """Offenders for a signal category: its NAG (feature-disabled) repos."""

    def _get(report: OrgReport) -> list[Repo]:
        return [
            repo
            for section in report.sections
            if section.signal is signal
            for repo in section.nag_repos
        ]

    return _get


def _find_table(report: OrgReport, key: CategoryKey) -> TableSection | None:
    """The posture table for ``key``, whether nested or a section of its own."""
    for table in (*report.dependabot_tables, *report.standalone_tables):
        if table is not None and table.category.key is key:
            return table
    return None


def _table_offenders(key: CategoryKey) -> Callable[[OrgReport], list[Repo]]:
    """Offenders for a posture-table category: the table's listed repos."""

    def _get(report: OrgReport) -> list[Repo]:
        table = _find_table(report, key)
        return [row.repo for row in table.rows] if table is not None else []

    return _get


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class _Remediator:
    key: CategoryKey
    offenders: Callable[[OrgReport], list[Repo]]
    enable: Callable[[RemediationClient, str, str], Awaitable[tuple[bool, str]]]


_REMEDIATORS: tuple[_Remediator, ...] = (
    _Remediator(
        CategoryKey.CODEQL,
        _nag_offenders(SignalType.CODEQL),
        lambda c, o, r: c.enable_codeql_default_setup(o, r),
    ),
    _Remediator(
        CategoryKey.SECRET_SCANNING,
        _nag_offenders(SignalType.SECRET_SCANNING),
        lambda c, o, r: c.enable_secret_scanning(o, r),
    ),
    _Remediator(
        CategoryKey.DEPENDABOT_ALERTS_ENABLED,
        _table_offenders(CategoryKey.DEPENDABOT_ALERTS_ENABLED),
        lambda c, o, r: c.enable_dependabot_alerts(o, r),
    ),
    _Remediator(
        CategoryKey.DEPENDABOT_UPDATES_ENABLED,
        _table_offenders(CategoryKey.DEPENDABOT_UPDATES_ENABLED),
        lambda c, o, r: c.enable_dependabot_security_updates(o, r),
    ),
    _Remediator(
        CategoryKey.PRIVATE_VULNERABILITY_REPORTING,
        _table_offenders(CategoryKey.PRIVATE_VULNERABILITY_REPORTING),
        lambda c, o, r: c.enable_private_vulnerability_reporting(o, r),
    ),
    _Remediator(
        CategoryKey.AUTO_MERGE,
        _table_offenders(CategoryKey.AUTO_MERGE),
        lambda c, o, r: c.enable_auto_merge(o, r),
    ),
)

_BY_KEY: dict[CategoryKey, _Remediator] = {r.key: r for r in _REMEDIATORS}

# The remediable category keys, in the order they are acted on and rendered.
REMEDIABLE: tuple[CategoryKey, ...] = tuple(r.key for r in _REMEDIATORS)


def parse_categories(values: Iterable[str]) -> tuple[list[CategoryKey], list[str]]:
    """Map user-supplied category strings to keys.

    Returns ``(keys, unknown)``: the resolved remediable keys (de-duplicated,
    input order preserved) and any values that are not remediable category
    names. The caller reports ``unknown`` and, when it is empty, acts on
    ``keys`` (or every remediable category when the user selected none).
    """
    valid = {key.value: key for key in REMEDIABLE}
    keys: list[CategoryKey] = []
    unknown: list[str] = []
    for value in values:
        key = valid.get(value)
        if key is None:
            unknown.append(value)
        elif key not in keys:
            keys.append(key)
    return keys, unknown


async def remediate_org(
    client: RemediationClient,
    report: OrgReport,
    *,
    categories: Sequence[CategoryKey] | None = None,
    apply: bool,
) -> list[CategoryRemediation]:
    """Enable (or, in dry run, preview enabling) features across one org report.

    Acts on every selected category (defaulting to all remediable categories),
    in the canonical :data:`REMEDIABLE` order. In dry run every offender yields
    a ``"would enable"`` outcome and no write is issued; with ``apply`` each
    offender is written and yields ``"enabled"`` or ``"FAILED"`` with the
    write's diagnostic note. Categories are always represented (with an empty
    outcome list when they have no offenders) so the renderer can show that a
    selected category had nothing to do.

    Raises :class:`ValueError` if ``categories`` contains a key that is not
    remediable, rather than failing later with an opaque ``KeyError``.
    Duplicate keys are collapsed so a feature is never enabled twice in a run.
    """
    requested = list(categories) if categories is not None else list(REMEDIABLE)
    invalid = [key for key in requested if key not in _BY_KEY]
    if invalid:
        names = ", ".join(key.value for key in invalid)
        raise ValueError(f"not remediable: {names}")
    # De-duplicate (a caller may repeat a key) while preserving first-seen
    # order; the canonical sort below then fixes the acting/rendering order.
    selected: list[CategoryKey] = []
    for key in requested:
        if key not in selected:
            selected.append(key)
    order = {rem.key: i for i, rem in enumerate(_REMEDIATORS)}
    results: list[CategoryRemediation] = []
    for key in sorted(selected, key=lambda k: order[k]):
        rem = _BY_KEY[key]
        outcomes: list[RepoOutcome] = []
        for repo in rem.offenders(report):
            if not apply:
                outcomes.append(RepoOutcome(repo.name, _WOULD_ENABLE))
                continue
            ok, note = await rem.enable(client, report.org, repo.name)
            outcomes.append(RepoOutcome(repo.name, _ENABLED if ok else _FAILED, note))
        results.append(
            CategoryRemediation(category=category_meta(key), outcomes=tuple(outcomes))
        )
    return results
