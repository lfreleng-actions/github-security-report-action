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

One category is destructive: stale CodeQL configurations are cleaned up by
deleting their analyses (ADR-0005). It runs only when named explicitly, never
as part of the default set, and each target passes guards that can refuse it
-- a refusal is reported beside the work done, not treated as a failure.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Iterable, Sequence
from dataclasses import dataclass

from github_security_report.categories import CategoryKey, category_meta
from github_security_report.models import Repo, SignalType
from github_security_report.remediate.codeql import (
    _cleanup_precheck,
    _cleanup_targets,
    _cleanup_write,
)
from github_security_report.remediate.model import (
    _DONE,
    _FAILED,
    _REFUSED,
    CategoryRemediation,
    RemediationClient,
    RepoOutcome,
    _repo_targets,
    _Target,
)
from github_security_report.report import OrgReport, TableSection

__all__ = [
    "DEFAULT_REMEDIABLE",
    "EXPLICIT_ONLY",
    "REMEDIABLE",
    "CategoryRemediation",
    "RemediationClient",
    "RepoOutcome",
    "parse_categories",
    "remediate_org",
]


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
    for table in (*report.nested_tables, *report.standalone_tables):
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
    targets: Callable[[OrgReport], list[_Target]]
    write: Callable[[RemediationClient, str, _Target], Awaitable[tuple[bool, str]]]
    # A last read before the write, in either mode: a reason to refuse the
    # target, or None to proceed.
    precheck: (
        Callable[[RemediationClient, str, _Target], Awaitable[str | None]] | None
    ) = None
    # Destructive remediators act only when named with --category.
    explicit_only: bool = False


_REMEDIATORS: tuple[_Remediator, ...] = (
    _Remediator(
        CategoryKey.CODEQL,
        _repo_targets(_nag_offenders(SignalType.CODEQL)),
        lambda c, o, t: c.enable_codeql_default_setup(o, t.repo.name),
    ),
    _Remediator(
        CategoryKey.SECRET_SCANNING,
        _repo_targets(_nag_offenders(SignalType.SECRET_SCANNING)),
        lambda c, o, t: c.enable_secret_scanning(o, t.repo.name),
    ),
    _Remediator(
        CategoryKey.DEPENDABOT_ALERTS_ENABLED,
        _repo_targets(_table_offenders(CategoryKey.DEPENDABOT_ALERTS_ENABLED)),
        lambda c, o, t: c.enable_dependabot_alerts(o, t.repo.name),
    ),
    _Remediator(
        CategoryKey.DEPENDABOT_UPDATES_ENABLED,
        _repo_targets(_table_offenders(CategoryKey.DEPENDABOT_UPDATES_ENABLED)),
        lambda c, o, t: c.enable_dependabot_security_updates(o, t.repo.name),
    ),
    _Remediator(
        CategoryKey.PRIVATE_VULNERABILITY_REPORTING,
        _repo_targets(_table_offenders(CategoryKey.PRIVATE_VULNERABILITY_REPORTING)),
        lambda c, o, t: c.enable_private_vulnerability_reporting(o, t.repo.name),
    ),
    _Remediator(
        CategoryKey.AUTO_MERGE,
        _repo_targets(_table_offenders(CategoryKey.AUTO_MERGE)),
        lambda c, o, t: c.enable_auto_merge(o, t.repo.name),
    ),
    _Remediator(
        CategoryKey.CODEQL_STALE_CONFIGURATIONS,
        _cleanup_targets,
        _cleanup_write,
        precheck=_cleanup_precheck,
        explicit_only=True,
    ),
)

_BY_KEY: dict[CategoryKey, _Remediator] = {r.key: r for r in _REMEDIATORS}

# The remediable category keys, in the order they are acted on and rendered.
REMEDIABLE: tuple[CategoryKey, ...] = tuple(r.key for r in _REMEDIATORS)

# What runs when no --category is given: everything but the destructive ones.
DEFAULT_REMEDIABLE: tuple[CategoryKey, ...] = tuple(
    r.key for r in _REMEDIATORS if not r.explicit_only
)

# The remediable keys that run only when named.
EXPLICIT_ONLY: tuple[CategoryKey, ...] = tuple(
    r.key for r in _REMEDIATORS if r.explicit_only
)


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
    """Remediate (or, in dry run, preview remediating) one org report.

    Acts on every selected category -- by default every remediable category
    except the explicit-only, destructive ones -- in the canonical
    :data:`REMEDIABLE` order. In dry run every target yields a ``"would
    <verb>"`` outcome and no write is issued; with ``apply`` each target is
    written and yields the verb's past participle or ``"FAILED"`` with the
    write's diagnostic note. A target the plan or its precheck refuses yields
    ``"refused"`` with the reason, in either mode, and is never written; the
    precheck is a read, so a dry run reports refusals exactly as an apply would.
    Categories are always represented (with an empty outcome list when they
    have no targets) so the renderer can show a selected category had nothing
    to do.

    Raises :class:`ValueError` if ``categories`` contains a key that is not
    remediable, rather than failing later with an opaque ``KeyError``.
    Duplicate keys are collapsed so nothing is remediated twice in a run.
    """
    requested = list(categories) if categories is not None else list(DEFAULT_REMEDIABLE)
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
        outcomes = [
            await _remediate_target(client, report.org, rem, target, apply=apply)
            for target in rem.targets(report)
        ]
        results.append(
            CategoryRemediation(category=category_meta(key), outcomes=tuple(outcomes))
        )
    return results


async def _remediate_target(
    client: RemediationClient,
    org: str,
    rem: _Remediator,
    target: _Target,
    *,
    apply: bool,
) -> RepoOutcome:
    """Refuse, preview or write one target, and say which."""
    refusal = target.refusal
    if refusal is None and rem.precheck is not None:
        refusal = await rem.precheck(client, org, target)
    if refusal is not None:
        return RepoOutcome(target.name, _REFUSED, refusal, target.verb)
    if not apply:
        return RepoOutcome(target.name, f"would {target.verb}", verb=target.verb)
    ok, note = await rem.write(client, org, target)
    action = _DONE[target.verb] if ok else _FAILED
    return RepoOutcome(target.name, action, note, target.verb)
