# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""The remediate mode: collect each organisation's posture, then act on it.

Split from :mod:`~github_security_report.cli.modes` so the report modes and
the write-capable one each read as a short file; the coroutine returns the
process exit code like the others.
"""

from __future__ import annotations

import datetime as dt
import logging
from collections.abc import Sequence
from pathlib import Path

from rich.console import Console

from github_security_report import collect, scope
from github_security_report import remediate as remediate_mod
from github_security_report.categories import CategoryKey
from github_security_report.cli.progress import make_tracker
from github_security_report.client import GitHubClient
from github_security_report.collect.context import CollectExtras
from github_security_report.collect.protocols import ClientProtocol
from github_security_report.config import Config
from github_security_report.models import Repo
from github_security_report.render import terminal as term_render

log = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Remediation
# --------------------------------------------------------------------------- #
async def _run_remediate(
    cfg: Config,
    *,
    console: Console,
    token: str,
    categories: Sequence[CategoryKey],
    apply: bool,
    repos: Sequence[scope.RepoRef] = (),
    config_path: Path | None = None,
    no_progress: bool = False,
) -> int:
    """Collect each org's posture and enable (or preview enabling) features.

    A single write-capable token drives both the read (collection) and the
    writes for every configured org, so the per-org read ``token_env`` in the
    config is intentionally bypassed. ``repos``, when given, limits every
    category to those repositories; the selection is checked against every
    org before anything is read or written, and a name that matches nothing,
    or only an excluded repository, stops the run. ``config_path`` is the
    auto-discovered config file, printed under each org's divider. Returns 2
    for a bad selection, 1 when any write failed, else 0.
    """
    now = dt.datetime.now(dt.timezone.utc)
    failures = 0
    # One live line per organisation, kept up through the writes too: the
    # paced CodeQL cleanup is otherwise a silent second per deletion.
    tracker = make_tracker(console, no_progress=no_progress)
    async with GitHubClient(token, progress=tracker) as client:
        selected = await _check_selection(client, cfg, repos, console=console)
        if selected is None:
            return 2
        for index, org_cfg in enumerate(cfg.organizations):
            if repos and index not in selected:
                continue  # none of the named repositories live here
            tracker.start(org_cfg.name)
            try:
                # The validated repositories themselves, so collection cannot
                # silently lose one to a second, incomplete listing.
                report = await collect.collect_org(
                    client,
                    org_cfg,
                    org_cfg.report,
                    generated_at=now,
                    selected=selected[index] if repos else None,
                    # No remediation acts on the author-aware tables, so their
                    # membership and viewer reads would only cost requests.
                    extras=CollectExtras(author_tables=False, progress=tracker),
                )
                tracker.phase("applying" if apply else "previewing remediation")
                results = await remediate_mod.remediate_org(
                    client, report, categories=categories, apply=apply
                )
            finally:
                tracker.stop()
            # Honour the org's configured terminal offender limit, the same
            # cap the report's CLI output uses, so large orgs stay readable.
            term_render.render_remediation(
                report.org,
                results,
                console,
                apply=apply,
                top_n=org_cfg.report.cli_top_n,
                # This entry's own validated repositories, not every selector:
                # in a multi-org run each org names only what it collected.
                limited_to=[r.name for r in selected[index]] if repos else [],
                config_path=config_path,
            )
            failures += sum(result.failures for result in results)
    return 1 if failures else 0


async def _check_selection(
    client: ClientProtocol,
    cfg: Config,
    repos: Sequence[scope.RepoRef],
    *,
    console: Console,
) -> dict[int, tuple[Repo, ...]] | None:
    """Each org entry's repositories a selection names, or None to stop.

    Keyed by the entry's position in the configuration, holding only entries
    with a match: a run collects exactly these, so an entry the selection
    never touches is skipped. Keyed by position rather than name because the
    configuration may list one organisation twice with different scoping;
    each entry must act only on what its own configuration allows.

    Every name must match a repository some configured org has in scope. A
    name matching nothing is almost always a typo, and one matching only an
    excluded repository (the exclude list, archived, fork, template, test)
    must not bypass that exclusion, so both stop the run. So does any org
    whose listing came back incomplete, since it may hide a repository a
    selector names. Every problem is reported at once. An empty selection
    returns an empty mapping, which callers read as "no selection".
    """
    if not repos:
        return {}
    usable: dict[scope.RepoRef, bool] = dict.fromkeys(repos, False)
    excluded: dict[scope.RepoRef, list[str]] = {ref: [] for ref in repos}
    touched: dict[int, tuple[Repo, ...]] = {}
    problems: list[str] = []
    for index, org_cfg in enumerate(cfg.organizations):
        named = await collect.check_named_repos(client, org_cfg, org_cfg.report, repos)
        if named.partial:
            # A narrowed run must validate its whole target set, and an
            # incomplete listing may hide a repository a selector names (a
            # bare name can match in any org), so it cannot proceed on the
            # matches it happened to see.
            problems.append(
                f"the repository listing for {org_cfg.name} was incomplete, so "
                "the selection cannot be checked in full; try again"
            )
        for ref in repos:
            if any(ref.matches(org_cfg.name, r.name) for r in named.in_scope):
                usable[ref] = True
            excluded[ref].extend(
                f"{r.full_name} is excluded ({reason})"
                for r, reason in named.excluded
                if ref.matches(org_cfg.name, r.name)
            )
        if named.in_scope:
            touched[index] = named.in_scope
    # A bare name may be usable in one org and excluded in another: only a
    # name with no usable match anywhere is a problem, so the run acts on the
    # usable match and never on the excluded one.
    for ref in repos:
        if not usable[ref]:
            problems.extend(excluded[ref])
    unknown = [str(ref) for ref in repos if not usable[ref] and not excluded[ref]]
    if unknown:
        where = ", ".join(org_cfg.name for org_cfg in cfg.organizations)
        problems.append(f"no repository named {', '.join(unknown)} in {where}")
    if problems:
        # markup=False: repository names come from the command line and the API.
        for problem in problems:
            console.print(f"--repos: {problem}", style="red", markup=False)
        return None
    return touched
