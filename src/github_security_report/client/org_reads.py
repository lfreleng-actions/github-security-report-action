# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Org-scope GitHub reads: repository listing, bulk sweeps and prefetch.

:class:`OrgReadClient` holds the reads issued once per organisation -- the
repository listing, the org-bulk alert sweeps, the org ruleset fetch and the
batched GraphQL prefetch -- leaving the per-repository probes to
:class:`~github_security_report.client.reads.ReadClient`, which extends it.
Methods return raw parsed JSON (and HTTP status where the status itself is the
signal, e.g. 404 = feature disabled).
"""

from __future__ import annotations

import logging

from github_security_report.client.endpoints import BULK_KINDS
from github_security_report.client.parsers import _parse_iso, _parse_repo_node
from github_security_report.client.queries import _REPO_GRAPH_FRAGMENT
from github_security_report.client.transport import NetworkError, Transport
from github_security_report.models import Repo, RepoGraphData

log = logging.getLogger(__name__)


def _aliases_with_errors(errors: object, alias_count: int) -> set[str]:
    """Alias keys implicated by a batched query's ``errors`` array.

    GitHub reports a *field-level* failure with HTTP 200: the alias is still a
    populated dictionary, the field that failed is null, and an ``errors``
    entry carries its path (e.g. ``["r3", "latestRelease"]``). Parsing such a
    node would convert a read failure into a confident negative -- a nulled
    ``latestRelease`` is indistinguishable from "never released" -- so the
    whole alias is treated as unreadable rather than partially trusted.

    The alias is failed wholesale rather than per field: a finer-grained flag
    per field would have to be threaded through every table to be honest
    about which half of a row is trustworthy, whereas one unknown repository
    is already a state every table renders correctly.

    An error whose path names no alias cannot be attributed, so it implicates
    every alias in the batch: with no way to tell which repositories it
    touched, treating any of them as successfully read would be a guess.
    """
    all_aliases = {f"r{i}" for i in range(alias_count)}
    if not isinstance(errors, list):
        return set()
    affected: set[str] = set()
    for entry in errors:
        path = entry.get("path") if isinstance(entry, dict) else None
        head = path[0] if isinstance(path, list) and path else None
        if isinstance(head, str) and head in all_aliases:
            affected.add(head)
        else:
            return all_aliases
    return affected


class OrgReadClient(Transport):
    """The org-scope reads: listing, bulk sweeps, rulesets and prefetch."""

    # ------------------------------------------------------------------ #
    # Repositories
    # ------------------------------------------------------------------ #
    async def list_org_repos(self, org: str) -> tuple[int, list[Repo]]:
        """List an organisation's repositories, skipping disabled/empty ones.

        Returns the listing status alongside the repos: a non-200 (a failed or
        mid-pagination-truncated listing) means the set is incomplete, so the
        caller can flag a partial report rather than silently omitting repos
        (and their offenders).
        """
        status, raws = await self._get_list(
            f"{self._api_url}/orgs/{org}/repos", type="all"
        )
        repos: list[Repo] = []
        for raw in raws:
            if raw.get("disabled") or raw.get("size", 0) == 0:
                log.info("skipping %s: disabled or empty", raw.get("full_name"))
                continue
            repos.append(
                Repo(
                    name=raw["name"],
                    full_name=raw["full_name"],
                    html_url=raw["html_url"],
                    archived=raw.get("archived", False),
                    fork=raw.get("fork", False),
                    is_template=raw.get("is_template", False),
                    private=raw.get("private", False),
                    created_at=_parse_iso(raw.get("created_at")),
                )
            )
        return status, repos

    # ------------------------------------------------------------------ #
    # Org-bulk alert sweeps
    # ------------------------------------------------------------------ #
    async def org_bulk_alerts(self, org: str, kind: str) -> tuple[int, list[dict]]:
        """Sweep all open alerts of one kind across the org.

        Returns the first-page HTTP status alongside the alerts so callers can
        tell an authoritative empty result (200 ``[]``) apart from an unreadable
        sweep (403/404/5xx), which must never be reported as "clean".
        """
        path = BULK_KINDS[kind]
        return await self._get_list(f"{self._api_url}/orgs/{org}/{path}", state="open")

    # ------------------------------------------------------------------ #
    # Organisation rulesets (workflow-driven tool enablement)
    # ------------------------------------------------------------------ #
    async def org_workflow_rulesets(self, org: str) -> tuple[int, list[dict]]:
        """Active, branch-targeted org rulesets, each with full rule details.

        Returns ``(status, details)``; status is the org-rulesets list status
        (e.g. 403 when the token lacks org access) so coverage can degrade
        gracefully. The list endpoint returns summaries, so each active branch
        ruleset is fetched in detail to expose its rules and conditions.
        """
        status, summaries = await self._get_list(f"{self._api_url}/orgs/{org}/rulesets")
        if status != 200:
            return status, []
        details: list[dict] = []
        for summary in summaries:
            if summary.get("enforcement") != "active":
                continue
            if summary.get("target") not in (None, "branch"):
                continue
            resp = await self._request(
                "GET", f"{self._api_url}/orgs/{org}/rulesets/{summary['id']}"
            )
            if resp.status_code == 200:
                details.append(resp.json())
            await resp.aclose()  # release the connection once the body is read
        return 200, details

    # ------------------------------------------------------------------ #
    # Batched per-repo prefetch (one query for many repositories)
    # ------------------------------------------------------------------ #
    async def repo_graph_batch(
        self, org: str, names: list[str]
    ) -> dict[str, RepoGraphData]:
        """Prefetch per-repo data for many repositories in one GraphQL query.

        Returns a ``RepoGraphData`` per requested name. This data is
        load-bearing for whole report sections (releases/tags, Dependabot
        enablement, open issues), and its defaults are indistinguishable from
        confident negatives ("never released"), so a wholly failed query --
        a non-200 response that survived the shared retry/backoff policy, or
        a 200 carrying no ``data`` object -- raises :class:`NetworkError` to
        abort the run rather than fabricating results. A repository that
        cannot be fully read -- a ``null`` alias, or a populated alias whose
        ``errors`` entry shows a field failed to resolve -- degrades to
        ``RepoGraphData(unreadable=True)`` so downstream tables report it as
        unknown. An empty ``names`` issues no request.
        """
        # Seed every requested name as unreadable; only a successfully parsed
        # alias replaces its entry, so nothing failed can masquerade as read.
        out = {name: RepoGraphData(unreadable=True) for name in names}
        if not names:
            return out
        aliases = "\n".join(
            f"  r{i}: repository(owner: $owner, name: $n{i}) {{ ...RepoData }}"
            for i in range(len(names))
        )
        var_decls = "".join(f", $n{i}: String!" for i in range(len(names)))
        query = (
            f"query($owner: String!{var_decls}) {{\n{aliases}\n}}\n"
            f"{_REPO_GRAPH_FRAGMENT}"
        )
        variables: dict[str, str] = {"owner": org}
        for i, name in enumerate(names):
            variables[f"n{i}"] = name
        resp = await self._request(
            "POST",
            self._graphql_url,
            json={"query": query, "variables": variables},
        )
        if resp.status_code != 200:
            status = resp.status_code
            await resp.aclose()  # unread body would leak a pooled connection
            raise NetworkError(
                f"GraphQL prefetch for {org} failed with HTTP {status} after "
                "exhausting retries; aborting because the release/tag, "
                "Dependabot-enablement and open-issues data for "
                f"{len(names)} repositories would otherwise be fabricated "
                "from defaults (e.g. reported as never released)."
            )
        body = resp.json()
        data = body.get("data")
        await resp.aclose()  # release the connection once the body is read
        # GitHub answers a partially-refused query with HTTP 200: the readable
        # aliases populated, the rest null or missing individual fields, and an
        # ``errors`` array explaining why. The paths are both logged for
        # diagnosis and used to fail the affected aliases, since a field nulled
        # by a failed read is indistinguishable from a genuine absence.
        errors = body.get("errors")
        errored_aliases = _aliases_with_errors(errors, len(names))
        if errors:
            log.warning(
                "GraphQL prefetch for %s returned %d error(s); affected data is "
                "reported as unknown: %s",
                org,
                len(errors),
                "; ".join(
                    f"{'.'.join(str(p) for p in (e.get('path') or []))}: "
                    f"{e.get('message', '')}"
                    for e in errors[:5]
                    if isinstance(e, dict)
                ),
            )
        if not isinstance(data, dict):
            # HTTP 200 with no data object at all: the whole batch failed
            # (e.g. a timed-out or refused query). Same stakes as a non-200.
            raise NetworkError(
                f"GraphQL prefetch for {org} returned no data for any of "
                f"{len(names)} repositories; aborting rather than reporting "
                "fabricated defaults. "
                f"errors={errors!r}"
            )
        for i, name in enumerate(names):
            alias = f"r{i}"
            if alias in errored_aliases:
                # A field of this alias failed to resolve, so its null fields
                # cannot be told apart from genuine absences. Leave the
                # pre-seeded unreadable default in place.
                continue
            node = data.get(alias)
            if isinstance(node, dict):
                out[name] = _parse_repo_node(node)
        unreadable = sorted(name for name, d in out.items() if d.unreadable)
        if unreadable:
            log.warning(
                "GraphQL prefetch for %s could not read %d repositories "
                "(reported as unknown): %s",
                org,
                len(unreadable),
                ", ".join(unreadable),
            )
        return out
