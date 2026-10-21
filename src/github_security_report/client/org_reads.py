# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Org-scope GitHub reads: repository listing, membership and prefetch.

:class:`OrgReadClient` holds the reads issued once per organisation -- the
repository listing, the org ruleset fetch, membership and the batched GraphQL
prefetch -- leaving the per-repository probes to
:class:`~github_security_report.client.reads.ReadClient`, which extends it, and
the alert sweeps to :class:`~github_security_report.client.alerts.AlertReads`,
which it extends. Methods return raw parsed JSON (and HTTP status where the
status itself is the signal, e.g. 404 = feature disabled).
"""

from __future__ import annotations

import logging

from github_security_report.authors import (
    MembershipGap,
    OrgMembership,
    is_automation_author,
    normalise_members,
)
from github_security_report.client.alerts import AlertReads
from github_security_report.client.batch_errors import _alias_errors, _batch_response
from github_security_report.client.parsers import _parse_iso, _parse_repo_node
from github_security_report.client.queries import (
    _ORG_MEMBERS_QUERY,
    _REPO_GRAPH_FRAGMENT,
    _VIEWER_QUERY,
)
from github_security_report.models import Repo, RepoGraphData

log = logging.getLogger(__name__)


# Pages of organisation membership to read before giving up. 100 pages is
# 10,000 members; beyond that the membership is reported as unknown rather than
# silently truncated.
_MEMBER_PAGE_LIMIT = 100


# HTTP statuses that mean the token may not read membership at all.
_PERMISSION_STATUSES = frozenset({401, 403})

# The GraphQL error ``type`` GitHub gives a query needing a scope the token
# lacks; for this query, ``read:org``.
_INSUFFICIENT_SCOPES = "INSUFFICIENT_SCOPES"


def _unreadable_membership(org: str, gap: MembershipGap) -> OrgMembership:
    """Record why membership is unknown; the terminal report shows the warning."""
    log.info("organisation membership for %s not read: %s", org, gap.value)
    return OrgMembership(members=None, gap=gap)


def _errors_gap(errors: object) -> MembershipGap:
    """Classify a GraphQL ``errors`` array: a missing scope, or anything else."""
    if isinstance(errors, list) and any(
        isinstance(error, dict) and error.get("type") == _INSUFFICIENT_SCOPES
        for error in errors
    ):
        return MembershipGap.PERMISSION
    return MembershipGap.UNREADABLE


class OrgReadClient(AlertReads):
    """The org-scope reads: listing, membership, rulesets and prefetch."""

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
                    # Every per-branch read (the CodeQL analyses, the head it
                    # is measured against) follows this, so a repository whose
                    # default branch is not "main" must not inherit that
                    # default from the model.
                    default_branch=raw.get("default_branch") or "main",
                    created_at=_parse_iso(raw.get("created_at")),
                )
            )
        return status, repos

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
    # Organisation membership (who counts as an insider)
    # ------------------------------------------------------------------ #
    async def org_members(self, org: str) -> OrgMembership:
        """Every organisation member's login, normalised, or why there are none.

        Collected once per organisation and reused for every repository, so
        deciding whether a contribution came from outside the organisation costs
        one query rather than a probe per author.

        The members are ``None`` -- never a partial set -- when membership
        cannot be read in full, and the result's ``gap`` says why: a token
        without ``read:org`` (:attr:`MembershipGap.PERMISSION`), a viewer
        outside the organisation (:attr:`MembershipGap.NOT_MEMBER`), or a
        failed page, malformed response or membership larger than the
        pagination guard (:attr:`MembershipGap.UNREADABLE`). A partial set is
        worse than none, because every member missing from it reads as an
        outsider, and the caller cannot tell an absent member from a genuine
        one. The caller degrades those authors to indeterminate instead.
        """
        logins: set[str] = set()
        after: str | None = None
        # Bounded so a malformed or hostile ``pageInfo`` cannot spin forever.
        # 100 pages is 10,000 members, far beyond any real organisation; an
        # organisation that somehow exceeds it is reported as unknown rather
        # than silently classified against its first 10,000 members.
        for _ in range(_MEMBER_PAGE_LIMIT):
            resp = await self._request(
                "POST",
                self._graphql_url,
                json={
                    "query": _ORG_MEMBERS_QUERY,
                    "variables": {"org": org, "after": after},
                },
            )
            if resp.status_code != 200:
                await resp.aclose()  # unread body would leak a pooled connection
                return _unreadable_membership(
                    org,
                    MembershipGap.PERMISSION
                    if resp.status_code in _PERMISSION_STATUSES
                    else MembershipGap.UNREADABLE,
                )
            body = resp.json()
            await resp.aclose()  # release the connection once the body is read
            if errors := body.get("errors"):
                # GraphQL answers a partially-failed query with HTTP 200,
                # populating what it could alongside an ``errors`` array. A
                # shortened member list is indistinguishable from a complete
                # one, so any error at all condemns the whole read. A token
                # without ``read:org`` lands here too: a null organisation and
                # an INSUFFICIENT_SCOPES error.
                return _unreadable_membership(org, _errors_gap(errors))
            organization = (body.get("data") or {}).get("organization")
            if not isinstance(organization, dict):
                # A token lacking organisation visibility gets HTTP 200 with a
                # null organisation and an ``errors`` entry; that is an unknown
                # membership, not an empty one.
                return _unreadable_membership(org, MembershipGap.UNREADABLE)
            if organization.get("viewerIsAMember") is not True:
                # The connection is visibility-filtered, not refused: a viewer
                # outside the organisation is served its *public* members with
                # no error at all. Trusting that would report every private
                # member as an outsider.
                return _unreadable_membership(org, MembershipGap.NOT_MEMBER)
            members = organization.get("membersWithRole")
            if not isinstance(members, dict):
                return _unreadable_membership(org, MembershipGap.UNREADABLE)
            for node in members.get("nodes") or []:
                # An unusable node is a member we cannot name, and a member
                # missing from the set reads as an outsider. There is no way to
                # tell a dropped entry from a genuine absence afterwards, so the
                # whole read is condemned rather than quietly shortened.
                login = node.get("login") if isinstance(node, dict) else None
                if not login:
                    return _unreadable_membership(org, MembershipGap.UNREADABLE)
                logins.add(str(login))
            page = members.get("pageInfo")
            if not isinstance(page, dict) or not isinstance(
                page.get("hasNextPage"), bool
            ):
                # Without a usable pageInfo there is no telling a final page
                # from a truncated one, so the set cannot be trusted as whole.
                return _unreadable_membership(org, MembershipGap.UNREADABLE)
            if not page["hasNextPage"]:
                return OrgMembership(members=normalise_members(logins))
            after = page.get("endCursor")
            if not isinstance(after, str):
                return _unreadable_membership(org, MembershipGap.UNREADABLE)
        return _unreadable_membership(org, MembershipGap.UNREADABLE)

    async def viewer_login(self) -> str:
        """The authenticated account's login, lower-cased, or ``""``.

        This is what "mine" means in the pull-request assignment breakdown, so
        it is the token's owner rather than a configured identity: a report run
        with someone else's token legitimately answers a different question.

        Returns ``""`` for an automation identity as well as for an unreadable
        account. A bot or App has no personal review queue, and its login can
        legitimately appear as an assignee, so returning it would populate
        "Mine" and the Assigned to Me table for an account that has no inbox --
        contradicting the documented behaviour of exactly the scheduled runs
        that are most likely to authenticate this way.
        """
        resp = await self._request(
            "POST", self._graphql_url, json={"query": _VIEWER_QUERY}
        )
        if resp.status_code != 200:
            await resp.aclose()  # unread body would leak a pooled connection
            return ""
        body = resp.json()
        await resp.aclose()  # release the connection once the body is read
        viewer = (body.get("data") or {}).get("viewer")
        if not isinstance(viewer, dict):
            return ""
        login = viewer.get("login")
        if not login:
            return ""
        typename = viewer.get("__typename")
        if is_automation_author(str(login), str(typename) if typename else None):
            log.info(
                "this run authenticated as the automation account %s, which has "
                "no personal review queue; the assignment breakdown reports "
                'nothing as "mine" and the Assigned to Me table is empty',
                login,
            )
            return ""
        return str(login).lower()

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
        a non-200 response that survived the shared retry/backoff policy, a
        200 carrying no ``data`` object, or a 200 whose ``errors`` report the
        query's resource limits exceeded -- raises :class:`GraphBatchError`
        (a :class:`NetworkError`; see :func:`_batch_response`) saying whether
        the caller may retry the same repositories in smaller batches, so a
        failure that query size could explain is split and any other aborts
        the run rather than fabricating results. A repository that
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
        status = resp.status_code
        # A non-200 body is never read; closing either way returns the pooled
        # connection rather than leaking it.
        body = resp.json() if status == 200 else None
        await resp.aclose()
        data, errors = _batch_response(org, len(names), status=status, body=body)
        # GitHub answers a partially-refused query with HTTP 200: the readable
        # aliases populated, the rest null or missing individual fields, and an
        # ``errors`` array explaining why. The paths are both logged for
        # diagnosis and used to fail the affected aliases, since a field nulled
        # by a failed read is indistinguishable from a genuine absence.
        errored_aliases, pull_request_errors = _alias_errors(errors, len(names))
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
        for i, name in enumerate(names):
            alias = f"r{i}"
            if alias in errored_aliases:
                # A field of this alias failed to resolve, so its null fields
                # cannot be told apart from genuine absences. Leave the
                # pre-seeded unreadable default in place.
                continue
            node = data.get(alias)
            if isinstance(node, dict):
                parsed = _parse_repo_node(node)
                if alias in pull_request_errors:
                    # Only the pull-request connection failed. Its own unknown
                    # state is already modelled, so report that rather than
                    # discarding this repository's other, readable data.
                    parsed.open_pull_requests = None
                    parsed.pull_requests = ()
                out[name] = parsed
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
