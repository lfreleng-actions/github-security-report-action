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

from github_security_report.authors import is_automation_author, normalise_members
from github_security_report.client.alerts import AlertReads
from github_security_report.client.parsers import _parse_iso, _parse_repo_node
from github_security_report.client.queries import (
    _ORG_MEMBERS_QUERY,
    _REPO_GRAPH_FRAGMENT,
    _VIEWER_QUERY,
)
from github_security_report.client.transport import NetworkError
from github_security_report.models import Repo, RepoGraphData

log = logging.getLogger(__name__)

# Pages of organisation membership to read before giving up. 100 pages is
# 10,000 members; beyond that the membership is reported as unknown rather than
# silently truncated.
_MEMBER_PAGE_LIMIT = 100

# Fields whose failure can be isolated to the data they feed instead of failing
# the whole repository. Only fields the model already carries a dedicated
# "unknown" for qualify: ``pullRequests`` has ``open_pull_requests=None``, which
# every pull-request table already renders as unknown, so a token that cannot
# read pull requests loses that one table rather than the repository's releases,
# issues, tags and Dependabot posture as well.
_ISOLABLE_FIELDS = frozenset({"pullRequests"})


def _log_unreadable_membership(org: str, *, outside: bool = False) -> None:
    """Report that membership could not be read in full, once per attempt."""
    reason = (
        "the account this run authenticated as is not a member of it, so "
        "GitHub served only its public members"
        if outside
        else "it could not be read in full"
    )
    log.warning(
        "organisation membership for %s is incomplete (%s); "
        "externally-raised contributions cannot be identified reliably and "
        "are reported as a lower bound rather than guessed from GitHub's "
        "per-item author association, which reports private members as "
        "outsiders to a token without organisation visibility",
        org,
        reason,
    )


def _alias_errors(errors: object, alias_count: int) -> tuple[set[str], set[str]]:
    """Alias keys implicated by a batched query's ``errors`` array.

    Returns ``(unreadable, pull_requests_only)``: aliases that must be failed
    wholesale, and aliases whose only failures were confined to fields in
    :data:`_ISOLABLE_FIELDS`.

    GitHub reports a *field-level* failure with HTTP 200: the alias is still a
    populated dictionary, the field that failed is null, and an ``errors``
    entry carries its path (e.g. ``["r3", "latestRelease"]``). Parsing such a
    node would convert a read failure into a confident negative -- a nulled
    ``latestRelease`` is indistinguishable from "never released" -- so the
    whole alias is treated as unreadable rather than partially trusted.

    The alias is failed wholesale rather than per field, because a per-field
    flag would have to be threaded through every table to be honest about which
    half of a row is trustworthy, whereas one unknown repository is already a
    state every table renders correctly. The exception is a field the model
    *already* carries a dedicated unknown for: failing the whole repository for
    one of those would let an optional, permission-sensitive section take the
    rest of the report down with it -- a token without pull-request access would
    lose its releases, issues and Dependabot posture too.

    An error whose path names no alias cannot be attributed, so it implicates
    every alias in the batch: with no way to tell which repositories it
    touched, treating any of them as successfully read would be a guess.

    An error *nested* inside an isolable field is classified by that field, and
    deliberately so. ``reviewThreads`` is non-null in GitHub's schema
    (``PullRequestReviewThreadConnection!``), so a resolver failure there does
    not null the connection: it propagates up to the nearest nullable ancestor,
    which is the pull-request node itself. The node arrives as ``null`` and
    carries none of its facts, so ignoring the error would silently drop that
    pull request from every column while ``totalCount`` still counted it --
    understating the breakdown with nothing to say so. Failing the connection
    reports the repository as unknown instead, which every table renders
    correctly.
    """
    all_aliases = {f"r{i}" for i in range(alias_count)}
    if not isinstance(errors, list):
        return set(), set()
    unreadable: set[str] = set()
    isolated: set[str] = set()
    for entry in errors:
        path = entry.get("path") if isinstance(entry, dict) else None
        if not isinstance(path, list) or not path:
            return all_aliases, set()
        head = path[0]
        if not isinstance(head, str) or head not in all_aliases:
            return all_aliases, set()
        field = path[1] if len(path) > 1 else None
        if isinstance(field, str) and field in _ISOLABLE_FIELDS:
            isolated.add(head)
        else:
            unreadable.add(head)
    # An alias with failures on both sides is unreadable: the isolable one is
    # the lesser problem, and the other still poisons the rest of the node.
    return unreadable, isolated - unreadable


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
    async def org_members(self, org: str) -> frozenset[str] | None:
        """Every organisation member's login, normalised, or ``None``.

        Collected once per organisation and reused for every repository, so
        deciding whether a contribution came from outside the organisation costs
        one query rather than a probe per author.

        Returns ``None`` -- never a partial set -- when membership cannot be
        read in full: a token without ``read:org``, a viewer outside the
        organisation, a failed page, or a membership larger than the pagination
        guard. A partial set is worse than none, because every member missing
        from it reads as an outsider, and the caller cannot tell an absent
        member from a genuine one. The caller degrades those authors to
        indeterminate instead.
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
                _log_unreadable_membership(org)
                return None
            body = resp.json()
            await resp.aclose()  # release the connection once the body is read
            if body.get("errors"):
                # GraphQL answers a partially-failed query with HTTP 200,
                # populating what it could alongside an ``errors`` array. A
                # shortened member list is indistinguishable from a complete
                # one, so any error at all condemns the whole read.
                _log_unreadable_membership(org)
                return None
            organization = (body.get("data") or {}).get("organization")
            if not isinstance(organization, dict):
                # A token lacking organisation visibility gets HTTP 200 with a
                # null organisation and an ``errors`` entry; that is an unknown
                # membership, not an empty one.
                _log_unreadable_membership(org)
                return None
            if organization.get("viewerIsAMember") is not True:
                # The connection is visibility-filtered, not refused: a viewer
                # outside the organisation is served its *public* members with
                # no error at all. Trusting that would report every private
                # member as an outsider.
                _log_unreadable_membership(org, outside=True)
                return None
            members = organization.get("membersWithRole")
            if not isinstance(members, dict):
                _log_unreadable_membership(org)
                return None
            for node in members.get("nodes") or []:
                # An unusable node is a member we cannot name, and a member
                # missing from the set reads as an outsider. There is no way to
                # tell a dropped entry from a genuine absence afterwards, so the
                # whole read is condemned rather than quietly shortened.
                login = node.get("login") if isinstance(node, dict) else None
                if not login:
                    _log_unreadable_membership(org)
                    return None
                logins.add(str(login))
            page = members.get("pageInfo")
            if not isinstance(page, dict) or not page.get("hasNextPage"):
                return normalise_members(logins)
            after = page.get("endCursor")
            if not isinstance(after, str):
                _log_unreadable_membership(org)
                return None
        _log_unreadable_membership(org)
        return None

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
