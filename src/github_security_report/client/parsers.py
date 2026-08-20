# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Pure parsing helpers for GitHub REST headers and GraphQL response nodes.

Stateless functions shared by the transport and read layers; none of them
performs I/O, so they are directly unit-testable.
"""

from __future__ import annotations

import contextlib
import datetime as dt
from dataclasses import replace
from email.utils import parsedate_to_datetime
from typing import cast

import httpx

from github_security_report.models import AuthorRef, IssueRef, ReleaseRef, RepoGraphData


def _parse_iso(value: object) -> dt.datetime | None:
    """Parse a GitHub ISO-8601 timestamp (``...Z``) into an aware datetime."""
    if not isinstance(value, str) or not value:
        return None
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _parse_retry_after(value: str | None) -> float | None:
    """Seconds to wait from a ``Retry-After`` header, or ``None`` if absent/bad.

    Per RFC 7231 ``Retry-After`` is either delta-seconds (an integer) or an
    HTTP-date. GitHub normally sends delta-seconds, but a proxy or future change
    may send a date, so both forms are parsed: a bare ``float(value)`` would
    raise ``ValueError`` on a date and crash rate-limit handling. A past or
    unparsable date clamps to ``0.0`` / returns ``None`` rather than raising.
    """
    if not value:
        return None
    value = value.strip()
    # Delta-seconds first; on ValueError fall through to HTTP-date parsing.
    with contextlib.suppress(ValueError):
        return max(0.0, float(value))
    try:
        when = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if when is None:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=dt.timezone.utc)
    return max(0.0, (when - dt.datetime.now(dt.timezone.utc)).total_seconds())


def _next_page_url(resp: httpx.Response) -> str | None:
    """URL of the RFC 5988 ``next`` link header, or ``None`` on the last page."""
    next_link = resp.links.get("next")
    return next_link.get("url") if next_link else None


def _tag_committed_date(tags: dict | None) -> dt.datetime | None:
    """Commit date of the most-recent tag from a ``tags`` connection node.

    A tag ref's target is a Commit (lightweight tag) or a Tag object (annotated
    tag) whose own target is the Commit; both branches are read.
    """
    nodes = (tags or {}).get("nodes") or []
    if not nodes:
        return None
    # GraphQL connection nodes may legally be null (or non-dict) when a
    # sub-object errors; guard the node and its target so a bad entry
    # degrades to None instead of aborting the batched collection.
    first = nodes[0]
    if not isinstance(first, dict):
        return None
    target = first.get("target")
    if not isinstance(target, dict):
        return None
    committed = target.get("committedDate")
    if committed is None:  # annotated tag: the Tag's target is the Commit
        inner = target.get("target")
        committed = inner.get("committedDate") if isinstance(inner, dict) else None
    return _parse_iso(committed)


def _release_refs(nodes: list[dict]) -> list[ReleaseRef]:
    """Build :class:`ReleaseRef` objects from release connection nodes.

    Draft releases are skipped (they are never published), as are nodes with no
    tag. ``published_at`` falls back to the creation time when GitHub supplies
    no publish timestamp.
    """
    refs: list[ReleaseRef] = []
    for node in nodes:
        # GraphQL list entries may be null (e.g. when a sub-object errors);
        # skip non-dict nodes so a single bad entry cannot abort collection.
        if not isinstance(node, dict):
            continue
        if node.get("isDraft"):
            continue
        tag = node.get("tagName")
        if not tag:
            continue
        published = _parse_iso(node.get("publishedAt")) or _parse_iso(
            node.get("createdAt")
        )
        # ``immutable`` is nullable in GitHub's GraphQL schema; preserve a
        # missing value as None (indeterminate) rather than coercing it to
        # False, which would misreport an unknown state as mutable.
        raw_immutable = node.get("immutable")
        refs.append(
            ReleaseRef(
                tag=tag,
                immutable=None if raw_immutable is None else bool(raw_immutable),
                published_at=published,
                is_latest=bool(node.get("isLatest")),
                is_prerelease=bool(node.get("isPrerelease")),
            )
        )
    return refs


def _last_published(refs: list[ReleaseRef]) -> ReleaseRef | None:
    """Most recently published release, ignoring those with no publish time."""
    dated = [r for r in refs if r.published_at is not None]
    if not dated:
        return None
    return max(dated, key=lambda r: cast(dt.datetime, r.published_at))


def _label_names(node: dict) -> tuple[tuple[str, ...], bool]:
    """Label names from one issue node's ``labels`` connection, and truncation.

    Returns the names in order alongside a flag saying whether the labels seen
    might be incomplete -- either because the issue carries more than the
    query's window returned, or because the connection could not be read at
    all. The connection, its ``nodes`` list and each entry may legally be null
    (or a non-dict) when a sub-object errors, so each level is guarded and
    unusable entries are skipped rather than aborting the parse.
    """
    labels = node.get("labels")
    if not isinstance(labels, dict):
        # The connection itself was unreadable. That is *not* an issue with no
        # labels: reporting it as such would fabricate a triage gap out of a
        # sub-object error, so it is flagged indeterminate and the row it lands
        # in is marked partial.
        return (), True
    names: list[str] = []
    for label in labels.get("nodes") or []:
        if not isinstance(label, dict):
            continue
        name = label.get("name")
        if not name:
            continue
        names.append(str(name))
    raw_total = labels.get("totalCount")
    if not isinstance(raw_total, int) or isinstance(raw_total, bool):
        # No usable count means no evidence that the names we got are all of
        # them, so the issue is flagged as possibly incompletely labelled.
        return tuple(names), True
    return tuple(names), raw_total > len(names)


def _author_ref(node: dict) -> AuthorRef | None:
    """The author facts from an issue or pull-request node, or None.

    GitHub renders ``author`` as null for a deleted account, which is not the
    same as an author we chose not to classify, so the absence is preserved.
    ``authorAssociation`` lives on the item rather than the actor, so it is read
    from the enclosing node.
    """
    author = node.get("author")
    if not isinstance(author, dict):
        return None
    login = author.get("login")
    if not login:
        return None
    association = node.get("authorAssociation")
    return AuthorRef(
        login=str(login),
        typename=str(author.get("__typename") or ""),
        association=str(association or ""),
    )


def _issue_ref(node: object) -> IssueRef | None:
    """One parsed issue, or None when the node is unusable.

    GraphQL list entries may legally be null (e.g. when a sub-object errors),
    and an entry without a usable number is not an issue we can report on, so
    both are rejected rather than aborting the surrounding parse.
    """
    if not isinstance(node, dict):
        return None
    number = node.get("number")
    if not isinstance(number, int) or isinstance(number, bool):
        return None
    labels, labels_truncated = _label_names(node)
    return IssueRef(
        number=number,
        title=str(node.get("title") or ""),
        labels=labels,
        labels_truncated=labels_truncated,
        created_at=_parse_iso(node.get("createdAt")),
        author=_author_ref(node),
    )


def _issue_refs(issues: object) -> tuple[int | None, tuple[IssueRef, ...], bool]:
    """Open-issue total and window from an ``issues`` connection node.

    Returns the authoritative ``totalCount`` alongside the bounded window of
    parsed issues; the window may be shorter than the total on a repository with
    a large backlog.

    A missing or failed connection returns ``(None, ())`` -- **not** ``(0, ())``.
    GitHub answers a query whose ``issues`` field it will not serve (a
    fine-grained token without ``Issues: read``, say) with HTTP 200, the rest of
    the repository populated, and this one sub-object null plus an entry in
    ``errors``. Reporting that as zero open issues would render a confident
    "no open issues" for an organisation whose backlog was never readable, so
    the absence is preserved as indeterminate for the caller to surface as
    unknown. A ``totalCount`` that is absent, null or not an integer is no
    reading at all rather than a reading of zero, so it is preserved as
    indeterminate too -- a repository whose nodes came back cannot be clean.

    The third element reports whether the leading (oldest) node was dropped.
    Skipping it silently would promote a newer issue to entry 0, whose age the
    report would then present as the oldest -- plausible, and wrong.
    """
    if not isinstance(issues, dict):
        return None, (), False
    raw_total = issues.get("totalCount")
    # ``bool`` is an ``int`` subclass; a boolean here would be a schema
    # violation, so reject it rather than silently counting it as 0/1.
    total = (
        raw_total
        if isinstance(raw_total, int) and not isinstance(raw_total, bool)
        else None
    )
    refs: list[IssueRef] = []
    lead_unreadable = False
    for node in issues.get("nodes") or []:
        ref = _issue_ref(node)
        if ref is None:
            # Only a gap *before* the first survivor changes which issue ends
            # up at entry 0; a later gap costs detail, not the oldest-issue
            # answer.
            lead_unreadable = lead_unreadable or not refs
            continue
        refs.append(ref)
    return total, tuple(refs), lead_unreadable


def _parse_repo_node(node: dict) -> RepoGraphData:
    """Map one repository alias from the batched query to ``RepoGraphData``.

    The "Latest" release is taken from GitHub's authoritative ``latestRelease``
    field rather than scanning the bounded ``releases`` window: a repository
    with many newer draft or pre-release entries could otherwise push the
    ``isLatest`` release out of the window, dropping it from staleness and the
    Mutable Releases findings. The window still feeds the last-published
    computation, with the latest ref folded in (deduplicated by tag).

    Open issues arrive as an authoritative ``totalCount`` plus a bounded,
    oldest-first window of nodes, which may be shorter than that total.
    """
    enabled_raw = node.get("hasVulnerabilityAlertsEnabled")
    enabled = bool(enabled_raw) if enabled_raw is not None else None
    config_obj = node.get("dependabotConfig")
    config_text = config_obj.get("text") if isinstance(config_obj, dict) else None
    window = _release_refs((node.get("releases") or {}).get("nodes") or [])
    latest_node = node.get("latestRelease")
    latest: ReleaseRef | None = None
    if isinstance(latest_node, dict):
        parsed = _release_refs([latest_node])
        if parsed:
            # Force the "Latest" badge: latestRelease is authoritative even
            # when the node's own isLatest flag is absent or stale.
            latest = replace(parsed[0], is_latest=True)
    candidates = list(window)
    if latest is not None and all(r.tag != latest.tag for r in candidates):
        candidates.append(latest)
    open_issues, issues, oldest_unreadable = _issue_refs(node.get("issues"))
    return RepoGraphData(
        dependabot_alerts_enabled=enabled,
        latest_tag_at=_tag_committed_date(node.get("tags")),
        latest_release_at=latest.published_at if latest else None,
        latest_release=latest,
        last_published_release=_last_published(candidates),
        dependabot_config=config_text,
        open_issues=open_issues,
        issues=issues,
        oldest_issue_unreadable=oldest_unreadable,
    )
