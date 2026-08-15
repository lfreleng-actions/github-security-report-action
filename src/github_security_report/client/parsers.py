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

from github_security_report.models import IssueRef, ReleaseRef, RepoGraphData


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


def _label_names(node: dict) -> tuple[str, ...]:
    """Label names from one issue node's ``labels`` connection, in order.

    The connection, its ``nodes`` list and each entry may legally be null (or a
    non-dict) when a sub-object errors, so each level is guarded and unusable
    entries are skipped rather than aborting the parse.
    """
    labels = node.get("labels")
    if not isinstance(labels, dict):
        return ()
    names: list[str] = []
    for label in labels.get("nodes") or []:
        if not isinstance(label, dict):
            continue
        name = label.get("name")
        if not name:
            continue
        names.append(str(name))
    return tuple(names)


def _issue_refs(issues: dict | None) -> tuple[int, tuple[IssueRef, ...]]:
    """Open-issue total and window from an ``issues`` connection node.

    Returns the authoritative ``totalCount`` alongside the bounded window of
    parsed issues; the window may be shorter than the total on a repository
    with a large backlog. A missing or failed connection degrades to ``(0, ())``
    rather than raising, matching the other fields in this module. ``totalCount``
    likewise degrades to ``0`` when absent or not an integer.
    """
    if not isinstance(issues, dict):
        return 0, ()
    raw_total = issues.get("totalCount")
    # ``bool`` is an ``int`` subclass; a boolean here would be a schema
    # violation, so reject it rather than silently counting it as 0/1.
    total = (
        raw_total
        if isinstance(raw_total, int) and not isinstance(raw_total, bool)
        else 0
    )
    refs: list[IssueRef] = []
    for node in issues.get("nodes") or []:
        # GraphQL list entries may be null (e.g. when a sub-object errors);
        # skip non-dict nodes so a single bad entry cannot abort collection.
        if not isinstance(node, dict):
            continue
        number = node.get("number")
        if not isinstance(number, int) or isinstance(number, bool):
            continue
        refs.append(
            IssueRef(
                number=number,
                title=str(node.get("title") or ""),
                labels=_label_names(node),
                created_at=_parse_iso(node.get("createdAt")),
            )
        )
    return total, tuple(refs)


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
    open_issues, issues = _issue_refs(node.get("issues"))
    return RepoGraphData(
        dependabot_alerts_enabled=enabled,
        latest_tag_at=_tag_committed_date(node.get("tags")),
        latest_release_at=latest.published_at if latest else None,
        latest_release=latest,
        last_published_release=_last_published(candidates),
        dependabot_config=config_text,
        open_issues=open_issues,
        issues=issues,
    )
