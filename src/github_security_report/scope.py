# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Repository scoping and exclusions.

Default in-scope set: non-archived, non-fork, non-template source repos. Test
repositories are excluded by **token-delimited** matching (a ``test``/``tests``
segment after splitting on ``-_./``), never a raw substring -- so ``latest``,
``attestation`` and ``contest`` are not dropped. Archived and test repos never
appear in nag lists. Every exclusion is logged with its reason so nothing is
dropped silently. See ``docs/BRIEF.md`` section 7.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Sequence
from dataclasses import dataclass

from github_security_report.models import Repo

log = logging.getLogger(__name__)

_SEGMENT_SPLIT = re.compile(r"[-_./]+")
_TEST_SEGMENTS = {"test", "tests"}


def is_test_named(name: str) -> bool:
    """True when a name segment is exactly ``test`` or ``tests``.

    Token-delimited, not substring: ``test-action`` and ``foo_test`` match;
    ``latest-tag``, ``attestation`` and ``contest`` do not.
    """
    segments = {seg.lower() for seg in _SEGMENT_SPLIT.split(name) if seg}
    return bool(segments & _TEST_SEGMENTS)


@dataclass(frozen=True)
class ScopeDecision:
    repo: Repo
    included: bool
    reason: str = ""


def decide(
    repo: Repo,
    *,
    include_archived: bool = False,
    include_test: bool = False,
    exclude: frozenset[str] | set[str] | tuple[str, ...] = (),
) -> ScopeDecision:
    """Decide whether a single repository is in scope, with a reason.

    ``exclude`` matches case-insensitively, as GitHub treats repository names,
    so an entry never fails to exclude a repository over its capitalisation.
    """
    if repo.name.lower() in {name.lower() for name in exclude}:
        return ScopeDecision(repo, False, "explicitly excluded")
    if repo.fork:
        return ScopeDecision(repo, False, "fork")
    if repo.is_template:
        return ScopeDecision(repo, False, "template")
    if repo.archived and not include_archived:
        return ScopeDecision(repo, False, "archived")
    if is_test_named(repo.name) and not include_test:
        return ScopeDecision(repo, False, "test repository")
    return ScopeDecision(repo, True)


def filter_repos(
    repos: list[Repo],
    *,
    include_archived: bool = False,
    include_test: bool = False,
    exclude: tuple[str, ...] = (),
) -> list[Repo]:
    """Return the in-scope repositories, logging every exclusion and reason."""
    exclude_set = set(exclude)
    kept: list[Repo] = []
    for repo in repos:
        decision = decide(
            repo,
            include_archived=include_archived,
            include_test=include_test,
            exclude=exclude_set,
        )
        if decision.included:
            kept.append(repo)
        else:
            log.info("excluding %s: %s", repo.full_name, decision.reason)
    log.info("%d repositories in scope (of %d)", len(kept), len(repos))
    return kept


def in_nag_scope(repo: Repo) -> bool:
    """Whether a repo may appear in nag lists.

    Archived and test repos are **never** nagged -- you cannot, or would not,
    enable tooling on them -- even when they are otherwise reported (e.g. under
    ``include_archived``/``include_test``).
    """
    return not (repo.archived or is_test_named(repo.name))


# --------------------------------------------------------------------------- #
# Named repository selection (``remediate --repos``)
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class RepoRef:
    """One named repository: ``name`` in any org, or ``owner/name`` in one.

    Matched case-insensitively, as GitHub treats repository and organisation
    names.
    """

    name: str
    owner: str | None = None

    def matches(self, org: str, repo_name: str) -> bool:
        """Whether this reference names ``repo_name`` in organisation ``org``."""
        if self.owner is not None and self.owner.lower() != org.lower():
            return False
        return self.name.lower() == repo_name.lower()

    def __str__(self) -> str:
        return f"{self.owner}/{self.name}" if self.owner else self.name


class RepoSelectionError(ValueError):
    """A ``--repos`` value that names no repository in a usable form."""


def parse_repo_selection(values: Sequence[str]) -> tuple[RepoRef, ...]:
    """The repositories named by ``--repos`` values, de-duplicated, in order.

    Each value is a comma-separated list, and the option may be repeated, so
    ``--repos a,b --repos c`` names three. An entry is ``name`` or
    ``owner/name``; blank entries (a trailing comma) are ignored, and anything
    else raises :class:`RepoSelectionError`.
    """
    refs: list[RepoRef] = []
    seen: set[tuple[str | None, str]] = set()
    for value in values:
        for entry in (part.strip() for part in value.split(",")):
            if not entry:
                continue
            owner, _, name = entry.rpartition("/")
            if not name or "/" in owner or (entry.count("/") and not owner):
                raise RepoSelectionError(
                    f"not a repository name or owner/name: {entry!r}"
                )
            ref = RepoRef(name=name, owner=owner or None)
            key = (ref.owner.lower() if ref.owner else None, ref.name.lower())
            if key not in seen:
                seen.add(key)
                refs.append(ref)
    return tuple(refs)


def select_named(
    org: str, repos: Sequence[Repo], refs: Sequence[RepoRef]
) -> list[Repo]:
    """The repositories in ``repos`` that any of ``refs`` names in ``org``."""
    return [repo for repo in repos if any(ref.matches(org, repo.name) for ref in refs)]
