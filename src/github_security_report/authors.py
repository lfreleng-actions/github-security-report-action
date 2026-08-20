# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Author classification: automation vs human, inside vs outside the org.

Two independent axes, both needed by the Issues and Pull Requests tables:

**Automation vs human.** Reproduces the canonical rule from the ``dependamerge``
tool (``bot_identity.py``): normalise the login (lower-case, strip a trailing
``[bot]``), match it against the known automation tools, and otherwise treat any
``[bot]``-suffixed login as automation so an unknown future bot still counts.
The GraphQL ``__typename`` is folded in first, because the API returns a bot's
login bare (``dependabot``) on some surfaces and suffixed (``dependabot[bot]``)
on others.

**Inside vs outside the organisation.** Deliberately *not* left to GitHub's
per-item ``authorAssociation`` alone, which is computed relative to the viewing
token: an organisation whose members' membership is private (the default) has
those members reported as ``MEMBER`` to a token with organisation visibility and
as ``CONTRIBUTOR``/``NONE`` to one without. Classifying on that field alone would
make a report's external-contribution counts depend on which token produced it,
and a token lacking ``read:org`` would report the entire organisation as
outsiders. So the collected organisation membership is the primary evidence and
``authorAssociation`` is a fallback -- the fallback still earns its place, since
it recognises a repository-level collaborator who is not an organisation member.

Automation is never counted as external. Bots are outsiders by association
(``dependabot[bot]`` reports ``CONTRIBUTOR`` or ``NONE``), so counting on
association alone would file every Dependabot pull request as an external
contribution and swamp the column that exists to surface genuine outside
contributors. Automation is reported in its own column instead.
"""

from __future__ import annotations

from collections.abc import Set

# --------------------------------------------------------------------------- #
# Automation authors
# --------------------------------------------------------------------------- #

# Marker GitHub appends to an App actor's login on the REST surface.
BOT_SUFFIX = "[bot]"

# GraphQL ``__typename`` for an App/bot actor.
BOT_TYPENAME = "Bot"

# Known automation-tool base logins (``[bot]``-stripped, lower-cased). Matching
# is against the *normalised* login so both the REST (``dependabot[bot]``) and
# GraphQL (``dependabot``) forms resolve. Any other App actor is still caught by
# the ``[bot]`` fallthrough, so this set exists to recognise the bare forms of
# known tools rather than to be exhaustive.
AUTOMATION_LOGINS = frozenset(
    {
        "dependabot",
        "renovate",
        "pre-commit-ci",
        "pre-commit",
        "github-actions",
        "allcontributors",
        "copilot",
        "github-copilot",
        "copilot-swe-agent",
    }
)


def normalise_login(login: str | None) -> str:
    """A lower-cased login with any trailing ``[bot]`` marker removed.

    Lets ``dependabot`` and ``dependabot[bot]`` compare equal regardless of
    which API surface produced the value.
    """
    if not login:
        return ""
    normalised = login.lower()
    if normalised.endswith(BOT_SUFFIX):
        normalised = normalised[: -len(BOT_SUFFIX)]
    return normalised


def is_automation_author(login: str | None, typename: str | None = None) -> bool:
    """Whether ``login`` is an automation/bot actor.

    ``typename`` is the GraphQL ``__typename`` of the author, which identifies an
    App actor authoritatively even when its login carries no ``[bot]`` marker.
    Falls back to the known-tool set and then to the ``[bot]`` suffix, so an
    unrecognised future bot is still classified as automation rather than being
    mistaken for an outside human contributor.
    """
    if not login:
        return False
    if typename == BOT_TYPENAME:
        return True
    if normalise_login(login) in AUTOMATION_LOGINS:
        return True
    return login.lower().endswith(BOT_SUFFIX)


# --------------------------------------------------------------------------- #
# Organisation insiders
# --------------------------------------------------------------------------- #

# ``authorAssociation`` values that place an author inside the organisation:
# an organisation member (any role), a repository-level collaborator, or the
# repository owner. Everything else (CONTRIBUTOR, FIRST_TIME_CONTRIBUTOR,
# FIRST_TIMER, MANNEQUIN, NONE) describes someone with no standing grant.
INSIDER_ASSOCIATIONS = frozenset({"OWNER", "MEMBER", "COLLABORATOR"})

# The full set of association values GitHub documents. A value outside this set
# is an API addition we have never seen, and guessing which side of the fence it
# belongs on would silently mis-count contributions, so it is reported as
# indeterminate instead.
KNOWN_ASSOCIATIONS = INSIDER_ASSOCIATIONS | {
    "CONTRIBUTOR",
    "FIRST_TIMER",
    "FIRST_TIME_CONTRIBUTOR",
    "MANNEQUIN",
    "NONE",
}


def is_external_author(
    login: str | None,
    *,
    association: str | None,
    members: Set[str] | None = frozenset(),
    typename: str | None = None,
) -> bool | None:
    """Whether an author contributed from outside the organisation.

    Returns ``None`` when the question cannot be answered: no login, an
    association GitHub has newly introduced, or membership that could not be
    read at all. ``None`` is not ``False`` -- an unclassifiable author must not
    be quietly counted as an insider, which would under-report exactly the
    contributions the column exists to surface.

    ``members`` is the organisation's collected membership (normalised logins),
    which is authoritative and token-independent; ``association`` is GitHub's
    per-item verdict, consulted afterwards so a repository-level collaborator
    who holds no organisation membership still counts as an insider.

    ``members`` of ``None`` means membership was never readable, which is
    materially different from an organisation with no members. In that state an
    association naming an insider is still trusted -- it is positive evidence,
    and only a token that *can* see the relationship reports it -- but an
    association naming an outsider proves nothing, because a token without
    organisation visibility reports private members exactly that way. Such
    authors are reported as indeterminate rather than external, so the very
    misclassification this function exists to avoid is not reintroduced through
    the fallback path.
    """
    if not login:
        return None
    # Automation is a separate axis, reported in its own column. Bots read as
    # outsiders by association, so this test must precede the association check.
    if is_automation_author(login, typename):
        return False
    if members and normalise_login(login) in members:
        return False
    if association in INSIDER_ASSOCIATIONS:
        return False
    if members is None:
        # Membership unknown, and the association cannot distinguish a genuine
        # outsider from a private member seen by an under-privileged token.
        return None
    if association in KNOWN_ASSOCIATIONS:
        return True
    return None


def normalise_members(logins: object) -> frozenset[str]:
    """Normalise a collected membership list into a comparable login set.

    Tolerates a malformed entry rather than failing the run: an unusable login
    is dropped, costing one member's insider status instead of the whole table.
    """
    if not isinstance(logins, (list, tuple, set, frozenset)):
        return frozenset()
    return frozenset(
        normalised
        for login in logins
        if isinstance(login, str) and (normalised := normalise_login(login))
    )
