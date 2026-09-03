# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""GitHub's non-default secret-scanning patterns, and the guard against rot.

``GET .../secret-scanning/alerts`` returns only GitHub's *default* provider
patterns unless ``secret_type`` names something else. Two of GitHub's three
pattern categories fall outside that default:

- the **generic** patterns -- private keys, database connection strings, HTTP
  authentication headers -- matched by regex;
- the **AI-detected** patterns -- passwords and other unstructured secrets.

An unfiltered sweep omits every one of them and answers ``200 []`` for a
repository that is leaking a private key or a password. That empty result is
indistinguishable from a genuinely clean one, so no amount of status handling
downstream can catch it: the fix has to be in the request.

``secret_type`` is a *filter*, not an addition, so a single request cannot
cover every category -- naming the non-default patterns excludes the 500-odd
default ones, and the default set is far too large to enumerate in a query
string. Each sweep is therefore issued twice and the two results merged by
:func:`merge_alerts`.

That leaves a hardcoded list of slugs holding up the whole guarantee, and an
unrecognised ``secret_type`` is *not* an error: GitHub answers ``200 []``,
exactly the bug being fixed. A typo, or a pattern GitHub renames, would
therefore reintroduce it silently. :func:`unknown_generic_slugs` checks the
list against GitHub's own pattern inventory at runtime so the rot surfaces as a
warning instead.

This module is a leaf -- it imports nothing from the rest of the package -- so
the transport and the report-category registry can both name the pattern
vocabulary without an import cycle.
"""

from __future__ import annotations

# GitHub's supported generic secret-scanning patterns, by API slug:
# https://docs.github.com/en/code-security/secret-scanning/introduction/supported-secret-scanning-patterns#supported-generic-patterns
#
# These are the slugs the ``secret_type`` filter accepts, which are NOT the
# ``token_type`` an alert reports: ``generic_private_key`` is
# ``GENERIC_PRIVATE_KEY``, but ``ec_private_key`` is ``EC_SSH_PRIVATE_KEY`` and
# ``mongodb_connection_string`` is ``MONGODB_CONNECTION_URL``. Validation must
# therefore compare against the ``slug`` field, never ``token_type``.
GENERIC_SECRET_TYPES: tuple[str, ...] = (
    "ec_private_key",
    "generic_private_key",
    "http_basic_authentication_header",
    "http_bearer_authentication_header",
    "mongodb_connection_string",
    "mysql_connection_url",
    "openssh_private_key",
    "pgp_private_key",
    "postgres_connection_string",
    "rsa_private_key",
)

# GitHub's AI-detected patterns, a category of their own:
# https://docs.github.com/en/code-security/secret-scanning/introduction/supported-secret-scanning-patterns#supported-ai-detected-patterns
#
# Excluded from an unfiltered sweep exactly as the generic patterns are, but
# absent from the provider-pattern inventory (they are model-detected, not
# regex patterns), so :func:`unknown_generic_slugs` cannot check them and does
# not try: doing so would report a false rename on every run.
AI_DETECTED_SECRET_TYPES: tuple[str, ...] = ("password",)

# Every pattern the alerts API omits unless it is asked for by name.
EXPLICIT_SECRET_TYPES: tuple[str, ...] = (
    *GENERIC_SECRET_TYPES,
    *AI_DETECTED_SECRET_TYPES,
)

# The value sent as ``secret_type`` on the second sweep.
SECRET_TYPE_FILTER = ",".join(EXPLICIT_SECRET_TYPES)

# Where the runtime check reads GitHub's pattern inventory from. A classic PAT
# reads it with the ``read:org`` scope the tool already requires; a fine-grained
# token needs the optional organisation ``Administration`` permission (read), so
# the check is best-effort and stays silent when it cannot read it.
PATTERN_CONFIG_PATH = "secret-scanning/pattern-configurations"


def _alert_identity(alert: dict) -> tuple[str, ...] | None:
    """A key identifying one alert across both sweeps, or None if it has none.

    ``url`` is the alert's own API address and so is unique org-wide; the
    ``(repository, number)`` pair is the fallback for a payload without one
    (alert numbers are per repository, so the repository must be part of the
    key). ``None`` means the alert carries neither, in which case the caller
    keeps it rather than risk collapsing distinct alerts into one.
    """
    url = alert.get("url")
    if isinstance(url, str) and url:
        return ("url", url)
    number = alert.get("number")
    repo = alert.get("repository")
    full_name = repo.get("full_name") if isinstance(repo, dict) else None
    if number is None:
        return None
    # A per-repo read has no ``repository`` block; its alerts all belong to the
    # one repository being read, so the number alone identifies them there.
    return ("number", str(full_name), str(number))


def merge_alerts(*batches: list[dict]) -> list[dict]:
    """Merge secret-scanning sweeps, keeping the first sighting of each alert.

    The two sweeps should be disjoint -- ``secret_type`` filters rather than
    adds -- but that is GitHub's classification to change, not ours, so an
    alert appearing in both is de-duplicated rather than double-counted.
    Ordering is preserved so the merged list reads as the default patterns
    followed by the generic ones. An alert with no stable identity is kept:
    dropping a possible leak to tidy the output would be the worse failure.
    """
    merged: list[dict] = []
    seen: set[tuple[str, ...]] = set()
    for batch in batches:
        for alert in batch:
            key = _alert_identity(alert)
            if key is None:
                merged.append(alert)
                continue
            if key in seen:
                continue
            seen.add(key)
            merged.append(alert)
    return merged


def unknown_generic_slugs(payload: object) -> tuple[str, ...] | None:
    """Generic slugs this build names that GitHub's pattern inventory does not.

    ``payload`` is the body of the pattern-configurations endpoint. Returns the
    offending slugs (empty when the list is intact), or ``None`` when the
    payload cannot be read as an inventory -- an unreadable check must not be
    reported as a clean bill of health, nor as a list full of typos.

    Only :data:`GENERIC_SECRET_TYPES` is checked. That inventory covers the
    regex-matched provider patterns, of which the generic ones are part; the
    AI-detected patterns are model-detected and absent from it, so checking
    them here would report a rename on every run. They go unverified.
    """
    if not isinstance(payload, dict):
        return None
    overrides = payload.get("provider_pattern_overrides")
    if not isinstance(overrides, list):
        return None
    known = {
        entry["slug"]
        for entry in overrides
        if isinstance(entry, dict) and isinstance(entry.get("slug"), str)
    }
    if not known:
        # An inventory with no usable slugs says nothing about our list; a
        # shape change here must not be mistaken for ten renamed patterns.
        return None
    return tuple(slug for slug in GENERIC_SECRET_TYPES if slug not in known)
