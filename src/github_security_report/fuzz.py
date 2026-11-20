# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Fuzzing: which repositories the organisation's fuzz job could cover.

Fuzz failures arrive as code-scanning alerts, so the signal is classified like
aislop, with one addition: a repository holding none of the fuzzable languages
has nothing a fuzz engine could run, so it is not applicable rather than not
enabled. Applicability comes from the Linguist languages the batched GraphQL
prefetch already reads for GitHub Code Quality. See ADR-0009.

This module depends on nothing else in the package, so the configuration, the
collection and the classifier can all import it without a cycle.
"""

from __future__ import annotations

from collections.abc import Iterable

# The Linguist languages the organisation's fuzz job runs or will run.
DEFAULT_FUZZ_LANGUAGES: tuple[str, ...] = ("Python", "Go")


def fuzz_applicable(
    linguist: Iterable[str] | None, fuzzable: Iterable[str]
) -> bool | None:
    """Whether a repository holding ``linguist`` languages can be fuzzed.

    ``None`` when the languages could not be read, so a repository is never
    presumed out of scope from a failed read (ADR-0006 treats Code Quality the
    same way). Names compare case-insensitively, so a configured ``python``
    matches Linguist's ``Python``.
    """
    if linguist is None:
        return None
    wanted = {name.casefold() for name in fuzzable}
    return any(name.casefold() in wanted for name in linguist)
