# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Repository-name patterns: how every exclusion list matches a name.

Each entry of an exclusion list -- the organisation's ``exclude``, the
Releases table's ``releases_exclude``, and the report-wide and per-category
``exclude`` and ``exclude_tests`` lists -- is a regular expression,
*searched* against the repository name case-insensitively, as GitHub
compares names. Search rather than full match, so ``^test-`` reads as the
prefix it looks like; a plain name is a valid pattern that matches itself
(and any name containing it), and ``^name$`` pins one repository exactly.

One module, so every list matches the same way. It depends on nothing else
in the package.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence

Pattern = re.Pattern[str]


def compile_patterns(
    patterns: Iterable[str | Pattern], where: str
) -> tuple[Pattern, ...]:
    """Compile each entry once, naming the list and the pattern that fails.

    Rejected here rather than mid-run: a pattern that does not compile would
    otherwise surface only after the whole organisation had been read. An
    oversized repeat count raises ``OverflowError`` and deep nesting
    ``RecursionError`` rather than ``re.error``, so those are caught too.
    An already-compiled pattern passes through unchanged.
    """
    compiled: list[Pattern] = []
    for pattern in patterns:
        if isinstance(pattern, re.Pattern):
            compiled.append(pattern)
            continue
        try:
            compiled.append(re.compile(pattern, re.IGNORECASE))
        except (re.error, OverflowError, RecursionError) as exc:
            raise ValueError(
                f"{where} pattern {pattern!r} is not a valid regular expression: {exc}"
            ) from exc
    return tuple(compiled)


def matches(name: str, patterns: Sequence[Pattern]) -> bool:
    """Whether any pattern is found in ``name``."""
    return any(pattern.search(name) for pattern in patterns)
