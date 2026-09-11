# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Worst-first ordering of the repositories a signal found something in.

The domain default behind every offender table: which repository a reader meets
first. ``ordering.py`` owns the *configurable* orderings a report may ask for
and defers to :func:`rank_offenders` when a signal names none, so the two are
separate concerns -- what the reader chose, and what the domain says when they
chose nothing.

Kept out of ``models.py`` because these are decisions taken *about* the models
rather than part of them, and out of ``severity.py`` because they read a
``RepoSignal``, which would make that module import the models that already
import it.
"""

from __future__ import annotations

from github_security_report.models import RepoSignal
from github_security_report.severity import RUNGS_WORST_FIRST, Severity

# The rungs eligible to lead the Scorecard ordering, worst-first.
# ``INFORMATIONAL`` is deliberately absent: it is the non-actionable rung, so it
# never displaces the score as the primary key.
LEAD_RUNGS: tuple[Severity, ...] = tuple(
    rung for rung in RUNGS_WORST_FIRST if rung is not Severity.INFORMATIONAL
)


def lead_rung(offenders: list[RepoSignal]) -> Severity | None:
    """The worst severity rung any offender actually carries.

    Returns ``None`` when no offender carries a finding at Low or above, in
    which case there is no severity tier worth leading on.
    """
    return next(
        (rung for rung in LEAD_RUNGS if any(s.counts.at(rung) for s in offenders)),
        None,
    )


def rank_offenders(signals: list[RepoSignal]) -> list[RepoSignal]:
    """Sort offenders worst-first for a single signal.

    Alert-based signals sort by the hierarchical severity key descending, with
    total as a tiebreaker.

    Scorecard sorts on two tiers: the count at the worst severity rung present
    anywhere in the table (descending), then the aggregate score (ascending,
    lower == worse). The leading rung cascades -- Critical, else High, else
    Medium, else Low -- so the rung that actually discriminates between
    repositories leads, and a lone Critical can never be buried mid-table by a
    weaker repository with a lower score. When no offender carries a finding at
    Low or above, the score alone orders the table.

    Repo name breaks remaining ties, ascending.

    Numeric components are negated so the whole sort runs ascending (no
    ``reverse=True``); that keeps the name tiebreaker correctly ascending even
    when one name is a prefix of another.
    """
    offenders = [s for s in signals if s.is_offender]
    if not offenders:
        return []
    signal = offenders[0].signal
    if signal.sort_ascending:
        rung = lead_rung(offenders)
        return sorted(
            offenders,
            key=lambda s: (
                -s.counts.at(rung) if rung is not None else 0,
                s.score if s.score is not None else float("inf"),
                s.repo.name,
            ),
        )
    return sorted(
        offenders,
        key=lambda s: (
            -s.counts.critical,
            -s.counts.high,
            -s.counts.medium,
            -s.counts.low,
            -s.counts.total,
            s.repo.name,
        ),
    )
