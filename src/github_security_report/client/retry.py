# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Retry bookkeeping for :class:`~.transport.Transport`'s request loop."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

from github_security_report.client.endpoints import API_MAX_TOTAL_WAIT_SECONDS
from github_security_report.client.events import RequestKind


def _is_read(method: str, kind: RequestKind) -> bool:
    """Whether a request reads: a ``GET``, or a GraphQL query's ``POST``."""
    return method.upper() == "GET" or kind == "graphql"


class _RetryBudget:
    """Attempts spent and seconds slept so far within one ``_request`` call.

    Holds the state the retry loop carries across iterations, so deciding that
    the budget has run out and spending it (sleep, then count the attempt) stay
    together instead of being open-coded at every backoff site.
    """

    def __init__(self, max_retries: int) -> None:
        self.attempt = 0
        self.waited = 0.0
        self.max_retries = max_retries

    def exhausted(self, delay: float) -> bool:
        """Whether sleeping ``delay`` would exceed the retry or wait budget."""
        return (
            self.attempt >= self.max_retries
            or self.waited + delay > API_MAX_TOTAL_WAIT_SECONDS
        )

    async def sleep(self, delay: float) -> None:
        """Back off for ``delay`` seconds and charge them to the budget."""
        await asyncio.sleep(delay)
        self.waited += delay
        self.attempt += 1


@dataclass(frozen=True)
class _RetryPlan:
    """How a reachable-but-degraded (403/429/5xx) response should be treated.

    ``retriable`` is false for a genuine permission error, which is handed
    straight back to the caller; ``server_error`` only selects the wording of
    the retry warning.
    """

    retriable: bool
    server_error: bool
    delay: float
