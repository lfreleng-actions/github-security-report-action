# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Progress events the transport emits, for a terminal display to consume.

The client knows when a request leaves, when its answer arrives and when
GitHub makes it wait, but it must not know how any of that is shown: it
imports nothing from the CLI or the renderers. Instead
:class:`~github_security_report.client.transport.Transport` reports each event
to a :class:`ProgressSink`, defaulting to :class:`NullSink`, so every caller
that passes none sees exactly the behaviour it saw before.
"""

from __future__ import annotations

from typing import Literal, Protocol

# What a request is: a REST read or write, a GraphQL query (a POST to the
# GraphQL endpoint) or a call to a third-party API (the Scorecard client).
RequestKind = Literal["rest", "graphql", "external"]


class ProgressSink(Protocol):
    """What a transport tells a display about the requests it makes.

    Every method is called from the event loop thread, between awaits, and
    must return quickly without raising: a slow or failing sink would stall
    or abort the collection it is meant to describe.
    """

    def on_request(self, kind: RequestKind, in_flight: int) -> None:
        """A request has been issued; ``in_flight`` counts it and its peers.

        In flight means inside the client's concurrency semaphore, awaiting
        an answer.
        """

    def on_response(
        self, kind: RequestKind, status: int | None, in_flight: int
    ) -> None:
        """A request has finished, with ``status`` or none when it never got one.

        ``in_flight`` is the count after this request left.
        """

    def on_rate_limited(self, delay: float, resource: str | None) -> None:
        """GitHub rate-limited a request; the client backs off ``delay`` seconds.

        ``resource`` is GitHub's ``x-ratelimit-resource`` for the request
        (``core``, ``graphql``, ...), when the response named one.
        """

    def on_rate_limit_cleared(self) -> None:
        """A rate-limit backoff reported by :meth:`on_rate_limited` has ended."""


class NullSink:
    """A sink that discards every event: the default."""

    def on_request(self, kind: RequestKind, in_flight: int) -> None:
        return None

    def on_response(
        self, kind: RequestKind, status: int | None, in_flight: int
    ) -> None:
        return None

    def on_rate_limited(self, delay: float, resource: str | None) -> None:
        return None

    def on_rate_limit_cleared(self) -> None:
        return None
