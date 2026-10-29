# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Paginated REST walks and single GraphQL queries over the transport.

:class:`Paging` adds the two read primitives every GitHub client layer above
it is built from: :meth:`Paging._paginate`, which walks a ``Link``-paginated
list (optionally stopping early and sending a conditional request), and
:meth:`Paging._graphql`, which posts one query and parses the answer. Both
run under :class:`~github_security_report.client.transport.Transport`'s
retry/backoff policy and close every response they open.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field

from github_security_report.client.parsers import _next_page_url
from github_security_report.client.transport import Transport

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class PageResult:
    """What walking a paginated GitHub list produced.

    ``status`` is the first page's HTTP status, or a later page's when one
    failed part-way (the items gathered before it are kept, so a caller can
    tell an undercount from a complete read). ``304`` means the caller's
    ``etag`` still matched: nothing was read and ``items`` is empty. ``etag``
    is the first page's validator, for the caller to present next time;
    ``None`` when the read failed or GitHub sent none. ``stopped`` says the
    caller's ``stop`` predicate ended the walk before the last page, which is
    how an incremental read knows it reached data it already held rather than
    the end of the list.
    """

    status: int
    items: list[dict] = field(default_factory=list)
    etag: str | None = None
    stopped: bool = False


@dataclass(frozen=True)
class GraphQLResult:
    """One GraphQL query's answer, parsed as far as the transport can.

    ``status`` is the HTTP status. ``data`` is the body's ``data`` object when
    the status was 200 and the body carried one, else ``None``; ``errors`` is
    the body's ``errors`` array, or an empty list. GitHub answers a partially
    failed query with 200, populated ``data`` and non-empty ``errors``, so a
    caller must read both: what each entry means for its query is the caller's
    policy, not the transport's.
    """

    status: int
    data: dict | None = None
    errors: list = field(default_factory=list)


class Paging(Transport):
    """The paginated-list and GraphQL read primitives over the transport."""

    async def _graphql(
        self,
        query: str,
        variables: dict[str, object] | None = None,
        *,
        quiet: bool = False,
    ) -> GraphQLResult:
        """POST one GraphQL query under the shared retry/backoff policy.

        Parses the response into a :class:`GraphQLResult` and closes it, so
        callers neither leak a pooled connection nor repeat the
        request/close/parse dance. A non-200 answer carries no ``data``; a
        200 whose body is not a JSON object reads as no ``data`` and no
        ``errors``, which a load-bearing caller treats as a failed query.
        """
        payload: dict[str, object] = {"query": query}
        if variables is not None:
            payload["variables"] = variables
        resp = await self._request("POST", self._graphql_url, json=payload, quiet=quiet)
        status = resp.status_code
        if status != 200:
            await resp.aclose()  # unread body would leak a pooled connection
            return GraphQLResult(status)
        body = resp.json()
        await resp.aclose()  # release the connection once the body is read
        if not isinstance(body, dict):
            return GraphQLResult(status)
        data = body.get("data")
        errors = body.get("errors")
        return GraphQLResult(
            status,
            data if isinstance(data, dict) else None,
            errors if isinstance(errors, list) else [],
        )

    async def _paginate(
        self,
        url: str,
        params: dict[str, object] | None = None,
        *,
        items_key: str | None = None,
        stop: Callable[[dict], bool] | None = None,
        etag: str | None = None,
        quiet: bool = False,
    ) -> PageResult:
        """Walk a paginated GitHub list, newest page first, into one result.

        ``params`` are sent with the first page (``per_page=100`` is added);
        later pages follow the ``Link: rel="next"`` header verbatim.
        ``items_key`` names the list inside an enveloped body such as
        ``{"total_count": N, "workflow_runs": [...]}``; ``None`` reads a bare
        JSON array.

        ``stop`` is consulted for each item in order. The first item it
        accepts ends the walk: that item and everything after it are dropped,
        no further page is requested, and the result says ``stopped``. An
        incremental read passes the predicate "older than what I already
        hold", so a newest-first listing costs one page on a quiet day rather
        than the whole history.

        ``etag`` is presented as ``If-None-Match`` on the first page. GitHub
        answers an unchanged resource with ``304`` and does not charge it
        against the rate limit, so a caller that keeps the validator between
        runs pays nothing to learn that nothing changed. The response's own
        ``ETag`` is returned for the next run. The validator is only useful
        when the URL and parameters are byte-for-byte stable across runs: a
        moving date filter in the query string is a different resource every
        day.

        If a *later* page fails, the items gathered so far are returned under
        that failing status (not 200): the data is incomplete, so callers must
        be able to degrade to unknown rather than treat an undercount as
        authoritative. Every response is closed once read, or unread on a
        failure, so no pooled connection leaks.
        """
        headers = {"If-None-Match": etag} if etag else None
        resp = await self._request(
            "GET",
            url,
            params={**(params or {}), "per_page": 100},
            headers=headers,
            quiet=quiet,
        )
        if resp.status_code != 200:
            status = resp.status_code
            await resp.aclose()  # unread body would leak a pooled connection
            return PageResult(status)
        first_etag = resp.headers.get("etag")
        items: list[dict] = []
        while True:
            page = _page_items(resp.json(), items_key)
            next_url = _next_page_url(resp)
            await resp.aclose()  # release the connection once body/links are read
            if stop is not None:
                for index, item in enumerate(page):
                    if stop(item):
                        items.extend(page[:index])
                        return PageResult(200, items, first_etag, stopped=True)
            items.extend(page)
            if not next_url:
                return PageResult(200, items, first_etag)
            resp = await self._request("GET", next_url, quiet=quiet)
            if resp.status_code != 200:
                log.log(
                    logging.DEBUG if quiet else logging.WARNING,
                    "pagination stopped early: %s -> %s (results may be partial)",
                    next_url,
                    resp.status_code,
                )
                status = resp.status_code
                await resp.aclose()
                return PageResult(status, items, first_etag)

    async def _get_list(self, url: str, **params: object) -> tuple[int, list[dict]]:
        """GET a paginated bare-array list, returning (status, items collected).

        The status is itself a signal for these endpoints (404 = feature
        disabled); see :meth:`_paginate` for the partial-read contract.
        """
        result = await self._paginate(url, dict(params))
        return result.status, result.items


def _page_items(body: object, items_key: str | None) -> list[dict]:
    """The items on one page: the bare array, or the list under ``items_key``.

    An envelope without the key, or a body of the wrong shape, reads as an
    empty page rather than raising: the page's status was 200, so the walk
    goes on to the next link and the caller sees what the remaining pages hold.
    """
    if items_key is not None:
        page = body.get(items_key) if isinstance(body, dict) else None
    else:
        page = body
    return list(page) if isinstance(page, list) else []
