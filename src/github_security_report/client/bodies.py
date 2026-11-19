# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Reading a ``200`` response's JSON body without trusting it.

A ``200`` does not guarantee the body a read expects: a proxy or
captive-portal page, a truncated body, or JSON of another shape can arrive
under it. Parsing such a body raises, and indexing the wrong shape either
raises or, worse, reads as a confident negative ("no alerts", "no tool has
run"). :func:`_read_body` turns both into one answer, ``None``, which each
read maps onto its own unreadable result.
"""

from __future__ import annotations

import logging
from typing import TypeVar

import httpx

log = logging.getLogger(__name__)

# The status a read reports for a 200 whose body it could not use: "the
# server returned an invalid response". Every caller already treats 502 as
# indeterminate, and it is never 200, 304, 403 or 404, the statuses that
# carry a meaning of their own.
MALFORMED_STATUS = 502

_T = TypeVar("_T", dict, list)


async def _read_body(
    resp: httpx.Response, expected: type[_T], *, quiet: bool = False
) -> _T | None:
    """The response's JSON body, or ``None`` when it is malformed.

    Malformed means not valid JSON, or JSON whose top-level type is not
    ``expected``. The response is closed on every path. A malformed body is
    logged once, at WARNING (DEBUG for a ``quiet`` read), naming the request,
    the ``Content-Type`` and the body's length but never the body itself,
    which may be a page that has nothing to do with GitHub.
    """
    try:
        body: object = resp.json()
    except ValueError:  # JSONDecodeError and UnicodeDecodeError alike
        body = None
        problem = "is not valid JSON"
    else:
        problem = f"is JSON {type(body).__name__}, not {expected.__name__}"
    finally:
        await resp.aclose()  # release the connection whatever the body held
    if isinstance(body, expected):
        return body
    try:
        method, url = resp.request.method, str(resp.request.url)
    except RuntimeError:  # a response built without a request
        method, url = "?", "?"
    log.log(
        logging.DEBUG if quiet else logging.WARNING,
        "%s %s answered 200 but its body %s (Content-Type %s, %d bytes); "
        "the read is reported as unknown",
        method,
        url,
        problem,
        resp.headers.get("content-type", "none"),
        len(resp.content),
    )
    return None
