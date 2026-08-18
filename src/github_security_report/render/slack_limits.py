# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Keeping a Slack payload inside Slack's hard structural limits.

Slack validates a ``chat.postMessage`` payload as a whole: exceeding any one
limit rejects the **entire** message, so a single oversized table costs the
whole digest rather than degrading it. This module is the one place those
limits are named and enforced:

* the **50-block** per-message ceiling, which a digest spanning many
  organisations crosses (see :func:`enforce_block_limit`);
* the **3,000-character** ceiling on a text object, which an uncapped table
  crosses long before it reaches 50 blocks (see :func:`fit_section_text`).
  The same limit applies to a ``context`` element, whose text carries the
  caller-supplied ``pages_url`` and so is *not* bounded by construction (see
  :func:`context_block`);
* the **150-character** ceiling on a ``header``, whose text carries a
  configured organisation name (see :func:`header_block`);
* the **40,000-character** ceiling on the top-level ``text`` fallback, which
  concatenates every organisation name (see :func:`fallback_text`).

Only one limit is left unguarded, and it is genuinely structural rather than
data-dependent: a ``context`` block may hold 10 elements and every one built
here holds exactly one. Everything an operator can influence -- configured
organisation names, ``pages_url``, and any "no limit" row setting -- is
measured rather than assumed.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence

# Slack rejects a chat.postMessage with more than 50 blocks, so a digest
# spanning many orgs must be capped or the whole message fails to deliver.
MAX_BLOCKS = 50

# Slack's text object caps ``text`` at 3,000 characters wherever it appears --
# section bodies and context elements alike -- and rejects the whole payload
# with it. Reachable through any documented "no limit" setting (``top_n: 0`` at
# report, surface or category level), which uncaps a table long before 50 blocks
# are in play.
MAX_TEXT_CHARS = 3000

# A header block uses a plain_text object with its own, much tighter ceiling.
MAX_HEADER_CHARS = 150

# The top-level ``text`` fallback (notification preview) has a far larger one.
MAX_FALLBACK_CHARS = 40000

# Appended when even a row-less, name-less block will not fit: a guaranteed
# last resort so an over-budget block can never leave this module.
_CLAMP_NOTE = "\n… truncated"
_FENCE = "```"


def text_length(text: str) -> int:
    """Length of ``text`` as Slack measures it, in UTF-16 code units.

    Slack's limits are enforced by a JavaScript-facing API, where string length
    counts UTF-16 code units, so an astral-plane emoji costs two. Python's
    ``len`` counts code points and would under-count, letting a payload that
    Slack rejects slip through. Counting UTF-16 is also the safe choice if
    Slack in fact counts code points: it is never smaller, so it can only make
    this module conservative, never permissive.

    ``surrogatepass`` because operator-controlled strings can carry an unpaired
    surrogate: :func:`json.loads` accepts ``\\ud800`` in a configured
    organisation name, and POSIX argument decoding turns undecodable bytes into
    lone surrogates. The strict encoder raises ``UnicodeEncodeError`` on those,
    which would abort report generation outright -- a worse failure than the
    oversized payload this module exists to prevent, and one introduced by the
    measuring rather than by the data.
    """
    return len(text.encode("utf-16-le", "surrogatepass")) // 2


def clamp(text: str, budget: int = MAX_TEXT_CHARS) -> str:
    """Hard-cut ``text`` to ``budget``, closing any code fence left open.

    The unconditional backstop beneath :func:`fit_section_text`: it makes the
    limit an invariant of this module rather than something every caller has to
    get right. Cutting mid-table would leave an unterminated code fence, which
    Slack renders as the rest of the block swallowed into a code span, so an odd
    fence count is balanced before the truncation note is appended.

    A budget too small to hold that note degrades further rather than
    overshooting -- a bare ellipsis, then nothing at all -- because a backstop
    that quietly exceeds its own budget is worse than no backstop. Only an
    explicit ``budget`` argument can reach those cases; every production caller
    passes :data:`MAX_TEXT_CHARS`.
    """
    if text_length(text) <= budget:
        return text
    reserved = text_length(_CLAMP_NOTE) + text_length(f"\n{_FENCE}")
    if budget < reserved:
        return _ellipsize(text, budget)
    room = budget - reserved
    cut = text[:room]
    # Re-measure rather than trusting the slice: ``room`` is a UTF-16 budget but
    # the slice is by code point, so a surrogate pair can overshoot it.
    while cut and text_length(cut) > room:
        cut = cut[:-1]
    if cut.count(_FENCE) % 2:
        cut += f"\n{_FENCE}"
    return cut + _CLAMP_NOTE


def _largest_fitting(
    render: Callable[[int], str],
    count: int,
    budget: int,
    breaks: Sequence[int] = (),
) -> int:
    """Largest ``n <= count`` whose rendered text fits ``budget`` (or ``0``).

    A binary search, which is valid only where rendered length is non-decreasing
    in ``n``. ``breaks`` names the values where that fails, splitting the range
    into windows that are individually monotonic; each is searched and the best
    result wins. The answer is therefore exact without enumerating every
    candidate -- a few binary searches rather than one linear scan.

    **Rows need no breaks.** :func:`fit_section_text` searches them only after
    the render at ``count`` has been measured and rejected, so every ``n``
    probed leaves rows hidden and the single "… and N more" note is present
    throughout. Each additional row adds at least a newline while that one note
    can shrink by at most a digit, so length never falls. The step that would
    shorten it -- the note vanishing once nothing is left over -- happens only
    at ``count``, which the precondition excludes.

    **Names do need them,** because that argument does not survive a second
    list. Each name list carries its own note, and a list shorter than the
    allowance completes *inside* the range: its ``… (+N more)`` suffix vanishes
    while only one entry is added, so with short repository names the render
    gets shorter as the allowance rises. Passing each list's length as a break
    puts every such transition on a window boundary, where it cannot mislead the
    search. Without them a rejected midpoint discards a fitting range above it
    and hides names that would have fitted.
    """
    starts = sorted({0, *(b for b in breaks if 0 < b <= count)})
    best = 0
    for i, start in enumerate(starts):
        end = starts[i + 1] - 1 if i + 1 < len(starts) else count
        # Within a window length is non-decreasing, so if the smallest value
        # does not fit then nothing above it in this window does either.
        if text_length(render(start)) > budget:
            continue
        lo, hi = start, end
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if text_length(render(mid)) <= budget:
                lo = mid
            else:
                hi = mid - 1
        best = max(best, lo)
    return best


def fit_section_text(
    render: Callable[[int, int], str],
    *,
    rows: int,
    names: int,
    name_breaks: Sequence[int] = (),
    budget: int = MAX_TEXT_CHARS,
) -> str:
    """Fit a section block's text into ``budget`` by shedding content.

    ``render(rows, names)`` must build the complete block text showing the first
    ``rows`` table rows and the first ``names`` entries of each repository name
    list, *including* the notes accounting for whatever it left out. Because
    both are plain prefix counts, every reduction here flows back through the
    same ``truncate``-shaped ``(shown, hidden)`` accounting the other surfaces
    use, so the "… and N more" tallies stay honest instead of being tracked by a
    second, parallel mechanism.

    Content is shed in ascending order of value. Repository **name lists** go
    first: they are pure enumeration, they are the part that grows without bound
    on a large organisation, and dropping them costs nothing that matters --
    their *counts* live on separate summary lines that always survive. **Table
    rows** go next, and only as far as needed; they are ordered worst-first, so
    a prefix is the most valuable part of the table.

    Rows are shed rather than split across additional blocks. Blocks are a
    scarce *global* resource -- 50 for the whole digest, shared by every
    organisation -- so spending them on one oversized table would evict other
    organisations from the message entirely, trading a partial table for total
    data loss elsewhere. Slack is a brevity-first surface and the digest links
    the full report whenever a usable URL is configured, so shedding rows and
    saying so is the right degradation.

    One probe decides which of the two is actually at fault. If the block still
    will not fit with *no* names at all, then no name allowance can save it and
    the rows are the problem, so the name search is skipped entirely rather than
    rebuilding a large table across a range of allowances that cannot help.

    ``name_breaks`` carries the length of each repository name list, marking
    where the name allowance stops behaving monotonically; see
    :func:`_largest_fitting`.
    """
    text = render(rows, names)
    if text_length(text) <= budget:
        return text
    if text_length(render(rows, 0)) <= budget:
        names = _largest_fitting(lambda n: render(rows, n), names, budget, name_breaks)
        return render(rows, names)
    rows = _largest_fitting(lambda n: render(n, 0), rows, budget)
    return clamp(render(rows, 0), budget)


def _ellipsize(text: str, budget: int) -> str:
    """Cut plain text to ``budget``, marking the cut with an ellipsis.

    For the header and fallback strings, where :func:`clamp`'s code-fence
    handling and multi-line note would be out of place, and as :func:`clamp`'s
    own fallback when the budget cannot hold that note. A budget with no room
    even for the ellipsis yields the empty string: there is nothing truthful
    left to say in zero characters.
    """
    if text_length(text) <= budget:
        return text
    if budget <= 0:
        return ""
    room = budget - 1
    cut = text[:room]
    # Re-measure: the budget is in UTF-16 units but the slice is by code point.
    while cut and text_length(cut) > room:
        cut = cut[:-1]
    return f"{cut}…"


def header_block(text: str) -> dict:
    """A header block sized to Slack's plain_text ceiling.

    The heading embeds a configured organisation name. GitHub caps its own
    logins well below the limit, but the name reaching here comes from the
    tool's configuration rather than from GitHub, so it is measured rather
    than assumed.
    """
    return {
        "type": "header",
        "text": {"type": "plain_text", "text": _ellipsize(text, MAX_HEADER_CHARS)},
    }


def context_block(text: str) -> dict:
    """A context block sized to Slack's text object ceiling.

    Context elements carry the caller-supplied ``pages_url``, which nothing
    validates for length, so the same 3,000-character limit applies here as to
    a section body. Callers that build a link must check it fits *before*
    passing it in and omit it otherwise: a clamped URL points somewhere other
    than the report, which is a wrong answer rather than a missing one.
    """
    return {"type": "context", "elements": [{"type": "mrkdwn", "text": clamp(text)}]}


def fallback_text(text: str) -> str:
    """The top-level notification text, sized to Slack's ceiling.

    It concatenates every organisation name in the digest, so it grows with the
    configuration even though the limit is generous.
    """
    return _ellipsize(text, MAX_FALLBACK_CHARS)


def enforce_block_limit(blocks: list[dict], pages_url: str | None) -> list[dict]:
    """Cap blocks at Slack's per-message limit, noting any truncation.

    A digest covering many orgs can exceed 50 blocks, which makes Slack reject
    the entire message (no digest delivered). Keep the first blocks and replace
    the overflow with a single note pointing at the full report.
    """
    if len(blocks) <= MAX_BLOCKS:
        return blocks
    note = f"… digest truncated to Slack's {MAX_BLOCKS}-block limit."
    if pages_url:
        linked = (
            f"… digest truncated to Slack's {MAX_BLOCKS}-block limit; "
            f"<{pages_url}|view the full report>."
        )
        # Prefer the linked note, but fall back to the bare one rather than
        # clamping a URL into something that no longer resolves.
        if text_length(linked) <= MAX_TEXT_CHARS:
            note = linked
    kept = blocks[: MAX_BLOCKS - 1]
    kept.append(context_block(note))
    return kept
