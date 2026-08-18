# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Tests for Slack's structural limits and the section character budget.

Slack rejects an entire ``chat.postMessage`` payload when any one block breaches
a limit, so these failures are invisible locally: the digest simply never
arrives. The integration tests here assert the invariant directly against a
synthetic organisation large enough to breach it.
"""

from __future__ import annotations

import datetime as dt
import json
import re

from github_security_report import report
from github_security_report.categories import CategoryKey, category_meta
from github_security_report.models import (
    Repo,
    RepoSignal,
    RepoState,
    SeverityCounts,
    SignalType,
)
from github_security_report.render import slack
from github_security_report.render import slack_limits as limits

WHEN = dt.datetime(2026, 6, 16, 9, 0, tzinfo=dt.timezone.utc)

# The GitHub Issues table is the widest the tool renders, so it reaches the
# character limit soonest; mirror its shape when building synthetic tables.
ISSUES_COLUMNS = (
    "Repository",
    "Open",
    "Bug",
    "Feature",
    "Untriaged",
    "Stale",
    "Oldest",
    "Newest",
)


def _repo(name: str) -> Repo:
    return Repo(name, f"o/{name}", f"https://github.com/o/{name}")


# The list lengths in _uneven_name_lists(), which are where the name allowance
# stops behaving monotonically.
_NAME_BREAKS = (3, 12)


def _uneven_name_lists() -> list[report.SummaryLine]:
    """Two name lists of different lengths, with short repository names.

    The shape that makes the name allowance non-monotonic: the shorter list
    completes partway through the range, dropping its "… (+N more)" suffix,
    and with names this short that suffix costs more than the entries gained.
    """
    return report.build_summary(
        [
            report.SummaryCount("disabled", 3, "Disabled", ("cli", "api", "sdk")),
            report.SummaryCount(
                "excluded", 12, "Excluded", tuple(f"r{i}" for i in range(12))
            ),
        ]
    )


def _issues_table(count: int) -> report.TableSection:
    """A wide Issues-shaped table with ``count`` rows of realistic width."""
    return report.TableSection(
        category=category_meta(CategoryKey.GITHUB_ISSUES),
        columns=ISSUES_COLUMNS,
        rows=[
            report.TableRow(
                repo=_repo(f"lfreleng-example-repository-{i:04d}"),
                cells=("12", "4", "3", "5", "2", "2026-01-01", "2026-06-01"),
            )
            for i in range(count)
        ],
        fail_count=count,
    )


def _section_texts(payload: dict) -> list[str]:
    return [
        block["text"]["text"]
        for block in payload["blocks"]
        if block.get("type") == "section"
    ]


# --------------------------------------------------------------------------
# The invariant
# --------------------------------------------------------------------------


def test_no_section_block_exceeds_slack_character_limit() -> None:
    # The bug this guards: `top_n: 0` is a documented "no limit" setting, and an
    # uncapped wide table passes 3,000 characters long before it reaches 50
    # blocks. Slack then rejects the *whole* payload, so the digest is lost
    # entirely rather than degraded.
    org = report.build_org_report(
        "lfreleng-actions", [], repo_count=500, generated_at=WHEN
    )
    org.issues = _issues_table(500)
    payload = slack.render_payload([org], channel="C", top_n=0)
    texts = _section_texts(payload)
    assert texts, "expected the issues table to render a section block"
    for text in texts:
        assert limits.text_length(text) <= limits.MAX_TEXT_CHARS


def test_oversized_table_keeps_its_hidden_tally_honest() -> None:
    # However rows are shed, the "… and N more" note must account for every row
    # that is not on screen -- the budget must feed the existing (shown, hidden)
    # accounting rather than running a second, parallel one.
    total = 400
    org = report.build_org_report(
        "lfreleng-actions", [], repo_count=total, generated_at=WHEN
    )
    org.issues = _issues_table(total)
    payload = slack.render_payload([org], channel="C", top_n=0)
    text = next(t for t in _section_texts(payload) if "…" in t)

    hidden = int(re.search(r"… and (\d+) more", text).group(1))  # type: ignore[union-attr]
    shown = len(re.findall(r"^lfreleng-example-repository-\d{4}", text, re.M))
    assert shown + hidden == total
    assert shown > 0, "a budgeted table should still show its worst rows"


def test_signal_table_is_budgeted_too() -> None:
    # Not just the generic tables: an uncapped offender table on a large org
    # reaches the limit the same way.
    signals = [
        RepoSignal(
            _repo(f"lfreleng-example-repository-{i:04d}"),
            SignalType.CODEQL,
            RepoState.OFFENDER,
            SeverityCounts(critical=1, high=2, medium=3, low=4),
        )
        for i in range(400)
    ]
    org = report.build_org_report(
        "lfreleng-actions", signals, repo_count=400, generated_at=WHEN
    )
    payload = slack.render_payload([org], channel="C", top_n=0)
    for text in _section_texts(payload):
        assert limits.text_length(text) <= limits.MAX_TEXT_CHARS


def test_small_report_is_not_truncated() -> None:
    # The budget must be inert below the limit: no spurious "… and N more".
    org = report.build_org_report(
        "lfreleng-actions", [], repo_count=3, generated_at=WHEN
    )
    org.issues = _issues_table(3)
    payload = slack.render_payload([org], channel="C", top_n=0)
    text = next(t for t in _section_texts(payload) if "Repository" in t)
    assert "… and" not in text
    assert text.count("lfreleng-example-repository-") == 3


# --------------------------------------------------------------------------
# Shedding order: enumerations before rows
# --------------------------------------------------------------------------


def test_name_lists_are_shed_before_table_rows() -> None:
    # Excluded/disabled name lists are pure enumeration and grow without bound,
    # so they give way before table rows do. Their *counts* live on separate
    # summary lines, which always survive: shedding names costs which
    # repositories, never how many.
    excluded = [
        _repo(f"excluded-repository-with-a-long-name-{i:04d}") for i in range(80)
    ]
    org = report.build_org_report(
        "lfreleng-actions", [], repo_count=120, generated_at=WHEN
    )
    org.excluded_repos = excluded
    # Sized so the rows alone fit comfortably and only the 80-name enumeration
    # breaches the budget, isolating which of the two gives way.
    org.issues = _issues_table(15)
    payload = slack.render_payload([org], channel="C", top_n=0)
    text = next(t for t in _section_texts(payload) if "Repository" in t)

    assert limits.text_length(text) <= limits.MAX_TEXT_CHARS
    # The count line always survives, so how many were excluded is never lost.
    assert "80 Excluded" in text
    # The enumeration is trimmed to what fits, and accounts for the remainder.
    listed = text.count("excluded-repository-with-a-long-name-")
    hidden = int(re.search(r"\(\+(\d+) more\)", text).group(1))  # type: ignore[union-attr]
    assert 0 < listed < 80
    assert listed + hidden == 80
    # Rows were the more valuable content and were kept in full.
    assert "… and" not in text
    assert text.count("lfreleng-example-repository-") == 15


def test_zero_name_allowance_drops_enumerations_not_counts() -> None:
    # The floor of the shedding cascade. ``0`` here means "list no names" -- not
    # ``truncate``'s "no limit" -- and the count lines must still be emitted,
    # otherwise a squeezed block would silently lose the numbers as well.
    lines = report.build_summary(
        [
            report.SummaryCount("pass", 5, "Clean", all_label="Clean"),
            report.SummaryCount("excluded", 2, "Excluded", ("alpha", "beta")),
        ]
    )
    text = slack._summary_text(lines, names=0)
    assert "2 Excluded" in text
    assert "alpha" not in text


def test_name_list_survives_when_there_is_room() -> None:
    org = report.build_org_report(
        "lfreleng-actions", [], repo_count=4, generated_at=WHEN
    )
    org.excluded_repos = [_repo("alpha"), _repo("beta")]
    org.issues = _issues_table(1)
    payload = slack.render_payload([org], channel="C", top_n=0)
    text = next(t for t in _section_texts(payload) if "Repository" in t)
    assert "Excluded: alpha, beta" in text


# --------------------------------------------------------------------------
# Every other limit data can reach
# --------------------------------------------------------------------------


def _assert_payload_within_limits(payload: dict) -> None:
    """Assert every block in a payload respects the limit that governs it."""
    blocks = payload["blocks"]
    assert len(blocks) <= limits.MAX_BLOCKS
    assert limits.text_length(payload["text"]) <= limits.MAX_FALLBACK_CHARS
    for block in blocks:
        kind = block["type"]
        if kind == "header":
            assert limits.text_length(block["text"]["text"]) <= limits.MAX_HEADER_CHARS
        elif kind == "section":
            assert limits.text_length(block["text"]["text"]) <= limits.MAX_TEXT_CHARS
        elif kind == "context":
            assert len(block["elements"]) <= 10
            for element in block["elements"]:
                assert limits.text_length(element["text"]) <= limits.MAX_TEXT_CHARS
        else:  # pragma: no cover - a new block type needs its own limit here
            raise AssertionError(f"unhandled block type: {kind}")


def test_hostile_configuration_stays_within_every_limit() -> None:
    # The operator-supplied values -- organisation name and pages_url -- are not
    # bounded by construction, so they are measured rather than assumed. This
    # walks every block type at once so a newly added one cannot quietly
    # reintroduce the gap.
    org = report.build_org_report(
        "o" * 400, [], repo_count=200, generated_at=WHEN, partial=True
    )
    org.issues = _issues_table(200)
    payload = slack.render_payload(
        [org], channel="C", top_n=0, pages_url="https://example.invalid/" + "p" * 5000
    )
    _assert_payload_within_limits(payload)


def test_oversized_pages_url_drops_the_link_rather_than_cutting_it() -> None:
    # A clamped URL resolves somewhere other than the report -- a wrong answer
    # rather than a missing one -- so the link is omitted entirely.
    org = report.build_org_report(
        "lfreleng-actions", [], repo_count=1, generated_at=WHEN
    )
    huge = "https://example.invalid/" + "p" * 5000
    blocks = slack.render_org_blocks(org, top_n=10, pages_url=huge)
    assert not [b for b in blocks if b["type"] == "context"]
    # A sane URL is still linked.
    ok = slack.render_org_blocks(org, top_n=10, pages_url="https://x.github.io/r/")
    assert ok[-1]["type"] == "context"
    assert "https://x.github.io/r/" in ok[-1]["elements"][0]["text"]


def test_block_limit_note_falls_back_to_the_unlinked_wording() -> None:
    # The overflow note embeds pages_url too; when that will not fit, the note
    # must still be delivered rather than carrying a truncated link.
    sigs = [
        RepoSignal(_repo("r"), st, RepoState.CLEAN, counts=SeverityCounts())
        for st in SignalType
    ]
    orgs = [
        report.build_org_report(
            "lfreleng-actions", sigs, repo_count=1, generated_at=WHEN
        )
        for _ in range(12)
    ]
    payload = slack.render_payload(
        orgs, channel="C", pages_url="https://example.invalid/" + "p" * 5000
    )
    note = payload["blocks"][-1]["elements"][0]["text"]
    assert "truncated" in note
    assert "example.invalid" not in note
    _assert_payload_within_limits(payload)


def test_header_is_ellipsized_not_dropped() -> None:
    block = limits.header_block("x" * 500)
    text = block["text"]["text"]
    assert limits.text_length(text) <= limits.MAX_HEADER_CHARS
    assert text.endswith("…")


def test_ellipsize_respects_budget_with_astral_characters() -> None:
    block = limits.header_block("\U0001f510" * 500)
    assert limits.text_length(block["text"]["text"]) <= limits.MAX_HEADER_CHARS


# --------------------------------------------------------------------------
# The primitives
# --------------------------------------------------------------------------


def test_name_allowance_never_exceeds_the_names_that_exist() -> None:
    # top_n is operator-supplied with no schema maximum. An allowance beyond the
    # available names renders identically, so leaving it unbounded would only
    # make the budget's search probe indistinguishable outcomes. Capping it also
    # keeps the value meaningful as a count.
    lines = report.build_summary(
        [
            report.SummaryCount("pass", 5, "Clean", all_label="Clean"),
            report.SummaryCount("excluded", 3, "Excluded", ("a", "b", "c")),
        ]
    )
    assert slack._name_cap(lines, 10**6) == 3
    assert slack._name_cap(lines, 2) == 2
    assert slack._name_cap(lines, 0) == 3
    assert slack._name_cap([], 10**6) == 0


def test_huge_top_n_renders_identically_to_an_exact_one() -> None:
    # Capping the allowance must not change any output.
    def build(top_n: int) -> dict:
        org = report.build_org_report(
            "lfreleng-actions", [], repo_count=6, generated_at=WHEN
        )
        org.excluded_repos = [_repo("alpha"), _repo("beta")]
        org.issues = _issues_table(2)
        return slack.render_payload([org], channel="C", top_n=top_n)

    assert build(10**6) == build(0)


def test_text_length_counts_utf16_code_units() -> None:
    # Slack's limits are enforced by a JavaScript-facing API, where an
    # astral-plane emoji costs two units. Counting code points would under-count
    # and let a payload Slack rejects slip through.
    assert limits.text_length("\U0001f510") == 2
    assert limits.text_length("\u274c") == 1
    assert limits.text_length("abc") == 3


def test_text_length_survives_unpaired_surrogates() -> None:
    # json.loads accepts "\ud800" in a configured organisation name, and POSIX
    # argument decoding turns undecodable bytes into lone surrogates. A strict
    # UTF-16 encoder raises on those, which would abort report generation --
    # a worse failure than the oversized payload this module prevents, and one
    # caused by the measuring rather than the data.
    lone = json.loads('"\\ud800abc"')
    assert limits.text_length(lone) == 4
    org = report.build_org_report(lone, [], repo_count=1, generated_at=WHEN)
    org.issues = _issues_table(2)
    payload = slack.render_payload([org], channel="C", top_n=0, pages_url=lone)
    _assert_payload_within_limits(payload)
    # The payload must still serialise for delivery.
    assert json.loads(json.dumps(payload))["channel"] == "C"


def test_clamp_is_inert_within_budget() -> None:
    assert limits.clamp("short", 100) == "short"


def test_clamp_never_exceeds_even_an_absurd_budget() -> None:
    # The backstop must hold for every budget, including ones too small for its
    # own truncation note -- a guard that overshoots its budget is worse than no
    # guard. Only an explicit budget argument reaches these; production always
    # passes MAX_TEXT_CHARS.
    text = "*Title*\n```\n" + ("row\n" * 50)
    for budget in range(-3, 40):
        out = limits.clamp(text, budget)
        assert limits.text_length(out) <= max(budget, 0), budget


def test_clamp_closes_an_open_code_fence() -> None:
    # Cutting mid-table would leave the fence unterminated, which Slack renders
    # as the remainder of the block swallowed into a code span.
    text = "*Title*\n```\n" + ("row\n" * 400)
    out = limits.clamp(text, 200)
    assert limits.text_length(out) <= 200
    assert out.count("```") % 2 == 0
    assert out.endswith("… truncated")


def test_clamp_respects_budget_with_astral_characters() -> None:
    # The slice is by code point but the budget is in UTF-16 units, so a cut
    # landing on a surrogate pair must not overshoot.
    out = limits.clamp("\U0001f510" * 200, 50)
    assert limits.text_length(out) <= 50


def test_names_alone_are_shed_when_the_rows_already_fit() -> None:
    def render(rows: int, names: int) -> str:
        return ("r" * rows) + ("n" * names)

    out = limits.fit_section_text(render, rows=10, names=1000, budget=50)
    assert out == ("r" * 10) + ("n" * 40)


def test_row_shedding_skips_the_name_search_entirely() -> None:
    # When the block will not fit even with no names at all, no name allowance
    # can save it. Searching that range would rebuild a large table across
    # allowances that cannot help, so a single probe settles it instead.
    calls: list[tuple[int, int]] = []

    def render(rows: int, names: int) -> str:
        calls.append((rows, names))
        return ("r" * rows * 10) + ("n" * names)

    limits.fit_section_text(render, rows=100, names=1000, budget=50)
    # Only the opening render and the deciding probe vary the name allowance;
    # every subsequent probe holds it at zero and moves rows.
    assert sorted({names for _, names in calls}) == [0, 1000]


def test_fit_section_text_clamps_when_nothing_can_be_shed() -> None:
    # A block whose fixed content alone exceeds the budget still must not leave
    # this module over-length: the clamp is the unconditional backstop.
    def render(rows: int, names: int) -> str:
        return "x" * 5000

    out = limits.fit_section_text(render, rows=10, names=10, budget=100)
    assert limits.text_length(out) <= 100


def test_fit_section_text_prefers_the_largest_fitting_prefix() -> None:
    def render(rows: int, names: int) -> str:
        return "r" * rows

    out = limits.fit_section_text(render, rows=500, names=0, budget=50)
    assert out == "r" * 50


def test_name_allowance_is_genuinely_non_monotonic() -> None:
    # The property that rules out a binary search for the name allowance, pinned
    # so it is not re-derived from intuition. With two lists of different
    # lengths, the shorter one's "… (+N more)" suffix vanishes once it is fully
    # shown; for short repository names that suffix outweighs the entries the
    # step adds, so the render shortens as the allowance rises.
    lines = _uneven_name_lists()
    lengths = [
        limits.text_length(slack._summary_text(lines, names=n)) for n in range(13)
    ]
    drops = [n for n in range(12) if lengths[n + 1] < lengths[n]]
    assert drops, "expected the render to shorten as the allowance rises"


def test_name_search_needs_the_break_points() -> None:
    # The concrete case a plain binary search gets wrong: at this budget the
    # full 12-name render fits, but n=11 does not, so a search with no break
    # points discards the fitting range above its rejected midpoint.
    lines = _uneven_name_lists()

    def render(n: int) -> str:
        return slack._summary_text(lines, names=n)

    assert limits.text_length(render(12)) <= 110 < limits.text_length(render(11))
    assert limits._largest_fitting(render, 12, 110, _NAME_BREAKS) == 12
    assert limits._largest_fitting(render, 12, 110) < 12  # the discarded range


def test_name_breaks_are_the_list_lengths() -> None:
    # The breaks handed to the budget must be exactly the rendered list
    # lengths; a stale or missing one silently reintroduces the bad search.
    assert slack._name_breaks(_uneven_name_lists()) == _NAME_BREAKS


def test_name_search_matches_an_exhaustive_search_at_every_budget() -> None:
    lines = _uneven_name_lists()

    def render(n: int) -> str:
        return slack._summary_text(lines, names=n)

    for budget in range(0, 200):
        expected = max(
            (n for n in range(13) if limits.text_length(render(n)) <= budget),
            default=0,
        )
        assert limits._largest_fitting(render, 12, budget, _NAME_BREAKS) == expected, (
            budget
        )


def test_largest_fitting_matches_an_exhaustive_search() -> None:
    # The binary search is only valid under the precondition documented on
    # _largest_fitting: it is called after the render at its upper bound has
    # already been rejected, so the truncation note is present throughout the
    # searched range. Within that regime it must agree with brute force for
    # every budget -- this is what makes the O(log n) shortcut safe.
    total = 200

    def render(n: int) -> str:
        body = "\n".join(f"repository-{i:03d}  {i:4d}  {i * 3:5d}" for i in range(n))
        hidden = total - n
        return body + (f"\n… and {hidden} more" if hidden else "")

    checked = 0
    for budget in range(0, 6000, 31):
        if limits.text_length(render(total)) <= budget:
            continue  # outside the documented precondition
        expected = max(
            (n for n in range(total) if limits.text_length(render(n)) <= budget),
            default=0,
        )
        assert limits._largest_fitting(render, total, budget) == expected
        checked += 1
    assert checked > 50, "expected the sweep to exercise a range of budgets"


def test_truncation_note_growth_never_shortens_the_render() -> None:
    # The property the search leans on, asserted directly: as rows are added the
    # note shrinks, but never by more than the row adds, so length is
    # non-decreasing across the whole searched range.
    total = 150

    def render(n: int) -> str:
        body = "\n".join(f"repository-{i:03d}  {i:4d}" for i in range(n))
        return body + f"\n… and {total - n} more"

    lengths = [limits.text_length(render(n)) for n in range(total)]
    # strict=False is intended: the tail is one shorter, which is what pairs
    # each value with its successor.
    assert all(b >= a for a, b in zip(lengths, lengths[1:], strict=False))
