# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Tests for how the windowed Workflow Failures tables travel through the
report model, the layout, every render surface and the JSON serialiser."""

from __future__ import annotations

import datetime as dt

from rich.console import Console

from github_security_report import layout, report
from github_security_report.categories import CategoryKey, category_meta
from github_security_report.cli import outputs
from github_security_report.cli.serialise import _org_to_dict
from github_security_report.config import ReportConfig
from github_security_report.models import Repo
from github_security_report.render import html, markdown, slack, terminal
from github_security_report.report import TableRow, TableSection, window_shown

WHEN = dt.datetime(2026, 6, 16, 9, 0, tzinfo=dt.timezone.utc)
WINDOWS = (7, 30, 90)
LINK = "https://github.com/o/a/actions/workflows/testing.yaml"
FAILURES = CategoryKey.WORKFLOW_FAILURES
DETAIL = CategoryKey.WORKFLOW_FAILURES_DETAIL


def _repo(name: str) -> Repo:
    return Repo(name, f"o/{name}", f"https://github.com/o/{name}")


def _table(key: CategoryKey, days: int, *, rows: int = 1) -> TableSection:
    """A one-row windowed table; repo rows carry a digest, detail rows none."""
    digest = f"a: {days}-day digest" if key is FAILURES else ""
    return TableSection(
        category=category_meta(key),
        columns=("Repository", "Failed", "Worst workflow"),
        rows=[
            TableRow(
                repo=_repo("a"),
                cells=(str(days), "Testing"),
                cell_urls=(None, LINK),
                digest=digest,
            )
            for _ in range(rows)
        ],
        sum_columns=frozenset({1}),
        fail_count=rows,
        window_days=days,
    )


def _org() -> report.OrgReport:
    org = report.build_org_report("o", [], repo_count=3, generated_at=WHEN)
    org.workflow_failures = tuple(_table(FAILURES, d) for d in WINDOWS)
    org.workflow_failures_detail = tuple(_table(DETAIL, d) for d in WINDOWS)
    org.section_order = layout.resolve(org)
    return org


def _week(_key: CategoryKey) -> set[int]:
    """A window policy showing the 7-day table alone."""
    return {7}


def test_first_window_leads_and_the_rest_nest() -> None:
    # The shortest window of each category is a section; the others are
    # nested beneath it and reachable as its siblings.
    org = _org()
    t7, t30, t90 = org.workflow_failures
    d7, d30, d90 = org.workflow_failures_detail
    assert t7 in org.standalone_tables
    assert d7 in org.standalone_tables
    assert t30 not in org.standalone_tables
    nested = org.nested_tables
    assert all(any(t is n for n in nested) for t in (t30, t90, d30, d90))
    assert org.sibling_windows(t7) == (t30, t90)
    assert org.sibling_windows(t30) == ()


def test_layout_attaches_later_windows_as_children() -> None:
    # One layout slot per category, the later windows as children, and the
    # drawn order names the category once rather than once per window.
    org = _org()
    t7, t30, t90 = org.workflow_failures
    item = next(i for i in layout.default_items(org) if i.section is t7)
    assert item.children == (t30, t90)
    drawn = layout.drawn_order(org)
    assert drawn.count(FAILURES) == 1
    assert drawn.count(DETAIL) == 1


def test_layout_item_is_populated_by_a_child_alone() -> None:
    # A quiet week over a noisy month still holds its band position.
    empty = _table(FAILURES, 7, rows=0)
    item = layout.LayoutItem(empty, (_table(FAILURES, 30),))
    assert item.populated
    assert not layout.LayoutItem(empty).populated


def test_window_shown_only_ever_narrows() -> None:
    # No policy shows everything; a policy hides the windows it omits; a
    # table without a window is never filtered.
    t7, t30 = _table(FAILURES, 7), _table(FAILURES, 30)
    plain = TableSection(category=category_meta(FAILURES), columns=("Repository",))
    assert window_shown(None, t30)
    assert window_shown(_week, t7)
    assert not window_shown(_week, t30)
    assert window_shown(_week, plain)
    assert window_shown(lambda _key: None, t30)


def _terminal(org: report.OrgReport, **kwargs: object) -> str:
    console = Console(record=True, width=200, no_color=True)
    terminal.render_org(org, console, **kwargs)  # type: ignore[arg-type]
    return console.export_text()


def test_terminal_shows_the_windows_its_policy_names() -> None:
    org = _org()
    week = _terminal(org, windows=_week)
    assert "Workflow Failures (7 days)" in week
    assert "(30 days)" not in week
    every = _terminal(org, windows=None)
    assert all(f"Workflow Failures ({d} days)" in every for d in WINDOWS)
    hidden = _terminal(org, show=lambda key: key not in {FAILURES, DETAIL})
    assert "Workflow Failures" not in hidden


def test_markdown_nests_later_windows_under_the_first() -> None:
    # The first shown window is a level-2 heading; later windows nest as
    # level 3; a window outside the policy is absent altogether.
    text = markdown.render_org(_org(), windows=lambda _key: {7, 30})
    assert "## Workflow Failures (7 days)" in text
    assert "### Workflow Failures (30 days)" in text
    assert "(90 days)" not in text
    assert f"[Testing]({LINK})" in text


def test_markdown_promotes_a_window_whose_leader_is_hidden() -> None:
    # Without the 7-day table the 30-day one must not float as an orphaned
    # sub-heading under the previous section.
    text = markdown.render_org(_org(), windows=lambda _key: {30})
    assert "## Workflow Failures (30 days)" in text
    assert "### Workflow Failures (30 days)" not in text
    assert "(7 days)" not in text


def test_html_nests_later_windows_in_the_first_card() -> None:
    page = html.render_org_html(_org(), windows=lambda _key: {7, 30})
    first = page.index("<h2>Workflow Failures (7 days)</h2>")
    nested = page.index("<h3>Workflow Failures (30 days)</h3>")
    assert first < nested < page.index("</section>", first)
    assert "(90 days)" not in page
    assert f'<a href="{LINK}">Testing</a>' in page


def test_html_promotes_a_window_whose_leader_is_hidden() -> None:
    page = html.render_org_html(_org(), windows=lambda _key: {30})
    assert "<h2>Workflow Failures (30 days)</h2>" in page
    assert "<h3>Workflow Failures (30 days)</h3>" not in page
    assert "(7 days)" not in page


def _block_text(blocks: list[dict], title: str) -> str | None:
    """The mrkdwn text of the block titled ``title``, or None when absent."""
    for block in blocks:
        text = block.get("text", {}).get("text", "")
        if text.startswith(f"*{title}*"):
            return str(text)
    return None


def test_slack_draws_digest_rows_as_bullets() -> None:
    # Rows carrying a digest render one bullet each, with no fixed-width code
    # table; the detail rows have none and keep the fenced table.
    blocks = slack.render_org_blocks(_org(), top_n=10, pages_url=None, windows=_week)
    repo_text = _block_text(blocks, "Workflow Failures (7 days)")
    assert repo_text is not None
    assert "• a: 7-day digest" in repo_text
    assert "```" not in repo_text
    detail_text = _block_text(blocks, "Workflow Failures: Detail (7 days)")
    assert detail_text is not None
    assert "```" in detail_text
    assert _block_text(blocks, "Workflow Failures (30 days)") is None


def test_serialise_lists_every_window_with_cell_links() -> None:
    # report.json carries all three windows, each row's links parallel to its
    # cells; a report without the tables serialises an empty list.
    data = _org_to_dict(_org())
    tables = data["workflow_failures"]
    assert [t["window_days"] for t in tables] == [7, 30, 90]
    assert [t["window_days"] for t in data["workflow_failures_detail"]] == [7, 30, 90]
    row = tables[0]["rows"][0]
    assert len(row["cell_urls"]) == len(row["cells"])
    assert row["cell_urls"] == [None, LINK]
    bare = report.build_org_report("o", [], repo_count=0, generated_at=WHEN)
    assert _org_to_dict(bare)["workflow_failures"] == []


def test_output_windows_follow_the_default_config() -> None:
    # The terminal and Slack get the week; the published report adds the
    # month and the quarter.
    cfg = ReportConfig()
    assert outputs.windows(cfg, "cli")(FAILURES) == {7}
    assert outputs.windows(cfg, "report")(FAILURES) == {7, 30, 90}
    assert outputs.windows(cfg, "slack")(FAILURES) == {7}
