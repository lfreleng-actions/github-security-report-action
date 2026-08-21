# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Tests for Slack payload rendering."""

from __future__ import annotations

import datetime as dt

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

WHEN = dt.datetime(2026, 6, 16, 9, 0, tzinfo=dt.timezone.utc)


def _repo(name: str) -> Repo:
    return Repo(name, f"o/{name}", f"https://github.com/o/{name}")


def _org(signals: list[RepoSignal], count: int = 1) -> report.OrgReport:
    return report.build_org_report(
        "lfreleng-actions", signals, repo_count=count, generated_at=WHEN
    )


def test_payload_shape() -> None:
    payload = slack.render_payload([_org([])], channel="C123")
    assert payload["channel"] == "C123"
    assert payload["blocks"][0]["type"] == "header"
    assert "lfreleng-actions" in payload["blocks"][0]["text"]["text"]


def test_visibility_is_resolved_per_organisation() -> None:
    # Organisations sharing a channel render into one digest, but visibility is
    # a property of each one's own data. Pooling it -- as the row limits are
    # pooled -- would let one organisation's opt-in publish another's, which
    # for a reader-specific category is a leak rather than an inconsistency.
    first = report.build_org_report("opted-in", [], repo_count=1, generated_at=WHEN)
    second = report.build_org_report("opted-out", [], repo_count=1, generated_at=WHEN)
    first.issues = report.TableSection(
        category=category_meta(CategoryKey.GITHUB_ISSUES),
        columns=("Repository", "Total"),
        rows=[report.TableRow(repo=_repo("shown-repo"), cells=("1",))],
    )
    second.issues = report.TableSection(
        category=category_meta(CategoryKey.GITHUB_ISSUES),
        columns=("Repository", "Total"),
        rows=[report.TableRow(repo=_repo("private-repo"), cells=("1",))],
    )

    def show(org: report.OrgReport, key: CategoryKey) -> bool:
        return org.org == "opted-in" or key is not CategoryKey.GITHUB_ISSUES

    payload = slack.render_payload([first, second], channel="C123", show=show)
    text = str(payload["blocks"])
    assert "shown-repo" in text
    # The opted-out organisation's row must not appear just because its
    # channel-mate enabled the category.
    assert "private-repo" not in text


def test_payload_enforces_slack_block_limit() -> None:
    # Many orgs would blow past Slack's 50-block ceiling and make the whole
    # message fail; the payload must be capped with a truncation note instead.
    sigs = [
        RepoSignal(_repo("r"), st, RepoState.CLEAN, counts=SeverityCounts())
        for st in SignalType
    ]
    orgs = [_org(sigs) for _ in range(12)]
    payload = slack.render_payload(
        orgs, channel="C", pages_url="https://x.github.io/r/"
    )
    blocks = payload["blocks"]
    assert len(blocks) <= 50
    assert blocks[-1]["type"] == "context"
    assert "truncated" in blocks[-1]["elements"][0]["text"]


def test_skipped_section_renders_single_skip_line() -> None:
    # A gated-out signal contributes one block: its heading plus the skip line
    # linking the setup guide -- no fenced table and no summary footer.
    org = report.build_org_report(
        "lfreleng-actions",
        [],
        repo_count=1,
        generated_at=WHEN,
        skipped_signals={SignalType.AISLOP},
    )
    blocks = slack.render_org_blocks(org, top_n=10, pages_url=None)
    text = next(
        b["text"]["text"]
        for b in blocks
        if "AI Slop Analysis" in b.get("text", {}).get("text", "")
    )
    assert report.SKIP_MESSAGE in text
    assert report.ORG_SETUP_DOC_URL in text
    assert "```" not in text  # no fixed-width table


def test_informational_column_in_slack_when_present() -> None:
    # Slack uses single-letter severity headers; the sub-low Info column is "I"
    # and appears only when a table carries note-level findings.
    sig = RepoSignal(
        _repo("noisy"),
        SignalType.ZIZMOR,
        RepoState.OFFENDER,
        SeverityCounts(high=2, informational=3),
    )
    blocks = slack.render_org_blocks(_org([sig]), top_n=10, pages_url=None)
    text = next(
        b["text"]["text"]
        for b in blocks
        if "Zizmor" in b.get("text", {}).get("text", "")
    )
    # Header carries the I column; hidden for tables without info findings.
    assert " I" in text
    codeql = RepoSignal(
        _repo("bad"), SignalType.CODEQL, RepoState.OFFENDER, SeverityCounts(critical=1)
    )
    blocks2 = slack.render_org_blocks(_org([codeql]), top_n=10, pages_url=None)
    ctext = next(
        b["text"]["text"]
        for b in blocks2
        if "CodeQL" in b.get("text", {}).get("text", "")
    )
    # No info findings -> the single-letter header row has no trailing " I".
    header_line = ctext.split("```")[1].splitlines()[1]
    assert not header_line.rstrip().endswith(" I")


def test_offenders_are_code_fenced() -> None:
    sig = RepoSignal(
        _repo("bad"), SignalType.CODEQL, RepoState.OFFENDER, SeverityCounts(critical=1)
    )
    blocks = slack.render_org_blocks(_org([sig]), top_n=10, pages_url=None)
    codeql = next(b for b in blocks if "CodeQL" in b.get("text", {}).get("text", ""))
    assert "```" in codeql["text"]["text"]
    assert "bad" in codeql["text"]["text"]
    # The fixed-width header capitalises the repository column for consistency
    # with the posture/release tables and the other render surfaces.
    assert "Repository" in codeql["text"]["text"]
    assert "repo " not in codeql["text"]["text"]


def test_all_offender_section_has_no_no_data_line() -> None:
    # Every repo is an offender, so the footer buckets (clean/nag/unknown/
    # excluded) are all zero. The table itself is the data, so the block must
    # not claim "no data" beneath it.
    sig = RepoSignal(
        _repo("bad"), SignalType.CODEQL, RepoState.OFFENDER, SeverityCounts(critical=1)
    )
    blocks = slack.render_org_blocks(_org([sig]), top_n=10, pages_url=None)
    codeql = next(b for b in blocks if "CodeQL" in b.get("text", {}).get("text", ""))
    assert "no data" not in codeql["text"]["text"]


def test_top_n_limits_code_fence_rows() -> None:
    signals = [
        RepoSignal(
            _repo(f"r{i}"),
            SignalType.CODEQL,
            RepoState.OFFENDER,
            SeverityCounts(high=i),
        )
        for i in range(1, 6)
    ]
    blocks = slack.render_org_blocks(_org(signals, count=5), top_n=2, pages_url=None)
    codeql = next(b for b in blocks if "CodeQL" in b.get("text", {}).get("text", ""))
    fence = codeql["text"]["text"].split("```")[1]
    # header + 2 data rows + a Total row + a "… and N more" tally (5 offenders,
    # 2 shown).
    assert len(fence.strip().splitlines()) == 5
    assert "… and 3 more" in fence


def test_pages_link_context() -> None:
    blocks = slack.render_org_blocks(
        _org([]), top_n=10, pages_url="https://x.github.io/r/"
    )
    context = blocks[-1]
    assert context["type"] == "context"
    assert "https://x.github.io/r/" in context["elements"][0]["text"]


def test_multi_org_payload() -> None:
    payload = slack.render_payload([_org([]), _org([])], channel="C1")
    headers = [b for b in payload["blocks"] if b["type"] == "header"]
    assert len(headers) == 2


def test_dependabot_and_releases_tables_rendered() -> None:
    org = _org([], count=2)
    org.dependabot_tables = [
        report.TableSection(
            category=category_meta(CategoryKey.DEPENDABOT_COOLDOWN),
            columns=("Repository", "Ecosystems without cooldown"),
            rows=[report.TableRow(repo=_repo("bad"), cells=("pip, npm",))],
            fail_count=1,
        )
    ]
    org.releases = report.TableSection(
        category=category_meta(CategoryKey.RELEASES),
        columns=("Repository", "Last release", "Last tag"),
        rows=[report.TableRow(repo=_repo("stale"), cells=("never", "never"))],
        fail_count=1,
    )
    blocks = slack.render_org_blocks(org, top_n=10, pages_url=None)
    texts = [b.get("text", {}).get("text", "") for b in blocks]
    cooldown = next(t for t in texts if "Dependabot: Cooldown Settings" in t)
    assert "bad" in cooldown and "```" in cooldown
    # Slack is brevity-first: the explanatory description is not emitted.
    assert "reference" not in cooldown
    assert any("Releases / Tagging" in t and "stale" in t for t in texts)


def test_mutable_releases_block_shows_summary() -> None:
    org = _org([], count=84)
    org.mutable_releases = report.TableSection(
        category=category_meta(CategoryKey.MUTABLE_RELEASES),
        columns=("Repository", "Releases"),
        rows=[report.TableRow(repo=_repo("img"), cells=("v0.1.0 (latest)",))],
        pass_count=82,
        fail_count=2,
    )
    blocks = slack.render_org_blocks(org, top_n=10, pages_url=None)
    texts = [b.get("text", {}).get("text", "") for b in blocks]
    block = next(t for t in texts if "Mutable Releases" in t)
    # The heading is bare; the standardised footer sits beneath the table.
    assert "*Mutable Releases*" in block
    assert "❌ 2 Mutable" in block
    assert "✅ 82 Immutable" in block
    assert "img" in block and "v0.1.0 (latest)" in block
    # Failures sort above the pass line in the footer.
    assert block.index("2 Mutable") < block.index("82 Immutable")


def test_empty_extra_tables_are_skipped() -> None:
    # A genuinely empty table (no rows, no countable state) is skipped to keep
    # the brevity-first digest tight.
    org = _org([], count=1)
    org.dependabot_tables = [
        report.TableSection(
            category=category_meta(CategoryKey.DEPENDABOT_ALERTS_ENABLED),
            columns=("Repository",),
            rows=[],
        )
    ]
    org.releases = report.TableSection(
        category=category_meta(CategoryKey.RELEASES),
        columns=("Repository",),
        rows=[],
    )
    blocks = slack.render_org_blocks(org, top_n=10, pages_url=None)
    texts = [b.get("text", {}).get("text", "") for b in blocks]
    assert not any("Dependabot: Alerts Enabled" in t for t in texts)
    assert not any("Releases / Tagging" in t for t in texts)


def test_offender_table_has_totals_row() -> None:
    signals = [
        RepoSignal(
            _repo("a"),
            SignalType.CODEQL,
            RepoState.OFFENDER,
            SeverityCounts(critical=1, high=2, medium=3, low=4),
        ),
        RepoSignal(
            _repo("b"),
            SignalType.CODEQL,
            RepoState.OFFENDER,
            SeverityCounts(critical=1, high=1, medium=1, low=1),
        ),
    ]
    blocks = slack.render_org_blocks(_org(signals, count=2), top_n=10, pages_url=None)
    codeql = next(b for b in blocks if "CodeQL" in b["text"]["text"])
    fence = codeql["text"]["text"].split("```")[1]
    total_line = next(line for line in fence.splitlines() if "Total" in line)
    # Slack omits the Total column; the severity columns are summed in place.
    assert total_line.split() == ["Total", "2", "3", "4", "5"]


def test_secret_scanning_has_no_totals_row() -> None:
    sig = RepoSignal(
        _repo("leaky"),
        SignalType.SECRET_SCANNING,
        RepoState.OFFENDER,
        SeverityCounts(critical=4),
    )
    blocks = slack.render_org_blocks(_org([sig]), top_n=10, pages_url=None)
    heading = SignalType.SECRET_SCANNING.heading
    secret = next(b for b in blocks if heading in b["text"]["text"])
    assert "Total" not in secret["text"]["text"]


def test_table_headers_are_title_case() -> None:
    # Slack headers must be capitalised consistently ("Open"/"Score"), matching
    # the "Repository" column and the other render surfaces.
    secret_sig = RepoSignal(
        _repo("leaky"),
        SignalType.SECRET_SCANNING,
        RepoState.OFFENDER,
        SeverityCounts(critical=4),
    )
    score_sig = RepoSignal(
        _repo("scored"),
        SignalType.SCORECARD,
        RepoState.OFFENDER,
        SeverityCounts(high=1),
        score=6.5,
    )
    blocks = slack.render_org_blocks(
        _org([secret_sig, score_sig], count=2), top_n=10, pages_url=None
    )
    secret = next(
        b for b in blocks if SignalType.SECRET_SCANNING.heading in b["text"]["text"]
    )
    assert "Open" in secret["text"]["text"]
    assert " open " not in secret["text"]["text"]
    scorecard = next(
        b for b in blocks if SignalType.SCORECARD.heading in b["text"]["text"]
    )
    assert "Score" in scorecard["text"]["text"]
    assert " score " not in scorecard["text"]["text"]


def test_full_report_link_targets_org_page() -> None:
    # The digest is per-org, so the "View the full report" link must point at
    # that organisation's latest report page, not the Pages site index.
    blocks = slack.render_org_blocks(
        _org([]), top_n=10, pages_url="https://x.github.io/r/"
    )
    link = blocks[-1]["elements"][0]["text"]
    assert "<https://x.github.io/r/lfreleng-actions/report.html|" in link


def test_full_report_link_handles_missing_trailing_slash() -> None:
    blocks = slack.render_org_blocks(
        _org([]), top_n=10, pages_url="https://x.github.io/r"
    )
    link = blocks[-1]["elements"][0]["text"]
    assert "<https://x.github.io/r/lfreleng-actions/report.html|" in link
