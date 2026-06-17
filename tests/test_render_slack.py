# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Tests for Slack payload rendering."""

from __future__ import annotations

import datetime as dt

from github_security_report import report
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


def test_offenders_are_code_fenced() -> None:
    sig = RepoSignal(
        _repo("bad"), SignalType.CODEQL, RepoState.OFFENDER, SeverityCounts(critical=1)
    )
    blocks = slack.render_org_blocks(_org([sig]), top_n=10, pages_url=None)
    codeql = next(b for b in blocks if "CodeQL" in b.get("text", {}).get("text", ""))
    assert "```" in codeql["text"]["text"]
    assert "bad" in codeql["text"]["text"]


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
    # header row + 2 data rows
    assert len(fence.strip().splitlines()) == 3


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
