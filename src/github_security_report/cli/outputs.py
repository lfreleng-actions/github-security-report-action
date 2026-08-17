# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Render-surface plumbing: offender limits, visibility, and file writing."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from github_security_report.categories import CategoryKey
from github_security_report.cli.serialise import _org_to_dict
from github_security_report.config import OrgConfig, ReportConfig
from github_security_report.models import RepoSignal
from github_security_report.render import html as html_render
from github_security_report.render import markdown as md_render
from github_security_report.report import LimitFor, OrgReport
from github_security_report.runner import should_fail

# Keep filenames within output_dir: a channel value containing "/" or ".."
# (misconfiguration or hostile input) must not escape the directory.
_UNSAFE_COMPONENT = re.compile(r"[^A-Za-z0-9_.-]+")


def _safe_component(value: str) -> str:
    """Sanitise a string for safe use as a single path component."""
    safe = _UNSAFE_COMPONENT.sub("-", value).strip("-.")
    return safe or "channel"


@dataclass(frozen=True)
class TopNLimits:
    """The offender-limit overrides supplied on the command line.

    Resolution order for one category on one output, most specific first: the
    category-specific CLI override, then the shared ``--top-n`` override, then
    the category's configured ``top_n``, then the org's configured value for
    that output. A value of 0 means "no limit" at every level.

    Command-line flags deliberately outrank the per-category configuration: a
    flag is a decision about this one run, so ``--top-n 5`` caps every category
    even where the config asked for an uncapped one.
    """

    shared: int | None = None
    report: int | None = None
    cli: int | None = None
    slack: int | None = None

    def resolve(
        self, org_cfg: OrgConfig, output: str, category: CategoryKey | None = None
    ) -> int:
        """The effective limit for ``output`` (``report``/``cli``/``slack``).

        With a ``category``, the category's own configured ``top_n`` is
        consulted before the per-output value; without one, the per-output value
        is used directly (the pre-category behaviour).
        """
        override: int | None = getattr(self, output)
        if override is not None:
            return override
        if self.shared is not None:
            return self.shared
        if category is not None:
            return org_cfg.report.category_top_n(category, output)
        return org_cfg.report.output_top_n(output)

    def resolver(self, org_cfg: OrgConfig, output: str) -> LimitFor:
        """A per-category limit lookup for one org and output.

        Renderers take this alongside the ``show`` predicate, so a category with
        its own configured ``top_n`` truncates independently of the rest.
        """
        return lambda key: self.resolve(org_cfg, output, key)


def most_generous(limits: list[int]) -> int:
    """The least restrictive of several offender limits.

    0 means "no limit", so it is the most generous value of all; otherwise the
    largest positive cap wins. Without this, ``max()`` would treat 0 as the
    smallest limit and silently re-impose a cap on an org that asked for
    everything when it shares a channel with a capped org.
    """
    if any(limit <= 0 for limit in limits):
        return 0
    return max(limits)


def show(report_cfg: ReportConfig, output: str) -> Callable[[CategoryKey], bool]:
    """A per-output category-visibility predicate for the render surfaces."""
    return lambda key: report_cfg.shows_category(key, output)


def slack_show(
    items: list[tuple[OrgConfig, OrgReport]],
) -> Callable[[CategoryKey], bool]:
    """Slack visibility for a channel: show a category if any org would.

    Orgs sharing a Slack channel render into one digest, so a category appears
    when any contributing org would show it on Slack -- mirroring the
    most-generous ``top_n`` rule for the same grouping.
    """
    return lambda key: any(oc.report.shows_category(key, "slack") for oc, _ in items)


def slack_limit(
    items: list[tuple[OrgConfig, OrgReport]], limits: TopNLimits
) -> LimitFor:
    """Per-category Slack limit for a channel: the most generous org's value.

    Orgs sharing a Slack channel render into one digest, so each category takes
    the most generous limit any contributing org configured for it -- the
    per-category counterpart of :func:`slack_show`.
    """
    return lambda key: most_generous(
        [limits.resolve(oc, "slack", key) for oc, _ in items]
    )


def write_org_files(
    org: OrgReport,
    output_dir: Path,
    *,
    top_n: int | None = None,
    limit: LimitFor | None = None,
    report_cfg: ReportConfig,
) -> None:
    """Write one org's Markdown, HTML and JSON artifacts under ``output_dir``."""
    slug = html_render.slugify(org.org)
    org_dir = output_dir / slug
    org_dir.mkdir(parents=True, exist_ok=True)
    (org_dir / "report.md").write_text(
        md_render.render_org(
            org, top_n=top_n, show=show(report_cfg, "markdown"), limit=limit
        ),
        encoding="utf-8",
    )
    (org_dir / "report.html").write_text(
        html_render.render_org_html(
            org, top_n=top_n, show=show(report_cfg, "html"), limit=limit
        ),
        encoding="utf-8",
    )
    # report.json is the complete machine-readable dataset, so the per-output
    # render toggles deliberately do not filter it.
    (org_dir / "report.json").write_text(
        json.dumps(_org_to_dict(org), indent=2) + "\n", encoding="utf-8"
    )


def repo_outputs(signals: list[RepoSignal], fail_threshold: str) -> dict[str, str]:
    """The GitHub Actions outputs a repo-mode run publishes."""
    outputs = {s.signal.value + "_open": str(s.counts.total) for s in signals}
    outputs["failed"] = "true" if should_fail(signals, fail_threshold) else "false"
    return outputs
