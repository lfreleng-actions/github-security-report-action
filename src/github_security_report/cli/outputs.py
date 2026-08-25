# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Render-surface plumbing: offender limits, visibility, and file writing."""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Collection
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
    the category's configured ``top_n``, then the configured value for that
    output. A value of 0 means "no limit" at every level.

    Resolved against a :class:`ReportConfig` rather than an :class:`OrgConfig`:
    every level of the fallback reads the report block alone, and repo mode has
    one of those without an organisation to hang it from.

    Command-line flags deliberately outrank the per-category configuration: a
    flag is a decision about this one run, so ``--top-n 5`` caps every category
    even where the config asked for an uncapped one.
    """

    shared: int | None = None
    report: int | None = None
    cli: int | None = None
    slack: int | None = None

    def resolve(
        self, report_cfg: ReportConfig, output: str, category: CategoryKey | None = None
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
            return report_cfg.category_top_n(category, output)
        return report_cfg.output_top_n(output)

    def resolver(self, report_cfg: ReportConfig, output: str) -> LimitFor:
        """A per-category limit lookup for one report config and output.

        Renderers take this alongside the ``show`` predicate, so a category with
        its own configured ``top_n`` truncates independently of the rest.
        """
        return lambda key: self.resolve(report_cfg, output, key)


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


# Render surfaces whose output is published rather than read locally. A
# category none of them carries has no business in the published report.json
# either, however complete that file is meant to be.
_PUBLISHED_OUTPUTS = ("markdown", "html", "slack")


def show(
    report_cfg: ReportConfig,
    output: str,
    hidden: Collection[CategoryKey] = (),
) -> Callable[[CategoryKey], bool]:
    """A per-output category-visibility predicate for the render surfaces.

    ``hidden`` is the command line's explicit suppression list and outranks the
    configuration entirely, matching the rule the row limits already follow: a
    flag is a decision about this one run. It is one-way on purpose -- it can
    hide a category the config would show, but never reveal one the config
    disabled -- so a CI invocation can suppress a category without having to
    know, or contradict, what the config asked for.
    """
    suppressed = frozenset(hidden)
    return lambda key: key not in suppressed and report_cfg.shows_category(key, output)


def slack_show(
    items: list[tuple[OrgConfig, OrgReport]],
    hidden: Collection[CategoryKey] = (),
) -> Callable[[OrgReport, CategoryKey], bool]:
    """Slack visibility for a channel, resolved **per organisation**.

    Deliberately not pooled the way the row limits are. A limit is a property
    of the shared digest, so taking the most generous value across contributing
    organisations is right; visibility is a property of each organisation's own
    data, and pooling it would let one organisation's opt-in publish another's.
    For a reader-specific category that is a leak rather than an inconsistency:
    an organisation that kept the personal queue terminal-only would have it
    posted to the channel because a different organisation enabled the table.

    An explicitly hidden category is suppressed for the whole digest, since the
    request was made of the run rather than of one organisation.
    """
    suppressed = frozenset(hidden)

    def visible(org: OrgReport, key: CategoryKey) -> bool:
        if key in suppressed:
            return False
        # Matched by identity rather than by name. The schema does not make
        # organisation names unique within a run, and a name-keyed lookup would
        # collapse two entries for the same org onto one configuration -- so a
        # report that opted out would be rendered under its duplicate's toggles,
        # which is the very leak this function exists to prevent. A channel
        # holds a handful of reports, so the scan costs nothing.
        for org_cfg, report in items:
            if report is org:
                return org_cfg.report.shows_category(key, "slack")
        # A report absent from the list was never configured here, so it falls
        # back to the default-visible rule the rest of the tool uses.
        return True

    return visible


def slack_limit(
    items: list[tuple[OrgConfig, OrgReport]], limits: TopNLimits
) -> LimitFor:
    """Per-category Slack limit for a channel: the most generous org's value.

    Orgs sharing a Slack channel render into one digest, so each category takes
    the most generous limit any contributing org configured for it -- the
    per-category counterpart of :func:`slack_show`.
    """
    return lambda key: most_generous(
        [limits.resolve(oc.report, "slack", key) for oc, _ in items]
    )


def write_org_files(
    org: OrgReport,
    output_dir: Path,
    *,
    top_n: int | None = None,
    limit: LimitFor | None = None,
    report_cfg: ReportConfig,
    hidden: Collection[CategoryKey] = (),
) -> None:
    """Write one org's Markdown, HTML and JSON artifacts under ``output_dir``."""
    slug = html_render.slugify(org.org)
    org_dir = output_dir / slug
    org_dir.mkdir(parents=True, exist_ok=True)
    (org_dir / "report.md").write_text(
        md_render.render_org(
            org,
            top_n=top_n,
            show=show(report_cfg, "markdown", hidden),
            limit=limit,
        ),
        encoding="utf-8",
    )
    (org_dir / "report.html").write_text(
        html_render.render_org_html(
            org, top_n=top_n, show=show(report_cfg, "html", hidden), limit=limit
        ),
        encoding="utf-8",
    )
    # report.json is the complete machine-readable dataset, so the per-output
    # render toggles deliberately do not filter it -- a category hidden from
    # the terminal is still published in full for a JSON consumer.
    #
    # Two exceptions, both because this file is written into the *published*
    # Pages directory alongside the HTML rather than kept locally:
    #
    #  * an explicit ``--hide``, whose whole purpose is keeping a category out
    #    of shared output for this run; and
    #  * a category no published surface carries at all. "Assigned to Me" is
    #    terminal-only by default, so serialising it here would publish one
    #    account's review queue through the back door while every rendered
    #    surface correctly omitted it.
    #
    # A category shown on *any* published surface stays in the JSON, so this
    # subtracts only what is genuinely local-only.
    terminal_only = frozenset(
        key
        for key in CategoryKey
        if not any(
            report_cfg.shows_category(key, output) for output in _PUBLISHED_OUTPUTS
        )
    )
    (org_dir / "report.json").write_text(
        json.dumps(_org_to_dict(org, frozenset(hidden) | terminal_only), indent=2)
        + "\n",
        encoding="utf-8",
    )


def repo_outputs(signals: list[RepoSignal], fail_threshold: str) -> dict[str, str]:
    """The GitHub Actions outputs a repo-mode run publishes."""
    outputs = {s.signal.value + "_open": str(s.counts.total) for s in signals}
    outputs["failed"] = "true" if should_fail(signals, fail_threshold) else "false"
    return outputs
