# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Where each category sits in the report, and why.

Every render surface used to hard-code the same sequence: the six signal
sections in ``SIGNAL_ORDER``, then the six generic tables in whatever order
their fields happened to be declared. That order was an artefact of how the
report is assembled rather than a statement about what matters, so a reader met
OpenSSF Scorecard first and an open secret-scanning alert somewhere below the
fold.

This module owns the sequence instead, and every surface renders what it
returns. The order is **resolved once, when the report is assembled**, and
stored on the report as a plain list of category keys, for the same reason
:mod:`github_security_report.ordering` resolves row ordering there: a section's
position is a property of the report, so the terminal, Slack, Markdown and HTML
surfaces must agree on it. A Slack digest whose sections run in a different
order from the page it links to is worse than either order alone. Storing the
resolved keys rather than the configuration also keeps the report model free of
a dependency on the config tree, matching how the rest of the package layers.

Three bands, and the movement between them
------------------------------------------

The default ``auto`` style sorts the categories into three bands:

* **Priority** -- findings that warrant acting on today: a leaked secret, a
  vulnerable dependency, a code-scanning alert, a mutable release.
* **Middle** -- everything else, in the order the report assembles it.
* **BAU** -- the categories expected to carry data every single run (Scorecard
  scores, open issues, open pull requests). They are the *background*, so
  leading with them buries whatever is actually new.

The bands are not fixed slots. A priority category with nothing to report is
noise at the top of a page, and a BAU category with nothing to report has
stopped being background, so **a band member with no rows moves into the
middle**. Demoted priority categories sit at the top of the middle band and
demoted BAU ones at the bottom, which keeps the gradient intact: whatever
survives in the priority band still bounds the middle from above, and whatever
survives in BAU still bounds it from below.

"Nothing to report" means no displayed rows -- no offenders on a signal
section, no rows on a table. A section skipped by organisation feature gating
renders a single notice rather than results, so it demotes too.

Styles
------

``report.order.style`` picks how the sequence is built:

``auto`` (the default)
    The bands above, with the built-in membership.
``dual``
    The same algorithm over ``priority`` and ``bau`` lists supplied by the
    operator. Either may be omitted to keep the built-in one.
``single``
    A strict hierarchy from one ``sequence`` list, applied verbatim with no
    demotion. Categories the list omits keep their assembly order behind it.
``fixed``
    No reordering at all -- the order this tool produced before any of this
    existed, kept so an operator who preferred it can say so.

The Dependabot posture tables (alerts enabled, security updates enabled,
cooldown) are **not** independently placeable. They render as sub-sections
beneath the Dependabot Alerts signal on every surface, and detaching them from
their parent would leave three near-identical headings floating in the report
with nothing to say which signal they qualified. They travel with it instead,
as :attr:`LayoutItem.children`.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from github_security_report.categories import CategoryKey
from github_security_report.config import OrderConfig, OrderStyle
from github_security_report.models import SignalType
from github_security_report.report import OrgReport, SignalSection, TableSection


@dataclass(frozen=True)
class LayoutItem:
    """One top-level entry in the report, with any sub-tables it carries.

    ``children`` is non-empty only for the Dependabot Alerts signal, whose
    posture tables render beneath it. Each surface decides how to nest them --
    Markdown and HTML demote them to sub-headings, the terminal and Slack simply
    follow the parent block -- but every surface renders them here, beside the
    signal they qualify.
    """

    section: SignalSection | TableSection
    children: tuple[TableSection, ...] = ()

    @property
    def key(self) -> CategoryKey:
        """The category this item renders."""
        if isinstance(self.section, SignalSection):
            return self.section.signal.category_key
        return self.section.category.key

    @property
    def populated(self) -> bool:
        """Whether this item has results to show, counting its children.

        "Results" means rows and named repositories -- a signal's offender
        table, the repositories it nags as having the tool disabled, or a
        table's rows. Those are what a reader sees when they look at the
        section, and what a band position is worth holding for.

        The bare counts every category prints regardless (clean, unknown) do
        not count. A category reporting only "All Clean" plainly has nothing to
        say; an unknown tally has nothing a reader can act on either, and
        counting it would keep a signal pinned at the top of the page on the
        strength of repositories it could not read.

        A skipped signal section is short-circuited: feature gating collected
        nothing, so it renders one line of explanation rather than results.
        """
        if isinstance(self.section, SignalSection):
            own = not self.section.skipped and bool(
                self.section.offenders or self.section.nag_repos
            )
        else:
            own = bool(self.section.rows)
        return own or any(child.rows for child in self.children)


def default_items(org: OrgReport) -> list[LayoutItem]:
    """Every renderable section, in the order the report assembles them.

    The sequence each surface hard-coded before this module existed, and the
    input every ordering style rearranges. A table that was never collected
    (repo mode does not build them) is absent rather than present and empty.
    """
    items = [
        LayoutItem(
            section,
            tuple(org.dependabot_tables)
            if section.signal is SignalType.DEPENDABOT
            else (),
        )
        for section in org.sections
    ]
    items.extend(
        LayoutItem(table)
        for table in (
            org.releases,
            org.mutable_releases,
            org.private_vulnerability_reporting,
            org.issues,
            org.pull_requests,
            org.assigned_pull_requests,
        )
        if table is not None
    )
    return items


def _in_order(
    items: Sequence[LayoutItem], keys: Iterable[CategoryKey]
) -> list[LayoutItem]:
    """``items`` reordered by ``keys``, with anything unnamed left behind it.

    A key naming a category this report did not produce is skipped, and a key
    repeated is placed once: the same section must never appear twice, and a
    repo-mode run legitimately has no Releases table for a key to name.
    """
    by_key = {item.key: item for item in items}
    named: list[LayoutItem] = []
    placed: set[CategoryKey] = set()
    for key in keys:
        item = by_key.get(key)
        if item is not None and key not in placed:
            placed.add(key)
            named.append(item)
    return [*named, *[item for item in items if item.key not in placed]]


def _banded(
    items: Sequence[LayoutItem],
    priority: Iterable[CategoryKey],
    bau: Iterable[CategoryKey],
) -> list[CategoryKey]:
    """Sort into priority / middle / BAU, demoting each band's empty members.

    Band membership is taken in the order the band lists it, so an operator's
    ``priority`` order is honoured rather than re-sorted by assembly order.
    """
    by_key = {item.key: item for item in items}
    claimed: set[CategoryKey] = set()

    def band(keys: Iterable[CategoryKey]) -> list[LayoutItem]:
        out = []
        for key in keys:
            item = by_key.get(key)
            # A key repeated, or already claimed by the other band, must not
            # place the same section in two positions.
            if item is not None and key not in claimed:
                claimed.add(key)
                out.append(item)
        return out

    top = band(priority)
    bottom = band(bau)
    middle = [item for item in items if item.key not in claimed]

    ordered = [
        *[item for item in top if item.populated],
        # Demoted band members bound the middle from each side, so the gradient
        # from "act on this" down to "background" survives the demotion.
        *[item for item in top if not item.populated],
        *middle,
        *[item for item in bottom if not item.populated],
        *[item for item in bottom if item.populated],
    ]
    return [item.key for item in ordered]


def resolve(
    org: OrgReport, order: OrderConfig | None = None
) -> tuple[CategoryKey, ...]:
    """The category sequence this report should render in.

    Called once during assembly; the result is stored on the report as
    :attr:`OrgReport.section_order` and applied by :func:`plan` on every
    surface.

    Always the **realised** sequence -- every section this report actually
    carries, in the order it will be drawn -- rather than whatever the
    configuration listed. A ``single`` sequence naming three categories, or
    naming one the report does not carry, would otherwise be stored verbatim
    and leave ``section_order`` disagreeing with what the renderers drew.
    """
    resolved = order if order is not None else OrderConfig()
    items = default_items(org)
    if resolved.style is OrderStyle.FIXED:
        keys: list[CategoryKey] = [item.key for item in items]
    elif resolved.style is OrderStyle.SINGLE:
        keys = [item.key for item in _in_order(items, resolved.sequence)]
    else:
        keys = _banded(items, resolved.priority, resolved.bau)
    return tuple(keys)


def plan(org: OrgReport) -> list[LayoutItem]:
    """The ordered sections every render surface should draw, in order.

    Applies the sequence resolved at assembly time. A report that never had one
    resolved -- one built straight from :func:`report.build_org_report`, as the
    tests do -- renders in assembly order, which is the pre-existing behaviour.
    Both real pipelines resolve one: org mode in ``attach_extra_tables`` and
    repo mode in ``_run_repo``.
    """
    return _in_order(default_items(org), org.section_order)


def drawn_order(org: OrgReport) -> list[CategoryKey]:
    """Every category in the order it is drawn, nested tables included.

    :attr:`OrgReport.section_order` holds top-level positions only, because a
    nested table has no position of its own to configure. A reader of the
    report still meets those tables somewhere definite, though, so this expands
    each parent to the children that follow it -- the sequence of headings, as
    opposed to the sequence of configurable slots.
    """
    return [
        key
        for item in plan(org)
        for key in (item.key, *(child.category.key for child in item.children))
    ]
