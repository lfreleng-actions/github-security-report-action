# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Slack rendering.

Slack mrkdwn cannot render Markdown tables, so the digest uses fixed-width
code-fenced blocks (the only way to align columns) showing the worst N
offenders per signal, plus a prominent link to the full GitHub Pages report.
Like the terminal, Slack is a brevity-first surface: it carries the
standardised summary footer but omits the per-category explanatory description.
Produces a ``chat.postMessage`` payload. See ``docs/BRIEF.md`` section 11.

Slack validates the payload as a whole and rejects all of it if any structural
limit is breached, so every block built here is sized by
:mod:`~github_security_report.render.slack_limits` before it is emitted.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence

from github_security_report import layout
from github_security_report.categories import CategoryKey
from github_security_report.models import Repo
from github_security_report.render.html import slugify
from github_security_report.render.slack_limits import (
    MAX_TEXT_CHARS,
    context_block,
    enforce_block_limit,
    fallback_text,
    fit_section_text,
    header_block,
    text_length,
)
from github_security_report.render.slack_text import (
    _fixed_table,
    _fixed_table_generic,
    _mrkdwn,
    _name_breaks,
    _name_cap,
    _summary_text,
)
from github_security_report.report import (
    DEFAULT_FOOTER,
    ORG_SETUP_DOC_URL,
    SKIP_MESSAGE,
    SUMMARY_EMOJI,
    FooterOptions,
    LimitFor,
    OrgReport,
    RepoList,
    SignalSection,
    TableSection,
    WindowsFor,
    build_summary,
    limit_resolver,
    table_column_totals,
    table_footer_rows,
    truncate,
    window_shown,
)


def _table_block(
    section: TableSection,
    top_n: int,
    *,
    excluded: Sequence[Repo],
    repo_list: RepoList = RepoList.AUTO,
) -> dict | None:
    """A Slack section block for a posture/freshness table (None when empty).

    The block is emitted whenever there is something to say -- offender rows or a
    non-empty standardised summary footer -- so a clean category still surfaces
    its "All <pass>" line. A table with neither rows nor any countable state
    (genuinely no data) is skipped, keeping the brevity-first digest tight. The
    explanatory description is omitted: Slack is a brevity-first surface. A
    boolean feature table draws no fixed-width table: its repositories are
    named in the footer, as on every other surface. A table whose rows carry
    a ``digest`` line is drawn as a bullet per row instead of a fixed-width
    table: it is too wide for a digest, and the line says what matters.
    """
    lines = build_summary(section.summary_counts(excluded, repo_list=repo_list))
    row_cap = 0 if section.lists_repos else len(truncate(section.rows, top_n)[0])
    name_cap = _name_cap(lines, top_n)
    if not row_cap and not _summary_text(lines, names=name_cap):
        return None
    digest = bool(section.rows) and all(row.digest for row in section.rows)

    def build(rows: int, names: int) -> str:
        text = f"*{section.title}*"
        if rows and digest:
            shown = section.rows[:rows]
            text += "".join(f"\n• {_mrkdwn(row.digest)}" for row in shown)
            hidden = len(section.rows) - len(shown)
            if hidden:
                text += f"\n… and {hidden} more"
        elif rows:
            shown = section.rows[:rows]
            cells = [[row.repo.name, *row.cells] for row in shown]
            totals = table_column_totals(section, shown)
            if totals is not None:
                cells.append(list(totals))
            # Aggregate rows beneath the totals, already full width so the
            # fixed-width column alignment holds. Not a personal surface: a
            # channel digest is read by the whole team, not by the token owner.
            for footer_row in table_footer_rows(section, shown):
                cells.append(list(footer_row))
            table = _fixed_table_generic(section.columns, cells)
            hidden = len(section.rows) - len(shown)
            if hidden:
                table += f"\n… and {hidden} more"
            text += f"\n```\n{table}\n```"
        summary = _summary_text(lines, names=names)
        if summary:
            text += f"\n{summary}"
        return text

    return {
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": fit_section_text(
                build,
                rows=row_cap,
                names=name_cap,
                name_breaks=_name_breaks(lines),
            ),
        },
    }


def _signal_block(
    section: SignalSection, top_n: int, *, excluded: Sequence[Repo]
) -> dict:
    """A Slack section block for one signal's offender table and footer."""
    lines = build_summary(section.summary_counts(excluded))

    def build(rows: int, names: int) -> str:
        text = f"*{section.signal.heading}*"
        if section.offenders:
            text += f"\n```\n{_fixed_table(section, rows)}\n```"
        summary = _summary_text(lines, names=names)
        if summary:
            text += f"\n{summary}"
        elif not section.offenders:
            # Only genuine absence of data (no rows and no countable state)
            # warrants "no data"; an all-offender table has nothing to add.
            text += "\nno data"
        return text

    row_cap = len(truncate(section.offenders, top_n)[0])
    text = fit_section_text(
        build,
        rows=row_cap,
        names=_name_cap(lines, top_n),
        name_breaks=_name_breaks(lines),
    )
    return {"type": "section", "text": {"type": "mrkdwn", "text": text}}


def render_org_blocks(
    org: OrgReport,
    *,
    top_n: int,
    pages_url: str | None,
    show: Callable[[CategoryKey], bool] | None = None,
    limit: LimitFor | None = None,
    footer: FooterOptions = DEFAULT_FOOTER,
    windows: WindowsFor | None = None,
) -> list[dict]:
    """Slack blocks for one organisation."""
    visible = show or (lambda _key: True)
    resolve = limit_resolver(top_n, limit)

    def limit_for(key: CategoryKey) -> int:
        # Slack's helpers take a plain int; ``truncate`` treats None and 0
        # identically (both mean "no limit"), so normalise None to 0 here.
        return resolve(key) or 0

    blocks: list[dict] = [header_block(f"🔐 Security report: {org.org}")]
    if org.partial:
        blocks.append(
            context_block(
                "⚠️ Incomplete: the repository listing could not "
                "be fully read; some repositories may be missing."
            )
        )

    def add_table(section: TableSection | None) -> None:
        """Append one extra table's block, honouring its visibility and limit."""
        if section is None or not visible(section.category.key):
            return
        if not window_shown(windows, section):
            return
        key = section.category.key
        block = _table_block(
            section,
            limit_for(key),
            excluded=footer.excluded_shown(org, key),
            repo_list=footer.repo_list(key),
        )
        if block is not None:
            blocks.append(block)

    for item in layout.plan(org):
        if isinstance(item.section, TableSection):
            add_table(item.section)
            for table_section in item.children:
                add_table(table_section)
            continue
        section = item.section
        key = section.signal.category_key
        if visible(key):
            if section.skipped:
                # Feature gating found no organisation support: one skip line
                # linking the setup guide, instead of a table and footer.
                text = (
                    f"*{section.signal.heading}*"
                    f"\n{SUMMARY_EMOJI['excluded']} {SKIP_MESSAGE} — "
                    f"<{ORG_SETUP_DOC_URL}|setup guide>"
                )
                blocks.append(
                    {"type": "section", "text": {"type": "mrkdwn", "text": text}}
                )
            else:
                blocks.append(
                    _signal_block(
                        section,
                        limit_for(key),
                        excluded=footer.excluded_shown(org, key),
                    )
                )
        # A signal's sub-tables follow its block.
        for table_section in item.children:
            add_table(table_section)
    if pages_url:
        # Link straight to this organisation's latest report page rather than
        # the Pages index: the digest is per-org, so the index is a detour.
        org_url = f"{pages_url.rstrip('/')}/{slugify(org.org)}/report.html"
        link = f"<{org_url}|View the full report>"
        # Omit the link rather than clamp it: a cut URL resolves elsewhere,
        # which is a wrong answer rather than a missing one.
        if text_length(link) <= MAX_TEXT_CHARS:
            blocks.append(context_block(link))
    return blocks


def render_payload(
    orgs: list[OrgReport],
    *,
    channel: str,
    top_n: int = 10,
    pages_url: str | None = None,
    show: Callable[[OrgReport, CategoryKey], bool] | None = None,
    limit: LimitFor | None = None,
    footer: Callable[[OrgReport], FooterOptions] | None = None,
    windows: Callable[[OrgReport], WindowsFor | None] | None = None,
) -> dict:
    """Build a ``chat.postMessage`` payload across one or more organisations.

    ``show`` is resolved per organisation rather than once for the channel:
    visibility is a property of each organisation's own data, so one
    organisation opting a category into Slack must not publish another's.
    ``footer`` is resolved per organisation for the same reason: each
    organisation's footers follow its own configuration. The ``limit`` stays
    channel-wide, since a row cap is a property of the shared digest rather
    than of the data in it.
    """
    blocks: list[dict] = []
    for org in orgs:
        org_show = (
            None if show is None else (lambda key, org=org: show(org, key))  # type: ignore[misc]
        )
        blocks.extend(
            render_org_blocks(
                org,
                top_n=top_n,
                pages_url=pages_url,
                show=org_show,
                limit=limit,
                footer=DEFAULT_FOOTER if footer is None else footer(org),
                windows=None if windows is None else windows(org),
            )
        )
    blocks = enforce_block_limit(blocks, pages_url)
    names = ", ".join(o.org for o in orgs)
    return {
        "channel": channel,
        "text": fallback_text(f"🔐 Security report: {names}"),
        "blocks": blocks,
    }
