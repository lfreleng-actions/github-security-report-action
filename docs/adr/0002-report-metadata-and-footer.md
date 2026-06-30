<!--
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
-->

# ADR-0002: Metadata-driven report categories and a standardised footer

- **Status:** Accepted
- **Date:** 2026-06-30
- **Supersedes:** —
- **Superseded by:** —
- **Related:** [`docs/BRIEF.md`](../BRIEF.md) (§4, §6, §11),
  [ADR-0001](0001-architecture-and-scope.md)

## Context

The report renders across four surfaces — Rich terminal, Slack mrkdwn, Markdown
(the canonical artifact and GitHub job summary), and HTML (GitHub Pages). Each
surface had grown its own copy of the per-category heading text, the under-table
summary wording, the "clean"/"not enabled"/"unknown" footnotes, and the
explanatory notes. The same conceptual line was phrased differently on each
surface ("✅ 86 repositories clean" vs "86 enabled" vs "All in-scope
repositories have this feature enabled."), some categories duplicated a count
that was already stated ("All enabled" *and* "86 enabled"), and the section
descriptions were either hard-coded per surface or absent for several
categories. Adding a category, renaming a label, or changing the footer ordering
meant editing four renderers and their tests in lockstep, and it was easy for
them to drift.

## Decision

1. **A single category registry.** `categories.py` holds a `CategoryMeta` for
   each of the ten reporting categories: stable `key` (also the future config
   key), display `title`, `pass_label`, `fail_label`, documentation `url`, and a
   default `description`. The registry imports nothing from the rest of the
   package, so both the domain models and the renderers depend on it without a
   cycle. Renderers no longer hard-code headings, labels or explanatory text.

2. **One footer builder for every surface.** `report.build_summary()` turns a
   category's normalised count buckets (fail / disabled / unknown / pass /
   excluded) into ordered, formatted `SummaryLine`s. Every surface renders those
   lines, so wording and ordering are identical everywhere. Ordering is
   remediation-first: failures and disabled at the top, then unknown, then the
   healthy pass line, then excluded — this tool drives remediation, so the work
   to do sits at the top.

3. **The "All <pass>" collapse.** The pass line reads `All <pass_label>` (no
   number) only when no other bucket needs attention; otherwise every present
   bucket shows its count. This replaces the previous mix of "All enabled" plus
   a redundant numeric count.

4. **Descriptions are a rich-surface affordance.** The per-category description
   and its documentation link render only on Markdown and HTML, where there is
   room to scroll. The terminal and Slack stay brevity-first (Slack is for
   incident response, where superfluous text is noise).

5. **Per-category exclusions, no org banner.** Excluded repositories are surfaced
   in each category's footer (a counted `⏩` line plus a named breakdown) rather
   than a single org-level banner, so the exclusion is visible in the context of
   every category it affects.

## Consequences

- A wording, label, URL or ordering change is made once in the registry or
  `build_summary()` and flows to all four surfaces.
- The `TableSection` model carries `CategoryMeta` plus normalised
  pass/fail/unknown counts instead of pre-rendered `note`/`summary`/`empty_note`
  strings; the old per-surface note-splitting helper is gone.
- Category `key` values are part of the configuration contract (they name the
  forthcoming per-category and per-output toggles), so they must be renamed with
  care.
- The Dependabot enablement table is titled **"Dependabot: Alerts Enabled"** to
  disambiguate it from the **"Dependabot: Security Alerts"** open-alert signal it
  nests beneath.
