<!--
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
-->

# ADR-0004: Report section order as a property of the report

- **Status:** Accepted
- **Date:** 2026-08-25
- **Supersedes:** —
- **Superseded by:** —
- **Related:** [`docs/BRIEF.md`](../BRIEF.md) (§4, §11),
  [ADR-0002](0002-report-metadata-and-footer.md)

## Context

Every render surface hard-coded the same section sequence: the six signal
sections in `SIGNAL_ORDER`, then the six generic tables in whatever order their
fields happened to be declared on `OrgReport`. Four renderers each repeated
that list, and each had to remember that the Dependabot posture tables nest
beneath the Dependabot Alerts signal.

Two problems followed. First, the order was an artefact of assembly rather than
a statement about what matters: a reader met OpenSSF Scorecard — a rating that
barely moves week to week — before an open secret-scanning alert. Second, the
sequence was not configurable at all, and any attempt to make it so would have
had to change four renderers in lockstep, which is exactly the drift ADR-0002
removed from the category metadata.

`ordering.py` already solved the adjacent problem of row order *within* a
table, and did so by resolving it once at assembly time rather than per
surface. Section order has the same shape and a stronger reason for the same
treatment: a Slack digest whose sections run in a different order from the
Pages report it links to is worse than either order alone.

## Decision

1. **One module owns the sequence.** `layout.py` produces the ordered list of
   `LayoutItem`s every surface draws. The renderers no longer hold a copy of
   the order, and the HTML template no longer has a named slot per table — it
   iterates one list, as it already did for the signal sections.

2. **Resolved once, at assembly.** `layout.resolve()` runs where
   `apply_configured_order()` already runs, after the tables are built (the
   automatic layout demotes empty categories, so it has to see them). The
   result is stored on the report and applied identically by every surface.

3. **Stored as plain category keys, not as configuration.**
   `OrgReport.section_order` is a `tuple[CategoryKey, ...]`. Storing the
   resolved `OrderConfig` instead would have made the report model depend on
   the config tree, which nothing else in `report/` does; `ordering.py` keeps
   the same separation by taking config as a parameter. An empty tuple means
   assembly order, so a report built without a resolution — repo mode, and
   every test that calls `build_org_report` directly — behaves exactly as
   before.

4. **Three bands, with movement between them.** The default `auto` style puts
   actionable findings first (secret scanning, Dependabot alerts, CodeQL,
   mutable releases), business-as-usual categories last (Scorecard, issues,
   pull requests), and everything else between. A band member with no rows
   **moves into the middle**: a clean priority category is noise at the top of
   a page, and a clean BAU category has stopped being background. Demoted
   members sit at the edge of the middle nearest their own band, so whatever
   survives in each band still bounds the middle from its own side.

5. **Automatic is the default, not an opt-in.** A configuration that says
   nothing about ordering gets the band layout. The alternative — defaulting to
   the old order — would have left the improvement switched off for every
   existing user, which is the outcome that motivated the change.

6. **`fixed` is the escape hatch.** The pre-existing order remains reachable by
   name. Making the automatic layout the default without one would have removed
   a behaviour some operator may prefer, with no way to ask for it back.

7. **Contradictory configuration is an error.** A band list paired with a style
   that does not read it, a `single` style with no sequence, a category named
   twice or in both bands — all rejected at load. Each names a case where the
   config asked for something specific and would otherwise have silently got
   something else.

8. **The Dependabot posture tables are not independently placeable.** They
   travel with their parent signal as `LayoutItem.children`. Detaching them
   would leave three near-identical headings adrift with nothing to say which
   signal they qualified.

## Consequences

- Reordering the report is a change in one module, and cannot leave one
  surface disagreeing with another.
- **The default output order changes for every user.** This is intended, and
  `report.order.style: "fixed"` restores the previous sequence exactly.
- `report.json` gains `section_order`, so a machine consumer can reproduce the
  published layout rather than inventing one. The file's keyed structure is
  otherwise unchanged, so existing consumers are unaffected.
- `report.order.*` joins the configuration contract, and the ordering lists
  name category keys — reinforcing ADR-0002's point that those keys must be
  renamed with care.
- The Slack renderer previously skipped a gated signal's posture sub-tables
  when the parent was both skipped and visible, but rendered them when the
  parent was hidden. Routing every surface through one layout makes the
  sub-tables independent of the parent's state everywhere, matching the other
  three renderers. Only gated signals could reach that path, and Dependabot is
  never gated, so no released output changes.
