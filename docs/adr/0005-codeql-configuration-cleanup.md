<!--
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
-->

# ADR-0005: Destructive remediation for stale CodeQL configurations

- **Status:** Accepted
- **Date:** 2026-09-25
- **Supersedes:** —
- **Superseded by:** —
- **Amends:** [ADR-0003](0003-remediate-subcommand.md) (decision 5)
- **Related:** [ADR-0004](0004-report-section-order.md)

## Context

The CodeQL scan-health tables report configurations whose last scan trails
the default branch head: GitHub's *"Code Scanning results may be out of
date"*. Across `lfreleng-actions` every such configuration had the same
history. A repository switched between default and advanced setup, and the
configurations the previous setup had uploaded stayed behind, frozen at their
last scan. GitHub rejects advanced CodeQL uploads while default setup is on,
so the two alternate rather than coexist. A configuration left behind like
that will never upload again, and its stale results stand until somebody
deletes it.

Cleaning up ten such configurations across six repositories by hand took a
one-off script, and exposed what a safe cleanup needs. ADR-0003 limits
`remediate` to switching on-off features on. This is the first remediation
that **deletes**: a configuration's analyses, and with them its alert history.

## Decision

1. **`codeql_stale_configurations` is remediable, and explicit-only.** It runs
   only when named with `--category`, never as part of the default
   no-argument run, so a routine `remediate --apply` can never delete
   anything. The registry marks it `explicit_only`; the default set and the
   `--category` help text are derived from that flag.

2. **Act only on configurations that cannot upload again.** The table's cause
   is an enum carrying the remediation policy, so the table and the plan
   cannot disagree. Delete when the setup is gone (default setup off, workflow
   file removed), blocked (superseded by default setup), or no longer covers
   the language. Re-enable the workflow when GitHub disabled it for
   inactivity; that restores the scan rather than discarding it. Every other
   cause (analyses failing, default setup changing state or not uploading, an
   upload from outside GitHub Actions, a workflow disabled by hand, one active
   but not uploading, an unreadable state) is reported and left for a person.

3. **Guards refuse rather than fail.** A deletion is refused when:
   - no current configuration scans its language, since the stale results are
     then the only record of it (add scanning first; the refusal names the
     language);
   - it would help close an open alert. The guard judges the repository's
     **whole planned deletion set**, not each deletion alone: an alert closes
     once every configuration holding it is deleted, so two configurations
     can jointly close an alert neither holds alone. Every deletion holding an
     alert that no remaining configuration would report is refused, keeping
     all of that alert's holders rather than choosing one to spare;
   - the alerts cannot be read, because an unknown answer must stop a
     deletion.

   The alert check is a read, taken once per repository before any write, so
   a dry run reports refusals exactly as an apply would, and nothing depends
   on instance reads catching up with earlier deletions. A refusal is shown
   beside the work done and does not fail the run: nothing broke, the work was
   withheld.

4. **Plan from the report's own data.** The report already reads every
   analysis to find stale configurations, so it keeps each configuration's
   analysis ids, newest first, which is the order GitHub requires. Deletion
   needs no second read of the history, and plans from exactly what the
   report showed.

5. **Delete defensively.** Deletion runs serially, behind a client-wide
   throttle that spaces every cleanup mutation at least a second from the
   last, across targets as well as within one, as GitHub asks of mutating
   requests. It walks the collected ids rather than following
   `confirm_delete_url`: live, that URL came back null while older analyses
   remained. GitHub answers a request it will not authorise with `404` as
   readily as one for something absent, so no `404` is taken at its word. A
   deletion's `404` is skipped as already gone (an interrupted run, or the
   listing lagging a deletion) only once reading the analysis back also
   returns `404`, so a re-run resumes but a token that may not delete fails
   loudly. A workflow reads as removed only when the repository's contents
   show no such file.

## Consequences

- Tidying CodeQL configurations is a previewable, resumable, scoped operation
  rather than a script, and acts only on rows the report showed.
- Language coverage gaps remain unremediable here. On an advanced setup the
  fix is a workflow change in the repository, which `remediate` does not
  make; on default setup the API reports only the languages it is configured
  for, so a detected but unconfigured language is invisible to it.
- `RepoOutcome` gains a per-outcome verb and a refused state, and remediators
  may supply a pre-write check. Feature toggles keep their exact output.
- Deleting a configuration removes its alert history. The guards above bound
  that to configurations whose results no longer describe the code, and to
  deletions that close no open alert: a deleted configuration may still have
  reported an open alert, provided a remaining configuration reports it too,
  so every open alert survives the cleanup.
