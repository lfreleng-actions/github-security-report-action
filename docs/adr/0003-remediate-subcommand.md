<!--
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
-->

# ADR-0003: A `remediate` subcommand that enables missing features

- **Status:** Accepted
- **Date:** 2026-07-02
- **Supersedes:** —
- **Superseded by:** —
- **Related:** [`docs/BRIEF.md`](../BRIEF.md) (§1, §4),
  [ADR-0001](0001-architecture-and-scope.md),
  [ADR-0002](0002-report-metadata-and-footer.md)

## Context

The report ends with nag lists — repositories where a supported security
feature is switched off. Acting on them meant either clicking through each
repository's settings or reaching for the standalone [`scripts/`](../../scripts)
helpers, which each cover a single feature and reimplement scoping and token
handling. As the number of remediable features grew (CodeQL, secret scanning,
Dependabot alerts and security updates, private vulnerability reporting), the
per-feature-script approach did not scale and drifted from the report's own
scoping rules.

The tool already knows, precisely, which repositories have a feature
**confirmed off**: the four-state model (ADR-0002) classifies a repository as an
offender only when its state was read successfully and the feature is disabled.
Repositories whose state could not be read are counted as *unknown* and never
appear as offenders. That collection is exactly the read-state a safe write
needs.

## Decision

1. **A first-class `remediate` subcommand.** Alongside `report`, the CLI gains
   `remediate`, which runs the same collection and then enables each selected
   remediable feature on the offenders the report surfaces. The standalone
   scripts remain for ad-hoc single-feature runs but are no longer the primary
   path.

2. **The report is the read-state; never blind-write.** Remediation acts only on
   confirmed-off, in-scope, non-excluded offenders. Because unknown-state
   repositories are never offenders, the collection step doubles as the
   pre-write read that the never-blind-write rule requires — no separate probe,
   and no risk of toggling a feature whose state we could not confirm.

3. **Dry run by default, `--apply` to write.** These are privileged writes, so
   the command previews the work by default (`would enable`) and only mutates
   GitHub when `--apply` is passed. Dry run prints a `DRY RUN` notice; apply
   mode prints no pre-amble, because the writes complete before the output
   renders, so a "changes in progress" banner would be misleading.

4. **A single write-capable token for read and write, org-scoped.** One
   org-admin token (from `--token-env`, default `GITHUB_TOKEN`) drives both the
   collection and the writes across every configured organisation, intentionally
   bypassing the per-org read-only `token_env` in the config. Remediation is
   organisation-scoped only (`--scope org`), because the write endpoints and the
   nag lists are defined at org scope.

5. **A narrower remediable set than the report.** Only simple on/off features
   with a documented enablement endpoint are remediable: `codeql`,
   `secret_scanning`, `dependabot_alerts_enabled`, `dependabot_updates_enabled`,
   `private_vulnerability_reporting`, `auto_merge`. Qualitative findings
   (Scorecard, zizmor, open alerts, cooldown, release freshness/mutability) are
   reported but not auto-remediated. The remediable keys reuse the ADR-0002
   category registry, so selection (`--category`) speaks the same vocabulary as
   the report.

6. **A registry-driven remediator, mirroring the report's inline style.** Each
   remediable category pairs an offender extractor (a signal's NAG repos, or a
   posture table's rows) with a client write method returning `(ok, note)`. The
   terminal renderer lists what would be / was enabled and any failures inline,
   the same brevity-first shape the report footer uses, rather than a table.

## Consequences

- Enabling a feature is a documented, scoped, previewable operation rather than
  a settings click or a bespoke script, and it always acts on exactly the
  repositories the report flags.
- CodeQL default setup provisions asynchronously (HTTP 202); a successful
  remediation means "accepted", not "already scanning". Repositories with no
  supported language, or with Actions disabled, surface as non-fatal failures
  with the API's diagnostic note.
- Dependabot security updates enable the prerequisite alerts first; if that step
  fails the run aborts for that repository and reports which step failed.
- Adding a remediable feature is a single registry entry plus a client write
  method; the CLI, renderer and `--category` validation pick it up
  automatically.
- The command needs a genuinely write-capable token. A **missing** token is
  rejected before any collection runs; a present but under-scoped (read-only)
  token is not probed up front (GitHub has no side-effect-free write check), so
  it surfaces as per-repository write failures carrying the API's diagnostic
  note rather than a single up-front error.
