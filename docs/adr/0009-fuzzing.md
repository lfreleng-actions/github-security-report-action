<!--
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
-->

# ADR-0009: Report fuzzing as a code-scanning signal

- **Status:** Accepted
- **Date:** 2026-11-19
- **Supersedes:** —
- **Superseded by:** —
- **Amends:** [ADR-0004](0004-report-section-order.md) (the default
  priority band)
- **Related:** [ADR-0006](0006-github-code-quality.md)

## Context

A daily publisher in `lfreleng-actions/.github`
(`fuzz-sarif-publish.yaml`) runs each repository's fuzz harnesses centrally
and uploads the failures as code-scanning SARIF, the way the zizmor and
aislop publishers upload theirs. It sends:

- tool name `fuzz`, on the default branch;
- one alert per distinct failure, each at SARIF level `error`, with rule IDs
  `fuzz/uncaught-exception`, `fuzz/timeout`, `fuzz/out-of-memory` and
  `fuzz/harness-error`;
- an analysis with no results for a repository fuzzed and found clean, and
  no analysis at all for a repository with no harness.

Many repositories in an organisation of GitHub Actions hold only workflow
files and shell, which no fuzz engine in use can run. Listing those as not
enabled would bury the repositories that could have a harness and do not.

## Decision

1. **A `fuzz` signal, classified like aislop.** `CODE_SCANNING_TOOLS` maps
   it to the tool name `fuzz`, and its category (key `fuzz`, title
   `Fuzzing`, pass label `Clean`) takes every per-category key: the render
   toggles, row limits, exclusions, row ordering and `fail_severity`. The
   default cutoff is `medium`; every result arrives at `error`, which
   normalises to `high`, so the default already counts each failure.

2. **Applicability from Linguist languages.** A repository is applicable
   when it holds at least one fuzzable language, read from the languages the
   batched GraphQL prefetch already fetches for Code Quality (ADR-0006), at
   no extra request. The set is `report.fuzz_languages`, default
   `["Python", "Go"]`, the languages the fuzz job runs or will run, matched
   case-insensitively.

3. **Five states.**
   - **Offender:** open `fuzz` alerts at or above the cutoff.
   - **Clean:** a `fuzz` analysis and no such alert.
   - **Not enabled:** applicable, with no `fuzz` analysis.
   - **Not applicable:** no fuzzable language. Counted on a footer line of
     its own and never listed as not enabled.
   - **Unknown:** as for the other code-scanning signals. A repository whose
     languages could not be read, or ran past the twenty-language window, is
     unknown rather than not enabled, as Code Quality treats it as
     unreadable.

   A `fuzz` analysis or ruleset is proof the job covers the repository, so
   such a repository is classified from its alerts whatever its languages.
   So is an open `fuzz` alert of any level, checked before any of this,
   even when the analyses read failed or lacks `fuzz`: one at or above the
   cutoff is an offender, and one below it leaves the repository clean
   after a complete alert read and unknown after an incomplete one. The
   language rule applies only after a definitive analyses read (200, or 404
   for code scanning disabled); after a forbidden or failed one the
   repository is unknown rather than Not applicable. The same holds when the
   analyses page omits `fuzz` and the filtered `fuzz` probe that should
   settle it fails: the repository is unknown, while the other signals keep
   treating a failed probe as their tool undetected. A probe answered with
   a malformed body leaves only its own tool unknown, for every signal
   (Scorecard too, unless its external score decides): it no longer turns
   the shared analyses status into a failure, so the tools the page did
   settle, and the alert read that depends on them, stand.

4. **Gated like the other workflow-driven signals.** Until an organisation
   shows an alert from the tool or an analysis on a sampled repository, the
   section shows the skip line and no repository is probed for it. No
   ruleset requires a fuzz workflow, so `report.ruleset_workflows` has no
   `fuzz` keyword.

5. **Placement.** A fuzz failure is a concrete defect with a reproducing
   input, so the section sits after CodeQL both in the fixed signal order
   and in the default **priority** band, amending ADR-0004's band
   membership.

6. **Repo mode** reads no languages, so there every repository is treated as
   applicable and `fuzz` behaves as aislop does, save that a failed `fuzz`
   probe leaves it unknown, as in organisation mode.

7. **No remediation.** Nothing about the category is fixable through a
   GitHub setting.

## Consequences

- Repositories with nothing to fuzz drop out of the nag list instead of
  padding it, and the footer says how many there are.
- Every signal section in `report.json` gains `not_applicable_count`, zero
  for every signal but `fuzz`.
- A repository holding a fuzzable language that is not worth a harness is
  dropped with the category's `exclude` list; applicability does not weigh
  the amount of code.
- Scorecard's own Fuzzing check is unaffected; the Scorecard category still
  reflects it.
