<!--
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
-->

# Phase 0 findings

Results from running `scripts/phase0_capability_spike.py` against
`lfreleng-actions`. This records what the real APIs returned so the design in
[`BRIEF.md`](BRIEF.md) and [`adr/0001-architecture-and-scope.md`](adr/0001-architecture-and-scope.md)
can be confirmed or corrected. Raw output lives in the git-ignored
`phase0-output/` (not committed).

First run: `--org lfreleng-actions --sample 5` (97 repos total, 96 in default
scope), classic PAT with `security_events`, `repo`, `read:org`. A second run
targeted five more demanding repos (`dependamerge`, `lftools-uv`,
`github2gerrit-action`, `gha-workflow-linter`, `python-nss-ng`) with the spike
refined to report the code-scanning **tool/severity mix** from the full first
page.

## Confirmed

- **Org-bulk endpoints work with the PAT** — all three returned `200`:
  `/orgs/{org}/code-scanning/alerts`, `/orgs/{org}/dependabot/alerts`,
  `/orgs/{org}/secret-scanning/alerts`. The **org-bulk-first** strategy is
  validated: the sampled five repos were individually clean, yet the org sweep
  surfaced real alerts — i.e. per-repo sampling misses offenders that the bulk
  sweep catches. Rate-limit cost is low (a few units per sweep).
- **Severity fields for ranking are present:**
  - code scanning: `rule.security_severity_level` ∈
    {critical, high, medium, low} **and** `rule.severity` ∈
    {error, warning, note}. Rank on `security_severity_level`, fall back to
    `severity`.
  - dependabot: `security_advisory.severity` plus
    `security_advisory.cvss.score` (and `cvss_severities`, `cwes`, `epss`).
- **Org-bulk alerts carry the full `repository` object** (`full_name`, `fork`,
  `private`, …) — so the ranked tables can be built entirely from the bulk
  sweep without per-repo alert calls.
- **Enabled-probes (positive cases) behave as designed:** code scanning
  `default-setup.state == "configured"`; secret scanning `200 []` =
  enabled-clean; Dependabot GraphQL `hasVulnerabilityAlertsEnabled == true`.

## Corrections to the design

### 1. Scorecard has two complementary sources (external API + code scanning)

The external `api.securityscorecards.dev` endpoint is viable for **prominent**
repos but not small ones: it returned the aggregate **0–10 score** for four of
the five demanding repos (`dependamerge` 8.2, `lftools-uv` 8.2,
`gha-workflow-linter` 8.4, `python-nss-ng` 7.7) and `404` for
`github2gerrit-action` — and `404` for *every* small action repo in the first
sample. Coverage tracks repo prominence/inclusion in the public dataset.

Scorecard results are **also** present in **code scanning** as alerts with
`tool.name == "Scorecard"` (per-check findings with `security_severity_level`),
for any repo running the `openssf-scorecard` workflow — broader coverage than
the external API, but per-check, not an aggregate score.

**Decision impact:** the Scorecard table prefers the **external API aggregate
score** (inverted, lower = worse) where available (`200`), falls back to
**code-scanning Scorecard findings** (count/severity) where the external API
404s but the workflow runs, and is a **nag** where neither exists
(e.g. `github2gerrit-action`: external 404 + 0 Scorecard code-scanning alerts).
This also resolves the earlier "where does the 0–10 score come from" question.

### 2. Code scanning multiplexes THREE tools — and zizmor dominates

The org-bulk code-scanning sweep (first page of 100 open alerts) split as:

- **zizmor: 47** (`severity` error:15, warning:32 — no `security_severity_level`)
- **Scorecard: 33** (high:12, medium:17, low:4)
- **CodeQL: 20** (all medium)

So `/code-scanning/alerts` multiplexes **CodeQL, Scorecard and zizmor** (the
GitHub Actions security linter), with **zizmor the single largest contributor**.
Partitioning by `tool.name` is mandatory; treating the feed as "CodeQL" would be
badly wrong. Note the per-repo view for the five demanding repos showed *only*
Scorecard alerts — their CodeQL/zizmor findings are clean, so the org-bulk
CodeQL/zizmor volume comes from other repos in the estate.

**Open decision (needs your call):** zizmor is out of the current v1 scope but
is the dominant signal. Options: (a) keep v1 as the four agreed tables and bin
zizmor under a future "other scanners" section; (b) **promote zizmor to a fifth
v1 table** given its volume and that it is a real GHA-workflow security signal.

### 3. Severity ranking keys confirmed (including the fallback)

- CodeQL & Scorecard populate `rule.security_severity_level`
  (critical/high/medium/low) — the primary ranking key.
- zizmor populates only `rule.severity` (error/warning) — exercising the
  **fallback** path exactly as designed.
- Dependabot: `security_advisory.severity` + `security_advisory.cvss.score`.

## Gaps — not yet observed (need targeted follow-up probes)

The sampled repos all had tooling enabled and were clean, so the **negative**
sides of the enabled-probe contract are unconfirmed:

- secret scanning `404` (feature disabled) — predicted but not seen.
- Dependabot `hasVulnerabilityAlertsEnabled == false` — not seen.
- code scanning `default-setup` `not-configured` / a repo with no CodeQL — not
  seen.
- a repo where code scanning is entirely absent (to confirm the
  empty-list-vs-disabled disambiguation end to end).

Follow-up: pick repos known to lack each feature (or a throwaway/private repo)
and re-run with explicit `--repo` to capture each negative status code.

## Spike refinements made / still to make

- ✅ Partition and report code-scanning counts by `tool.name` + severity in the
  matrix (done; surfaced zizmor).
- ✅ Capture a fuller first page (list cap raised to 25; code-scanning page
  size raised to 100) for representative tool mix.
- ⏳ Probe a **deliberately under-configured repo** to capture the disabled/404
  enabled-probe cases above.
- ✅ Scorecard aggregate score source resolved: external API where covered,
  code-scanning Scorecard findings otherwise.
- ⏳ Decide zizmor scope (fifth v1 table vs deferred).
