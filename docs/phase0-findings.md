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

### 4. The CodeQL enabled-probe is `analyses` presence, not `default-setup`

Probing simple shell action repos exposed that **`default-setup=not-configured`
does not mean "no code scanning"**. `github-security-report-action`,
`maven-stage-prep-action` and `openstack-cron-action` all report
`default-setup=not-configured` (CodeQL default setup off) yet still carry
code-scanning alerts — entirely from Scorecard and zizmor SARIF uploads.
`openstack-cron-action` has 24 code-scanning alerts (11 Scorecard, 13 zizmor)
and **zero** CodeQL.

A dedicated probe — `/code-scanning/analyses?tool_name=CodeQL` — disambiguates
cleanly: the not-configured repos return `present=False` (CodeQL genuinely off
→ nag), while `default-setup=configured` repos return `present=True` (enabled).
CodeQL can also run via *advanced* setup with default-setup still
not-configured, so analyses presence is the **authoritative** signal.

**Decision impact:**

- CodeQL enabled-probe = **presence of CodeQL analyses**, not `default-setup`.
- The CodeQL table counts only alerts with `tool.name == "CodeQL"`. Example:
  `dependamerge` has 4 code-scanning alerts but **0 CodeQL** (all Scorecard),
  so it is CodeQL-clean — using the raw code-scanning count would wrongly brand
  it a CodeQL offender. The same per-tool filtering applies to the Scorecard
  and zizmor tables.

## Negative cases — captured via the fork org

The fork org `modeseven-lfreleng-actions` (forks default to security features
**off**) supplied every negative case that `lfreleng-actions` could not, and
added a new signal:

- **Secret scanning disabled** → `/secret-scanning/alerts` returns **`404`**
  (vs `200 []` when enabled-clean). Confirmed across all sampled forks.
- **Dependabot disabled** → GraphQL `hasVulnerabilityAlertsEnabled == false`.
  Confirmed across all sampled forks.
- **Code scanning entirely disabled** → **both** `/code-scanning/alerts` *and*
  `/code-scanning/analyses` return **`404`** (not `200 []`). So a `404` here is
  the authoritative "code scanning off" signal; `200 []` means enabled-clean.
- **CodeQL via advanced setup** → the `dependamerge` fork reports
  `default-setup=not-configured` **yet** `analyses present=True` (CodeQL runs
  from a workflow). This is the decisive proof that `default-setup` is the
  wrong probe and **analyses presence** is authoritative.

The `dependamerge` fork is ideal **mixed-state** fixture material: CodeQL and
Scorecard enabled (score 6.1, advanced setup) while secret scanning (`404`) and
Dependabot (`false`) are disabled — every per-signal state in one repo,
confirming the four-state model is genuinely per-report-type, not global.

**Status-code semantics for the four-state model** (with an owning PAT):
`404` = feature disabled → **nag**; `403` = insufficient permission / GHAS
unlicensed → **unknown** bucket; `200` with data → offender; `200` empty →
clean.

Note: org-bulk endpoints still returned data on the fork org (code-scanning 84,
Dependabot 23) — other repos there have features enabled — so org-bulk is not a
proxy for per-repo enablement; the per-signal enabled-probe is still required.

## Spike refinements made / still to make

- ✅ Partition and report code-scanning counts by `tool.name` + severity in the
  matrix (done; surfaced zizmor).
- ✅ Capture a fuller first page (list cap raised to 25; code-scanning page
  size raised to 100) for representative tool mix.
- ✅ Secret scanning `404` / Dependabot `false` negative cases captured via the
  `modeseven-lfreleng-actions` fork org; code scanning disabled → `404` on
  both alerts and analyses. All four-state status semantics now confirmed.
- ✅ Scorecard aggregate score source resolved: external API where covered,
  code-scanning Scorecard findings otherwise.
- ✅ zizmor promoted to a fifth v1 table (decided).
- ✅ CodeQL enabled-probe resolved: CodeQL analyses presence, with per-tool
  alert filtering.
