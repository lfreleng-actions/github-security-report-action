<!--
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
-->

# ADR-0001: Architecture and scope of the GitHub Security Report Action

- **Status:** Accepted
- **Date:** 2026-06-16
- **Supersedes:** —
- **Superseded by:** —
- **Related:** [`docs/BRIEF.md`](../BRIEF.md) (full design brief and decision log)

## Context

The `lfreleng-actions` organisation needs a way to see, in one place, the
security and code-quality posture of every repository so that remediation
effort can be directed at the worst offenders. The existing tools each solve
part of the problem:

- `project-reporting-tool` runs on a schedule, publishes to GitHub Pages, and
  pings Slack on failure.
- the `.github` special repo scans the org and posts a code-fenced Slack list.
- `dependamerge` is the canonical Python CLI with the current PyPI CI/release
  workflows.

None aggregate per-repository security signals (CodeQL, Dependabot, secret
scanning, OpenSSF Scorecard) across the org for triage. The signals live behind
heterogeneous APIs with different access models and maturity, and one of them
(GitHub Code Quality) has no public API yet. A design that commits to column
shapes, a config schema, and "enabled vs clean" semantics before validating the
real APIs against our estate would be built on guesses.

This decision was reached through a structured grilling session; the full
reasoning, alternatives, and a 23-item decision log are in
[`docs/BRIEF.md`](../BRIEF.md).

## Decision

We will build a **reporting (not scanning)** GitHub Action plus Python CLI
(`github-security-report`, published to PyPI, run via `uvx`) with the following
load-bearing architecture:

1. **Phase 0 capability spike gates the design.** Before finalising schema and
   columns, a throwaway spike hits the real `lfreleng-actions` estate and emits
   a capability matrix (availability, transport, scope, status codes) per
   signal. Its scrubbed captures become the golden test fixtures.
2. **Hybrid REST + GraphQL transport.** GraphQL-only is not viable; secret
   scanning and code scanning are REST. Prefer **org-bulk endpoints first**,
   per-repo fallback, with bounded async concurrency and a single shared
   retry/backoff policy (exponential backoff, capped retries and a cumulative
   wait ceiling) honouring `Retry-After`/secondary limits. A GitHub transport
   failure that outlives the budget **hard-fails the run** (network error)
   rather than degrading; only the third-party Scorecard endpoint degrades on
   transport failure.
3. **v1 scope = five ranked tables** (CodeQL, OpenSSF Scorecard, zizmor,
   Dependabot, secret scanning) plus a boolean posture/coverage section. The
   single code-scanning sweep multiplexes CodeQL, Scorecard and zizmor, so it is
   **partitioned by `tool.name`** and counts are filtered per tool. Every
   section is **best-effort and independently degradable** and never fails the
   whole run. **GitHub Code Quality is deferred** until a mature public API
   exists.
4. **Four-state model per report type per repo:** offenders (table row) /
   clean (counted) / not-enabled (nag list) / unknown-permission (footnote).
   Each signal declares an explicit enabled-probe — e.g. CodeQL enablement is
   determined by the presence of CodeQL **analyses**, not `default-setup`.
5. **Metrics are per-report-type**, severity-weighted where available (else flat
   count), with separate severity columns and worst-first hierarchical sorting
   (critical → high → medium → low; Scorecard sorts by score ascending).
6. **Two operating modes** via `scope: auto|org|repo`. Org mode requires a
   classic PAT (the ephemeral `GITHUB_TOKEN` cannot read org-wide security
   data) and produces Pages + Slack. Repo mode is a degraded, self-contained PR
   gate using `GITHUB_TOKEN` for the current repo only — job summary + outputs
   - a fail-threshold, no Pages/Slack.
7. **Four presentation surfaces** from one canonical dataset: GitHub Pages
   (full results, Simple-DataTables, Jinja2 card index — canonical), Slack
   (code-fenced top-N + Pages link, gated to `report_day`), job summary (repo
   mode), and Rich terminal (local).
8. **Configuration** is JSON (CLI file, plain `vars.`, or base64 in `secrets.`),
   global defaults + per-org overrides, `jsonschema`-validated, with tokens
   referenced by env-var name and an optional per-org exclude list (defaults to
   empty).
9. **Scheduling**: a single daily 09:00 UTC workflow refreshes Pages every day;
   Slack is gated to `report_day` (default Tuesday) via a tool-owned
   `should_notify` output.
10. **CI/release** adopts `dependamerge`'s `build-test.yaml` /
    `build-test-release.yaml` + `lfreleng-actions/python-*` composite actions
    verbatim; the action auto-runs from local checkout on PRs and from the
    pinned PyPI release otherwise.

## Consequences

**Positive**

- Design risk is front-loaded into a cheap, throwaway spike rather than baked
  into schema and rendering code.
- Best-effort per-section degradation means partial API/permission coverage
  still yields a useful report.
- The repo mode makes the action useful to external single-repo consumers, not
  just our org.
- Reusing sibling patterns (Pages publish, Slack delivery, Python CI) minimises
  novel surface area.

**Negative / costs**

- Hybrid transport plus four-state probes are more complex than a single
  GraphQL sweep.
- Org mode depends on a classic PAT secret with broad scopes
  (`security_events`, `repo`, `read:org`) — a credential to manage and rotate.
- Code Quality coverage is intentionally absent in v1.
- Several specifics (org-bulk availability, exact enabled-probe status codes,
  Scorecard source) remain **open until Phase 0** completes.

**Follow-up**

- Execute Phase 0 and record results (capability matrix + golden fixtures).
  *(Complete — see [`../phase0-findings.md`](../phase0-findings.md). Confirmed
  org-bulk-first, the three-tool code-scanning split with zizmor as a fifth
  table, the Scorecard dual source, the CodeQL analyses enabled-probe, and —
  via the `modeseven-lfreleng-actions` fork org — all four-state status
  semantics (404 = disabled, 403 = unknown).)*
- Revisit Code Quality when/if a public API ships (would be a new ADR).
- Pin the Simple-DataTables CDN asset + add SRI rather than `@latest`.
