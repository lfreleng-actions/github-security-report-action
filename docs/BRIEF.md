<!--
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
-->

# Design Brief: GitHub Security Report Action

> Status: **Pre-implementation design brief.** Captures the outcome of a
> structured Q&A (grilling) session. This document is the authoritative source
> of intent until superseded by a `CONTEXT.md` + ADRs. It records *what* and
> *why*; implementation details (the *how*) follow during build.

## 1. Purpose and framing

A **reporting** (not scanning) GitHub Action and Python CLI that aggregates
existing security and code-quality signals across one or more GitHub
organisations and presents them for **remediation triage** — surfacing the
worst offenders so resources can be directed where they are most needed.

- Implemented as a **Python CLI** (Typer) with a **thin `action.yaml`** that
  maps inputs to CLI flags/args.
- Published to **PyPI**; executed via **`uvx`**; a **uv project** with a
  committed `uv.lock`.
- Borrows mechanisms from sibling repos:
  - `project-reporting-tool` — scheduled run, GitHub Pages publishing,
    Simple-DataTables HTML, Slack delivery via third-party action,
    base64 config-in-secret pattern, `concurrency/` async shape, `syrupy`
    snapshot tests.
  - `.github` — single-org `gh api` scan + code-fenced Slack block message,
    per-org `excluded-repos.json` exclusion pattern.
  - `dependamerge` — **canonical** Python CI/release workflows
    (`build-test.yaml`, `build-test-release.yaml`) built from
    `lfreleng-actions/python-*` composite actions, `hatch-vcs` versioning.

## 2. Naming (locked)

| Identifier | Value |
|---|---|
| Repository / action | `github-security-report-action` |
| PyPI distribution | `github-security-report` (verified available on PyPI) |
| CLI command | `github-security-report` |

## 3. Phase 0 — capability spike (gates all design)

The design is **gated** behind a throwaway API spike, because the target
signals live behind very different APIs with different access models and
maturity. Phase 0 must, before schema/column design is finalised:

- Hit the real `lfreleng-actions` estate and produce a **capability matrix**
  per signal: available? / which API (REST vs GraphQL vs external) / which
  token scope / sample response shape / org-bulk vs per-repo / observed HTTP
  status codes for enabled-clean vs disabled vs insufficient-permission.
- Confirm which **org-bulk** endpoints actually return data for our token tier.
- Capture **scrubbed** real response shapes — these become the **golden test
  fixtures** (no sensitive data; no live API in CI).

Transport is therefore **hybrid REST + GraphQL** (GraphQL-only is not viable —
secret scanning and code scanning are REST).

## 4. Report scope (v1)

**Five ranked tables**, each using the four-state model (§6), plus a boolean
**posture/coverage** section feeding nag lists:

| Signal | Transport | Metric |
|---|---|---|
| Code scanning alerts (CodeQL) | REST (org-bulk preferred), filtered `tool.name == "CodeQL"` | severity counts |
| OpenSSF Scorecard | external API score (where covered) + code-scanning `tool.name == "Scorecard"` | score (inverted) / finding severity |
| zizmor (GHA workflow linter) | code-scanning `tool.name == "zizmor"` | severity counts (`severity` error/warning) |
| Dependabot alerts | GraphQL + REST org-bulk | severity counts |
| Secret scanning alerts | REST (org-bulk preferred) | open count |

> **Phase 0 findings:** the single code-scanning sweep multiplexes **three**
> tools (`CodeQL`, `Scorecard`, `zizmor`) and must be **partitioned by
> `tool.name`** — each feeds its own table, and per-tool filtering of counts is
> mandatory (e.g. a repo with code-scanning alerts that are all Scorecard is
> CodeQL-clean). zizmor was the largest contributor in our estate and is now a
> first-class v1 table. Scorecard prefers the external `securityscorecards.dev`
> aggregate score where the repo is covered and falls back to code-scanning
> Scorecard findings otherwise. See [`docs/phase0-findings.md`](phase0-findings.md).

Posture booleans (no ranking, feed coverage/nag): Security policy, Private
vulnerability reporting, Security advisories, etc.

**Resilience:** every section is **best-effort and independently degradable** —
an unavailable individual signal renders "no data available" and **never fails
the whole run**. The one exception is a **transport failure to the GitHub API
itself** (DNS/connect/TLS/read timeout that outlives the shared retry budget):
the run **hard-fails** with a network error, because a report built without any
live GitHub data would read as falsely reassuring. A transport failure to the
third-party Scorecard endpoint still degrades that one signal only.

### Deferred

- **GitHub Code Quality (preview)** — Maintainability / Reliability / AI
  Suggestions. **No documented public API** at time of writing. Requirement is
  captured here and deferred until a mature API surfaces. When available, report
  the three categories as separate columns/sub-reports. Language support
  (C#, Go, Java, JavaScript, Python, Ruby, TypeScript) would later be detected
  from repository metadata to decide whether a repo *should* have it enabled.

### Extra reporting categories (configuration posture & freshness)

Beyond the five ranked signals, two further categories report **configuration
posture** and **freshness**. They sit outside the four-state model and render as
plain tables (no offender/clean/nag/unknown classification).

**Dependabot** (sub-tables nested beneath the "Dependabot: Security Alerts"
signal heading):

- **Dependabot: Alerts Enabled** (enablement) — repositories where Dependabot
  vulnerability alerts are *not* switched on (the GraphQL
  `hasVulnerabilityAlertsEnabled` read). This replaces the Dependabot signal's
  nag list so the same repositories are not listed twice. Its title is
  deliberately distinct from the **Dependabot: Security Alerts** signal heading
  (open alerts) above it.
- **Dependabot: Security Updates** — a single **Repository** column listing
  repositories where Dependabot security updates
  (`GET /repos/{o}/{r}/automated-security-fixes`) are *not* switched on.
- **Dependabot: Cooldown Settings** — repositories/ecosystems whose
  `.github/dependabot.yml` declares an `updates` entry with **no `cooldown`**. A
  cooldown is a mandatory requirement; **any** cooldown value passes.
  Repositories with no Dependabot configuration are not listed.

Alerts and security updates are deliberately two separate single-feature tables
rather than one matrix — they are the only two features with a public
per-repository API. **Dependabot malware alerts** and **Grouped security
updates** are intentionally omitted; GitHub exposes no public per-repository API
for them at time of writing.

**Releases / Tagging** (top-level section): repositories that have gone too long
without a release or tag. Releases (`GET /repos/{o}/{r}/releases/latest`) and
tags (GraphQL `refs(refPrefix: "refs/tags/", orderBy: TAG_COMMIT_DATE)`) are
reported in **two separate columns** as a human "last release / last tag" age.

- **Age hold:** repositories created within `report.repo_min_age_days` days
  (default **28**, CLI `--repo-min-age-days`) are excluded; **0** disables
  the hold so every repository is included. (`release_min_age_days` /
  `--release-min-age-days` are deprecated aliases of this control.)
- **Release-staleness threshold:** `report.release_max_age_days` (default
  **60**, CLI `--release-max-age-days`) flags a repository only when its newest
  release **or** tag is older than that many days; a repository with neither is
  always flagged. **0** disables the threshold, so every eligible repository is
  listed.
- **On-demand exclusions:** `releases_exclude` (per org; CLI `--releases-exclude`,
  repeatable) drops repositories that are never released / not consumed
  externally.
- **Hidden sort key (never displayed):** rows rank by release/tag staleness
  alone; repository age only gates scope and never affects ordering. A
  **missing** release or tag is treated as the worst possible signal, so a
  repository missing one sorts above any fully-dated repository, and a
  repository with **neither** a release nor a tag ranks highest of all.
  Repositories with the same number of missing signals are then ordered by
  their combined known staleness (oldest first), and ties break on repository
  name. The two columns show the individual staleness; the sort key is used
  only for ordering and is deliberately not rendered. Release and tag data are
  gathered for every in-scope repository through the batched GraphQL prefetch;
  the repository-age grace period and `releases_exclude` are then applied when
  the Releases/Tagging table is built, rather than skipping per-repository
  probes up front.

## 5. Metrics, ranking and columns

- **Per-report-type metric definitions** — no single universal "issue count".
  Each report declares `(value, sort_direction)`.
- **Severity-weighted where available; fall back to flat count** otherwise.
- **Severity scale (lowest to highest):** informational → low → medium → high →
  critical. `informational` is the sub-low rung that SARIF `note`/`none`
  findings (the bulk of a tool like zizmor) normalise to, so a category can
  treat them as non-actionable.
- **Pass/fail cutoff (`fail_severity`):** each severity-ranked signal carries a
  cutoff in its category metadata. A repository is an offender only when it has
  a finding **at or above** the cutoff; sub-threshold findings fold into the
  clean count. The global default is **medium** (low and informational pass);
  **zizmor** lowers it to **low** (only informational passes). The cutoff is
  overridable per category via `report.categories.<key>.fail_severity`.
- When severity data exists, show **separate columns** (critical / high /
  medium / low). The sub-low **informational** column is shown **only when the
  displayed offenders actually carry informational (SARIF `note`) findings** —
  e.g. zizmor — so severity tables without such data (CodeQL, most Dependabot
  alerts) are not padded with an all-zero column. When shown, its counts feed
  the trailing `Total` column, so the visible severity columns sum vertically.
- **Row sort:** hierarchical, worst-first — critical desc → high desc →
  medium desc → low desc. Scorecard sorts by score **ascending** (lowest =
  worst = top).

## 6. Four-state model (per report type, per repo)

Each in-scope repo falls into exactly one bucket **per report type** (not
global):

1. **Enabled + has a finding at/above the cutoff** → table row (sorted
   worst-first). The `fail_severity` cutoff (§5) decides "actionable": a repo
   whose findings are all below the cutoff is treated as clean, not an offender.
2. **Enabled + zero failing findings** → omitted from table; counted in the
   standardised summary footer beneath the table (the "✅ N <pass>" /
   "✅ All <pass>" line).
3. **Supported but NOT enabled** → counted as a **disabled** footer line with a
   named repository breakdown (excludes archived/test repos).
4. **Unknown / insufficient permission** (indeterminate probe: missing scope,
   GHAS not licensed, ambiguous 403/404) → **unknown** footer line; never merged
   into clean or disabled.

**Standardised summary footer.** Every category — the five ranked signals and
every posture/freshness table — renders the same metadata-driven footer beneath
its table, built once in `report.build_summary()` and reused by all surfaces
(terminal, Slack, Markdown, HTML). Lines are ordered remediation-first
(failures, disabled, unknown, then the healthy pass line, then excluded). The
pass line collapses to **"All <pass_label>"** (no number) only when nothing else
needs attention; otherwise every present bucket shows its count. Each category's
pass/fail vocabulary, documentation URL and explanatory description live in the
`categories` registry (`CategoryMeta`). The description is shown only on the rich
surfaces (Markdown and HTML); the terminal and Slack stay brevity-first.

**Enabled-probe contract** (each signal declares its own probe; Phase 0 locks
exact rules):

- CodeQL → **presence of `code-scanning/analyses?tool_name=CodeQL`** (the
  authoritative probe). `default-setup` is **insufficient**: Phase 0 found
  `not-configured` repos that still carry code-scanning alerts from other
  tools, and the `dependamerge` fork runs CodeQL via advanced setup with
  `default-setup` off. Code scanning **entirely disabled** → `404` on both
  `/alerts` and `/analyses` (vs `200 []` = enabled-clean).
- Scorecard / zizmor → presence of their respective `tool.name` analyses /
  workflow. Counts for every code-scanning-derived table are **filtered by
  `tool.name`** — a repo whose code-scanning alerts are all Scorecard is
  CodeQL-clean.
- **Workflow-driven tools enforced by an org ruleset** (e.g. zizmor) are also
  enabled via that ruleset, not only a per-repo file. A repo is enabled when an
  **active** org ruleset has a `workflows` rule whose required-workflow path
  matches the tool (keyword, configurable via `report.ruleset_workflows`,
  default `{"zizmor": "zizmor"}`) **and** the repo matches the ruleset's
  `repository_name` targeting. Org mode reads `GET /orgs/{org}/rulesets`; repo
  mode reads the repo's effective `GET .../rules/branches/{branch}`. If the
  token cannot read rulesets (403), coverage degrades to per-repo evidence.
  This prevents falsely nagging the many repos whose zizmor scan runs from the
  central `.github/workflows/zizmor.yaml` ruleset.
- Secret scanning → **404 on alerts = disabled** (confirmed on the fork org)
  vs `[]` = enabled-clean.
- Dependabot → `hasVulnerabilityAlertsEnabled` (`false` = disabled, confirmed
  on the fork org) / 403 = insufficient permission.

**Status-code mapping** (owning PAT): `404` = disabled → nag; `403` =
insufficient permission / GHAS unlicensed → unknown bucket; `200`+data =
offender; `200`+empty = clean.

## 7. Repository scope and exclusions

Default in-scope: **non-archived, non-fork, non-template, sources only**,
public and private (visibility follows the token; external consumers
considered even though our own org has few/no private repos). Empty/disabled
repos auto-skipped.

- **Per-org `exclude` list** — optional (mirrors `.github/excluded-repos.json`);
  omitted in the minimal config and defaults to empty. Excluded repositories are
  removed from analysis but **surfaced as "excluded"** (counted and listed once
  per org, on every render surface), so an explicit exclusion is visible and
  clearly distinct from a "not enabled" nag rather than silently dropped.
- **Archived** — fully excluded by default; opt back in via config option +
  CLI flag.
- **Test repos** — excluded by default; opt back in via `--include-test`.
  Matched as a **delimited token** (`test`/`tests` as a segment after splitting
  on `-`, `_`, `.`, `/`) — **not** a raw substring (so `latest`, `attestation`,
  `contest` are NOT excluded).
- **Archived and test repos never appear in nag lists / notifications.**
- **All exclusions are logged with their reason** (INFO) — never silent.

## 8. Configuration

Sourced from a CLI-supplied JSON file **or** a GitHub secret/variable.

- **Variable vs secret applies only to the config JSON**, not the credential:
  plain `vars.` entry when the JSON holds no secrets (single org); **base64**
  in a `secrets.` entry when wrapping is wanted. Base64 is used because raw
  JSON braces trip GitHub's log-redaction and mangle tool output (encoding,
  not encryption).
- **Token is referenced by env-var name** (`token_env`), resolved at runtime.
  Literal tokens are permitted but **discouraged (warn)**.
- **Structure:** global defaults + per-org overrides.
- **Validated** against a `jsonschema`.
- `report_day` accepts: a single weekday (default `tuesday`), a list of days,
  `"never"`, or `"always"`.

Sketch:

```json
{
  "slack": { "channel": "releng-scm", "report_day": "tuesday" },
  "report": {
    "top_n": 10,
    "include_archived": false,
    "include_test": false,
    "repo_min_age_days": 28,
    "release_max_age_days": 60
  },
  "organizations": [
    {
      "name": "lfreleng-actions",
      "token_env": "SECURITY_REPORT_PAT",
      "exclude": ["actions-template"],
      "releases_exclude": ["internal-only-repo"]
    }
  ]
}
```

- `report.repo_min_age_days` (default `28`, `0` = include all) is the
  repository-age grace period and `report.release_max_age_days` (default `60`;
  `0` = flag every eligible repo) is the release-staleness threshold; together
  with the per-org `releases_exclude` they control the Releases / Tagging section
  (§4). All three can be overridden at the CLI with `--repo-min-age-days`,
  `--release-max-age-days`, and the repeatable `--releases-exclude`. The former
  `release_min_age_days` key (and `--release-min-age-days` flag) is a deprecated
  alias of `repo_min_age_days`, retained for backward compatibility.
- **Config source precedence (CLI):** `--config` file > `--config-data`
  (raw/base64) > `--org` shorthand > a per-user config file at
  `$XDG_CONFIG_HOME/github-security-report/config.json` (falling back to
  `~/.config/...`). The per-user file makes a flagless local run resolve to org
  mode instead of erroring; the action never reads it (configuration is passed
  explicitly). Secrets stay out of the file — the token is referenced by
  `token_env`, and the Slack bot token is a workflow-only secret.
- **Per-category render toggles:** `report.categories.<key>` switches a category
  on or off without affecting data collection (collection is always
  exhaustive). Each key carries a global `enabled` switch (highest precedence)
  and a lower-precedence `outputs` map for the four surfaces (`cli`, `slack`,
  `markdown`, `html`); a category renders on a surface only when `enabled` **and**
  that surface's toggle are both true. Everything defaults to true. The keys are
  the `categories` registry keys (§6); they merge per-org like the rest of the
  `report` block. The `report.json` artifact is always complete regardless.

## 9. Credentials and operating modes

- **Org-wide security data requires a PAT.** The ephemeral `GITHUB_TOKEN` is
  **repo-scoped** and is 403/404'd on org-level security endpoints. A
  **fine-grained** PAT (read-only: metadata, contents, dependabot/code/secret
  scanning alerts, repo + org administration) covers a **single** organisation;
  a **classic** PAT (`security_events`, `repo`, `read:org`) is needed to span
  **multiple** orgs (fine-grained tokens are bound to one owner). See the README
  "Token permissions" section. The token is **always a PAT secret** referenced
  by `token_env` for org mode.
- **`scope` input: `auto | org | repo`.**
  - **Org mode** — PAT + config; org-bulk endpoints; multi-org; Pages + Slack.
  - **Repo mode** — degraded, self-contained: uses the ephemeral
    `GITHUB_TOKEN` for the **current repo's own** data only (`security-events:
    read`). A drop-in others add to a single repo. **No HTML/Pages, no Slack.**
    Output = tidy `$GITHUB_STEP_SUMMARY` + action **outputs** (per-signal
    counts) + a configurable **fail-threshold** input (e.g. fail on any open
    critical) so it works as a **PR gate**.
  - **`auto`** resolves to `repo` when no PAT/config is supplied, `org` when
    they are. The resolved mode is **logged loudly** and surfaced in the
    summary — never silent.
- **Mode precedence:** explicit `--scope` flag > PAT/config presence >
  git-remote auto-detect > clear error.

## 10. Local CLI / developer experience

- `GITHUB_TOKEN` sourced from the **shell environment** for local runs.
- When CWD is a Git repo, detect the GitHub repo from remotes —
  **`upstream` preferred, `origin` fallback** — and default to **repo mode**
  for that repo. Handle both `git@github.com:org/repo.git` and
  `https://github.com/org/repo(.git)` forms; strip `.git`; ignore
  non-`github.com` remotes (graceful fallback / clear error if none qualify).
- **Rich** terminal rendering (tables, severity colour) is the **default on a
  TTY**; in CI / non-TTY / `--no-color` / `CI=true`, fall back to plain output.
- Local **org** runs (export an org PAT + `--scope org`) render the same ranked
  tables in the terminal via Rich (no Pages/Slack needed locally).

## 11. Output targets

Four presentation surfaces from one canonical dataset:

1. **GitHub Pages (canonical, org mode)** — full results, every category, no
   top-N truncation. `gh-pages/<org-slug>/report.{html,md,json}` +
   `metadata.json`; generated root `index.html` card-grid landing page
   (reuse `project-reporting-tool`'s gradient style/CSS), one card per org.
   Per-org `report.html` is a **single scrollable page** with all sections.
   Index generation is **owned by the Python tool** (Jinja2), not a bash
   script. The main `README.md` carries a prominent Pages link near the top.
   HTML tables use **Simple-DataTables** (sortable + searchable + pagination),
   reusing `project-reporting-tool`'s macro approach. *(Refinement: pin the CDN
   version + add SRI instead of `@latest` — security tool should not load an
   unpinned CDN asset.)*
2. **Slack (org mode, gated)** — delivered via the same third-party action
   (`slackapi/slack-github-action`) to `vars.SLACK_CHANNEL_ID` (channel
   `releng-scm`). Slack **cannot render Markdown tables**, so the message is a
   **code-fenced (monospace) top-N (10) block** per report type **plus a
   prominent link** to the GitHub Pages report. Top-N (10) applies **only to
   Slack**.
3. **Job summary (repo mode)** — tidy `$GITHUB_STEP_SUMMARY` + action outputs.
4. **Rich terminal (local)** — see §10.

## 12. Scheduling and Slack gating

- Single `reporting.yaml`: `cron: '0 9 * * *'` (**daily 09:00 UTC**) +
  `workflow_dispatch` with a `force_notify` boolean for off-schedule Slack
  testing.
- **Pages refreshed daily** (remediation progress visible day-to-day).
- **Slack gated to `report_day`** (default Tuesday). The **tool** owns the
  day logic: it parses `report_day` and emits a `should_notify` output; the
  workflow's Slack step is a dumb `if: should_notify == 'true'` gate (logic
  lives in one tested place, not duplicated in YAML).

## 13. Bulk-query strategy, rate limits, concurrency

- **Org-bulk-first, per-repo fallback.** Prefer `GET /orgs/{org}/...` bulk
  alert endpoints (one paginated sweep per signal per org, `repository`
  attached); per-repo calls only when bulk is unavailable.
- **GraphQL batching** (aliased multi-repo, paginated) for repo metadata +
  Dependabot.
- **`httpx` with bounded async concurrency** (configurable, conservative
  default ~4–8) + **exponential backoff honoring `Retry-After` and secondary
  rate-limit** signals; respect `x-ratelimit-remaining`; surface budget in
  logs. Borrow `project-reporting-tool`'s `concurrency/` shape.

## 14. Distribution, CI and release

- **CI/release baseline adopted from `dependamerge` verbatim:**
  `build-test.yaml` (PR: `python-build-action` → `python-test-action` matrix →
  `python-audit-action` → SBOM → grype, all behind `harden-runner-block-action`,
  SHA-pinned) and `build-test-release.yaml` (tag → PyPI trusted publishing).
  `hatch-vcs` dynamic version; `uv.lock` committed.
- **Action runtime hybrid:** `action.yaml` **auto-detects** run source —
  `local` when `github.event_name == 'pull_request'` **or** `use_local_source
  == true` (`uvx --from "${GITHUB_ACTION_PATH}"` so PRs and manual test runs
  exercise unreleased code), otherwise `pypi`
  (`uvx --from github-security-report==<version> github-security-report ...`).
  For the `pypi` path an explicit `tool_version` input wins; when it is empty
  (the default) the version is read from the Dependabot-managed pin in
  `.github/runtime-pin/requirements.txt`, so bumps arrive as cooldown-gated
  PRs instead of a hand-edited default that silently drifts each release.
  Harden-runner egress must allow `pypi.org` / `files.pythonhosted.org` for the
  `pypi` path and the GitHub API for both.

## 15. Dependabot

`.github/dependabot.yml`, three ecosystems (`github-actions`, `uv`, and a
`pip` entry scoped to `.github/runtime-pin/` that manages the published tool
version the action installs at runtime):

- weekly interval, **7-day cooldown**, **15** open-PR limit; `CI(actions)`
  commit prefix for the `github-actions` ecosystem and `CI(deps)` for the
  `uv` and `pip` ecosystems.

## 16. Testing strategy

- **No live API in CI.** Unit tests over pure functions (severity ranking,
  four-state classification, sort order, Markdown/Slack/HTML/Rich rendering,
  config schema validation, exclusion logic) fed by **scrubbed Phase 0 fixture
  JSON**.
- **Transport tests** via `respx` (httpx mock) / recorded cassettes for
  pagination, backoff, 404-as-disabled behaviour.
- **`syrupy` snapshots** for rendered Markdown/HTML (as in
  `project-reporting-tool`).
- Phase 0 scrubbed captures **are** the golden fixture corpus.

## 17. Open items for Phase 0 to resolve

First spike run recorded in [`docs/phase0-findings.md`](phase0-findings.md).

- ✅ Org-bulk endpoints available for our PAT tier (all `200`); org-bulk-first
  validated.
- ✅ Scorecard data source resolved: external `securityscorecards.dev`
  aggregate score where the repo is covered (4/5 demanding repos), falling back
  to code-scanning Scorecard findings; nag where neither exists.
- ✅ Code scanning multiplexes `CodeQL` + `Scorecard` + `zizmor`; partition by
  `tool.name` confirmed mandatory; **zizmor promoted to a fifth v1 table**.
- ✅ Severity ranking keys confirmed (`security_severity_level` primary,
  `severity` fallback exercised by zizmor).
- ✅ CodeQL enabled-probe resolved: **CodeQL analyses presence** (not
  `default-setup`), with per-tool alert filtering. Fork org confirmed CodeQL
  via advanced setup (`default-setup=not-configured` + analyses present).
- ✅ All four-state status semantics confirmed via the
  `modeseven-lfreleng-actions` fork org: secret scanning `404` = disabled,
  Dependabot `false` = disabled, code scanning disabled → `404` on alerts +
  analyses. `403` reserved for the unknown/insufficient-permission bucket.
- ⏳ Confirm Code Quality remains API-less (keep deferred).

## 18. Decision log (this session)

1. Phase 0 capability spike gates the design; transport is hybrid REST+GraphQL.
2. Code Quality deferred (no public API) — captured, not built.
3. Per-report metric definitions; severity-weighted where available, else count.
4. Separate severity columns; rows sorted critical→high→medium→low desc.
5. Scope = non-archived/non-fork/non-template/sources; public+private.
6. Optional per-org exclude list (defaults to empty); archived opt-in; test opt-in.
7. `test` matched as delimited token, not substring; exclusions logged.
8. Config: token by env-var name; global+per-org; jsonschema; flexible
   `report_day`.
9. Slack = code-fenced top-N + Pages link; tool owns `should_notify` gating.
10. Top-N (10) is Slack-only; Pages shows full results.
11. Four-state model (offenders / clean count / nag / unknown).
12. Pages = `gh-pages/<org>/...` + Jinja2 card index; single scrollable page;
    Simple-DataTables.
13. Action runtime: auto `local` on PR, else pinned PyPI via `uvx`.
14. Adopt `dependamerge` CI/release verbatim.
15. v1 = 5 ranked tables (CodeQL, Scorecard, zizmor, Dependabot, secret
    scanning) + boolean posture; best-effort degradation.
16. Daily 09:00 UTC cron; Pages daily; Slack on `report_day`; `force_notify`.
17. Enabled-probe contract per signal; fourth unknown/insufficient bucket.
18. Org-bulk-first + per-repo fallback; bounded async + backoff; classic PAT.
19. Token always a PAT for org mode; default `GITHUB_TOKEN` insufficient.
20. `scope: auto|org|repo`; repo mode = summary + outputs + fail-threshold,
    no Pages/Slack.
21. PyPI + CLI name `github-security-report` (available).
22. Local: shell `GITHUB_TOKEN`; git-remote detect (`upstream`→`origin`);
    Rich terminal output, plain fallback in CI.
23. Tests: fixtures + `respx` + `syrupy`, no live API; Phase 0 captures =
    golden fixtures.
