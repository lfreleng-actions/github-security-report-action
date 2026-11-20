<!--
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
-->

# Organisation scan setup

How to prepare a GitHub organisation so every workflow-driven signal in the
security report produces data. The report aggregates **existing** telemetry;
it never scans code itself. Four of its signals therefore depend on
workflows your organisation must deploy first:

| Signal | Tool | Deployment model |
| ------ | ---- | ---------------- |
| Zizmor Static Analysis | [zizmor](https://github.com/zizmorcore/zizmor) | Central: daily org-wide scan + PR ruleset |
| AI Slop Analysis | [aislop](https://github.com/scanaislop/aislop) | Central: daily org-wide scan + PR ruleset |
| Fuzzing | `fuzz` (each repository's own harnesses) | Central: daily org-wide fuzz run; harnesses per repository |
| OpenSSF Scorecard | [scorecard](https://github.com/ossf/scorecard) | **Per-repository** reusable workflow |

The remaining signals (CodeQL, Dependabot, secret scanning) are GitHub-native
features enabled per repository through GitHub's own settings and need no
extra workflows.

## How the report detects organisation support (feature gating)

Before gathering telemetry for a workflow-driven signal, the tool performs a
cheap, layered support check:

1. **Alert evidence** — the org-wide code-scanning sweep (already fetched)
   contains at least one alert from the tool.
2. **Ruleset evidence** — an active organisation repository ruleset requires
   a workflow whose path matches the signal's keyword (see
   `report.ruleset_workflows`; defaults: `zizmor`, `aislop`).
3. **Sampled analyses** — the code-scanning analyses of a small sample of
   repositories are probed for the tool. For Scorecard, the external
   [scorecard.dev](https://scorecard.dev/) API is also sampled, since
   publish-enabled workflows surface scores there.

When no evidence is found at any layer, the signal is **skipped** for that
organisation: its report section shows a single line —
`⏩ Skipping feature: organisation support missing` — linking back to this
guide, instead of nagging every repository about a tool the organisation has
never deployed.

Notes and caveats:

- The check is evidence-based. A brand-new deployment can be skipped for one
  run until the first SARIF upload or ruleset becomes visible.
- To force collection regardless of evidence, set `report.gating: false` in
  the tool configuration (globally or per organisation):

  ```json
  {
    "report": { "gating": false },
    "organizations": [{ "name": "my-org" }]
  }
  ```

- To hide a signal you never intend to deploy, disable its category instead:
  `report.categories.<key>.enabled: false` (keys: `zizmor`, `aislop`,
  `fuzz`, `scorecard`).

## Zizmor and aislop: central org-wide scanning

Both scanners follow the same two-part pattern, and the
[`lfreleng-actions/.github`](https://github.com/lfreleng-actions/.github)
repository holds complete reference implementations:

| Part | Purpose | Reference workflow |
| ---- | ------- | ------------------ |
| Daily SARIF publisher | Full scan of every in-scope repo; uploads SARIF to each repo's code scanning | [`zizmor-sarif-publish.yaml`](https://github.com/lfreleng-actions/.github/blob/main/.github/workflows/zizmor-sarif-publish.yaml), [`aislop-sarif-publish.yaml`](https://github.com/lfreleng-actions/.github/blob/main/.github/workflows/aislop-sarif-publish.yaml) |
| PR gate (org ruleset) | Required workflow that scans changed files on every pull request | [`zizmor.yaml`](https://github.com/lfreleng-actions/.github/blob/main/.github/workflows/zizmor.yaml), [`aislop.yaml`](https://github.com/lfreleng-actions/.github/blob/main/.github/workflows/aislop.yaml) |

### 1. Daily org-wide scan with SARIF upload

Create a scheduled workflow (typically in your organisation's `.github`
repository) that enumerates in-scope repositories, runs a full scan against
each, and uploads the SARIF to that repository's code scanning. The upload is
what makes findings visible to this report (and to GitHub's Security tab).

Key requirements:

- A PAT with cross-repository code-scanning write access (classic scopes:
  `repo`, `read:org`, `security_events`), stored as an organisation or
  repository secret. The default `GITHUB_TOKEN` cannot upload SARIF to
  *other* repositories.
- A stable SARIF **category** per tool (`zizmor`, `aislop`). Code scanning
  keys analysis lineage by category; changing it strands old alerts open.
- For zizmor, run with `--min-severity low` so informational noise stays out
  of the uploaded SARIF.

A minimal single-repository example of the scan-and-upload step pair using
[`aislop-scan-action`](https://github.com/lfreleng-actions/aislop-scan-action):

```yaml
jobs:
  aislop:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write  # SARIF upload to code scanning
    steps:
      - name: 'Checkout repository'
        # yamllint disable-line rule:line-length
        uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0  # v7.0.0
        with:
          persist-credentials: false

      - name: 'AI slop scan'
        # yamllint disable-line rule:line-length
        uses: lfreleng-actions/aislop-scan-action@c22239a94af095c0f1c15a8ae7f3bd3eda711700  # v0.2.1
        with:
          scan-mode: 'full'
          upload-sarif: 'true'  # publishes under category "aislop"
```

The equivalent zizmor action is
[`lfreleng-actions/zizmor-scan-action`](https://github.com/lfreleng-actions/zizmor-scan-action)
(`lfreleng-actions/zizmor-scan-action@5fa3f036566614a35970aa50d984905df82333c9`
— v0.4.0). For scanning a whole organisation from one workflow, follow the
matrix-over-repositories pattern in the reference publishers above.

### 2. PR gate via an organisation repository ruleset

To block regressions at pull-request time, add the scan workflow to an
**organisation repository ruleset** (Organisation → Settings → Repository →
Rulesets):

1. Host the required workflow (for example `.github/workflows/aislop.yaml`)
   in a repository readable by all target repositories.
2. Create a ruleset targeting the default branch of the chosen repositories
   with a **Require workflows to pass** rule referencing that workflow.
3. Keep the tool keyword (`zizmor` / `aislop`) in the workflow *path* — the
   report matches ruleset coverage by that keyword, so covered repositories
   are treated as having the tool enabled even without a local workflow file,
   and the ruleset itself counts as organisation support for gating.

If your workflow paths use different names, map them in the configuration:

```json
{
  "report": {
    "ruleset_workflows": {
      "zizmor": "actions-security",
      "aislop": "quality-gate"
    }
  }
}
```

## Fuzzing: central fuzz run, per-repository harnesses

Fuzzing splits the work: each repository carries its own harness files,
while one scheduled job runs them all centrally. The reference workflow is
[`fuzz-sarif-publish.yaml`](https://github.com/lfreleng-actions/.github/blob/main/.github/workflows/fuzz-sarif-publish.yaml)
in `lfreleng-actions/.github`. Every day it runs the harnesses of each
in-scope repository and uploads the failures to that repository's code
scanning as SARIF under the tool name `fuzz`, on the default branch:

- one alert per distinct failure, at SARIF level `error`, with rule IDs
  `fuzz/uncaught-exception`, `fuzz/timeout`, `fuzz/out-of-memory` and
  `fuzz/harness-error`;
- an analysis with no results for a repository fuzzed and found clean;
- nothing at all for a repository with no harness.

The report lists a repository that holds a fuzzable language but has no
`fuzz` analysis as not enabled: the repositories still to cover. One holding
none of the languages in `report.fuzz_languages` (default `["Python", "Go"]`,
matched against GitHub Linguist names) counts as not applicable instead.
Drop a repository that is not worth a harness with
`report.categories.fuzz.exclude`. No ruleset requires a fuzz workflow, so
gating finds fuzz support from its alerts and sampled analyses only. See
[ADR-0009](adr/0009-fuzzing.md).

## OpenSSF Scorecard: per-repository reusable workflow

Scorecard **cannot** be deployed via a central org-wide scan or a ruleset.
The scorecard action runs under strict constraints — it must run in its own
dedicated job on the default branch of the repository under analysis, with
tightly controlled permissions and environment (OIDC `id-token: write` for
publishing), and it does not permit running alongside arbitrary other steps.
A supporting workflow therefore **must be installed in each repository**.

Linux Foundation projects should call the reusable workflow from
[`lfit/releng-reusable-workflows`](https://github.com/lfit/releng-reusable-workflows):

```yaml
---
name: 'OpenSSF Scorecard'

# yamllint disable-line rule:truthy
on:
  workflow_dispatch:
  branch_protection_rule:
  schedule:
    - cron: '50 4 * * 0'
  push:
    branches: ['main', 'master']

permissions: {}

jobs:
  openssf-scorecard:
    name: 'OpenSSF Scorecard'
    # yamllint disable-line rule:line-length
    uses: lfit/releng-reusable-workflows/.github/workflows/reuse-openssf-scorecard.yaml@fd3c1b43bc919e9e70787b009ffa2768ddbb1267  # v0.7.2
    permissions:
      contents: read
      security-events: write  # Upload results to the code-scanning dashboard
      id-token: write  # Publish results and obtain a Scorecard badge via OIDC
      # Uncomment the permission below if installing in a private repository.
      # actions: read
```

The reusable workflow uploads SARIF to the repository's code scanning and
publishes the aggregate score, which the report reads from the external
scorecard.dev API (preferred) or from code-scanning findings.

## Verifying the setup

After the first daily scans complete:

1. Check a scanned repository's **Security → Code scanning** tab for
   analyses from the expected tools (`zizmor`, `aislop`, `fuzz`,
   `Scorecard`).
2. Run the report; previously skipped sections should now render tables (or
   an `All Clean` footer). Run with `--verbose` to see the per-signal gate
   decisions and the evidence that satisfied them.
