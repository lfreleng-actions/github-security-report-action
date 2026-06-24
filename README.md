<!--
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
-->

# 🔐 GitHub Security Report

<!-- prettier-ignore-start -->
<!-- markdownlint-disable-next-line MD013 -->
[![Linux Foundation](https://img.shields.io/badge/Linux-Foundation-blue)](https://linuxfoundation.org/) [![Source Code](https://img.shields.io/badge/GitHub-100000?logo=github&logoColor=white&color=blue)](https://github.com/lfreleng-actions/github-security-report-action) [![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
<!-- prettier-ignore-end -->

> Security and quality **reporting** (not scanning) across GitHub
> organisations. Aggregates existing signals — CodeQL, OpenSSF Scorecard,
> zizmor, Dependabot, and secret scanning — and ranks the worst offenders so
> remediation effort goes where it is needed.

## 🗒️ Published reports

<https://lfreleng-actions.github.io/github-security-report-action/>

## What it does

For each in-scope repository, every signal is classified into one of four
states and rendered worst-first:

- **Offenders** — enabled with open findings (a ranked table row).
- **Clean** — enabled with zero findings (a count beneath the table).
- **Not enabled** — supported but switched off (a nag list prompting you to
  enable it).
- **Unknown** — indeterminate (insufficient permission), footnoted separately.

The single GitHub code-scanning feed is partitioned by `tool.name` into CodeQL,
Scorecard, and zizmor; Scorecard prefers the external aggregate score and falls
back to code-scanning findings. See [`docs/BRIEF.md`](docs/BRIEF.md) and
[`docs/phase0-findings.md`](docs/phase0-findings.md) for the full design and the
API research it is built on.

Two further sections report **configuration posture** and **freshness** as plain
tables (org mode):

- **Dependabot** — three tables: repositories with vulnerability **alerts not
  enabled**, repositories with **security updates not enabled**, and ecosystems
  with no update `cooldown` configured (mandatory; any value passes).
- **Releases / Tagging** — repositories overdue a release or tag, ranked by
  release/tag staleness (repository age never affects ordering; a repository
  with no release or tag ranks highest). Repositories younger than
  `repo_min_age_days` (default 28; `0` includes all) and those in
  `releases_exclude` are omitted. Set `release_max_age_days` to only flag
  repositories whose newest release or tag is older than that many days
  (default `0` = flag every eligible repository).

## Operating modes

| Mode | Token | Scope | Output |
| ---- | ----- | ----- | ------ |
| `org` | fine-grained PAT (single org) or classic PAT (multiple orgs) | one or more organisations | GitHub Pages + Slack + terminal |
| `repo` | `GITHUB_TOKEN` | the current repository only | job summary + outputs + optional PR gate |

`scope: auto` resolves to org mode when configuration is supplied, otherwise
repo mode for the detected repository. The ephemeral `GITHUB_TOKEN` cannot read
org-wide security data, so org mode requires a PAT — see
[Token permissions](#token-permissions) for the exact scopes.

## Token permissions

Repo mode needs nothing beyond the workflow's ephemeral `GITHUB_TOKEN`. Org mode
needs a Personal Access Token; choose **one** of the two options below depending
on how many organisations the report covers.

Almost all required access is **read-only**. The tool degrades any read it is
not permitted to make to an "unknown" status rather than reporting a repository
as clean, so an under-scoped token surfaces as unknowns in the report instead of
silently wrong results — start minimal and widen if you see unknowns.

The **one** exception is organisation-ruleset coverage. GitHub gates the
org-rulesets endpoint behind an org-admin permission (classic `admin:org` scope,
or fine-grained Administration **write**), even though the tool only reads it.
That coverage is **optional**: it detects tools enforced through an org ruleset
(for example a required-workflow or code-scanning ruleset). Without it that one
signal is skipped and every other part of the report is unaffected, so the
minimal tokens below omit it. Grant the org-admin permission only if you want
ruleset-based tool coverage.

### Single organisation — fine-grained PAT

A fine-grained PAT is bound to one resource owner, so it works for a report
covering a **single** organisation. Create it with **Resource owner** set to the
organisation and **Repository access** set to *All repositories*, then grant:

**Repository permissions** (all Read-only):

| Permission | Used for |
| ---------- | -------- |
| Metadata | Mandatory baseline; listing organisation repositories |
| Contents | `.github/dependabot.yml`, latest release, and tag dates |
| Dependabot alerts | Open Dependabot vulnerability alerts |
| Code scanning alerts | CodeQL / Scorecard / zizmor findings |
| Secret scanning alerts | Open secret-scanning alerts |
| Administration | Dependabot enablement + security-updates status, and effective branch rules |

**Organization permissions:**

| Permission | Access | Used for |
| ---------- | ------ | -------- |
| Administration | Read and write | *Optional* — organisation rulesets (detect tools enforced through an org ruleset). GitHub gates this endpoint behind Administration **write**; omit it to keep the token read-only and skip ruleset-based tool coverage. |

> Read-only is enough for everything except the optional ruleset coverage
> above. A fine-grained token cannot span organisations. For a report covering
> more than one org, use a classic PAT (below).

### Multiple organisations — classic PAT

A classic PAT is authorised across every organisation its creator can access
(subject to SSO authorisation), so a single token can report on **multiple**
organisations. Grant these scopes:

| Scope | Used for |
| ----- | -------- |
| `repo` | Repository data, including private repositories |
| `security_events` | Code scanning, secret scanning, and Dependabot alerts (org-bulk and per-repo) |
| `read:org` | Listing organisation repositories |
| `admin:org` | *Optional* — reading organisation rulesets for ruleset-based tool coverage. GitHub gates `GET /orgs/{org}/rulesets` behind the full `admin:org` scope; `read:org` and `write:org` return 404. Omit it to skip that one signal; everything else is unaffected. |

> For organisations that enforce SSO, the PAT must be **SSO-authorised** for
> each target organisation, or the org-level endpoints return `403` (reported as
> unknown). Store the token as a secret (e.g. `SECURITY_REPORT_PAT`) and
> reference it by env-var name via `token_env`; never embed it in the config.

## Usage

### Org mode (scheduled report)

```yaml
- name: "Security report"
  id: report
  uses: lfreleng-actions/github-security-report-action@v0.1.0
  with:
    scope: "org"
    config: "${{ secrets.GSR_CONFIG || vars.GSR_CONFIG }}"
    token: "${{ secrets.SECURITY_REPORT_PAT }}"
    output_dir: "site"
    pages_url: "https://lfreleng-actions.github.io/github-security-report-action/"
```

A ready-to-use scheduled workflow lives in
[`.github/workflows/reporting.yaml`](.github/workflows/reporting.yaml): it runs
daily at 09:00 UTC, publishes to GitHub Pages every day, and posts a Slack
digest only on the configured `report_day` (default Tuesday).

### Repo mode (PR gate)

```yaml
- name: "Security report"
  uses: lfreleng-actions/github-security-report-action@v0.1.0
  with:
    scope: "repo"
    token: "${{ github.token }}"
    fail_threshold: "high"  # fail the job on any open high/critical finding
  # requires: permissions: { security-events: read }
```

## Configuration

Configuration is JSON, supplied as a plain `vars.` entry or base64-encoded in a
`secrets.` entry (base64 only to stop JSON braces tripping GitHub's log
redaction — it is encoding, not encryption). Tokens are referenced by
environment-variable name, never embedded.

```json
{
  "slack": { "channel": "releng-scm", "report_day": "tuesday" },
  "report": {
    "top_n": 10,
    "top_n_report": 10,
    "top_n_cli": 10,
    "top_n_slack": 10,
    "include_archived": false,
    "include_test": false,
    "repo_min_age_days": 28,
    "release_max_age_days": 0
  },
  "organizations": [
    {
      "name": "lfreleng-actions",
      "token_env": "GITHUB_TOKEN",
      "exclude": ["actions-template"],
      "releases_exclude": ["internal-only-repo"]
    }
  ]
}
```

`report_day` accepts a single weekday, a list of weekdays, `"never"`, or
`"always"`.

`top_n` controls how many offenders are shown per signal. It is the shared
default for all three outputs; set any of `top_n_report` (GitHub Pages),
`top_n_cli` (terminal), or `top_n_slack` (Slack digest) to override an
individual output. Set a value to `0` to remove the limit entirely and show
every offender. Each can also be set at the CLI with `--top-n`,
`--top-n-report`, `--top-n-cli`, and `--top-n-slack`.

The Releases / Tagging section has two independent freshness levers:

- `report.repo_min_age_days` (default `28`, `0` = include all) is a grace
  period that omits **brand-new repositories** — those *created* within that
  many days — before a release or tag is expected of them. CLI:
  `--repo-min-age-days`.
- `report.release_max_age_days` (default `0` = flag everything) is the
  release-staleness threshold: a repository is only flagged when its newest
  release **or** tag is older than that many days (a repository with neither is
  always flagged). Raise it to match your release cadence so actively released
  repositories drop out of the table. CLI: `--release-max-age-days`.

The per-org `releases_exclude` (CLI `--releases-exclude`, repeatable) drops
named repositories from the section entirely.

> The former `release_min_age_days` key was a misleading name for
> `repo_min_age_days` (it gates *repository* age, not *release* age). It is
> still accepted as a deprecated alias and emits a warning; prefer
> `repo_min_age_days`.

The per-org `exclude` list removes repositories from analysis entirely; they are
reported as **excluded** (distinct from "not enabled"), so an intentional
exclusion is visible rather than silently dropped.

`slack.channel` is optional. The action's `slack_channel` input (wired to the
`SLACK_CHANNEL_ID` variable in `reporting.yaml`) overrides it, so the channel
can live as an org/repo variable rather than in the config JSON. It must be the
channel **ID** (`C0…`), not the name.

### Config file location

For local use you can drop the same JSON at a conventional per-user path and run
with no flags — it is picked up automatically when no `--config`,
`--config-data`, or `--org` is given (instead of erroring):

```text
$XDG_CONFIG_HOME/github-security-report/config.json
# or, when XDG_CONFIG_HOME is unset:
~/.config/github-security-report/config.json
```

An explicit `--config`, `--config-data`, or `--org` always takes precedence, and
the action itself never reads this path (it is supplied configuration directly).
Secrets stay out of the file: reference the token by environment-variable name
via `token_env` (e.g. `SECURITY_REPORT_PAT`, exported in your shell or sourced
from a secrets file) — the channel ID is the only Slack value the file holds,
and the Slack **bot token** is consumed by the workflow, not the CLI.

## Inputs

<!-- markdownlint-disable MD013 -->

| Name | Required | Default | Description |
| ---- | -------- | ------- | ----------- |
| `scope` | No | `auto` | `auto`, `org`, or `repo` |
| `config` | No | — | JSON config (raw or base64) |
| `org` | No | — | Single organisation (shorthand for org mode) |
| `repo` | No | detected | `owner/name` for repo mode |
| `token` | No | `${{ github.token }}` | PAT (org mode) or `GITHUB_TOKEN` (repo mode) |
| `token_env` | No | `GITHUB_TOKEN` | Env var name the tool reads the token from |
| `output_dir` | No | — | Directory for Pages output (org mode) |
| `pages_url` | No | — | Published Pages URL (used in the Slack link) |
| `slack_channel` | No | — | Slack channel ID; overrides the config `slack.channel` (e.g. the `SLACK_CHANNEL_ID` variable) |
| `top_n` | No | `10` | Offenders per signal across all outputs (shared default; `0` = no limit) |
| `top_n_report` | No | — | Offenders per signal in the GitHub Pages output (`0` = no limit; overrides `top_n`) |
| `top_n_cli` | No | — | Offenders per signal in the terminal output (`0` = no limit; overrides `top_n`) |
| `top_n_slack` | No | — | Offenders per signal in the Slack digest (`0` = no limit; overrides `top_n`) |
| `fail_threshold` | No | `none` | `none`/`low`/`medium`/`high`/`critical`/`any` (repo mode) |
| `force_notify` | No | `false` | Post to Slack regardless of `report_day` |
| `tool_version` | No | `0.1.0` | Published PyPI version (ignored on pull requests) |
| `use_local_source` | No | `false` | Run from the checked-out source instead of PyPI (for testing unreleased code from any event) |

<!-- markdownlint-enable MD013 -->

## Outputs

| Name | Description |
| ---- | ----------- |
| `should_notify` | Whether today is a Slack notification day |
| `slack_payload` | Prebuilt Slack `chat.postMessage` payload (JSON) |
| `failed` | Whether the repo-mode fail threshold was met |

## Running locally

The tool is published to PyPI and runs with `uvx`. Inside a Git checkout with a
`GITHUB_TOKEN` exported, it auto-detects the repository (preferring the
`upstream` remote, then `origin`) and prints a Rich table report:

```bash
export GITHUB_TOKEN=ghp_your_token
uvx github-security-report report

# Or org mode locally with a PAT:
uvx github-security-report report --org lfreleng-actions
```

## Bulk Remediation Scripts

The report ends with **nag lists** — repositories where a supported feature is
switched off. Where GitHub exposes the relevant toggle through its REST API,
the [`scripts/`](scripts/) directory ships standalone helpers that clear a whole
nag list in one pass instead of clicking through each repository's settings.
They reuse the tool's own scoping rules
([`src/github_security_report/scope.py`](src/github_security_report/scope.py)),
so they act on exactly the repositories the report does. See
[`scripts/README.md`](scripts/README.md) for full details.

Each script is a self-contained [PEP 723](https://peps.python.org/pep-0723/)
program: `uv run` resolves its inline dependencies on the fly — no project
install required.

### `enable_dependabot_security_updates.py`

Enables **Dependabot security updates** (and the prerequisite alerts) across an
organisation, clearing the "Dependabot: Security Updates" nag list. It reads
the current state of each repository, enables the feature where it is off, and
verifies the result.

```bash
# An org-admin token is required (classic PAT with repo admin / admin:org).
source ~/.secrets.github.classic.god   # exports $GITHUB_TOKEN

# Dry run (default): preview every change, touch nothing.
uv run scripts/enable_dependabot_security_updates.py \
  --config ~/.config/github-security-report/config.json

# Apply: switch the feature on for every in-scope repository.
uv run scripts/enable_dependabot_security_updates.py \
  --config ~/.config/github-security-report/config.json --apply
```

`--config` reads the organisation name and exclusions straight from the
reporting tool's JSON config, so the script and the report never drift. The
operation is **dry-run by default** (these are privileged writes) and reversible
via `DELETE /repos/{owner}/{repo}/automated-security-fixes`.

## Development

```bash
uv sync --extra dev
uv run pytest
uv run ruff check src/ tests/
```
