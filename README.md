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

- **Dependabot** — repositories without Dependabot enabled, ecosystems with no
  update `cooldown` configured (mandatory; any value passes), and a scored
  matrix of disabled Dependabot features (worst first).
- **Releases / Tagging** — repositories overdue a release or tag, ranked by a
  hidden compound staleness score. Repositories younger than
  `release_min_age_days` (default 28; `0` includes all) and those in
  `releases_exclude` are omitted.

## Operating modes

| Mode | Token | Scope | Output |
| ---- | ----- | ----- | ------ |
| `org` | classic PAT (`security_events`, `repo`, `read:org`) | one or more organisations | GitHub Pages + Slack + terminal |
| `repo` | `GITHUB_TOKEN` | the current repository only | job summary + outputs + optional PR gate |

`scope: auto` resolves to org mode when configuration is supplied, otherwise
repo mode for the detected repository. The ephemeral `GITHUB_TOKEN` cannot read
org-wide security data, so org mode requires a PAT.

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
    "include_archived": false,
    "include_test": false,
    "release_min_age_days": 28
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

`report.release_min_age_days` (default `28`, `0` = include all) and the per-org
`releases_exclude` tune the Releases / Tagging section; they can be overridden
locally with `--release-min-age-days` and the repeatable `--releases-exclude`.

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
| `top_n` | No | `10` | Offenders per signal in the Slack digest |
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

## Development

```bash
uv sync --extra dev
uv run pytest
uv run ruff check src/ tests/
```
