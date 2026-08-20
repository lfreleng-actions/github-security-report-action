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
> zizmor, aislop (AI slop), Dependabot, and secret scanning — and ranks the
> worst offenders so remediation effort goes where it is needed.

## 🗒️ Published reports

<https://lfreleng-actions.github.io/github-security-report-action/>

## What it does

For each in-scope repository, every signal is classified into one of four
states and rendered worst-first:

- **Offenders** — enabled with open findings (a ranked table row).
- **Clean** — enabled with zero findings (a count beneath the table).
- **Not enabled** — supported but switched off (a counted "disabled" footer
  line, with the affected repositories named).
- **Unknown** — indeterminate (insufficient permission), counted separately.

Every category renders the same **standardised summary footer** beneath its
table: remediation-first count lines (failures, disabled, unknown, then the
healthy pass line, then excluded). The pass line reads **"All <state>"** when
nothing needs attention, or **"N <state>"** otherwise. The terminal and Slack
stay brevity-first; the explanatory per-category description and documentation
link are shown only on the richer Markdown and HTML (GitHub Pages) outputs.

The single GitHub code-scanning feed is partitioned by `tool.name` into CodeQL,
Scorecard, zizmor, and aislop; Scorecard prefers the external aggregate score
and falls back to code-scanning findings. See [`docs/BRIEF.md`](docs/BRIEF.md)
and [`docs/phase0-findings.md`](docs/phase0-findings.md) for the full design and
the API research it is built on.

The workflow-driven signals (OpenSSF Scorecard, zizmor, aislop) only produce
data when an organisation has deployed supporting workflows. The tool checks
for that support cheaply before collecting (**feature gating**): an
organisation with no evidence of a tool — no ruleset requiring its workflow,
no alerts, no analyses on a sample of repositories — gets a single
`⏩ Skipping feature: organisation support missing` line for that section
instead of a nag list. See the
[organisation scan setup guide](docs/org-scan-setup.md) for the required
workflows, and disable the check with `report.gating: false` if you want to
probe everything regardless.

Further sections report **configuration posture** and **freshness** as plain
tables (org mode):

- **Dependabot** — three tables: repositories with vulnerability **alerts not
  enabled**, repositories with **security updates not enabled**, and ecosystems
  with no update `cooldown` configured (mandatory; any value passes).
- **Releases / Tagging** — repositories overdue a release or tag, ranked by
  release/tag staleness (repository age never affects ordering; a repository
  with no release or tag ranks highest). Repositories younger than
  `repo_min_age_days` (default 28; `0` includes all) and those in
  `releases_exclude` are omitted. A repository is flagged only when its newest
  release or tag is older than `release_max_age_days` (default 60; `0` flags
  every eligible repository), so a repository released or tagged within that
  window counts as recently maintained and drops out of the table.
- **Private Vulnerability Reporting** — repositories where GitHub's private
  vulnerability reporting feature is **not enabled**, so security researchers
  cannot privately disclose vulnerabilities. Probed per repository (GitHub
  exposes no org-wide or GraphQL equivalent) and, like every other category,
  always collected; hide it with the `private_vulnerability_reporting` render
  toggle.

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

A token without that permission gets a `404` from the endpoint, which the tool
reports at **INFO** — so it is invisible unless you pass `--verbose`:

```text
org rulesets not readable for <org> (status 404); expected unless the token
carries the optional org-admin permission ...
```

That line is informational, not a defect. Tools are still detected from the
code-scanning analyses they upload, so the report is identical unless a
repository is covered *solely* by a required-workflow ruleset whose workflow has
never run. A genuinely unexpected failure to read the rulesets (for example a
`5xx`) is still logged as a warning.

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
| Code scanning alerts | CodeQL / Scorecard / zizmor / aislop findings |
| Secret scanning alerts | Open secret-scanning alerts |
| Issues | Open issues and their labels (GitHub Issues table) |
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
> unknown). Store the token as a secret (e.g. `LFRELENG_ACTIONS_REPORT_PAT`) and
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
    token: "${{ secrets.LFRELENG_ACTIONS_REPORT_PAT }}"
    # Must match the per-org "token_env" in your config (below).
    token_env: "LFRELENG_ACTIONS_REPORT_PAT"
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
    "release_max_age_days": 60
  },
  "organizations": [
    {
      "name": "lfreleng-actions",
      "token_env": "LFRELENG_ACTIONS_REPORT_PAT",
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
- `report.release_max_age_days` (default `60`; `0` = flag everything) is the
  release-staleness threshold: a repository is only flagged when its newest
  release **or** tag is older than that many days (a repository with neither is
  always flagged). Tune it to match your release cadence so actively released
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

### Per-category render toggles

Every reporting category can be switched on or off, globally and per output
surface, under `report.categories`. Data is **always** collected; these toggles
govern presentation only. Each category key takes an `enabled` switch (highest
precedence — `false` hides it everywhere) and a lower-precedence `outputs` map
for the four surfaces (`cli`, `slack`, `markdown`, `html`). Everything defaults
to `true`, so an omitted category or key stays fully enabled. A category is
rendered on a surface only when `enabled` **and** that surface's toggle are
both true.

```json
{
  "report": {
    "categories": {
      "zizmor": { "enabled": false },
      "releases": { "outputs": { "cli": false, "slack": false } }
    }
  },
  "organizations": [{ "name": "lfreleng-actions" }]
}
```

The example above hides Zizmor on every surface, and keeps Releases / Tagging
out of the terminal and Slack while still publishing it to the Markdown and HTML
Pages output. The valid category keys are: `codeql`, `scorecard`, `zizmor`,
`aislop`, `dependabot_alerts`, `secret_scanning`, `dependabot_alerts_enabled`,
`dependabot_updates_enabled`, `dependabot_cooldown`, `releases`,
`mutable_releases`, `private_vulnerability_reporting`, `github_issues`. Like the
other `report`
settings, `categories` can be set
globally and overridden per organisation (overrides merge key-by-key, so
flipping one output leaves the rest untouched). The machine-readable
`report.json` artifact always contains the complete dataset, regardless of these
toggles.

When several organisations share one Slack channel they render into a single
combined digest, so the per-org Slack toggles are unioned for that channel: a
category appears if **any** contributing org would show it on Slack. An org-level
Slack disable therefore does not suppress a category in a shared-channel digest
unless every org sharing that channel also disables it (this mirrors the
most-generous `top_n` rule applied to the same grouping). The terminal, Markdown
and HTML surfaces are per-org and are not affected by this union.

### Per-category row limits

A category can also set its own `top_n`, capping that one table independently of
every other. Reach for this when one category is worth showing in full while the
rest stay short — set it to `0` for no limit at all:

```json
{
  "report": {
    "top_n": 10,
    "categories": {
      "releases": { "top_n": 0 },
      "codeql": { "top_n": 3 }
    }
  },
  "organizations": [{ "name": "lfreleng-actions" }]
}
```

Here Releases / Tagging lists every repository, CodeQL shows its worst three, and
every other category keeps the shared limit of 10. A category's `top_n` applies
to all four surfaces at once; combine it with `top_n_report` / `top_n_cli` /
`top_n_slack` to vary the fallback per surface.

The resolution order for one category on one surface, most specific first:

1. `--top-n-report` / `--top-n-cli` / `--top-n-slack` (command line)
2. `--top-n` (command line)
3. `report.categories.<key>.top_n` (config)
4. `report.top_n_report` / `top_n_cli` / `top_n_slack` (config)
5. `report.top_n` (config, default `10`)

Command-line flags deliberately outrank the per-category configuration: a flag is
a decision about a single run, so `--top-n 5` caps every category even where the
config asked for an uncapped one. `0` means "no limit" at every level. In a
shared Slack channel the most generous value any contributing org configured for
that category wins, matching the visibility rule above.

On Slack, `0` is best-effort rather than absolute. Slack imposes hard structural
limits on a message — 50 blocks per post, 3,000 characters per text object (a
section body or a context note) and 150 for a header — and rejects the **whole**
post if any is breached, so an uncapped table would cost the entire digest rather
than merely overflowing. The digest therefore sizes itself to fit: repository
name lists are trimmed first, then table rows, and whatever is left out is
reported by the usual `… and N more` tally so the numbers on screen stay honest.
Counts are never dropped, only names and rows. The other three surfaces have no
Slack-style ceiling, but they still apply their own row limits — only the
`report.json` artifact is unconditionally complete. The digest links to the
GitHub Pages report whenever `pages_url` is set and short enough to render as a
link.

### Per-category row ordering

Each table ships a sensible default ordering — largest backlog first, stalest
release first, and so on. `report.categories.<key>.sort` overrides it with a list
of column names, evaluated left to right:

```json
{
  "report": {
    "categories": {
      "github_issues": { "sort": ["untriaged", "bug", "total", "oldest"] }
    }
  },
  "organizations": [{ "name": "lfreleng-actions" }]
}
```

That ranks the Issues table by untriaged count, breaking ties on Bug, then on
total open issues, then on the oldest issue.

- Names match column headers **case-insensitively**, so `untriaged` finds
  `Untriaged` and a custom `issue_labels` column such as `Regression` works with
  no extra configuration. `repository` sorts by repository name.
- **Direction is implicit by type**: numeric columns descend (most first, which
  is also oldest-first for an age column) and text columns ascend.
- A leading **`-` forces descending** and **`+` forces ascending**, so
  `["+total"]` lists the smallest backlogs first.
- A cell with **no value to sort on** — an `Oldest` of `unknown`, say — stays at
  the bottom whichever direction you choose. Missing is not the same as small.
- The repository name is always applied as the final tiebreaker, so rows that
  are equal under every configured term still order deterministically.
- An unrecognised column name is logged and skipped rather than failing the run.
- Omitting `sort` keeps the table's own default ordering. This matters: some
  defaults rank on values that are never displayed as a column — Releases /
  Tagging ranks on *missing* release and tag signals — so they cannot be
  expressed as a column list.

Ordering is resolved once, when the report is built, so every surface and
`report.json` agree. It applies to the generic tables (GitHub Issues, Releases /
Tagging, Mutable Releases, the Dependabot posture tables) **and** to the severity
signal tables (CodeQL, OpenSSF Scorecard, zizmor, AI Slop, Dependabot alerts,
secret scanning).

The signal tables resolve their terms against a fixed vocabulary rather than a
rendered column list, because their columns vary by surface and by data (Slack
abbreviates the headers and drops `Total`, and `Info` appears only when some
repository carries note-level findings):

| Signal | Accepted sort names |
| ------ | ------------------- |
| OpenSSF Scorecard | `repository`, `score`, `critical`, `high`, `medium`, `low`, `info`, `total` |
| CodeQL, zizmor, AI Slop, Dependabot alerts | `repository`, `critical`, `high`, `medium`, `low`, `info`, `total` |
| Secret Scanning | `repository`, `open` |

`informational` is accepted for `info`, and `total` for secret scanning's `open`.

A bare `score` sorts **ascending**, because the rule is "worst first" and a lower
Scorecard score is the weaker repository — so `sort: ["score"]` agrees with the
default ranking instead of contradicting it. Every count sorts descending. A
repository with no published score sorts last in either direction: unknown health
is not bad health.

Ranking by remediation volume rather than by score is the common case, since the
score is a health rating and not a count of work:

```json
{
  "report": {
    "categories": {
      "scorecard": { "sort": ["total", "score"] }
    }
  },
  "organizations": [{ "name": "lfreleng-actions" }]
}
```

Omitting `sort` keeps each signal's default ranking, which is not expressible as
a column list — Scorecard cascades through the worst severity rung any offender
actually carries, so a lone Critical is never buried by a weaker repository with
a lower score.

### GitHub Issues

The `github_issues` category counts each repository's **open issues**, split by
label into columns. It reads from the same batched GraphQL prefetch as the
release and Dependabot data, so it costs no extra API requests:

```text
GitHub Issues
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━┳━━━━━━━━━┳━━━━━━┳━━━━━━━┳━━━━━━━━━━━┳━━━━━━━┳━━━━━┳━━━━━━━━━┓
┃ Repository                    ┃ Bug ┃ Feature ┃ Docs ┃ Other ┃ Untriaged ┃ Total ┃ Ext ┃  Oldest ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━╇━━━━━━━━━╇━━━━━━╇━━━━━━━╇━━━━━━━━━━━╇━━━━━━━╇━━━━━╇━━━━━━━━━┩
│ .github                       │   1 │       0 │    0 │     0 │        10 │    11 │   0 │ 16 days │
│ tag-validate-action           │   0 │       0 │    0 │     0 │         8 │     8 │   0 │ 25 days │
│ security-workflows            │   0 │       5 │    1 │     0 │         0 │     6 │   0 │   today │
│ github-security-report-action │   0 │       0 │    0 │     3 │         1 │     4 │   0 │ 52 days │
│ dependamerge                  │   0 │       1 │    0 │     1 │         1 │     3 │   0 │ 52 days │
├───────────────────────────────┼─────┼─────────┼──────┼───────┼───────────┼───────┼─────┼─────────┤
│ Total                         │   1 │       6 │    1 │     4 │        20 │    32 │   0 │         │
└───────────────────────────────┴─────┴─────────┴──────┴───────┴───────────┴───────┴─────┴─────────┘
  … and 11 more
  ❌ 16 With open issues
  ✅ 87 No open issues
```

That is a real run of `lfreleng-actions` under `top_n: 5`. The totals row sums
the rows actually **displayed**, matching the offender tables, so it stays
consistent with a truncated view; `… and 11 more` plus the five listed rows
reconcile with the `❌ 16` in the footer.

Two columns are always present and are not configurable:

- **Other** — the issue is labelled, but with nothing you asked about.
- **Untriaged** — the issue has no labels at all. This is the column to watch:
  an unlabelled issue is one nobody has categorised.

A third, **Ext**, counts the issues raised from **outside the organisation** —
see [Inside or outside the organisation](#inside-or-outside-the-organisation).

All three names are reserved, as are `Repository`, `Total` and `Oldest`:
configuring a
column with one of those names is rejected, because it would either share a
counter with the implicit column — stopping the class columns summing to `Total`
— or duplicate a header, which would also make `sort: ["repository"]` resolve to
a count column instead of the repository name. Column names must additionally be
non-blank, unpadded, distinct case-insensitively (`sort` matches them that way,
and strips its terms), and free of `|`, backticks and control characters, which
would corrupt the Markdown table or Slack code fence they are rendered into.

The remaining columns come from `report.issue_labels`, which maps a column name
to the issue labels that count towards it. An issue counts **once**, under the
first column whose labels it carries, so the columns always sum to the classified
total. Matching is case-insensitive on the whole label name, so `docs` does not
swallow an unrelated `docs-needed`. The default is:

```json
{
  "report": {
    "issue_labels": {
      "Bug": ["bug", "defect"],
      "Feature": ["feature", "enhancement"],
      "Docs": ["documentation", "docs"]
    }
  },
  "organizations": [{ "name": "lfreleng-actions" }]
}
```

Unlike `ruleset_workflows`, a configured `issue_labels` **replaces** the default
rather than merging into it — the mapping defines a coherent set of table
columns, so merging would leave behind default columns you deliberately left out.

Repositories with no open issues are counted in the `✅ No open issues` footer
rather than listed. Rows rank by total open issues, then by Untriaged. Pull
requests are **not** counted: the GraphQL `issues` connection excludes them.

> **Accuracy note.** `Total` is exact at any backlog size, as is `Oldest`
> wherever an age is shown. The label columns are computed from a bounded,
> oldest-first window of each repository's open issues (25 issues, 5 labels
> each) that keeps the query well inside GitHub's GraphQL rate-limit budget. A
> repository whose label breakdown is partial shows a trailing `+` on its
> `Oldest` cell. That covers a backlog exceeding the issue window, and any issue
> whose classification a label beyond the label window could have changed —
> which is every classification except a match on the *first* configured column,
> since columns are matched in declaration order and an unseen label could
> belong to an earlier one. An issue whose labels could not be read at all is
> left out of the class columns entirely rather than counted as `Untriaged`. An
> `Oldest` of `unknown` means the oldest issue came back unreadable or undated;
> it can still carry the `+`.

**Permissions.** A fine-grained PAT needs **Issues: read** for this table; a
classic PAT's `repo` scope already covers it. Without it GitHub serves the query
with HTTP 200 and this one field null, so affected repositories are reported as
`❓ Unknown` rather than counted as having no open issues — an unreadable backlog
is never presented as a clean one.

### Pull Requests

The `pull_requests` category counts each repository's **open pull requests**,
split by who raised them and by what is holding them up. It rides the same
batched GraphQL prefetch as the issues data, so it costs **no extra API
requests** — measured against a five-repository batch, adding the connection and
the head commit's check rollup moved the query cost from 1 point to 3, against
an hourly budget of 5,000:

```text
Pull Requests
┏━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━┳━━━━━┳━━━━━━┳━━━━━━━━━━┳━━━━━━┳━━━━━━━┳━━━━━━━┓
┃ Repository           ┃ Human ┃ Ext ┃ Auto ┃ Conflict ┃ Fail ┃ Draft ┃ Total ┃
┡━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━╇━━━━━╇━━━━━━╇━━━━━━━━━━╇━━━━━━╇━━━━━━━╇━━━━━━━┩
│ lftools-uv           │     8 │   0 │    0 │        0 │    0 │     0 │     8 │
│ dependamerge         │     3 │   0 │    0 │        0 │    0 │     0 │     3 │
│ gha-workflow-linter  │     2 │   0 │    0 │        0 │    1 │     1 │     2 │
│ harden-runner-block- │     1 │   0 │    0 │        1 │    0 │     1 │     1 │
│ action               │       │     │      │          │      │       │       │
├─────────────────────┼───────┼─────┼──────┼──────────┼──────┼───────┼───────┤
│ Total                │    14 │   0 │    0 │        1 │    1 │     2 │    14 │
└─────────────────────┴───────┴─────┴──────┴──────────┴──────┴───────┴───────┘
  … and 9 more
  ❌ 13 With open pull requests
  ✅ 104 No open pull requests
```

The columns form **two independent groupings**:

| Column | Meaning |
| ------ | ------- |
| `Human` / `Auto` | Partition the total by author. `Auto` is recognised automation; `Human` is everyone else. |
| `Ext` | Human pull requests raised from outside the organisation — a **subset of Human**, which is why it sits beside it. |
| `Conflict` | Blocked on a merge conflict. |
| `Fail` | Blocked on failing checks (including pre-commit.ci). |
| `Draft` | Marked as a draft. |

`Conflict`, `Fail` and `Draft` **overlap** each other and the author split, so
they do not sum to `Total` and are not meant to: one pull request that is
conflicting, failing *and* a draft is counted once in each of those three
columns, and once under `Human` or `Auto`. Only `Human` + `Auto` reconciles with
the collected total. They are ordered worst-first — a conflict needs a human to
rebase, a failing check may only need a re-run, and a draft is not blocked at
all.

`Auto` recognises the same automation accounts as the
[`dependamerge`](https://github.com/lfreleng-actions/dependamerge) tool:
Dependabot, Renovate, pre-commit.ci, `github-actions`, Copilot and
Allcontributors, by their bare or `[bot]`-suffixed login, plus any actor GitHub
reports as an App and any unrecognised login carrying the `[bot]` marker — so a
future bot is classified as automation rather than mistaken for an outside
contributor.

`Fail` and `Conflict` count only **established** blockers. GitHub computes
mergeability lazily and answers `UNKNOWN` until it settles, and reports no check
rollup at all when no checks have run; neither absence is evidence that a pull
request is ready, so neither is counted either way.

Repositories with no open pull requests are counted in the footer rather than
listed. Rows rank by total open pull requests, then by those actually blocked
(`Fail` + `Conflict`), so two repositories with equal backlogs surface the more
stuck one first.

> **Accuracy note.** As with the issues table, `Total` is exact at any size,
> while the breakdown columns are computed from a bounded, oldest-first window
> of 25 open pull requests per repository. A repository whose backlog exceeds
> that window shows a trailing `+` on its `Total` cell, marking the breakdown as
> partial; the total itself stays exact.

**Permissions.** A fine-grained PAT needs **Pull requests: read**; a classic
PAT's `repo` scope already covers it. Without it the connection comes back null
and affected repositories are reported as `❓ Unknown` rather than as having no
open pull requests.

### Inside or outside the organisation

The `Ext` column on both the Issues and Pull Requests tables counts
contributions from **outside the organisation**. Two pieces of evidence decide
it, in this order:

1. **The organisation's membership**, collected once per organisation in a
   single GraphQL query (one page per 100 members) and reused for every
   repository and every table.
2. **GitHub's per-item `authorAssociation`**, consulted when the author is not a
   known member. This is what recognises a repository-level *collaborator* who
   holds no organisation membership.

The membership query is not redundant, and this ordering is deliberate.
`authorAssociation` is computed **relative to the requesting token**: where an
organisation's members keep their membership private — GitHub's default — the
same issue reports `MEMBER` to a token with organisation visibility and
`CONTRIBUTOR` to one without. Classifying on that field alone would make the
counts depend on which token produced the report, and a token lacking
`read:org` would file an entire organisation as outsiders.

**Automation is never counted as external.** Bots are outsiders by association —
`dependabot[bot]` genuinely reports `CONTRIBUTOR` or `NONE` — so counting on
association alone would file every dependency-update pull request as an external
contribution and bury the genuine outside contributors the column exists to
surface. Automation is reported under `Auto` instead.

An author who cannot be classified at all — a deleted account, or an
association value GitHub has newly introduced — is **not** counted as external.
The column understates rather than inventing an outsider.

**Permissions.** Reading organisation membership needs `read:org` (classic) or
**Members: read** (fine-grained). Without it the tool logs a single line and
falls back to `authorAssociation` alone, which still works but is subject to the
private-membership caveat above.

### Organisation feature gating

The workflow-driven signals (OpenSSF Scorecard, zizmor, aislop) need
organisation-deployed workflows before they produce any data (see the
[organisation scan setup guide](docs/org-scan-setup.md)). By default the tool
runs a cheap support check per organisation before collecting each of them:
evidence is an org ruleset requiring the tool's workflow, existing
code-scanning alerts from the tool, analyses on a sample of repositories, or
(for Scorecard) an external scorecard.dev score. A signal with no evidence is
**skipped** — not probed per repository, not classified — and its section
shows a single `⏩ Skipping feature: organisation support missing` line
linking the setup guide, on every output surface. Set `report.gating` to
`false` (globally or per organisation) to always probe everything:

```json
{
  "report": { "gating": false },
  "organizations": [{ "name": "lfreleng-actions" }]
}
```

Gating decides **collection**; the per-category render toggles above decide
**presentation**. A skipped section still renders (as the one-line notice)
unless its category is also disabled.

### Pass/fail severity cutoff

The severity-ranked signals (CodeQL, Scorecard, Zizmor, aislop, Dependabot
alerts) use a `fail_severity` cutoff to decide when a repository counts as a
failure. A repository is flagged as an offender only when it carries a finding
**at or above** the cutoff; findings below it fold into the clean count.
Severities run (lowest to highest) `informational`, `low`, `medium`, `high`,
`critical` — `informational` being the sub-low rung for SARIF `none` findings
and unclassifiable alerts. Zizmor's SARIF `note` findings normalise to `low`
(zizmor emits its Low findings at `note`, and the organisation scan pipeline's
`--min-severity low` floor keeps informational findings out of the uploaded
SARIF), matching the ruleset-enforced PR gate that blocks on note-and-above.
aislop populates the same SARIF level axis and normalises identically.

The global default cutoff is `medium`, so `low` and `informational` findings
pass. Zizmor and aislop default to `low` (only `informational` passes).
Override the cutoff per category under
`report.categories.<key>.fail_severity`:

```json
{
  "report": {
    "categories": {
      "codeql": { "fail_severity": "low" },
      "zizmor": { "fail_severity": "informational" }
    }
  },
  "organizations": [{ "name": "lfreleng-actions" }]
}
```

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
via `token_env` (e.g. `LFRELENG_ACTIONS_REPORT_PAT`, exported in your shell or sourced
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
| `token_env` | No | `GITHUB_TOKEN` | Env var name the token is exported under. In org mode it **must match** the per-org `token_env` in your config (e.g. `LFRELENG_ACTIONS_REPORT_PAT`), otherwise the tool looks up an unset variable and reports no token. |
| `output_dir` | No | — | Directory for Pages output (org mode) |
| `pages_url` | No | — | Published Pages URL (used in the Slack link) |
| `slack_channel` | No | — | Slack channel ID; overrides the config `slack.channel` (e.g. the `SLACK_CHANNEL_ID` variable) |
| `top_n` | No | `10` | Offenders per signal across all outputs (shared default; `0` = no limit) |
| `top_n_report` | No | — | Offenders per signal in the GitHub Pages output (`0` = no limit; overrides `top_n`) |
| `top_n_cli` | No | — | Offenders per signal in the terminal output (`0` = no limit; overrides `top_n`) |
| `top_n_slack` | No | — | Offenders per signal in the Slack digest (`0` = no limit; overrides `top_n`) |
| `fail_threshold` | No | `none` | `none`/`low`/`medium`/`high`/`critical`/`any` (repo mode) |
| `force_notify` | No | `false` | Post to Slack regardless of `report_day` |
| `tool_version` | No | `""` | Published PyPI version to install. Empty (the default) uses the Dependabot-managed pin in `.github/runtime-pin/requirements.txt`; set a specific version to override. Ignored on pull requests or when `use_local_source` is `true` (both run from source) |
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
export GITHUB_TOKEN="your-token"
uvx github-security-report report

# Or org mode locally with a PAT:
uvx github-security-report report --org lfreleng-actions
```

### GitHub Enterprise Server

The API endpoints honour the standard environment variables that GitHub
Actions exports, so the tool works against GitHub Enterprise Server
without code changes: set `GITHUB_API_URL` and `GITHUB_GRAPHQL_URL` to
your enterprise endpoints (Actions sets these automatically on GHES
runners). `SCORECARD_API_URL` overrides the external OpenSSF Scorecard
API in the same way.

### Exit codes

| Code | Meaning |
| ---- | ------- |
| `0` | The report ran. |
| `1` | Repo mode only: findings met or exceeded `--fail-threshold`. |
| `2` | Usage or configuration error (bad flag, unreadable config). |
| `3` | The GitHub API was unreachable after the retry budget. |
| `4` | GitHub rejected the credentials (HTTP 401). |

Codes `3` and `4` are **aborts, not reports**: nothing is written and no Pages
artifact is produced. That is deliberate. A token that has expired, been revoked
or been rotated makes every read fail, and a run that degraded instead would
render a complete, confidently clean report — `0 repositories analysed`, every
section `No data` or `All Clean` — and a scheduled job would then publish it
over the last good one. Reporting false data is worse than reporting none, so
the run stops at the first rejected request.

The two are separate codes because the remedy differs: `4` means rotate or fix
the token, `3` means retry later.

## Remediation

The `remediate` subcommand is the in-tool counterpart to the report: it runs the
same collection, then switches on each selected security feature wherever a
repository has it **confirmed off**. Only the offenders the report already
surfaces are acted on — repositories whose state could not be read are counted
as *unknown* and are never written to, so remediation never blind-writes.

It is **dry run by default** (these are privileged writes); pass `--apply` to
make changes. A single **write-capable** org-admin token (from `--token-env`,
default `GITHUB_TOKEN`) drives both the read and the writes across every
configured organisation, so it bypasses the per-org read-only `token_env` in the
config.

```bash
# An org-admin token is required: a classic PAT with the `repo` scope
# (administers repository security settings) plus `read:org` to enumerate repos.
source ~/.secrets.github.classic.god   # exports $GITHUB_TOKEN

# Dry run (default): preview every change, touch nothing.
uvx github-security-report remediate --org lfreleng-actions

# Apply: enable every remediable feature that is off, across all configured orgs.
uvx github-security-report remediate \
  --config ~/.config/github-security-report/config.json --apply

# Limit to specific categories (repeatable).
uvx github-security-report remediate --org lfreleng-actions \
  --category codeql --category private_vulnerability_reporting --apply
```

The remediable categories are the simple on/off features with a documented
enablement endpoint:

| `--category` | Enables |
|---|---|
| `codeql` | CodeQL default setup (provisioned asynchronously) |
| `secret_scanning` | Secret scanning |
| `dependabot_alerts_enabled` | Dependabot vulnerability alerts |
| `dependabot_updates_enabled` | Dependabot security updates (plus alerts) |
| `private_vulnerability_reporting` | Private vulnerability reporting |

Qualitative findings (Scorecard, zizmor, open Dependabot alerts, cooldown,
release freshness/mutability) are reported but not auto-remediated. Remediation
is organisation-scoped (`--scope org`, the default and only supported scope).

## Bulk Remediation Scripts

The standalone scripts below predate the `remediate` subcommand and remain for
ad-hoc, single-feature runs. For most workflows, prefer `remediate` above.

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
# An org-admin token is required: a classic PAT with the `repo` scope
# (administers repository security settings) plus `read:org` to enumerate repos.
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
