<!--
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
-->

# Issue tracker: GitHub

Issues and PRDs for this repo live as GitHub issues. Use the `gh` CLI for all
operations.

## Remotes

- `origin` — `modeseven-lfreleng-actions/github-security-report-action` (a
  personal fork; push feature branches here).
- `upstream` — `lfreleng-actions/github-security-report-action` (the canonical
  repo; issues are tracked here and pull requests are raised against it).

When running `gh` issue commands, target the upstream repo explicitly so
issues land in the canonical tracker rather than the fork, e.g.
`gh issue list --repo lfreleng-actions/github-security-report-action`.

## Conventions

- **Create an issue**: `gh issue create --repo lfreleng-actions/github-security-report-action --title "..." --body "..."`. Use a heredoc for multi-line bodies.
- **Read an issue**: `gh issue view <number> --repo lfreleng-actions/github-security-report-action --comments`.
- **List issues**: `gh issue list --repo lfreleng-actions/github-security-report-action --state open --json number,title,body,labels,comments --jq '[.[] | {number, title, body, labels: [.labels[].name], comments: [.comments[].body]}]'` with appropriate `--label` and `--state` filters.
- **Comment on an issue**: `gh issue comment <number> --repo lfreleng-actions/github-security-report-action --body "..."`
- **Apply / remove labels**: `gh issue edit <number> --repo lfreleng-actions/github-security-report-action --add-label "..."` / `--remove-label "..."`
- **Close**: `gh issue close <number> --repo lfreleng-actions/github-security-report-action --comment "..."`

## When a skill says "publish to the issue tracker"

Create a GitHub issue on the upstream repo.

## When a skill says "fetch the relevant ticket"

Run `gh issue view <number> --repo lfreleng-actions/github-security-report-action --comments`.
