<!--
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
-->

# Agent Guidance

Repository-level guidance for AI coding agents working in this repo. This
complements (does not replace) any global agent configuration.

## Agent skills

Configuration consumed by the Matt Pocock engineering skills
(`diagnose`, `tdd`, `triage`, `improve-codebase-architecture`, `zoom-out`,
`grill-with-docs`, and friends).

### Issue tracker

Issues and PRDs live as GitHub issues on the `upstream`
(`lfreleng-actions/github-security-report-action`) repository; `origin` is a
personal fork used for branches and pull requests. See
`docs/agents/issue-tracker.md`.

### Triage labels

Canonical triage label vocabulary (label strings equal their role names). See
`docs/agents/triage-labels.md`.

### Domain docs

Single-context layout: one `CONTEXT.md` plus `docs/adr/` at the repo root
(created lazily by `grill-with-docs`). See `docs/agents/domain.md`.
