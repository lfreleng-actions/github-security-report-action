<!--
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
-->

# ADR-0006: Report and remediate GitHub Code Quality

- **Status:** Accepted
- **Date:** 2026-10-21
- **Supersedes:** [ADR-0001](0001-architecture-and-scope.md), partially: the
  deferral of GitHub Code Quality in decision 3, and nothing else
- **Superseded by:** —
- **Amends:** [ADR-0003](0003-remediate-subcommand.md) (decision 5)
- **Related:** [ADR-0005](0005-codeql-configuration-cleanup.md)

## Context

ADR-0001 deferred GitHub Code Quality until a mature public API existed. That
API now exists: `GET` and `PATCH /repos/{owner}/{repo}/code-quality/setup`
([REST reference](https://docs.github.com/en/rest/code-quality/code-quality)).
A maintainer exercised both against `lfreleng-actions` with a classic PAT
carrying `repo`:

| Repository | Linguist languages | `code-quality/setup` response |
| --- | --- | --- |
| `github-security-report-action` | Python | `configured`, `["python"]` |
| `lftools-uv` | Makefile, PowerShell, Python, Shell | `configured`, `["python"]` |
| `gerrit-clone-action` | Python | `configured`, `["python"]` |
| `python-twine-check-action` | *(none)* | `not-configured`, `[]` |
| `docker-workflows` | Shell | `not-configured`, `[]` |
| `node-workflows` | *(none)* | `not-configured`, `[]` |

Two facts shape the design. Code Quality analyses six language families
only, so most of an organisation of GitHub Actions has nothing for it to
analyse, and a report calling those repositories "off" would bury the ones
that matter. And a `not-configured` repository answers with an empty
`languages` list, so the setup cannot say which languages a repository holds.

The API documents the remaining behaviour. Fine-grained tokens need
**Administration: write**, even for the `GET`. `PATCH` answers `202` with a
`run_id` and `run_url` once it has queued the first analysis; `403` when the
repository is archived or Code Quality is not allowed for it; `409` when an
update is already in progress; `422` when GitHub refuses the change.

## Decision

1. **A `code_quality` report category.** It reads the setup with
   `GET .../code-quality/setup` and writes it with
   `PATCH .../code-quality/setup`. Counting Code Quality findings
   (`/code-quality/findings`) is out of scope.

2. **Scope by Linguist languages.** Applicability comes from the
   repository's Linguist languages, which the batched GraphQL prefetch reads
   with `languages(first: 20) { nodes { name } }` at no extra request; never
   from the setup response, which is empty when the feature is off, nor from
   CodeQL default-setup detection, which reads only for repositories that
   have run CodeQL and lists only the languages it scans. The query also asks
   for `pageInfo { hasNextPage }`: a repository holding more than twenty
   languages could hide a supported one past the window, so its list is
   treated as unread rather than complete. Linguist names map onto Code
   Quality identifiers:

   | Linguist name | Code Quality identifier |
   | --- | --- |
   | Python | `python` |
   | Go | `go` |
   | Java, Kotlin | `java-kotlin` |
   | JavaScript, TypeScript | `javascript-typescript` |
   | Ruby | `ruby` |
   | C# | `csharp` |

   Every other language is ignored. A repository with no mapped language is
   **not applicable**: never reported as off and never remediated. The setup
   is read only for applicable repositories.

3. **Four states for an applicable repository.**
   - **Enabled:** `configured`, and the configured languages cover every
     applicable language.
   - **Partial:** `configured`, but an applicable language is missing.
   - **Disabled:** `not-configured`.
   - **Unreadable:** the setup read failed, or its state is undocumented.
     Reported on a line of its own, never folded into Disabled. A
     repository whose Linguist languages could not be read, or ran past the
     twenty-language window, is unreadable too, since nothing shows whether
     it is applicable or which languages it needs.

   Disabled and Partial are the offenders. Not applicable and Unreadable each
   get their own count line in the standard footer.

4. **A per-language breakdown on every surface.** For each Code Quality
   language with at least one applicable repository, the report shows the
   enabled count out of the applicable count, such as
   `python 30/32 · go 5/5 · javascript-typescript 10/12`. A repository counts
   under every applicable language it holds, and as enabled under each one
   its setup configures. The breakdown is a footer line, so the terminal,
   which omits descriptions, shows it too.

5. **Remediation is explicit-only, for billing.** Code Quality is billed per
   active committer and consumes GitHub Actions minutes, so switching it on
   is a spending decision a routine `remediate --apply` must not make. The
   remediator is `explicit_only`, and runs only via
   `remediate --category code_quality`, alongside the destructive
   `codeql_stale_configurations` (ADR-0005) but for a different reason.
   - For a Disabled or Partial repository it sends `state: configured` with
     `languages` set to the union of the languages already configured and
     the applicable ones, so it never drops a configured language.
   - Not applicable and Unreadable repositories are never offenders, so
     never written.
   - A `409` is a failure whose diagnostic says an update is already in
     progress.

## Consequences

- An organisation sees Code Quality coverage per language, and the
  repositories with nothing for it to analyse drop out of the count instead
  of padding it.
- The prefetch query grows by up to twenty language nodes per repository;
  each applicable repository costs one more REST read per run.
- A fine-grained token without Administration: write reports every
  applicable repository as Unreadable, and none as Disabled.
- Linguist may name a language whose code Code Quality finds nothing in
  (a vendored script, say). Remediation then configures a language with no
  findings, which costs its Actions minutes; the dry run names each
  repository's languages, so this is visible before `--apply`.
- `explicit_only` now covers two reasons, deletion and billing, and the
  `--category` help says so rather than calling every explicit-only
  category destructive.
