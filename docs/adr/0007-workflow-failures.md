<!--
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
-->

# ADR-0007: Workflow Failures tables and the run store

- **Status:** Accepted
- **Date:** 2026-10-29
- **Supersedes:** —
- **Superseded by:** —
- **Amends:** [ADR-0004](0004-report-section-order.md) (the nested tables
  that travel with a parent now include a windowed category's later windows)
- **Related:** [ADR-0002](0002-report-metadata-and-footer.md) (the standard
  footer the new tables use), [ADR-0006](0006-github-code-quality.md) (the
  prefetch the probe consolidation builds on),
  [issue #199](https://github.com/lfreleng-actions/github-security-report-action/issues/199)
  (the API spike and the design discussion)

## Context

Bulk Dependabot merges through `dependamerge` produce a stream of post-merge
workflow-failure emails. The workflows that fail are typically integration
tests that need credentials, a publish step, or a protected environment, so
they run only once merged and never fail on the pull request that introduced
the change. Nothing in the existing report could say which workflows fail
*only after merge*, nor whether a failure is a root cause (every run fails)
or flakiness (some runs fail), nor which job inside the workflow is the one
to fix.

A maintainer measured the GitHub APIs against `lfreleng-actions` (143 active
repositories) on 2026-10-15. The facts that shape the design:

- The organisation produced 15,428 workflow runs in 7 days and 127,981 in
  90 days; 1,893 of the 90-day runs concluded `failure`, across 777 distinct
  (repository, workflow) pairs. Enumerating every run for 90 days is 1,346
  REST pages.
- `GET /repos/{owner}/{repo}/actions/runs` lists newest first, 100 per page,
  and filters by `created` (to the hour) and by one `status` value. Its
  pagination **stops after 1,000 items**, and `total_count` itself caps at
  2,500. 39 repositories exceeded 1,000 runs in 90 days, and `dependamerge`
  reached 2,500 in a single week during a bulk-merge round, so any
  enumeration must be sliced by date beneath the cap.
- An `If-None-Match` request against the first page answers `304 Not
  Modified` without touching `x-ratelimit-used`. A conditional read of an
  unchanged listing is free, provided the URL is stable between runs.
- Each 100-run page is about 1.2 MB; a cold 90-day read of the organisation
  is roughly 1.6 GB of transfer, acceptable once, not daily.
- The listing shows only the **latest attempt** of each run. A run that
  failed and then passed on re-run is a `success` with `run_attempt: 2`, a
  direct flakiness signal, and a re-run keeps its original `created_at`.
- `head_branch` cannot tell a tag push from a branch push (a tag run shows
  `event: push, head_branch: v0.18.0`). GraphQL's `CheckSuite.branch.prefix`
  can.
- GitHub-managed workflows (Dependabot updates, default-setup CodeQL, Copilot
  review) carry a `path` beginning `dynamic/` and no file in the repository;
  259 of the 1,894 failures were theirs.
- GraphQL `nodes(ids: [...])` over `WorkflowRun` returns the failing check
  runs, the workflow's current name and the ref prefix for **50 runs per
  query at a cost of one point**, in about 2.3 s. The REST alternative,
  `/runs/{id}/jobs`, is one request per failure.
- `Workflow.runs` in GraphQL can enumerate runs per workflow but is
  latency-bound, has no date filter and needs a cursor per workflow.
- A repository with Actions disabled answers `200` with no runs; a token
  without Actions read gets `403`.

The same spike audited the existing report and found that about 600 of its
1,387 requests re-read data the run already held: four per-tool code-scanning
probes per repository where one unfiltered analyses page names every tool,
and per-repository secret-scanning and security-updates probes whose answers
the organisation listing already carries under `security_and_analysis`.

## Decision

1. **A trigger taxonomy and four outcome buckets.** Every run is classified
   once, on the way into the store, so the collector, the store and the
   aggregation share one vocabulary rather than GitHub's raw `event` and
   `conclusion` strings. The triggers are `pr` (`pull_request`,
   `pull_request_target`), `merge` (a push to the default branch), `tag` (a
   tag push or the `release` event), `branch` (a push to any other ref),
   `schedule`, `manual` (`workflow_dispatch`), `dynamic` (a `dynamic/` path)
   and `other`. A push to a non-default ref is a `branch` until the GraphQL
   drill-down settles whether the ref was a tag. The outcomes are `pass`
   (`success`), `fail` (`failure`, `startup_failure`, `timed_out`,
   `action_required`), `skip` (`skipped`, `cancelled`, `neutral`, `stale`,
   and any conclusion GitHub adds later) and `pending` (no conclusion yet).
   **Cancelled counts as a skip**: a bulk-merge round cancels hundreds of
   superseded runs, and none of them says anything about whether the
   workflow works.

2. **The fail rate excludes skips.** Fail % is failed over failed plus
   passed. A skipped or cancelled run reached no verdict, and counting it in
   the denominator would dilute the rate of exactly the repositories the
   table is for. The `Runs` column still counts every concluded run, skips
   included, so the two are visibly different numbers.

3. **Persistent, intermittent or insufficient.** A workflow whose fail rate
   is at or above `persistent_threshold` (default 0.9) is **persistent**: fix
   the root cause. Below it, **intermittent**: harden the workflow. With
   fewer than `min_runs` (default 3) runs that reached a verdict, the sample
   is too small to call either way and the pattern is **insufficient**. Both
   thresholds are configuration, and both judge the same pass-or-fail
   population the rate does.

4. **A reading column that isolates post-merge-only failures.** For each
   failing workflow the detail table says where its failures sit relative to
   its pull-request runs: **post-merge only** when every pull-request run
   passed and only merges or tag pushes failed; **no PR runs** when it failed
   on merge or tag and never ran on a pull request; **everywhere** when a
   pull-request run failed too; and **other** when the failures lie only on
   schedule, manual or branch runs. A single pull-request failure makes a
   workflow `everywhere`, since the code under review can evidently break it.
   The two post-merge readings are the reason the category exists: a
   workflow a pull request could not have caught is the `dependamerge` case,
   and the column lets a reader find it without scanning the trigger counts.

5. **A SQLite run store that is a cache, never a source of truth.** Every
   `WorkflowRunRecord` seen is kept in
   `$XDG_CACHE_HOME/github-security-report/<api-host>/<org>/runs.sqlite`
   (`~/.cache/...` when the variable is unset), keyed by API host as well as
   organisation because the same name can exist on github.com and on an
   enterprise instance. Both path components are sanitised to
   `[A-Za-z0-9_.-]`, so a hostile organisation name cannot escape the cache
   directory. The stdlib `sqlite3` module is enough: one connection per
   organisation, explicit transactions so a crash mid-sync leaves the
   previous state intact, and a `user_version` schema stamp whose mismatch
   **drops and recreates** the tables rather than migrating them, because
   everything in the file can be rebuilt from GitHub. Records older than the
   retention are pruned after each sync; retention is never shorter than the
   longest configured window, and the loader rejects a `retention_days` that
   is, since the store would otherwise prune records a table still shows.
   Deleting the file, or passing `--refresh-runs`, costs one backfill.

6. **Incremental sync.** Per repository the store remembers a watermark (the
   newest `created_at` held), the listing's first-page ETag, the failure
   list's ETag, and how far back the history has ever been read.
   - A repository never seen is **backfilled** to `backfill_days` in date
     slices: the first slice is seven days, a slice that still hits the
     1,000-run cap is halved down to a single day, and a day that alone
     exceeds the cap is read as far as GitHub lists it and logged.
   - Every later sync reads newest first with the stored ETag and stops at
     the watermark. An unchanged listing answers `304` and costs nothing.
     A listing that caps before reaching the watermark (a bulk-merge week)
     falls back to date slices for the remainder.
   - A re-run keeps its `created_at`, so the incremental read can never see
     a stored failure that later passed. The sync therefore **re-reads the
     window's failure list** (conditionally, with its own ETag) and re-reads
     each stored `failure` missing from it, **but only when the first page
     moved**: an unchanged page means no run was created, re-run or
     concluded among the newest hundred. Only plain `failure` is reconciled,
     because the `status` filter takes one value and a `startup_failure`
     absent from a `failure` list was never in it.
   - Runs stored while still **pending** are re-read each sync until they
     conclude.
   - Individual re-reads are capped at **50 per repository per sync**; the
     rest wait for the next run rather than cost a request each now.
   - A re-read keeps the enrichment it cannot supply (failing jobs, the tag
     flag) while the outcome and attempt are unchanged, and a stored failure
     re-read as a pass is marked **retried**.

7. **GraphQL enrichment in batches of fifty.** Every stored failure within
   the longest window whose jobs are unread is drilled into through
   `nodes(ids:)`, fifty node ids per query through the shared batched driver
   that halves a query GitHub refuses. The drill-down fills the failing check
   runs (name, conclusion, details URL), the workflow's current name, and the
   ref prefix, which turns a `branch` the listing could only guess at into a
   `tag`. A drill-down the API refuses outright is logged and left for the
   next run; the tables render those failures with their jobs
   **unreadable**, which is accurate, whereas aborting would cost the whole
   report for one column of detail.

8. **Degradation.** A repository whose listing answered anything other than
   `200` or `304` (a `403` from a token without Actions read, a `5xx`) is
   **Unreadable** on every window and is never counted as failure-free. A
   window that reaches further back than a repository's stored history gets
   a footer note (`N repositories hold less than D days of run history`), so
   a cold cache's first report says what it is missing.

9. **One table per window, nested beneath the first.** Each surface shows
   the windows it is configured for (`cli` and `slack` default to seven days;
   `report`, the Pages Markdown and HTML, to 7, 30 and 90). The tables are
   built shortest window first and titled with the window, `Workflow
   Failures (7 days)`. The later windows are not independently placeable:
   they render as children beneath the first on every surface, exactly as
   the Dependabot posture tables do beneath their signal, since three
   near-identical headings adrift in the report would not say which they
   qualified. This extends ADR-0004's nested-table rule from signal parents
   to a windowed `TableSection`, and `report.json` carries `window_days` per
   table so a consumer can tell them apart. `TableRow.cell_urls` was added so
   a cell other than the repository can carry a link: the worst workflow
   links to its run history, a failing job to its newest check-run log, and
   the last failure to its run page. The Markdown and HTML surfaces draw the
   links; the terminal and the Slack digest ignore them.

10. **Two categories, the detail shipped collected but disabled.**
    `workflow_failures` is the per-repository ranking (`Repository | Failed |
    Runs | Fail % | Skipped | Retried | Workflows | Worst workflow`), shown
    everywhere by default and ranked by failures, then fail rate.
    `workflow_failures_detail` is one row per failing workflow (`Repository |
    Workflow | File | Failing job | Failed | Runs | Fail % | Pattern |
    Triggers | Reading | Last failure`). The detail is **collected on every
    run but `enabled: false` by default**, and its outputs keep it off Slack
    even once enabled: its shape (which jobs to list, how wide a row may run)
    is still being settled against real data, and a dozen columns across
    several rows per repository is too wide for a chat digest. Because
    `report.json` omits any category no published surface shows, the detail
    is absent from the artifact until it is enabled.

11. **GitHub-managed workflows are excluded by default.** A `dynamic/`
    workflow has no file in the repository to fix, so its failures are left
    out of both tables unless `include_dynamic` is set. `exclude_workflows`
    globs on the workflow path let an organisation drop a deliberately
    failing canary or an experiment.

12. **Repo mode reads the terminal's windows into an in-memory store.** A
    single repository's listing is cheap, and a repo-mode run (a pull
    request's CI, a developer's shell) should leave nothing behind, so repo
    mode always uses an in-memory store and the `cli` windows alone (a week,
    by default) rather than the published report's quarter. The three store
    flags (`--no-run-cache`, `--run-cache-dir`, `--refresh-runs`) are refused
    in repo mode rather than accepted and ignored; `--run-windows` applies.

13. **CI keeps the store with `actions/cache`.** The bundled
    `reporting.yaml` restores `~/.cache/github-security-report` before the
    report and saves it afterwards whatever the report's outcome, under a key
    unique to the run (`gsr-runs-${{ github.run_id }}`) with a `gsr-runs-`
    restore prefix so the newest earlier store is picked up. A daily schedule
    keeps the entry inside GitHub's seven-day cache eviction. The save runs
    even after a failed report step because the store is written in
    transactions: a run that aborted part-way still leaves it consistent, and
    the repositories it did sync need not be re-read.

14. **Probe consolidation and phase overlap, as behaviour-preserving
    optimisations.** One unfiltered `code-scanning/analyses?per_page=100`
    page is read per repository and cached for the client's lifetime; the
    per-tool `tool_name` probes run only for tools a *full* page omits, and
    the CodeQL configuration walk is answered from that page when it holds
    the repository's whole history, walking the filtered history only when
    it does not. The organisation
    listing's `security_and_analysis` block supplies the secret-scanning and
    security-updates states where the token can see it, sparing those two
    probes. The GraphQL prefetch now runs alongside the organisation sweeps
    and feature gating, and the per-repository posture, CodeQL, author and
    workflow-run collections run concurrently rather than as sequential
    passes. Snapshot tests hold the rendered report identical. Measured on
    `lfreleng-actions`, warm runs in the same hour: 1,830 requests, 1,558
    core points and 116 s before; 1,130 / 849 / 95 s after the probe
    consolidation; 1,136 / 838 / 82 s after the phases overlapped. A cold
    90-day backfill of the run store is about 1,500 requests, once.

15. **The CodeQL analyses walk stays unbounded.** It would be easy to cap the
    walk at a page or two, and it is now the largest remaining REST cost
    (about 305 requests on `lfreleng-actions`). It is deliberately left
    complete. A configuration whose newest analysis lies beyond any bound is
    exactly the stale or orphaned one the walk exists to find, and the
    remediation of ADR-0005 needs every analysis id of a configuration to
    delete it. A bound would make the stale-configuration table quietly miss
    its worst cases.

## Consequences

- An organisation can see which repositories' workflows fail, which
  workflow and job, whether the failure is persistent or flaky, and whether
  a pull request could have caught it. The post-merge-only reading answers
  the question that motivated the work.
- A warm run costs each repository one conditional request on a quiet day,
  and GitHub does not charge a `304`. The existing report's own cost fell by
  about 700 requests and 30 s at the same time, so the run as a whole is
  faster than before the category existed.
- The first run against an organisation, or any run without the cache, is
  a backfill of about 1,500 requests and a little over a gigabyte of
  transfer. The bundled workflow caches the store; a caller's own workflow
  must do the same or pay the backfill daily.
- Fewer requests, more bytes: the run's received volume rose from about 25
  to about 39 MiB, since a full unfiltered analyses page and a hundred-run
  listing page are each larger than the filtered probes they replace.
- The store is about 25 MB for a 140-repository organisation and grows with
  the longest window and the organisation's activity. It is a per-user cache
  on a workstation and a cache entry in CI; neither needs backing up.
- Rate-limit headroom improves: the run spends about 840 core points against
  a 5,000-point hourly budget, and the GraphQL drill-down about one point per
  fifty failures.
- A fine-grained token without Actions read reports every repository as
  Unreadable in this one category and nothing else changes.
- A re-run of a run older than the newest hundred is noticed only when the
  first page moves, which for an active repository is the next run and for a
  dormant one may be days; the Retried column can lag by that much.
- The detail table's shape may still change before it is enabled by
  default; consumers of `report.json` should not depend on its columns yet.

## Alternatives considered

- **A JSON Lines store** (gzip, about 15 MB per organisation). Simpler, but
  every sync rewrites the whole file, a crash mid-write loses it, and the
  watermark lookups the sync needs would mean loading everything. SQLite
  from the stdlib adds no dependency and gives atomic writes and an index on
  `(repo, created_at)`.
- **Enumerating runs through GraphQL `Workflow.runs`.** One point per query,
  but latency-bound (fifteen workflows of fifty runs took six seconds; a
  hundred timed out), with no date filter and a cursor per workflow.
  Rejected; REST is time-sliceable and conditional.
- **HTTP/2 for the transport.** The issue's A/B measurement found no gain
  over the connection pool already in use, so it was not adopted.
- **Trigger columns on the per-repository table** (`PR | Merge | Tag |
  Sched`). Prototyped, then dropped: they widened the headline table past
  the terminal and said nothing the detail table's Triggers and Reading
  columns do not say better. The trigger split lives on the detail table.
- **A multi-window wide table with a trend column, and a grouped
  repository ▸ workflow ▸ job tree** (prototypes B and D in the issue).
  Deferred until the data has been in `report.json` long enough to know
  which comparisons readers make.
