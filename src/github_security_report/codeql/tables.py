# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""The two CodeQL scan-health tables, nested beneath the CodeQL signal.

**Stale Configurations** lists every configuration whose last scan trails the
default branch head by more than the configured threshold, with the setup type
that produced it and the reason it stopped. **Language Coverage** lists
repositories where GitHub detects a CodeQL language that no current
configuration scans.

The two are deliberately separate. A stale configuration is a question about
the past (something scanned, then stopped); a coverage gap is a question about
the present (something should be scanning, and is not). One repository can
have either without the other. Replacing default setup with a narrower advanced
workflow leaves both: the default configurations go stale, and the languages
only they covered go unscanned.

Both tables consider only repositories where CodeQL has uploaded at least once.
A repository with no CodeQL at all already appears in the CodeQL signal's
not-enabled list, and repeating it here would only restate that.
"""

from __future__ import annotations

from collections.abc import Sequence

from github_security_report.categories import CategoryKey, category_meta
from github_security_report.codeql.facts import (
    WORKFLOW_ACTIVE,
    WORKFLOW_DELETED,
    WORKFLOW_DISABLED_INACTIVITY,
    WORKFLOW_MISSING,
    CodeQLConfiguration,
    CodeQLFacts,
    SetupType,
    StaleCause,
)
from github_security_report.report import TableRow, TableSection


def _setup_cell(config: CodeQLConfiguration) -> str:
    """``Default``, or ``Advanced (<workflow file>)`` naming the workflow."""
    if config.setup is SetupType.DEFAULT:
        return SetupType.DEFAULT.value
    path = config.workflow_path
    if path is None:
        return SetupType.ADVANCED.value
    return f"{SetupType.ADVANCED.value} ({path.rsplit('/', 1)[-1]})"


def _default_setup_cause(config: CodeQLConfiguration, facts: CodeQLFacts) -> StaleCause:
    setup = facts.default_setup
    if setup is None:
        return StaleCause.DEFAULT_SETUP_UNREADABLE
    if setup.transitional:
        return StaleCause.DEFAULT_SETUP_TRANSITIONAL
    if not setup.configured:
        return StaleCause.DEFAULT_SETUP_DISABLED
    if config.language is not None and config.language not in setup.languages:
        return StaleCause.LANGUAGE_REMOVED
    return StaleCause.DEFAULT_SETUP_IDLE


def _advanced_setup_cause(
    config: CodeQLConfiguration, facts: CodeQLFacts
) -> StaleCause:
    setup = facts.default_setup
    if setup is not None and setup.transitional:
        # Default setup is mid-change: nothing about this configuration is
        # settled, so no workflow state -- not even a removed one -- may be
        # read as final. Checked first, so an unsettled migration can never
        # reach an "orphaned" cause that a cleanup would act on.
        return StaleCause.DEFAULT_SETUP_TRANSITIONAL
    path = config.workflow_path
    state = facts.workflow_states.get(path) if path is not None else None
    if state in (WORKFLOW_MISSING, WORKFLOW_DELETED):
        return StaleCause.WORKFLOW_REMOVED
    disabled = state is not None and state.startswith("disabled")
    if setup is not None and setup.configured:
        # GitHub rejects advanced CodeQL uploads while default setup is on, so
        # this configuration cannot upload again whatever the workflow does.
        return StaleCause.SUPERSEDED_DISABLED if disabled else StaleCause.SUPERSEDED
    if path is None:
        # The analysis key names no workflow file: CodeQL ran outside GitHub
        # Actions (the CLI in another CI system, say), so there is no workflow
        # state to read and none to point the reader at.
        return StaleCause.EXTERNAL_UPLOADER
    if state == WORKFLOW_DISABLED_INACTIVITY:
        return StaleCause.WORKFLOW_INACTIVE
    if disabled:
        return StaleCause.WORKFLOW_DISABLED
    if state == WORKFLOW_ACTIVE:
        return StaleCause.WORKFLOW_IDLE
    return StaleCause.WORKFLOW_UNREADABLE


def stale_cause(config: CodeQLConfiguration, facts: CodeQLFacts) -> StaleCause:
    """Why a stale configuration stopped scanning, as far as the API can tell.

    An errored newest attempt comes first: the setup still exists and still
    runs, so whatever its state, the reader's next step is its failing logs.
    """
    if config.failing:
        return StaleCause.ANALYSES_FAILING
    if config.setup is SetupType.DEFAULT:
        return _default_setup_cause(config, facts)
    return _advanced_setup_cause(config, facts)


def build_stale_configurations_table(
    facts: Sequence[CodeQLFacts], *, stale_days: int
) -> TableSection:
    """Configurations whose last scan trails the default branch head.

    One row per stale configuration, so a repository can occupy several
    rows; the footer counts repositories. Repositories are ranked by their
    stalest configuration, and each repository's rows run stalest first.
    """
    flagged: list[tuple[CodeQLFacts, list[CodeQLConfiguration]]] = []
    current = 0
    unknown = 0
    for repo_facts in facts:
        if repo_facts.analyses_status == 404 or (
            repo_facts.analyses_status == 200 and not repo_facts.configurations
        ):
            continue  # no CodeQL here; the CodeQL signal reports that
        if not repo_facts.readable:
            unknown += 1
            continue
        stale = repo_facts.stale_configurations(stale_days)
        if stale:
            ordered = sorted(stale, key=lambda c: (c.scan_order, c.category))
            flagged.append((repo_facts, ordered))
        else:
            current += 1
    # Oldest first: the stalest configuration anywhere leads, then by name.
    flagged.sort(key=lambda item: (item[1][0].scan_order, item[0].repo.name))
    rows = []
    for repo_facts, stale in flagged:
        for config in stale:
            last_scan = (
                config.last_scan_at.date().isoformat()
                if config.last_scan_at is not None
                else "never"
            )
            setup = _setup_cell(config)
            language = config.language or "unknown"
            cause = stale_cause(config, repo_facts).value
            rows.append(
                TableRow(
                    repo=repo_facts.repo,
                    cells=(setup, language, last_scan, cause),
                    # The last-scan sort key is the ISO date behind the cell,
                    # with "never" as the oldest possible date so a configured
                    # ascending sort keeps it stalest-first, not after every date.
                    sort_values=(
                        setup,
                        language,
                        config.scan_order.date().isoformat(),
                        cause,
                    ),
                )
            )
    meta = category_meta(CategoryKey.CODEQL_STALE_CONFIGURATIONS)
    return TableSection(
        category=meta,
        columns=("Repository", "Setup", "Language", "Last scan", "Cause"),
        rows=rows,
        pass_count=current,
        fail_count=len(flagged),
        unknown_count=unknown,
        description=(
            f"A configuration is stale once its last scan trails the default "
            f"branch's newest commit by more than {stale_days} day(s). "
            + meta.description
        ),
    )


def _current_setup_cell(current: Sequence[CodeQLConfiguration]) -> str:
    setups = sorted({config.setup.value for config in current})
    return " + ".join(setups) if setups else "None current"


def build_language_coverage_table(
    facts: Sequence[CodeQLFacts], *, stale_days: int
) -> TableSection:
    """Repositories with a detected CodeQL language that nothing scans now.

    "Scans now" means a configuration that is not stale by the same threshold
    as the Stale Configurations table: a language covered only by an abandoned
    configuration is not being scanned, whatever its old results say.
    """
    rows = []
    covered = 0
    unknown = 0
    for repo_facts in facts:
        if not repo_facts.uses_codeql and repo_facts.analyses_status in (200, 404):
            continue  # no CodeQL here; the CodeQL signal reports that
        head = repo_facts.head_committed_at
        setup = repo_facts.default_setup
        if not repo_facts.readable or head is None or setup is None:
            unknown += 1
            continue
        if setup.transitional:
            # Mid-change, "languages" is neither the configured set nor the
            # detected inventory, so no coverage claim can be made either way.
            unknown += 1
            continue
        current = [
            config
            for config in repo_facts.configurations
            if not config.is_stale(head, stale_days)
        ]
        scanned = repo_facts.current_languages(stale_days)
        unscanned = sorted(setup.languages - scanned)
        if not unscanned:
            covered += 1
            continue
        rows.append(
            TableRow(
                repo=repo_facts.repo,
                cells=(
                    _current_setup_cell(current),
                    ", ".join(unscanned),
                    ", ".join(sorted(scanned)) or "nothing",
                ),
            )
        )
    rows.sort(key=lambda row: row.repo.name)
    return TableSection(
        category=category_meta(CategoryKey.CODEQL_LANGUAGE_COVERAGE),
        columns=("Repository", "Current setup", "Unscanned", "Scanned"),
        rows=rows,
        pass_count=covered,
        fail_count=len(rows),
        unknown_count=unknown,
    )


def build_codeql_tables(
    facts: Sequence[CodeQLFacts], *, stale_days: int
) -> list[TableSection]:
    """Both CodeQL scan-health tables, in render order."""
    return [
        build_stale_configurations_table(facts, stale_days=stale_days),
        build_language_coverage_table(facts, stale_days=stale_days),
    ]
