# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Metadata for the table categories outside the ranked signals, in render order.

Configuration posture, freshness and workload tables: everything rendered as a
:class:`~github_security_report.report.TableSection` rather than a signal.
"""

from __future__ import annotations

from github_security_report.categories.keys import CategoryKey, CategoryMeta

TABLE_CATEGORIES: dict[CategoryKey, CategoryMeta] = {
    CategoryKey.CODEQL_STALE_CONFIGURATIONS: CategoryMeta(
        key=CategoryKey.CODEQL_STALE_CONFIGURATIONS,
        title="CodeQL: Stale Configurations",
        pass_label="Current",
        fail_label="With stale configurations",
        url=(
            "https://docs.github.com/en/code-security/code-scanning/"
            "managing-your-code-scanning-configuration/about-the-tool-status-page"
        ),
        description=(
            "CodeQL configurations on the default branch whose last scan trails "
            "the branch's newest commit by more than the configured threshold -- "
            "the condition GitHub's tool status page reports as 'Code Scanning "
            "results may be out of date'. Its alerts describe code that has "
            "since changed, so a stale configuration can hold a Results/Findings "
            "row 'Clean' while nothing is being scanned. Setup is Default (GitHub-"
            "managed) or Advanced (a workflow in the repository), and Cause says "
            "why the configuration stopped. Last scan is the newest successful "
            "upload: a configuration whose runs keep failing ages from its last "
            "success, and its cause says so. Orphaned means the setup that "
            "produced it no longer exists, so it will never scan again: once the "
            "live setup covers its language (see Language Coverage), delete it "
            "from the repository's code-scanning tool status page. Superseded "
            "means default setup is on, which blocks advanced CodeQL uploads."
        ),
    ),
    CategoryKey.CODEQL_LANGUAGE_COVERAGE: CategoryMeta(
        key=CategoryKey.CODEQL_LANGUAGE_COVERAGE,
        title="CodeQL: Language Coverage",
        pass_label="Covered",
        fail_label="With unscanned languages",
        url=(
            "https://docs.github.com/en/code-security/code-scanning/"
            "creating-an-advanced-setup-for-code-scanning/"
            "customizing-your-advanced-setup-for-code-scanning"
        ),
        description=(
            "Repositories where GitHub detects a CodeQL-supported language that "
            "no current configuration scans -- typically an advanced workflow "
            "whose language matrix omits one the repository contains, such as "
            "'actions' for its own workflow files. Repositories with no CodeQL "
            "at all appear in the Results/Findings not-enabled list instead. "
            "On default setup GitHub reports only the languages it is set to "
            "scan, so a detected language deliberately left out of default "
            "setup is not visible here."
        ),
    ),
    CategoryKey.DEPENDABOT_ALERTS_ENABLED: CategoryMeta(
        key=CategoryKey.DEPENDABOT_ALERTS_ENABLED,
        title="Dependabot: Alerts Enabled",
        pass_label="Enabled",
        fail_label="Not enabled",
        url=(
            "https://docs.github.com/en/code-security/dependabot/"
            "dependabot-alerts/configuring-dependabot-alerts"
        ),
        description=(
            "Repositories with Dependabot security alerts disabled. Enable "
            "them so vulnerable dependencies surface as alerts."
        ),
    ),
    CategoryKey.DEPENDABOT_UPDATES_ENABLED: CategoryMeta(
        key=CategoryKey.DEPENDABOT_UPDATES_ENABLED,
        title="Dependabot: Security Updates",
        pass_label="Enabled",
        fail_label="Not enabled",
        url=(
            "https://docs.github.com/en/code-security/concepts/"
            "supply-chain-security/dependabot-security-updates"
        ),
        description=(
            "Repositories with Dependabot security updates disabled. Enable "
            "them so fixes for vulnerable dependencies arrive as pull requests "
            "automatically."
        ),
    ),
    CategoryKey.DEPENDABOT_COOLDOWN: CategoryMeta(
        key=CategoryKey.DEPENDABOT_COOLDOWN,
        title="Dependabot: Cooldown Settings",
        pass_label="Enabled",
        fail_label="Without cooldown",
        url=(
            "https://docs.github.com/en/code-security/reference/"
            "supply-chain-security/dependabot-options-reference#cooldown-"
        ),
        description=(
            "Repositories whose Dependabot configuration omits an update "
            "cooldown. A cooldown is mandatory; any cooldown value passes. "
            "Repositories with no Dependabot configuration do not appear here."
        ),
    ),
    CategoryKey.RELEASES: CategoryMeta(
        key=CategoryKey.RELEASES,
        title="Releases / Tagging",
        pass_label="Current",
        fail_label="Overdue",
        url=(
            "https://docs.github.com/en/repositories/"
            "releasing-projects-on-github/about-releases"
        ),
        description=(
            "Repositories ranked by combined release and tag staleness "
            "(oldest first). A repository with neither a release nor a tag "
            "ranks highest."
        ),
    ),
    CategoryKey.MUTABLE_RELEASES: CategoryMeta(
        key=CategoryKey.MUTABLE_RELEASES,
        title="Mutable Releases",
        pass_label="Immutable",
        fail_label="Mutable",
        url=(
            "https://docs.github.com/en/code-security/concepts/"
            "supply-chain-security/immutable-releases"
        ),
        description=(
            "Repositories whose latest or last-published release is mutable. "
            "Republish them as immutable releases so a published artifact "
            "cannot change after the fact."
        ),
    ),
    CategoryKey.PRIVATE_VULNERABILITY_REPORTING: CategoryMeta(
        key=CategoryKey.PRIVATE_VULNERABILITY_REPORTING,
        title="Private Vulnerability Reporting",
        pass_label="Enabled",
        fail_label="Not enabled",
        url=(
            "https://docs.github.com/en/code-security/security-advisories/"
            "working-with-repository-security-advisories/"
            "configuring-private-vulnerability-reporting-for-a-repository"
        ),
        description=(
            "Repositories with private vulnerability reporting disabled. Enable "
            "it so security researchers can privately report vulnerabilities "
            "instead of disclosing them publicly."
        ),
    ),
    CategoryKey.AUTO_MERGE: CategoryMeta(
        key=CategoryKey.AUTO_MERGE,
        title="Auto-merge",
        pass_label="Enabled",
        fail_label="Not enabled",
        url=(
            "https://docs.github.com/en/pull-requests/collaborating-with-"
            "pull-requests/incorporating-changes-from-a-pull-request/"
            "automatically-merging-a-pull-request"
        ),
        description=(
            "Repositories with the 'Allow auto-merge' setting switched off, so "
            "a pull request cannot be queued to merge itself once its "
            "requirements are met. The setting only offers the option: an "
            "auto-merging pull request still waits for the required checks, "
            "reviews and branch protections the repository already enforces, "
            "so enabling it relaxes nothing. What it removes is the interval "
            "between a change becoming mergeable and somebody noticing -- the "
            "window a reviewed dependency update sits in while the "
            "vulnerability it fixes stays unpatched."
        ),
    ),
    CategoryKey.MALWARE_ALERTS: CategoryMeta(
        key=CategoryKey.MALWARE_ALERTS,
        title="Dependabot: Malware Alerts",
        pass_label="Clean",
        fail_label="With malware alerts",
        unknown_label="Alerts off or unreadable",
        url=(
            "https://docs.github.com/en/code-security/concepts/"
            "supply-chain-security/malware-alerts"
        ),
        description=(
            "Open Dependabot alerts for dependencies GitHub's Advisory "
            "Database flags as malicious rather than merely vulnerable, one "
            "row per alert. A malicious package warrants removal, not an "
            "upgrade: there is rarely a safe version to move to, and its code "
            "may already have run wherever it was installed. A repository with "
            "Dependabot alerts off cannot raise one, so it counts as unknown "
            "rather than clean. GitHub's API does not yet expose whether the "
            "malware alerts feature is switched on, so this table shows "
            "findings but not coverage."
        ),
    ),
    CategoryKey.CODE_QUALITY: CategoryMeta(
        key=CategoryKey.CODE_QUALITY,
        title="Code Quality",
        pass_label="Enabled",
        fail_label="Disabled or partial",
        unknown_label="Unreadable",
        url=(
            "https://docs.github.com/en/code-security/concepts/code-quality/"
            "code-quality"
        ),
        description=(
            "Repositories holding a language GitHub Code Quality analyses "
            "(python, go, java-kotlin, javascript-typescript, ruby, csharp, as "
            "GitHub's Linguist classifies them) where Code Quality is off "
            "(Disabled) or configured without one of those languages "
            "(Partial). Missing names the languages to add. A repository with "
            "none of them -- shell scripts and workflow files alone, say -- is "
            "Not applicable and never counted as off. Unreadable counts the "
            "repositories whose setup, or whose languages, could not be read."
        ),
    ),
    CategoryKey.WORKFLOW_FAILURES: CategoryMeta(
        key=CategoryKey.WORKFLOW_FAILURES,
        title="Workflow Failures",
        pass_label="Without failures",
        fail_label="With failures",
        unknown_label="Unreadable",
        url=(
            "https://docs.github.com/en/actions/monitoring-and-troubleshooting-"
            "workflows/monitoring-workflows/viewing-workflow-run-history"
        ),
        description=(
            "Repositories whose GitHub Actions workflows failed in the window, "
            "ranked by failed runs. Runs counts the concluded runs of every "
            "workflow in the repository; Fail % is failed over failed plus "
            "passed, so skipped and cancelled runs (Skipped) never dilute it. "
            "Retried counts runs that passed on a later attempt, a direct sign "
            "of flakiness. Workflows is how many distinct workflows failed, and "
            "Worst workflow the one with the most failures. GitHub-managed "
            "workflows (Dependabot updates, default-setup CodeQL, Copilot "
            "review) are left out unless configured in, since nobody can edit "
            "them. Unreadable counts the repositories whose run listing could "
            "not be read this run; their failures are unknown, not absent."
        ),
    ),
    CategoryKey.WORKFLOW_FAILURES_DETAIL: CategoryMeta(
        key=CategoryKey.WORKFLOW_FAILURES_DETAIL,
        title="Workflow Failures: Detail",
        pass_label="Without failures",
        fail_label="Failing workflows",
        unknown_label="Unreadable",
        url=(
            "https://docs.github.com/en/actions/monitoring-and-troubleshooting-"
            "workflows/troubleshooting-workflows/using-workflow-run-logs"
        ),
        description=(
            "Every workflow that failed in the window, one row per workflow, "
            "with the jobs that failed (and how often each did) linked to "
            "their most recent failed run. Pattern is persistent when the "
            "failure rate is at or above the configured threshold, "
            "intermittent below it, and insufficient with too few runs to "
            "judge. Triggers says what started the failing runs. Reading "
            "isolates where the workflow fails: 'post-merge only' when every "
            "pull-request run passed and only merges or tag pushes fail -- the "
            "integration test that needs credentials a pull request cannot "
            "have -- 'no PR runs' when it never ran on a pull request, and "
            "'everywhere' when pull requests fail too. Matrix legs are folded "
            "into one job name unless configured otherwise."
        ),
    ),
    CategoryKey.GITHUB_ISSUES: CategoryMeta(
        key=CategoryKey.GITHUB_ISSUES,
        title="GitHub Issues",
        pass_label="No open issues",
        # "All No open issues" does not parse; the collapsed line reads
        # "All Clean", matching the other categories' vocabulary.
        pass_all_label="Clean",
        fail_label="With open issues",
        url="https://docs.github.com/en/issues",
        description=(
            "Open issues per repository, split by label into the configured "
            "classes. Issues carrying none of the configured labels count as "
            "Other; issues with no labels at all count as Untriaged, which is "
            "the column to watch -- an unlabelled issue has not been triaged. "
            "Ext counts issues raised from outside the organisation, computed "
            "from the collected window rather than the whole backlog. "
            "Ranked by total open issues, then by Untriaged."
        ),
    ),
    CategoryKey.PULL_REQUESTS: CategoryMeta(
        key=CategoryKey.PULL_REQUESTS,
        title="Pull Requests",
        pass_label="No open pull requests",
        # "All No open pull requests" does not parse; the collapsed line reads
        # "All Clean", matching the other categories' vocabulary.
        pass_all_label="Clean",
        fail_label="With open pull requests",
        url="https://docs.github.com/en/pull-requests",
        description=(
            "Open pull requests per repository, split by who raised them and "
            "what is holding them up. Human and Auto partition the total by "
            "author: Auto counts recognised automation (Dependabot, "
            "pre-commit.ci, Renovate and the like), Human counts everyone "
            "else. Ext counts the human pull requests raised from outside the "
            "organisation, so it is a subset of Human and never counts a bot. "
            "Conflict counts pull requests blocked on a merge conflict; Fail "
            "counts those whose latest checks did not pass, which includes "
            "optional checks and so is not by itself proof that a merge is "
            "blocked; Review counts those a reviewer has asked for changes on, "
            "which is a person waiting on the author; Copilot counts those "
            "still carrying an unresolved review thread opened by GitHub's "
            "automated code reviewer; Draft counts "
            "those still marked as drafts. Those five "
            "are independent of the author split and of each other, so one "
            "pull request can appear in more than one of them. Ranked by total "
            "open pull requests, then by those failing, conflicting or "
            "awaiting review, counted once each. "
            "Beneath the totals, Unassigned counts the pull requests nobody "
            "has picked up; the rest are on somebody's plate. A terminal run "
            "that authenticated as a personal account splits that remainder "
            "again, into the reader's own queue and everyone else's. A "
            "published report leaves that split out, since its readers are not "
            "the account it ran as."
        ),
    ),
    CategoryKey.PULL_REQUESTS_ASSIGNED: CategoryMeta(
        key=CategoryKey.PULL_REQUESTS_ASSIGNED,
        title="Assigned to Me",
        pass_label="None assigned",
        pass_all_label="Clean",
        fail_label="With assigned pull requests",
        url="https://docs.github.com/en/pull-requests",
        description=(
            "The Pull Requests table narrowed to those assigned to the account "
            "this report ran as -- a personal review queue, so it changes with "
            "the token used. Columns carry the same meaning as the table "
            "above. Empty when the account has nothing assigned; a run that "
            "authenticated as a bot or App has no personal queue at all, and "
            "omits this table rather than reporting an empty one."
        ),
    ),
    CategoryKey.GITHUB_ISSUES_ASSIGNED: CategoryMeta(
        key=CategoryKey.GITHUB_ISSUES_ASSIGNED,
        title="Issues: Assigned to Me",
        pass_label="None assigned",
        pass_all_label="Clean",
        fail_label="With assigned issues",
        url="https://docs.github.com/en/issues",
        description=(
            "The GitHub Issues table narrowed to the issues assigned to the "
            "account this report ran as, so it changes with the token used "
            "rather than with any configured name. Columns carry the same "
            "meaning as the GitHub Issues table, but every count, Total "
            "included, covers only the oldest open issues the run collects "
            "per repository: an issue assigned to the account beyond that "
            "window, in a repository with a larger backlog, is not counted, "
            "and such a repository with none of the account's issues inside "
            "the window counts as unknown rather than clean. "
            "A repository with open issues but none assigned to the account "
            "is clean rather than a row of zeros; a run that authenticated "
            "as a bot or App has no personal queue at all, and omits this "
            "table rather than reporting an empty one."
        ),
    ),
}
