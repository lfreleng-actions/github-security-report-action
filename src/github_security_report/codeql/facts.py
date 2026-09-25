# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""The per-repository facts the CodeQL scan-health tables are built from.

GitHub groups code-scanning analyses into *configurations*, one per analysis
``category``. Each configuration's alerts stand until that configuration
uploads again, so one that has stopped uploading keeps presenting results for
code that has since changed. That is what the tool status page means by "Code
Scanning results may be out of date".

A configuration comes from one of two setup types. **Default** setup is managed
by GitHub, and its analyses carry a ``dynamic/github-code-scanning/...``
analysis key. **Advanced** setup is a workflow in the repository, and its
analysis key starts with the workflow file's path. GitHub rejects advanced
CodeQL uploads while default setup is enabled, so the two alternate rather than
coexist. Switching from one to the other leaves the previous setup's
configurations behind, frozen at their last scan.

Everything here is pure. The client gathers the raw payloads and maps them onto
these types (see ``client.codeql_parsers``), and the tables classify them.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType

from github_security_report.models import Repo

# Analysis-key prefix of every analysis uploaded by GitHub-managed default
# setup. Advanced setup keys start with the workflow path instead.
_DEFAULT_SETUP_KEY_PREFIX = "dynamic/github-code-scanning/"
_WORKFLOW_DIR = ".github/workflows/"

# The default-setup API lists some languages individually that CodeQL analyses
# as one extractor (and a configuration names by the combined identifier), so
# both sides are folded onto the combined name before they are compared.
# Without this a repository scanning "javascript-typescript" would be reported
# as leaving "javascript" and "typescript" unscanned.
_LANGUAGE_FAMILIES: Mapping[str, str] = MappingProxyType(
    {
        "javascript": "javascript-typescript",
        "typescript": "javascript-typescript",
        "c": "c-cpp",
        "cpp": "c-cpp",
        "java": "java-kotlin",
        "kotlin": "java-kotlin",
    }
)

# Workflow states the Actions API reports, plus MISSING for a workflow file the
# repository no longer contains (the API answers 404).
WORKFLOW_ACTIVE = "active"
WORKFLOW_DELETED = "deleted"
WORKFLOW_MISSING = "missing"
WORKFLOW_DISABLED_INACTIVITY = "disabled_inactivity"


def normalise_language(language: str) -> str:
    """The CodeQL extractor name for ``language`` (lower-cased, families folded)."""
    lowered = language.strip().lower()
    return _LANGUAGE_FAMILIES.get(lowered, lowered)


class SetupType(str, Enum):
    """Which kind of CodeQL setup produced a configuration."""

    DEFAULT = "Default"
    ADVANCED = "Advanced"


class StaleCause(str, Enum):
    """Why a stale configuration stopped scanning, as far as the API can tell.

    The value is the label the Stale Configurations table shows. The two
    properties are the remediation policy, kept here beside the diagnosis so
    the table and the cleanup plan can never disagree about a configuration.
    """

    # The setup still runs, but its newest attempt errored: never deleted,
    # since fixing the run is what brings the scan back.
    ANALYSES_FAILING = "Analyses failing; check the latest run"
    DEFAULT_SETUP_DISABLED = "Default setup disabled; orphaned"
    LANGUAGE_REMOVED = "Language removed from default setup"
    DEFAULT_SETUP_IDLE = "Default setup not uploading"
    DEFAULT_SETUP_UNREADABLE = "Default setup state unreadable"
    # Neither on nor off: GitHub is evaluating a change, or failed to make one.
    DEFAULT_SETUP_TRANSITIONAL = "Default setup changing state; recheck later"
    WORKFLOW_REMOVED = "Workflow removed; orphaned"
    SUPERSEDED = "Superseded by default setup"
    SUPERSEDED_DISABLED = "Superseded by default setup; workflow disabled"
    WORKFLOW_INACTIVE = "Workflow disabled after inactivity"
    WORKFLOW_DISABLED = "Workflow disabled"
    WORKFLOW_IDLE = "Workflow active, not uploading"
    WORKFLOW_UNREADABLE = "Workflow state unreadable"
    # CodeQL ran outside GitHub Actions; remediate cannot see or reach it.
    EXTERNAL_UPLOADER = "Uploaded outside GitHub Actions; check that pipeline"

    @property
    def orphaned(self) -> bool:
        """Whether the configuration can never upload again as things stand.

        Its setup is gone (default setup off, workflow file removed), blocked
        (advanced uploads are rejected while default setup is on), or no
        longer covers its language. Only these are safe to delete: every other
        cause may yet resume, or needs a person to decide.
        """
        return self in _ORPHANED_CAUSES

    @property
    def reenable_workflow(self) -> bool:
        """Whether re-enabling the workflow is the fix, rather than deleting.

        GitHub disables a scheduled workflow after a spell of repository
        inactivity; that is not a decision anybody made, and undoing it
        restores the scan the configuration belongs to.
        """
        return self is StaleCause.WORKFLOW_INACTIVE


_ORPHANED_CAUSES = frozenset(
    {
        StaleCause.DEFAULT_SETUP_DISABLED,
        StaleCause.LANGUAGE_REMOVED,
        StaleCause.WORKFLOW_REMOVED,
        StaleCause.SUPERSEDED,
        StaleCause.SUPERSEDED_DISABLED,
    }
)


@dataclass(frozen=True)
class CodeQLConfiguration:
    """One CodeQL configuration on the default branch, as of its latest scan."""

    category: str
    analysis_key: str
    # The newest successful upload. None when no upload has ever succeeded:
    # a configuration that has never produced results has never scanned,
    # whatever its attempts' timestamps say.
    last_scan_at: dt.datetime | None
    # The normalised CodeQL language, or None when the analysis names none.
    language: str | None = None
    # True when the newest attempt uploaded an error rather than results.
    failing: bool = False
    # Every analysis in this configuration on the collected ref, newest first.
    # GitHub deletes a configuration one analysis at a time in exactly this
    # order, so remediation needs no second read of the history.
    analysis_ids: tuple[int, ...] = ()

    @property
    def setup(self) -> SetupType:
        """Default setup when GitHub manages the analysis, else advanced."""
        if self.analysis_key.startswith(_DEFAULT_SETUP_KEY_PREFIX):
            return SetupType.DEFAULT
        return SetupType.ADVANCED

    @property
    def workflow_path(self) -> str | None:
        """The advanced workflow file behind this configuration, if any."""
        if self.setup is SetupType.DEFAULT:
            return None
        path = self.analysis_key.partition(":")[0]
        return path if path.startswith(_WORKFLOW_DIR) else None

    def is_stale(self, head_committed_at: dt.datetime, stale_days: int) -> bool:
        """Whether the last scan trails the branch head by over ``stale_days``.

        Measured against the newest commit rather than the clock: a repository
        nobody has pushed to in a year, scanned only on push, is not out of
        date -- nothing it would scan has changed. A configuration that has
        never once succeeded is always stale: measuring a failed attempt
        against the head would let a first run that failed on a quiet
        repository read as current, and its language as covered, forever.
        """
        if self.last_scan_at is None:
            return True
        return head_committed_at - self.last_scan_at > dt.timedelta(days=stale_days)

    @property
    def scan_order(self) -> dt.datetime:
        """The last scan for ordering: a never-successful one sorts oldest."""
        return self.last_scan_at or _NEVER


# Aware sentinel so a configuration that never succeeded sorts ahead of every
# dated one, without comparing a naive and an aware value.
_NEVER = dt.datetime.min.replace(tzinfo=dt.timezone.utc)


@dataclass(frozen=True)
class DefaultSetup:
    """A repository's default-setup state.

    ``languages`` is what GitHub detects as CodeQL-scannable when default setup
    is off, and the languages it is set to scan when default setup is on. So
    for a repository on default setup, a detected language deliberately left
    out of that list is invisible here, and Language Coverage cannot report it.
    No public API reports detection independently of the setup, and the
    alternative inventory (Linguist's repository languages) names no
    ``actions`` and misreads vendored code, so the limit is stated rather than
    papered over.
    """

    configured: bool
    languages: frozenset[str] = frozenset()
    # True when GitHub reports a state other than configured or
    # not-configured (it is evaluating a change, say, or the last change
    # failed). Neither "on" nor "off" can then be assumed.
    transitional: bool = False


@dataclass(frozen=True)
class CodeQLFacts:
    """Everything the scan-health tables need to know about one repository."""

    repo: Repo
    # Status of the analyses read: 200 is a complete read, 404 means code
    # scanning is unavailable, and anything else leaves the state unknown.
    analyses_status: int = 200
    configurations: tuple[CodeQLConfiguration, ...] = ()
    # The default branch head's commit date. None when it could not be read,
    # which leaves every configuration's freshness unknown.
    head_committed_at: dt.datetime | None = None
    # None when the default-setup state could not be read.
    default_setup: DefaultSetup | None = None
    # Workflow path -> Actions workflow state, for the stale advanced
    # configurations whose state was read. An absent path was not read.
    workflow_states: Mapping[str, str] = field(
        default_factory=lambda: MappingProxyType({})
    )

    @property
    def uses_codeql(self) -> bool:
        """Whether CodeQL has ever uploaded to this repository's default branch."""
        return self.analyses_status == 200 and bool(self.configurations)

    @property
    def readable(self) -> bool:
        """Whether the configurations and their freshness could be read in full."""
        return self.analyses_status == 200 and self.head_committed_at is not None

    def stale_configurations(self, stale_days: int) -> list[CodeQLConfiguration]:
        """The configurations trailing the head by over ``stale_days``."""
        head = self.head_committed_at
        if head is None:
            return []
        return [c for c in self.configurations if c.is_stale(head, stale_days)]

    def current_languages(self, stale_days: int) -> frozenset[str]:
        """The languages at least one non-stale configuration still scans."""
        head = self.head_committed_at
        if head is None:
            return frozenset()
        return frozenset(
            c.language
            for c in self.configurations
            if c.language and not c.is_stale(head, stale_days)
        )


@dataclass(frozen=True)
class CodeQLHealth:
    """The collected CodeQL facts, with the threshold they were judged by.

    Kept on the report so remediation plans from exactly the data and the
    threshold the Stale Configurations table was built from, rather than
    re-reading every repository's history or re-deriving the setting.
    """

    facts: tuple[CodeQLFacts, ...]
    stale_days: int
