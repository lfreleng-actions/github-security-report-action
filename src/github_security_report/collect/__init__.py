# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Collection: gather, classify, and aggregate GitHub security signals.

Ties the transport (:mod:`client`), scoping (:mod:`scope`), classification
(:mod:`classify`) and aggregation (:mod:`report`) together. Both entry points
accept any object satisfying the client protocols in :mod:`collect.protocols`,
so they are testable without a live network.

- :func:`collect_org` -- org mode: one org-bulk sweep per signal, then bounded
  per-repo enabled-probes (:mod:`collect.org`, with the extra reporting tables
  in :mod:`collect.extras`).
- :func:`collect_repo` -- repo mode: per-repository endpoints only
  (:mod:`collect.repo`).

The org-wide evidence shared by every per-repository probe is bundled into
:class:`OrgCollectContext` (:mod:`collect.context`).
"""

from __future__ import annotations

from github_security_report.collect.context import (
    REPO_BATCH,
    OrgCollectContext,
    gather_in_batches,
)
from github_security_report.collect.org import collect_org
from github_security_report.collect.protocols import (
    ClientProtocol,
    RepoClientProtocol,
)
from github_security_report.collect.repo import collect_repo
from github_security_report.collect.scoping import (
    NamedRepos,
    check_named_repos,
)
from github_security_report.config import ReportConfig

# Deprecated: the GraphQL prefetch batch size is ``report.graph_batch`` (config,
# ``--graph-batch``) and adapts at run time; this name is kept for importers of
# the former module constant and mirrors the built-in default.
GRAPH_BATCH = ReportConfig.graph_batch

__all__ = [
    "GRAPH_BATCH",
    "REPO_BATCH",
    "ClientProtocol",
    "OrgCollectContext",
    "RepoClientProtocol",
    "NamedRepos",
    "check_named_repos",
    "collect_org",
    "collect_repo",
    "gather_in_batches",
]
