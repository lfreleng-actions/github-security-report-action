# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""GraphQL documents and the derived per-repo probe tool list."""

from __future__ import annotations

from github_security_report.models import CODE_SCANNING_TOOLS

_DEPENDABOT_ENABLED_QUERY = """
query($owner: String!, $name: String!) {
  repository(owner: $owner, name: $name) {
    hasVulnerabilityAlertsEnabled
  }
}
"""

# The code-scanning-derived signal tools whose enablement we probe per repo.
# Each is checked via the analyses ``tool_name`` filter (a definitive presence
# test) rather than scanning the analysis history, which a busy repo could push
# a low-frequency tool out of. Derived from the shared signal->tool mapping so
# adding a SARIF-uploading tool needs no client change.
_CODE_SCANNING_SIGNAL_TOOLS = tuple(CODE_SCANNING_TOOLS.values())

# Batched per-repo prefetch: one aliased query fetches Dependabot enablement,
# the newest tag's commit date, latest/recent releases with immutability, and
# the raw .github/dependabot.yml, replacing four per-repo round-trips.
_REPO_GRAPH_FRAGMENT = """\
fragment RepoData on Repository {
  hasVulnerabilityAlertsEnabled
  dependabotConfig: object(expression: "HEAD:.github/dependabot.yml") {
    ... on Blob { text }
  }
  tags: refs(refPrefix: "refs/tags/", first: 1,
       orderBy: {field: TAG_COMMIT_DATE, direction: DESC}) {
    nodes {
      target {
        __typename
        ... on Commit { committedDate }
        ... on Tag { target { ... on Commit { committedDate } } }
      }
    }
  }
  latestRelease {
    tagName isLatest isPrerelease isDraft immutable publishedAt createdAt
  }
  releases(first: 25, orderBy: {field: CREATED_AT, direction: DESC}) {
    nodes {
      tagName isLatest isPrerelease isDraft immutable publishedAt createdAt
    }
  }
}
"""
