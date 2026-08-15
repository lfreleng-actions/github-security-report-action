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
# the newest tag's commit date, latest/recent releases with immutability, the
# raw .github/dependabot.yml, and the open issues, replacing five per-repo
# round-trips.
#
# Two notes on the ``issues`` connection:
#  * GraphQL's ``issues`` excludes pull requests natively, unlike the REST
#    ``/issues`` endpoint which interleaves them, so no PR filtering is needed.
#  * ``orderBy CREATED_AT ASC`` is deliberate: it keeps the oldest issue exact
#    even when a repository has more than ``_ISSUE_WINDOW`` open issues, and it
#    points the bounded window at the most-aged (so most report-worthy) issues
#    rather than the newest ones.
#
# The two window sizes below are a rate-limit decision, not an arbitrary cap.
# GitHub scores a GraphQL query by the nodes it could return, multiplied down
# each level of nesting, then divided by 100 -- so an issues window multiplies
# by its label window. At 100 issues x 20 labels one 118-repository organisation
# costs ~2,650 points of the 5,000-point hourly budget; at 25 x 5 it costs ~220,
# leaving room for the several organisations a single scheduled run covers.
# ``totalCount`` is unaffected by the window, so the reported open-issue total
# stays exact however large a backlog is; only the label breakdown is
# window-scoped. Note that ``GRAPH_BATCH`` is not a lever here: batching changes
# how many requests carry the nodes, not how many nodes are charged for.
# ``totalCount`` is requested on both connections. It costs no nodes, and it is
# what keeps a bounded window honest: the issue total stays exact however large
# a backlog is, and an issue carrying more labels than the label window returned
# can be reported as partially classified rather than silently mislabelled.
_ISSUE_WINDOW = 25
_ISSUE_LABEL_WINDOW = 5
_REPO_GRAPH_FRAGMENT = f"""\
fragment RepoData on Repository {{
  hasVulnerabilityAlertsEnabled
  dependabotConfig: object(expression: "HEAD:.github/dependabot.yml") {{
    ... on Blob {{ text }}
  }}
  tags: refs(refPrefix: "refs/tags/", first: 1,
       orderBy: {{field: TAG_COMMIT_DATE, direction: DESC}}) {{
    nodes {{
      target {{
        __typename
        ... on Commit {{ committedDate }}
        ... on Tag {{ target {{ ... on Commit {{ committedDate }} }} }}
      }}
    }}
  }}
  latestRelease {{
    tagName isLatest isPrerelease isDraft immutable publishedAt createdAt
  }}
  releases(first: 25, orderBy: {{field: CREATED_AT, direction: DESC}}) {{
    nodes {{
      tagName isLatest isPrerelease isDraft immutable publishedAt createdAt
    }}
  }}
  issues(states: OPEN, first: {_ISSUE_WINDOW},
         orderBy: {{field: CREATED_AT, direction: ASC}}) {{
    totalCount
    nodes {{
      number
      title
      createdAt
      labels(first: {_ISSUE_LABEL_WINDOW}) {{ totalCount nodes {{ name }} }}
    }}
  }}
}}
"""
