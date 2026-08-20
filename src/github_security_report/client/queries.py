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

# Organisation membership, collected once per organisation and reused for every
# repository. This is the authoritative, token-independent basis for deciding
# whether a contribution came from outside the organisation.
#
# It cannot be replaced by the per-item ``authorAssociation``: that field is
# computed relative to the viewing token, so an organisation whose members keep
# their membership private (GitHub's default) has them reported as ``MEMBER`` to
# a token with organisation visibility and as ``CONTRIBUTOR``/``NONE`` to one
# without. Collecting membership once costs a single query (measured: 1 point,
# one page per 100 members) and makes the external-contribution counts the same
# whichever token produced the report.
#
# ``membersWithRole`` covers every role, including members whose repository
# access arrives via a team rather than a direct grant -- which is how access is
# normally organised, and why per-repository collaborator enumeration adds
# nothing for most organisations.
_ORG_MEMBERS_QUERY = """
query($org: String!, $after: String) {
  organization(login: $org) {
    membersWithRole(first: 100, after: $after) {
      totalCount
      pageInfo { hasNextPage endCursor }
      nodes { login }
    }
  }
}
"""

# The authenticated account, which is what "mine" means in the assignment
# breakdown. Token-scoped rather than organisation-scoped, but read once per
# organisation run alongside the membership, since both answer "who is who".
_VIEWER_QUERY = """
query {
  viewer { login }
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
# Open pull requests ride the same batched prefetch, and are windowed and
# ordered on the same basis as the issues connection: ``totalCount`` keeps the
# headline exact at any backlog size, while the bounded, oldest-first window
# points the per-PR breakdown (automation, drafts, external, blocked) at the
# most-aged -- so most review-worthy -- pull requests. Measured against a
# five-repository batch, adding this connection together with the head commit's
# check rollup moved the query cost from 1 point to 3, and adds no extra HTTP
# request at all, since it rides a query the run already makes.
_PULL_REQUEST_WINDOW = 25
# GitHub caps an issue or pull request at 10 assignees, so this window is
# exhaustive by construction: unlike the issue-label window, it can never
# truncate, and the assignment breakdown is therefore exact for every collected
# pull request.
_ASSIGNEE_WINDOW = 10
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
      authorAssociation
      author {{ __typename login }}
      labels(first: {_ISSUE_LABEL_WINDOW}) {{ totalCount nodes {{ name }} }}
    }}
  }}
  pullRequests(states: OPEN, first: {_PULL_REQUEST_WINDOW},
               orderBy: {{field: CREATED_AT, direction: ASC}}) {{
    totalCount
    nodes {{
      number
      isDraft
      mergeable
      authorAssociation
      author {{ __typename login }}
      assignees(first: {_ASSIGNEE_WINDOW}) {{ nodes {{ login }} }}
      commits(last: 1) {{
        nodes {{ commit {{ statusCheckRollup {{ state }} }} }}
      }}
    }}
  }}
}}
"""
