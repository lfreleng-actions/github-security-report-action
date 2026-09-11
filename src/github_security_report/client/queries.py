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
# ``membersWithRole`` is visibility-filtered rather than access-controlled: a
# token that is not a member of the organisation receives a perfectly valid
# connection containing only the *public* members, with no error and a
# ``totalCount`` filtered to match. Counting that as the membership would report
# every private member as an outsider, so ``viewerIsAMember`` is requested
# alongside it -- it is the only field that distinguishes "these are all the
# members" from "these are the ones you are allowed to see". Members can see
# each other, so a viewer inside the organisation gets the complete list.
_ORG_MEMBERS_QUERY = """
query($org: String!, $after: String) {
  organization(login: $org) {
    viewerIsAMember
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
  viewer { __typename login }
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
# window-scoped. Note that ``report.graph_batch`` is not a lever here: batching
# changes how many requests carry the nodes, not how many nodes are charged for.
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
# check rollup and the assignee list moved the query cost from 1 point to 4, and
# adds no extra HTTP
# request at all, since it rides a query the run already makes.
_PULL_REQUEST_WINDOW = 25
# GitHub caps an issue or pull request at 10 assignees, so this window is
# exhaustive by construction: unlike the issue-label window, it can never
# truncate, and the assignment breakdown is therefore exact for every collected
# pull request.
_ASSIGNEE_WINDOW = 10
# Opinionated reviews inspected per pull request, to tell whose request for
# changes is outstanding. ``reviewDecision`` says *that* changes are requested
# but names nobody, and a GitHub App with pull-request write permission can
# request them exactly as a person can -- so identity needs its own field.
#
# The connection returns at most one review per reviewer, so five covers a pull
# request with five opinionated reviewers rather than five reviews. Measured
# against a 25-repository batch this adds 6 points, which is the cheapest of the
# three windows here by an order of magnitude, and ``totalCount`` rides along
# free to keep it honest.
_OPINIONATED_REVIEW_WINDOW = 5
# Review threads inspected per pull request, to spot outstanding Copilot review
# feedback. This is the most expensive window in the fragment, because it
# multiplies the pull-request window and then again by the one comment needed to
# identify each thread's author (a review thread exposes no author of its own).
#
# Measured against a 25-repository batch, the whole fragment costs 20 points
# without this connection and 57, 89 or 151 with a window of 5, 10 or 20. At 20
# a 118-repository organisation costs ~755 points of the 5,000-point hourly
# budget, which leaves room for the several organisations a scheduled run
# covers.
#
# The window is taken with ``last``, not ``first``, and which end it is anchored
# to decides whether it can answer the question at all. ``reviewThreads`` is
# ordered oldest-first and accepts no ``orderBy``, so ``first`` collects the
# threads a review has already worked through -- exactly the ones most likely to
# have been resolved. A pull request that has answered dozens of rounds and is
# now waiting on the latest would fill the window with settled threads and
# report the outstanding ones as never seen. Unresolved feedback ages into
# resolution rather than the other way round, so the newest threads are where
# the column's answer lives. Same node cost, opposite blind spot.
#
# ``totalCount`` rides along free of node cost and is what keeps the bounded
# window honest -- a pull request carrying more threads than the window returned
# is reported as indeterminate rather than as having nothing outstanding.
_REVIEW_THREAD_WINDOW = 20
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
      reviewDecision
      authorAssociation
      author {{ __typename login }}
      assignees(first: {_ASSIGNEE_WINDOW}) {{ nodes {{ login }} }}
      latestOpinionatedReviews(first: {_OPINIONATED_REVIEW_WINDOW}) {{
        totalCount
        nodes {{ state author {{ __typename login }} }}
      }}
      reviewThreads(last: {_REVIEW_THREAD_WINDOW}) {{
        totalCount
        nodes {{
          isResolved
          comments(first: 1) {{ nodes {{ author {{ __typename login }} }} }}
        }}
      }}
      commits(last: 1) {{
        nodes {{ commit {{ statusCheckRollup {{ state }} }} }}
      }}
    }}
  }}
}}
"""
