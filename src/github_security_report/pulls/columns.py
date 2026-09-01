# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""The pull-request table's schema: its columns and its aggregate rows.

Names and order for everything the table draws, kept in one place because the
counting, the cell emphasis and the table builder all key off them.
"""

from __future__ import annotations

REPOSITORY_COLUMN = "Repository"
HUMAN_COLUMN = "Human"
AUTOMATION_COLUMN = "Auto"
DRAFT_COLUMN = "Draft"
EXTERNAL_COLUMN = "Ext"
FAILING_COLUMN = "Fail"
CONFLICT_COLUMN = "Conflict"
COPILOT_COLUMN = "Copilot"
TOTAL_COLUMN = "Total"

# Counted columns in render order, framed by the repository and the total.
# Ordered so related columns read together: the author split first, with Ext
# beside Human because it qualifies it (Ext is a subset of Human, never of
# Auto), then the blockers, worst first -- a conflict needs a human to rebase,
# a failing check may only need a re-run, unresolved Copilot feedback needs a
# human but does not hold the merge button down, and a draft is not blocked at
# all.
BREAKDOWN_COLUMNS = (
    HUMAN_COLUMN,
    EXTERNAL_COLUMN,
    AUTOMATION_COLUMN,
    CONFLICT_COLUMN,
    FAILING_COLUMN,
    COPILOT_COLUMN,
    DRAFT_COLUMN,
)

ALL_COLUMNS = (REPOSITORY_COLUMN, *BREAKDOWN_COLUMNS, TOTAL_COLUMN)

# Aggregate rows drawn beneath the totals, splitting the same pull requests by
# who is expected to move them. A partition, not another set of columns: every
# collected pull request falls in exactly one, so the rows sum to the total.
#
# Only ``Unassigned`` is a fact about the pull request. ``Mine`` and ``Others``
# are read relative to the account the report authenticated as, so they exist
# only when that account is a person (see :func:`assignment_rows`) and are
# rendered only on the surface that person reads (see
# ``TableSection.personal_footer_labels``).
UNASSIGNED_ROW = "Unassigned"
OTHERS_ROW = "Others"
MINE_ROW = "Mine"
PERSONAL_ASSIGNMENT_ROWS = (OTHERS_ROW, MINE_ROW)
ASSIGNMENT_ROWS = (UNASSIGNED_ROW, *PERSONAL_ASSIGNMENT_ROWS)

# Marker appended to a repository's total when its open pull requests exceed the
# collected window, so a partial breakdown is visible as such.
TRUNCATED_MARKER = "+"
