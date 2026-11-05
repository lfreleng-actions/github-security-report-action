# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""The ``report.order`` block: which category a reader meets first.

The vocabulary and the parser for output ordering, kept together and apart from
the rest of the configuration tree: the validation below is most of what there
is to say about these four keys, and it is meaningless without the styles and
band defaults it validates against.

:mod:`github_security_report.layout` implements what each style does; this
module only decides what an operator is allowed to ask for.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any

from github_security_report.categories import CategoryKey
from github_security_report.config.schema import ConfigError, collecting


class OrderStyle(str, Enum):
    """How the report's section sequence is built.

    See :mod:`github_security_report.layout`, which implements each style.
    """

    AUTO = "auto"
    DUAL = "dual"
    SINGLE = "single"
    FIXED = "fixed"


# Findings worth acting on today, most urgent first: a leaked secret is live
# credential exposure, a malicious dependency is a compromise already in the
# tree, a vulnerable dependency is exploitable now, a code-scanning alert is a
# defect in code we own, and a mutable release is a published artifact that
# can still change under its consumers.
DEFAULT_PRIORITY: tuple[CategoryKey, ...] = (
    CategoryKey.SECRET_SCANNING,
    CategoryKey.MALWARE_FINDINGS,
    CategoryKey.DEPENDABOT_ALERTS,
    CategoryKey.CODEQL,
    CategoryKey.MUTABLE_RELEASES,
)

# Business as usual: categories that carry data on essentially every run. A
# healthy organisation still has open issues, open pull requests and a Scorecard
# score, so none of them is news, and leading with them buries whatever is.
# "Pull Requests: Assigned to Me" follows Pull Requests, and "GitHub Issues:
# Assigned to Me" follows GitHub Issues, because each is the same backlog
# narrowed to one reader.
DEFAULT_BAU: tuple[CategoryKey, ...] = (
    CategoryKey.SCORECARD,
    CategoryKey.GITHUB_ISSUES,
    CategoryKey.GITHUB_ISSUES_ASSIGNED,
    CategoryKey.PULL_REQUESTS,
    CategoryKey.PULL_REQUESTS_ASSIGNED,
)

# Which list keys each style actually reads. A style not listed here reads none.
_READS: Mapping[OrderStyle, tuple[str, ...]] = {
    OrderStyle.AUTO: (),
    OrderStyle.DUAL: ("priority", "bau"),
    OrderStyle.SINGLE: ("sequence",),
    OrderStyle.FIXED: (),
}

_LIST_KEYS = ("priority", "bau", "sequence")


@dataclass(frozen=True)
class OrderConfig:
    """The resolved ``report.order`` block.

    Defaults to the ``auto`` style with the built-in band membership, so a
    configuration that says nothing about ordering still gets the automatic
    layout -- which is the point of making it the default rather than an opt-in.
    """

    style: OrderStyle = OrderStyle.AUTO
    priority: tuple[CategoryKey, ...] = DEFAULT_PRIORITY
    bau: tuple[CategoryKey, ...] = DEFAULT_BAU
    sequence: tuple[CategoryKey, ...] = ()


def _style_from(data: Mapping[str, Any], base: OrderConfig) -> OrderStyle:
    """The requested style, normalising the ``automatic`` spelling."""
    name = str(data.get("style", base.style.value)).strip().lower()
    # "automatic" is the same request spelled out; normalise it rather than
    # carrying two enum members that mean one thing.
    return OrderStyle("auto" if name == "automatic" else name)


def _check_style_reads(data: Mapping[str, Any], style: OrderStyle) -> None:
    """Reject a list key the chosen style ignores.

    Almost always a misunderstanding rather than a harmless extra: an operator
    who writes a ``priority`` list and leaves the style at ``auto`` has asked
    for a custom band and been given the built-in one, silently.

    Reads the block as written rather than the inherited result, because the
    question is what this block asked for. Whether ``single`` ends up with a
    sequence is a separate question, settled against the effective value once
    inheritance has been applied.
    """
    reads = _READS[style]
    ignored = sorted(key for key in _LIST_KEYS if key in data and key not in reads)
    if ignored:
        raise ConfigError(
            f"report.order.style: {style.value!r} does not read "
            f"{', '.join(repr(key) for key in ignored)}; "
            f"it reads {', '.join(repr(key) for key in reads) or 'no list keys'}. "
            "Use style 'dual' for priority/bau lists, or 'single' for a sequence."
        )


def _keys(
    data: Mapping[str, Any], name: str, fallback: tuple[CategoryKey, ...]
) -> tuple[CategoryKey, ...]:
    """One ordering list as category keys, rejecting a repeated entry.

    The schema constrains each item to a known category key, so the conversion
    cannot raise; duplicates it cannot express, and a category listed twice
    would otherwise claim one position and silently lose the other.
    """
    if name not in data:
        return fallback
    raw = [str(item) for item in data[name]]
    seen: set[str] = set()
    for item in raw:
        if item in seen:
            raise ConfigError(
                f"report.order.{name}: lists {item!r} more than once; a category "
                "can hold only one position"
            )
        seen.add(item)
    return tuple(CategoryKey(item) for item in raw)


def order_from(
    data: Mapping[str, Any], base: OrderConfig, *, inherited: bool = True
) -> OrderConfig:
    """Validate and build the ``report.order`` block over an inherited one.

    ``inherited=False`` says ``base`` only stands in for a parent block that
    failed to parse, so a check that reads an inherited value is skipped.

    Every check runs and their findings are raised together: a style that
    does not read a list, a list naming a category twice, and a ``single``
    style without a sequence are independent mistakes. Only a comparison
    whose input failed to parse is skipped.
    """
    style = _style_from(data, base)
    # Without inherited settings and without a style of its own, the block's
    # style is only the default's stand-in: the checks on what that style
    # reads are skipped, but the lists the block sets are still checked.
    placeholder = not inherited and "style" not in data
    problems: list[str] = []
    if not placeholder:
        with collecting(problems):
            _check_style_reads(data, style)
    # ``auto`` is defined as the built-in bands, and it reads no list keys,
    # so it must not inherit them either. Without this, an organisation
    # switching a global ``dual`` back to ``auto`` would silently keep the
    # parent's custom bands -- the one thing naming ``auto`` rules out. Its
    # inherited lists are not compared, but those it writes are still
    # checked for repeats.
    builtin = style is OrderStyle.AUTO and not placeholder
    lists: dict[str, tuple[CategoryKey, ...]] = {}
    for name, fallback in (
        ("priority", base.priority),
        ("bau", base.bau),
        ("sequence", base.sequence),
    ):
        with collecting(problems):
            lists[name] = _keys(data, name, fallback)
    if builtin:
        if problems:
            raise ConfigError(*problems)
        return OrderConfig()
    # Checked against the effective value, not the block as written: an
    # organisation restating `style: single` without repeating the global
    # sequence has inherited a perfectly good one, and rejecting that would
    # contradict the inheritance the rest of the config offers.
    if (
        style is OrderStyle.SINGLE
        and "sequence" in lists
        and not lists["sequence"]
        and (inherited or "sequence" in data)
    ):
        problems.append(
            "report.order.style: 'single' needs a non-empty 'sequence' listing "
            "the categories in the order you want them; without one it is "
            "equivalent to style 'fixed'"
        )
    if "priority" in lists and "bau" in lists:
        overlap = sorted(
            {key.value for key in lists["priority"]}
            & {key.value for key in lists["bau"]}
        )
        if overlap and (inherited or ("priority" in data and "bau" in data)):
            problems.append(
                f"report.order: lists {', '.join(repr(key) for key in overlap)} "
                "in both 'priority' and 'bau'; a category cannot be both the "
                "first thing a reader sees and the last"
            )
    if problems:
        raise ConfigError(*problems)
    priority, bau, sequence = lists["priority"], lists["bau"], lists["sequence"]
    if style is OrderStyle.AUTO:
        return OrderConfig()
    return OrderConfig(
        style=style,
        priority=priority,
        bau=bau,
        sequence=sequence,
    )
