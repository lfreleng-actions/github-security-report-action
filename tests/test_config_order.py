# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Tests for the ``report.order`` configuration block."""

from __future__ import annotations

import pytest

from github_security_report import config
from github_security_report.categories import CategoryKey
from github_security_report.config import (
    DEFAULT_BAU,
    DEFAULT_PRIORITY,
    ConfigError,
    OrderStyle,
)


def _load(order: dict[str, object]) -> config.OrderConfig:
    cfg = config.build_config(
        {"organizations": [{"name": "o"}], "report": {"order": order}}
    )
    return cfg.report.order


class TestDefaults:
    def test_absent_block_is_not_an_error_and_defaults_to_auto(self) -> None:
        cfg = config.build_config({"organizations": [{"name": "o"}]})
        assert cfg.report.order.style is OrderStyle.AUTO
        assert cfg.report.order.priority == DEFAULT_PRIORITY
        assert cfg.report.order.bau == DEFAULT_BAU

    def test_automatic_is_accepted_as_a_spelling_of_auto(self) -> None:
        # The issue that asked for this called the mode "auto/automatic", so
        # both spellings resolve to the one canonical style.
        assert _load({"style": "automatic"}).style is OrderStyle.AUTO

    @pytest.mark.parametrize("style", ["auto", "dual", "single", "fixed"])
    def test_every_documented_style_loads(self, style: str) -> None:
        order: dict[str, object] = {"style": style}
        if style == "single":
            order["sequence"] = ["codeql"]
        assert _load(order).style is OrderStyle(style)


class TestBands:
    def test_dual_reads_both_lists(self) -> None:
        order = _load(
            {
                "style": "dual",
                "priority": ["codeql", "secret_scanning"],
                "bau": ["github_issues"],
            }
        )
        assert order.priority == (CategoryKey.CODEQL, CategoryKey.SECRET_SCANNING)
        assert order.bau == (CategoryKey.GITHUB_ISSUES,)

    def test_an_omitted_band_keeps_the_built_in_one(self) -> None:
        order = _load({"style": "dual", "priority": ["codeql"]})
        assert order.bau == DEFAULT_BAU

    def test_single_reads_its_sequence(self) -> None:
        order = _load({"style": "single", "sequence": ["codeql", "github_issues"]})
        assert order.sequence == (CategoryKey.CODEQL, CategoryKey.GITHUB_ISSUES)


class TestValidation:
    """Each rejection exists because the alternative is a silent surprise."""

    def test_unknown_category_is_rejected(self) -> None:
        with pytest.raises(ConfigError):
            _load({"style": "dual", "priority": ["not_a_category"]})

    def test_unknown_style_is_rejected(self) -> None:
        with pytest.raises(ConfigError):
            _load({"style": "sideways"})

    def test_a_list_the_style_ignores_is_rejected(self) -> None:
        # Writing a priority band and leaving the style at auto asks for a
        # custom band and silently gets the built-in one.
        with pytest.raises(ConfigError, match="does not read"):
            _load({"style": "auto", "priority": ["codeql"]})

    def test_a_sequence_under_dual_is_rejected(self) -> None:
        with pytest.raises(ConfigError, match="does not read"):
            _load({"style": "dual", "sequence": ["codeql"]})

    def test_bands_under_single_are_rejected(self) -> None:
        with pytest.raises(ConfigError, match="does not read"):
            _load({"style": "single", "sequence": ["codeql"], "bau": ["scorecard"]})

    def test_single_without_a_sequence_is_rejected(self) -> None:
        # Without one it is an elaborate way of writing 'fixed', so the config
        # meant something the tool cannot guess.
        with pytest.raises(ConfigError, match="non-empty 'sequence'"):
            _load({"style": "single"})

    def test_a_category_in_both_bands_is_rejected(self) -> None:
        with pytest.raises(ConfigError, match="both"):
            _load(
                {
                    "style": "dual",
                    "priority": ["codeql"],
                    "bau": ["codeql"],
                }
            )

    def test_a_repeated_category_is_rejected(self) -> None:
        with pytest.raises(ConfigError, match="more than once"):
            _load({"style": "dual", "priority": ["codeql", "codeql"]})

    @pytest.mark.parametrize(
        "key",
        [
            "dependabot_alerts_enabled",
            "dependabot_updates_enabled",
            "dependabot_cooldown",
        ],
    )
    def test_a_nested_category_is_rejected(self, key: str) -> None:
        # The Dependabot posture tables render beneath their parent signal and
        # have no position of their own, so accepting one here would validate
        # and then do nothing.
        with pytest.raises(ConfigError):
            _load({"style": "dual", "priority": [key]})


class TestInheritance:
    def test_an_org_inherits_the_global_order(self) -> None:
        cfg = config.build_config(
            {
                "report": {"order": {"style": "fixed"}},
                "organizations": [{"name": "o"}],
            }
        )
        assert cfg.organizations[0].report.order.style is OrderStyle.FIXED

    def test_an_org_can_override_the_global_order(self) -> None:
        cfg = config.build_config(
            {
                "report": {"order": {"style": "fixed"}},
                "organizations": [
                    {"name": "o", "report": {"order": {"style": "auto"}}}
                ],
            }
        )
        assert cfg.report.order.style is OrderStyle.FIXED
        assert cfg.organizations[0].report.order.style is OrderStyle.AUTO

    def test_an_org_inherits_a_band_it_does_not_restate(self) -> None:
        cfg = config.build_config(
            {
                "report": {"order": {"style": "dual", "priority": ["codeql"]}},
                "organizations": [
                    {
                        "name": "o",
                        "report": {"order": {"style": "dual", "bau": ["scorecard"]}},
                    }
                ],
            }
        )
        org_order = cfg.organizations[0].report.order
        assert org_order.priority == (CategoryKey.CODEQL,)
        assert org_order.bau == (CategoryKey.SCORECARD,)

    def test_an_org_may_restate_single_without_repeating_the_sequence(self) -> None:
        # The sequence is inherited, so demanding the org repeat it would
        # contradict the inheritance the rest of the config block offers.
        cfg = config.build_config(
            {
                "report": {"order": {"style": "single", "sequence": ["codeql"]}},
                "organizations": [
                    {"name": "o", "report": {"order": {"style": "single"}}}
                ],
            }
        )
        org_order = cfg.organizations[0].report.order
        assert org_order.style is OrderStyle.SINGLE
        assert org_order.sequence == (CategoryKey.CODEQL,)

    def test_an_org_inherits_single_through_an_empty_order_block(self) -> None:
        cfg = config.build_config(
            {
                "report": {"order": {"style": "single", "sequence": ["codeql"]}},
                "organizations": [{"name": "o", "report": {"order": {}}}],
            }
        )
        assert cfg.organizations[0].report.order.sequence == (CategoryKey.CODEQL,)

    def test_returning_to_auto_restores_the_built_in_bands(self) -> None:
        # 'auto' is defined as the built-in bands and reads no list keys, so it
        # must not inherit a parent's custom ones -- keeping them is the single
        # thing naming 'auto' rules out.
        cfg = config.build_config(
            {
                "report": {
                    "order": {
                        "style": "dual",
                        "priority": ["codeql"],
                        "bau": ["scorecard"],
                    }
                },
                "organizations": [
                    {"name": "o", "report": {"order": {"style": "auto"}}}
                ],
            }
        )
        org_order = cfg.organizations[0].report.order
        assert org_order.style is OrderStyle.AUTO
        assert org_order.priority == DEFAULT_PRIORITY
        assert org_order.bau == DEFAULT_BAU


class TestPriorityDefaults:
    """The built-in bands are the ones the issue asked for."""

    def test_priority_leads_with_the_most_urgent_findings(self) -> None:
        assert DEFAULT_PRIORITY == (
            CategoryKey.SECRET_SCANNING,
            CategoryKey.DEPENDABOT_ALERTS,
            CategoryKey.CODEQL,
            CategoryKey.MUTABLE_RELEASES,
        )

    def test_bau_trails_with_the_always_populated_categories(self) -> None:
        assert DEFAULT_BAU == (
            CategoryKey.SCORECARD,
            CategoryKey.GITHUB_ISSUES,
            CategoryKey.PULL_REQUESTS,
            CategoryKey.PULL_REQUESTS_ASSIGNED,
        )
