# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Shared pytest fixtures."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _isolate_user_config(
    tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Point ``$XDG_CONFIG_HOME`` at an empty temp dir for every test.

    Otherwise ``config.default_config_path()`` would resolve to the developer's
    real ``~/.config/github-security-report/config.json`` and tests that expect
    "no configuration" could pick it up non-deterministically.
    """
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path_factory.mktemp("xdg")))
