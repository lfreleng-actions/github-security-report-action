# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Shared pytest fixtures."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _isolate_user_config(
    tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Point ``$XDG_CONFIG_HOME`` and ``$XDG_CACHE_HOME`` at empty temp dirs.

    Otherwise ``config.default_config_path()`` would resolve to the developer's
    real ``~/.config/github-security-report/config.json`` and tests that expect
    "no configuration" could pick it up non-deterministically; likewise
    ``config.default_cache_dir()`` would resolve to the real ``~/.cache``, and a
    test opening the run store there could read, or clobber, a real cache.
    """
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path_factory.mktemp("xdg")))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path_factory.mktemp("xdg-cache")))
