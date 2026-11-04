# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Contract tests for how ``action.yaml`` chooses and starts Python.

A composite action inherits the caller job's environment, so any uv or Python
start that lets a variable such as ``PATH``, ``UV_PYTHON`` or ``VIRTUAL_ENV``
pick the interpreter runs code the caller's checkout controls. These tests pin
the guarded ``setup-uv`` step and check that every later uv call names one
trusted interpreter by absolute path and every Python start runs isolated.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

ACTION = Path(__file__).resolve().parents[1] / "action.yaml"


def _steps() -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = yaml.safe_load(ACTION.read_text())["runs"]["steps"]
    return steps


def _step(step_id: str) -> dict[str, Any]:
    return next(s for s in _steps() if s.get("id") == step_id)


def _commands() -> list[str]:
    """Every logical shell line the action runs, comments dropped."""
    commands: list[str] = []
    for step in _steps():
        script = step.get("run", "").replace("\\\n", " ")
        for line in script.splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                commands.append(stripped)
    return commands


def test_setup_uv_step_takes_the_guarded_form() -> None:
    step = _step("setup-uv")
    assert step["uses"].startswith("astral-sh/setup-uv@")
    assert step["with"] == {
        "working-directory": "${{ github.action_path }}",
        "tool-bin-dir": "${{ runner.temp }}/github-security-report/bin",
        "enable-cache": False,
    }
    assert step["env"] == {
        "UV_NO_CONFIG": "1",
        "UV_NO_PROJECT": "1",
        "UV_PYTHON_PREFERENCE": "lookup-disabled",
        "UV_PYTHON_ARCH": "",
        "UV_PYTHON_INSTALL_DIR": "${{ runner.temp }}/github-security-report/python",
    }


def test_python_is_installed_with_an_empty_environment() -> None:
    step = _step("python")
    assert step["working-directory"] == "${{ github.action_path }}"
    assert step["env"]["UV"] == "${{ steps.setup-uv.outputs.uv-path }}"
    assert step["env"]["INSTALL_DIR"] == (
        "${{ runner.temp }}/github-security-report/python"
    )
    uv_calls = [c for c in _commands() if '"$UV" python' in c]
    assert len(uv_calls) == 2
    for command in uv_calls:
        assert command.split('"$UV"')[0].endswith('env -i "${clean[@]}" '), command
    assert '"$INSTALL_DIR"/*) ;;' in step["run"]


def test_uv_is_never_looked_up_on_path() -> None:
    bare = re.compile(r"(^|[;&|(]\s*|\$\()(uv|uvx|python3?)\s")
    assert [c for c in _commands() if bare.search(c)] == []


def test_every_uv_call_names_the_trusted_interpreter() -> None:
    commands = [c for c in _commands() if '"$UV"' in c and '"$UV" python' not in c]
    assert commands
    for command in commands:
        assert re.search(r'--python "\$[A-Z_]+[^"]*"', command), command
        assert "--no-config" in command, command
        assert "--system" not in command, command
        assert "--managed-python" not in command, command


def test_tool_runs_isolated_from_the_trusted_environment() -> None:
    script = _step("run")["run"]
    assert "uvx" not in script
    # The caller's PYTHONPATH, PYTHONHOME and active environment are dropped
    # before uv starts any Python, the local-source build backend included.
    assert "PYTHON*|__PYVENV_LAUNCHER__|VIRTUAL_ENV|CONDA_*|UV_PYTHON*|" in script
    assert 'unset "$name"' in script
    assert (
        '"$VENV/bin/python" -I "$VENV/bin/github-security-report" "${args[@]}"'
        in script
    )
