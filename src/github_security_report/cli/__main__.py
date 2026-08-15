# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Support ``python -m github_security_report.cli``.

The console script declared in ``pyproject.toml`` is the usual entry point, but
the module form worked while the CLI was a single module and is preserved here:
a package cannot be executed through the ``if __name__ == "__main__"`` guard in
its ``__init__``, so it needs this file instead.
"""

from __future__ import annotations

from github_security_report.cli.app import app

if __name__ == "__main__":  # pragma: no cover
    app()
