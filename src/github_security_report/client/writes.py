# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Remediation writes, and the public :class:`GitHubClient` façade.

``GitHubClient`` completes the linear ``Transport -> OrgReadClient ->
ReadClient -> GitHubClient`` chain. The chain exists so each layer stays a
readable size -- connection/retry mechanics, org-scope reads, per-repository
reads, and remediation writes are separable concerns -- while callers still get
a single object, because one client instance serves both the reporting reads
and the remediation writes.
"""

from __future__ import annotations

import httpx

from github_security_report.client.reads import ReadClient


class GitHubClient(ReadClient):
    """Thin async client over the GitHub REST + GraphQL APIs."""

    # ------------------------------------------------------------------ #
    # Remediation writes (enable a feature on one repository)
    # ------------------------------------------------------------------ #
    @staticmethod
    def _write_note(resp: httpx.Response) -> str:
        """A short ``"<status> <body>"`` note for a failed write (truncated).

        Only the first slice of the body is processed: the body is capped at 80
        characters (after a short numeric status prefix), so normalising the
        whole body -- which may be a large HTML or JSON error page -- would
        allocate for output that is discarded anyway.
        """
        body = " ".join(resp.text[:200].split())
        return f"{resp.status_code} {body[:80]}".strip()

    async def enable_dependabot_alerts(self, org: str, repo: str) -> tuple[bool, str]:
        """Enable Dependabot vulnerability alerts. Returns ``(ok, note)``.

        ``PUT .../vulnerability-alerts`` is idempotent and returns ``204``; any
        other status is a failure whose note carries the status and body.
        """
        resp = await self._request(
            "PUT", f"{self._api_url}/repos/{org}/{repo}/vulnerability-alerts"
        )
        ok = resp.status_code == 204
        note = "" if ok else self._write_note(resp)
        await resp.aclose()
        return ok, note

    async def enable_dependabot_security_updates(
        self, org: str, repo: str
    ) -> tuple[bool, str]:
        """Enable Dependabot security updates. Returns ``(ok, note)``.

        Alerts are the prerequisite, so they are enabled first (idempotent
        ``204``); then ``PUT .../automated-security-fixes`` (``204``). Either
        step failing aborts and returns that step's status note.
        """
        ok, note = await self.enable_dependabot_alerts(org, repo)
        if not ok:
            return False, f"vulnerability-alerts -> {note}"
        resp = await self._request(
            "PUT", f"{self._api_url}/repos/{org}/{repo}/automated-security-fixes"
        )
        fixed = resp.status_code == 204
        fnote = "" if fixed else f"automated-security-fixes -> {self._write_note(resp)}"
        await resp.aclose()
        return fixed, fnote

    async def enable_private_vulnerability_reporting(
        self, org: str, repo: str
    ) -> tuple[bool, str]:
        """Enable private vulnerability reporting (``PUT``, ``204``).

        Returns ``(ok, note)``; a classic PAT needs the ``repo`` scope (write).
        """
        resp = await self._request(
            "PUT",
            f"{self._api_url}/repos/{org}/{repo}/private-vulnerability-reporting",
        )
        ok = resp.status_code == 204
        note = "" if ok else self._write_note(resp)
        await resp.aclose()
        return ok, note

    async def enable_codeql_default_setup(
        self, org: str, repo: str
    ) -> tuple[bool, str]:
        """Enable CodeQL default setup. Returns ``(ok, note)``.

        ``PATCH .../code-scanning/default-setup`` with ``{"state":
        "configured"}`` usually provisions a scan asynchronously and returns
        ``202`` with a run URL, but can also return ``200`` when the update is
        applied synchronously; both are treated as success. A ``202`` means
        "accepted", not "already scanning", so it keeps an async hint.
        Repositories with no CodeQL-supported languages, or with Actions
        disabled, return a 4xx; those are reported as failures but are
        non-fatal to the rest of the run.
        """
        resp = await self._request(
            "PATCH",
            f"{self._api_url}/repos/{org}/{repo}/code-scanning/default-setup",
            json={"state": "configured"},
        )
        ok = resp.status_code in (200, 202)
        if not ok:
            note = self._write_note(resp)
        elif resp.status_code == 202:
            note = "accepted (async)"
        else:
            note = ""
        await resp.aclose()
        return ok, note

    async def enable_secret_scanning(self, org: str, repo: str) -> tuple[bool, str]:
        """Enable secret scanning. Returns ``(ok, note)``.

        ``PATCH /repos/{o}/{r}`` with the repository's ``security_and_analysis``
        block returns the updated repository (``200``); any other status is a
        failure whose note carries the status and body.
        """
        resp = await self._request(
            "PATCH",
            f"{self._api_url}/repos/{org}/{repo}",
            json={
                "security_and_analysis": {
                    "secret_scanning": {"status": "enabled"},
                },
            },
        )
        ok = resp.status_code == 200
        note = "" if ok else self._write_note(resp)
        await resp.aclose()
        return ok, note
