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

import asyncio

import httpx

from github_security_report.client.reads import ReadClient

# Minimum spacing between cleanup mutations. GitHub asks integrations to leave
# at least a second between mutating requests to avoid its secondary rate
# limits, and a cleanup can issue hundreds across many configurations. A class
# attribute so tests can set it to zero.
_MUTATION_INTERVAL_SECONDS = 1.0


class GitHubClient(ReadClient):
    """Thin async client over the GitHub REST + GraphQL APIs."""

    mutation_interval_seconds: float = _MUTATION_INTERVAL_SECONDS
    # Event-loop time of the last paced mutation; None before the first.
    _last_mutation_at: float | None = None

    async def _pace_mutation(self) -> None:
        """Wait until the interval since the previous paced mutation has passed.

        Client-wide rather than per call, so the spacing holds across targets:
        the last deletion of one configuration and the first of the next are
        as far apart as any two within one.
        """
        loop = asyncio.get_running_loop()
        if self._last_mutation_at is not None:
            wait = self._last_mutation_at + self.mutation_interval_seconds - loop.time()
            if wait > 0:
                await asyncio.sleep(wait)
        self._last_mutation_at = loop.time()

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

    async def enable_auto_merge(self, org: str, repo: str) -> tuple[bool, str]:
        """Allow auto-merge on a repository. Returns ``(ok, note)``.

        ``PATCH /repos/{o}/{r}`` with ``allow_auto_merge`` returns the updated
        repository (``200``); any other status is a failure whose note carries
        the status and body. The write only offers the option -- it grants no
        pull request a merge it could not already have had -- but an archived
        repository rejects the patch outright, which is reported as a failure
        rather than retried.
        """
        resp = await self._request(
            "PATCH",
            f"{self._api_url}/repos/{org}/{repo}",
            json={"allow_auto_merge": True},
        )
        ok = resp.status_code == 200
        note = "" if ok else self._write_note(resp)
        await resp.aclose()
        return ok, note

    # ------------------------------------------------------------------ #
    # CodeQL configuration cleanup
    # ------------------------------------------------------------------ #
    async def delete_codeql_analyses(
        self, org: str, repo: str, analysis_ids: tuple[int, ...]
    ) -> tuple[bool, str]:
        """Delete one configuration's analyses, newest first. ``(ok, note)``.

        GitHub deletes a configuration one analysis at a time, and only its
        newest is deletable at any moment, so ``analysis_ids`` must arrive
        newest first. ``confirm_delete`` permits removing the last one, which
        is the point: the configuration itself goes with it.

        The delete response's ``confirm_delete_url`` is documented to chain to
        the next analysis, but in practice returns null while older analyses
        remain, so the ids collected with the report drive the walk instead.

        A ``404`` may mean the analysis is already gone (a previous,
        interrupted run, or the listing lagging behind a deletion), but GitHub
        also answers a token that may not delete with ``404``. So the analysis
        is read back with the same token, which listed it moments ago: gone
        there too means skip it, so a re-run resumes; still readable means the
        delete was refused, and the walk stops with a failure rather than
        reporting a cleanup that never happened. The note reports how many
        were deleted.
        """
        deleted = 0
        for analysis_id in analysis_ids:
            await self._pace_mutation()
            resp = await self._request(
                "DELETE",
                f"{self._api_url}/repos/{org}/{repo}/code-scanning/analyses/{analysis_id}",
                params={"confirm_delete": "true"},
            )
            status = resp.status_code
            stopped = f"stopped after {deleted} of {len(analysis_ids)}"
            if status not in (200, 404):
                note = self._write_note(resp)
                await resp.aclose()
                return False, f"{stopped}: {note}"
            await resp.aclose()
            if status == 404:
                gone = await self._analysis_gone(org, repo, analysis_id)
                if gone is not True:
                    reason = (
                        "delete refused (404) though the analysis still exists; "
                        "check the token can delete code scanning analyses"
                        if gone is False
                        else "could not confirm the analysis was already gone"
                    )
                    return False, f"{stopped}: {reason}"
            deleted += status == 200
        return True, f"{deleted} analyses deleted"

    async def _analysis_gone(
        self, org: str, repo: str, analysis_id: int
    ) -> bool | None:
        """Whether an analysis no longer exists: True gone, False present.

        ``None`` when the read itself fails otherwise, which a caller must not
        mistake for either answer.
        """
        resp = await self._request(
            "GET",
            f"{self._api_url}/repos/{org}/{repo}/code-scanning/analyses/{analysis_id}",
        )
        status = resp.status_code
        await resp.aclose()  # only the status matters here
        if status == 404:
            return True
        if status == 200:
            return False
        return None

    async def enable_workflow(self, org: str, repo: str, path: str) -> tuple[bool, str]:
        """Re-enable the workflow at ``path``. Returns ``(ok, note)``.

        ``PUT .../actions/workflows/{file}/enable`` answers ``204``; the
        workflow is addressed by file name, which the API accepts in place of
        its numeric id.
        """
        name = path.rsplit("/", 1)[-1]
        await self._pace_mutation()
        resp = await self._request(
            "PUT",
            f"{self._api_url}/repos/{org}/{repo}/actions/workflows/{name}/enable",
        )
        ok = resp.status_code == 204
        note = "" if ok else self._write_note(resp)
        await resp.aclose()
        return ok, note
