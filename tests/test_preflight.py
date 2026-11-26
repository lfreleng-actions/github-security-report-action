# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""The pre-flight checks org-mode ``report`` and ``remediate`` run first."""

from __future__ import annotations

import asyncio
import datetime as dt
import json
import logging
from collections.abc import Sequence
from pathlib import Path

import httpx
import pytest
import respx
from rich.console import Console
from typer.testing import CliRunner

from github_security_report import remediate
from github_security_report.categories import CategoryKey
from github_security_report.cli import app, preflight
from github_security_report.client import GitHubClient
from github_security_report.config import Config, OrgConfig

API = "https://api.github.com"
RATE_LIMIT = f"{API}/rate_limit"

cli = CliRunner()


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    monkeypatch.delenv("GITHUB_OUTPUT", raising=False)
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    """Retry backoff costs these tests no time."""

    async def no_sleep(_delay: float) -> None:
        return None

    monkeypatch.setattr(
        "github_security_report.client.transport.asyncio.sleep", no_sleep
    )


def _limits(core: int = 5000, graphql: int = 5000, reset: int = 0) -> dict:
    return {
        "resources": {
            "core": {"limit": 5000, "used": 0, "remaining": core, "reset": reset},
            "graphql": {"limit": 5000, "used": 0, "remaining": graphql, "reset": reset},
        }
    }


def _mock_probe(headers: dict[str, str] | None = None, **limits: int) -> respx.Route:
    return respx.get(RATE_LIMIT).mock(
        return_value=httpx.Response(200, json=_limits(**limits), headers=headers)
    )


def _mock_listing(
    org: str = "o", response: httpx.Response | None = None
) -> respx.Route:
    return respx.get(url__startswith=f"{API}/orgs/{org}/repos").mock(
        return_value=response if response is not None else httpx.Response(200, json=[])
    )


def _two_orgs() -> Config:
    return Config(organizations=(OrgConfig(name="o"), OrgConfig(name="p")))


async def _check(cfg: Config) -> tuple[int, str]:
    console = Console(record=True, no_color=True, width=200)
    code = await preflight.check_org_run(cfg, ["t"] * len(cfg.organizations), console)
    return code, console.export_text()


# --------------------------------------------------------------------------- #
# Tokens present
# --------------------------------------------------------------------------- #
@respx.mock
def test_every_missing_token_is_reported_before_any_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("MISSING_TOKEN", raising=False)
    monkeypatch.delenv("ALSO_MISSING", raising=False)
    config_data = json.dumps(
        {
            "organizations": [
                {"name": "o"},
                {"name": "p", "token_env": "MISSING_TOKEN"},
                {"name": "q", "token_env": "ALSO_MISSING"},
            ]
        }
    )
    result = cli.invoke(app, ["report", "--config-data", config_data, "--no-color"])
    assert result.exit_code == 2, result.stdout
    assert "No token in $MISSING_TOKEN for p" in result.stdout
    assert "No token in $ALSO_MISSING for q" in result.stdout
    assert not respx.calls


# --------------------------------------------------------------------------- #
# Listing readable
# --------------------------------------------------------------------------- #
@respx.mock
@pytest.mark.parametrize("status", [403, 404])
def test_an_unreadable_listing_aborts_with_nothing_written(
    status: int, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "github_output"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    _mock_probe()
    listing = _mock_listing(
        response=httpx.Response(
            status, json={"message": "nope"}, headers={"X-GitHub-SSO": "required"}
        )
    )
    site = tmp_path / "site"
    result = cli.invoke(
        app, ["report", "--org", "o", "--no-color", "--output-dir", str(site)]
    )
    assert result.exit_code == 5, result.stdout
    text = " ".join(result.stdout.split())
    assert f"HTTP {status} for the repositories of o;" in text
    assert "SSO-authorised" in text
    assert "X-GitHub-SSO: required" in text
    assert "Security report" not in result.stdout
    assert not site.exists()
    assert not output.exists()
    # One page of one repository, not the whole listing.
    assert listing.calls.last.request.url.params["per_page"] == "1"


@respx.mock
def test_a_rate_limited_listing_aborts_as_a_rate_limit() -> None:
    _mock_probe()
    _mock_listing(
        response=httpx.Response(
            403, headers={"x-ratelimit-remaining": "0", "retry-after": "0"}
        )
    )
    result = cli.invoke(app, ["report", "--org", "o", "--no-color"])
    assert result.exit_code == 6, result.stdout
    assert "Rate limit exhausted" in result.stdout


@respx.mock
@pytest.mark.parametrize(
    "message",
    [
        "You have exceeded a secondary rate limit. Please wait a few minutes.",
        "You have triggered an abuse detection mechanism.",
    ],
)
async def test_a_secondary_rate_limit_named_only_in_its_message_exits_6(
    message: str,
) -> None:
    _mock_probe()
    _mock_listing(response=httpx.Response(403, json={"message": message}))
    code, text = await _check(Config(organizations=(OrgConfig(name="o"),)))
    assert code == 6
    text = " ".join(text.split())
    assert "a secondary rate limit" in text
    assert "SSO-authorised" not in text


@respx.mock
async def test_a_rate_limit_abort_gives_the_retry_after_wait_over_the_reset() -> None:
    _mock_probe()
    soon = int((dt.datetime.now(dt.UTC) + dt.timedelta(seconds=30)).timestamp())
    _mock_listing(
        response=httpx.Response(
            403, headers={"retry-after": "120", "x-ratelimit-reset": str(soon)}
        )
    )
    code, text = await _check(Config(organizations=(OrgConfig(name="o"),)))
    assert code == 6
    text = " ".join(text.split())
    assert "(Retry-After: wait 120 second(s))" in text
    assert "resets at" not in text


@respx.mock
async def test_a_rate_limit_abort_waits_for_a_spent_budget_past_retry_after() -> None:
    _mock_probe()
    later = int((dt.datetime.now(dt.UTC) + dt.timedelta(minutes=30)).timestamp())
    _mock_listing(
        response=httpx.Response(
            403,
            headers={
                "retry-after": "60",
                "x-ratelimit-remaining": "0",
                "x-ratelimit-reset": str(later),
            },
        )
    )
    code, text = await _check(Config(organizations=(OrgConfig(name="o"),)))
    assert code == 6
    text = " ".join(text.split())
    assert "resets at " in text
    assert "Retry-After" not in text


@respx.mock
async def test_a_secondary_limit_without_a_wait_advises_a_minute_not_the_reset() -> (
    None
):
    _mock_probe()
    _mock_listing(
        response=httpx.Response(
            403,
            json={"message": "You have exceeded a secondary rate limit."},
            headers={"x-ratelimit-remaining": "4999", "x-ratelimit-reset": "0"},
        )
    )
    code, text = await _check(Config(organizations=(OrgConfig(name="o"),)))
    assert code == 6
    text = " ".join(text.split())
    assert "at least one minute" in text
    assert "resets at" not in text


@respx.mock
@pytest.mark.parametrize(
    "retry_after", ["inf", "1e300", "99999999999999", "nan", "-inf", "-5"]
)
async def test_an_unusable_retry_after_still_aborts_as_a_rate_limit(
    retry_after: str,
) -> None:
    _mock_probe()
    _mock_listing(response=httpx.Response(403, headers={"retry-after": retry_after}))
    code, text = await _check(Config(organizations=(OrgConfig(name="o"),)))
    assert code == 6
    text = " ".join(text.split())
    assert "at least one minute" in text
    assert "Retry-After" not in text


@respx.mock
@pytest.mark.parametrize(
    "response",
    [httpx.Response(503), httpx.Response(200, text="<html>portal</html>")],
)
async def test_a_listing_that_cannot_be_read_aborts_as_a_network_error(
    response: httpx.Response,
) -> None:
    _mock_probe()
    _mock_listing(response=response)
    code, text = await _check(Config(organizations=(OrgConfig(name="o"),)))
    assert code == 3
    assert text.startswith("Network error:")


@respx.mock
@pytest.mark.parametrize(
    "entry",
    [
        {},
        "not a repository",
        {"name": "r"},
        {"name": "", "full_name": "", "html_url": ""},
        {"name": "r", "full_name": " ", "html_url": "https://github.com/o/r"},
    ],
)
async def test_a_listing_entry_without_a_repository_identity_aborts(
    entry: object,
) -> None:
    _mock_probe()
    _mock_listing(response=httpx.Response(200, json=[entry]))
    code, text = await _check(Config(organizations=(OrgConfig(name="o"),)))
    assert code == 3
    assert "an entry that is not a repository" in " ".join(text.split())


@respx.mock
async def test_a_listing_that_spends_the_last_request_aborts_as_a_rate_limit() -> None:
    _mock_probe(core=1)
    repo = {"name": "r", "full_name": "o/r", "html_url": "https://github.com/o/r"}
    _mock_listing(
        response=httpx.Response(
            200,
            json=[repo],
            headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": "0"},
        )
    )
    code, text = await _check(Config(organizations=(OrgConfig(name="o"),)))
    assert code == 6
    text = " ".join(text.split())
    assert "spent the last request of the rate limit" in text
    assert "resets at 1970-01-01 00:00:00 UTC" in text


@respx.mock
async def test_a_healthy_run_is_silent_and_costs_one_request_per_token_and_org(
    caplog: pytest.LogCaptureFixture,
) -> None:
    probe = _mock_probe()
    first, second = _mock_listing("o"), _mock_listing("p")
    with caplog.at_level(logging.WARNING):
        code, text = await _check(_two_orgs())
    assert code == 0
    assert text == ""
    assert not caplog.records
    assert (probe.call_count, first.call_count, second.call_count) == (1, 1, 1)


def _two_tokens() -> str:
    return json.dumps(
        {
            "organizations": [
                {"name": "o", "token_env": "TOKEN_O"},
                {"name": "p", "token_env": "TOKEN_P"},
            ]
        }
    )


def _bearer(request: httpx.Request) -> str:
    return request.headers["Authorization"].removeprefix("Bearer ")


@respx.mock
async def test_distinct_tokens_each_probe_and_list_with_their_own_credential() -> None:
    probe = _mock_probe()
    first, second = _mock_listing("o"), _mock_listing("p")
    cfg = Config(
        organizations=(
            OrgConfig(name="o", token_env="TOKEN_O"),
            OrgConfig(name="p", token_env="TOKEN_P"),
            OrgConfig(name="q", token_env="TOKEN_O"),
        )
    )
    third = _mock_listing("q")
    console = Console(record=True, no_color=True, width=200)
    code = await preflight.check_org_run(cfg, ["to", "tp", "to"], console)
    assert code == 0
    assert [_bearer(call.request) for call in probe.calls] == ["to", "tp"]
    assert [_bearer(call.request) for call in first.calls] == ["to"]
    assert [_bearer(call.request) for call in second.calls] == ["tp"]
    assert [_bearer(call.request) for call in third.calls] == ["to"]


@respx.mock
@pytest.mark.parametrize(
    ("second_probe", "exit_code"),
    [
        (httpx.Response(401), 4),
        (httpx.Response(200, json=_limits(core=0)), 6),
    ],
)
def test_a_bad_second_token_stops_the_run_before_either_org_is_collected(
    second_probe: httpx.Response,
    exit_code: int,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TOKEN_O", "to")
    monkeypatch.setenv("TOKEN_P", "tp")

    def probe_for(request: httpx.Request) -> httpx.Response:
        if _bearer(request) == "tp":
            return second_probe
        return httpx.Response(200, json=_limits())

    respx.get(RATE_LIMIT).mock(side_effect=probe_for)
    _mock_listing("o")
    _mock_listing("p")
    result = cli.invoke(app, ["report", "--config-data", _two_tokens(), "--no-color"])
    assert result.exit_code == exit_code, result.stdout
    assert "Security report" not in result.stdout
    if exit_code == 4:
        assert "rejected: the token in $TOKEN_P" in result.stdout
    # Only pre-flight reads went out: no collection request for either org.
    paths = {call.request.url.path for call in respx.calls}
    assert paths <= {"/rate_limit", "/orgs/o/repos"}, paths


@respx.mock
async def test_an_empty_listing_is_not_a_failure() -> None:
    _mock_probe()
    _mock_listing()
    code, _text = await _check(Config(organizations=(OrgConfig(name="o"),)))
    assert code == 0


# --------------------------------------------------------------------------- #
# Token probe
# --------------------------------------------------------------------------- #
@respx.mock
@pytest.mark.parametrize("resource", ["core", "graphql"])
async def test_a_spent_rate_limit_aborts_naming_the_resource_and_reset(
    resource: str,
) -> None:
    reset = int((dt.datetime.now(dt.UTC) + dt.timedelta(minutes=30)).timestamp())
    _mock_probe(
        reset=reset,
        core=0 if resource == "core" else 5000,
        graphql=0 if resource == "graphql" else 5000,
    )
    listing = _mock_listing()
    code, text = await _check(Config(organizations=(OrgConfig(name="o"),)))
    assert code == 6
    assert f"{resource}: resets at " in text
    assert " UTC (wait 30 minute(s))" in text
    assert listing.call_count == 0


@respx.mock
@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(404),
        httpx.Response(200, text="<html>not json</html>"),
        httpx.Response(200, json=["not", "an", "object"]),
    ],
)
async def test_a_probe_that_cannot_be_read_is_skipped(response: httpx.Response) -> None:
    respx.get(RATE_LIMIT).mock(return_value=response)
    _mock_listing()
    code, text = await _check(Config(organizations=(OrgConfig(name="o"),)))
    assert code == 0
    assert text == ""


@respx.mock
@pytest.mark.parametrize("outcome", [httpx.Response(503), httpx.ReadTimeout("slow")])
async def test_a_failing_probe_is_tried_once_under_a_short_timeout(
    outcome: httpx.Response | Exception,
) -> None:
    probe = respx.get(RATE_LIMIT).mock(side_effect=[outcome])
    listing = _mock_listing()
    code, text = await _check(Config(organizations=(OrgConfig(name="o"),)))
    assert (code, text) == (0, "")
    assert probe.call_count == 1
    timeout = probe.calls.last.request.extensions["timeout"]
    assert timeout["read"] == preflight.PROBE_TIMEOUT_SECONDS
    assert listing.call_count == 1


@respx.mock
async def test_a_probe_that_trickles_past_its_timeout_is_skipped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def never_finishes(_request: httpx.Request) -> httpx.Response:
        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    monkeypatch.setattr(preflight, "PROBE_TIMEOUT_SECONDS", 0.05)
    respx.get(RATE_LIMIT).mock(side_effect=never_finishes)
    listing = _mock_listing()
    cfg = Config(organizations=(OrgConfig(name="o"),))
    code, text = await asyncio.wait_for(_check(cfg), timeout=5)
    assert (code, text) == (0, "")
    assert listing.call_count == 1


# Python before 3.13 raises OverflowError from parsedate_to_datetime for a zone
# offset too large for a timedelta; it is simulated so every version tests it.
_OVERFLOWING_DATE = "Fri, 31 Dec 9999 23:59:59 +99999999999999999999"


@pytest.fixture
def _overflowing_dates(monkeypatch: pytest.MonkeyPatch) -> None:
    def overflow(_value: str) -> dt.datetime:
        raise OverflowError("date value out of range")

    monkeypatch.setattr(
        "github_security_report.client.parsers.parsedate_to_datetime", overflow
    )


@respx.mock
@pytest.mark.usefixtures("_overflowing_dates")
async def test_an_overflowing_retry_after_date_skips_the_probe() -> None:
    respx.get(RATE_LIMIT).mock(
        return_value=httpx.Response(403, headers={"retry-after": _OVERFLOWING_DATE})
    )
    listing = _mock_listing()
    code, text = await _check(Config(organizations=(OrgConfig(name="o"),)))
    assert (code, text) == (0, "")
    assert listing.call_count == 1


@respx.mock
@pytest.mark.usefixtures("_overflowing_dates")
async def test_an_overflowing_retry_after_date_still_aborts_the_listing() -> None:
    _mock_probe()
    _mock_listing(
        response=httpx.Response(403, headers={"retry-after": _OVERFLOWING_DATE})
    )
    code, text = await _check(Config(organizations=(OrgConfig(name="o"),)))
    assert code == 6
    assert "at least one minute" in " ".join(text.split())


@respx.mock
def test_a_rejected_token_still_exits_4() -> None:
    respx.get(RATE_LIMIT).mock(return_value=httpx.Response(401))
    result = cli.invoke(app, ["report", "--org", "o", "--no-color"])
    assert result.exit_code == 4, result.stdout


@respx.mock
@pytest.mark.parametrize(
    ("granted", "missing"),
    [
        ("public_repo, read:org", "'repo' scope: only public repositories"),
        ("read:org", "'security_events' scope: code scanning"),
        ("repo", "'admin:org' scope: organisation membership"),
    ],
)
async def test_a_classic_token_lacking_a_scope_warns_once(
    granted: str, missing: str, caplog: pytest.LogCaptureFixture
) -> None:
    _mock_probe(headers={"X-OAuth-Scopes": granted})
    _mock_listing("o")
    _mock_listing("p")
    with caplog.at_level(logging.WARNING):
        code, _text = await _check(_two_orgs())
    assert code == 0
    messages = [r.getMessage() for r in caplog.records]
    assert sum(missing in m for m in messages) == 1, messages
    assert all(m.startswith("The token in $GITHUB_TOKEN lacks") for m in messages)


def test_every_scope_row_is_met_by_the_recommended_classic_scopes() -> None:
    assert preflight.scope_warnings("repo, security_events, read:org") == []
    assert len(preflight.scope_warnings("")) == len(preflight.SCOPE_REQUIREMENTS)


@respx.mock
async def test_no_scopes_header_means_no_scope_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    _mock_probe()
    _mock_listing()
    with caplog.at_level(logging.WARNING):
        await _check(Config(organizations=(OrgConfig(name="o"),)))
    assert not caplog.records


@respx.mock
@pytest.mark.parametrize(("days", "warns"), [(3, True), (30, False)])
async def test_a_token_expiring_within_a_week_warns(
    days: int, warns: bool, caplog: pytest.LogCaptureFixture
) -> None:
    expires = dt.datetime.now(dt.UTC) + dt.timedelta(days=days, hours=1)
    _mock_probe(
        headers={
            "github-authentication-token-expiration": f"{expires:%Y-%m-%d %H:%M:%S} UTC"
        }
    )
    _mock_listing()
    with caplog.at_level(logging.WARNING):
        await _check(Config(organizations=(OrgConfig(name="o"),)))
    messages = [r.getMessage() for r in caplog.records]
    assert any(f"in {days} day(s)" in m for m in messages) is warns, messages


@respx.mock
@pytest.mark.parametrize("value", ["soon", "9999-12-31 23:59:59 -2359"])
async def test_an_unparsable_expiry_is_ignored(
    value: str, caplog: pytest.LogCaptureFixture
) -> None:
    _mock_probe(headers={"github-authentication-token-expiration": value})
    _mock_listing()
    with caplog.at_level(logging.WARNING):
        code, _text = await _check(Config(organizations=(OrgConfig(name="o"),)))
    assert code == 0
    assert not caplog.records


# --------------------------------------------------------------------------- #
# Remediate
# --------------------------------------------------------------------------- #
@respx.mock
def test_remediate_runs_the_preflight_before_checking_the_selection() -> None:
    probe = _mock_probe()
    listing = _mock_listing(response=httpx.Response(404))
    result = cli.invoke(app, ["remediate", "--org", "o", "--repos", "r", "--no-color"])
    assert result.exit_code == 5, result.stdout
    assert "--repos:" not in result.stdout
    assert (probe.call_count, listing.call_count) == (1, 1)


@respx.mock
@pytest.mark.parametrize(
    ("flags", "label"),
    [
        ([], "the token in $GITHUB_TOKEN\n"),
        (["--token-env", "WRITE_PAT"], "the token in $WRITE_PAT\n"),
    ],
)
def test_remediate_names_its_token_env_when_the_token_is_rejected(
    flags: list[str], label: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WRITE_PAT", "tw")
    respx.get(RATE_LIMIT).mock(return_value=httpx.Response(401))
    result = cli.invoke(app, ["remediate", "--org", "o", *flags, "--no-color"])
    assert result.exit_code == 4, result.stdout
    assert f"rejected: {label}" in result.stdout


@respx.mock
def test_remediate_apply_writes_nothing_when_a_later_org_fails_the_preflight() -> None:
    _mock_probe()
    _mock_listing("o", httpx.Response(200, json=[]))
    _mock_listing("p", httpx.Response(404))
    # Any other request, a write to the first organisation included, is
    # answered and recorded rather than failing the test as unmocked.
    respx.route().mock(return_value=httpx.Response(200, json={}))
    config_data = json.dumps({"organizations": [{"name": "o"}, {"name": "p"}]})
    result = cli.invoke(
        app, ["remediate", "--config-data", config_data, "--apply", "--no-color"]
    )
    assert result.exit_code == 5, result.stdout
    assert all(call.request.method == "GET" for call in respx.calls)
    paths = [call.request.url.path for call in respx.calls]
    assert paths == ["/rate_limit", "/orgs/o/repos", "/orgs/p/repos"], paths


# --------------------------------------------------------------------------- #
# Remediate: can the token write?
# --------------------------------------------------------------------------- #
_NO_WRITE = "could not apply the changes previewed"
_PUBLIC_ONLY = "private repositories cannot be changed"


async def _check_remediate(
    *,
    apply: bool,
    categories: Sequence[CategoryKey] = remediate.DEFAULT_REMEDIABLE,
) -> tuple[int, str]:
    console = Console(record=True, no_color=True, width=200)
    async with GitHubClient("t") as client:
        code = await preflight.check_remediate_run(
            client,
            ["o"],
            console,
            token_envs=["GITHUB_TOKEN"],
            apply=apply,
            categories=categories,
        )
    return code, console.export_text()


@respx.mock
@pytest.mark.parametrize(
    ("granted", "apply", "code", "warning"),
    [
        ("read:org", False, 0, _NO_WRITE),
        ("public_repo, read:org", False, 0, _PUBLIC_ONLY),
        ("public_repo, read:org", True, 0, _PUBLIC_ONLY),
        ("repo", False, 0, None),
        ("repo", True, 0, None),
    ],
)
async def test_remediate_checks_the_classic_token_can_write(
    granted: str,
    apply: bool,
    code: int,
    warning: str | None,
    caplog: pytest.LogCaptureFixture,
) -> None:
    _mock_probe(headers={"X-OAuth-Scopes": granted})
    _mock_listing()
    with caplog.at_level(logging.WARNING):
        result, _text = await _check_remediate(apply=apply)
    assert result == code
    messages = [r.getMessage() for r in caplog.records]
    written = [m for m in messages if _NO_WRITE in m or _PUBLIC_ONLY in m]
    if warning is None:
        assert written == [], messages
    else:
        assert written == [f"The token in $GITHUB_TOKEN lacks {_lacks(warning)}"]
    # A run whose token can write warns about nothing and asks nothing more.
    assert [c.request.url.path for c in respx.calls] == ["/rate_limit", "/orgs/o/repos"]


def _lacks(warning: str) -> str:
    scopes = "'repo' or 'public_repo'" if warning == _NO_WRITE else "'repo'"
    return f"the {scopes} scope: {warning}"


@respx.mock
async def test_remediate_apply_aborts_when_the_classic_token_cannot_write() -> None:
    _mock_probe(headers={"X-OAuth-Scopes": "read:org"})
    listing = _mock_listing()
    code, text = await _check_remediate(apply=True)
    assert code == 2
    text = " ".join(text.split())
    assert "The token in $GITHUB_TOKEN lacks the 'repo' or 'public_repo' scope" in text
    assert listing.call_count == 0


_CLEANUP = CategoryKey.CODEQL_STALE_CONFIGURATIONS


_REENABLES = f"{_CLEANUP.value} (workflow re-enables)"


@respx.mock
@pytest.mark.parametrize(
    ("granted", "categories", "warning"),
    [
        # 'security_events' deletes code scanning analyses, so the cleanup can
        # still write, but not re-enable a workflow, which the warning names.
        (
            "security_events, read:org",
            [_CLEANUP],
            f"lacks the 'repo' or 'public_repo' scope: {_NO_WRITE} in {_REENABLES}",
        ),
        (
            "security_events, read:org",
            [CategoryKey.CODEQL, _CLEANUP],
            "lacks the 'repo' or 'public_repo' scope: "
            f"{_NO_WRITE} in codeql, {_REENABLES}",
        ),
        (
            "public_repo, security_events, read:org",
            [CategoryKey.CODEQL, _CLEANUP],
            f"lacks the 'repo' scope: {_PUBLIC_ONLY} in codeql, {_REENABLES}",
        ),
        (
            "public_repo, read:org",
            [CategoryKey.CODEQL, _CLEANUP],
            f"lacks the 'repo' scope: {_PUBLIC_ONLY}",
        ),
        ("repo", [CategoryKey.CODEQL, _CLEANUP], None),
    ],
)
async def test_remediate_apply_weighs_security_events_for_the_codeql_cleanup(
    granted: str,
    categories: list[CategoryKey],
    warning: str | None,
    caplog: pytest.LogCaptureFixture,
) -> None:
    _mock_probe(headers={"X-OAuth-Scopes": granted})
    _mock_listing()
    with caplog.at_level(logging.WARNING):
        code, _text = await _check_remediate(apply=True, categories=categories)
    assert code == 0
    messages = [r.getMessage() for r in caplog.records]
    written = [m for m in messages if _NO_WRITE in m or _PUBLIC_ONLY in m]
    expected = [] if warning is None else [f"The token in $GITHUB_TOKEN {warning}"]
    assert written == expected


@respx.mock
async def test_remediate_apply_cleanup_aborts_without_security_events() -> None:
    _mock_probe(headers={"X-OAuth-Scopes": "read:org"})
    listing = _mock_listing()
    code, _text = await _check_remediate(apply=True, categories=[_CLEANUP])
    assert code == 2
    assert listing.call_count == 0


@respx.mock
@pytest.mark.parametrize(
    "probe",
    [
        httpx.Response(200, json=_limits()),  # no X-OAuth-Scopes: not classic
        httpx.Response(404),  # the probe is skipped
    ],
)
async def test_remediate_apply_without_scopes_to_read_is_not_checked(
    probe: httpx.Response, caplog: pytest.LogCaptureFixture
) -> None:
    respx.get(RATE_LIMIT).mock(return_value=probe)
    _mock_listing()
    with caplog.at_level(logging.WARNING):
        code, _text = await _check_remediate(apply=True)
    assert code == 0
    assert not caplog.records


@respx.mock
def test_remediate_apply_with_a_token_that_cannot_write_collects_nothing() -> None:
    _mock_probe(headers={"X-OAuth-Scopes": ""})
    respx.route().mock(return_value=httpx.Response(200, json=[]))
    result = cli.invoke(app, ["remediate", "--org", "o", "--apply", "--no-color"])
    assert result.exit_code == 2, result.stdout
    assert "'repo' or 'public_repo' scope" in " ".join(result.stdout.split())
    assert [c.request.url.path for c in respx.calls] == ["/rate_limit"]
