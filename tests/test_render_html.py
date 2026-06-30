# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Tests for HTML rendering (Jinja2 + Simple-DataTables)."""

from __future__ import annotations

import datetime as dt

from github_security_report import report
from github_security_report.categories import CategoryKey, category_meta
from github_security_report.models import (
    Repo,
    RepoSignal,
    RepoState,
    SeverityCounts,
    SignalType,
)
from github_security_report.render import html

WHEN = dt.datetime(2026, 6, 16, 9, 0, tzinfo=dt.timezone.utc)


def _repo(name: str) -> Repo:
    return Repo(name, f"o/{name}", f"https://github.com/o/{name}")


def _org(name: str, signals: list[RepoSignal], count: int = 1) -> report.OrgReport:
    return report.build_org_report(name, signals, repo_count=count, generated_at=WHEN)


class TestOrgHtml:
    def test_contains_sections_and_data(self) -> None:
        signals = [
            RepoSignal(
                _repo("bad"),
                SignalType.CODEQL,
                RepoState.OFFENDER,
                SeverityCounts(critical=1),
            ),
            RepoSignal(_repo("nagme"), SignalType.CODEQL, RepoState.NAG),
        ]
        out = html.render_org_html(_org("lfreleng-actions", signals, count=2))
        assert "Security report: lfreleng-actions" in out
        # The decorative heading emoji is hidden from assistive tech.
        assert 'aria-hidden="true"' in out
        assert "CodeQL" in out
        assert '<a href="https://github.com/o/bad">bad</a>' in out
        # The not-enabled repository surfaces in the standardised footer's
        # "Disabled" name list, as a link.
        assert "Disabled" in out
        assert '<a href="https://github.com/o/nagme">nagme</a>' in out

    def test_datatables_pinned_not_latest(self) -> None:
        out = html.render_org_html(_org("o", []))
        assert f"simple-datatables@{html.DATATABLES_VERSION}" in out
        assert "simple-datatables@latest" not in out
        assert "simpleDatatables.DataTable" in out
        # CDN assets carry Subresource Integrity hashes + crossorigin.
        assert f'integrity="{html.DATATABLES_CSS_SRI}"' in out
        assert f'integrity="{html.DATATABLES_JS_SRI}"' in out
        assert 'crossorigin="anonymous"' in out

    def test_html_escaping(self) -> None:
        # A pathological repo name must be escaped, not injected.
        signals = [
            RepoSignal(
                Repo("<x>", "o/<x>", "https://github.com/o/x"),
                SignalType.CODEQL,
                RepoState.OFFENDER,
                SeverityCounts(low=1),
            )
        ]
        out = html.render_org_html(_org("o", signals))
        assert "<x>" not in out.replace(
            "&lt;x&gt;", ""
        )  # only the escaped form appears

    def test_renders_dependabot_subtables_and_releases(self) -> None:
        org = _org("o", [], count=2)
        org.dependabot_tables = [
            report.TableSection(
                category=category_meta(CategoryKey.DEPENDABOT_ALERTS_ENABLED),
                columns=("Repository",),
                rows=[report.TableRow(repo=_repo("off"), cells=())],
                pass_count=5,
                fail_count=1,
            )
        ]
        org.releases = report.TableSection(
            category=category_meta(CategoryKey.RELEASES),
            columns=("Repository", "Last release", "Last tag"),
            rows=[report.TableRow(repo=_repo("stale"), cells=("never", "never"))],
            pass_count=7,
            fail_count=3,
            description="Ranked by combined staleness.",
        )
        out = html.render_org_html(org)
        # Headings are bare; the standardised footer renders as a list below.
        assert "<h3>Dependabot: Alerts Enabled</h3>" in out
        assert "1 Not enabled" in out
        assert "5 Enabled" in out
        assert "kind-fail" in out and "kind-pass" in out
        assert '<a href="https://github.com/o/off">off</a>' in out
        assert "<h2>Releases / Tagging</h2>" in out
        assert "3 Overdue" in out
        assert "7 Current" in out
        assert '<a href="https://github.com/o/stale">stale</a>' in out
        # HTML is a rich surface: the description renders with a reference link.
        assert "Ranked by combined staleness." in out
        assert 'class="desc"' in out

    def test_dependabot_posture_tables_when_parent_hidden(self) -> None:
        # Hiding the parent Dependabot Alerts signal must not drop the
        # independently-toggled posture sub-tables on the HTML surface; an
        # enabled posture table surfaces as its own top-level section instead
        # (matching the terminal/Markdown/Slack renderers, which decouple the
        # posture tables from the parent signal's visibility).
        signals = [
            RepoSignal(
                _repo("dep"),
                SignalType.DEPENDABOT,
                RepoState.OFFENDER,
                SeverityCounts(high=1),
            ),
        ]
        org = _org("o", signals, count=2)
        org.dependabot_tables = [
            report.TableSection(
                category=category_meta(CategoryKey.DEPENDABOT_ALERTS_ENABLED),
                columns=("Repository",),
                rows=[report.TableRow(repo=_repo("off"), cells=())],
                pass_count=5,
                fail_count=1,
            )
        ]

        def show(key: CategoryKey) -> bool:
            return key is not CategoryKey.DEPENDABOT_ALERTS

        out = html.render_org_html(org, show=show)
        # The parent Dependabot Alerts signal is hidden...
        assert "Dependabot: Security Alerts" not in out
        # ...but the enabled posture table still renders, now promoted to a
        # top-level section heading rather than nested as an <h3> sub-table.
        assert "<h2>Dependabot: Alerts Enabled</h2>" in out
        assert '<a href="https://github.com/o/off">off</a>' in out

    def test_renders_mutable_releases_with_summary(self) -> None:
        org = _org("o", [], count=84)
        org.mutable_releases = report.TableSection(
            category=category_meta(CategoryKey.MUTABLE_RELEASES),
            columns=("Repository", "Releases"),
            rows=[report.TableRow(repo=_repo("img"), cells=("v0.1.0 (latest)",))],
            pass_count=82,
            fail_count=2,
        )
        out = html.render_org_html(org)
        assert "<h2>Mutable Releases</h2>" in out
        assert "2 Mutable" in out
        assert "82 Immutable" in out
        assert "kind-fail" in out and "kind-pass" in out
        assert '<a href="https://github.com/o/img">img</a>' in out
        assert "v0.1.0 (latest)" in out

    def test_table_section_no_data_placeholder(self) -> None:
        # No rows and every footer bucket zero must surface a "no data"
        # placeholder, not a bare heading with nothing beneath it.
        org = _org("o", [], count=0)
        org.mutable_releases = report.TableSection(
            category=category_meta(CategoryKey.MUTABLE_RELEASES),
            columns=("Repository", "Releases"),
            rows=[],
        )
        out = html.render_org_html(org)
        assert "<h2>Mutable Releases</h2>" in out
        assert "No data available." in out

    def test_renders_category_description_with_reference_link(self) -> None:
        # HTML shows the per-category description and links to the documentation
        # reference; the description is a single paragraph (not sentence-split).
        org = _org("o", [], count=2)
        org.releases = report.TableSection(
            category=category_meta(CategoryKey.RELEASES),
            columns=("Repository", "Last release"),
            rows=[report.TableRow(repo=_repo("stale"), cells=("never",))],
            fail_count=1,
            description="First sentence here. Second sentence here.",
        )
        out = html.render_org_html(org)
        assert '<p class="desc">First sentence here. Second sentence here.' in out
        meta = category_meta(CategoryKey.RELEASES)
        assert f'href="{meta.url}"' in out

    def test_excluded_repos_in_per_category_footer(self) -> None:
        # The org-level excluded banner is gone; exclusions appear in each
        # category's standardised footer instead.
        org = _org("o", [], count=3)
        org.excluded_repos = [_repo("opted-out")]
        out = html.render_org_html(org)
        assert "excluded-banner" not in out
        assert "1 Excluded" in out
        assert "kind-excluded" in out
        assert '<a href="https://github.com/o/opted-out">opted-out</a>' in out

    def test_offender_table_has_totals_tfoot(self) -> None:
        signals = [
            RepoSignal(
                _repo("a"),
                SignalType.CODEQL,
                RepoState.OFFENDER,
                SeverityCounts(critical=1, high=2, medium=3, low=4),
            ),
            RepoSignal(
                _repo("b"),
                SignalType.CODEQL,
                RepoState.OFFENDER,
                SeverityCounts(critical=1, high=1, medium=1, low=1),
            ),
        ]
        out = html.render_org_html(_org("o", signals, count=2))
        # The totals render in a <tfoot> so DataTables treats them as a footer
        # rather than paginating/sorting them as data.
        assert "<tfoot>" in out
        tfoot = out.split("<tfoot>", 1)[1].split("</tfoot>", 1)[0]
        assert "<td>Total</td>" in tfoot
        for value in ("2", "3", "4", "5", "14"):
            assert f'<td class="num">{value}</td>' in tfoot

    def test_secret_scanning_has_no_totals_tfoot(self) -> None:
        sig = RepoSignal(
            _repo("leaky"),
            SignalType.SECRET_SCANNING,
            RepoState.OFFENDER,
            SeverityCounts(critical=4),
        )
        out = html.render_org_html(_org("o", [sig]))
        assert "<tfoot>" not in out

    def test_severity_cells_right_aligned_posture_cells_not(self) -> None:
        # Severity-count columns are numeric and right-aligned (class="num");
        # posture/freshness columns are textual and must stay left-aligned, so
        # their cells carry no "num" class (a regression guard for the shared
        # render_table macro, which previously forced num on every column).
        signals = [
            RepoSignal(
                _repo("bad"),
                SignalType.CODEQL,
                RepoState.OFFENDER,
                SeverityCounts(high=2),
            ),
        ]
        org = _org("o", signals, count=2)
        org.releases = report.TableSection(
            category=category_meta(CategoryKey.RELEASES),
            columns=("Repository", "Last release", "Last tag"),
            rows=[
                report.TableRow(
                    repo=_repo("stale"), cells=("223 days ago", "223 days ago")
                )
            ],
            fail_count=1,
        )
        out = html.render_org_html(org)
        # Numeric severity cell is right-aligned.
        assert '<td class="num">2</td>' in out
        # Textual release cell is left-aligned (no num class).
        assert '<td class="">223 days ago</td>' in out
        assert '<td class="num">223 days ago</td>' not in out


class TestIndexHtml:
    def test_card_per_org(self) -> None:
        orgs = [_org("alpha", [], count=3), _org("beta", [], count=7)]
        out = html.render_index_html(orgs)
        assert "alpha" in out and "beta" in out
        assert 'href="alpha/report.html"' in out
        assert "3 repositories" in out
        assert "7 repositories" in out

    def test_slugify(self) -> None:
        assert html.slugify("Linux Foundation") == "linux-foundation"

    def test_slugify_strips_path_traversal(self) -> None:
        # A hostile org name must never produce a path separator or ".." that
        # could escape the output directory.
        for hostile in ("../etc", "a/b", "..", "../../x"):
            slug = html.slugify(hostile)
            assert "/" not in slug
            assert ".." not in slug

    def test_slugify_empty_falls_back(self) -> None:
        assert html.slugify("///") == "org"
        assert html.slugify("   ") == "org"
