"""Tests for tools/fresh_code.py.

Discipline (PRD C4): tests assert on STRUCTURAL invariants. They do
NOT pin specific subdomain names, commit counts, or changelog text.
Network calls are mocked via monkeypatch on _http_get.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from fresh_code import (
    _detect_github_org,
    _extract_changelog_snippets,
    fetch_ct_log_subdomains,
    fetch_changelog_highlights,
    fetch_github_org_activity,
    render_fresh_code_md,
    write_fresh_code,
)


REPO_ROOT = Path(__file__).resolve().parent.parent


def _mock_http(monkeypatch, response_map: dict):
    """Replace fresh_code._http_get with one that consults response_map.

    response_map: {url_substring: (status, body_bytes)}. First substring
    match wins. Unknown URLs return (0, b'').
    """
    def fake(url, timeout, extra_headers=None):
        for key, value in response_map.items():
            if key in url:
                return value
        return (0, b"")
    monkeypatch.setattr("fresh_code._http_get", fake)


class TestFetchCtLogSubdomains:
    def test_empty_target_returns_error(self):
        result = fetch_ct_log_subdomains("")
        assert result["subdomains"] == []
        assert "error" in result["status"]

    def test_network_failure_returns_error(self, monkeypatch):
        _mock_http(monkeypatch, {})  # all calls fail
        result = fetch_ct_log_subdomains("x.com")
        assert result["subdomains"] == []
        assert "error" in result["status"]

    def test_parses_ct_response(self, monkeypatch):
        # Synthetic crt.sh response: 2 recent, 1 old
        old_date = "2020-01-01"  # well before 90-day cutoff
        from datetime import datetime, timezone, timedelta
        recent_date = (datetime.now(timezone.utc) - timedelta(days=10)).date().isoformat()
        rows = [
            {"not_before": f"{recent_date}T00:00:00", "name_value": "admin.x.com"},
            {"not_before": f"{recent_date}T00:00:00", "name_value": "staging.x.com"},
            {"not_before": f"{old_date}T00:00:00", "name_value": "ancient.x.com"},
        ]
        _mock_http(monkeypatch, {
            "crt.sh": (200, json.dumps(rows).encode("utf-8")),
        })
        result = fetch_ct_log_subdomains("x.com", days=90)
        assert result["status"] == "ok"
        names = [entry["name"] for entry in result["subdomains"]]
        assert "admin.x.com" in names
        assert "staging.x.com" in names
        assert "ancient.x.com" not in names

    def test_wildcard_names_skipped(self, monkeypatch):
        from datetime import datetime, timezone, timedelta
        recent = (datetime.now(timezone.utc) - timedelta(days=5)).date().isoformat()
        rows = [{"not_before": f"{recent}T00:00:00", "name_value": "*.x.com"}]
        _mock_http(monkeypatch, {"crt.sh": (200, json.dumps(rows).encode("utf-8"))})
        result = fetch_ct_log_subdomains("x.com")
        assert result["subdomains"] == []


class TestExtractChangelogSnippets:
    def test_extracts_h2_headings(self):
        html = "<html><h2>2026-05-01 Release</h2><p>foo</p><h2>2026-05-15 Patch</h2></html>"
        snippets = _extract_changelog_snippets(html, days=90)
        # At least one snippet picked up with the heading text
        assert any("2026-05" in s for s in snippets)

    def test_filters_old_dates(self):
        html = "<html><h2>2020-01-01 Old release</h2></html>"
        snippets = _extract_changelog_snippets(html, days=90)
        # 2020 is way older than 90 days ago — filtered
        assert all("2020" not in s for s in snippets)

    def test_ignores_script_style(self):
        html = "<script>foo</script><h2>2026-05-01 Real</h2>"
        snippets = _extract_changelog_snippets(html, days=365 * 10)
        joined = " ".join(snippets)
        assert "Real" in joined
        assert "foo" not in joined


class TestFetchChangelogHighlights:
    def test_empty_target(self):
        result = fetch_changelog_highlights("")
        assert result["highlights"] == []
        assert "error" in result["status"]

    def test_network_failure_returns_empty(self, monkeypatch):
        _mock_http(monkeypatch, {})
        result = fetch_changelog_highlights("x.com")
        assert result["highlights"] == []
        assert result["status"] == "empty"

    def test_parses_changelog_page(self, monkeypatch):
        from datetime import datetime, timezone
        recent_year = datetime.now(timezone.utc).year
        html = f"<html><h2>{recent_year}-04-01 New billing API</h2><h3>{recent_year}-04-15 Webhook v2</h3></html>"
        _mock_http(monkeypatch, {"x.com/changelog": (200, html.encode("utf-8"))})
        result = fetch_changelog_highlights("x.com", days=365 * 2)
        assert result["status"] == "ok"
        assert len(result["highlights"]) >= 1


class TestFetchGithubOrgActivity:
    def test_no_org_returns_no_org(self):
        result = fetch_github_org_activity("")
        assert result["repos"] == []
        assert result["status"] == "no_org"

    def test_rate_limit_handled(self, monkeypatch):
        _mock_http(monkeypatch, {"api.github.com/orgs": (403, b"rate limit")})
        result = fetch_github_org_activity("someorg")
        assert result["status"] == "rate_limited"
        assert result["repos"] == []

    def test_org_404_returns_no_org(self, monkeypatch):
        _mock_http(monkeypatch, {"api.github.com/orgs": (404, b"")})
        result = fetch_github_org_activity("ghostorg")
        assert result["status"] == "no_org"

    def test_parses_repos_and_commits(self, monkeypatch):
        from datetime import datetime, timezone, timedelta
        recent_iso = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        repos = [{
            "name": "platform",
            "full_name": "someorg/platform",
            "pushed_at": recent_iso,
        }]
        commits = [{"sha": "a"}, {"sha": "b"}, {"sha": "c"}]
        _mock_http(monkeypatch, {
            "api.github.com/orgs/someorg/repos": (200, json.dumps(repos).encode("utf-8")),
            "api.github.com/repos/someorg/platform/commits": (200, json.dumps(commits).encode("utf-8")),
        })
        result = fetch_github_org_activity("someorg", days=90)
        assert result["status"] == "ok"
        assert len(result["repos"]) == 1
        assert result["repos"][0]["recent_commits"] == 3
        assert result["repos"][0]["repo"] == "platform"


class TestDetectGithubOrg:
    def test_finds_org_in_business_model(self, tmp_path):
        evidence_dir = tmp_path / "evidence" / "x.com"
        evidence_dir.mkdir(parents=True)
        (evidence_dir / "business_model.md").write_text(
            "# x.com\nSource available at https://github.com/somecompany/platform.\n",
            encoding="utf-8",
        )
        assert _detect_github_org("x.com", tmp_path) == "somecompany"

    def test_finds_org_in_intelligence(self, tmp_path):
        evidence_dir = tmp_path / "evidence" / "x.com"
        evidence_dir.mkdir(parents=True)
        (evidence_dir / "intelligence.md").write_text(
            "Public commits at github.com/AcmeCorp/main\n",
            encoding="utf-8",
        )
        assert _detect_github_org("x.com", tmp_path) == "AcmeCorp"

    def test_no_evidence_returns_empty(self, tmp_path):
        assert _detect_github_org("nothing.com", tmp_path) == ""

    def test_skips_navigation_paths(self, tmp_path):
        evidence_dir = tmp_path / "evidence" / "x.com"
        evidence_dir.mkdir(parents=True)
        (evidence_dir / "business_model.md").write_text(
            "See https://github.com/orgs/foo or https://github.com/search?q=bar",
            encoding="utf-8",
        )
        # 'orgs' / 'search' / etc. are skipped — real org name might still be found
        assert _detect_github_org("x.com", tmp_path) != "orgs"


class TestRenderMarkdown:
    def test_all_three_section_headers_present(self):
        md = render_fresh_code_md(
            "x.com",
            ct={"subdomains": [], "status": "empty"},
            changelog={"highlights": [], "status": "empty"},
            github={"repos": [], "status": "no_org"},
        )
        assert "# Fresh Code (last 90 days) — x.com" in md
        assert "## New subdomains" in md
        assert "## Changelog highlights" in md
        assert "## GitHub recent activity" in md

    def test_empty_buckets_show_helpful_message(self):
        md = render_fresh_code_md(
            "x.com",
            ct={"subdomains": [], "status": "empty"},
            changelog={"highlights": [], "status": "empty"},
            github={"repos": [], "status": "no_org"},
        )
        assert "No new subdomains" in md or "CT log unavailable" in md
        assert "No accessible changelog" in md
        assert "No public GitHub org" in md

    def test_rate_limit_message_explicit(self):
        md = render_fresh_code_md(
            "x.com",
            ct={"subdomains": [], "status": "empty"},
            changelog={"highlights": [], "status": "empty"},
            github={"repos": [], "status": "rate_limited"},
        )
        assert "rate limit" in md.lower()

    def test_populated_buckets_render(self):
        md = render_fresh_code_md(
            "x.com",
            ct={
                "subdomains": [{"name": "admin.x.com", "cert_date": "2026-05-01"}],
                "status": "ok",
            },
            changelog={
                "highlights": [{"url": "https://x.com/changelog", "snippet": "v2 API"}],
                "status": "ok",
            },
            github={
                "repos": [{
                    "repo": "platform", "full_name": "someorg/platform",
                    "recent_commits": 5, "last_commit_date": "2026-05-12",
                }],
                "status": "ok",
            },
        )
        assert "admin.x.com" in md
        assert "v2 API" in md
        assert "someorg/platform" in md


class TestWriteFreshCode:
    def test_no_network_produces_full_shape_document(self, tmp_path):
        out = write_fresh_code("x.com", repo_root=tmp_path, skip_network=True)
        assert out.exists()
        text = out.read_text(encoding="utf-8")
        # All 3 mandatory section headers must be present even in
        # skip-network mode (graceful degradation)
        assert "## New subdomains" in text
        assert "## Changelog highlights" in text
        assert "## GitHub recent activity" in text

    def test_custom_output_path_honored(self, tmp_path):
        custom = tmp_path / "out" / "fresh.md"
        out = write_fresh_code("x.com", repo_root=tmp_path,
                                output_path=custom, skip_network=True)
        assert out == custom
        assert custom.exists()


class TestQuestionToToolDiscoverability:
    """PRD R5 + Contract 6: tool must appear in Q->Tool table."""

    def test_autopilot_md_has_fresh_code_row(self):
        md = (REPO_ROOT / "commands" / "autopilot.md").read_text(encoding="utf-8")
        assert "tools/fresh_code.py" in md

    def test_intel_md_documents_tool_without_auto_run(self):
        md = (REPO_ROOT / "commands" / "intel.md").read_text(encoding="utf-8")
        assert "fresh_code.py" in md
        # And the document explicitly says it's NOT auto-run
        lowered = md.lower()
        assert "not auto-run" in lowered or "does not auto-spawn" in lowered or "claude-invoked" in lowered
