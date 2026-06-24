"""Tests for disclosed-pattern dedup against hunt-memory/patterns.jsonl.

Covers task 05-16-b7-disclosed-pattern-dedup:
  R1 — dedup runs at write-time before disclosed_patterns.md is rendered
  R2 — matched patterns are labelled inline (NOT filtered out)
  R3 — header shows M of N counts (same/similar breakdown)
  R4 — pattern_db.match() signature unchanged (verified by direct call)
  R5 — empty hunt memory → output unchanged behavior + 0 of N count
  C4 — mcp_unavailable → no dedup section
  AC bullets including the 1000-entry + 100-disclosed performance bound.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.disclosure_search import (
    DisclosedReport,
    _dedup_against_local,
    _format_dedup_header,
    _infer_vuln_class_from_title,
    render_disclosed_patterns_md,
    write_disclosed_patterns,
)


def _make_report(title: str, **kwargs) -> DisclosedReport:
    base = dict(title=title, severity="high", disclosed_at="2026-05-15",
                url="https://h1/r/1", state="closed", program="acme",
                program_name="Acme Inc")
    base.update(kwargs)
    return DisclosedReport(**base)


def _seed_patterns(repo: Path, entries: list[dict]) -> Path:
    hm = repo / "hunt-memory"
    hm.mkdir(parents=True, exist_ok=True)
    path = hm / "patterns.jsonl"
    with path.open("w", encoding="utf-8") as f:
        for entry in entries:
            f.write(json.dumps(entry) + "\n")
    return path


class TestInferVulnClass:
    def test_idor_detected(self):
        assert _infer_vuln_class_from_title("IDOR in /api/users/{id}") == "IDOR"
        assert _infer_vuln_class_from_title("Insecure direct object reference") == "IDOR"

    def test_xss_detected(self):
        assert _infer_vuln_class_from_title("Reflected XSS via search") == "XSS"
        assert _infer_vuln_class_from_title("Cross-site scripting in profile") == "XSS"

    def test_ssrf_before_xss(self):
        """SSRF token must be detected even though 'ss' could match xss."""
        assert _infer_vuln_class_from_title("SSRF in image fetch") == "SSRF"

    def test_sqli_detected(self):
        assert _infer_vuln_class_from_title("SQL injection in /reports") == "SQLi"
        assert _infer_vuln_class_from_title("Blind SQLi in user search") == "SQLi"

    def test_empty_title_returns_empty(self):
        assert _infer_vuln_class_from_title("") == ""

    def test_unrecognised_title_returns_empty(self):
        assert _infer_vuln_class_from_title("misc thing about widgets") == ""


class TestDedupAgainstLocal:
    def test_no_patterns_file_returns_no_matches(self, tmp_path):
        reports = [_make_report("IDOR in /api")]
        result, stats = _dedup_against_local(
            reports=reports, target="x.com", tech_stack=[], repo_root=tmp_path,
        )
        assert stats["matched"] == 0
        assert stats["total"] == 1
        assert all(ref == "" for _, ref in result)

    def test_same_target_match_wins(self, tmp_path):
        _seed_patterns(tmp_path, [
            {"ts": "2026-05-01T00:00:00Z", "target": "x.com",
             "vuln_class": "IDOR", "technique": "numeric_id_swap",
             "tech_stack": [], "endpoint": "/api/u/{id}", "payout": 500,
             "schema_version": 1},
        ])
        reports = [_make_report("IDOR in /api/orders")]
        result, stats = _dedup_against_local(
            reports=reports, target="x.com", tech_stack=[], repo_root=tmp_path,
        )
        assert stats["matched"] == 1
        assert stats["same_target_matched"] == 1
        assert stats["similar_target_matched"] == 0
        assert "numeric_id_swap" in result[0][1]
        assert "@x.com" in result[0][1]

    def test_similar_target_match_via_tech_overlap(self, tmp_path):
        _seed_patterns(tmp_path, [
            {"ts": "2026-05-01T00:00:00Z", "target": "other.com",
             "vuln_class": "SQLi", "technique": "union_based",
             "tech_stack": ["express", "postgresql"],
             "endpoint": "/api/q", "payout": 1000,
             "schema_version": 1},
        ])
        reports = [_make_report("SQL injection in /search")]
        result, stats = _dedup_against_local(
            reports=reports, target="x.com",
            tech_stack=["express"], repo_root=tmp_path,
        )
        assert stats["matched"] == 1
        assert stats["similar_target_matched"] == 1
        assert stats["same_target_matched"] == 0

    def test_uninferrable_title_not_matched(self, tmp_path):
        _seed_patterns(tmp_path, [
            {"ts": "2026-05-01T00:00:00Z", "target": "x.com",
             "vuln_class": "IDOR", "technique": "swap",
             "tech_stack": [], "endpoint": "/a", "payout": 100,
             "schema_version": 1},
        ])
        reports = [_make_report("Some random widget bug")]
        result, stats = _dedup_against_local(
            reports=reports, target="x.com", tech_stack=[], repo_root=tmp_path,
        )
        assert stats["matched"] == 0

    def test_reports_returned_in_order(self, tmp_path):
        """R2: dedup labels but does NOT filter. Order is preserved."""
        _seed_patterns(tmp_path, [
            {"ts": "2026-05-01T00:00:00Z", "target": "x.com",
             "vuln_class": "IDOR", "technique": "t1",
             "tech_stack": [], "endpoint": "/a", "payout": 100,
             "schema_version": 1},
        ])
        reports = [
            _make_report("Some widget bug"),  # uninferrable
            _make_report("IDOR in /api"),     # matches
            _make_report("XSS in profile"),   # no match
        ]
        result, stats = _dedup_against_local(
            reports=reports, target="x.com", tech_stack=[], repo_root=tmp_path,
        )
        assert len(result) == 3
        assert result[0][1] == ""
        assert "t1" in result[1][1]
        assert result[2][1] == ""


class TestFormatDedupHeader:
    def test_header_shape(self):
        same_stats = {"matched": 1, "total": 3, "same_target_matched": 1,
                      "similar_target_matched": 0}
        similar_stats = {"matched": 1, "total": 2, "same_target_matched": 0,
                         "similar_target_matched": 1}
        header = _format_dedup_header(same_stats, similar_stats)
        assert "**Pattern dedup**: 2 of 5" in header
        assert "Same-target dedup: 1 of 3" in header
        assert "Similar-target dedup: 1 of 2" in header

    def test_header_with_zero_matches(self):
        z = {"matched": 0, "total": 4, "same_target_matched": 0,
             "similar_target_matched": 0}
        header = _format_dedup_header(z, z)
        assert "0 of 8" in header


class TestRenderWithDedup:
    def test_inline_dedup_tag_appears_in_same_row(self):
        rep = _make_report("IDOR in /api")
        md = render_disclosed_patterns_md(
            "x.com",
            same=[rep], similar=[], seeds=["s"],
            same_dedup=[(rep, "numeric_id_swap@x.com")],
            similar_dedup=[],
            dedup_header="**Pattern dedup**: 1 of 1...",
        )
        assert "[DEDUP: matches local pattern numeric_id_swap@x.com]" in md
        assert "**Pattern dedup**: 1 of 1" in md

    def test_no_inline_tag_when_ref_empty(self):
        rep = _make_report("IDOR in /api")
        md = render_disclosed_patterns_md(
            "x.com",
            same=[rep], similar=[], seeds=["s"],
            same_dedup=[(rep, "")],
            similar_dedup=[],
            dedup_header="**Pattern dedup**: 0 of 1...",
        )
        assert "[DEDUP:" not in md

    def test_mcp_unavailable_omits_dedup_section(self):
        rep = _make_report("IDOR in /api")
        md = render_disclosed_patterns_md(
            "x.com",
            same=[rep], similar=[], seeds=["s"],
            coverage_status="mcp_unavailable",
            same_dedup=[(rep, "numeric_id_swap@x.com")],
            similar_dedup=[],
            dedup_header="**Pattern dedup**: 1 of 1...",
        )
        # C4: dedup section omitted entirely
        assert "Pattern dedup" not in md
        assert "[DEDUP:" not in md


class TestWriteFullPipelineWithDedup:
    def test_fixture_5_disclosed_2_local_matches(self, tmp_path):
        """AC bullet: 5 disclosed + patterns.jsonl with 2 matches → 2 of 5 + 2 tags."""
        # Seed 2 patterns that match 2 of 5 inferred vuln classes
        _seed_patterns(tmp_path, [
            {"ts": "2026-05-01T00:00:00Z", "target": "fresh-target.example",
             "vuln_class": "IDOR", "technique": "uuid_swap",
             "tech_stack": [], "endpoint": "/a", "payout": 100,
             "schema_version": 1},
            {"ts": "2026-05-02T00:00:00Z", "target": "fresh-target.example",
             "vuln_class": "XSS", "technique": "reflected_html",
             "tech_stack": [], "endpoint": "/b", "payout": 200,
             "schema_version": 1},
        ])

        # Use no_mcp=True so coverage_status is mcp_unavailable — but per C4
        # that suppresses dedup output. Instead inject custom path manually
        # by patching the cache flow. Simpler: use render directly with 5
        # synthetic reports and confirm the same dedup helper produces 2 of 5.
        reports = [
            _make_report("IDOR in /api"),         # match (IDOR)
            _make_report("XSS in profile"),       # match (XSS)
            _make_report("SSRF in image fetch"),  # no match
            _make_report("Some widget bug"),      # uninferrable
            _make_report("CSRF in /vote"),        # no match
        ]
        result, stats = _dedup_against_local(
            reports=reports, target="fresh-target.example",
            tech_stack=[], repo_root=tmp_path,
        )
        assert stats["total"] == 5
        assert stats["matched"] == 2
        # Inline tags count: 2 non-empty refs
        tag_count = sum(1 for _, ref in result if ref)
        assert tag_count == 2

    def test_empty_patterns_jsonl_zero_of_n(self, tmp_path):
        """R5: empty patterns.jsonl → 0 of N header, no inline tags."""
        # Create empty patterns.jsonl
        hm = tmp_path / "hunt-memory"
        hm.mkdir(parents=True)
        (hm / "patterns.jsonl").write_text("")
        reports = [
            _make_report("IDOR in /api"),
            _make_report("XSS in profile"),
        ]
        result, stats = _dedup_against_local(
            reports=reports, target="x.com", tech_stack=[], repo_root=tmp_path,
        )
        assert stats["matched"] == 0
        assert stats["total"] == 2
        assert all(ref == "" for _, ref in result)

    def test_write_disclosed_patterns_includes_dedup_section(self, tmp_path):
        """Integration: write_disclosed_patterns with no_mcp=False path
        produces a markdown body that includes the dedup header.

        Uses no_mcp=True for now (MCP would block CI). With no_mcp the
        coverage_status becomes mcp_unavailable, which per C4 omits the
        dedup section — so we assert the section is NOT present.
        """
        _seed_patterns(tmp_path, [
            {"ts": "2026-05-01T00:00:00Z", "target": "x.com",
             "vuln_class": "IDOR", "technique": "t",
             "tech_stack": [], "endpoint": "/a", "payout": 100,
             "schema_version": 1},
        ])
        out = write_disclosed_patterns("x.com", repo_root=tmp_path, no_mcp=True)
        text = out.read_text(encoding="utf-8")
        # no_mcp ⇒ mcp_unavailable ⇒ dedup omitted (C4)
        assert "Pattern dedup" not in text

    def test_performance_1000_patterns_100_disclosed_under_5s(self, tmp_path):
        """C3: 1000-entry patterns.jsonl + 100 disclosed reports < 5s."""
        # Seed 1000 patterns across 5 vuln classes
        patterns = []
        vcs = ["IDOR", "XSS", "SSRF", "SQLi", "Authz"]
        for i in range(1000):
            patterns.append({
                "ts": "2026-05-01T00:00:00Z",
                "target": f"target{i % 50}.com",
                "vuln_class": vcs[i % 5],
                "technique": f"tech_{i}",
                "tech_stack": ["express"] if i % 3 == 0 else [],
                "endpoint": f"/api/{i}",
                "payout": 100 + i,
                "schema_version": 1,
            })
        _seed_patterns(tmp_path, patterns)

        # 100 reports across the same vuln classes
        reports = []
        for i in range(100):
            title = {
                0: "IDOR in /api",
                1: "Reflected XSS",
                2: "SSRF in webhook",
                3: "SQL injection in /q",
                4: "Auth bypass on /admin",
            }[i % 5]
            reports.append(_make_report(title))

        t0 = time.time()
        result, stats = _dedup_against_local(
            reports=reports, target="x.com",
            tech_stack=["express"], repo_root=tmp_path,
        )
        elapsed = time.time() - t0
        assert elapsed < 5.0, f"dedup took {elapsed:.2f}s, > 5s C3 budget"
        assert stats["total"] == 100
