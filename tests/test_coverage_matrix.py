"""Tests for tools/coverage_matrix.py.

Discipline (PRD C4): tests assert on STRUCTURAL invariants and
ANCHOR fields. They do NOT pin specific endpoint strings, specific
cell counts, or specific vuln-class ordering.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from coverage_matrix import (
    DEFAULT_MIN_WEIGHT,
    STATUS_VALUES,
    VULN_CLASS_ALIASES,
    VULN_CLASSES,
    _canonicalize_endpoint,
    _compute_summary,
    _empty_matrix,
    class_relevance,
    find_high_value_gaps,
    load_matrix,
    mark_cell,
    normalize_vuln_class,
    rebuild_matrix,
    save_matrix,
)


REPO_ROOT = Path(__file__).resolve().parent.parent


def _seed_recon(tmp_path: Path, target: str, urls: list[str]) -> None:
    urls_dir = tmp_path / "recon" / target / "urls"
    urls_dir.mkdir(parents=True)
    (urls_dir / "all.txt").write_text("\n".join(urls), encoding="utf-8")


class TestEmptyMatrix:
    def test_initial_shape(self):
        m = _empty_matrix("x.com")
        assert m["target"] == "x.com"
        assert m["vuln_classes"] == list(VULN_CLASSES)
        assert m["endpoints"] == []
        assert "summary" in m
        assert "last_updated" in m

    def test_load_missing_returns_empty(self, tmp_path):
        m = load_matrix("ghost.com", repo_root=tmp_path)
        assert m["endpoints"] == []
        assert m["target"] == "ghost.com"


class TestCanonicalizeEndpoint:
    def test_strips_query(self):
        assert _canonicalize_endpoint("/api/v1/orders/1?foo=bar") == "/api/v1/orders/1"

    def test_strips_scheme_and_host(self):
        assert _canonicalize_endpoint("https://x.com/api/v1") == "/api/v1"

    def test_empty(self):
        assert _canonicalize_endpoint("") == ""


class TestComputeSummary:
    def test_empty_matrix_zero_totals(self):
        s = _compute_summary({"endpoints": []})
        assert s["total_cells"] == 0
        assert s["high_value_gaps_count"] == 0

    def test_counts_cells_correctly(self):
        matrix = {
            "endpoints": [{
                "endpoint": "/admin/x",
                "weight": 5.0,
                "cells": {
                    "IDOR": {"status": "tested_finding"},
                    "SSRF": {"status": "untested"},
                    "XSS": {"status": "n_a", "reason": "no input"},
                }
            }]
        }
        s = _compute_summary(matrix)
        assert s["total_cells"] == 3
        assert s["tested_finding"] == 1
        assert s["untested"] == 1
        assert s["n_a"] == 1
        # untested cell on weight>=3.0 endpoint -> high_value_gap
        assert s["high_value_gaps_count"] == 1


class TestSaveLoadRoundTrip:
    def test_save_then_load(self, tmp_path):
        m = _empty_matrix("x.com")
        m["endpoints"].append({
            "endpoint": "/api/v1/admin/users",
            "weight": 5.0,
            "cells": {vc: {"status": "untested"} for vc in VULN_CLASSES},
        })
        save_matrix("x.com", m, repo_root=tmp_path)
        loaded = load_matrix("x.com", repo_root=tmp_path)
        assert len(loaded["endpoints"]) == 1
        assert loaded["endpoints"][0]["endpoint"] == "/api/v1/admin/users"

    def test_save_recomputes_summary(self, tmp_path):
        m = _empty_matrix("x.com")
        m["endpoints"].append({
            "endpoint": "/admin/x",
            "weight": 5.0,
            "cells": {
                "IDOR": {"status": "untested"},
                "SSRF": {"status": "untested"},
            },
        })
        save_matrix("x.com", m, repo_root=tmp_path)
        loaded = load_matrix("x.com", repo_root=tmp_path)
        assert loaded["summary"]["untested"] == 2
        assert loaded["summary"]["high_value_gaps_count"] == 2

    def test_save_mutates_caller_summary_in_place(self, tmp_path):
        """Bug fix .trellis/tasks/05-15-fix-stale-summary: save_matrix
        must mutate the caller's matrix dict so `matrix["summary"]`
        immediately after the call reflects on-disk state. A prior
        shallow-copy implementation caused the CLI `rebuild` stdout to
        report a stale summary (e.g. cells=1291) while the on-disk
        file was correct (cells=1935 = 15 × 129)."""
        m = _empty_matrix("x.com")
        m["endpoints"].append({
            "endpoint": "/admin/x",
            "weight": 5.0,
            "cells": {
                "IDOR": {"status": "untested"},
                "SSRF": {"status": "tested_finding"},
                "XSS": {"status": "n_a", "reason": "no input"},
            },
        })
        # Pre-condition: caller's matrix has no summary yet (or stale)
        m["summary"] = {"total_cells": 0, "untested": 0,
                        "tested_finding": 0, "tested_clean": 0,
                        "n_a": 0, "high_value_gaps_count": 0}
        save_matrix("x.com", m, repo_root=tmp_path)
        # After save, the SAME dict reference now has the fresh summary
        assert m["summary"]["total_cells"] == 3
        assert m["summary"]["untested"] == 1
        assert m["summary"]["tested_finding"] == 1
        assert m["summary"]["n_a"] == 1
        # And the on-disk file matches the in-memory dict — no drift
        loaded = load_matrix("x.com", repo_root=tmp_path)
        assert loaded["summary"] == m["summary"]
        # last_updated was also refreshed in place
        assert m["last_updated"] == loaded["last_updated"]


class TestRebuildMatrix:
    def test_rebuild_from_recon_urls(self, tmp_path):
        _seed_recon(tmp_path, "x.com", [
            "/api/v1/admin/users",        # weight high (admin + api_v)
            "/api/v1/orders/123",          # weight (api_v)
            "/blog/post-1",                # weight low — should be skipped at default 1.0
        ])
        matrix = rebuild_matrix("x.com", repo_root=tmp_path)
        endpoints = [ep["endpoint"] for ep in matrix["endpoints"]]
        # High-value paths must be in matrix
        assert "/api/v1/admin/users" in endpoints
        # Low-weight path filtered at default min_weight_to_include=1.0
        assert "/blog/post-1" not in endpoints

    def test_rebuild_creates_all_vuln_class_cells(self, tmp_path):
        _seed_recon(tmp_path, "x.com", ["/api/v1/admin/users"])
        matrix = rebuild_matrix("x.com", repo_root=tmp_path)
        cells = matrix["endpoints"][0]["cells"]
        for vc in VULN_CLASSES:
            assert vc in cells
            assert cells[vc]["status"] == "untested"

    def test_rebuild_preserves_existing_annotations(self, tmp_path):
        _seed_recon(tmp_path, "x.com", ["/api/v1/admin/users"])
        # First rebuild + manual annotation
        matrix = rebuild_matrix("x.com", repo_root=tmp_path)
        matrix["endpoints"][0]["cells"]["XSS"] = {"status": "n_a", "reason": "no input"}
        save_matrix("x.com", matrix, repo_root=tmp_path)
        # Second rebuild — preserve the annotation
        rebuilt = rebuild_matrix("x.com", repo_root=tmp_path)
        save_matrix("x.com", rebuilt, repo_root=tmp_path)
        loaded = load_matrix("x.com", repo_root=tmp_path)
        cell = loaded["endpoints"][0]["cells"]["XSS"]
        assert cell["status"] == "n_a"
        assert cell["reason"] == "no input"

    def test_force_clean_wipes_annotations(self, tmp_path):
        _seed_recon(tmp_path, "x.com", ["/api/v1/admin/users"])
        matrix = rebuild_matrix("x.com", repo_root=tmp_path)
        matrix["endpoints"][0]["cells"]["XSS"] = {"status": "n_a", "reason": "stale"}
        save_matrix("x.com", matrix, repo_root=tmp_path)
        # Force-clean rebuild
        rebuilt = rebuild_matrix("x.com", repo_root=tmp_path, force_clean=True)
        save_matrix("x.com", rebuilt, repo_root=tmp_path)
        loaded = load_matrix("x.com", repo_root=tmp_path)
        # XSS reverted to untested
        assert loaded["endpoints"][0]["cells"]["XSS"]["status"] == "untested"

    def test_no_recon_dir_safe(self, tmp_path):
        matrix = rebuild_matrix("ghost.com", repo_root=tmp_path)
        assert matrix["endpoints"] == []

    def test_findings_mark_tested_finding(self, tmp_path):
        _seed_recon(tmp_path, "x.com", ["/api/v1/orders/123"])
        findings_dir = tmp_path / "findings" / "x.com"
        findings_dir.mkdir(parents=True)
        (findings_dir / "findings.json").write_text(json.dumps([{
            "id": "F-1",
            "endpoint": "/api/v1/orders/123",
            "vuln_class": "IDOR",
        }]), encoding="utf-8")
        matrix = rebuild_matrix("x.com", repo_root=tmp_path)
        ep = [e for e in matrix["endpoints"] if e["endpoint"] == "/api/v1/orders/123"][0]
        assert ep["cells"]["IDOR"]["status"] == "tested_finding"

    def test_rebuild_adds_endpoints_from_findings_only(self, tmp_path):
        """PR-12 audit: an endpoint present ONLY in findings.json (absent
        from recon URLs) must end up in the matrix with `tested_finding`
        on the right cell. Pilot 2026-05-15 surfaced this as a real gap
        — wp-json/* endpoints discovered through working_hypothesis
        exploration never made it into the matrix.
        """
        # Recon contains ONE endpoint only
        _seed_recon(tmp_path, "x.com", ["/api/v1/orders/123"])
        # findings.json adds a SECOND, distinct endpoint not in recon
        findings_dir = tmp_path / "findings" / "x.com"
        findings_dir.mkdir(parents=True)
        (findings_dir / "findings.json").write_text(json.dumps([
            {"id": "F-1", "endpoint": "/api/v1/orders/123", "vuln_class": "IDOR"},
            {"id": "F-2", "endpoint": "/wp-json/wp/v2/users", "vuln_class": "Authz"},
        ]), encoding="utf-8")
        matrix = rebuild_matrix("x.com", repo_root=tmp_path)
        endpoints = {ep["endpoint"] for ep in matrix["endpoints"]}
        # Both endpoints must be present
        assert "/api/v1/orders/123" in endpoints
        assert "/wp-json/wp/v2/users" in endpoints
        # The findings-only endpoint has the right cell marked
        wp_ep = next(ep for ep in matrix["endpoints"] if ep["endpoint"] == "/wp-json/wp/v2/users")
        assert wp_ep["cells"]["Authz"]["status"] == "tested_finding"
        # All vuln_class cells exist on the new endpoint (not just the marked one)
        for vc in VULN_CLASSES:
            assert vc in wp_ep["cells"]

    def test_rebuild_handles_full_url_in_findings(self, tmp_path):
        """A finding's endpoint may be a full URL (https://host/path) —
        canonicalization must strip scheme + host before matrix lookup.
        Otherwise the same logical endpoint creates two distinct rows.
        """
        _seed_recon(tmp_path, "x.com", [])  # no recon URLs
        findings_dir = tmp_path / "findings" / "x.com"
        findings_dir.mkdir(parents=True)
        (findings_dir / "findings.json").write_text(json.dumps([{
            "id": "F-1",
            "endpoint": "https://wp.x.com/wp-json/wp/v2/users",
            "vuln_class": "Authz",
        }]), encoding="utf-8")
        matrix = rebuild_matrix("x.com", repo_root=tmp_path)
        # The endpoint should appear with its canonical path (no scheme/host)
        endpoints = {ep["endpoint"] for ep in matrix["endpoints"]}
        assert "/wp-json/wp/v2/users" in endpoints
        # And the marked cell exists
        ep = next(ep for ep in matrix["endpoints"] if ep["endpoint"] == "/wp-json/wp/v2/users")
        assert ep["cells"]["Authz"]["status"] == "tested_finding"


class TestFindGaps:
    def test_returns_untested_cells_above_threshold(self, tmp_path):
        _seed_recon(tmp_path, "x.com", [
            "/api/v1/admin/users",   # weight high
            "/api/v1/orders/123",     # weight medium
        ])
        matrix = rebuild_matrix("x.com", repo_root=tmp_path)
        save_matrix("x.com", matrix, repo_root=tmp_path)
        gaps = find_high_value_gaps("x.com", repo_root=tmp_path, min_weight=3.0)
        # Every gap has an endpoint, vuln_class, and weight >= 3.0
        for gap in gaps:
            assert "endpoint" in gap
            assert "vuln_class" in gap
            assert gap["weight"] >= 3.0

    def test_filter_respects_min_weight(self, tmp_path):
        _seed_recon(tmp_path, "x.com", ["/api/v1/admin/users", "/api/v1/anything/1"])
        matrix = rebuild_matrix("x.com", repo_root=tmp_path)
        save_matrix("x.com", matrix, repo_root=tmp_path)
        high_only = find_high_value_gaps("x.com", repo_root=tmp_path, min_weight=5.0)
        all_above_1 = find_high_value_gaps("x.com", repo_root=tmp_path, min_weight=1.0)
        # min_weight=5.0 yields fewer-or-equal gaps than min_weight=1.0
        assert len(high_only) <= len(all_above_1)

    def test_empty_matrix_yields_empty_gaps(self, tmp_path):
        gaps = find_high_value_gaps("ghost.com", repo_root=tmp_path, min_weight=3.0)
        assert gaps == []

    def test_semantic_ranking_prioritizes_authz_over_generic_idor(self, tmp_path):
        _seed_recon(tmp_path, "x.com", [
            "https://api.target.com/api/admin/users?isAdmin=true&userId=1001",
        ])
        matrix = rebuild_matrix("x.com", repo_root=tmp_path)
        save_matrix("x.com", matrix, repo_root=tmp_path)

        gaps = find_high_value_gaps("x.com", repo_root=tmp_path, min_weight=3.0)
        endpoint_gaps = [g for g in gaps if g["endpoint"] == "/api/admin/users"]

        assert endpoint_gaps
        assert endpoint_gaps[0]["vuln_class"] == "Authz"
        assert endpoint_gaps[0]["relevance_score"] > 0
        ep = load_matrix("x.com", repo_root=tmp_path)["endpoints"][0]
        assert set(ep["observed_params"]) == {"isAdmin", "userId"}

    @pytest.mark.parametrize(
        ("url", "expected_class"),
        [
            ("https://api.target.com/api/v1/fetch?url=http://127.0.0.1/", "SSRF"),
            ("https://api.target.com/download?file=readme.txt", "Path"),
            ("https://api.target.com/api/render?template=invoice", "RCE"),
            ("https://api.target.com/api/search?q=test&sort=created_at", "SQLi"),
        ],
    )
    def test_semantic_ranking_maps_common_high_value_surfaces(self, tmp_path, url, expected_class):
        _seed_recon(tmp_path, "x.com", [url])
        matrix = rebuild_matrix("x.com", repo_root=tmp_path)
        save_matrix("x.com", matrix, repo_root=tmp_path)

        endpoint = _canonicalize_endpoint(url)
        gaps = [
            g for g in find_high_value_gaps("x.com", repo_root=tmp_path, min_weight=1.0)
            if g["endpoint"] == endpoint
        ]

        assert gaps
        assert gaps[0]["vuln_class"] == expected_class

    def test_class_relevance_is_soft_signal_not_na(self):
        rel = class_relevance("/plain/path", "RCE", [])
        assert rel["relevance_score"] == 0
        assert rel["relevance_reason"] == ""

    def test_sqli_semantics_require_real_query_signals_not_resource_words(self, tmp_path):
        """`select` / `order` 资源名不应单靠路径触发 SQLi 高价值 gap。"""
        _seed_recon(tmp_path, "x.com", [
            "https://api.target.com/rest/order-history",
            "https://api.target.com/address/select",
            "https://api.target.com/rest/products/search?q=test",
        ])
        matrix = rebuild_matrix("x.com", repo_root=tmp_path)
        save_matrix("x.com", matrix, repo_root=tmp_path)

        gaps = find_high_value_gaps("x.com", repo_root=tmp_path, min_weight=3.0)
        gap_pairs = {(gap["endpoint"], gap["vuln_class"]) for gap in gaps}
        top_gap_pairs = {(gap["endpoint"], gap["vuln_class"]) for gap in gaps[:5]}

        assert ("/rest/order-history", "SQLi") not in top_gap_pairs
        assert ("/address/select", "SQLi") not in gap_pairs
        assert ("/rest/products/search", "SQLi") in gap_pairs

        assert class_relevance("/rest/order-history", "SQLi", [])["relevance_score"] == 0
        assert class_relevance("/address/select", "SQLi", [])["relevance_score"] == 0
        assert class_relevance("/rest/products/search", "SQLi", ["q"])["relevance_score"] > 0

    def test_race_semantics_require_state_transition_not_state_resource_words(self, tmp_path):
        """`order` / `balance` 资源名不应单靠路径触发 Race 高价值 gap。"""
        _seed_recon(tmp_path, "x.com", [
            "https://api.target.com/rest/order-history",
            "https://api.target.com/rest/track-order",
            "https://api.target.com/rest/wallet/balance",
            "https://api.target.com/api/cart/checkout",
            "https://api.target.com/api/payment/confirm?coupon=SAVE10",
        ])
        matrix = rebuild_matrix("x.com", repo_root=tmp_path)
        save_matrix("x.com", matrix, repo_root=tmp_path)

        gaps = find_high_value_gaps("x.com", repo_root=tmp_path, min_weight=3.0)
        gap_pairs = {(gap["endpoint"], gap["vuln_class"]) for gap in gaps}

        assert ("/rest/order-history", "Race") not in gap_pairs
        assert ("/rest/track-order", "Race") not in gap_pairs
        assert ("/rest/wallet/balance", "Race") not in gap_pairs
        assert ("/api/cart/checkout", "Race") in gap_pairs
        assert ("/api/payment/confirm", "Race") in gap_pairs

        assert class_relevance("/rest/order-history", "Race", [])["relevance_score"] == 0
        assert class_relevance("/rest/track-order", "Race", [])["relevance_score"] == 0
        assert class_relevance("/rest/wallet/balance", "Race", [])["relevance_score"] == 0
        assert class_relevance("/api/cart/checkout", "Race", [])["relevance_score"] > 0
        assert class_relevance("/api/orders", "Race", ["coupon"])["relevance_score"] > 0


class TestMarkCell:
    def test_mark_creates_endpoint_if_missing(self, tmp_path):
        cell = mark_cell(
            "x.com", "/admin/x", "IDOR", "n_a",
            reason="read-only resource",
            repo_root=tmp_path,
        )
        assert cell["status"] == "n_a"
        loaded = load_matrix("x.com", repo_root=tmp_path)
        # endpoint now exists
        ep = [e for e in loaded["endpoints"] if e["endpoint"] == "/admin/x"][0]
        assert ep["cells"]["IDOR"]["status"] == "n_a"
        assert ep["cells"]["IDOR"]["reason"] == "read-only resource"

    def test_mark_overwrites_existing(self, tmp_path):
        mark_cell("x.com", "/admin/x", "IDOR", "untested", repo_root=tmp_path)
        mark_cell("x.com", "/admin/x", "IDOR", "tested_clean", repo_root=tmp_path)
        loaded = load_matrix("x.com", repo_root=tmp_path)
        ep = loaded["endpoints"][0]
        assert ep["cells"]["IDOR"]["status"] == "tested_clean"

    def test_invalid_vuln_class_rejected(self, tmp_path):
        with pytest.raises(ValueError):
            mark_cell("x.com", "/admin/x", "Bogus", "untested", repo_root=tmp_path)

    def test_invalid_status_rejected(self, tmp_path):
        with pytest.raises(ValueError):
            mark_cell("x.com", "/admin/x", "IDOR", "bogus", repo_root=tmp_path)

    def test_mark_with_write_finding_appends_to_findings_json(self, tmp_path):
        """PR-12: when mark with status=tested_finding and write_finding=True,
        the cell ALSO appears in findings/<target>/findings.json so a
        future rebuild_matrix re-ingests it. Closes the pilot-flow gap
        where mark_cell calls were lost on rebuild.
        """
        mark_cell(
            "x.com", "/wp-json/wp/v2/users", "Authz", "tested_finding",
            reason="user enum verified",
            repo_root=tmp_path,
            write_finding=True,
        )
        findings_path = tmp_path / "findings" / "x.com" / "findings.json"
        assert findings_path.is_file()
        data = json.loads(findings_path.read_text(encoding="utf-8"))
        assert isinstance(data, list)
        entry = next(e for e in data if e["endpoint"] == "/wp-json/wp/v2/users")
        assert entry["vuln_class"] == "Authz"
        assert entry["reason"] == "user enum verified"
        assert entry["source"] == "mark_cell"

    def test_write_finding_idempotent(self, tmp_path):
        """Repeated mark_cell with write_finding=True must not duplicate."""
        for _ in range(3):
            mark_cell(
                "x.com", "/wp-json/wp/v2/users", "Authz", "tested_finding",
                reason="r",
                repo_root=tmp_path,
                write_finding=True,
            )
        findings_path = tmp_path / "findings" / "x.com" / "findings.json"
        data = json.loads(findings_path.read_text(encoding="utf-8"))
        wp_entries = [e for e in data if e["endpoint"] == "/wp-json/wp/v2/users"]
        assert len(wp_entries) == 1

    def test_write_finding_skipped_for_non_finding_status(self, tmp_path):
        """write_finding only takes effect for status=tested_finding."""
        mark_cell(
            "x.com", "/admin/x", "IDOR", "n_a",
            reason="read-only baseline", repo_root=tmp_path, write_finding=True,
        )
        findings_path = tmp_path / "findings" / "x.com" / "findings.json"
        # No findings.json should be created for n_a marks
        assert not findings_path.is_file()

    def test_rebuild_after_write_finding_preserves_cell(self, tmp_path):
        """End-to-end PR-12 contract: mark_cell --write-finding then
        rebuild_matrix must preserve the marked cell, even when the
        endpoint is absent from recon URLs.
        """
        # No recon URLs at all
        _seed_recon(tmp_path, "x.com", [])
        mark_cell(
            "x.com", "/wp-json/wp/v2/users", "Authz", "tested_finding",
            reason="user enum",
            repo_root=tmp_path,
            write_finding=True,
        )
        # Force-clean rebuild — wipes operator annotations BUT findings.json
        # endpoints must re-appear with tested_finding status
        rebuilt = rebuild_matrix("x.com", repo_root=tmp_path, force_clean=True)
        save_matrix("x.com", rebuilt, repo_root=tmp_path)
        loaded = load_matrix("x.com", repo_root=tmp_path)
        endpoints = {ep["endpoint"] for ep in loaded["endpoints"]}
        assert "/wp-json/wp/v2/users" in endpoints
        ep = next(e for e in loaded["endpoints"] if e["endpoint"] == "/wp-json/wp/v2/users")
        assert ep["cells"]["Authz"]["status"] == "tested_finding"


class TestQuestionToToolDiscoverability:
    """PRD R5 + Contract 6: tool must appear in Q->Tool table."""

    def test_autopilot_md_has_find_gaps_row(self):
        md = (REPO_ROOT / "commands" / "autopilot.md").read_text(encoding="utf-8")
        assert "coverage_matrix.py find-gaps" in md

    def test_check_coverage_command_runs_matrix_before_manual_summary(self):
        md = (REPO_ROOT / "commands" / "check-coverage.md").read_text(encoding="utf-8")
        assert "tools/coverage_matrix.py rebuild" in md
        assert "tools/coverage_matrix.py find-gaps" in md
        assert "tools/surface.py --target" in md
        assert "find-gaps` 非空" in md

    def test_coverage_gate_requires_matrix_when_target_artifacts_exist(self):
        md = (REPO_ROOT / "rules" / "coverage-gate.md").read_text(encoding="utf-8")
        assert "## 矩阵检查" in md
        assert "tools/coverage_matrix.py rebuild" in md
        assert "tools/coverage_matrix.py find-gaps" in md
        assert "rebuild 后 endpoint 为空" in md


class TestF3InvariantActivation:
    """PR-10 must activate F3 — the placeholder note is gone, active
    text references the CLI."""

    def test_placeholder_note_removed(self):
        md = (REPO_ROOT / "commands" / "autopilot.md").read_text(encoding="utf-8")
        assert "Phase 3 placeholder" not in md
        assert "Today this condition is a" not in md

    def test_f3_references_active_cli(self):
        md = (REPO_ROOT / "commands" / "autopilot.md").read_text(encoding="utf-8")
        # F3 body must reference the find-gaps subcommand explicitly
        assert "tools/coverage_matrix.py find-gaps" in md


class TestExtendedVulnClasses:
    """PRD .trellis/tasks/05-15-extend-vuln-classes — VULN_CLASSES gains
    SQLi/XXE/RCE/Path/CSRF (5 new classes appended to the original 10).

    These tests exercise contracts C1-C3 from design.md and back the
    AC1-AC3 acceptance criteria. They follow the same discipline as
    the rest of the suite (PRD C4): assert on STRUCTURAL invariants
    and ANCHOR fields; do NOT pin specific cell counts derived from
    `len(VULN_CLASSES)` so future enum extensions don't break.
    """

    NEW_CLASSES = ("SQLi", "XXE", "RCE", "Path", "CSRF")

    def test_new_classes_in_enum(self):
        """C1: enum contains the 5 new classes; original 10 retain
        their relative ordering at the head of the tuple (positional
        stability for any downstream tooling that reads the prefix).
        """
        assert set(self.NEW_CLASSES) <= set(VULN_CLASSES)
        # Original 10 still in original positions (head of tuple)
        assert VULN_CLASSES[:10] == (
            "IDOR", "SSRF", "XSS", "Race", "Authz",
            "GraphQL", "OAuth", "Upload", "Webhook", "JWT",
        )
        # The 5 new classes are present after the original 10
        assert set(VULN_CLASSES[10:]) == set(self.NEW_CLASSES)

    def test_new_classes_create_cells_on_rebuild(self, tmp_path):
        """C3: a fresh rebuild produces an `untested` cell for each of
        the 5 new classes on every endpoint, alongside cells for the
        10 originals.
        """
        _seed_recon(tmp_path, "x.com", ["/api/v1/admin/users"])
        matrix = rebuild_matrix("x.com", repo_root=tmp_path)
        cells = matrix["endpoints"][0]["cells"]
        for vc in self.NEW_CLASSES:
            assert vc in cells, f"new class {vc} missing on rebuild"
            assert cells[vc]["status"] == "untested"

    def test_legacy_matrix_auto_migrates_on_rebuild(self, tmp_path):
        """C3 auto-migration: a matrix JSON written before this enum
        extension has only the 10 old cell keys per endpoint. On the
        next rebuild, line 235 `setdefault` adds the 5 new cells as
        `untested` while preserving any pre-existing operator
        annotations on the original cells.
        """
        target = "legacy.com"
        matrix_dir = tmp_path / "evidence" / target
        matrix_dir.mkdir(parents=True)
        # Hand-craft a 10-class matrix shape (the pre-extension wire)
        legacy_cells = {
            vc: {"status": "untested"}
            for vc in ("IDOR", "SSRF", "XSS", "Race", "Authz",
                       "GraphQL", "OAuth", "Upload", "Webhook", "JWT")
        }
        legacy_cells["XSS"] = {"status": "n_a", "reason": "no-input page"}
        legacy_matrix = {
            "target": target,
            "vuln_classes": ["IDOR", "SSRF", "XSS", "Race", "Authz",
                             "GraphQL", "OAuth", "Upload", "Webhook", "JWT"],
            "endpoints": [{
                "endpoint": "/api/v1/admin/users",
                "weight": 5.0,
                "cells": legacy_cells,
            }],
            "summary": {},
            "last_updated": "2026-05-14T00:00:00+00:00",
        }
        (matrix_dir / "coverage_matrix.json").write_text(
            json.dumps(legacy_matrix), encoding="utf-8"
        )
        # Same endpoint must be in recon for the merge path to fire
        _seed_recon(tmp_path, target, ["/api/v1/admin/users"])
        rebuilt = rebuild_matrix(target, repo_root=tmp_path)
        save_matrix(target, rebuilt, repo_root=tmp_path)
        loaded = load_matrix(target, repo_root=tmp_path)
        # vuln_classes field upgraded to the 15-class list
        assert len(loaded["vuln_classes"]) == len(VULN_CLASSES)
        ep = next(e for e in loaded["endpoints"]
                  if e["endpoint"] == "/api/v1/admin/users")
        # All 15 cells exist
        for vc in VULN_CLASSES:
            assert vc in ep["cells"], f"cell {vc} missing after auto-migration"
        # New cells default to untested
        for vc in self.NEW_CLASSES:
            assert ep["cells"][vc]["status"] == "untested"
        # Pre-existing annotation survived
        assert ep["cells"]["XSS"]["status"] == "n_a"
        assert ep["cells"]["XSS"]["reason"] == "no-input page"

    @pytest.mark.parametrize("new_class", list(NEW_CLASSES))
    def test_mark_writefinding_rebuild_for_each_new_class(self, tmp_path, new_class):
        """C2 end-to-end PR-12 contract for each of the 5 new classes:
        `mark --write-finding` then `rebuild --force-clean` must
        preserve the marked cell, even when the endpoint is absent
        from recon URLs (this is the exact failure mode the pilot
        SQLi cell hit before this PR).
        """
        target = f"x-{new_class.lower()}.com"
        endpoint = f"/api/v1/{new_class.lower()}-target"
        # No recon URLs — endpoint exists only because mark created it
        _seed_recon(tmp_path, target, [])
        mark_cell(
            target, endpoint, new_class, "tested_finding",
            reason=f"PoC: {new_class} confirmed end-to-end",
            repo_root=tmp_path,
            write_finding=True,
        )
        # findings.json was created with the new-class entry
        findings_path = tmp_path / "findings" / target / "findings.json"
        assert findings_path.is_file()
        data = json.loads(findings_path.read_text(encoding="utf-8"))
        entry = next(e for e in data if e["endpoint"] == endpoint)
        assert entry["vuln_class"] == new_class
        assert entry["source"] == "mark_cell"
        # Force-clean rebuild wipes operator state, but findings.json
        # entries with the new-class string must NOT be filtered out
        # by the line-256 guard
        rebuilt = rebuild_matrix(target, repo_root=tmp_path, force_clean=True)
        save_matrix(target, rebuilt, repo_root=tmp_path)
        loaded = load_matrix(target, repo_root=tmp_path)
        ep = next(e for e in loaded["endpoints"] if e["endpoint"] == endpoint)
        assert ep["cells"][new_class]["status"] == "tested_finding"
        assert "evidence_ref" in ep["cells"][new_class]

    def test_findings_with_new_class_strings_pass_filter(self, tmp_path):
        """C2: the line-256 filter (`if vc not in VULN_CLASSES: continue`)
        used to silently drop SQLi/XXE/RCE/Path/CSRF entries from
        findings.json on rebuild. After enum extension, all 5 new
        class strings must produce cells.
        """
        target = "all-new.com"
        _seed_recon(tmp_path, target, [])
        findings_dir = tmp_path / "findings" / target
        findings_dir.mkdir(parents=True)
        findings = [
            {
                "id": f"F-{nc}",
                "endpoint": f"/v1/{nc.lower()}-endpoint",
                "vuln_class": nc,
            }
            for nc in self.NEW_CLASSES
        ]
        (findings_dir / "findings.json").write_text(
            json.dumps(findings), encoding="utf-8"
        )
        matrix = rebuild_matrix(target, repo_root=tmp_path)
        endpoint_cells = {ep["endpoint"]: ep["cells"] for ep in matrix["endpoints"]}
        for nc in self.NEW_CLASSES:
            ep_path = f"/v1/{nc.lower()}-endpoint"
            assert ep_path in endpoint_cells, (
                f"endpoint {ep_path} not in matrix — finding for {nc} "
                "was silently dropped (line-256 filter still rejecting?)"
            )
            assert endpoint_cells[ep_path][nc]["status"] == "tested_finding"


class TestVulnClassNormalization:
    """PRD .trellis/tasks/05-15-vuln-class-aliases — normalize_vuln_class
    accepts canonical names case-insensitively plus a curated alias
    set, returning the canonical form. Unknown input raises ValueError
    with a helpful message.
    """

    def test_canonical_exact_match(self):
        for vc in VULN_CLASSES:
            assert normalize_vuln_class(vc) == vc

    def test_lowercase_canonical(self):
        for vc in VULN_CLASSES:
            assert normalize_vuln_class(vc.lower()) == vc

    def test_uppercase_canonical(self):
        for vc in VULN_CLASSES:
            assert normalize_vuln_class(vc.upper()) == vc

    def test_path_aliases(self):
        for alias in ("lfi", "rfi", "pathtraversal", "path-traversal",
                      "directory-traversal", "PATHTRAVERSAL", "LFI"):
            assert normalize_vuln_class(alias) == "Path", alias

    def test_rce_aliases(self):
        for alias in ("ssti", "deser", "deserialization", "oscommand",
                      "os-command", "cmdinjection", "cmd-injection",
                      "commandinjection", "template-injection",
                      "OSCOMMAND", "Deser"):
            assert normalize_vuln_class(alias) == "RCE", alias

    def test_xss_aliases(self):
        for alias in ("xss-dom", "dom-xss", "domxss",
                      "prototype-pollution", "prototypepollution", "pp"):
            assert normalize_vuln_class(alias) == "XSS", alias

    def test_sqli_aliases(self):
        for alias in ("sql-injection", "sqlinjection", "sqlblind",
                      "sqli-blind", "sqli-time", "blindsqli",
                      "SQL-INJECTION", "Sqli"):
            assert normalize_vuln_class(alias) == "SQLi", alias

    def test_xxe_aliases(self):
        for alias in ("xxe-blind", "xml-injection", "xinclude",
                      "xmlinjection"):
            assert normalize_vuln_class(alias) == "XXE", alias

    def test_csrf_aliases(self):
        for alias in ("csrf-token", "xsrf"):
            assert normalize_vuln_class(alias) == "CSRF", alias

    def test_unknown_raises_with_helpful_message(self):
        with pytest.raises(ValueError) as excinfo:
            normalize_vuln_class("totally-bogus-name")
        msg = str(excinfo.value)
        # Message includes the input
        assert "totally-bogus-name" in msg
        # Message lists at least a few canonical names so the operator
        # can pick the right one
        assert "SQLi" in msg
        assert "RCE" in msg

    def test_unknown_via_mark_cell_raises(self, tmp_path):
        with pytest.raises(ValueError):
            mark_cell("x.com", "/admin/x", "totally-bogus", "untested",
                      repo_root=tmp_path)

    def test_mark_cell_with_lowercase(self, tmp_path):
        """AC2: `mark --vuln-class sqli` must succeed and the on-disk
        matrix must store the canonical `SQLi`."""
        mark_cell("x.com", "/api/orders/1", "sqli", "tested_finding",
                  reason="boolean blind", repo_root=tmp_path,
                  write_finding=True)
        loaded = load_matrix("x.com", repo_root=tmp_path)
        ep = loaded["endpoints"][0]
        # Cell stored under canonical key
        assert "SQLi" in ep["cells"]
        assert "sqli" not in ep["cells"]
        assert ep["cells"]["SQLi"]["status"] == "tested_finding"
        # findings.json also uses canonical name
        findings = json.loads(
            (tmp_path / "findings" / "x.com" / "findings.json").read_text(
                encoding="utf-8"
            )
        )
        assert findings[0]["vuln_class"] == "SQLi"

    def test_mark_cell_with_alias(self, tmp_path):
        """AC3: `mark --vuln-class lfi` resolves to canonical `Path`."""
        mark_cell("x.com", "/file/download", "lfi", "tested_finding",
                  reason="../../etc/passwd disclosed",
                  repo_root=tmp_path, write_finding=True)
        loaded = load_matrix("x.com", repo_root=tmp_path)
        ep = loaded["endpoints"][0]
        assert "Path" in ep["cells"]
        assert "lfi" not in ep["cells"]
        assert ep["cells"]["Path"]["status"] == "tested_finding"

    def test_alias_table_round_trip(self):
        """Every alias in the table must resolve to a canonical name
        that is itself in VULN_CLASSES (no broken aliases)."""
        for alias, canonical in VULN_CLASS_ALIASES.items():
            assert canonical in VULN_CLASSES, (
                f"alias {alias!r} maps to {canonical!r} which is not "
                "in VULN_CLASSES — broken alias table"
            )
