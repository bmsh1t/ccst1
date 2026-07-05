"""Tests for scanner_pass.json + coverage_matrix interplay.

Covers task 05-16-b4-scanner-matrix-feedback:
  - scanner_pass_writer produces a valid scanner_pass.json
  - coverage_matrix.rebuild records scanner-swept metadata when scanner_pass
    lists them, but does not close cells as `tested_clean`
  - Precedence: tested_finding / tested_clean / n_a statuses are preserved
  - Backwards compatibility: missing scanner_pass.json → matrix unchanged
  - Unknown vuln_class → warning + cell stays untested (not crash)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.coverage_matrix import (
    VULN_CLASSES,
    _apply_scanner_pass,
    load_matrix,
    rebuild_matrix,
    save_matrix,
)
from tools.scanner_pass_writer import (
    CATEGORY_TO_VULN_CLASS,
    build_scanner_pass,
    write_scanner_pass,
)


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def fake_repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    return repo


def _seed_recon(repo: Path, target: str, urls: list[str]):
    p = repo / "recon" / target / "urls"
    p.mkdir(parents=True, exist_ok=True)
    (p / "all.txt").write_text("\n".join(urls), encoding="utf-8")


def _seed_recon_filtered(repo: Path, target: str, raw_urls: list[str], filtered_urls: list[str]):
    p = repo / "recon" / target / "urls"
    p.mkdir(parents=True, exist_ok=True)
    (p / "all.txt").write_text("\n".join(raw_urls), encoding="utf-8")
    (p / "all_filtered.txt").write_text("\n".join(filtered_urls), encoding="utf-8")


def _seed_findings_dir(repo: Path, target: str, categories: list[str]):
    base = repo / "findings" / target
    base.mkdir(parents=True, exist_ok=True)
    for cat in categories:
        cat_dir = base / cat
        cat_dir.mkdir(exist_ok=True)
        # marker file so directory detection treats the lane as ran
        (cat_dir / "ran.marker").write_text("")
    return base


def _seed_findings_json(repo: Path, target: str, findings: list[dict]):
    base = repo / "findings" / target
    base.mkdir(parents=True, exist_ok=True)
    (base / "findings.json").write_text(json.dumps({"findings": findings}))


def _write_scanner_pass_inline(repo: Path, target: str, rows: list[dict]):
    base = repo / "findings" / target
    base.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": 1,
        "target": target,
        "scanned_at": "2026-05-16T10:00:00+00:00",
        "scanner_version": "vuln_scanner.sh@test",
        "module_count": 1,
        "endpoint_count": len({r["endpoint"] for r in rows}),
        "endpoints": rows,
    }
    (base / "scanner_pass.json").write_text(json.dumps(payload, indent=2))


# ─────────────────────────────────────────────────────────────────────────────
# scanner_pass_writer
# ─────────────────────────────────────────────────────────────────────────────

class TestScannerPassWriter:
    def test_build_emits_rows_for_each_category(self, fake_repo):
        _seed_recon(fake_repo, "ex.com", ["https://api.ex.com/v1/users/1", "https://api.ex.com/v1/orders/2"])
        findings = _seed_findings_dir(fake_repo, "ex.com", ["sqli", "idor", "ssrf"])

        payload = build_scanner_pass(
            target="ex.com",
            findings_dir=findings,
            recon_dir=fake_repo / "recon" / "ex.com",
        )
        assert payload["target"] == "ex.com"
        assert payload["module_count"] == 3
        assert payload["endpoint_count"] == 2
        # 3 modules * 2 endpoints = 6 rows
        assert len(payload["endpoints"]) == 6
        vuln_classes = {row["vuln_class"] for row in payload["endpoints"]}
        assert {"SQLi", "IDOR", "SSRF"} <= vuln_classes

    def test_build_skips_uncurated_categories(self, fake_repo):
        _seed_recon(fake_repo, "ex.com", ["https://x.com/a"])
        # `cves` and `exposure` are not in CATEGORY_TO_VULN_CLASS — skip them
        findings = _seed_findings_dir(fake_repo, "ex.com", ["cves", "exposure", "sqli"])
        payload = build_scanner_pass(
            target="ex.com",
            findings_dir=findings,
            recon_dir=fake_repo / "recon" / "ex.com",
        )
        assert payload["module_count"] == 1  # only sqli was kept
        modules = {row["module"] for row in payload["endpoints"]}
        assert modules == {"vuln_scanner.sqli"}

    def test_build_ignores_precreated_empty_category_dirs(self, fake_repo):
        _seed_recon(fake_repo, "ex.com", ["https://x.com/a"])
        findings = fake_repo / "findings" / "ex.com"
        (findings / "sqli").mkdir(parents=True)
        (findings / "idor").mkdir(parents=True)

        payload = build_scanner_pass(
            target="ex.com",
            findings_dir=findings,
            recon_dir=fake_repo / "recon" / "ex.com",
        )

        assert payload["module_count"] == 0
        assert payload["endpoints"] == []

    def test_build_empty_when_no_endpoints(self, fake_repo):
        # recon/<t>/urls/all.txt missing
        findings = _seed_findings_dir(fake_repo, "ex.com", ["sqli"])
        payload = build_scanner_pass(
            target="ex.com",
            findings_dir=findings,
            recon_dir=fake_repo / "recon" / "ex.com",
        )
        assert payload["endpoint_count"] == 0
        assert payload["endpoints"] == []

    def test_write_creates_file_at_target_root(self, fake_repo):
        _seed_recon(fake_repo, "ex.com", ["https://x.com/a"])
        findings = _seed_findings_dir(fake_repo, "ex.com", ["sqli"])
        out = write_scanner_pass(
            target="ex.com",
            findings_dir=findings,
            recon_dir=fake_repo / "recon" / "ex.com",
        )
        assert out.is_file()
        assert out.parent == fake_repo / "findings" / "ex.com"

    def test_write_from_session_subdir_still_writes_target_root(self, fake_repo):
        """When findings_dir is .../sessions/<id>, scanner_pass still lands at
        findings/<target>/scanner_pass.json so rebuild can pick it up."""
        _seed_recon(fake_repo, "ex.com", ["https://x.com/a"])
        session_dir = fake_repo / "findings" / "ex.com" / "sessions" / "abc123"
        (session_dir / "sqli").mkdir(parents=True)
        (session_dir / "sqli" / "ran.marker").write_text("")

        out = write_scanner_pass(
            target="ex.com",
            findings_dir=session_dir,
            recon_dir=fake_repo / "recon" / "ex.com",
        )
        # Walked back up to findings/<target>/
        assert out == fake_repo / "findings" / "ex.com" / "scanner_pass.json"

    def test_all_mapped_classes_are_canonical(self):
        """Every value in CATEGORY_TO_VULN_CLASS must be in VULN_CLASSES."""
        for category, vc in CATEGORY_TO_VULN_CLASS.items():
            assert vc in VULN_CLASSES, (
                f"category {category!r} → {vc!r} is not a canonical VULN_CLASSES entry"
            )


# ─────────────────────────────────────────────────────────────────────────────
# coverage_matrix.rebuild + scanner_pass interplay
# ─────────────────────────────────────────────────────────────────────────────

class TestCoverageMatrixScannerPass:
    def test_url_target_rebuild_uses_canonical_storage_key(self, fake_repo):
        """URL targets must share the recon/findings/evidence storage key.

        Regression: raw URL targets previously wrote
        `evidence/http:/127.0.0.1:3002/coverage_matrix.json`, while recon and
        autopilot state used `127.0.0.1:3002`.
        """
        target = "http://127.0.0.1:3002"
        target_key = "127.0.0.1:3002"
        _seed_recon(fake_repo, target_key, [
            "http://127.0.0.1:3002/rest/admin/application-configuration",
        ])

        matrix = rebuild_matrix(target, repo_root=fake_repo)
        out = save_matrix(target, matrix, fake_repo)

        assert out == fake_repo / "evidence" / target_key / "coverage_matrix.json"
        assert matrix["endpoints"][0]["endpoint"] == "/rest/admin/application-configuration"
        assert not (fake_repo / "evidence" / "http:" / "127.0.0.1:3002").exists()

    def test_rebuild_prefers_filtered_urls_over_external_raw_embeds(self, fake_repo):
        """Filtered recon URLs should drive coverage when present.

        Regression: raw all.txt may retain third-party iframe/player URLs for
        audit. Rebuild previously canonicalized those external URLs by path,
        creating fake target gaps like `/player/ x SSRF`.
        """
        target = "http://127.0.0.1:3002"
        target_key = "127.0.0.1:3002"
        _seed_recon_filtered(
            fake_repo,
            target_key,
            raw_urls=[
                "http://127.0.0.1:3002/rest/admin/application-configuration",
                "https://w.soundcloud.com/player/?url=https%3A%2F%2Fapi.soundcloud.com%2Ftracks%2F771984076",
            ],
            filtered_urls=[
                "http://127.0.0.1:3002/rest/admin/application-configuration",
            ],
        )

        matrix = rebuild_matrix(target, repo_root=fake_repo)
        endpoints = {ep["endpoint"] for ep in matrix["endpoints"]}

        assert "/rest/admin/application-configuration" in endpoints
        assert "/player/" not in endpoints

    def test_scanner_pass_records_scanner_swept_without_marking_clean(self, fake_repo):
        _seed_recon(fake_repo, "ex.com", [
            "https://api.ex.com/v1/users/1",
        ])
        _write_scanner_pass_inline(
            fake_repo, "ex.com",
            [
                {"endpoint": "https://api.ex.com/v1/users/1", "vuln_class": "SQLi", "module": "vuln_scanner.sqli"},
                {"endpoint": "https://api.ex.com/v1/users/1", "vuln_class": "IDOR", "module": "vuln_scanner.idor"},
            ],
        )
        matrix = rebuild_matrix("ex.com", repo_root=fake_repo)
        endpoints = matrix["endpoints"]
        assert len(endpoints) == 1
        ep = endpoints[0]
        cells = ep["cells"]
        assert cells["SQLi"]["status"] == "untested"
        assert cells["SQLi"]["scanner_swept"] is True
        assert cells["SQLi"]["scanner_module"] == "vuln_scanner.sqli"
        assert cells["IDOR"]["status"] == "untested"
        assert cells["IDOR"]["scanner_swept"] is True
        # other classes still untested
        assert cells["XSS"]["status"] == "untested"
        assert "scanner_swept" not in cells["XSS"]

    def test_scanner_pass_preserves_route_prefix_candidate_hint(self, fake_repo):
        """scanner_pass advisory metadata must not erase AI-first endpoint hints."""
        _seed_recon(fake_repo, "ex.com", [
            "https://ex.com/rest/admin",
            "https://ex.com/rest/admin/application-configuration",
        ])
        _write_scanner_pass_inline(
            fake_repo, "ex.com",
            [{
                "endpoint": "https://ex.com/rest/admin",
                "vuln_class": "SQLi",
                "module": "vuln_scanner.sqli",
            }],
        )

        matrix = rebuild_matrix("ex.com", repo_root=fake_repo)
        by_endpoint = {ep["endpoint"]: ep for ep in matrix["endpoints"]}
        admin_ep = by_endpoint["/rest/admin"]

        assert admin_ep["endpoint_kind"] == "untriaged"
        assert "api_like_path" in admin_ep["auto_hints"]
        assert "route_prefix_candidate" in admin_ep["auto_hints"]
        assert admin_ep["source_count"] == 1
        assert admin_ep["cells"]["SQLi"]["status"] == "untested"
        assert admin_ep["cells"]["SQLi"]["scanner_swept"] is True

    def test_findings_takes_precedence_over_scanner_pass(self, fake_repo):
        _seed_recon(fake_repo, "ex.com", ["https://api.ex.com/v1/users/1"])
        _seed_findings_json(fake_repo, "ex.com", [{
            "id": "f1",
            "endpoint": "https://api.ex.com/v1/users/1",
            "vuln_class": "SQLi",
        }])
        _write_scanner_pass_inline(
            fake_repo, "ex.com",
            [{
                "endpoint": "https://api.ex.com/v1/users/1",
                "vuln_class": "SQLi",
                "module": "vuln_scanner.sqli",
            }],
        )
        matrix = rebuild_matrix("ex.com", repo_root=fake_repo)
        cells = matrix["endpoints"][0]["cells"]
        # tested_finding wins (precedence)
        assert cells["SQLi"]["status"] == "tested_finding"

    def test_n_a_takes_precedence_over_scanner_pass(self, fake_repo):
        from tools.coverage_matrix import mark_cell, save_matrix

        _seed_recon(fake_repo, "ex.com", ["https://api.ex.com/v1/users/1"])
        # Initialise matrix and mark a cell n_a using the canonical endpoint
        # path (host stripped — api.ex.com → just /v1/users/1).
        m = rebuild_matrix("ex.com", repo_root=fake_repo)
        save_matrix("ex.com", m, fake_repo)
        canonical_endpoint = m["endpoints"][0]["endpoint"]
        assert canonical_endpoint == "/v1/users/1"
        mark_cell("ex.com", canonical_endpoint, "SQLi", "n_a",
                  reason="manual exemption", repo_root=fake_repo)

        _write_scanner_pass_inline(
            fake_repo, "ex.com",
            [{
                "endpoint": "https://api.ex.com/v1/users/1",
                "vuln_class": "SQLi",
                "module": "vuln_scanner.sqli",
            }],
        )
        m2 = rebuild_matrix("ex.com", repo_root=fake_repo)
        cells = m2["endpoints"][0]["cells"]
        # n_a stays (precedence)
        assert cells["SQLi"]["status"] == "n_a"

    def test_missing_scanner_pass_does_not_break(self, fake_repo):
        _seed_recon(fake_repo, "ex.com", ["https://api.ex.com/v1/users/1"])
        # no scanner_pass.json — matrix should rebuild fine with all untested
        matrix = rebuild_matrix("ex.com", repo_root=fake_repo)
        cells = matrix["endpoints"][0]["cells"]
        for vc in VULN_CLASSES:
            assert cells[vc]["status"] == "untested"

    def test_unknown_vuln_class_in_scanner_pass_skipped(self, fake_repo, capsys):
        _seed_recon(fake_repo, "ex.com", ["https://api.ex.com/v1/users/1"])
        _write_scanner_pass_inline(
            fake_repo, "ex.com",
            [{
                "endpoint": "https://api.ex.com/v1/users/1",
                "vuln_class": "TotallyMadeUp",
                "module": "vuln_scanner.fake",
            }],
        )
        matrix = rebuild_matrix("ex.com", repo_root=fake_repo)
        cells = matrix["endpoints"][0]["cells"]
        # Cell stays untested — did not crash, did not mark
        for vc in VULN_CLASSES:
            assert cells[vc]["status"] == "untested"
        # And a warning was emitted
        captured = capsys.readouterr()
        assert "unknown vuln_class" in captured.err

    def test_scanner_pass_can_add_new_endpoints(self, fake_repo):
        """scanner_pass with an endpoint not in recon urls/all.txt should still
        register so the tested_clean mark survives subsequent rebuilds."""
        _seed_recon(fake_repo, "ex.com", [])  # no recon URLs
        _write_scanner_pass_inline(
            fake_repo, "ex.com",
            [{
                "endpoint": "https://api.ex.com/v1/standalone",
                "vuln_class": "SQLi",
                "module": "vuln_scanner.sqli",
            }],
        )
        matrix = rebuild_matrix("ex.com", repo_root=fake_repo)
        endpoints = matrix["endpoints"]
        assert any("/standalone" in ep["endpoint"] for ep in endpoints)

    def test_scanner_swept_metadata_persists_after_rebuild(self, fake_repo):
        """Rebuild a second time — scanner-swept metadata stays advisory."""
        _seed_recon(fake_repo, "ex.com", ["https://api.ex.com/v1/users/1"])
        _write_scanner_pass_inline(
            fake_repo, "ex.com",
            [{
                "endpoint": "https://api.ex.com/v1/users/1",
                "vuln_class": "SQLi",
                "module": "vuln_scanner.sqli",
            }],
        )
        m1 = rebuild_matrix("ex.com", repo_root=fake_repo)
        from tools.coverage_matrix import save_matrix
        save_matrix("ex.com", m1, fake_repo)
        m2 = rebuild_matrix("ex.com", repo_root=fake_repo)
        cells = m2["endpoints"][0]["cells"]
        assert cells["SQLi"]["status"] == "untested"
        assert cells["SQLi"]["scanner_swept"] is True

    def test_apply_scanner_pass_unit(self, fake_repo):
        """Direct _apply_scanner_pass call exercises the helper unit."""
        _write_scanner_pass_inline(
            fake_repo, "ex.com",
            [{
                "endpoint": "/api/v1/users/1",
                "vuln_class": "IDOR",
                "module": "vuln_scanner.idor",
            }],
        )
        endpoints: list[dict] = [{
            "endpoint": "/api/v1/users/1",
            "weight": 5.0,
            "cells": {vc: {"status": "untested"} for vc in VULN_CLASSES},
        }]
        _apply_scanner_pass("ex.com", fake_repo, endpoints)
        assert endpoints[0]["cells"]["IDOR"]["status"] == "untested"
        assert endpoints[0]["cells"]["IDOR"]["scanner_swept"] is True
        # other cells unchanged
        assert endpoints[0]["cells"]["XSS"]["status"] == "untested"
        assert "scanner_swept" not in endpoints[0]["cells"]["XSS"]
