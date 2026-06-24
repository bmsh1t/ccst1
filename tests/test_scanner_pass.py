"""Tests for scanner_pass.json + coverage_matrix interplay.

Covers task 05-16-b4-scanner-matrix-feedback:
  - scanner_pass_writer produces a valid scanner_pass.json
  - coverage_matrix.rebuild marks cells `tested_clean` when scanner_pass
    lists them and no higher-precedence status applies
  - Precedence: tested_finding > tested_clean > n_a > untested
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
    def test_scanner_pass_marks_untested_cells_tested_clean(self, fake_repo):
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
        assert cells["SQLi"]["status"] == "tested_clean"
        assert cells["IDOR"]["status"] == "tested_clean"
        # other classes still untested
        assert cells["XSS"]["status"] == "untested"

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

    def test_unknown_status_does_not_downgrade_after_rebuild(self, fake_repo):
        """Rebuild a second time — tested_clean stays tested_clean."""
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
        assert cells["SQLi"]["status"] == "tested_clean"

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
        assert endpoints[0]["cells"]["IDOR"]["status"] == "tested_clean"
        # other cells unchanged
        assert endpoints[0]["cells"]["XSS"]["status"] == "untested"
