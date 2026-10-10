"""Tests for tools/coverage_matrix.py.

Discipline (PRD C4): tests assert on STRUCTURAL invariants and
ANCHOR fields. They do NOT pin specific endpoint strings, specific
cell counts, or specific vuln-class ordering.
"""

from __future__ import annotations

import json
import multiprocessing
from pathlib import Path

import pytest

import coverage_matrix as coverage_matrix_module
from coverage_matrix import (
    STATUS_VALUES,
    VULN_CLASS_ALIASES,
    VULN_CLASSES,
    _canonicalize_endpoint,
    _route_template,
    _compute_summary,
    _empty_matrix,
    find_high_value_gaps,
    load_matrix,
    load_matrix_projection,
    read_matrix,
    high_value_gaps_from_matrix,
    mark_cell,
    mark_endpoint_kind,
    matrix_is_fresh,
    needs_endpoint_triage,
    normalize_vuln_class,
    rebuild_matrix,
    save_matrix,
)
from tools.target_store import TargetStore
from surface_index import build_surface_index


REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def store(tmp_path):
    result = TargetStore(tmp_path, "x.com")
    result.initialize()
    return result


def _claim(store, finding_id, endpoint, family):
    store.create_finding(
        command_id=finding_id, finding_id=finding_id,
        endpoint=endpoint if "://" in endpoint else f"https://{store.target}{endpoint}",
        method="GET", family=family, title="Unassessed claim",
        claim="Requires evidence and technical assessment", actor="operator",
    )


def test_primary_projection_uses_current_truth_without_publishing(tmp_path):
    from tools.current_truth import current_cell_projection
    from tools.target_store import TargetStore

    target = "coverage.test"
    store = TargetStore(tmp_path, target)
    store.initialize()
    _seed_recon(tmp_path, target, [f"https://{target}/observed"])
    path = coverage_matrix_module._matrix_path(tmp_path, target)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"target": target, "endpoints": [{
        "endpoint": "/historical", "endpoint_kind": "route_prefix",
        "endpoint_kind_source": "operator", "cells": {
            "Authz": {"status": "tested_finding", "evidence_ref": "old"},
            "XSS": {"status": "n_a", "reason": "historical applicability"},
        },
    }]}), encoding="utf-8")
    store.create_finding(
        command_id="candidate", finding_id="candidate", endpoint=f"https://{target}/candidate",
        method="GET", family="Authz", title="Unassessed", claim="needs evidence", actor="ai",
    )
    raw = tmp_path / "evidence" / target / "response.txt"
    raw.parent.mkdir(parents=True, exist_ok=True)
    raw.write_text("response", encoding="utf-8")
    store.start_attempt(attempt_id="attempt", source="native", started_at="2026-09-22T00:00:00Z", actor="ai")
    store.record_execution(attempt_id="attempt", outcome="complete", actor="ai", observations=[{
        "endpoint": f"https://{target}/verified", "method": "GET", "family": "Authz",
        "observed_at": "2026-09-22T00:00:00Z", "description": "Recorded clean response",
        "artifacts": {"response": raw.relative_to(tmp_path).as_posix()}, "result": "tested_clean",
    }, {
        "endpoint": f"https://{target}/variant?actor=peer", "method": "GET", "family": "Authz",
        "observed_at": "2026-09-22T00:00:00Z", "description": "One exact variant only",
        "artifacts": {"response": raw.relative_to(tmp_path).as_posix()}, "result": "tested_clean",
    }])

    def snapshot():
        return {str(p.relative_to(tmp_path)): (p.read_bytes(), p.stat().st_mtime_ns)
                for p in tmp_path.rglob("*") if p.is_file()
                and p.name not in {"metadata.sqlite3-wal", "metadata.sqlite3-shm"}}

    before = snapshot()
    matrix = load_matrix_projection(target, tmp_path)
    endpoints = {row["endpoint"]: row for row in matrix["endpoints"]}
    assert set(endpoints) == {"/observed", "/candidate", "/verified", "/variant"}
    # Old annotations remain explicit historical input until imported into Store.
    assert load_matrix(target, tmp_path)["endpoints"][0]["cells"]["XSS"]["reason"] == "historical applicability"
    assert endpoints["/candidate"]["cells"]["Authz"]["status"] == "untested"
    assert endpoints["/verified"]["cells"]["Authz"]["status"] == "untested"
    assert endpoints["/variant"]["cells"]["Authz"]["status"] == "untested"
    assert matrix["closure_projection"] == current_cell_projection(tmp_path, target)["projection"]
    assert matrix["store_revision"] == store.binding()["revision"]
    assert snapshot() == before

    raw.write_text("corrupt", encoding="utf-8")
    before = snapshot()
    damaged = coverage_matrix_module.read_matrix(target, tmp_path)
    assert damaged["evidence_health"]["status"] == "partial"
    assert all(cell["status"] == "untested" for row in damaged["endpoints"] for cell in row["cells"].values())
    assert snapshot() == before


def test_primary_projection_retains_scanner_advice_for_observed_open_cells(tmp_path):
    from tools.target_store import TargetStore

    target = "scanner-coverage.test"
    store = TargetStore(tmp_path, target)
    store.initialize()
    raw = tmp_path / "evidence" / target / "response.txt"
    raw.parent.mkdir(parents=True, exist_ok=True)
    raw.write_text("response", encoding="utf-8")
    store.start_attempt(attempt_id="attempt", source="native", started_at="2026-09-22T00:00:00Z", actor="ai")
    store.record_execution(attempt_id="attempt", outcome="complete", actor="ai", observations=[{
        "endpoint": f"https://{target}/observed", "method": "GET", "family": "Authz",
        "observed_at": "2026-09-22T00:00:00Z", "description": "Unresolved candidate",
        "artifacts": {"response": raw.relative_to(tmp_path).as_posix()}, "result": "candidate",
    }])
    scanner = tmp_path / "findings" / target / "scanner_pass.json"
    scanner.parent.mkdir(parents=True)
    scanner.write_text(json.dumps({"endpoints": [
        {"endpoint": endpoint, "vuln_class": "Authz", "module": "authz"}
        for endpoint in ("/observed", "/scanner-only")
    ]}), encoding="utf-8")

    matrix = coverage_matrix_module.read_matrix(target, tmp_path)

    for row in matrix["endpoints"]:
        cell = row["cells"]["Authz"]
        assert cell["status"] == "untested"
        assert cell["scanner_swept"] is True
        assert cell["scanner_evidence_ref"] == f"findings/{target}/scanner_pass.json#authz"
    assert matrix["high_risk_lanes"]["Authz"]["scanner_swept"] == 2
    assert not coverage_matrix_module._matrix_path(tmp_path, target).exists()


@pytest.mark.parametrize("result", ["dead_end", "not_applicable", "blocked_redline"])
def test_primary_terminal_dispositions_filter_only_exact_authorized_gaps(tmp_path, result):
    from tools.target_store import TargetStore

    target = "terminal-coverage.test"
    store = TargetStore(tmp_path, target)
    store.initialize()
    raw = tmp_path / "evidence" / target / "response.txt"
    raw.parent.mkdir(parents=True)
    raw.write_text("response", encoding="utf-8")
    as_of = "2026-09-22T00:00:00Z"
    store.start_attempt(attempt_id="attempt", source="native", started_at=as_of, actor="ai")
    receipt = store.record_execution(attempt_id="attempt", outcome="complete", actor="ai", observations=[{
        "endpoint": f"https://{target}{endpoint}", "method": "GET", "family": "Authz",
        "observed_at": as_of, "description": "Evidence-backed disposition",
        "artifacts": {"response": raw.relative_to(tmp_path).as_posix()}, "result": result,
        "identity_dimensions": dimensions,
    } for endpoint, dimensions in [
        ("/exact", {}), ("/query?actor=peer", {}), ("/fragment#/peer", {}),
        ("/scoped", {"method": "GET", "actor_role": "admin", "object_scope": "admin_object"}),
    ]])

    matrix = coverage_matrix_module.read_matrix(target, tmp_path, as_of=as_of)
    assert matrix == coverage_matrix_module.read_matrix(target, tmp_path, as_of=as_of)
    assert matrix["as_of"] == matrix["last_updated"] == as_of
    assert matrix["source_snapshot"]["store"] == store.binding()
    assert matrix["source_snapshot"]["operation_ids"] == [receipt["entity_id"]]
    assert len(matrix["source_snapshot"]["observation_ids"]) == 4
    assert matrix_is_fresh(target, matrix, tmp_path)
    assert all(row["cells"]["Authz"]["status"] == "untested" for row in matrix["endpoints"])
    gaps = coverage_matrix_module.high_value_gaps_from_matrix(matrix)
    assert {gap["endpoint"] for gap in gaps if gap["vuln_class"] == "Authz"} == {
        "/exact", "/query", "/fragment", "/scoped",
    }
    assert matrix["closure_projection"]["closed_cells_v2"] == []
    summary = matrix["summary"]
    assert summary["high_value_gaps_count"] == summary["actionable_high_value_gaps_count"] == len(gaps)
    assert summary["untested"] == len(gaps)
    assert coverage_matrix_module.high_value_gap_window_from_matrix(matrix, limit=1)[1] == len(gaps)

    raw.write_text("corrupted", encoding="utf-8")
    damaged = coverage_matrix_module.read_matrix(target, tmp_path, as_of=as_of)
    assert damaged["store_revision"] == matrix["store_revision"]
    assert damaged["source_fingerprint"] != matrix["source_fingerprint"]
    assert damaged["evidence_health"]["status"] == "partial"
    assert not matrix_is_fresh(target, matrix, tmp_path)
    assert any(gap["endpoint"] == "/exact" and gap["vuln_class"] == "Authz"
               for gap in coverage_matrix_module.high_value_gaps_from_matrix(damaged))


@pytest.mark.parametrize("changed_input", ["discovery", "store", "review"])
def test_primary_read_rejects_input_drift(tmp_path, monkeypatch, changed_input):
    from tools.target_store import StoreError, TargetStore

    target = "drifting-coverage.test"
    store = TargetStore(tmp_path, target)
    store.initialize()
    _seed_recon(tmp_path, target, [f"https://{target}/before"])
    rebuild = coverage_matrix_module._rebuild_matrix_unlocked

    def changing_rebuild(*args, **kwargs):
        matrix = rebuild(*args, **kwargs)
        if changed_input == "discovery":
            (tmp_path / "recon" / target / "urls" / "all.txt").write_text(
                f"https://{target}/after\n", encoding="utf-8",
            )
        elif changed_input == "review":
            store.record_coverage_review(command_id="new-review", endpoint="/before", kind="cell_status",
                                         family="Authz", value="n_a", reason="authored input", actor="operator")
        else:
            store.create_finding(command_id="new", finding_id="new", endpoint=f"https://{target}/new",
                                 method="GET", family="Authz", title="New", claim="Unassessed", actor="ai")
        return matrix

    monkeypatch.setattr(coverage_matrix_module, "_rebuild_matrix_unlocked", changing_rebuild)
    with pytest.raises(StoreError, match="inputs changed during assembly"):
        coverage_matrix_module.read_matrix(target, tmp_path, as_of="2026-09-22T00:00:00Z")


def _coverage_mark_worker(repo_root: str, target: str, vuln_class: str, ready, start) -> None:
    ready.set()
    start.wait(10)
    mark_cell(
        target,
        "/api/admin/users",
        vuln_class,
        "tested_clean",
        repo_root=repo_root,
    )


def test_readme_names_the_canonical_web2_closure_taxonomy():
    text = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    heading = f"{len(VULN_CLASSES)} Canonical Web2 Closure Classes"
    assert heading in text
    section = text.split(heading, 1)[1].split("</details>", 1)[0]
    assert all(f"**{vuln_class}**" in section for vuln_class in VULN_CLASSES)
    assert "20 Web2 Bug Classes" not in text


def test_default_xss_skip_is_visible_without_closing_coverage(tmp_path):
    TargetStore(tmp_path, "xss-policy.test").initialize()
    _seed_recon(tmp_path, "xss-policy.test", ["https://xss-policy.test/search?q=one"])
    findings_dir = tmp_path / "findings" / "xss-policy.test"
    findings_dir.mkdir(parents=True)
    (findings_dir / "summary.json").write_text(
        json.dumps({"skipped_checks": ["xss"]}), encoding="utf-8"
    )

    matrix = rebuild_matrix("xss-policy.test", repo_root=tmp_path)

    assert matrix["policy_skips"]["XSS"]["status"] == "skipped"
    assert all(item["cells"]["XSS"]["status"] == "untested" for item in matrix["endpoints"])

    browser_dir = tmp_path / "recon" / "xss-policy.test" / "browser"
    browser_dir.mkdir(parents=True)
    (browser_dir / "xhr_endpoints.txt").write_text(
        "https://xss-policy.test/search?q=one innerHTML reflection\n", encoding="utf-8"
    )
    refreshed = rebuild_matrix("xss-policy.test", repo_root=tmp_path)
    assert refreshed["policy_skips"] == {}


def _seed_recon(tmp_path: Path, target: str, urls: list[str]) -> None:
    urls_dir = tmp_path / "recon" / target / "urls"
    urls_dir.mkdir(parents=True)
    (urls_dir / "all.txt").write_text("\n".join(urls), encoding="utf-8")


def _seed_recon_with_filtered(
    tmp_path: Path,
    target: str,
    *,
    raw_urls: list[str],
    filtered_urls: list[str],
    filter_log: str = "",
) -> None:
    urls_dir = tmp_path / "recon" / target / "urls"
    urls_dir.mkdir(parents=True)
    (urls_dir / "all.txt").write_text("\n".join(raw_urls), encoding="utf-8")
    (urls_dir / "all_filtered.txt").write_text("\n".join(filtered_urls), encoding="utf-8")
    if filter_log:
        (urls_dir / "filter.log").write_text(filter_log, encoding="utf-8")


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

    def test_load_existing_corrupt_matrix_fails_explicitly(self, tmp_path):
        path = tmp_path / "evidence" / "x.com" / "coverage_matrix.json"
        path.parent.mkdir(parents=True)
        path.write_text("{broken", encoding="utf-8")

        with pytest.raises(ValueError, match="invalid coverage matrix JSON"):
            load_matrix("x.com", repo_root=tmp_path)

    def test_load_recomputes_legacy_high_risk_alias_statuses(self, tmp_path):
        matrix = _empty_matrix("x.com")
        matrix["high_risk_lanes"] = {
            "RCE": {"disposition": "tested"},
            "Deserialization": {"disposition": "tested", "alias_of": "RCE"},
        }
        path = tmp_path / "evidence" / "x.com" / "coverage_matrix.json"
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps(matrix), encoding="utf-8")

        loaded = load_matrix("x.com", repo_root=tmp_path)

        assert set(loaded["high_risk_lanes"]) == set(VULN_CLASSES)
        assert "Deserialization" not in loaded["high_risk_lanes"]
        assert loaded["high_risk_lanes"]["RCE"]["techniques"] == [
            "SSTI", "CommandInjection", "Deserialization",
        ]

    def test_cli_rejects_uninitialized_target_without_using_corrupt_cache(self, tmp_path, capsys):
        path = tmp_path / "evidence/x.com/coverage_matrix.json"
        path.parent.mkdir(parents=True)
        path.write_text("{broken", encoding="utf-8")
        before = path.read_bytes()
        rc = coverage_matrix_module.main(["find-gaps", "--repo-root", str(tmp_path), "--target", "x.com"])
        captured = capsys.readouterr()
        assert rc == 2 and captured.out == ""
        assert "coverage matrix command failed" in captured.err
        assert "import" in captured.err or "initialized" in captured.err
        assert path.read_bytes() == before
        assert not (tmp_path / "state/x.com/metadata.sqlite3").exists()

    @pytest.mark.parametrize(
        "payload, message",
        [
            ([], "must contain one object"),
            ({}, "endpoints must be a list"),
            ({"endpoints": {}}, "endpoints must be a list"),
        ],
    )
    def test_load_existing_invalid_matrix_shape_fails_explicitly(self, tmp_path, payload, message):
        path = tmp_path / "evidence" / "x.com" / "coverage_matrix.json"
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps(payload), encoding="utf-8")

        with pytest.raises(ValueError, match=message):
            load_matrix("x.com", repo_root=tmp_path)


def test_concurrent_coverage_marks_preserve_disjoint_cells(tmp_path, store):
    context = multiprocessing.get_context("fork")
    start = context.Event()
    ready = [context.Event() for _ in ("IDOR", "SSRF", "XSS")]
    processes = [
        context.Process(
            target=_coverage_mark_worker,
            args=(str(tmp_path), "x.com", vuln_class, ready[index], start),
        )
        for index, vuln_class in enumerate(("IDOR", "SSRF", "XSS"))
    ]
    for process in processes:
        process.start()
    assert all(event.wait(10) for event in ready)
    start.set()
    for process in processes:
        process.join(10)
        assert process.exitcode == 0

    matrix = read_matrix("x.com", repo_root=tmp_path)
    endpoint = next(item for item in matrix["endpoints"] if item["endpoint"] == "/api/admin/users")
    assert {name for name, cell in endpoint["cells"].items() if cell.get("review", {}).get("value") == "tested_clean"} >= {
        "IDOR", "SSRF", "XSS",
    }


class TestCanonicalizeEndpoint:
    def test_strips_query(self):
        assert _canonicalize_endpoint("/api/v1/orders/1?foo=bar") == "/api/v1/orders/1"

    def test_strips_scheme_and_host(self):
        assert _canonicalize_endpoint("https://x.com/api/v1") == "/api/v1"

    def test_empty(self):
        assert _canonicalize_endpoint("") == ""


class TestRouteTemplate:
    def test_collapses_obvious_dynamic_tokens(self):
        assert _route_template("/users/123/orders/2025-01-02") == "/users/{id}/orders/{date}"
        assert _route_template("/objects/550e8400-e29b-41d4-a716-446655440000") == "/objects/{uuid}"
        assert _route_template("/download/abcdef0123456789abcdef0123456789") == "/download/{hash}"

    def test_preserves_static_and_metadata_paths(self):
        assert _route_template("/assets/123/app.js") == "/assets/123/app.js"
        assert _route_template("/.well-known/openid-configuration") == "/.well-known/openid-configuration"

    def test_rebuild_collapses_dynamic_rows(self, tmp_path, store):
        _seed_recon(tmp_path, "x.com", [
            "https://x.com/users/123",
            "https://x.com/users/456",
            "https://x.com/users/789",
        ])
        matrix = rebuild_matrix("x.com", repo_root=tmp_path)
        save_matrix("x.com", matrix, repo_root=tmp_path)
        assert [item["endpoint"] for item in matrix["endpoints"]] == ["/users/{id}"]
        assert matrix["endpoints"][0]["representative_endpoint"] == "/users/123"
        assert matrix["endpoints"][0]["source_count"] == 1
        assert matrix["endpoints"][0]["observation_count"] == 3
        gap = next(
            item
            for item in find_high_value_gaps("x.com", repo_root=tmp_path)
            if item["vuln_class"] == "IDOR"
        )
        assert gap["endpoint"] == "/users/{id}"
        assert gap["representative_endpoint"] == "/users/123"

    def test_source_count_tracks_provenance_not_duplicate_url_observations(self, tmp_path, store):
        url = "https://x.com/api/users/123"
        _seed_recon(tmp_path, "x.com", [url])
        urls_dir = tmp_path / "recon" / "x.com" / "urls"
        (urls_dir / "api_endpoints.txt").write_text(url + "\n", encoding="utf-8")
        build_surface_index(tmp_path, "x.com")

        endpoint = rebuild_matrix("x.com", repo_root=tmp_path)["endpoints"][0]

        assert endpoint["source_count"] == 2
        assert endpoint["observation_count"] == 1

    def test_query_variants_do_not_trigger_route_template_folding(self, tmp_path, store):
        _seed_recon(tmp_path, "x.com", [
            "https://x.com/users/123?view=summary",
            "https://x.com/users/123?view=detail",
        ])

        endpoint = rebuild_matrix("x.com", repo_root=tmp_path)["endpoints"][0]

        assert endpoint["endpoint"] == "/users/123"
        assert endpoint["source_count"] == 1
        assert endpoint["observation_count"] == 2

    def test_rebuild_preserves_exact_rows_with_operator_state(self, tmp_path, store):
        _seed_recon(tmp_path, "x.com", ["https://x.com/users/123"])
        save_matrix("x.com", rebuild_matrix("x.com", repo_root=tmp_path), repo_root=tmp_path)
        mark_cell("x.com", "/users/123", "IDOR", "tested_clean", repo_root=tmp_path)
        (tmp_path / "recon/x.com/urls/all.txt").write_text(
            "https://x.com/users/123\nhttps://x.com/users/456\n",
            encoding="utf-8",
        )
        matrix = rebuild_matrix("x.com", repo_root=tmp_path)
        endpoints = {item["endpoint"]: item for item in matrix["endpoints"]}
        assert endpoints["/users/123"]["cells"]["IDOR"]["status"] == "untested"
        assert endpoints["/users/123"]["cells"]["IDOR"]["review"]["value"] == "tested_clean"
        assert "/users/{id}" in endpoints

    def test_rebuild_retains_reviewed_endpoint_when_recon_no_longer_reports_it(self, tmp_path, store):
        _seed_recon(tmp_path, store.target, ["/api/v1/admin/legacy"])
        mark_cell(store.target, "/api/v1/admin/legacy", "Authz", "tested_clean",
                  reason="Operator reviewed historical route", repo_root=tmp_path)
        (tmp_path / "recon/x.com/urls/all.txt").write_text("/api/v1/admin/current\n")
        rebuilt = rebuild_matrix(store.target, repo_root=tmp_path)
        rows = {row["endpoint"]: row for row in rebuilt["endpoints"]}
        cell = rows["/api/v1/admin/legacy"]["cells"]["Authz"]
        assert cell["status"] == "untested"
        assert cell["review"]["value"] == "tested_clean"
        assert cell["review"]["reason"] == "Operator reviewed historical route"
        assert "/api/v1/admin/current" in rows


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

        semantic = _compute_summary({
            "endpoints": [{
                "endpoint": "/api/import",
                "weight": 5.0,
                "observed_params": ["url"],
                "cells": {
                    "SSRF": {"status": "untested"},
                    "IDOR": {"status": "untested"},
                },
            }],
        })
        # Both cells are evidence-backed (observed param "url"), so both count
        # as evidence-backed gaps under the observation criterion.
        assert semantic["high_value_gaps_count"] == 2
        assert semantic["actionable_high_value_gaps_count"] == 2


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

    def test_atomic_save_failure_preserves_previous_matrix(self, tmp_path, monkeypatch):
        matrix = _empty_matrix("x.com")
        save_matrix("x.com", matrix, repo_root=tmp_path)
        path = tmp_path / "evidence" / "x.com" / "coverage_matrix.json"
        previous = path.read_bytes()
        matrix["endpoints"].append({
            "endpoint": "/api/private",
            "weight": 5.0,
            "cells": {"IDOR": {"status": "untested"}},
        })
        original_replace = Path.replace

        def fail_matrix_replace(self, target):
            if Path(target) == path:
                raise OSError("synthetic replace failure")
            return original_replace(self, target)

        monkeypatch.setattr(Path, "replace", fail_matrix_replace)

        with pytest.raises(OSError, match="synthetic replace failure"):
            save_matrix("x.com", matrix, repo_root=tmp_path)

        assert path.read_bytes() == previous
        assert list(path.parent.glob(f".{path.name}.*.tmp")) == []

    def test_current_projection_refreshes_sources_without_publishing(self, tmp_path, store):
        _seed_recon(tmp_path, store.target, ["https://x.com/api/users/1"])
        projection = load_matrix_projection(store.target, repo_root=tmp_path)
        assert projection["store_id"] == store.binding()["store_id"]
        assert projection["summary"]["total_cells"] > 0
        (tmp_path / "recon/x.com/urls/all.txt").write_text("https://x.com/new\n")
        fresh = load_matrix_projection(store.target, repo_root=tmp_path)
        assert fresh["source_fingerprint"] != projection["source_fingerprint"]
        assert [row["endpoint"] for row in fresh["endpoints"]] == ["/new"]
        assert not coverage_matrix_module._matrix_path(tmp_path, store.target).exists()


class TestRebuildMatrix:
    def test_rebuild_consumes_complete_surface_index_and_tracks_its_generation(self, tmp_path, store):
        urls_dir = tmp_path / "recon" / "x.com" / "urls"
        urls_dir.mkdir(parents=True)
        urls = [f"https://x.com/api/admin/resources/{index}?tenant_id={index}" for index in range(9)]
        (urls_dir / "api_endpoints.txt").write_text("\n".join(urls), encoding="utf-8")
        build_surface_index(tmp_path, "x.com")

        matrix = rebuild_matrix("x.com", repo_root=tmp_path)

        assert {item["endpoint"] for item in matrix["endpoints"]} == {
            f"/api/admin/resources/{index}" for index in range(9)
        }
        assert matrix_is_fresh("x.com", matrix, repo_root=tmp_path) is True

        with (urls_dir / "api_endpoints.txt").open("a", encoding="utf-8") as handle:
            handle.write("\nhttps://x.com/api/admin/resources/9?tenant_id=9")
        build_surface_index(tmp_path, "x.com")

        assert matrix_is_fresh("x.com", matrix, repo_root=tmp_path) is False

    def test_source_fingerprint_skips_only_unchanged_inputs(self, tmp_path, store):
        _seed_recon(tmp_path, "x.com", ["https://x.com/api/users/1"])
        matrix = rebuild_matrix("x.com", repo_root=tmp_path)
        assert matrix_is_fresh("x.com", matrix, repo_root=tmp_path) is True

        with (tmp_path / "recon/x.com/urls/all.txt").open("a", encoding="utf-8") as handle:
            handle.write("\nhttps://x.com/api/users/2")
        assert matrix_is_fresh("x.com", matrix, repo_root=tmp_path) is False

    def test_rebuild_cli_reuses_fresh_matrix_without_rebuild_or_write(self, tmp_path, monkeypatch, capsys, store):
        _seed_recon(tmp_path, "x.com", ["https://x.com/api/users/1"])
        args = ["rebuild", "--target", "x.com", "--repo-root", str(tmp_path)]

        assert coverage_matrix_module.main(args) == 0
        path = tmp_path / "evidence" / "x.com" / "coverage_matrix.json"
        before = path.read_bytes()
        before_mtime = path.stat().st_mtime_ns

        def fail_rebuild(*_args, **_kwargs):
            raise AssertionError("fresh matrix should be reused")

        monkeypatch.setattr(coverage_matrix_module, "rebuild_matrix", fail_rebuild)

        assert coverage_matrix_module.main(args) == 0
        assert path.read_bytes() == before
        assert path.stat().st_mtime_ns == before_mtime
        assert "coverage_matrix reused:" in capsys.readouterr().out

    def test_rebuild_cli_force_clean_ignores_fresh_matrix(self, tmp_path, capsys, store):
        _seed_recon(tmp_path, "x.com", ["https://x.com/api/users/1"])
        args = ["rebuild", "--target", "x.com", "--repo-root", str(tmp_path)]
        assert coverage_matrix_module.main(args) == 0

        matrix = load_matrix("x.com", repo_root=tmp_path)
        matrix["endpoints"][0]["cells"]["XSS"] = {
            "status": "n_a",
            "reason": "operator annotation",
        }
        save_matrix("x.com", matrix, repo_root=tmp_path)

        assert coverage_matrix_module.main(args + ["--force-clean"]) == 0
        loaded = load_matrix("x.com", repo_root=tmp_path)
        assert loaded["endpoints"][0]["cells"]["XSS"]["status"] == "untested"
        assert "coverage_matrix written:" in capsys.readouterr().out

    def test_rebuild_and_read_need_no_compact_cache(self, tmp_path, store):
        _seed_recon(tmp_path, "x.com", ["https://x.com/api/users/1"])
        args = ["rebuild", "--target", "x.com", "--repo-root", str(tmp_path)]
        assert coverage_matrix_module.main(args) == 0
        path = tmp_path / "evidence/x.com/coverage_matrix.json"
        before = path.read_bytes(), path.stat().st_mtime_ns, store.binding()
        assert coverage_matrix_module.main(args) == 0
        matrix = load_matrix_projection("x.com", tmp_path)
        assert matrix["summary"]["total_cells"] == len(VULN_CLASSES)
        assert (path.read_bytes(), path.stat().st_mtime_ns, store.binding()) == before
        assert not (path.parent / "coverage_matrix-summary.json").exists()

    def test_rebuild_does_not_expand_ffuf_only_evidence(self, tmp_path, store):
        dirs = tmp_path / "recon" / "x.com" / "dirs"
        dirs.mkdir(parents=True)
        (dirs / "ffuf_results.jsonl").write_text(
            json.dumps({
                "url": "https://x.com/admin",
                "status": 403,
                "length": 123,
                "words": 10,
                "lines": 2,
                "content-type": "text/html",
                "input": {"FUZZ": "admin"},
            }) + "\n",
            encoding="utf-8",
        )

        matrix = rebuild_matrix("x.com", repo_root=tmp_path)

        assert matrix["endpoints"] == []

    def test_rebuild_from_recon_urls(self, tmp_path, store):
        _seed_recon(tmp_path, "x.com", [
            "/api/v1/admin/users",        # weight high (admin + api_v)
            "/api/v1/orders/123",          # weight (api_v)
            "/blog/post-1",                # weight low — should be skipped at default 1.0
        ])
        matrix = rebuild_matrix("x.com", repo_root=tmp_path)
        endpoints = [ep["endpoint"] for ep in matrix["endpoints"]]
        # High-value paths must be in matrix
        assert "/api/v1/admin/users" in endpoints
        # Unfamiliar and static-looking paths remain visible too.
        assert "/blog/post-1" in endpoints

    def test_rebuild_normalizes_attack_probe_without_losing_surface(self, tmp_path, store):
        _seed_recon(tmp_path, "x.com", [
            "/rest/admin/application-configuration",
            "/rest/admin/%5C%22/",
            "/api/search?q=<script>alert(1)</script>",
        ])
        matrix = rebuild_matrix("x.com", repo_root=tmp_path)
        endpoints = [ep["endpoint"] for ep in matrix["endpoints"]]

        assert "/rest/admin/application-configuration" in endpoints
        assert "/rest/admin" in endpoints
        assert "/api/search" in endpoints
        assert "/rest/admin/%5C%22/" not in endpoints

        by_endpoint = {ep["endpoint"]: ep for ep in matrix["endpoints"]}
        admin_ep = by_endpoint["/rest/admin"]
        assert "route_prefix_candidate" in admin_ep["auto_hints"]
        assert admin_ep["source_count"] == 1
        assert "weight" not in admin_ep

    def test_rebuild_uses_filtered_view_when_legacy_raw_backstop_exists(self, tmp_path, store):
        _seed_recon_with_filtered(
            tmp_path,
            "x.com",
            raw_urls=[
                "/api/v1/admin/users",
                "/api/v1/orders/123",
            ],
            filtered_urls=[
                "/api/v1/admin/users",
            ],
        )
        matrix = rebuild_matrix("x.com", repo_root=tmp_path)
        endpoints = [ep["endpoint"] for ep in matrix["endpoints"]]

        assert "/api/v1/admin/users" in endpoints
        assert "/api/v1/orders/123" not in endpoints

    def test_rebuild_does_not_restore_logged_js_path_artifact_from_raw_backstop(self, tmp_path, store):
        artifact = "https://x.com/i.visualViewport.scale/i.document.do"
        _seed_recon_with_filtered(
            tmp_path,
            "x.com",
            raw_urls=[
                "https://x.com/rest/admin/application-configuration",
                artifact,
            ],
            filtered_urls=[
                "https://x.com/rest/admin/application-configuration",
            ],
            filter_log=f"[JS_PATH_ARTIFACT] {artifact}\n",
        )
        matrix = rebuild_matrix("x.com", repo_root=tmp_path)
        endpoints = [ep["endpoint"] for ep in matrix["endpoints"]]

        assert "/rest/admin/application-configuration" in endpoints
        assert "/i.visualViewport.scale/i.document.do" not in endpoints

    def test_rebuild_drops_minified_js_pseudo_endpoint_without_filter_log(self, tmp_path, store):
        _seed_recon(tmp_path, "x.com", [
            "https://x.com/i.visualViewport.scale/i.document.do",
            "https://x.com/rest/admin/application-configuration",
        ])

        matrix = rebuild_matrix("x.com", repo_root=tmp_path)
        endpoints = [ep["endpoint"] for ep in matrix["endpoints"]]

        assert "/i.visualViewport.scale/i.document.do" not in endpoints
        assert "/rest/admin/application-configuration" in endpoints

    def test_static_and_public_metadata_stay_visible_without_predicted_value(self, tmp_path, store):
        _seed_recon(tmp_path, "x.com", [
            "https://x.com/assets/public/images/logo.png",
            "https://x.com/.well-known/csaf/provider-metadata.json",
            "https://x.com/__/firebase/init.json",
            "https://x.com/.well-known/oauth-authorization-server",
            "https://x.com/.well-known/oauth-protected-resource",
            "https://x.com/rest/admin/application-configuration",
        ])

        matrix = rebuild_matrix("x.com", repo_root=tmp_path)
        by_endpoint = {ep["endpoint"]: ep for ep in matrix["endpoints"]}

        static_ep = by_endpoint["/assets/public/images/logo.png"]
        assert static_ep["endpoint_kind"] == "untriaged"
        assert "static_asset_shape" in static_ep["auto_hints"]
        assert "weight" not in static_ep
        assert {cell["status"] for cell in static_ep["cells"].values()} == {"untested"}

        metadata_ep = by_endpoint["/.well-known/csaf/provider-metadata.json"]
        assert metadata_ep["endpoint_kind"] == "untriaged"
        assert "public_metadata_path" in metadata_ep["auto_hints"]
        assert "weight" not in metadata_ep
        assert {cell["status"] for cell in metadata_ep["cells"].values()} == {"untested"}

        for endpoint in (
            "/__/firebase/init.json",
            "/.well-known/oauth-authorization-server",
            "/.well-known/oauth-protected-resource",
        ):
            assert "public_metadata_path" in by_endpoint[endpoint]["auto_hints"]
            assert "weight" not in by_endpoint[endpoint]

        save_matrix("x.com", matrix, repo_root=tmp_path)
        gaps = find_high_value_gaps("x.com", repo_root=tmp_path)
        gap_endpoints = {gap["endpoint"] for gap in gaps}
        assert "/assets/public/images/logo.png" in gap_endpoints
        assert "/.well-known/csaf/provider-metadata.json" in gap_endpoints
        assert "/__/firebase/init.json" in gap_endpoints
        assert "/.well-known/oauth-authorization-server" in gap_endpoints
        assert "/.well-known/oauth-protected-resource" in gap_endpoints

    def test_route_prefix_like_endpoint_stays_visible_for_ai_judgement(self, tmp_path, store):
        _seed_recon(tmp_path, "x.com", [
            "https://x.com/rest/admin",
            "https://x.com/rest/admin/application-configuration",
        ])

        matrix = rebuild_matrix("x.com", repo_root=tmp_path)
        by_endpoint = {ep["endpoint"]: ep for ep in matrix["endpoints"]}

        prefix_ep = by_endpoint["/rest/admin"]
        child_ep = by_endpoint["/rest/admin/application-configuration"]
        assert prefix_ep["endpoint_kind"] == "untriaged"
        assert "api_like_path" in prefix_ep["auto_hints"]
        assert "route_prefix_candidate" in prefix_ep["auto_hints"]
        assert prefix_ep["source_count"] == 1
        assert "weight" not in prefix_ep
        assert prefix_ep["cells"]["Authz"]["status"] == "untested"
        assert child_ep["endpoint_kind"] == "untriaged"
        assert child_ep["cells"]["Authz"]["status"] == "untested"

    def test_ai_marked_route_prefix_closes_only_container(self, tmp_path, store):
        _seed_recon(tmp_path, "x.com", [
            "https://x.com/rest/admin",
            "https://x.com/rest/admin/application-configuration",
        ])
        matrix = rebuild_matrix("x.com", repo_root=tmp_path)
        save_matrix("x.com", matrix, repo_root=tmp_path)

        marked = mark_endpoint_kind(
            "x.com",
            "/rest/admin",
            "route_prefix",
            reason="container path; test concrete child handlers instead",
            repo_root=tmp_path,
        )
        assert marked["kind_review"]["value"] == "route_prefix"

        rebuilt = rebuild_matrix("x.com", repo_root=tmp_path)
        save_matrix("x.com", rebuilt, repo_root=tmp_path)
        by_endpoint = {ep["endpoint"]: ep for ep in rebuilt["endpoints"]}
        assert by_endpoint["/rest/admin"]["endpoint_kind"] == "route_prefix"
        assert {cell["status"] for cell in by_endpoint["/rest/admin"]["cells"].values()} == {"n_a"}
        assert by_endpoint["/rest/admin/application-configuration"]["cells"]["Authz"]["status"] == "untested"

        gaps = find_high_value_gaps("x.com", repo_root=tmp_path)
        gap_endpoints = {gap["endpoint"] for gap in gaps}
        assert "/rest/admin" not in gap_endpoints
        assert "/rest/admin/application-configuration" in gap_endpoints

    def test_needs_triage_lists_untriaged_endpoints_with_hints(self, tmp_path, store):
        _seed_recon(tmp_path, "x.com", [
            "https://x.com/rest/admin",
            "https://x.com/assets/app.js",
        ])
        matrix = rebuild_matrix("x.com", repo_root=tmp_path)
        save_matrix("x.com", matrix, repo_root=tmp_path)

        items = needs_endpoint_triage("x.com", repo_root=tmp_path)
        by_endpoint = {item["endpoint"]: item for item in items}

        assert "/rest/admin" in by_endpoint
        assert "api_like_path" in by_endpoint["/rest/admin"]["auto_hints"]
        assert "/assets/app.js" in by_endpoint
        assert "static_asset_shape" in by_endpoint["/assets/app.js"]["auto_hints"]

    def test_mark_endpoint_kind_persists_across_rebuild(self, tmp_path, store):
        _seed_recon(tmp_path, "x.com", [
            "https://x.com/orders",
        ])
        matrix = rebuild_matrix("x.com", repo_root=tmp_path)
        save_matrix("x.com", matrix, repo_root=tmp_path)

        marked = mark_endpoint_kind(
            "x.com",
            "/orders",
            "page_route",
            reason="SPA page route; capture underlying XHR before replay",
            repo_root=tmp_path,
        )
        assert marked["endpoint_kind"] == "page_route"
        assert marked["kind_source"] == "ai_triage"

        rebuilt = rebuild_matrix("x.com", repo_root=tmp_path)
        by_endpoint = {ep["endpoint"]: ep for ep in rebuilt["endpoints"]}
        assert by_endpoint["/orders"]["endpoint_kind"] == "page_route"
        assert by_endpoint["/orders"]["kind_reason"].startswith("SPA page route")

        remaining = needs_endpoint_triage("x.com", repo_root=tmp_path)
        assert "/orders" not in {item["endpoint"] for item in remaining}

    def test_rebuild_creates_all_vuln_class_cells(self, tmp_path, store):
        _seed_recon(tmp_path, "x.com", ["/api/v1/admin/users"])
        matrix = rebuild_matrix("x.com", repo_root=tmp_path)
        cells = matrix["endpoints"][0]["cells"]
        for vc in VULN_CLASSES:
            assert vc in cells
            assert cells[vc]["status"] == "untested"

    def test_rebuild_preserves_store_reviews_as_advisory(self, tmp_path, store):
        _seed_recon(tmp_path, "x.com", ["/api/v1/admin/users"])
        mark_cell("x.com", "/api/v1/admin/users", "XSS", "n_a", reason="no input", repo_root=tmp_path)
        rebuild_matrix("x.com", repo_root=tmp_path)
        coverage_matrix_module._matrix_path(tmp_path, "x.com").unlink()
        cell = read_matrix("x.com", tmp_path)["endpoints"][0]["cells"]["XSS"]
        assert cell["status"] == "untested"
        assert cell["review"]["value"] == "n_a"
        assert cell["review"]["reason"] == "no input"

    def test_force_clean_wipes_annotations(self, tmp_path, store):
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
        TargetStore(tmp_path, "ghost.com").initialize()
        matrix = rebuild_matrix("ghost.com", repo_root=tmp_path)
        assert matrix["endpoints"] == []

    def test_findings_mark_tested_finding(self, tmp_path, store):
        _seed_recon(tmp_path, "x.com", ["/api/v1/orders/123"])
        _claim(store, 'F-1', '/api/v1/orders/123', 'IDOR')
        matrix = rebuild_matrix("x.com", repo_root=tmp_path)
        ep = [e for e in matrix["endpoints"] if e["endpoint"] == "/api/v1/orders/123"][0]
        assert ep["cells"]["IDOR"]["status"] == "untested"

    def test_rebuild_adds_endpoints_from_findings_only(self, tmp_path, store):
        """PR-12 audit: an endpoint present ONLY in findings.json (absent
        from recon URLs) must end up in the matrix with `tested_finding`
        on the right cell. Pilot 2026-05-15 surfaced this as a real gap
        — wp-json/* endpoints discovered through working_hypothesis
        exploration never made it into the matrix.
        """
        # Recon contains ONE endpoint only
        _seed_recon(tmp_path, "x.com", ["/api/v1/orders/123"])
        # findings.json adds a SECOND, distinct endpoint not in recon
        _claim(store, 'F-1', '/api/v1/orders/123', 'IDOR')
        _claim(store, 'F-2', '/wp-json/wp/v2/users', 'Authz')
        matrix = rebuild_matrix("x.com", repo_root=tmp_path)
        endpoints = {ep["endpoint"] for ep in matrix["endpoints"]}
        # Both endpoints must be present
        assert "/api/v1/orders/123" in endpoints
        assert "/wp-json/wp/v2/users" in endpoints
        # The findings-only endpoint has the right cell marked
        wp_ep = next(ep for ep in matrix["endpoints"] if ep["endpoint"] == "/wp-json/wp/v2/users")
        assert wp_ep["cells"]["Authz"]["status"] == "untested"
        # All vuln_class cells exist on the new endpoint (not just the marked one)
        for vc in VULN_CLASSES:
            assert vc in wp_ep["cells"]

    def test_findings_for_folded_route_mark_template_cell(self, tmp_path, store):
        _seed_recon(tmp_path, "x.com", [
            "https://x.com/api/v1/orders/123",
            "https://x.com/api/v1/orders/456",
        ])
        _claim(store, 'F-folded', '/api/v1/orders/123', 'IDOR')

        matrix = rebuild_matrix("x.com", repo_root=tmp_path)
        endpoints = {ep["endpoint"]: ep for ep in matrix["endpoints"]}

        assert "/api/v1/orders/{id}" in endpoints
        assert "/api/v1/orders/123" not in endpoints
        assert endpoints["/api/v1/orders/{id}"]["cells"]["IDOR"]["status"] == "untested"

    def test_rebuild_preserves_ai_kind_for_findings_only_endpoint(self, tmp_path, store):
        _seed_recon(tmp_path, "x.com", [])
        _claim(store, 'F-1', '/rest/products/search?q=', 'SQLi')

        first = rebuild_matrix("x.com", repo_root=tmp_path)
        save_matrix("x.com", first, repo_root=tmp_path)
        mark_endpoint_kind(
            "x.com",
            "/rest/products/search",
            "api_endpoint",
            reason="browser-observed query API",
            repo_root=tmp_path,
        )

        rebuilt = rebuild_matrix("x.com", repo_root=tmp_path)
        by_endpoint = {ep["endpoint"]: ep for ep in rebuilt["endpoints"]}
        ep = by_endpoint["/rest/products/search"]
        assert ep["endpoint_kind"] == "api_endpoint"
        assert ep["kind_reason"] == "browser-observed query API"
        assert ep["cells"]["SQLi"]["status"] == "untested"

    def test_rebuild_handles_full_url_in_findings(self, tmp_path, store):
        """A finding's endpoint may be a full URL (https://host/path) —
        canonicalization must strip scheme + host before matrix lookup.
        Otherwise the same logical endpoint creates two distinct rows.
        """
        _seed_recon(tmp_path, "x.com", [])  # no recon URLs
        _claim(store, 'F-1', 'https://wp.x.com/wp-json/wp/v2/users', 'Authz')
        matrix = rebuild_matrix("x.com", repo_root=tmp_path)
        # The endpoint should appear with its canonical path (no scheme/host)
        endpoints = {ep["endpoint"] for ep in matrix["endpoints"]}
        assert "/wp-json/wp/v2/users" in endpoints
        # And the marked cell exists
        ep = next(ep for ep in matrix["endpoints"] if ep["endpoint"] == "/wp-json/wp/v2/users")
        assert ep["cells"]["Authz"]["status"] == "untested"


class TestFindGaps:
    def test_returns_untested_cells_without_word_scores(self, tmp_path, store):
        _seed_recon(tmp_path, "x.com", [
            "/api/v1/admin/users",   # weight high
            "/api/v1/orders/123",     # weight medium
        ])
        matrix = rebuild_matrix("x.com", repo_root=tmp_path)
        save_matrix("x.com", matrix, repo_root=tmp_path)
        gaps = find_high_value_gaps("x.com", repo_root=tmp_path)
        # Every gap has an endpoint, vuln_class, and weight >= 3.0
        for gap in gaps:
            assert "endpoint" in gap
            assert "vuln_class" in gap
            assert "weight" not in gap
            assert "relevance_score" not in gap

    def test_legacy_weight_cannot_hide_untested_cells(self, tmp_path):
        matrix = _empty_matrix("x.com")
        matrix["endpoints"] = [
            {"endpoint": "/plain", "weight": 0, "cells": {"SQLi": {"status": "untested"}}},
            {"endpoint": "/admin", "weight": 100, "cells": {"Authz": {"status": "tested_clean"}}},
        ]
        gaps = high_value_gaps_from_matrix(matrix)
        assert [(g["endpoint"], g["vuln_class"]) for g in gaps] == [("/plain", "SQLi")]
        assert "weight" not in gaps[0]

    def test_empty_matrix_yields_empty_gaps(self, tmp_path):
        TargetStore(tmp_path, "ghost.com").initialize()
        gaps = find_high_value_gaps("ghost.com", repo_root=tmp_path)
        assert gaps == []

    def test_cli_limit_is_presentation_only_and_reports_total(self, tmp_path, monkeypatch, capsys, store):
        _seed_recon(tmp_path, "x.com", ["https://x.com/api/admin/users"])
        save_matrix("x.com", rebuild_matrix("x.com", repo_root=tmp_path), repo_root=tmp_path)

        full_rc = coverage_matrix_module.main([
            "find-gaps", "--target", "x.com", "--repo-root", str(tmp_path),
        ])
        assert full_rc == 0
        full = json.loads(capsys.readouterr().out)
        assert isinstance(full, list)
        assert len(full) > 1

        def fail_full_gap_materialization(*_args, **_kwargs):
            raise AssertionError("limited output should not materialize every gap")

        monkeypatch.setattr(
            coverage_matrix_module,
            "high_value_gaps_from_matrix",
            fail_full_gap_materialization,
        )

        limited_rc = coverage_matrix_module.main([
            "find-gaps", "--target", "x.com", "--repo-root", str(tmp_path),
            "--limit", "1",
        ])
        assert limited_rc == 0
        limited = json.loads(capsys.readouterr().out)
        assert limited["items"] == full[:1]
        assert limited["total"] == len(full)
        assert limited["returned"] == 1
        assert limited["truncated"] is True

    def test_cli_default_keeps_unfamiliar_and_keyword_named_routes(self, tmp_path, capsys, store):
        _seed_recon(tmp_path, "x.com", ["https://x.com/plain/path", "https://x.com/api/import?url=one"])
        rebuild_matrix("x.com", repo_root=tmp_path)
        assert coverage_matrix_module.main(["find-gaps", "--target", "x.com", "--repo-root", str(tmp_path)]) == 0
        gaps = json.loads(capsys.readouterr().out)
        assert {item["endpoint"] for item in gaps} == {"/plain/path", "/api/import"}
        assert all("relevance_score" not in item and "weight" not in item for item in gaps)


    def test_parameter_names_do_not_choose_a_vulnerability_class(self, tmp_path, store):
        _seed_recon(tmp_path, "x.com", [
            "https://api.x.com/api/admin/users?isAdmin=true&userId=1001",
        ])
        matrix = rebuild_matrix("x.com", repo_root=tmp_path)
        save_matrix("x.com", matrix, repo_root=tmp_path)

        gaps = find_high_value_gaps("x.com", repo_root=tmp_path)
        endpoint_gaps = [g for g in gaps if g["endpoint"] == "/api/admin/users"]

        # Fact-ordered ranking: ordering follows route-kind/params/weight/impact,
        # not word-list relevance, so any class may lead. What must hold: the
        # evidence-backed gap set includes the word-relevant classes with their
        # relevance annotation intact (visible to AI, outside the ordering).
        assert endpoint_gaps
        assert {g["vuln_class"] for g in endpoint_gaps} >= {"Authz", "IDOR"}
        assert {g["vuln_class"] for g in endpoint_gaps} == set(VULN_CLASSES)
        assert all("relevance_score" not in g for g in endpoint_gaps)
        ep = load_matrix("x.com", repo_root=tmp_path)["endpoints"][0]
        assert set(ep["observed_params"]) == {"isAdmin", "userId"}

    @pytest.mark.parametrize(
        ("url", "expected_class"),
        [
            ("https://api.x.com/api/v1/fetch?url=http://127.0.0.1/", "SSRF"),
            ("https://api.x.com/download?file=readme.txt", "Path"),
            ("https://api.x.com/api/render?template=invoice", "RCE"),
            ("https://api.x.com/api/search?q=test&sort=created_at", "SQLi"),
        ],
    )
    def test_class_named_routes_keep_every_canonical_family(self, tmp_path, url, expected_class, store):
        _seed_recon(tmp_path, "x.com", [url])
        matrix = rebuild_matrix("x.com", repo_root=tmp_path)
        save_matrix("x.com", matrix, repo_root=tmp_path)

        endpoint = _canonicalize_endpoint(url)
        gaps = [
            g for g in find_high_value_gaps("x.com", repo_root=tmp_path)
            if g["endpoint"] == endpoint
        ]

        # Ordering is fact-based; the word-relevant class stays present with a
        # positive relevance annotation the AI can read.
        assert gaps
        assert expected_class in {g["vuln_class"] for g in gaps}
        assert {g["vuln_class"] for g in gaps} == set(VULN_CLASSES)
        assert all("relevance_score" not in g for g in gaps)


    def test_sqli_semantics_require_real_query_signals_not_resource_words(self, tmp_path, store):
        """`select` / `order` 资源名不应单靠路径触发 SQLi 高价值 gap。"""
        _seed_recon(tmp_path, "x.com", [
            "https://api.x.com/rest/order-history",
            "https://api.x.com/address/select",
            "https://api.x.com/rest/products/search?q=test",
        ])
        matrix = rebuild_matrix("x.com", repo_root=tmp_path)
        save_matrix("x.com", matrix, repo_root=tmp_path)

        gaps = find_high_value_gaps("x.com", repo_root=tmp_path)
        gap_pairs = {(gap["endpoint"], gap["vuln_class"]) for gap in gaps}
        top_gap_pairs = {(gap["endpoint"], gap["vuln_class"]) for gap in gaps[:5]}

        assert ("/rest/order-history", "SQLi") not in top_gap_pairs
        assert ("/address/select", "SQLi") in gap_pairs
        assert ("/rest/products/search", "SQLi") in gap_pairs


    def test_payload_shaped_dom_paths_rank_as_xss_not_ssrf_or_rce(self, tmp_path, store):
        _seed_recon(tmp_path, "x.com", [
            "https://x.com/urldom/location/hash/fetch",
            "https://x.com/reflected/filteredstrings/body/caseSensitive/script?q=a",
        ])
        matrix = rebuild_matrix("x.com", repo_root=tmp_path)
        save_matrix("x.com", matrix, repo_root=tmp_path)

        gaps = find_high_value_gaps("x.com", repo_root=tmp_path)
        classes_by_endpoint = {}
        for gap in gaps:
            classes_by_endpoint.setdefault(gap["endpoint"], set()).add(gap["vuln_class"])

        # Fact ordering no longer puts the word-relevant class first, but the
        # XSS signal stays present and annotated on these DOM-shaped paths.
        assert "XSS" in classes_by_endpoint["/urldom/location/hash/fetch"]
        assert "XSS" in classes_by_endpoint["/reflected/filteredstrings/body/caseSensitive/script"]

    def test_unbalanced_archive_path_stays_raw_but_not_in_coverage_queue(self, tmp_path, store):
        malformed = "https://x.com/dom/index.html.[10"
        valid = "https://x.com/dom/index.html"
        _seed_recon(tmp_path, "x.com", [malformed, valid])

        matrix = rebuild_matrix("x.com", repo_root=tmp_path)

        endpoints = {item["endpoint"] for item in matrix["endpoints"]}
        assert "/dom/index.html.[10" not in endpoints
        assert "/dom/index.html" in endpoints
        assert malformed in (tmp_path / "recon" / "x.com" / "urls" / "all.txt").read_text()


    def test_embedded_external_path_noise_is_excluded_without_dropping_query_urls(self, tmp_path, store):
        malformed = [
            "https://x.com/articles/http://external.example/report",
            "https://x.com/articles/annual%0Areport",
            "https://x.com/articles/annual%09report",
            r"https://x.com/articles/annual%5Cnreport",
            r"https://x.com/articles/%5Cu003Cdiv%5Cu003E",
            r"https://x.com/articles/\u003cdiv\u003e",
            "https://x.com/articles/http&#x3a;//external.example/report",
            "https://x.com/articles/http&colon;//external.example/report",
            "https://x.com/articles/http%25253a%25252f%25252fexternal.example/report",
        ]
        query_url = "https://x.com/api/fetch?url=http://127.0.0.1:80/"
        _seed_recon(tmp_path, "x.com", [*malformed, query_url])

        matrix = rebuild_matrix("x.com", repo_root=tmp_path)

        endpoints = {item["endpoint"] for item in matrix["endpoints"]}
        assert not any(endpoint.startswith("/articles/") for endpoint in endpoints)
        assert "/api/fetch" in endpoints

    def test_numeric_paths_are_not_dropped_by_value_words(self, tmp_path, store):
        _seed_recon(tmp_path, "x.com", [
            "https://app.x.com/16",
            "https://app.x.com/orders/16",
        ])
        matrix = rebuild_matrix("x.com", repo_root=tmp_path)
        save_matrix("x.com", matrix, repo_root=tmp_path)

        endpoints = {ep["endpoint"]: ep for ep in load_matrix("x.com", repo_root=tmp_path)["endpoints"]}
        gaps = find_high_value_gaps("x.com", repo_root=tmp_path)
        gap_pairs = {(gap["endpoint"], gap["vuln_class"]) for gap in gaps}

        assert "/16" in endpoints
        assert "/orders/16" in endpoints
        assert ("/16", "IDOR") in gap_pairs

    def test_race_semantics_require_state_transition_not_state_resource_words(self, tmp_path, store):
        """`order` / `balance` 资源名不应单靠路径触发 Race 高价值 gap。"""
        _seed_recon(tmp_path, "x.com", [
            "https://api.x.com/rest/order-history",
            "https://api.x.com/rest/track-order",
            "https://api.x.com/rest/wallet/balance",
            "https://api.x.com/api/cart/checkout",
            "https://api.x.com/api/payment/confirm?coupon=SAVE10",
        ])
        matrix = rebuild_matrix("x.com", repo_root=tmp_path)
        save_matrix("x.com", matrix, repo_root=tmp_path)

        gaps = find_high_value_gaps("x.com", repo_root=tmp_path)
        gap_pairs = {(gap["endpoint"], gap["vuln_class"]) for gap in gaps}

        assert ("/rest/order-history", "Race") in gap_pairs
        assert ("/rest/track-order", "Race") in gap_pairs
        assert ("/rest/wallet/balance", "Race") in gap_pairs
        assert ("/api/cart/checkout", "Race") in gap_pairs
        assert ("/api/payment/confirm", "Race") in gap_pairs


def test_high_value_gap_preserves_explicit_closure_identity(tmp_path):
    identity = {
        "schema_version": 2,
        "kind": "closure_cell",
        "endpoint": {"schema_version": 2, "kind": "endpoint", "endpoint": "/api/search?q="},
        "family": "SQLi",
        "dimensions": {"method": "GET", "parameter": "q"},
    }
    matrix = _empty_matrix("x.com")
    matrix["endpoints"] = [{
        "endpoint": "/api/search?q=",
        "weight": 5.0,
        "observed_params": ["q"],
        "source_count": 1,
        "cells": {
            vuln_class: (
                {"status": "untested", "identity_v2": identity}
                if vuln_class == "SQLi"
                else {"status": "n_a", "reason": "fixture"}
            )
            for vuln_class in VULN_CLASSES
        },
    }]
    gap = next(item for item in high_value_gaps_from_matrix(matrix) if item["vuln_class"] == "SQLi")
    assert gap["identity_v2"] == identity


class TestMarkCell:
    def test_mark_creates_advisory_endpoint_if_missing(self, tmp_path, store):
        marked = mark_cell("x.com", "/admin/x", "IDOR", "n_a", reason="read-only resource", repo_root=tmp_path)
        assert marked["advisory"] is True
        assert marked["review"]["value"] == "n_a"
        ep = read_matrix("x.com", tmp_path)["endpoints"][0]
        assert ep["endpoint"] == "/admin/x"
        assert ep["cells"]["IDOR"]["status"] == "untested"
        assert ep["cells"]["IDOR"]["review"]["reason"] == "read-only resource"

    def test_mark_appends_review_and_preserves_prior_input(self, tmp_path, store):
        first = mark_cell("x.com", "/admin/x", "IDOR", "untested", repo_root=tmp_path)
        second = mark_cell("x.com", "/admin/x", "IDOR", "tested_clean", repo_root=tmp_path)
        cell = read_matrix("x.com", tmp_path)["endpoints"][0]["cells"]["IDOR"]
        assert cell["status"] == "untested"
        assert cell["review"]["id"] == second["review"]["id"]
        assert store.coverage_review(first["review"]["id"])["value"] == "untested"

    def test_invalid_vuln_class_rejected(self, tmp_path, store):
        with pytest.raises(ValueError):
            mark_cell("x.com", "/admin/x", "Bogus", "untested", repo_root=tmp_path)

    def test_invalid_status_rejected(self, tmp_path, store):
        with pytest.raises(ValueError):
            mark_cell("x.com", "/admin/x", "IDOR", "bogus", repo_root=tmp_path)

    def test_mark_with_write_finding_creates_unassessed_store_claim(self, tmp_path, store):
        result = mark_cell("x.com", "/wp-json/wp/v2/users", "Authz", "tested_finding",
                           reason="User enumeration claim", repo_root=tmp_path, write_finding=True)
        finding = store.finding(result["review"]["finding_id"])
        assert finding["endpoint"] == "https://x.com/wp-json/wp/v2/users"
        assert finding["family"] == "Authz"
        assert finding["claim"] == "User enumeration claim"
        assert finding["assessment"] is None
        assert store.page("operations")["total"] == 0
        assert not (tmp_path / "findings/x.com/findings.json").exists()

    def test_primary_mark_with_write_finding_uses_store_claim_owner(self, tmp_path):
        from tools.target_store import TargetStore

        target = "primary-coverage.test"
        store = TargetStore(tmp_path, target)
        store.initialize()
        mark_cell(
            target, "/api/orders", "Authz", "tested_finding",
            reason="peer object was returned", repo_root=tmp_path, write_finding=True,
        )
        findings = store.page("findings")["items"]
        assert len(findings) == 1
        assert findings[0]["endpoint"] == "https://primary-coverage.test/api/orders"
        assert not (tmp_path / "findings" / target / "findings.json").exists()

    def test_primary_store_revision_invalidates_coverage_projection(self, tmp_path):
        from tools.target_store import TargetStore

        target = "primary-coverage.test"
        urls = tmp_path / "recon" / target / "urls"
        urls.mkdir(parents=True)
        (urls / "all.txt").write_text("https://primary-coverage.test/api/orders\n", encoding="utf-8")
        store = TargetStore(tmp_path, target)
        store.initialize()
        matrix = rebuild_matrix(target, repo_root=tmp_path)
        assert matrix["backend"] == "primary"
        assert matrix["store_id"] == store.context(limit=1)["store_id"]
        assert matrix_is_fresh(target, matrix, repo_root=tmp_path)

        store.create_finding(
            command_id="finding-revision-1", finding_id="F-1",
            endpoint="https://primary-coverage.test/api/orders", method="GET",
            family="Authz", title="peer read", claim="peer object was returned", actor="operator",
        )
        assert not matrix_is_fresh(target, matrix, repo_root=tmp_path)

    def test_write_finding_idempotent(self, tmp_path, store):
        for _ in range(3):
            mark_cell("x.com", "/wp-json/wp/v2/users", "Authz", "tested_finding",
                      reason="Unassessed claim", repo_root=tmp_path, write_finding=True, command_id="same-command")
        assert store.page("findings")["total"] == 1
        assert store.coverage_review_page()["total"] == 1
        assert store.binding()["revision"] == 1

    def test_write_finding_preserves_existing_claim(self, tmp_path, store):
        _claim(store, "existing", "/search?q=1", "SQLi")
        before = store.finding("existing")
        mark_cell("x.com", "/api/orders/1", "IDOR", "tested_finding",
                  reason="owner/peer divergence", repo_root=tmp_path, write_finding=True)
        assert store.page("findings")["total"] == 2
        assert store.finding("existing") == {**before, "revision": store.binding()["revision"]}

    def test_write_finding_skipped_for_non_finding_status(self, tmp_path, store):
        """write_finding only takes effect for status=tested_finding."""
        mark_cell(
            "x.com", "/admin/x", "IDOR", "n_a",
            reason="read-only baseline", repo_root=tmp_path, write_finding=True,
        )
        findings_path = tmp_path / "findings" / "x.com" / "findings.json"
        # No findings.json should be created for n_a marks
        assert not findings_path.is_file()

    def test_rebuild_after_write_finding_preserves_cell(self, tmp_path, store):
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
        assert ep["cells"]["Authz"]["status"] == "untested"


class TestQuestionToToolDiscoverability:
    """PRD R5 + Contract 6: tool must appear in Q->Tool table."""

    def test_autopilot_md_has_find_gaps_row(self):
        md = (REPO_ROOT / "commands" / "autopilot.md").read_text(encoding="utf-8")
        assert "rules/coverage-gate.md" in md
        owner = (REPO_ROOT / "rules/coverage-gate.md").read_text(encoding="utf-8")
        assert "tools/coverage_matrix.py find-gaps" in owner

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


class TestCoverageGateFourStateInterface:
    """A5 (task 09-11-ai-capability-roadmap batch 6): the AI-facing coverage
    interface collapses to 4 states while the 9 storage states and the
    reason discipline stay intact. Structural anchors only, per PRD C4.
    """

    def _gate_md(self) -> str:
        return (REPO_ROOT / "rules" / "coverage-gate.md").read_text(encoding="utf-8")

    def test_nine_storage_states_table_is_preserved(self):
        """The 9-state table survives as the internal storage model."""
        md = self._gate_md()
        assert "### 内部存储状态（9 态）" in md
        for state in (
            "unknown", "queued", "tested", "lead", "signal",
            "candidate", "blocked", "n/a", "dead-end",
        ):
            assert f"`{state}`" in md, f"storage state {state!r} missing"

    def test_four_state_interface_section_exists(self):
        """The AI-facing interface section declares the 4 states."""
        md = self._gate_md()
        assert "### AI 接口状态（4 态）" in md
        for state in ("untested", "investigating", "confirmed", "ruled_out"):
            assert f"`{state}`" in md, f"interface state {state!r} missing"

    def test_mapping_table_covers_all_nine_storage_states(self):
        """Every storage state is projected to exactly one interface state.

        blocked -> investigating and n/a -> ruled_out are deliberate design
        decisions (blocked is an investigation on hold; n/a is an explicit
        not-applicable ruling) and are asserted here so they cannot drift.
        """
        md = self._gate_md()
        assert "### 4 态 ↔ 9 态映射" in md
        expected = {
            "unknown": "untested",
            "queued": "untested",
            "lead": "investigating",
            "signal": "investigating",
            "candidate": "investigating",
            "blocked": "investigating",
            "tested": "ruled_out",
            "n/a": "ruled_out",
            "dead-end": "ruled_out",
        }
        # The projection row asserts the storage states explicitly.
        assert "`unknown`、`queued`" in md
        assert "`lead`、`signal`、`candidate`、`blocked`" in md
        assert "`tested`、`n/a`、`dead-end`" in md
        # Deliberate placements stated in prose.
        assert "blocked` 归 `investigating`，理由写阻塞原因" in md
        assert "不适用原因（n/a）/ 证伪原因（dead-end）" in md
        # The mapping table itself must not assign any storage state to
        # `confirmed` — confirmed has no per-cell preimage and comes from the
        # finding lifecycle only. Guard against a future edit that "fixes"
        # this by inventing a 9-state preimage (e.g. mapping `candidate`
        # straight to `confirmed`, which would bypass /validate).
        confirm_row = next(
            line for line in md.splitlines()
            if line.startswith("| `confirmed` |") and "无逐格对应物" in line
        )
        assert "candidate 经 `/validate` 确证" in confirm_row
        # The read-direction mapping table lists exactly the 4 interface
        # states as row keys. A row keyed by a 9-state name (candidate, etc.)
        # would break the storage/interface separation, so pin the row keys.
        lines = md.splitlines()
        start = lines.index("### 4 态 ↔ 9 态映射")
        end = next(
            i for i in range(start, len(lines))
            if lines[i].startswith("## ")
        )
        row_keys = [
            line.split("|")[1].strip()
            for line in lines[start:end]
            if line.startswith("| `")
        ]
        assert row_keys == [
            "`untested`", "`investigating`", "`confirmed`", "`ruled_out`",
        ], f"mapping table row keys drifted: {row_keys}"

    def test_reason_field_is_part_of_the_mapping_not_decoration(self):
        """The doc must state that the reason field carries the mapping
        detail (which sub-state, which evidence) — lossless projection."""
        md = self._gate_md()
        assert "理由字段是映射的一部分，不是可选装饰" in md
        # conservative write-direction default: investigating -> lead.
        assert "默认落" in md
        assert "`lead`" in md

    def test_reason_requirements_survive_four_state_interface(self):
        """Safety residual (prd A5 row): final-state reason discipline
        stays mandatory — ruled_out must carry the reason, including the
        n/a inapplicability reason."""
        md = self._gate_md()
        assert "## 必填理由" in md
        assert "`ruled_out` 必写理由" in md
        for reason_rule in (
            "`tested`：写明证据或测试方式",
            "`blocked`：写明阻塞原因和需要什么输入",
            "`n/a`：写明为什么不适用",
            "`dead-end`：写明证伪原因",
            "`unknown`：写明下一步或为什么本轮未覆盖",
        ):
            assert reason_rule in md, f"reason rule lost: {reason_rule!r}"

    def test_matrix_cell_projection_declared(self):
        """The tool's own per-cell enum (tested_clean/tested_finding/
        untested/n_a) has an explicit projection into the 4-state
        interface — the code enum is unchanged, the doc states the bridge."""
        md = self._gate_md()
        assert "`tested_clean` → `ruled_out`" in md
        assert "`tested_finding` → `confirmed`" in md
        assert "`n_a` → `ruled_out`" in md
        # The tool enum itself is untouched by this batch.
        assert STATUS_VALUES == (
            "tested_clean", "tested_finding", "untested", "n_a",
        )

    def test_tool_remains_untouched_by_interface_change(self):
        """A5 tool-side decision: the lane-narrative 9-state vocabulary has
        no CLI surface in coverage_matrix.py, so no code mapping layer was
        added. The mark CLI enum keeps its exact 4 evidence values."""
        assert coverage_matrix_module.STATUS_VALUES == (
            "tested_clean", "tested_finding", "untested", "n_a",
        )
        # The lane-narrative 9-state vocabulary must not leak into the
        # accepted mark-cell statuses (it never did; guard against
        # accidental conflation of the two models in either direction).
        for narrative_state in ("dead-end", "blocked", "signal", "investigating", "ruled_out"):
            assert narrative_state not in coverage_matrix_module.STATUS_VALUES


class TestCoverageGateSemanticGapDuty:
    """A6 (task 09-11-ai-capability-roadmap batch 6): the explanation duty
    narrows from "explain every gap" to "explain the high-value gaps you
    choose NOT to pursue", while the anti-early-stopping rule stays
    word-for-word.
    """

    def _gate_md(self) -> str:
        return (REPO_ROOT / "rules" / "coverage-gate.md").read_text(encoding="utf-8")

    def test_explanation_duty_targets_unpursued_gaps(self):
        md = self._gate_md()
        assert "解释你选择不追的高价值 gap" in md

    def test_anti_early_stopping_rule_is_word_for_word(self):
        md = self._gate_md()
        assert "如果存在高价值 `unknown`，不能说“完成全面测试”，只能说：" in md
        assert "本轮覆盖了 X；仍未覆盖 Y；下一步建议 Z。" in md

    def test_ledger_framing_survives(self):
        md = self._gate_md()
        assert "矩阵不是唯一真相，而是防偷懒的 evidence hint ledger" in md
        assert "未解释的 AI-actionable `find-gaps` 非空：只能 checkpoint 或继续，不能声称全面完成。" in md

    def test_full_view_does_not_impose_a_test_menu(self):
        md = self._gate_md()
        assert "解释义务落在 AI 判断值得关注但选择不追的 gap 上" in md
        assert "矩阵枚举不等于逐格实测清单" in md

    def test_weight_and_noop_all_flags_are_retired(self, tmp_path):
        for option in (["--min-weight", "3"], ["--all"]):
            with pytest.raises(SystemExit) as exc:
                coverage_matrix_module.main(["find-gaps", "--target", "x.com", "--repo-root", str(tmp_path), *option])
            assert exc.value.code == 2
        assert not (tmp_path / "evidence").exists()


class TestF3InvariantActivation:
    """PR-10 must activate F3 — the placeholder note is gone, active
    text references the CLI."""

    def test_placeholder_note_removed(self):
        md = (REPO_ROOT / "commands" / "autopilot.md").read_text(encoding="utf-8")
        assert "Phase 3 placeholder" not in md
        assert "Today this condition is a" not in md

    def test_f3_references_active_cli(self):
        md = (REPO_ROOT / "commands" / "autopilot.md").read_text(encoding="utf-8")
        assert "Coverage `rebuild` then `find-gaps` per `rules/coverage-gate.md`" in md
        owner = (REPO_ROOT / "rules/coverage-gate.md").read_text(encoding="utf-8")
        assert owner.index("tools/coverage_matrix.py rebuild") < owner.index("tools/coverage_matrix.py find-gaps")
        assert md.index("Coverage `rebuild`") < md.index("--closure --projection-only")


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
    SEMANTIC_CLASSES = ("NoSQLi", "PrototypePollution", "OpenRedirect", "BusinessLogic")

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
        assert set(VULN_CLASSES[10:15]) == set(self.NEW_CLASSES)
        assert tuple(VULN_CLASSES[15:]) == self.SEMANTIC_CLASSES

    def test_new_classes_create_cells_on_rebuild(self, tmp_path, store):
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

    def test_legacy_matrix_does_not_authorize_current_cells_on_rebuild(self, tmp_path, store):
        _seed_recon(tmp_path, "x.com", ["/api/v1/admin/users"])
        path = tmp_path / "evidence/x.com/coverage_matrix.json"
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps({"target": "x.com", "endpoints": [{
            "endpoint": "/api/v1/admin/users", "cells": {"XSS": {"status": "n_a", "reason": "legacy"}},
        }]}))
        matrix = read_matrix("x.com", tmp_path)
        cells = matrix["endpoints"][0]["cells"]
        assert set(cells) == set(VULN_CLASSES)
        assert all(cell["status"] == "untested" for cell in cells.values())
        assert load_matrix("x.com", tmp_path)["endpoints"][0]["cells"]["XSS"]["reason"] == "legacy"

    @pytest.mark.parametrize("new_class", list(NEW_CLASSES))
    def test_mark_writefinding_rebuild_for_each_new_class(self, tmp_path, new_class, store):
        endpoint = f"/api/v1/{new_class.lower()}-target"
        result = mark_cell(store.target, endpoint, new_class, "tested_finding", reason="Claim requiring validation",
                           repo_root=tmp_path, write_finding=True)
        finding = store.finding(result["review"]["finding_id"])
        assert finding["family"] == new_class and finding["assessment"] is None
        rebuilt = rebuild_matrix(store.target, tmp_path, force_clean=True)
        ep = next(e for e in rebuilt["endpoints"] if e["endpoint"] == endpoint)
        assert ep["cells"][new_class]["status"] == "untested"
        assert ep["cells"][new_class]["review"]["finding_id"] == finding["id"]

    def test_findings_with_new_class_strings_pass_filter(self, tmp_path, store):
        """C2: the line-256 filter (`if vc not in VULN_CLASSES: continue`)
        used to silently drop SQLi/XXE/RCE/Path/CSRF entries from
        findings.json on rebuild. After enum extension, all 5 new
        class strings must produce cells.
        """
        target = "x.com"
        _seed_recon(tmp_path, target, [])
        for nc in self.NEW_CLASSES:
            _claim(store, f"F-{nc}", f"/v1/{nc.lower()}-endpoint", nc)
        matrix = rebuild_matrix(target, repo_root=tmp_path)
        endpoint_cells = {ep["endpoint"]: ep["cells"] for ep in matrix["endpoints"]}
        for nc in self.NEW_CLASSES:
            ep_path = f"/v1/{nc.lower()}-endpoint"
            assert ep_path in endpoint_cells, (
                f"endpoint {ep_path} not in matrix — finding for {nc} "
                "was silently dropped (line-256 filter still rejecting?)"
            )
            assert endpoint_cells[ep_path][nc]["status"] == "untested"


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

    def test_upload_aliases(self):
        for alias in ("file-upload", "file_upload", "FILE-UPLOAD"):
            assert normalize_vuln_class(alias) == "Upload", alias

    def test_rce_aliases(self):
        for alias in ("ssti", "deser", "deserialization", "oscommand",
                      "os-command", "cmdinjection", "cmd-injection",
                      "commandinjection", "template-injection",
                      "OSCOMMAND", "Deser"):
            assert normalize_vuln_class(alias) == "RCE", alias

    def test_xss_aliases(self):
        for alias in ("xss-dom", "dom-xss", "domxss"):
            assert normalize_vuln_class(alias) == "XSS", alias

    def test_prototype_pollution_aliases(self):
        for alias in ("prototype-pollution", "prototypepollution", "pp"):
            assert normalize_vuln_class(alias) == "PrototypePollution", alias

    def test_sqli_aliases(self):
        for alias in ("sql-injection", "sqlinjection", "sqlblind",
                      "sqli-blind", "sqli-time", "blindsqli",
                      "SQL-INJECTION", "Sqli"):
            assert normalize_vuln_class(alias) == "SQLi", alias

    def test_nosqli_aliases(self):
        for alias in ("nosqli", "nosql-injection", "nosqlinjection"):
            assert normalize_vuln_class(alias) == "NoSQLi", alias

    def test_xxe_aliases(self):
        for alias in ("xxe-blind", "xml-injection", "xinclude",
                      "xmlinjection"):
            assert normalize_vuln_class(alias) == "XXE", alias

    def test_csrf_aliases(self):
        for alias in ("csrf-token", "xsrf"):
            assert normalize_vuln_class(alias) == "CSRF", alias

    def test_open_redirect_aliases(self):
        for alias in ("openredirect", "open-redirect", "redirect"):
            assert normalize_vuln_class(alias) == "OpenRedirect", alias

    def test_business_logic_aliases(self):
        for alias in ("business-logic", "businesslogic"):
            assert normalize_vuln_class(alias) == "BusinessLogic", alias

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

    def test_unknown_via_mark_cell_raises(self, tmp_path, store):
        with pytest.raises(ValueError):
            mark_cell("x.com", "/admin/x", "totally-bogus", "untested",
                      repo_root=tmp_path)

    def test_mark_cell_with_lowercase(self, tmp_path, store):
        result = mark_cell("x.com", "/api/check", "sqli", "tested_finding",
                           reason="Claim requiring validation", repo_root=tmp_path, write_finding=True)
        assert result["review"]["family"] == "SQLi"
        assert store.finding(result["review"]["finding_id"])["family"] == "SQLi"
        cell = read_matrix("x.com", tmp_path)["endpoints"][0]["cells"]["SQLi"]
        assert cell["status"] == "untested"
        assert cell["review"]["value"] == "tested_finding"

    def test_mark_cell_with_alias(self, tmp_path, store):
        result = mark_cell("x.com", "/api/check", "lfi", "tested_finding",
                           reason="Claim requiring validation", repo_root=tmp_path, write_finding=True)
        assert result["review"]["family"] == "Path"
        assert store.finding(result["review"]["finding_id"])["family"] == "Path"
        cell = read_matrix("x.com", tmp_path)["endpoints"][0]["cells"]["Path"]
        assert cell["status"] == "untested"
        assert cell["review"]["value"] == "tested_finding"

    def test_alias_table_round_trip(self):
        """Every alias in the table must resolve to a canonical name
        that is itself in VULN_CLASSES (no broken aliases)."""
        for alias, canonical in VULN_CLASS_ALIASES.items():
            assert canonical in VULN_CLASSES, (
                f"alias {alias!r} maps to {canonical!r} which is not "
                "in VULN_CLASSES — broken alias table"
            )


class TestRouteKindQualification:
    """Route-kind observations order the queue by facts; no qualification filter.

    Anchors after the selection-authority refactor: every untested
    high-value cell stays in the matrix and AI-selectable regardless of its
    route kind; ordering follows endpoint/class identity. Route observations
    remain evidence for AI review without choosing the first work item.
    """

    def _seed_route_kind(self, tmp_path: Path, target: str, endpoint_url: str, kind: str) -> None:
        recon_dir = tmp_path / "recon" / target
        recon_dir.mkdir(parents=True, exist_ok=True)
        path = recon_dir / "route_kinds.json"
        existing: dict = {"schema_version": 1, "target": target, "endpoints": {}}
        if path.is_file():
            try:
                existing = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                pass
        endpoints = existing.setdefault("endpoints", {})
        endpoints[endpoint_url] = {
            "route_kind": kind,
            "source": "route_probe",
            "observed_at": "2026-09-10T00:00:00Z",
            "facts": {"status": 200, "content_type": "text/html", "body_length": 9903, "body_sha256": "x", "probe_error": ""},
        }
        path.write_text(json.dumps(existing), encoding="utf-8")

    def test_client_route_gap_stays_in_matrix_with_identity_order(self, tmp_path):
        TargetStore(tmp_path, "route.test").initialize()
        target = "route.test"
        _seed_recon(tmp_path, target, [
            "https://route.test/payment",
            "https://route.test/rest/admin/application-configuration",
        ])
        self._seed_route_kind(tmp_path, target, "https://route.test/payment", "client_route")
        self._seed_route_kind(
            tmp_path, target,
            "https://route.test/rest/admin/application-configuration", "json_api",
        )
        matrix = coverage_matrix_module._rebuild_matrix_unlocked(target, tmp_path)
        gaps = list(coverage_matrix_module._iter_high_value_gaps(matrix))
        payment_gaps = [g for g in gaps if g["endpoint"] == "/payment"]
        assert payment_gaps, "client_route stays in the matrix, never dropped"
        assert all(g.get("route_kind") == "client_route" for g in payment_gaps)
        # All gaps are returned; ordering does not prefer server-backed routes.
        assert set(VULN_CLASSES) == {gap["vuln_class"] for gap in payment_gaps}
        server_gaps = [g for g in gaps if g.get("route_kind") == "json_api"]
        assert server_gaps
        ordered = sorted(gaps, key=coverage_matrix_module._gap_sort_key)
        assert [gap["endpoint"] for gap in ordered[:len(payment_gaps)]] == ["/payment"] * len(payment_gaps)
        assert [(gap["endpoint"], gap["vuln_class"]) for gap in ordered] == sorted(
            (gap["endpoint"], gap["vuln_class"]) for gap in gaps
        )

    def test_word_list_relevance_stays_visible_but_exits_ordering(self, tmp_path):
        gap_high = {
            "endpoint": "/a", "vuln_class": "Authz", "weight": 5.0,
            "relevance_score": 9, "route_kind": "client_route",
        }
        gap_low = {
            "endpoint": "/b", "vuln_class": "Authz", "weight": 5.0,
            "relevance_score": 0, "route_kind": "json_api",
        }
        ordered = sorted([gap_high, gap_low], key=coverage_matrix_module._gap_sort_key)
        assert ordered[0] is gap_high, "identity order is independent of route kind and relevance"
        # The relevance annotation survives for AI visibility.
        assert gap_high["relevance_score"] == 9

    def test_server_backed_route_kind_recorded_on_matrix_row(self, tmp_path):
        TargetStore(tmp_path, "route.test").initialize()
        target = "route.test"
        _seed_recon(tmp_path, target, ["https://route.test/rest/admin/application-configuration"])
        self._seed_route_kind(
            tmp_path, target,
            "https://route.test/rest/admin/application-configuration", "json_api",
        )
        matrix = coverage_matrix_module._rebuild_matrix_unlocked(target, tmp_path)
        gaps = list(coverage_matrix_module._iter_high_value_gaps(matrix))
        assert any(g.get("route_kind") == "json_api" for g in gaps)

    def test_matrix_fingerprint_binds_route_kinds_file(self, tmp_path):
        TargetStore(tmp_path, "route.test").initialize()
        target = "route.test"
        _seed_recon(tmp_path, target, ["https://route.test/payment"])
        matrix = coverage_matrix_module._rebuild_matrix_unlocked(target, tmp_path)
        assert coverage_matrix_module.matrix_is_fresh(target, matrix, repo_root=tmp_path)
        self._seed_route_kind(tmp_path, target, "https://route.test/payment", "client_route")
        assert not coverage_matrix_module.matrix_is_fresh(target, matrix, repo_root=tmp_path), (
            "a new route_kinds.json generation must invalidate the cached matrix"
        )
