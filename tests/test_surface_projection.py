"""Surface 派生投影的 manifest、原子发布与只读消费契约。"""

from __future__ import annotations

import json
import os

import pytest

from tools import surface as surface_module
from tools.action_queue import ingest_checkpoint, load_queue, save_queue
from tools.evidence_ledger import ledger_path, record_entry
from tools.surface_index import SurfaceIndexError
from tools.surface_projection import (
    build_surface_input_manifest,
    load_surface_projection,
    surface_projection_path,
    write_surface_projection,
)


def _write_surface_inputs(repo_root, target: str = "target.com"):
    recon_dir = repo_root / "recon" / target
    (recon_dir / "live").mkdir(parents=True)
    (recon_dir / "urls").mkdir()
    (recon_dir / "live" / "httpx_full.txt").write_text(
        "https://api.target.com [200] [API] [Python] [100]\n",
        encoding="utf-8",
    )
    (recon_dir / "urls" / "with_params.txt").write_text(
        "https://api.target.com/orders?id=1\n",
        encoding="utf-8",
    )
    return recon_dir


def _ranked(target: str = "target.com") -> dict:
    return {
        "available": True,
        "target": target,
        "p1": [{"url": f"https://api.{target}/orders?id=1", "score": 10}],
        "p2": [],
        "review_pool": [],
        "stats": {"total_candidates": 1, "p1": 1, "p2": 0, "review_pool": 0},
    }


def test_projection_exact_manifest_hit_and_source_change_stale(tmp_path):
    recon_dir = _write_surface_inputs(tmp_path)
    manifest = build_surface_input_manifest(tmp_path, "target.com")

    write_surface_projection(tmp_path, "target.com", _ranked(), manifest=manifest)

    hit = load_surface_projection(tmp_path, "target.com")
    assert hit["status"] == "valid"
    assert hit["surface"]["p1"][0]["score"] == 10
    assert "input_manifest" not in hit["surface"]

    with (recon_dir / "urls" / "with_params.txt").open("a", encoding="utf-8") as handle:
        handle.write("https://api.target.com/orders?id=2\n")

    stale = load_surface_projection(tmp_path, "target.com")
    assert stale["status"] == "stale"
    assert stale["surface"] == {}
    assert stale["reason"] == "input-manifest-mismatch"
    assert stale["input_fingerprint"] == build_surface_input_manifest(
        tmp_path, "target.com"
    )["fingerprint"]


def test_empty_checkpoint_sync_keeps_valid_projection(tmp_path):
    _write_surface_inputs(tmp_path)
    queue_path = save_queue(
        tmp_path,
        "target.com",
        load_queue(tmp_path, "target.com"),
    )
    manifest = build_surface_input_manifest(tmp_path, "target.com")
    write_surface_projection(tmp_path, "target.com", _ranked(), manifest=manifest)
    queue_inode = queue_path.stat().st_ino

    result = ingest_checkpoint(
        tmp_path,
        "target.com",
        checkpoint={"next_action_queue": []},
    )

    assert result["stats"] == {
        "added": 0,
        "updated": 0,
        "skipped_final": 0,
        "retired_stale": 0,
        "retired_superseded": 0,
    }
    assert queue_path.stat().st_ino == queue_inode
    assert (tmp_path / "findings" / "target.com" / ".locks" / "findings.lock").is_file()
    assert load_surface_projection(tmp_path, "target.com")["status"] == "valid"


def test_queue_claim_runner_writeback_and_timestamps_keep_projection_valid(tmp_path):
    _write_surface_inputs(tmp_path)
    queue = load_queue(tmp_path, "target.com")
    queue["actions"] = [{
        "id": "AQ-0001",
        "target": "target.com",
        "status": "queued",
        "type": "coverage-gap",
        "metadata": {"endpoint": "/orders/1", "vuln_class": "Authz"},
        "next_question": "Before",
        "updated_at": "2026-01-01T00:00:00Z",
    }]
    queue_path = save_queue(tmp_path, "target.com", queue)
    manifest = build_surface_input_manifest(tmp_path, "target.com")
    write_surface_projection(tmp_path, "target.com", _ranked(), manifest=manifest)
    before = build_surface_input_manifest(tmp_path, "target.com")

    queue = load_queue(tmp_path, "target.com")
    action = queue["actions"][0]
    action["status"] = "running"
    action["next_question"] = "After claim"
    action["updated_at"] = "2026-08-22T00:00:00Z"
    action.setdefault("metadata", {})["last_outcome"] = {
        "status": "observed",
        "at": "2026-08-22T00:00:01Z",
        "evidence_ref": "evidence/trace.json",
    }
    queue["updated_at"] = "2026-08-22T00:00:02Z"
    save_queue(tmp_path, "target.com", queue)

    after = build_surface_input_manifest(tmp_path, "target.com")
    assert before["fingerprint"] == after["fingerprint"]
    assert queue_path.stat().st_ino != next(
        item["st_ino"]
        for item in before["items"]
        if item["path"] == "state/target.com/action_queue.json"
    )
    assert load_surface_projection(tmp_path, "target.com")["status"] == "valid"


def test_queue_final_endpoint_or_status_change_stales_projection(tmp_path):
    _write_surface_inputs(tmp_path)
    queue = load_queue(tmp_path, "target.com")
    queue["actions"] = [{
        "id": "AQ-0001",
        "target": "target.com",
        "status": "tested",
        "type": "coverage-gap",
        "metadata": {"endpoint": "/orders/1", "vuln_class": "Authz"},
    }]
    save_queue(tmp_path, "target.com", queue)
    manifest = build_surface_input_manifest(tmp_path, "target.com")
    write_surface_projection(tmp_path, "target.com", _ranked(), manifest=manifest)

    queue = load_queue(tmp_path, "target.com")
    queue["actions"][0]["status"] = "blocked"
    queue["actions"][0]["metadata"]["endpoint"] = "/orders/2"
    save_queue(tmp_path, "target.com", queue)

    stale = load_surface_projection(tmp_path, "target.com")
    assert stale["status"] == "stale"
    assert stale["reason"] == "input-manifest-mismatch"


def test_non_closing_ledger_append_keeps_projection_valid_but_closure_stales(tmp_path):
    _write_surface_inputs(tmp_path)
    path = ledger_path(tmp_path, "target.com")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("", encoding="utf-8")
    manifest = build_surface_input_manifest(tmp_path, "target.com")
    write_surface_projection(tmp_path, "target.com", _ranked(), manifest=manifest)

    record_entry(
        tmp_path,
        target="target.com",
        endpoint="/orders/1",
        vuln_class="Authz",
        result="lead",
    )
    assert load_surface_projection(tmp_path, "target.com")["status"] == "valid"
    raw_before_terminal = path.read_bytes()

    record_entry(
        tmp_path,
        target="target.com",
        endpoint="/orders/1",
        vuln_class="Authz",
        result="tested_clean",
    )
    stale = load_surface_projection(tmp_path, "target.com")
    assert stale["status"] == "stale"
    assert stale["reason"] == "input-manifest-mismatch"
    assert path.read_bytes().startswith(raw_before_terminal)


def test_first_non_closing_ledger_append_keeps_projection_valid(tmp_path):
    _write_surface_inputs(tmp_path)
    manifest = build_surface_input_manifest(tmp_path, "target.com")
    write_surface_projection(tmp_path, "target.com", _ranked(), manifest=manifest)

    record_entry(
        tmp_path,
        target="target.com",
        endpoint="/orders/1",
        vuln_class="Authz",
        result="lead",
    )

    assert load_surface_projection(tmp_path, "target.com")["status"] == "valid"


def test_calibration_manifest_tracks_effective_exclusions_only(tmp_path):
    _write_surface_inputs(tmp_path)
    memory_dir = tmp_path / "hunt-memory"
    memory_dir.mkdir()
    manifest = build_surface_input_manifest(
        tmp_path,
        "target.com",
        memory_dir=memory_dir,
    )
    write_surface_projection(
        tmp_path,
        "target.com",
        _ranked(),
        manifest=manifest,
        memory_dir=memory_dir,
    )

    calibration = memory_dir / "pattern_calibration.jsonl"
    calibration.write_text("", encoding="utf-8")
    assert load_surface_projection(
        tmp_path,
        "target.com",
        memory_dir=memory_dir,
    )["status"] == "valid"

    calibration.write_text(
        json.dumps({"pattern_id": "p1", "outcome": "no_signal"}) + "\n",
        encoding="utf-8",
    )
    assert load_surface_projection(
        tmp_path,
        "target.com",
        memory_dir=memory_dir,
    )["status"] == "valid"

    with calibration.open("a", encoding="utf-8") as handle:
        for _ in range(5):
            handle.write(json.dumps({"pattern_id": "p1", "outcome": "false_positive"}) + "\n")
    assert load_surface_projection(
        tmp_path,
        "target.com",
        memory_dir=memory_dir,
    )["status"] == "stale"


def test_projection_ignores_recon_finalize_manifest(tmp_path):
    recon_dir = _write_surface_inputs(tmp_path)
    manifest = build_surface_input_manifest(tmp_path, "target.com")
    write_surface_projection(tmp_path, "target.com", _ranked(), manifest=manifest)

    control_file = recon_dir / "recon_manifest.jsonl"
    control_file.write_text('{"phase":"run_budget","status":"ok"}\n', encoding="utf-8")
    assert load_surface_projection(tmp_path, "target.com")["status"] == "valid"

    control_file.write_text('{"phase":"run_budget","status":"partial"}\n', encoding="utf-8")
    assert load_surface_projection(tmp_path, "target.com")["status"] == "valid"


def test_projection_manifest_rejects_same_size_mtime_restored_replacement(tmp_path):
    recon_dir = _write_surface_inputs(tmp_path)
    manifest = build_surface_input_manifest(tmp_path, "target.com")
    write_surface_projection(tmp_path, "target.com", _ranked(), manifest=manifest)
    source = recon_dir / "urls" / "with_params.txt"
    before = source.stat()
    replacement = source.read_text(encoding="utf-8").replace("id=1", "id=2")
    replacement_path = source.with_name(".with_params.replacement")
    replacement_path.write_text(replacement, encoding="utf-8")
    os.utime(replacement_path, ns=(before.st_atime_ns, before.st_mtime_ns))
    replacement_path.replace(source)

    refreshed = build_surface_input_manifest(tmp_path, "target.com")
    before_item = next(item for item in manifest["items"] if item["path"].endswith("with_params.txt"))
    after_item = next(item for item in refreshed["items"] if item["path"].endswith("with_params.txt"))
    assert after_item["size"] == before_item["size"]
    assert after_item["mtime_ns"] == before_item["mtime_ns"]
    assert after_item["st_ino"] != before_item["st_ino"]
    assert refreshed["fingerprint"] != manifest["fingerprint"]
    assert load_surface_projection(tmp_path, "target.com")["status"] == "stale"


def test_projection_missing_corrupt_and_target_mismatch_are_not_consumed(tmp_path):
    _write_surface_inputs(tmp_path)
    missing = load_surface_projection(tmp_path, "target.com")
    assert missing["status"] == "missing"
    assert missing["surface"] == {}

    path = surface_projection_path(tmp_path, "target.com")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{broken", encoding="utf-8")
    corrupt = load_surface_projection(tmp_path, "target.com")
    assert corrupt["status"] == "invalid"
    assert "invalid-json" in corrupt["reason"]

    manifest = build_surface_input_manifest(tmp_path, "target.com")
    write_surface_projection(tmp_path, "target.com", _ranked(), manifest=manifest)
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["target"] = "other.test"
    path.write_text(json.dumps(payload), encoding="utf-8")
    mismatch = load_surface_projection(tmp_path, "target.com")
    assert mismatch["status"] == "invalid"
    assert mismatch["reason"] == "target-mismatch"


def test_projection_replace_failure_preserves_previous_bytes(tmp_path, monkeypatch):
    _write_surface_inputs(tmp_path)
    manifest = build_surface_input_manifest(tmp_path, "target.com")
    path = write_surface_projection(tmp_path, "target.com", _ranked(), manifest=manifest)
    original = path.read_bytes()
    original_replace = type(path).replace

    def fail_projection_replace(self, target):
        if self.name.startswith(".surface-projection.json."):
            raise OSError("simulated projection replace failure")
        return original_replace(self, target)

    monkeypatch.setattr(type(path), "replace", fail_projection_replace)
    changed = _ranked()
    changed["p1"][0]["score"] = 99

    with pytest.raises(OSError, match="simulated projection replace failure"):
        write_surface_projection(tmp_path, "target.com", changed, manifest=manifest)

    assert path.read_bytes() == original
    assert not list(path.parent.glob(".surface-projection.json.*.tmp"))


def test_surface_refresh_input_race_preserves_previous_projection(tmp_path, monkeypatch):
    recon_dir = _write_surface_inputs(tmp_path)
    surface_module.build_surface_review(tmp_path, "target.com", refresh=True)
    path = surface_projection_path(tmp_path, "target.com")
    original = path.read_bytes()

    with (recon_dir / "urls" / "with_params.txt").open("a", encoding="utf-8") as handle:
        handle.write("https://api.target.com/orders?id=2\n")

    original_rank = surface_module.rank_surface

    def mutate_input_during_rank(context):
        ranked = original_rank(context)
        with (recon_dir / "urls" / "with_params.txt").open("a", encoding="utf-8") as handle:
            handle.write("https://api.target.com/orders?id=3\n")
        return ranked

    monkeypatch.setattr(surface_module, "rank_surface", mutate_input_during_rank)

    with pytest.raises(SurfaceIndexError, match="inputs changed during ranking"):
        surface_module.build_surface_review(tmp_path, "target.com", refresh=True)

    assert path.read_bytes() == original


def test_projection_preserves_browser_and_js_evidence_refs(tmp_path):
    recon_dir = _write_surface_inputs(tmp_path)
    browser_dir = recon_dir / "browser"
    browser_dir.mkdir()
    (browser_dir / "xhr_endpoints.txt").write_text(
        "https://api.target.com/orders?id=1\n", encoding="utf-8"
    )
    (browser_dir / "api_endpoints.txt").write_text(
        "https://api.target.com/orders?id=1\n", encoding="utf-8"
    )
    js_dir = tmp_path / "findings" / "target.com" / "js_intel"
    js_dir.mkdir(parents=True)
    (js_dir / "hypotheses.json").write_text(
        json.dumps({"endpoints": [{"path": "/orders?id=1"}]}), encoding="utf-8"
    )
    (js_dir / "materials.json").write_text("{}\n", encoding="utf-8")

    ranked = _ranked()
    ranked["evidence_refs"] = {
        "browser": ["recon/target.com/browser/xhr_endpoints.txt"],
        "js": ["findings/target.com/js_intel/hypotheses.json"],
    }
    manifest = build_surface_input_manifest(tmp_path, "target.com")
    write_surface_projection(tmp_path, "target.com", ranked, manifest=manifest)

    loaded = load_surface_projection(tmp_path, "target.com")
    assert loaded["status"] == "valid"
    assert loaded["surface"]["evidence_refs"]["browser"]
    assert loaded["surface"]["evidence_refs"]["js"]


def test_projection_keeps_rebuildable_semantic_surface(tmp_path):
    _write_surface_inputs(tmp_path)
    ranked = _ranked()
    ranked["semantic_surface"] = [{
        "shape_id": "shape-1",
        "url_shape_id": "url-shape-1",
        "candidate_count": 1,
        "active_variant_count": 12,
        "representative_url": "https://api.target.com/orders?id=...",
        "raw_reference": "recon/target.com/urls/raw/all.txt.gz",
    }]
    manifest = build_surface_input_manifest(tmp_path, "target.com")
    write_surface_projection(tmp_path, "target.com", ranked, manifest=manifest)

    loaded = load_surface_projection(tmp_path, "target.com")
    assert loaded["status"] == "valid"
    assert loaded["surface"]["semantic_surface"][0]["active_variant_count"] == 12
