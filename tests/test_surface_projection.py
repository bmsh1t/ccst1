"""Surface 派生投影的 manifest、原子发布与只读消费契约。"""

from __future__ import annotations

import json
import os

import pytest

from tools import surface as surface_module
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
