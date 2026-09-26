import json

import pytest

from tools.scope_source import scope_source_path
from tools.recon_candidates import build_recon_candidates
from tools.runtime_state import inspect_recon_artifacts, inspect_recon_artifacts_fast
from tools.surface import _build_exposure_lead_hints


def _observation(value, related):
    return {
        "schema_version": 1,
        "kind": "asset-relation-observation",
        "asset_type": "domain",
        "value": value,
        "relation": "ownership",
        "related": related,
        "source": "ownership-record",
        "source_ref": value,
        "confidence": "high",
    }


def _save_scope(memory_dir, target, snapshot):
    path = scope_source_path(memory_dir.parent, target)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_text(json.dumps({"schema_version": 1, "root_target": target, **snapshot}))
    path.chmod(0o600)


def _setup(tmp_path, monkeypatch, *, target="target.example", snapshot=None):
    memory_dir = tmp_path / "hunt-memory"
    monkeypatch.setenv("HUNT_MEMORY_DIR", str(memory_dir))
    _save_scope(memory_dir, target, snapshot or {})
    exposure = tmp_path / "recon" / target / "exposure"
    exposure.mkdir(parents=True)
    return memory_dir, exposure


def test_relation_classification_respects_scope_exclusion_and_related_host(tmp_path, monkeypatch):
    target = "target.example"
    _memory_dir, exposure = _setup(
        tmp_path, monkeypatch, snapshot={"out_of_scope": ["admin.target.example"]}
    )
    source = exposure / "asset_relation_observations.jsonl"
    source.write_text(
        "\n".join(json.dumps(row) for row in (
            _observation("admin.target.example", []),
            _observation("vendor.example", ["admin.target.example"]),
            _observation("partner.example", [target]),
            _observation("api.target.example", []),
        )) + "\n",
        encoding="utf-8",
    )

    build_recon_candidates(tmp_path, target, asset_input=source)
    rows = [json.loads(line) for line in (exposure / "asset_relation_candidates.jsonl").read_text().splitlines()]
    statuses = {row["value"]: row["scope_status"] for row in rows}
    assert statuses == {
        "admin.target.example": "excluded",
        "vendor.example": "external-chain-context",
        "partner.example": "scope-review",
        "api.target.example": "in_scope",
    }


def test_asset_cursor_is_invalidated_by_scope_change(tmp_path, monkeypatch):
    target = "target.example"
    memory_dir, exposure = _setup(tmp_path, monkeypatch)
    source = exposure / "asset_relation_observations.jsonl"
    source.write_text(
        "\n".join(json.dumps(_observation(value, [target])) for value in ("a.example", "b.example")) + "\n",
        encoding="utf-8",
    )
    first = build_recon_candidates(tmp_path, target, asset_input=source, asset_limit=1)
    assert first["asset_relation_next_cursor"]
    assert inspect_recon_artifacts(tmp_path, target)["asset_relations"]["available"] is True

    _save_scope(memory_dir, target, {"out_of_scope": ["admin.target.example"]})
    recon = inspect_recon_artifacts(tmp_path, target)
    assert "Scope changed" in recon["asset_relations"]["error"]
    assert "Scope changed" in inspect_recon_artifacts_fast(tmp_path, target)["asset_relations"]["error"]
    assert not any(
        lead["category"] in {"asset-relation", "asset-scope-review"}
        for lead in _build_exposure_lead_hints(recon, target)
    )
    with pytest.raises(ValueError, match="cursor source changed"):
        build_recon_candidates(
            tmp_path, target, asset_input=source, asset_limit=1,
            asset_cursor=first["asset_relation_next_cursor"],
        )
    source.unlink()
    with pytest.raises(ValueError, match="cursor source missing"):
        build_recon_candidates(
            tmp_path, target, asset_input=source, asset_limit=1,
            asset_cursor=first["asset_relation_next_cursor"],
        )


def test_invalid_scope_source_does_not_publish_candidates(tmp_path, monkeypatch):
    target = "target.example"
    memory_dir, exposure = _setup(tmp_path, monkeypatch)
    _save_scope(memory_dir, target, {"out_of_scope": "admin.target.example"})
    with pytest.raises(ValueError, match="out_of_scope must be a list"):
        build_recon_candidates(tmp_path, target)
    assert not (exposure / "asset_relation_candidates.jsonl").exists()
