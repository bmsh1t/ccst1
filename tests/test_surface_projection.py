"""Surface binds consumed review inputs, not checkpoint-only attachments."""

import json

import pytest

from tools import surface
from tools.checkpoint import begin_round, record_round_closure, record_round_lane, record_round_lane_result
from tools.surface_projection import load_surface_projection, surface_projection_path
from tools.target_store import TargetStore


TARGET = "surface-inputs.test"


def _write(root, relative, text="review evidence\n"):
    path = root / "findings" / TARGET / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


@pytest.fixture
def store(tmp_path):
    owner = TargetStore(tmp_path, TARGET)
    owner.initialize()
    (tmp_path / "recon" / TARGET).mkdir(parents=True)
    return owner


def _refresh(root):
    ranked = surface.build_surface_review(root, TARGET)
    assert load_surface_projection(root, TARGET)["status"] == "valid"
    return ranked


@pytest.mark.parametrize("field", ["store_id", "revision"])
def test_projection_binding_matches_owner_and_rejects_mismatch(tmp_path, store, field):
    _refresh(tmp_path)
    owner_binding = store.binding()
    path = surface_projection_path(tmp_path, TARGET)
    original = path.read_bytes()
    payload = json.loads(original)
    binding = payload["input_manifest"]["binding"]
    assert binding == {
        "target": TARGET,
        "policy_version": payload["schema_version"],
        "as_of": "",
        "store_id": owner_binding["store_id"],
        "revision": owner_binding["revision"],
    }
    assert isinstance(binding["store_id"], str)
    assert type(binding["revision"]) is int
    loaded = load_surface_projection(tmp_path, TARGET)
    assert loaded["status"] == "valid"
    assert loaded["surface"] == payload["surface"]
    assert loaded["input_fingerprint"] == payload["input_fingerprint"]
    assert path.read_bytes() == original

    binding[field] = "other-store" if field == "store_id" else binding[field] + 1
    path.write_text(json.dumps(payload), encoding="utf-8")
    mismatched = path.read_bytes()
    loaded = load_surface_projection(tmp_path, TARGET)
    assert loaded["status"] == "stale"
    assert loaded["reason"] == "store-revision-mismatch"
    assert loaded["surface"] == {}
    assert loaded["input_fingerprint"] == payload["input_fingerprint"]
    assert path.read_bytes() == mismatched
    assert store.binding() == owner_binding


def test_checkpoint_lane_attachment_and_round_closure_preserve_surface(tmp_path, store):
    _refresh(tmp_path)
    binding = store.binding()
    projection = surface_projection_path(tmp_path, TARGET).read_bytes()
    begin_round(tmp_path, TARGET, max_lanes=1)
    record_round_lane(tmp_path, TARGET, lane="review", max_lanes=1)
    evidence = _write(tmp_path, "manual_review/round/lane.json", '{"reviewed": true}')
    assert load_surface_projection(tmp_path, TARGET)["status"] == "valid"
    record_round_lane_result(
        tmp_path, TARGET, lane="review", status="completed", decision="review completed",
        evidence_ref=str(evidence.relative_to(tmp_path)), next_action="none",
    )
    result = record_round_closure(tmp_path, TARGET)
    assert result["round_progress"]["status"] == "completed"
    assert store.binding() == binding
    assert load_surface_projection(tmp_path, TARGET)["status"] == "valid"
    assert surface_projection_path(tmp_path, TARGET).read_bytes() == projection
    evidence.write_text('{"reviewed": true, "note": "attachment only"}')
    assert load_surface_projection(tmp_path, TARGET)["status"] == "valid"
    evidence.unlink()
    assert load_surface_projection(tmp_path, TARGET)["status"] == "valid"

    store.create_action(command_id="follow-up", action_id="follow-up", kind="work",
                        subject={"target": TARGET}, intent="Review next surface",
                        execution_key="follow-up", actor="operator")
    changed = load_surface_projection(tmp_path, TARGET)
    assert changed["status"] == "stale"
    assert changed["reason"] == "store-revision-mismatch"


@pytest.mark.parametrize("relative", [
    "manual_review/unsafe_skipped.txt",
    "manual_review/open_200_api.txt",
    "manual_review/standard_public_metadata.txt",
    "manual_review/nested/custom.txt",
])
def test_manual_review_inputs_bind_creation_edits_and_deletion(tmp_path, store, relative):
    if relative.endswith("custom.txt"):
        _write(tmp_path, "summary.json", json.dumps({
            "target": TARGET, "manual_review": [{"path": relative}],
        }))
    _refresh(tmp_path)
    path = _write(tmp_path, relative, "")
    assert load_surface_projection(tmp_path, TARGET)["status"] == "stale"
    _refresh(tmp_path)
    path.write_text("https://surface-inputs.test/api/review\n")
    assert load_surface_projection(tmp_path, TARGET)["status"] == "stale"
    ranked = _refresh(tmp_path)
    if relative.endswith("custom.txt"):
        assert ranked["scanner"]["manual_review"][0]["relative_path"] == relative
        assert ranked["scanner"]["manual_review"][0]["count"] == 1
    else:
        assert any(json.loads(item)["source"] == "scanner_manual_review" for item in ranked["workflow_leads"])
    path.unlink()
    assert load_surface_projection(tmp_path, TARGET)["status"] == "stale"


def test_manual_review_summary_uses_shared_target_and_path_validation(tmp_path, store):
    relative = "manual_review/review.txt"
    path = _write(tmp_path, relative)
    outside = tmp_path / "outside.txt"
    outside.write_text("outside\n")
    _write(tmp_path, "summary.json", json.dumps({"target": TARGET, "manual_review": [
        {"path": relative}, {"path": relative}, {"path": "../../outside.txt"},
        {"path": str(outside)}, {"path": ""}, "invalid",
    ]}))
    ranked = _refresh(tmp_path)
    assert [item["relative_path"] for item in ranked["scanner"]["manual_review"]] == [relative]
    outside.write_text("changed outside\n")
    assert load_surface_projection(tmp_path, TARGET)["status"] == "valid"
    _write(tmp_path, "summary.json", json.dumps({"target": "other.test", "manual_review": [{"path": relative}]}))
    assert load_surface_projection(tmp_path, TARGET)["status"] == "stale"
    assert _refresh(tmp_path)["scanner"]["manual_review"] == []
    path.write_text("unconsumed foreign-summary attachment\n")
    assert load_surface_projection(tmp_path, TARGET)["status"] == "valid"


def test_registered_manual_review_evidence_still_binds_file_bytes(tmp_path, store):
    path = _write(tmp_path, "manual_review/registered.txt")
    store.create_action(command_id="review-artifact", action_id="review-artifact", kind="work",
                        subject={"artifact": str(path.relative_to(tmp_path))}, intent="Review artifact",
                        execution_key="review-artifact", actor="operator")
    _refresh(tmp_path)
    binding = store.binding()
    path.write_text("changed registered evidence\n")
    assert store.binding() == binding
    assert load_surface_projection(tmp_path, TARGET)["status"] == "stale"


@pytest.mark.parametrize("relative", [
    "scanner_pass.json", "js_intel/hypotheses.json", "source_intel/routes.json",
    "source_intel/manual_review/nested.txt",
])
def test_other_findings_inputs_keep_existing_bindings(tmp_path, store, relative):
    _refresh(tmp_path)
    path = _write(tmp_path, relative, "{}")
    assert load_surface_projection(tmp_path, TARGET)["status"] == "stale"
    _refresh(tmp_path)
    path.unlink()
    assert load_surface_projection(tmp_path, TARGET)["status"] == "stale"


def test_consumed_review_edit_during_ranking_does_not_publish(tmp_path, store, monkeypatch):
    path = _write(tmp_path, "manual_review/open_200_api.txt")
    _refresh(tmp_path)
    previous = surface_projection_path(tmp_path, TARGET).read_bytes()
    rank = surface.rank_surface

    def change_input(context):
        ranked = rank(context)
        path.write_text("changed during ranking\n")
        return ranked

    monkeypatch.setattr(surface, "rank_surface", change_input)
    with pytest.raises(surface.SurfaceIndexError, match="inputs changed during ranking"):
        surface.build_surface_review(tmp_path, TARGET)
    assert surface_projection_path(tmp_path, TARGET).read_bytes() == previous
