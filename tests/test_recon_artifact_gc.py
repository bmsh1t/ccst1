import json

import pytest

from tools import recon_artifact_gc


def _seed(tmp_path):
    recon = tmp_path / "recon" / "target.com" / "urls"
    raw = recon / "raw"
    raw.mkdir(parents=True)
    (raw / "all.txt.gz").write_bytes(b"raw")
    (raw / "unused.txt").write_text("raw", encoding="utf-8")
    (recon / "all.txt").write_text("https://target.com/active\n", encoding="utf-8")
    state = tmp_path / "state" / "target.com"
    state.mkdir(parents=True)
    (state / "checkpoint_latest.json").write_text(
        json.dumps({"raw_ref": "recon/target.com/urls/raw/all.txt.gz"}), encoding="utf-8"
    )


def test_gc_is_reference_aware_and_apply_keeps_active(tmp_path, monkeypatch):
    _seed(tmp_path)
    monkeypatch.setattr(
        recon_artifact_gc,
        "build_autopilot_state",
        lambda *args, **kwargs: {"resolved_target": "target.com", "next_action": "handoff"},
    )
    monkeypatch.setattr(
        recon_artifact_gc,
        "load_closure_projection",
        lambda *args, **kwargs: {
            "verdict": "finish",
            "can_claim_exhausted": True,
            "reasons": [],
        },
    )

    plan = recon_artifact_gc.collect_gc_plan(tmp_path, "target.com")
    assert "recon/target.com/urls/raw/all.txt.gz" not in plan["removable"]
    assert "recon/target.com/urls/raw/unused.txt" in plan["removable"]
    assert recon_artifact_gc.apply_gc_plan(tmp_path, plan) == 1
    assert not (tmp_path / "recon/target.com/urls/raw/unused.txt").exists()
    assert (tmp_path / "recon/target.com/urls/raw/all.txt.gz").exists()
    assert (tmp_path / "recon/target.com/urls/all.txt").exists()
    assert recon_artifact_gc.apply_gc_plan(tmp_path, plan) == 0


def test_gc_refuses_apply_before_closure(tmp_path, monkeypatch):
    _seed(tmp_path)
    monkeypatch.setattr(
        recon_artifact_gc,
        "build_autopilot_state",
        lambda *args, **kwargs: {"resolved_target": "target.com", "next_action": "handoff"},
    )
    monkeypatch.setattr(
        recon_artifact_gc,
        "load_closure_projection",
        lambda *args, **kwargs: {
            "verdict": "handoff",
            "can_claim_exhausted": False,
            "reasons": ["coverage_high_value_gaps"],
        },
    )

    plan = recon_artifact_gc.collect_gc_plan(tmp_path, "target.com")
    with pytest.raises(RuntimeError, match="closure is not exhausted"):
        recon_artifact_gc.apply_gc_plan(tmp_path, plan)


def test_gc_fails_closed_on_corrupt_structured_reference(tmp_path, monkeypatch):
    _seed(tmp_path)
    (tmp_path / "state" / "target.com" / "broken.json").write_text("{", encoding="utf-8")
    monkeypatch.setattr(
        recon_artifact_gc,
        "build_autopilot_state",
        lambda *args, **kwargs: {"resolved_target": "target.com", "next_action": "handoff"},
    )
    monkeypatch.setattr(
        recon_artifact_gc,
        "load_closure_projection",
        lambda *args, **kwargs: {
            "verdict": "finish",
            "can_claim_exhausted": True,
            "reasons": [],
        },
    )

    with pytest.raises(RuntimeError, match="invalid JSON reference source"):
        recon_artifact_gc.collect_gc_plan(tmp_path, "target.com")
