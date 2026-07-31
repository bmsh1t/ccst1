"""Autopilot routing for the bounded FFUF rotation ledger."""

import json

from tools.autopilot_state import _pick_next_action
from tools.recon_target_selector import load_rotation_status


def test_pending_directory_rotation_routes_to_recon_after_surface_handoff(tmp_path):
    recon_dir = tmp_path / "recon" / "target.test" / "dirs"
    recon_dir.mkdir(parents=True)
    (recon_dir / "ffuf_target_plan.json").write_text(
        json.dumps({"schema": 1, "eligible_count": 3}), encoding="utf-8"
    )
    (recon_dir / "ffuf_target_state.json").write_text(
        json.dumps({"schema": 1, "completed": {"https://target.test": {"status": "ok"}}}),
        encoding="utf-8",
    )

    status = load_rotation_status(tmp_path, "target.test")
    assert status["status"] == "pending"
    assert status["remaining"] == 2
    assert _pick_next_action(
        True,
        {},
        None,
        surface_context_required=False,
        dir_fuzz_rotation_pending=True,
    ) == "run_recon"


def test_rotation_does_not_preempt_surface_or_finding_work(tmp_path):
    assert _pick_next_action(
        True,
        {},
        None,
        surface_context_required=True,
        dir_fuzz_rotation_pending=True,
    ) == "prepare_surface_context"
    assert _pick_next_action(
        True,
        {"p1": [{"url": "https://target.test/admin"}]},
        None,
        dir_fuzz_rotation_pending=True,
    ) == "hunt_p1"


def test_invalid_rotation_ledger_is_advisory_not_an_infinite_recon_loop(tmp_path):
    recon_dir = tmp_path / "recon" / "target.test" / "dirs"
    recon_dir.mkdir(parents=True)
    (recon_dir / "ffuf_target_plan.json").write_text("not-json", encoding="utf-8")
    (recon_dir / "ffuf_target_state.json").write_text("{}", encoding="utf-8")

    status = load_rotation_status(tmp_path, "target.test")
    assert status["status"] == "invalid"
    assert status["pending"] is False
