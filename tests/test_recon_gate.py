from __future__ import annotations

from tools.recon_gate import build_phase_gate, gate_from_record


def test_success_zero_result_with_existing_artifact_is_complete(tmp_path):
    artifact = tmp_path / "recon" / "target.com" / "live" / "waf_hits.txt"
    artifact.parent.mkdir(parents=True)
    artifact.write_text("", encoding="utf-8")

    gate = build_phase_gate(
        tmp_path,
        phase="waf_fp",
        status="ok",
        artifact="recon/target.com/live/waf_hits.txt",
    )

    assert gate["status"] == "complete"
    assert gate["evidence_refs"] == ["recon/target.com/live/waf_hits.txt"]
    assert gate["coverage_gaps"] == []
    assert gate["next_focus"]


def test_missing_artifact_prevents_complete_gate(tmp_path):
    gate = build_phase_gate(
        tmp_path,
        phase="js_analysis",
        status="ok",
        artifact="recon/target.com/js/endpoints.txt",
    )

    assert gate["status"] == "partial"
    assert gate["evidence_refs"] == []
    assert "missing_artifact:recon/target.com/js/endpoints.txt" in gate["coverage_gaps"]


def test_skipped_phase_is_blocked_without_becoming_clean(tmp_path):
    gate = build_phase_gate(
        tmp_path,
        phase="origin_disco",
        status="skipped",
        artifact="recon/target.com/live/origin_candidates.txt",
    )

    assert gate["status"] == "blocked"
    assert "phase_status:skipped" in gate["coverage_gaps"]


def test_legacy_phase_record_gets_a_read_time_gate(tmp_path):
    artifact = tmp_path / "recon" / "target.com" / "urls" / "all.txt"
    artifact.parent.mkdir(parents=True)
    artifact.write_text("https://target.com/\n", encoding="utf-8")

    gate = gate_from_record(
        tmp_path,
        {
            "record_type": "recon_phase",
            "phase": "url_collection",
            "status": "ok",
            "artifact": "recon/target.com/urls/all.txt",
        },
    )

    assert gate["status"] == "complete"
    assert gate["evidence_refs"] == ["recon/target.com/urls/all.txt"]

