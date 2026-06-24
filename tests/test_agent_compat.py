"""Compatibility tests for agent.py against the current tools/hunt.py layout."""

from pathlib import Path

import agent


def test_agent_only_exposes_wired_and_dispatcher_tools():
    supported = agent._h().supported_tool_names()
    dispatcher_only = {
        "read_autopilot_state",
        "read_guard_status",
        "read_repo_source_summary",
        "read_resume_summary",
        "read_surface_summary",
        "read_intelligence",
        "run_intel",
        "remember_finding",
        "read_recon_summary",
        "read_findings_summary",
        "update_working_memory",
        "pattern_calibration_summary",
        "read_browser_screenshot",
        "run_vision_probe",
        "run_sibling_probe",
        "run_hypothesis_fleet",
        "run_self_review",
        "finish",
    }

    assert agent.TOOL_NAMES == supported | dispatcher_only
    assert "run_sqlmap_on_file" in agent.TOOL_NAMES
    assert "run_sqlmap_request_file" not in agent.TOOL_NAMES
    assert {"setup_wordlists", "select_targets", "show_status", "hunt_target"} & agent.TOOL_NAMES == set()


def test_hunt_compat_maps_private_function_to_public_tool_name():
    supported = agent._h().supported_tool_names()

    assert "run_sqlmap_on_file" in supported
    assert "run_sqlmap_request_file" not in supported


def test_hunt_compat_session_dir_creation(monkeypatch, tmp_path):
    hunt = agent._h()
    monkeypatch.setattr(hunt, "TARGETS_DIR", str(tmp_path / "targets"))

    session_id, recon_dir = hunt._activate_recon_session(
        "example.com",
        create=True,
    )

    assert session_id
    assert Path(recon_dir).is_dir()
    assert Path(recon_dir).parts[-4:] == ("example.com", "sessions", session_id, "recon")


def test_hunt_compat_default_session_is_fresh(monkeypatch, tmp_path):
    hunt = agent._h()
    monkeypatch.setattr(hunt, "TARGETS_DIR", str(tmp_path / "targets"))

    first_id, first_recon_dir = hunt._activate_recon_session("example.com", create=True)
    second_id, second_recon_dir = hunt._activate_recon_session("example.com", create=True)

    assert first_id != second_id
    assert Path(first_recon_dir).is_dir()
    assert Path(second_recon_dir).is_dir()


def test_hunt_compat_latest_resumes_existing_session(monkeypatch, tmp_path):
    hunt = agent._h()
    monkeypatch.setattr(hunt, "TARGETS_DIR", str(tmp_path / "targets"))

    first_id, _ = hunt._activate_recon_session("example.com", create=True)
    second_id, _ = hunt._activate_recon_session("example.com", create=True)
    latest_id, latest_recon_dir = hunt._activate_recon_session(
        "example.com",
        requested_session_id="latest",
        create=True,
    )

    assert first_id != second_id
    assert latest_id == second_id
    assert Path(latest_recon_dir).parts[-4:] == ("example.com", "sessions", second_id, "recon")


def test_hunt_compat_explicit_session_id_resumes_named_session(monkeypatch, tmp_path):
    hunt = agent._h()
    monkeypatch.setattr(hunt, "TARGETS_DIR", str(tmp_path / "targets"))

    session_id, recon_dir = hunt._activate_recon_session(
        "example.com",
        requested_session_id="manual-001",
        create=True,
    )

    assert session_id == "manual-001"
    assert Path(recon_dir).parts[-4:] == ("example.com", "sessions", "manual-001", "recon")


def test_phase_flags_map_run_prefixed_steps():
    flags = agent._phase_flags(
        [
            "check_tools",
            "run_recon",
            "run_vuln_scan",
            "run_sqlmap_on_file",
            "run_post_param_discovery",
            "run_cve_hunt",
            "generate_reports",
            "read_resume_summary",
        ]
    )

    assert flags["tool_check"] is True
    assert flags["recon"] is True
    assert flags["scan"] is True
    assert flags["sqlmap"] is True
    assert flags["post_param_discovery"] is True
    assert flags["jwt_audit"] is False
    assert flags["cve_hunt"] is True
    assert flags["zero_day_fuzzer"] is False
    assert flags["reports_generated"] is True
