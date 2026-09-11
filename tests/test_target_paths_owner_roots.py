"""Tests for the single-source target-scoped owner enumeration used by reset."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from target_paths import active_goal_pointer_path, target_scoped_owner_roots


def _roots(repo: Path, target: str = "target.com") -> dict[str, str]:
    return {
        name: str(Path(path).relative_to(repo))
        for name, path in target_scoped_owner_roots(repo, target).items()
    }


def test_owner_roots_cover_every_per_target_state_location(tmp_path):
    """The enumeration is the reset source of truth: every per-target owner
    path must appear. Adding an owner without extending this list is the bug
    class the 2026-09-11 acceptance round caught (evidence/, memory/evidence/,
    goals target file, journal rows, and the active-goal pointer were all
    leaked by the hand-maintained list)."""
    roots = _roots(tmp_path)
    assert roots == {
        "recon": "recon/target.com",
        "findings": "findings/target.com",
        "reports": "reports/target.com",
        "state": "state/target.com",
        "evidence": "evidence/target.com",
        "memory_evidence": "memory/evidence/target.com",
        "goal_target_file": "memory/goals/targets/target.com.json",
        "targets_sessions": "targets/target.com/sessions",
        "hunt_memory_target": "hunt-memory/targets/target.com.json",
        "hunt_memory_guard": "hunt-memory/guards/target.com.json",
    }


def test_owner_roots_key_escapes_storage_colon_for_hunt_memory(tmp_path):
    """IP:port keys keep their storage-key form for repo dirs but the
    hunt-memory file name uses the dash-escaped profile name."""
    roots = target_scoped_owner_roots(tmp_path, "127.0.0.1:3001")
    assert roots["hunt_memory_target"].endswith("hunt-memory/targets/127.0.0.1-3001.json")
    assert roots["recon"].endswith("recon/127.0.0.1:3001")


def test_reset_script_lists_owner_roots(tmp_path):
    """reset_target.sh derives its deletion list from the same function, so
    dry-run and real reset can never diverge from the enumeration."""
    script = Path(__file__).resolve().parent.parent / "tools" / "reset_target.sh"
    result = subprocess.run(
        ["bash", str(script), "target.com", "--print-only"],
        capture_output=True,
        text=True,
        env={"BBHUNT_BASE_DIR": str(tmp_path), "PATH": "/usr/bin:/bin:" + __import__("os").environ.get("PATH", "")},
        check=True,
    )
    expected = _roots(tmp_path)
    for relative in expected.values():
        assert f"{tmp_path}/{relative}" in result.stdout, relative


def test_active_goal_pointer_is_reported_separately(tmp_path):
    pointer = Path(active_goal_pointer_path(tmp_path))
    assert pointer == tmp_path / "memory" / "goals" / "active.json"


def test_journal_row_filter_removes_only_target_session_summaries(tmp_path):
    """The journal is global; only the target's session_summary rows are
    filtered. Other rows — including other targets' and non-session rows for
    this target — survive."""
    journal = tmp_path / "hunt-memory" / "journal.jsonl"
    journal.parent.mkdir(parents=True)
    rows = [
        {"ts": "1", "target": "other.com", "vuln_class": "session_summary"},
        {"ts": "2", "target": "target.com", "vuln_class": "session_summary"},
        {"ts": "3", "target": "target.com", "vuln_class": "tested_finding"},
        {"ts": "4", "target": "target.com", "vuln_class": "session_summary"},
    ]
    journal.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")

    script = Path(__file__).resolve().parent.parent / "tools" / "reset_target.sh"
    subprocess_env = {
        "BBHUNT_BASE_DIR": str(tmp_path),
        "HUNT_MEMORY_DIR": str(tmp_path / "hunt-memory"),
        "PATH": "/usr/bin:/bin:" + __import__("os").environ.get("PATH", ""),
    }
    subprocess.run(
        ["bash", str(script), "target.com"],
        capture_output=True,
        text=True,
        env=subprocess_env,
        check=True,
    )
    kept = [json.loads(line) for line in journal.read_text().splitlines() if line.strip()]
    assert kept == [
        {"ts": "1", "target": "other.com", "vuln_class": "session_summary"},
        {"ts": "3", "target": "target.com", "vuln_class": "tested_finding"},
    ]
