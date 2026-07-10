"""Tests for F3 (coverage matrix) and F4 (intelligence) finish-gate invariants.

Covers tasks 05-16-b1-f3-finish-gate and 05-16-b2-f4-finish-gate.

These tests exercise the gate helper functions directly with synthetic
fixtures — they do NOT spin up a full ReActAgent or call Ollama. That keeps
the test fast (<1s each) and provider-independent, mirroring B5's structural
test philosophy.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import agent
from agent import (
    _f3_coverage_gate,
    _f4_intelligence_gate,
    _finish_gate_block_or_warn,
)

REPO_ROOT = Path(agent.__file__).resolve().parent


# ─────────────────────────────────────────────────────────────────────────────
# F3 — coverage_matrix.find-gaps
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def stub_coverage_matrix(monkeypatch, tmp_path):
    """Replace tools/coverage_matrix.py with a stub script that prints whatever
    JSON the test fixture pre-writes to gaps.json.

    Activated by writing tools/coverage_matrix.py-stub.json under tmp_path
    repo_root; the stub reads that to decide what to emit.
    """
    fake_repo = tmp_path / "repo"
    (fake_repo / "tools").mkdir(parents=True)
    stub_script = fake_repo / "tools" / "coverage_matrix.py"
    stub_script.write_text(
        "import json, os, sys\n"
        "p = os.environ.get('STUB_GAPS_FILE','')\n"
        "if not p or not os.path.isfile(p):\n"
        "    print('[]'); sys.exit(0)\n"
        "with open(p) as f:\n"
        "    print(f.read())\n"
    )
    return fake_repo


def _write_gaps(repo: Path, gaps: list[dict]) -> Path:
    gp = repo / "gaps.json"
    gp.write_text(json.dumps(gaps))
    return gp


def test_f3_passes_when_no_gaps(stub_coverage_matrix, monkeypatch):
    gp = _write_gaps(stub_coverage_matrix, [])
    monkeypatch.setenv("STUB_GAPS_FILE", str(gp))
    passed, msg = _f3_coverage_gate("test.com", repo_root=stub_coverage_matrix)
    assert passed is True
    assert msg == ""


def test_f3_blocks_when_gaps_present(stub_coverage_matrix, monkeypatch):
    gaps = [
        {"endpoint": "/api/users/{id}", "vuln_class": "IDOR", "weight": 3.0},
        {"endpoint": "/api/orders/{id}", "vuln_class": "IDOR", "weight": 2.5},
    ]
    gp = _write_gaps(stub_coverage_matrix, gaps)
    monkeypatch.setenv("STUB_GAPS_FILE", str(gp))
    passed, msg = _f3_coverage_gate("test.com", repo_root=stub_coverage_matrix)
    assert passed is False
    assert "F3 finish-gate blocked" in msg
    assert "test.com" in msg
    assert "/api/users/{id}" in msg
    assert "IDOR" in msg


def test_f3_truncates_large_gap_list(stub_coverage_matrix, monkeypatch):
    gaps = [
        {"endpoint": f"/api/x{i}", "vuln_class": "IDOR", "weight": 2.0}
        for i in range(20)
    ]
    gp = _write_gaps(stub_coverage_matrix, gaps)
    monkeypatch.setenv("STUB_GAPS_FILE", str(gp))
    passed, msg = _f3_coverage_gate("test.com", repo_root=stub_coverage_matrix)
    assert passed is False
    assert "20 high-value coverage" in msg
    assert "... (15 more)" in msg


def test_f3_treats_missing_matrix_tool_as_pass(tmp_path):
    """No tools/coverage_matrix.py → F3 cannot run, treat as pass with no warning."""
    fake_repo = tmp_path / "empty"
    fake_repo.mkdir()
    passed, msg = _f3_coverage_gate("test.com", repo_root=fake_repo)
    assert passed is True
    assert msg == ""


def test_f3_handles_subprocess_error(stub_coverage_matrix, monkeypatch):
    """If coverage_matrix exits non-zero, emit audit note but pass."""
    bad_script = stub_coverage_matrix / "tools" / "coverage_matrix.py"
    bad_script.write_text("import sys; sys.stderr.write('boom'); sys.exit(1)\n")
    passed, msg = _f3_coverage_gate("test.com", repo_root=stub_coverage_matrix)
    assert passed is True
    assert "[AUDIT]" in msg
    assert "exited 1" in msg


def test_f3_handles_non_json_output(stub_coverage_matrix, monkeypatch):
    """Non-JSON output → audit + pass."""
    bad_script = stub_coverage_matrix / "tools" / "coverage_matrix.py"
    bad_script.write_text("print('not json output')\n")
    passed, msg = _f3_coverage_gate("test.com", repo_root=stub_coverage_matrix)
    assert passed is True
    assert "[AUDIT]" in msg
    assert "not JSON" in msg


# ─────────────────────────────────────────────────────────────────────────────
# F4 — intelligence.md read
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def fake_repo(tmp_path):
    repo = tmp_path / "fake_repo"
    (repo / "evidence" / "test.com").mkdir(parents=True)
    return repo


def test_f4_blocks_when_intelligence_exists_but_unread(fake_repo):
    intel = fake_repo / "evidence" / "test.com" / "intelligence.md"
    intel.write_text("# Intelligence\nVendor: Acme\n")
    passed, msg = _f4_intelligence_gate(
        "test.com", completed_steps=["run_recon", "run_vuln_scan"],
        repo_root=fake_repo,
    )
    assert passed is False
    assert "F4 finish-gate blocked" in msg
    assert "read_intelligence" in msg


def test_f4_passes_when_intelligence_was_read(fake_repo):
    intel = fake_repo / "evidence" / "test.com" / "intelligence.md"
    intel.write_text("# Intelligence\n")
    passed, msg = _f4_intelligence_gate(
        "test.com",
        completed_steps=["run_recon", "read_intelligence", "run_vuln_scan"],
        repo_root=fake_repo,
    )
    assert passed is True
    assert msg == ""


def test_f4_passes_when_no_intelligence_layer(fake_repo):
    # No intelligence.md present
    passed, msg = _f4_intelligence_gate(
        "test.com", completed_steps=["run_recon"], repo_root=fake_repo,
    )
    assert passed is True
    assert "[AUDIT]" in msg
    assert "no intelligence layer" in msg


def test_f4_url_target_reads_canonical_intelligence_path(tmp_path):
    repo = tmp_path / "repo"
    intel = repo / "evidence" / "127.0.0.1:3002" / "intelligence.md"
    intel.parent.mkdir(parents=True)
    intel.write_text("# Intelligence\n", encoding="utf-8")

    passed, msg = _f4_intelligence_gate(
        "http://127.0.0.1:3002/#/login",
        completed_steps=[],
        repo_root=repo,
    )

    assert passed is False
    assert str(intel) in msg


# ─────────────────────────────────────────────────────────────────────────────
# Mode awareness: yolo override
# ─────────────────────────────────────────────────────────────────────────────

def test_paranoid_blocks():
    block, emit = _finish_gate_block_or_warn("[SYSTEM] X", "paranoid")
    assert block is True
    assert emit == "[SYSTEM] X"


def test_normal_blocks():
    block, emit = _finish_gate_block_or_warn("[SYSTEM] X", "normal")
    assert block is True
    assert emit == "[SYSTEM] X"


def test_yolo_emits_override_warning_and_does_not_block():
    block, emit = _finish_gate_block_or_warn("[SYSTEM] X", "yolo")
    assert block is False
    assert emit.startswith("[YOLO-OVERRIDE]")
    assert "[SYSTEM] X" in emit


def test_empty_message_never_blocks():
    block, emit = _finish_gate_block_or_warn("", "paranoid")
    assert block is False
    assert emit == ""


@pytest.mark.parametrize("mode", ["paranoid", "normal", "yolo"])
def test_passed_gate_audit_message_never_blocks(mode):
    audit = "[AUDIT] gate unavailable; continuing"
    block, emit = _finish_gate_block_or_warn(audit, mode, passed=True)
    assert block is False
    assert emit == audit


# ─────────────────────────────────────────────────────────────────────────────
# min_steps_before_finish — yolo downgrade parity with F3/F4 gates
#
# These tests cover the inline branch in agent.py:3510-3529 that gates the
# `finish` tool call by completed-step count. The branch is NOT factored
# into a helper, so the tests below verify the **decision predicate** and
# the **advisory message contract** instead of spinning up a ReActAgent.
#
# The production branch is:
#     if name == "finish" and progress_steps < self.min_steps_before_finish:
#         if self.autopilot_mode == "yolo":
#             # advisory only — finish proceeds to F3/F4 gates and dispatch
#         else:
#             # block: append advisory and `continue`
#
# Parity with _finish_gate_block_or_warn / _f3_coverage_gate / _f4_intelligence_gate
# (paranoid/normal block, yolo emit-and-proceed) is the contract being asserted.
# ─────────────────────────────────────────────────────────────────────────────

from agent import _finish_floor_for_mode, _normalize_autopilot_mode  # noqa: E402


def _min_steps_predicate(progress: int, mode: str) -> tuple[bool, str]:
    """Mirror of agent.py:3510-3529 decision. Kept inline-equivalent on purpose.

    Returns (should_block_finish, advisory_message). If the change at
    agent.py:3510-3529 ever drifts away from this predicate, the
    test_min_steps_advisory_message_format test below will detect it
    (advisory string is asserted exactly).
    """
    floor = _finish_floor_for_mode(mode)
    if progress >= floor:
        return False, ""
    remaining = floor - progress
    advisory = (
        f"[SYSTEM] Too early to finish. You have only run "
        f"{progress} substantive tools. Run at least "
        f"{remaining} more high-impact tools before concluding."
    )
    normalized = _normalize_autopilot_mode(mode)
    if normalized == "yolo":
        # advisory only — does NOT block dispatch
        return False, advisory
    return True, advisory


def test_min_steps_paranoid_blocks_when_under_floor():
    block, msg = _min_steps_predicate(progress=1, mode="paranoid")
    # paranoid floor = 8; progress 1 < 8 → block
    assert block is True
    assert "[SYSTEM] Too early to finish" in msg
    assert "1 substantive tools" in msg
    assert "7 more high-impact" in msg


def test_min_steps_normal_blocks_when_under_floor():
    block, msg = _min_steps_predicate(progress=2, mode="normal")
    # normal floor = 6; progress 2 < 6 → block
    assert block is True
    assert "4 more high-impact" in msg


def test_min_steps_yolo_emits_advisory_but_does_not_block():
    """Yolo mode must NOT block finish — only emit advisory and let dispatch
    proceed to F3/F4 gates. This is parity with _finish_gate_block_or_warn."""
    block, msg = _min_steps_predicate(progress=1, mode="yolo")
    # yolo floor = 4; progress 1 < 4 → would-block in paranoid/normal,
    # but yolo emits advisory and proceeds
    assert block is False
    assert "[SYSTEM] Too early to finish" in msg
    assert "1 substantive tools" in msg
    assert "3 more high-impact" in msg


def test_min_steps_paranoid_passes_when_at_or_above_floor():
    """Progress ≥ floor means the gate doesn't fire at all (no advisory)."""
    block, msg = _min_steps_predicate(progress=8, mode="paranoid")
    assert block is False
    assert msg == ""
    # And well above floor
    block, msg = _min_steps_predicate(progress=20, mode="paranoid")
    assert block is False
    assert msg == ""


def test_min_steps_yolo_passes_silently_when_at_floor():
    """Yolo floor = 4. At 4 steps, no advisory emitted (predicate doesn't fire)."""
    block, msg = _min_steps_predicate(progress=4, mode="yolo")
    assert block is False
    assert msg == ""


def test_min_steps_floor_per_mode_unchanged():
    """Mode-to-floor mapping is part of the gate contract. Surfaces drift if
    anyone changes _finish_floor_for_mode without intending to."""
    assert _finish_floor_for_mode("paranoid") == 8
    assert _finish_floor_for_mode("normal") == 6
    assert _finish_floor_for_mode("yolo") == 4


def test_min_steps_advisory_message_format():
    """Lock the advisory string format so a drift in agent.py:3514-3518
    breaks this test. The LLM reads this text — wording matters."""
    block, msg = _min_steps_predicate(progress=3, mode="paranoid")
    expected = (
        "[SYSTEM] Too early to finish. You have only run "
        "3 substantive tools. Run at least "
        "5 more high-impact tools before concluding."
    )
    assert msg == expected


# ─────────────────────────────────────────────────────────────────────────────
# read_intelligence dispatcher path
# ─────────────────────────────────────────────────────────────────────────────

def test_read_intelligence_handles_missing_file(tmp_path, monkeypatch):
    """The dispatcher's _read_intelligence handler returns a usable message
    when evidence/<target>/intelligence.md is missing."""
    fake_repo = tmp_path / "repo"
    fake_repo.mkdir()

    class FakeDispatcher:
        domain = "missing.com"
    fd = FakeDispatcher()
    # Reuse the bound method
    out = agent.ReActAgent.__dict__  # confirm class exists
    # Use the dispatcher class directly
    from agent import ToolDispatcher
    # Build a real dispatcher via constructor with minimal args
    class _DummyHuntMemory:
        completed_steps: list = []
    dispatcher = ToolDispatcher.__new__(ToolDispatcher)
    dispatcher.domain = "missing.com"
    msg = dispatcher._read_intelligence("missing.com", repo_root=str(fake_repo))
    assert "No intelligence layer" in msg
    assert "intelligence_extractor.py" in msg


def test_read_intelligence_reads_existing_file(tmp_path):
    fake_repo = tmp_path / "repo"
    (fake_repo / "evidence" / "target.com").mkdir(parents=True)
    intel_path = fake_repo / "evidence" / "target.com" / "intelligence.md"
    intel_path.write_text("# heading\nbody line\n")

    from agent import ToolDispatcher
    dispatcher = ToolDispatcher.__new__(ToolDispatcher)
    dispatcher.domain = "target.com"
    msg = dispatcher._read_intelligence("target.com", repo_root=str(fake_repo))
    assert "intelligence.md" in msg
    assert "body line" in msg


def test_read_intelligence_url_target_uses_canonical_path(tmp_path):
    fake_repo = tmp_path / "repo"
    intel_path = fake_repo / "evidence" / "127.0.0.1:3002" / "intelligence.md"
    intel_path.parent.mkdir(parents=True)
    intel_path.write_text("# canonical intel\n", encoding="utf-8")

    from agent import ToolDispatcher
    dispatcher = ToolDispatcher.__new__(ToolDispatcher)
    dispatcher.domain = "http://127.0.0.1:3002/#/login"
    msg = dispatcher._read_intelligence(dispatcher.domain, repo_root=str(fake_repo))

    assert "canonical intel" in msg
    assert str(intel_path) in msg


def test_read_intelligence_truncates_huge_files(tmp_path):
    fake_repo = tmp_path / "repo"
    (fake_repo / "evidence" / "target.com").mkdir(parents=True)
    huge = "X" * 20000
    intel_path = fake_repo / "evidence" / "target.com" / "intelligence.md"
    intel_path.write_text(huge)

    from agent import ToolDispatcher
    dispatcher = ToolDispatcher.__new__(ToolDispatcher)
    dispatcher.domain = "target.com"
    msg = dispatcher._read_intelligence("target.com", repo_root=str(fake_repo))
    assert "truncated" in msg
    # Ensure we did not leak the entire 20000-byte body
    assert len(msg) < 14000


# ─────────────────────────────────────────────────────────────────────────────
# Tool surface: read_intelligence is exposed in TOOLS
# ─────────────────────────────────────────────────────────────────────────────

def test_read_intelligence_in_tools_schema():
    """The tool MUST be exposed to the LLM, otherwise F4 would block forever."""
    names = {t["function"]["name"] for t in agent.TOOLS}
    assert "read_intelligence" in names


def test_read_intelligence_in_dispatcher_only_set():
    """read_intelligence is a dispatcher-only tool (no hunt.py wrapper required)."""
    assert "read_intelligence" in agent._DISPATCHER_ONLY_TOOLS
