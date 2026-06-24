"""tests/test_bootstrap_serialize.py — P5-B9 bootstrap_context round-trip tests."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))


# ---------------------------------------------------------------------
#  R1/R2 — Round-trip save+load
# ---------------------------------------------------------------------

class TestBootstrapRoundTrip:
    def test_save_and_load_round_trip_preserves_bootstrap_context(self, tmp_path):
        from agent import HuntMemory
        sess = tmp_path / "sess.json"
        m1 = HuntMemory(str(sess))
        m1.bootstrap_context = "operator focus: IDOR on /api/users/{id}; skip xss"
        m1.save()

        m2 = HuntMemory(str(sess))
        assert m2.bootstrap_context == "operator focus: IDOR on /api/users/{id}; skip xss"

    def test_save_and_load_round_trip_preserves_bootstrap_state(self, tmp_path):
        from agent import HuntMemory
        sess = tmp_path / "sess.json"
        m1 = HuntMemory(str(sess))
        m1.bootstrap_state = {
            "focus": ["IDOR", "auth_bypass"],
            "skip_lanes": ["xss"],
            "operator_notes": "victim+attacker accounts already set up",
        }
        m1.save()

        m2 = HuntMemory(str(sess))
        assert m2.bootstrap_state == m1.bootstrap_state

    def test_empty_bootstrap_context_round_trips_to_empty(self, tmp_path):
        from agent import HuntMemory
        sess = tmp_path / "sess.json"
        m1 = HuntMemory(str(sess))
        m1.save()  # bootstrap_context defaults to ""
        m2 = HuntMemory(str(sess))
        assert m2.bootstrap_context == ""

    def test_save_writes_keys_to_json(self, tmp_path):
        from agent import HuntMemory
        sess = tmp_path / "sess.json"
        m = HuntMemory(str(sess))
        m.bootstrap_context = "x"
        m.bootstrap_state = {"k": "v"}
        m.save()
        data = json.loads(sess.read_text())
        assert "bootstrap_context" in data
        assert "bootstrap_state" in data
        assert data["bootstrap_context"] == "x"
        assert data["bootstrap_state"] == {"k": "v"}


# ---------------------------------------------------------------------
#  R3 — Backwards compatibility
# ---------------------------------------------------------------------

class TestBackwardsCompat:
    def test_legacy_session_without_keys_loads_clean(self, tmp_path):
        """A session.json written BEFORE B9 must load without raising."""
        from agent import HuntMemory
        sess = tmp_path / "sess.json"
        sess.write_text(json.dumps({
            "working_memory": "old session content",
            "findings_log": [],
            "observation_buf": [],
            "completed_steps": ["run_recon"],
            "step_count": 5,
            "saved_at": "2026-05-01T00:00:00",
        }))
        m = HuntMemory(str(sess))
        # Defaults to empty for missing keys
        assert m.bootstrap_context == ""
        assert m.bootstrap_state == {}
        # Other fields preserved
        assert m.working_memory == "old session content"
        assert m.step_count == 5

    def test_legacy_session_with_bootstrap_state_as_non_dict_falls_back(self, tmp_path):
        from agent import HuntMemory
        sess = tmp_path / "sess.json"
        sess.write_text(json.dumps({
            "bootstrap_state": "not-a-dict",
        }))
        m = HuntMemory(str(sess))
        assert m.bootstrap_state == {}


# ---------------------------------------------------------------------
#  R4 — Audit log on update
# ---------------------------------------------------------------------

class TestAuditLog:
    def test_update_bootstrap_context_writes_audit_row(self, tmp_path):
        from agent import HuntMemory
        sess = tmp_path / "targets" / "x" / "sessions" / "s1" / "agent_session.json"
        audit = tmp_path / "audit" / "bootstrap_changes.jsonl"
        m = HuntMemory(str(sess))
        m.bootstrap_context = "old"
        rec = m.update_bootstrap_context("new operator focus", audit_path=audit)
        assert rec["old_len"] == 3
        assert rec["new_len"] == len("new operator focus")
        assert audit.exists()
        parsed = json.loads(audit.read_text().strip())
        assert parsed["new_len"] == len("new operator focus")
        # In-memory context was updated
        assert m.bootstrap_context == "new operator focus"

    def test_update_bootstrap_context_in_memory_succeeds_even_when_audit_fails(self, tmp_path):
        from agent import HuntMemory
        sess = tmp_path / "sess.json"
        m = HuntMemory(str(sess))
        # Use an unwritable path (parent is a file)
        bad_parent = tmp_path / "blocker"
        bad_parent.write_text("blocker")
        m.update_bootstrap_context("focus", audit_path=bad_parent / "x" / "log.jsonl")
        # In-memory update still worked
        assert m.bootstrap_context == "focus"

    def test_update_bootstrap_context_returns_audit_record(self, tmp_path):
        from agent import HuntMemory
        sess = tmp_path / "sess.json"
        m = HuntMemory(str(sess))
        rec = m.update_bootstrap_context("x" * 100, audit_path=tmp_path / "audit.jsonl")
        assert rec["new_len"] == 100
        assert "ts" in rec
