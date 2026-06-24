"""tests/test_loop_detector_semantic.py — P5-B3 semantic loop detector tests."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from agent import LoopDetector  # noqa: E402


# ---------------------------------------------------------------------
#  R1 — endpoint_family normalization
# ---------------------------------------------------------------------

class TestEndpointFamily:
    def test_numeric_id_collapses(self):
        a = LoopDetector.endpoint_family("/api/v1/users/123")
        b = LoopDetector.endpoint_family("/api/v1/users/456")
        assert a == b == "/api/v1/users/{id}"

    def test_uuid_collapses(self):
        a = LoopDetector.endpoint_family(
            "/api/v1/orders/550e8400-e29b-41d4-a716-446655440000"
        )
        b = LoopDetector.endpoint_family(
            "/api/v1/orders/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        )
        assert a == b == "/api/v1/orders/{uuid}"

    def test_long_hex_collapses(self):
        a = LoopDetector.endpoint_family("/blob/abcdef0123456789abcd")
        b = LoopDetector.endpoint_family("/blob/0123456789abcdef0123")
        assert a == b == "/blob/{hex}"

    def test_query_string_stripped(self):
        a = LoopDetector.endpoint_family("/api/users/123?page=1")
        b = LoopDetector.endpoint_family("/api/users/456?page=2")
        assert a == b == "/api/users/{id}"

    def test_different_paths_not_collapsed(self):
        assert (
            LoopDetector.endpoint_family("/api/users/1")
            != LoopDetector.endpoint_family("/api/orders/1")
        )

    def test_empty_endpoint_returns_empty(self):
        assert LoopDetector.endpoint_family("") == ""

    def test_no_id_unchanged(self):
        assert LoopDetector.endpoint_family("/api/health") == "/api/health"


# ---------------------------------------------------------------------
#  R2 — _normalise_response strips noise
# ---------------------------------------------------------------------

class TestNormaliseResponse:
    def test_iso_timestamps_stripped(self):
        a = LoopDetector._normalise_response('{"at":"2025-01-01T00:00:00Z","ok":1}')
        b = LoopDetector._normalise_response('{"at":"2025-12-31T23:59:59Z","ok":1}')
        assert a == b
        assert "<TS>" in a

    def test_bare_time_stripped(self):
        a = LoopDetector._normalise_response("logged at 12:34:56")
        b = LoopDetector._normalise_response("logged at 09:00:00")
        assert a == b
        assert "<TIME>" in a

    def test_uuid_stripped(self):
        a = LoopDetector._normalise_response(
            '{"id":"550e8400-e29b-41d4-a716-446655440000"}'
        )
        b = LoopDetector._normalise_response(
            '{"id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}'
        )
        assert a == b
        assert "<UUID>" in a

    def test_long_hex_stripped(self):
        a = LoopDetector._normalise_response(
            "etag=abcdef0123456789abcdef0123456789ab"
        )
        b = LoopDetector._normalise_response(
            "etag=0123456789abcdef0123456789abcdef01"
        )
        assert a == b

    def test_request_id_field_stripped(self):
        a = LoopDetector._normalise_response('{"request":"req-123","ok":1}')
        b = LoopDetector._normalise_response('{"request":"req-9999","ok":1}')
        assert a == b

    def test_non_string_input_coerced(self):
        out = LoopDetector._normalise_response(12345)  # type: ignore[arg-type]
        assert "12345" in out

    def test_unrelated_text_unchanged(self):
        s = "hello world, this is fine"
        assert LoopDetector._normalise_response(s) == s


# ---------------------------------------------------------------------
#  R3 — record_with_response and is_semantic_loop
# ---------------------------------------------------------------------

class TestRecordAndDetect:
    def test_no_history_no_loop(self):
        d = LoopDetector()
        assert d.is_semantic_loop() == (False, "")

    def test_single_record_no_loop(self):
        d = LoopDetector()
        d.record_with_response("/api/users/1", '{"ok":1}')
        assert d.is_semantic_loop() == (False, "")

    def test_two_records_same_family_hash_no_loop(self):
        d = LoopDetector()
        d.record_with_response("/api/users/1", '{"ok":1}')
        d.record_with_response("/api/users/2", '{"ok":1}')
        assert d.is_semantic_loop() == (False, "")

    def test_three_records_same_family_hash_triggers_rule_1(self):
        d = LoopDetector()
        d.record_with_response("/api/users/1", '{"ok":1}')
        d.record_with_response("/api/users/2", '{"ok":1}')
        d.record_with_response("/api/users/3", '{"ok":1}')
        looped, reason = d.is_semantic_loop()
        assert looped is True
        assert reason.startswith("same_family_hash:/api/users/{id}")

    def test_same_hash_across_different_families_triggers_rule_2(self):
        d = LoopDetector()
        # 5 different families, same response hash → Rule 2
        for ep in ("/a/1", "/b/1", "/c/1", "/d/1", "/e/1"):
            d.record_with_response(ep, '{"err":"forbidden"}')
        looped, reason = d.is_semantic_loop()
        assert looped is True
        assert reason.startswith("same_hash:")

    def test_diverse_responses_no_loop(self):
        d = LoopDetector()
        for i in range(8):
            d.record_with_response(f"/api/users/{i}", f'{{"ok":{i}}}')
        # Each response has a distinct hash
        assert d.is_semantic_loop() == (False, "")

    def test_window_trims_to_sem_window(self):
        d = LoopDetector()
        for i in range(LoopDetector.SEM_WINDOW + 10):
            d.record_with_response(f"/x/{i}", f'{{"ok":{i}}}')
        assert len(d._sem_history) == LoopDetector.SEM_WINDOW

    def test_rule_1_uses_last_10_window(self):
        """Old repeats outside the last-10 window should not trigger Rule 1."""
        d = LoopDetector()
        # Three matching repeats early
        for ep in ("/api/users/1", "/api/users/2", "/api/users/3"):
            d.record_with_response(ep, '{"ok":1}')
        # 9 distinct responses fill the recent10 window so the early triple
        # falls out
        for i in range(9):
            d.record_with_response(f"/diverse/{i}", f'{{"unique":{i}}}')
        # Rule 1 is about the LAST 10 — early triple is now outside window
        # Rule 2 also doesn't fire (need 5 same-hash, we have 1 left)
        assert d.is_semantic_loop() == (False, "")

    def test_normalisation_lets_timestamped_responses_collapse(self):
        d = LoopDetector()
        for i in range(3):
            d.record_with_response(
                "/api/users/1",
                f'{{"at":"2025-01-01T00:00:0{i}Z","ok":1}}',
            )
        # Normalisation strips timestamps → all three have same hash → loop
        looped, _ = d.is_semantic_loop()
        assert looped is True

    def test_endpoint_with_no_match_falls_through(self):
        d = LoopDetector()
        d.record_with_response("", '{"ok":1}')
        assert d.is_semantic_loop() == (False, "")


# ---------------------------------------------------------------------
#  R4 — rotation_hint emits injectable text
# ---------------------------------------------------------------------

class TestRotationHint:
    def test_no_loop_returns_empty_hint(self):
        d = LoopDetector()
        d.record_with_response("/api/users/1", '{"ok":1}')
        assert d.rotation_hint() == ""

    def test_rule_1_hint_mentions_family(self):
        d = LoopDetector()
        for ep in ("/api/users/1", "/api/users/2", "/api/users/3"):
            d.record_with_response(ep, '{"ok":1}')
        hint = d.rotation_hint()
        assert hint.startswith("[loop-detector]")
        assert "/api/users/{id}" in hint
        assert "different attack class" in hint

    def test_rule_2_hint_mentions_technique_change(self):
        d = LoopDetector()
        for ep in ("/a/1", "/b/1", "/c/1", "/d/1", "/e/1"):
            d.record_with_response(ep, '{"err":"forbidden"}')
        hint = d.rotation_hint()
        assert hint.startswith("[loop-detector]")
        assert "technique" in hint or "auth" in hint


# ---------------------------------------------------------------------
#  R5 — reset clears semantic state
# ---------------------------------------------------------------------

class TestReset:
    def test_reset_clears_sem_history(self):
        d = LoopDetector()
        for i in range(3):
            d.record_with_response("/x/1", '{"ok":1}')
        assert d.is_semantic_loop()[0] is True
        d.reset()
        assert d._sem_history == []
        assert d._last_loop_reason == ""
        assert d.is_semantic_loop() == (False, "")

    def test_reset_does_not_break_signature_history(self):
        d = LoopDetector()
        d.record("read_recon_summary", {"target": "x"})
        d.reset()
        # Both the legacy and semantic histories cleared
        assert d._history == []
        assert d._sem_history == []


# ---------------------------------------------------------------------
#  R6 — coexistence with the legacy signature loop detector
# ---------------------------------------------------------------------

class TestCoexistenceLegacy:
    def test_record_and_record_with_response_independent(self):
        """The two histories are independent and both work in one detector."""
        d = LoopDetector()
        # Drive the legacy signature path
        for _ in range(3):
            warn, brk = d.record("read_recon_summary", {"target": "x"})
        assert warn is True
        # Drive the semantic path independently
        d.record_with_response("/api/users/1", '{"ok":1}')
        d.record_with_response("/api/users/2", '{"ok":1}')
        d.record_with_response("/api/users/3", '{"ok":1}')
        looped, _ = d.is_semantic_loop()
        assert looped is True
