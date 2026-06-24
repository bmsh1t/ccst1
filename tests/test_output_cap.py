"""tests/test_output_cap.py — P5-B11 tool output size cap tests."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools import output_cap as oc  # noqa: E402


# ---------------------------------------------------------------------
#  R1 — cap() boundary cases
# ---------------------------------------------------------------------

class TestCapBasic:
    def test_under_cap_is_unchanged(self):
        s = "hello world"
        assert oc.cap(s, max_bytes=1000) == s

    def test_exact_boundary_unchanged(self):
        s = "x" * 100
        assert oc.cap(s, max_bytes=100) == s

    def test_over_cap_truncates_and_marker_appended(self):
        s = "x" * 1_000_000
        out = oc.cap(s, max_bytes=50_000)
        assert len(out.encode("utf-8")) <= 50_000
        assert "TRUNCATED" in out

    def test_default_cap_is_50k(self):
        assert oc.DEFAULT_CAP_BYTES == 50_000

    def test_zero_cap_returns_empty(self):
        assert oc.cap("abc", max_bytes=0) == ""

    def test_negative_cap_returns_empty(self):
        assert oc.cap("abc", max_bytes=-1) == ""

    def test_non_string_input_coerced(self):
        assert oc.cap(12345, max_bytes=1000) == "12345"  # type: ignore[arg-type]


# ---------------------------------------------------------------------
#  R1 — multi-byte UTF-8 safety
# ---------------------------------------------------------------------

class TestCapUtf8Safety:
    def test_does_not_break_mid_multibyte(self):
        """Truncating must not yield a replacement char or partial codepoint."""
        # '€' = 3 bytes in UTF-8; build a string where exact byte cap would
        # cut a euro symbol in half.
        s = "abc" + ("€" * 100)
        out = oc.cap(s, max_bytes=10)
        # Whatever we got back, it must round-trip clean UTF-8
        out.encode("utf-8").decode("utf-8")

    def test_prefers_line_boundary(self):
        s = "line one\nline two\nline three\n" + ("x" * 10_000)
        out = oc.cap(s, max_bytes=100)
        # Should end on a newline boundary (the line break before truncation)
        head = out.replace("\n[…OUTPUT TRUNCATED…]", "")
        assert head.endswith("\n") or len(head) < 50, (
            f"expected line-boundary truncation, got tail={head[-30:]!r}"
        )

    def test_falls_back_when_no_line_in_first_half(self):
        s = "x" * 200_000
        out = oc.cap(s, max_bytes=50_000)
        # No newlines available; falls back to byte boundary
        assert len(out.encode("utf-8")) <= 50_000


# ---------------------------------------------------------------------
#  R1 — cap_dict()
# ---------------------------------------------------------------------

class TestCapDict:
    def test_caps_string_leaf(self):
        d = {"a": "x" * 100_000, "b": "short"}
        out = oc.cap_dict(d, max_bytes=1000)
        assert len(out["a"].encode("utf-8")) <= 1000
        assert "TRUNCATED" in out["a"]
        assert out["b"] == "short"

    def test_preserves_non_string_leaves(self):
        d = {"count": 42, "items": [1, 2, 3], "name": "foo"}
        out = oc.cap_dict(d, max_bytes=1000)
        assert out["count"] == 42
        assert out["items"] == [1, 2, 3]
        assert out["name"] == "foo"

    def test_recurses_into_nested_dict(self):
        d = {"outer": {"inner": "x" * 100_000}}
        out = oc.cap_dict(d, max_bytes=1000)
        assert len(out["outer"]["inner"].encode("utf-8")) <= 1000

    def test_recurses_into_list_of_strings(self):
        d = {"lines": ["x" * 100_000, "short"]}
        out = oc.cap_dict(d, max_bytes=1000)
        assert len(out["lines"][0].encode("utf-8")) <= 1000
        assert out["lines"][1] == "short"

    def test_does_not_mutate_input(self):
        original = "x" * 100_000
        d = {"a": original}
        oc.cap_dict(d, max_bytes=1000)
        assert d["a"] == original  # unchanged

    def test_rejects_non_dict(self):
        with pytest.raises(TypeError):
            oc.cap_dict("not a dict", max_bytes=1000)  # type: ignore[arg-type]

    def test_empty_dict_returns_empty(self):
        assert oc.cap_dict({}, max_bytes=1000) == {}


# ---------------------------------------------------------------------
#  R2 — Overflow event log
# ---------------------------------------------------------------------

class TestOverflowLog:
    def test_log_overflow_writes_jsonl_row(self, tmp_path):
        path = tmp_path / "overflow.jsonl"
        rec = oc.log_overflow("read_recon_summary",
                              original_bytes=200_000, capped_bytes=50_000,
                              path=path)
        assert rec["tool"] == "read_recon_summary"
        assert rec["original_bytes"] == 200_000
        assert rec["capped_bytes"] == 50_000
        # File contains exactly one valid JSON row
        lines = path.read_text().strip().splitlines()
        assert len(lines) == 1
        parsed = json.loads(lines[0])
        assert parsed["marker_appended"] is True
        assert "ts" in parsed

    def test_log_overflow_appends(self, tmp_path):
        path = tmp_path / "overflow.jsonl"
        oc.log_overflow("t1", original_bytes=100, capped_bytes=50, path=path)
        oc.log_overflow("t2", original_bytes=200, capped_bytes=80, path=path)
        lines = path.read_text().strip().splitlines()
        assert len(lines) == 2
        assert json.loads(lines[0])["tool"] == "t1"
        assert json.loads(lines[1])["tool"] == "t2"

    def test_log_overflow_swallows_errors(self, tmp_path):
        # Use a path that can't be created (parent is a file, not a dir)
        bad_parent = tmp_path / "blocker"
        bad_parent.write_text("blocking file")
        # log_overflow should NOT raise — best-effort
        rec = oc.log_overflow("t", original_bytes=1, capped_bytes=0,
                              path=bad_parent / "x" / "log.jsonl")
        assert isinstance(rec, dict)


# ---------------------------------------------------------------------
#  Convenience wrapper
# ---------------------------------------------------------------------

class TestCapWithLog:
    def test_no_log_when_under_cap(self, tmp_path):
        path = tmp_path / "overflow.jsonl"
        out = oc.cap_with_log("hi", tool="t", max_bytes=1000, log_path=path)
        assert out == "hi"
        assert not path.exists()

    def test_log_when_over_cap(self, tmp_path):
        path = tmp_path / "overflow.jsonl"
        out = oc.cap_with_log("x" * 100_000, tool="read_recon_summary",
                              max_bytes=1000, log_path=path)
        assert "TRUNCATED" in out
        assert path.exists()
        parsed = json.loads(path.read_text().strip())
        assert parsed["tool"] == "read_recon_summary"
        assert parsed["original_bytes"] == 100_000


# ---------------------------------------------------------------------
#  R3 — Dispatcher integration
# ---------------------------------------------------------------------

class TestDispatcherIntegration:
    def test_dispatcher_caps_read_recon_summary(self, monkeypatch, tmp_path):
        """Verify the cap is APPLIED in ToolDispatcher.dispatch() for read_*."""
        from agent import HuntMemory, ToolDispatcher
        memory = HuntMemory(session_file=str(tmp_path / "sess.json"))
        d = ToolDispatcher("x.com", memory)

        # Stub _read_recon_files to return a 200KB string
        monkeypatch.setattr(d, "_read_recon_files", lambda dom: "y" * 200_000)
        # Stub _classify_obs to a no-op so nothing barfs on the huge string
        monkeypatch.setattr(d, "_classify_obs", lambda n, o: None)
        # Stub save so we don't touch disk
        monkeypatch.setattr(memory, "save", lambda: None)

        out = d.dispatch("read_recon_summary", {})
        # Output is now capped + trailing dispatcher footer
        head = out.split("\n\n[", 1)[0]
        assert "TRUNCATED" in head
        # Compact: well under 200KB
        assert len(out.encode("utf-8")) < 100_000

    def test_dispatcher_does_not_cap_other_tools(self, monkeypatch, tmp_path):
        """Non-listed tools should pass through unchanged."""
        from agent import HuntMemory, ToolDispatcher
        memory = HuntMemory(session_file=str(tmp_path / "sess.json"))
        d = ToolDispatcher("x.com", memory)

        # update_working_memory returns directly without the cap layer
        out = d.dispatch("update_working_memory", {"notes": "x" * 100_000})
        # Plain non-truncated success message
        assert "Working memory updated" in out
        assert "TRUNCATED" not in out
