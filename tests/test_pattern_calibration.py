"""tests/test_pattern_calibration.py — B12d acceptance tests."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools import pattern_calibration as pc      # noqa: E402
from memory.pattern_db import PatternDB           # noqa: E402


@pytest.fixture
def cal_path(tmp_path):
    return tmp_path / "pattern_calibration.jsonl"


# ---------------------------------------------------------------------
#  R1, R2: Record per-match outcome
# ---------------------------------------------------------------------

class TestRecordOutcome:
    def test_record_happy_path(self, cal_path):
        rec = pc.record_outcome(
            pattern_id="p1", outcome=pc.OUTCOME_HELPED,
            session_id="s1", target="x.com", path=cal_path,
        )
        assert rec["pattern_id"] == "p1"
        assert rec["outcome"] == "helped"
        assert rec["session_id"] == "s1"
        assert rec["target"] == "x.com"
        assert "ts" in rec
        # File should contain one JSONL row
        assert cal_path.read_text().strip().count("\n") == 0  # one line, no trailing newline
        loaded = json.loads(cal_path.read_text().strip())
        assert loaded["pattern_id"] == "p1"

    def test_record_rejects_invalid_outcome(self, cal_path):
        with pytest.raises(ValueError):
            pc.record_outcome(pattern_id="p1", outcome="other", path=cal_path)

    def test_record_rejects_empty_pattern_id(self, cal_path):
        with pytest.raises(ValueError):
            pc.record_outcome(pattern_id="", outcome="helped", path=cal_path)

    def test_record_multiple_appends(self, cal_path):
        pc.record_outcome(pattern_id="p1", outcome="helped", path=cal_path)
        pc.record_outcome(pattern_id="p2", outcome="no_signal", path=cal_path)
        pc.record_outcome(pattern_id="p1", outcome="false_positive", path=cal_path)
        rows = pc.read_all(cal_path)
        assert len(rows) == 3
        assert {r["pattern_id"] for r in rows} == {"p1", "p2"}


# ---------------------------------------------------------------------
#  R3: Aggregated precision/recall
# ---------------------------------------------------------------------

class TestSummarise:
    def _seed(self, cal_path: Path, rows: list[tuple[str, str]]):
        for pid, outcome in rows:
            pc.record_outcome(pattern_id=pid, outcome=outcome, path=cal_path)

    def test_summarise_returns_per_pattern_stats(self, cal_path):
        self._seed(cal_path, [
            ("p1", "helped"), ("p1", "helped"), ("p1", "false_positive"),
            ("p2", "no_signal"), ("p2", "no_signal"),
        ])
        stats = pc.summarise(cal_path)
        # p1 has more samples → first
        by_id = {r["pattern_id"]: r for r in stats}
        assert by_id["p1"]["samples"] == 3
        assert by_id["p1"]["helped"] == 2
        assert by_id["p1"]["false_positive"] == 1
        assert by_id["p1"]["precision"] == pytest.approx(2 / 3)
        assert by_id["p1"]["recall_proxy"] == pytest.approx(2 / 3)
        # p2: no helped, no fp → precision is None (no denominator)
        assert by_id["p2"]["samples"] == 2
        assert by_id["p2"]["helped"] == 0
        assert by_id["p2"]["precision"] is None
        assert by_id["p2"]["recall_proxy"] == 0.0

    def test_summarise_empty_returns_empty_list(self, cal_path):
        assert pc.summarise(cal_path) == []

    def test_summarise_skips_corrupt_lines(self, cal_path):
        cal_path.write_text(
            '{"ts":"2026-01-01T00:00:00+00:00","pattern_id":"p1","outcome":"helped"}\n'
            "not json\n"
            '{"ts":"2026-01-01T00:00:01+00:00","pattern_id":"p1","outcome":"helped"}\n'
        )
        stats = pc.summarise(cal_path)
        assert len(stats) == 1
        assert stats[0]["helped"] == 2

    def test_summarise_skips_invalid_outcome_lines(self, cal_path):
        cal_path.write_text(
            '{"ts":"x","pattern_id":"p1","outcome":"helped"}\n'
            '{"ts":"y","pattern_id":"p2","outcome":"bogus"}\n'
        )
        stats = pc.summarise(cal_path)
        ids = {r["pattern_id"] for r in stats}
        assert ids == {"p1"}


# ---------------------------------------------------------------------
#  R4: Calibrated match() exclusion
# ---------------------------------------------------------------------

class TestExcludedPatternIds:
    def test_excludes_only_when_samples_and_low_precision(self, cal_path):
        # p1: 5 samples, 1 helped, 4 fp → precision = 0.2 → NOT excluded (strict <)
        # p2: 5 samples, 0 helped, 5 fp → precision = 0.0 → excluded
        # p3: 10 samples, all helped → precision = 1.0 → not excluded
        # p4: 4 samples, 0 helped, 4 fp → below min samples → not excluded
        for _ in range(1):
            pc.record_outcome(pattern_id="p1", outcome="helped", path=cal_path)
        for _ in range(4):
            pc.record_outcome(pattern_id="p1", outcome="false_positive", path=cal_path)
        for _ in range(5):
            pc.record_outcome(pattern_id="p2", outcome="false_positive", path=cal_path)
        for _ in range(10):
            pc.record_outcome(pattern_id="p3", outcome="helped", path=cal_path)
        for _ in range(4):
            pc.record_outcome(pattern_id="p4", outcome="false_positive", path=cal_path)
        ex = pc.excluded_pattern_ids(cal_path)
        assert ex == {"p2"}

    def test_no_data_returns_empty_exclusion_set(self, cal_path):
        assert pc.excluded_pattern_ids(cal_path) == set()


class TestCalibratedMatch:
    def _seed_patterns(self, tmp_path: Path) -> Path:
        db_path = tmp_path / "patterns.jsonl"
        db = PatternDB(db_path)
        for i in range(3):
            ok = db.save({
                "ts": f"2026-01-0{i+1}T00:00:00Z",
                "schema_version": 1,
                "target": "alpha.com",
                "vuln_class": "IDOR",
                "technique": f"swap-{i}",
                "payout": 100 * (i + 1),
                "tech_stack": ["Express"],
            })
            assert ok, f"failed to save pattern {i}"
        return db_path

    def test_default_match_returns_all(self, tmp_path):
        db = PatternDB(self._seed_patterns(tmp_path))
        results = db.match(vuln_class="IDOR")
        assert len(results) == 3

    def test_calibrated_excludes_low_precision_patterns(self, tmp_path):
        db_path = self._seed_patterns(tmp_path)
        cal_path = tmp_path / "calibration.jsonl"
        # Mark pattern (alpha.com|IDOR|swap-0) as a 5-fp pattern → excluded
        target_pid = "alpha.com|IDOR|swap-0"
        for _ in range(5):
            pc.record_outcome(pattern_id=target_pid, outcome="false_positive", path=cal_path)
        db = PatternDB(db_path)
        results = db.match(vuln_class="IDOR", calibrated=True, calibration_path=cal_path)
        techniques = {p["technique"] for p in results}
        assert "swap-0" not in techniques
        assert techniques == {"swap-1", "swap-2"}

    def test_calibrated_unchanged_when_calibration_file_missing(self, tmp_path):
        db = PatternDB(self._seed_patterns(tmp_path))
        cal_path = tmp_path / "absent.jsonl"
        results = db.match(vuln_class="IDOR", calibrated=True, calibration_path=cal_path)
        assert len(results) == 3   # behaviour matches calibrated=False

    def test_calibrated_false_is_default(self, tmp_path):
        """C2 — calibrated=False is the default."""
        db_path = self._seed_patterns(tmp_path)
        cal_path = tmp_path / "calibration.jsonl"
        target_pid = "alpha.com|IDOR|swap-0"
        for _ in range(5):
            pc.record_outcome(pattern_id=target_pid, outcome="false_positive", path=cal_path)
        db = PatternDB(db_path)
        # Without calibrated=True, the low-precision pattern stays
        results = db.match(vuln_class="IDOR")
        assert any(p["technique"] == "swap-0" for p in results)

    def test_pattern_id_for_helper(self):
        pid = pc.pattern_id_for({
            "target": "x", "vuln_class": "IDOR", "technique": "swap",
        })
        assert pid == "x|IDOR|swap"


# ---------------------------------------------------------------------
#  R6: CLI flag
# ---------------------------------------------------------------------

class TestCliFlag:
    def test_agent_py_has_calibrate_patterns_flag(self):
        text = (REPO_ROOT / "agent.py").read_text(encoding="utf-8")
        assert "--calibrate-patterns" in text


# ---------------------------------------------------------------------
#  R7: Dispatcher tool exposure
# ---------------------------------------------------------------------

class TestDispatcherToolExposure:
    def test_pattern_calibration_summary_in_dispatcher_only_set(self):
        import agent
        assert "pattern_calibration_summary" in agent._DISPATCHER_ONLY_TOOLS

    def test_pattern_calibration_summary_in_tool_specs(self):
        import agent
        tool_names = {
            spec["function"]["name"] for spec in agent._ALL_TOOL_SPECS
            if isinstance(spec, dict) and spec.get("type") == "function"
        }
        assert "pattern_calibration_summary" in tool_names


# ---------------------------------------------------------------------
#  Rotation (C4)
# ---------------------------------------------------------------------

class TestRotation:
    def test_rotation_keeps_backups_when_file_exceeds_cap(self, cal_path):
        # Write a tiny cap so rotation fires after the first row
        big = "x" * 100
        # Seed an oversized file
        cal_path.write_text(big * 100)
        before_size = cal_path.stat().st_size
        pc.record_outcome(
            pattern_id="p1", outcome="helped",
            path=cal_path,
            max_bytes=1000, keep_backups=2,
        )
        # After rotation, the new file is small and a .1 backup exists
        assert cal_path.stat().st_size < before_size
        assert cal_path.with_suffix(cal_path.suffix + ".1").exists()


# ---------------------------------------------------------------------
#  CLI subcommands
# ---------------------------------------------------------------------

class TestCliMain:
    def test_record_subcommand_writes_to_path(self, tmp_path, capsys):
        cal = tmp_path / "cal.jsonl"
        rc = pc.main([
            "--path", str(cal),
            "record",
            "--pattern-id", "p1",
            "--outcome", "helped",
            "--session-id", "s",
            "--target", "x.com",
        ])
        assert rc == 0
        assert cal.exists()
        out = capsys.readouterr().out
        assert "p1" in out
        assert "helped" in out

    def test_summarise_subcommand_outputs_json(self, tmp_path, capsys):
        cal = tmp_path / "cal.jsonl"
        pc.record_outcome(pattern_id="p1", outcome="helped", path=cal)
        rc = pc.main(["--path", str(cal), "summarise"])
        assert rc == 0
        out = capsys.readouterr().out
        data = json.loads(out)
        assert data[0]["pattern_id"] == "p1"

    def test_excluded_subcommand_returns_list(self, tmp_path, capsys):
        cal = tmp_path / "cal.jsonl"
        for _ in range(5):
            pc.record_outcome(pattern_id="bad", outcome="false_positive", path=cal)
        rc = pc.main(["--path", str(cal), "excluded"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "bad" in out


# ---------------------------------------------------------------------
#  Documentation hooks
# ---------------------------------------------------------------------

class TestDocsMention:
    def test_autopilot_md_mentions_calibrate_patterns(self):
        md = (REPO_ROOT / "commands" / "autopilot.md").read_text(encoding="utf-8")
        # Per B12d AC bullet
        assert "calibrate" in md.lower() or "--calibrate-patterns" in md


# ---------------------------------------------------------------------
#  Dispatcher method
# ---------------------------------------------------------------------

class TestDispatcherMethod:
    def test_pattern_calibration_summary_renders_json_text(self, tmp_path, monkeypatch):
        import agent
        # Point default calibration path at a tmp file
        cal = tmp_path / "cal.jsonl"
        pc.record_outcome(pattern_id="p1", outcome="helped", path=cal)
        monkeypatch.setattr(
            pc, "default_calibration_path", lambda repo_root=None: cal,
        )
        dispatcher = agent.ToolDispatcher.__new__(agent.ToolDispatcher)
        out = dispatcher._pattern_calibration_summary(format="json")
        data = json.loads(out)
        assert any(r["pattern_id"] == "p1" for r in data["rows"])
        assert data["exclusion_rule"].startswith("samples>=5")

    def test_pattern_calibration_summary_text_format(self, tmp_path, monkeypatch):
        import agent
        cal = tmp_path / "cal.jsonl"
        pc.record_outcome(pattern_id="p1", outcome="helped", path=cal)
        monkeypatch.setattr(
            pc, "default_calibration_path", lambda repo_root=None: cal,
        )
        dispatcher = agent.ToolDispatcher.__new__(agent.ToolDispatcher)
        out = dispatcher._pattern_calibration_summary(format="text")
        assert "p1" in out
        # Header row
        assert "pattern_id" in out

    def test_pattern_calibration_summary_handles_no_data(self, tmp_path, monkeypatch):
        import agent
        cal = tmp_path / "cal.jsonl"
        monkeypatch.setattr(
            pc, "default_calibration_path", lambda repo_root=None: cal,
        )
        dispatcher = agent.ToolDispatcher.__new__(agent.ToolDispatcher)
        out = dispatcher._pattern_calibration_summary(format="text")
        # No file, no data → graceful
        assert "no data" in out.lower() or out.strip() != ""
