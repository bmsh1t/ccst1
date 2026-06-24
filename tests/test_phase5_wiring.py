"""tests/test_phase5_wiring.py — P5-W1 wiring contract tests.

Verifies that the 5 Phase-4 primitives are now wired into the agent.py
autopilot execution path, gated by their respective CLI flags. Each
primitive's logic is already tested in its own test file; this suite
covers only the wire-up contract:

  R1 sibling parallel       — agent.py reads args.parallel
  R2 hypothesis fleet       — agent.py reads args.parallel_hypotheses
  R3 vision write           — run_vision_probe dispatcher branch + gating
  R4 self-review            — pre-finish hook reads args.self_review
  R5 calibration write      — validate.py records outcome per /validate
"""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))


# ---------------------------------------------------------------------
#  R5 — Calibration write
# ---------------------------------------------------------------------

class TestR5CalibrationWiring:
    def test_validate_module_exposes_record_validation_calibration(self):
        from tools import validate
        assert hasattr(validate, "record_validation_calibration")
        assert callable(validate.record_validation_calibration)

    def test_outcome_mapping_confirmed_maps_to_helped(self):
        from tools.validate import _map_validate_result_to_calibration_outcome as mapfn
        assert mapfn("confirmed") == "helped"

    def test_outcome_mapping_rejected_maps_to_false_positive(self):
        from tools.validate import _map_validate_result_to_calibration_outcome as mapfn
        assert mapfn("rejected") == "false_positive"

    def test_outcome_mapping_partial_maps_to_no_signal(self):
        from tools.validate import _map_validate_result_to_calibration_outcome as mapfn
        assert mapfn("partial") == "no_signal"

    def test_outcome_mapping_informational_maps_to_no_signal(self):
        from tools.validate import _map_validate_result_to_calibration_outcome as mapfn
        assert mapfn("informational") == "no_signal"

    def test_outcome_mapping_unknown_returns_none(self):
        from tools.validate import _map_validate_result_to_calibration_outcome as mapfn
        assert mapfn("") is None
        assert mapfn("???") is None
        assert mapfn(None) is None  # type: ignore[arg-type]

    def test_record_validation_calibration_writes_helped(self, tmp_path):
        from tools.validate import record_validation_calibration
        cal_path = tmp_path / "cal.jsonl"
        summary = {
            "target": "alpha.com",
            "vuln_class": "idor",
            "result": "confirmed",
            "technique": "swap-numeric",
        }
        record = record_validation_calibration(summary, path=cal_path)
        assert record is not None
        assert record["outcome"] == "helped"
        assert record["pattern_id"] == "alpha.com|idor|swap-numeric"
        # File contains exactly one JSON line
        lines = cal_path.read_text().strip().splitlines()
        assert len(lines) == 1
        parsed = json.loads(lines[0])
        assert parsed["outcome"] == "helped"

    def test_record_validation_calibration_writes_false_positive(self, tmp_path):
        from tools.validate import record_validation_calibration
        cal_path = tmp_path / "cal.jsonl"
        summary = {
            "target": "beta.com",
            "vuln_class": "xss",
            "result": "rejected",
        }
        record = record_validation_calibration(summary, path=cal_path)
        assert record is not None
        assert record["outcome"] == "false_positive"
        # technique missing → empty in pattern_id
        assert record["pattern_id"] == "beta.com|xss|"

    def test_record_validation_calibration_skips_missing_target(self, tmp_path):
        from tools.validate import record_validation_calibration
        cal_path = tmp_path / "cal.jsonl"
        summary = {"target": "", "vuln_class": "idor", "result": "confirmed"}
        record = record_validation_calibration(summary, path=cal_path)
        assert record is None
        assert not cal_path.exists()

    def test_record_validation_calibration_skips_missing_vuln_class(self, tmp_path):
        from tools.validate import record_validation_calibration
        cal_path = tmp_path / "cal.jsonl"
        summary = {"target": "alpha.com", "vuln_class": "", "result": "confirmed"}
        record = record_validation_calibration(summary, path=cal_path)
        assert record is None
        assert not cal_path.exists()

    def test_record_validation_calibration_skips_unknown_result(self, tmp_path):
        from tools.validate import record_validation_calibration
        cal_path = tmp_path / "cal.jsonl"
        summary = {"target": "alpha.com", "vuln_class": "idor", "result": "wat"}
        record = record_validation_calibration(summary, path=cal_path)
        assert record is None
        assert not cal_path.exists()

    def test_update_runtime_state_after_validate_calls_calibration(self, tmp_path, monkeypatch):
        """The post-validate hook must call record_validation_calibration."""
        from tools import validate as vmod
        calls: list[dict] = []

        def fake_record(summary, *, session_id="", path=None):
            calls.append({"summary": summary, "session_id": session_id})
            return {"ok": True}

        monkeypatch.setattr(vmod, "record_validation_calibration", fake_record)
        # Defang the runtime-state writer
        try:
            import tools.runtime_state as rs
            monkeypatch.setattr(rs, "update_runtime_state", lambda *a, **k: None, raising=False)
            monkeypatch.setattr(rs, "inspect_recon_artifacts", lambda *a, **k: {}, raising=False)
        except Exception:
            pass

        summary = {
            "target": "gamma.com",
            "vuln_class": "ssrf",
            "result": "confirmed",
            "session_id": "sess-123",
        }
        vmod.update_runtime_state_after_validate(summary)
        assert len(calls) == 1
        assert calls[0]["summary"]["target"] == "gamma.com"
        assert calls[0]["session_id"] == "sess-123"


# ---------------------------------------------------------------------
#  Placeholder collections — filled in as R1/R2/R3/R4 land
# ---------------------------------------------------------------------

class TestR1SiblingWiring:
    """Wire-up for spawn_sibling_worker."""

    def _make_dispatcher(self, *, parallel_enabled, max_parallel=3,
                         autopilot_mode="normal"):
        from agent import HuntMemory, ToolDispatcher
        memory = HuntMemory(session_file="/tmp/__pytest_session.json")
        memory.session_id = "test-session"  # type: ignore[attr-defined]
        return ToolDispatcher(
            "x.com", memory,
            parallel_enabled=parallel_enabled,
            max_parallel=max_parallel,
            autopilot_mode=autopilot_mode,
        )

    def test_dispatcher_init_default_parallel_off(self):
        from agent import HuntMemory, ToolDispatcher
        memory = HuntMemory(session_file="/tmp/__pytest_session.json")
        d = ToolDispatcher("x.com", memory)
        assert d.parallel_enabled is False
        assert d.max_parallel >= 1

    def test_dispatcher_init_paranoid_forces_max_parallel_1(self):
        d = self._make_dispatcher(parallel_enabled=True, max_parallel=5,
                                  autopilot_mode="paranoid")
        assert d.max_parallel == 1

    def test_dispatcher_init_normal_caps_max_parallel_3(self):
        d = self._make_dispatcher(parallel_enabled=True, max_parallel=99,
                                  autopilot_mode="normal")
        assert d.max_parallel == 3

    def test_run_sibling_probe_rejects_empty_seeds(self):
        d = self._make_dispatcher(parallel_enabled=True)
        out = d.dispatch("run_sibling_probe", {"seed_findings": []})
        head = out.split("\n\n[", 1)[0]
        assert "seed_findings is required" in head

    def test_run_sibling_probe_rejects_seeds_missing_endpoint(self):
        d = self._make_dispatcher(parallel_enabled=True)
        out = d.dispatch("run_sibling_probe", {"seed_findings": [{"id": "x"}]})
        head = out.split("\n\n[", 1)[0]
        assert "no usable seed_findings" in head

    def test_parallel_branch_calls_spawn_for_each_seed(self, monkeypatch):
        d = self._make_dispatcher(parallel_enabled=True, max_parallel=3,
                                  autopilot_mode="normal")
        spawn_calls = []

        class FakeHandle:
            def __init__(self, wid): self.worker_id = wid

        def fake_spawn(seed_finding, worker_id, target, *, timeout_secs=300,
                       parent_session=None, **kw):
            spawn_calls.append({"worker_id": worker_id, "seed": seed_finding,
                                "target": target})
            return FakeHandle(worker_id)

        def fake_wait(handles, *, timeout_secs=300):
            return [type("R", (), {"worker_id": h.worker_id,
                                    "findings": [{"id": h.worker_id,
                                                  "endpoint": "/x",
                                                  "vuln_class": "idor",
                                                  "severity": "medium"}]})()
                    for h in handles]

        import tools.parallel_workers as pw
        monkeypatch.setattr(pw, "spawn_sibling_worker", fake_spawn)
        monkeypatch.setattr(pw, "wait_for_workers", fake_wait)

        seeds = [{"id": "a", "endpoint": "/a"}, {"id": "b", "endpoint": "/b"},
                 {"id": "c", "endpoint": "/c"}]
        out = d.dispatch("run_sibling_probe", {"seed_findings": seeds})
        head = out.split("\n\n[", 1)[0]
        payload = json.loads(head)
        assert payload["mode"] == "parallel"
        assert payload["workers_spawned"] == 3
        assert len(spawn_calls) == 3

    def test_sequential_branch_when_parallel_off(self, monkeypatch):
        d = self._make_dispatcher(parallel_enabled=False, max_parallel=3)
        spawn_calls = []

        class FakeHandle:
            def __init__(self, wid): self.worker_id = wid

        def fake_spawn(seed_finding, worker_id, target, **kw):
            spawn_calls.append({"worker_id": worker_id})
            return FakeHandle(worker_id)

        def fake_wait(handles, *, timeout_secs=300):
            return [type("R", (), {"worker_id": h.worker_id,
                                    "findings": []})() for h in handles]

        import tools.parallel_workers as pw
        monkeypatch.setattr(pw, "spawn_sibling_worker", fake_spawn)
        monkeypatch.setattr(pw, "wait_for_workers", fake_wait)

        seeds = [{"id": "a", "endpoint": "/a"}, {"id": "b", "endpoint": "/b"}]
        out = d.dispatch("run_sibling_probe", {"seed_findings": seeds})
        head = out.split("\n\n[", 1)[0]
        payload = json.loads(head)
        assert payload["mode"] == "sequential"
        # Sequential calls wait_for_workers per seed
        assert payload["workers_spawned"] == 2
        assert len(spawn_calls) == 2

    def test_parallel_branch_respects_max_parallel_cap(self, monkeypatch):
        d = self._make_dispatcher(parallel_enabled=True, max_parallel=2,
                                  autopilot_mode="normal")
        spawn_calls = []

        class FakeHandle:
            def __init__(self, wid): self.worker_id = wid

        def fake_spawn(seed_finding, worker_id, target, **kw):
            spawn_calls.append(worker_id)
            return FakeHandle(worker_id)

        def fake_wait(handles, *, timeout_secs=300):
            return [type("R", (), {"worker_id": h.worker_id,
                                    "findings": []})() for h in handles]

        import tools.parallel_workers as pw
        monkeypatch.setattr(pw, "spawn_sibling_worker", fake_spawn)
        monkeypatch.setattr(pw, "wait_for_workers", fake_wait)

        seeds = [{"endpoint": f"/p{i}"} for i in range(5)]
        out = d.dispatch("run_sibling_probe", {"seed_findings": seeds})
        head = out.split("\n\n[", 1)[0]
        payload = json.loads(head)
        # Capped at 2 even though 5 seeds provided
        assert payload["workers_spawned"] == 2
        assert len(spawn_calls) == 2


class TestR2HypothesisWiring:
    """Wire-up for run_fanout."""

    def _make_dispatcher(self, *, parallel_hypotheses, max_parallel=3,
                         autopilot_mode="normal"):
        from agent import HuntMemory, ToolDispatcher
        memory = HuntMemory(session_file="/tmp/__pytest_session.json")
        memory.session_id = "test-session"  # type: ignore[attr-defined]
        return ToolDispatcher(
            "x.com", memory,
            parallel_hypotheses=parallel_hypotheses,
            max_parallel=max_parallel,
            autopilot_mode=autopilot_mode,
        )

    def test_dispatcher_init_default_parallel_hypotheses_off(self):
        from agent import HuntMemory, ToolDispatcher
        memory = HuntMemory(session_file="/tmp/__pytest_session.json")
        d = ToolDispatcher("x.com", memory)
        assert d.parallel_hypotheses is False

    def test_run_hypothesis_fleet_rejects_empty_list(self):
        d = self._make_dispatcher(parallel_hypotheses=True)
        out = d.dispatch("run_hypothesis_fleet", {"hypotheses": []})
        head = out.split("\n\n[", 1)[0]
        assert "hypotheses is required" in head

    def test_parallel_mode_calls_run_fanout_with_max_parallel_n(self, monkeypatch):
        d = self._make_dispatcher(parallel_hypotheses=True, max_parallel=3,
                                  autopilot_mode="normal")
        captured = {}

        def fake_fanout(*, hypotheses, target, max_parallel, parent_session=None,
                        timeout_secs=300, **kw):
            captured["max_parallel"] = max_parallel
            captured["target"] = target
            captured["hypothesis_count"] = len(hypotheses)
            return {
                "workers_total": len(hypotheses),
                "winner": {"id": "h1", "outcome": "validated_finding"},
                "demoted_count": len(hypotheses) - 1,
            }

        import tools.hypothesis_fleet as hf
        monkeypatch.setattr(hf, "run_fanout", fake_fanout)

        hyps = [{"id": "h1"}, {"id": "h2"}, {"id": "h3"}]
        out = d.dispatch("run_hypothesis_fleet", {"hypotheses": hyps})
        head = out.split("\n\n[", 1)[0]
        payload = json.loads(head)
        assert payload["mode"] == "parallel"
        assert payload["max_parallel"] == 3
        assert payload["workers_total"] == 3
        assert payload["demoted_count"] == 2
        assert captured["max_parallel"] == 3

    def test_sequential_mode_forces_max_parallel_1(self, monkeypatch):
        d = self._make_dispatcher(parallel_hypotheses=False, max_parallel=5,
                                  autopilot_mode="normal")
        captured = {}

        def fake_fanout(*, hypotheses, target, max_parallel, parent_session=None,
                        timeout_secs=300, **kw):
            captured["max_parallel"] = max_parallel
            return {
                "workers_total": len(hypotheses),
                "winner": None,
                "demoted_count": 0,
            }

        import tools.hypothesis_fleet as hf
        monkeypatch.setattr(hf, "run_fanout", fake_fanout)

        out = d.dispatch("run_hypothesis_fleet", {"hypotheses": [{"id": "h1"}]})
        head = out.split("\n\n[", 1)[0]
        payload = json.loads(head)
        assert payload["mode"] == "sequential"
        assert payload["max_parallel"] == 1
        assert captured["max_parallel"] == 1

    def test_winner_propagated_in_output(self, monkeypatch):
        d = self._make_dispatcher(parallel_hypotheses=True)

        def fake_fanout(**kw):
            return {"workers_total": 2,
                    "winner": {"id": "win", "outcome": "validated_finding"},
                    "demoted_count": 1}

        import tools.hypothesis_fleet as hf
        monkeypatch.setattr(hf, "run_fanout", fake_fanout)
        out = d.dispatch("run_hypothesis_fleet", {"hypotheses": [{"id": "h1"}]})
        head = out.split("\n\n[", 1)[0]
        payload = json.loads(head)
        assert payload["winner"]["outcome"] == "validated_finding"


class TestR3VisionWiring:
    """Wire-up for run_vision_probe dispatcher tool."""

    def _make_dispatcher(self, *, vision_enabled, model_id, max_screenshots=5):
        from agent import HuntMemory, ToolDispatcher
        memory = HuntMemory(session_file="/tmp/__pytest_session.json")
        return ToolDispatcher(
            "x.com", memory,
            vision_enabled=vision_enabled,
            max_screenshots=max_screenshots,
            model_id=model_id,
        )

    def test_dispatcher_init_accepts_vision_kwargs(self):
        d = self._make_dispatcher(vision_enabled=True, model_id="claude-opus-4-7")
        assert d.vision_enabled is True
        assert d.max_screenshots == 5
        assert d.model_id == "claude-opus-4-7"

    def test_dispatcher_init_default_vision_off(self):
        from agent import HuntMemory, ToolDispatcher
        memory = HuntMemory(session_file="/tmp/__pytest_session.json")
        d = ToolDispatcher("x.com", memory)
        assert d.vision_enabled is False

    def test_run_vision_probe_rejects_when_flag_off(self, monkeypatch):
        d = self._make_dispatcher(vision_enabled=False, model_id="claude-opus-4-7")
        out = d.dispatch("run_vision_probe", {"url": "https://x/"})
        assert "disabled" in out
        assert "--vision" in out

    def test_run_vision_probe_rejects_when_model_text_only(self):
        d = self._make_dispatcher(vision_enabled=True, model_id="qwen2.5:32b")
        out = d.dispatch("run_vision_probe", {"url": "https://x/"})
        assert "disabled" in out

    def test_run_vision_probe_rejects_when_url_missing(self):
        d = self._make_dispatcher(vision_enabled=True, model_id="claude-opus-4-7")
        out = d.dispatch("run_vision_probe", {})
        assert "url is required" in out

    def test_run_vision_probe_calls_capture(self, monkeypatch, tmp_path):
        d = self._make_dispatcher(vision_enabled=True, model_id="claude-opus-4-7",
                                  max_screenshots=7)
        calls: list[dict] = []

        def fake_capture(target, url, *, label="vision", max_screenshots=5, **kw):
            calls.append({
                "target": target,
                "url": url,
                "label": label,
                "max_screenshots": max_screenshots,
            })
            return {
                "screenshot_seq": 4,
                "screenshot_path": str(tmp_path / "screenshot_4.png"),
                "dom_path": str(tmp_path / "dom_4.html"),
                "capped": False,
            }

        import tools.vision_browser as vb
        monkeypatch.setattr(vb, "capture_with_screenshot_sequence", fake_capture)
        out = d.dispatch("run_vision_probe", {"url": "https://x/login", "label": "login"})
        assert len(calls) == 1
        assert calls[0]["url"] == "https://x/login"
        assert calls[0]["label"] == "login"
        assert calls[0]["max_screenshots"] == 7
        # Dispatcher appends "[<name> completed in ...]"; parse the JSON head.
        head = out.split("\n\n[", 1)[0]
        payload = json.loads(head)
        assert payload["screenshot_seq"] == 4
        assert payload["capped"] is False

    def test_run_vision_probe_propagates_capped(self, monkeypatch):
        d = self._make_dispatcher(vision_enabled=True, model_id="claude-opus-4-7")

        import tools.vision_browser as vb
        monkeypatch.setattr(vb, "capture_with_screenshot_sequence",
                            lambda *a, **k: {"screenshot_seq": 11,
                                              "screenshot_path": "",
                                              "dom_path": "",
                                              "capped": True})
        out = d.dispatch("run_vision_probe", {"url": "https://x/"})
        head = out.split("\n\n[", 1)[0]
        payload = json.loads(head)
        assert payload["capped"] is True

    def test_run_vision_probe_in_tool_specs_after_read_browser_screenshot(self):
        # Tool spec list contains both
        import agent
        names = [s["function"]["name"] for s in agent._ALL_TOOL_SPECS]
        assert "read_browser_screenshot" in names
        assert "run_vision_probe" in names
        # run_vision_probe is in the dispatcher-only set
        assert "run_vision_probe" in agent._DISPATCHER_ONLY_TOOLS


class TestR4SelfReviewWiring:
    """Wire-up for pre-finish self-review hook."""

    def _make_dispatcher(self, *, self_review_enabled):
        from agent import HuntMemory, ToolDispatcher
        memory = HuntMemory(session_file="/tmp/__pytest_session.json")
        memory.session_id = "test-session"  # type: ignore[attr-defined]
        return ToolDispatcher(
            "x.com", memory,
            self_review_enabled=self_review_enabled,
        )

    def test_dispatcher_init_default_self_review_off(self):
        from agent import HuntMemory, ToolDispatcher
        memory = HuntMemory(session_file="/tmp/__pytest_session.json")
        d = ToolDispatcher("x.com", memory)
        assert d.self_review_enabled is False

    def test_run_self_review_skipped_when_flag_off(self):
        d = self._make_dispatcher(self_review_enabled=False)
        out = d.dispatch("run_self_review", {"candidates": [{"id": "f1"}]})
        head = out.split("\n\n[", 1)[0]
        payload = json.loads(head)
        assert payload["skipped"] is True
        assert "--self-review" in payload["reason"]

    def test_run_self_review_rejects_empty_candidates(self):
        d = self._make_dispatcher(self_review_enabled=True)
        out = d.dispatch("run_self_review", {"candidates": []})
        head = out.split("\n\n[", 1)[0]
        assert "candidates is required" in head

    def test_run_self_review_rejects_candidates_missing_id(self):
        d = self._make_dispatcher(self_review_enabled=True)
        out = d.dispatch("run_self_review", {"candidates": [{"endpoint": "/x"}]})
        head = out.split("\n\n[", 1)[0]
        assert "no usable candidates" in head

    def test_keep_decision_when_verdict_no_flaw(self, monkeypatch):
        d = self._make_dispatcher(self_review_enabled=True)

        class FakeHandle:
            def __init__(self, wid): self.worker_id = wid

        def fake_spawn(candidate_finding, worker_id, target, **kw):
            return FakeHandle(worker_id)

        import tools.parallel_workers as pw
        import tools.self_review as sr
        monkeypatch.setattr(pw, "spawn_red_team_worker", fake_spawn)
        monkeypatch.setattr(pw, "wait_for_workers", lambda h, **k: [])
        monkeypatch.setattr(sr, "parse_verdict_file", lambda p: "no_flaw_found")

        out = d.dispatch("run_self_review", {"candidates": [{"id": "f1"}]})
        head = out.split("\n\n[", 1)[0]
        payload = json.loads(head)
        assert payload["keep_count"] == 1
        assert payload["demote_count"] == 0
        assert payload["kill_count"] == 0

    def test_demote_decision_when_verdict_likely_flaw(self, monkeypatch):
        d = self._make_dispatcher(self_review_enabled=True)

        class FakeHandle:
            def __init__(self, wid): self.worker_id = wid

        import tools.parallel_workers as pw
        import tools.self_review as sr
        monkeypatch.setattr(pw, "spawn_red_team_worker",
                            lambda **kw: FakeHandle(kw["worker_id"]))
        monkeypatch.setattr(pw, "wait_for_workers", lambda h, **k: [])
        monkeypatch.setattr(sr, "parse_verdict_file", lambda p: "likely_flaw")

        out = d.dispatch("run_self_review", {"candidates": [{"id": "f1"}]})
        head = out.split("\n\n[", 1)[0]
        payload = json.loads(head)
        assert payload["demote_count"] == 1
        assert payload["decisions"][0]["decision"] == "demote"

    def test_kill_decision_records_false_positive(self, monkeypatch):
        d = self._make_dispatcher(self_review_enabled=True)
        recorded = []

        class FakeHandle:
            def __init__(self, wid): self.worker_id = wid

        import tools.parallel_workers as pw
        import tools.self_review as sr
        monkeypatch.setattr(pw, "spawn_red_team_worker",
                            lambda **kw: FakeHandle(kw["worker_id"]))
        monkeypatch.setattr(pw, "wait_for_workers", lambda h, **k: [])
        monkeypatch.setattr(sr, "parse_verdict_file", lambda p: "definitive_disqualifier")
        monkeypatch.setattr(sr, "record_disqualifier_as_false_positive",
                            lambda *, finding, target, **kw: recorded.append({
                                "finding": finding, "target": target}))

        out = d.dispatch("run_self_review", {"candidates": [{"id": "f1",
                                                              "endpoint": "/x"}]})
        head = out.split("\n\n[", 1)[0]
        payload = json.loads(head)
        assert payload["kill_count"] == 1
        assert len(recorded) == 1
        assert recorded[0]["finding"]["id"] == "f1"

    def test_missing_verdict_treated_as_keep(self, monkeypatch):
        d = self._make_dispatcher(self_review_enabled=True)

        class FakeHandle:
            def __init__(self, wid): self.worker_id = wid

        import tools.parallel_workers as pw
        import tools.self_review as sr
        monkeypatch.setattr(pw, "spawn_red_team_worker",
                            lambda **kw: FakeHandle(kw["worker_id"]))
        monkeypatch.setattr(pw, "wait_for_workers", lambda h, **k: [])
        monkeypatch.setattr(sr, "parse_verdict_file", lambda p: None)

        out = d.dispatch("run_self_review", {"candidates": [{"id": "f1"}]})
        head = out.split("\n\n[", 1)[0]
        payload = json.loads(head)
        # Missing verdict → keep (per decision_for default)
        assert payload["keep_count"] == 1
        assert payload["decisions"][0]["verdict"] == "missing"
