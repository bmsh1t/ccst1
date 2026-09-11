"""Stage-one UX: minimal record, bootstrap summary, structured leads."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.evidence_ledger import _load_probe_entry, record_entry
from tools.autopilot_state import _plain_summary
from tools.resume import _scene_summary


def _seed_ledger(repo: Path, target: str) -> str:
    # record_entry 的 event_id 由调用方（probe.py）注入——测试模拟 probe 形态
    record_entry(
        repo,
        target=target,
        endpoint="/api/thing/9",
        method="POST",
        vuln_class="IDOR",
        actor="peer",
        variant="id_swap",
        result="lead",
        evidence_ref="evidence/t.example/probe/1.json",
        event_id="probe-20260911T000000Z-test01",
    )
    return "probe-20260911T000000Z-test01"


def test_from_probe_copies_mechanical_fields(tmp_path):
    event_id = _seed_ledger(tmp_path, "t.example")
    entry = _load_probe_entry(tmp_path, "t.example", event_id)
    assert entry["endpoint"] == "/api/thing/9"
    assert entry["method"] == "POST"
    assert entry["actor"] == "peer"
    assert entry["variant"] == "id_swap"


def test_from_probe_unknown_event_id_rejected(tmp_path):
    with pytest.raises(ValueError, match="not found"):
        _load_probe_entry(tmp_path, "t.example", "nope-404")


def test_plain_summary_derives_from_projection_fields():
    state = {
        "priority_frontier": [{"action": "probe /rest/basket/1"}],
        "hard_gate": {"action": "resume_action_queue"},
        "runtime_derived": {"queue": {"active": 3}},
    }
    summary = _plain_summary(state)
    assert "probe /rest/basket/1" in summary
    assert "resume_action_queue" in summary
    assert "3 active" in summary
    # 一致性：frontier 首项与 hard_gate 都出现在摘要里
    assert state["priority_frontier"][0]["action"] in summary
    assert state["hard_gate"]["action"] in summary


def test_plain_summary_empty_state_degrades_gracefully():
    summary = _plain_summary({})
    assert "Next:" in summary and "Gate:" in summary


def test_scene_summary_uses_structured_leads():
    summary = {
        "target_leads": [
            {
                "text": "basket BOLA",
                "structured": {
                    "hypothesis": "basket BOLA anonymous read",
                    "evidence_ref": "evidence/t.example/probe/1.json",
                    "next": "three-way diff",
                    "stop_condition": "401/403",
                },
            }
        ],
        "checkpoint": {"decision": "validate"},
    }
    scene = _scene_summary(summary)
    assert "basket BOLA anonymous read" in scene
    assert "three-way diff" in scene
    assert "validate" in scene


def test_scene_summary_falls_back_to_plain_text_lead():
    summary = {
        "target_leads": [{"text": "plain old lead"}],
        "checkpoint": {},
    }
    scene = _scene_summary(summary)
    assert "plain old lead" in scene


def test_scene_summary_empty_returns_empty():
    assert _scene_summary({"target_leads": [], "checkpoint": {}}) == ""


def test_target_memory_structured_lead_roundtrip(tmp_path):
    """CLI 层 structured lead 落盘形态（dict 带 structured 键）。"""
    from tools.target_memory import append_entry, load_target_memory
    import argparse

    args = argparse.Namespace(
        text=[],
        target="t.example",
        structured_json=json.dumps(
            {
                "hypothesis": "h",
                "evidence_ref": "evidence/t.example/probe/1.json",
                "next": "n",
                "stop_condition": "s",
            }
        ),
        kind=None,
        evidence_ref=[],
    )
    append_entry(args, "active_leads", "LEAD")
    memory = load_target_memory("t.example")
    last = memory["active_leads"][-1]
    assert last["structured"]["hypothesis"] == "h"
    assert last["structured"]["stop_condition"] == "s"


def test_target_memory_structured_lead_requires_all_four_fields(tmp_path):
    from tools.target_memory import append_entry
    import argparse

    args = argparse.Namespace(
        text=[],
        target="t.example",
        structured_json=json.dumps({"hypothesis": "h"}),  # 缺 3 个字段
        kind=None,
        evidence_ref=[],
    )
    with pytest.raises(SystemExit, match="requires all of"):
        append_entry(args, "active_leads", "LEAD")
