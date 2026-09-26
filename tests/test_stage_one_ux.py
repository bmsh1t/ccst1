"""Stage-one UX: bootstrap summary and Store-backed conditional leads."""

from __future__ import annotations

import json

import pytest

from tools.autopilot_state import _plain_summary
from tools.resume import _scene_summary
from tools.target_store import StoreError, TargetStore, initialize_target_store


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


def test_target_memory_conditional_lead_roundtrip(tmp_path):
    from tools.target_memory import append_entry, load_target_memory
    import argparse

    initialize_target_store(tmp_path, "t.example")
    args = argparse.Namespace(
        repo_root=tmp_path, text=["h"], target="t.example",
        conditions="peer session", reopen_when="identity changes", next_intent="n",
        command_id="lead-roundtrip", json=True,
    )
    saved = append_entry(args, "active_leads", "LEAD")
    memory = load_target_memory("t.example", repo_root=tmp_path)
    last = memory["active_leads"][-1]
    assert last["entry_id"] == saved["receipt"]["entity_id"]
    assert last["text"] == "h"
    assert last["structured"] == {
        "conditions": "peer session", "reopen_when": "identity changes", "next_intent": "n",
    }
    assert last["evidence_refs"] == []
    assert not (tmp_path / "memory/goals/targets/t.example.json").exists()


@pytest.mark.parametrize("structured,error", [
    ({"hypothesis": "h"}, "requires all of"),
    ({"hypothesis": "h", "evidence_ref": "evidence/t.example/probe/1.json",
      "next": "n", "stop_condition": "s"}, "legacy --structured-json"),
])
def test_target_memory_rejects_legacy_structured_write(tmp_path, structured, error):
    from tools.target_memory import append_entry
    import argparse

    initialize_target_store(tmp_path, "t.example")
    store = TargetStore(tmp_path, "t.example")
    revision = store.binding()["revision"]
    args = argparse.Namespace(
        repo_root=tmp_path,
        text=[],
        target="t.example",
        structured_json=json.dumps(structured),
        kind=None,
        evidence_ref=[],
    )
    with pytest.raises((SystemExit, StoreError), match=error):
        append_entry(args, "active_leads", "LEAD")
    assert store.binding()["revision"] == revision
