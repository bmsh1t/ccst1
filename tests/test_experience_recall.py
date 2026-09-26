"""experience_recall: unified episodic recall view (memory-loop step 2.1).

Store 经验 + 已审核知识、目标隔离、查询与完整分页；旧文件不参与当前读取。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.experience_recall import build_recall_view, main
from tools.target_store import TargetStore, StoreError


def _seed(repo: Path, *, target: str = "t.example", other: str = "other.example", current: bool = True) -> None:
    if current:
        store = TargetStore(repo, target)
        store.initialize()
        raw = repo / ".private" / "validation" / target / "recall-response.txt"
        raw.parent.mkdir(parents=True, exist_ok=True)
        raw.write_text("HTTP/1.1 403 Forbidden\r\n\r\n")
        store.start_attempt(attempt_id="recall-check", source="native",
                            started_at="2026-09-24T00:00:00Z", actor="test")
        operation = store.record_execution(
            attempt_id="recall-check", outcome="complete", actor="test",
            observations=[{"endpoint": f"https://{target}/graphql", "method": "GET",
                           "family": "graphql", "observed_at": "2026-09-24T00:00:00Z",
                           "description": "Introspection denied", "state_changing": False,
                           "artifacts": {"response": raw.relative_to(repo).as_posix()}}],
        )
        for entry_id, kind, text in (
            ("lead-basket", "hypothesis", "basket BOLA anonymous read"),
            ("lead-sso", "hypothesis", "Evidence: Workflow lead: sso bypass. Next action: replay."),
            ("negative-graphql", "negative", "graphql introspection disabled; no schema leak"),
            ("next-work", "handoff", "validate AQ-0002"),
            ("primitive-graphql", "primitive", "Introspection requires the correct session"),
        ):
            store.remember(command_id=entry_id, kind=kind, statement=text,
                           conditions="anonymous session", reopen_when="session changes",
                           next_intent="compare authenticated response", actor="test",
                           evidence=[{"operation_id": operation["entity_id"], "step": 0}]
                           if kind in {"negative", "primitive"} else [])
        other_store = TargetStore(repo, other)
        other_store.initialize()
        other_store.remember(command_id="other-private", kind="hypothesis",
                             statement="other target private lead about BOLA basket",
                             conditions="private", reopen_when="", next_intent="",
                             evidence=[], actor="test")
    tkey = target.replace(":", "-")
    okey = other.replace(":", "-")
    goals = repo / "memory" / "goals" / "targets"
    goals.mkdir(parents=True, exist_ok=True)
    (goals / f"{tkey}.json").write_text(json.dumps({
        "schema_version": 1,
        "target": target,
        "active_leads": [
            {"ts": "2026-09-11T00:00:00Z", "text": "basket BOLA anonymous read",
             "structured": {"hypothesis": "basket BOLA", "evidence_ref": "evidence/x.json"}},
            {"ts": "2026-09-11T01:00:00Z",
             "text": "{'schema_version': 1, 'text': 'Evidence: Workflow lead: sso bypass. Next action: replay.'}"},
        ],
        "dead_ends": [
            {"ts": "2026-09-11T02:00:00Z", "text": "graphql introspection disabled; no schema leak",
             "entry_id": "tm-abc", "kind": "dead-end", "evidence_refs": ["evidence/de.json"]},
        ],
        "useful_patterns": [],
        "next_actions": [{"ts": "2026-09-11T03:00:00Z", "text": "validate AQ-0002"}],
        "facts": {},
    }), encoding="utf-8")
    # 另一个目标的私有情节——绝不能出现在 t.example 的视图里
    (goals / f"{okey}.json").write_text(json.dumps({
        "schema_version": 1,
        "target": other,
        "active_leads": [{"ts": "2026-09-11T00:00:00Z", "text": "other target private lead about BOLA basket"}],
        "dead_ends": [], "useful_patterns": [], "next_actions": [], "facts": {},
    }), encoding="utf-8")
    # PatternDB：当前目标 + 跨目标 + 三类 outcome
    hunt = repo / "hunt-memory"
    hunt.mkdir(parents=True, exist_ok=True)
    (hunt / "patterns.jsonl").write_text(
        json.dumps({"ts": "2026-09-11T00:00:00Z", "target": target, "vuln_class": "idor",
                    "technique": "numeric id swap", "tech_stack": ["node"], "schema_version": 1,
                    "payout": 500, "outcome": "helped"}) + "\n"
        + json.dumps({"ts": "2026-09-11T00:00:01Z", "target": "third.example", "vuln_class": "idor",
                      "technique": "jwt none alg", "tech_stack": ["node"], "schema_version": 1,
                      "outcome": "false-positive"}) + "\n",
        encoding="utf-8",
    )
    # 知识卡（审计 F5：准入走 registry，不再 glob 目录）
    cards = repo / "knowledge" / "cards"
    cards.mkdir(parents=True, exist_ok=True)
    (cards / "basket-idor.md").write_text(
        "---\nid: basket-idor\nmaturity: tested\ntrigger_tags:\n  - basket\n  - idor\n---\nbody",
        encoding="utf-8",
    )
    (repo / "knowledge" / "capabilities.yaml").write_text(
        "schema_version: 1\n"
        "contracts:\n"
        "  max_core_cards: 20\n  default_cards_max: 8\n"
        "  card_layers:\n    - core\n    - reference\n    - case-router\n"
        "  load_modes:\n    - default\n    - signal-or-default\n    - signal-only\n    - on-demand\n    - gated\n"
        "capabilities:\n"
        "  - id: basket-idor\n    kind: card\n    file: knowledge/cards/basket-idor.md\n"
        "    layer: case-router\n    load: on-demand\n    purpose: validate\n"
        "    triggers:\n      - basket\n      - idor\n",
        encoding="utf-8",
    )


def test_view_combines_store_experiences_and_registered_knowledge(tmp_path):
    _seed(tmp_path)
    view = build_recall_view(tmp_path, target="t.example")
    assert view["counts"]["target_entries"] == 5  # hypotheses, negative, primitive and handoff
    assert view["counts"]["pattern_db"] == 0  # retired PatternDB is not a current source
    assert view["counts"]["knowledge_cards"] == 1
    kinds = {e["kind"] for e in view["target_entries"]}
    assert kinds == {"lead", "dead_end", "useful_pattern", "next_action"}


def test_primary_recall_reads_store_experiences_not_target_memory(tmp_path):
    from tools.target_store import TargetStore

    store = TargetStore(tmp_path, "t.example")
    store.initialize()
    store.remember(
        command_id="hypothesis-1",
        kind="hypothesis",
        statement="Check basket ownership boundary",
        conditions="Peer session and owner session are both available",
        reopen_when="When actor sessions change",
        next_intent="Compare the peer response",
        evidence=[],
        actor="operator",
    )
    old_patterns = tmp_path / "hunt-memory" / "patterns.jsonl"
    old_patterns.parent.mkdir(parents=True)
    old_patterns.write_text(json.dumps({"target": "t.example", "vuln_class": "idor",
                                        "technique": "stale pattern", "tech_stack": ["node"]}) + "\n")

    view = build_recall_view(tmp_path, target="t.example")

    assert view["counts"]["target_entries"] == 1
    entry = view["target_entries"][0]
    assert entry["text"] == "Check basket ownership boundary"
    assert entry["structured"]["next_intent"] == "Compare the peer response"
    assert view["pattern_db"] == []
    with pytest.raises(ValueError, match="PatternDB is legacy-only"):
        build_recall_view(tmp_path, target="t.example", kinds=["pattern_db"])
    assert not (tmp_path / "memory" / "goals" / "targets" / "t.example.json").exists()


def test_primary_recall_combines_store_experience_with_registered_knowledge_only(tmp_path):
    from tools.target_store import TargetStore

    store = TargetStore(tmp_path, "t.example")
    store.initialize()
    store.remember(command_id="historical-1", kind="note", statement="Historical owner swap",
                   conditions="unknown", reopen_when="", next_intent="", evidence=[], actor="migration")
    _seed(tmp_path, current=False)
    (tmp_path / "knowledge" / "cards" / "unregistered.md").write_text(
        "---\nid: unregistered\nmaturity: tested\ntrigger_tags:\n  - basket\n---\nbody")

    view = build_recall_view(tmp_path, target="t.example")

    assert [entry["entry_id"] for entry in view["target_entries"]] == ["historical-1"]
    assert view["pattern_db"] == []
    assert [entry["ref"] for entry in view["knowledge_cards"]] == ["knowledge/cards/basket-idor.md"]


def test_primary_recall_pages_without_losing_conditions_or_history(tmp_path, capsys):
    from tools.target_store import TargetStore

    store = TargetStore(tmp_path, "t.example")
    store.initialize()
    for index in range(7):
        store.remember(command_id=f"lead-{index}", kind="hypothesis",
                       statement=f"Candidate {index}", conditions="same tenant",
                       reopen_when="When actor changes", next_intent="Compare peer response",
                       evidence=[], actor="operator")

    first = build_recall_view(tmp_path, target="t.example", kinds=["lead"])
    assert first["counts"]["target_entries"] == 5
    assert first["counts"]["truncated_windows"] == 1
    assert first["target_page"]["remaining"] == 2
    second = build_recall_view(tmp_path, target="t.example", kinds=["lead"],
                               cursor=first["target_page"]["next_cursor"])
    assert len(second["target_entries"]) == 2
    assert second["target_page"]["remaining"] == 0
    assert {item["entry_id"] for item in first["target_entries"] + second["target_entries"]} == {
        f"lead-{index}" for index in range(7)
    }
    expanded = build_recall_view(tmp_path, target="t.example", kinds=["lead"], experience_id="lead-0")
    assert expanded["target_entries"][0]["conditions"] == "same tenant"
    assert main(["--repo-root", str(tmp_path), "--target", "t.example", "--kind", "lead"]) == 0
    output = capsys.readouterr().out
    assert "conditions: same tenant" in output
    assert "reopen_when: When actor changes" in output
    assert "next_intent: Compare peer response" in output
    assert "More target experiences: 2" in output


def test_isolation_excludes_other_targets_private_episodes(tmp_path):
    _seed(tmp_path)
    view = build_recall_view(tmp_path, target="t.example", query="BOLA basket")
    all_text = " ".join(e["text"] for e in view["target_entries"])
    assert "other target private lead" not in all_text
    # 跨项目现场记忆不自动带入（2026-09-12 收敛裁定）：jwt none 属于
    # third.example，只能通过人工晋升的知识卡通道复用，不能从 pattern_db 混入
    full = build_recall_view(tmp_path, target="t.example")
    assert not any("jwt none" in e["text"] for e in full["pattern_db"])


def test_query_filters_and_matches_structured_fields(tmp_path):
    _seed(tmp_path)
    view = build_recall_view(tmp_path, target="t.example", query="basket")
    texts = [e["text"] for e in view["target_entries"]]
    assert any("basket BOLA anonymous read" in t for t in texts)
    assert not any("graphql introspection" in t for t in texts)
    # Search the saved statement without interpreting nested structures.
    sso_view = build_recall_view(tmp_path, target="t.example", query="sso")
    assert any("sso bypass" in e["text"] for e in sso_view["target_entries"])


def test_recall_preserves_explicit_note_text_without_unpacking_it(tmp_path):
    _seed(tmp_path)
    literal = "{'schema_version': 1, 'text': 'nested note remains data'}"
    TargetStore(tmp_path, "t.example").remember(
        command_id="literal-note", kind="note", statement=literal, conditions="operator note",
        reopen_when="", next_intent="", evidence=[], actor="test",
    )
    view = build_recall_view(tmp_path, target="t.example", experience_id="literal-note")
    assert view["target_entries"][0]["text"] == literal


def test_kind_restriction(tmp_path):
    _seed(tmp_path)
    view = build_recall_view(tmp_path, target="t.example", kinds=["dead_end"])
    assert view["counts"]["target_entries"] == 1
    assert view["counts"]["pattern_db"] == 0
    assert view["counts"]["knowledge_cards"] == 0


def test_uninitialized_is_distinct_from_empty_store(tmp_path):
    (tmp_path / "hunt-memory").mkdir()
    (tmp_path / "hunt-memory" / "patterns.jsonl").write_text(
        json.dumps({"ts": "t", "target": "x.example", "vuln_class": "v",
                    "technique": "k", "tech_stack": ["s"], "schema_version": 1}) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(StoreError, match="not initialized"):
        build_recall_view(tmp_path, target="never-seen.example")
    assert not (tmp_path / "state").exists()
    TargetStore(tmp_path, "never-seen.example").initialize()
    view = build_recall_view(tmp_path, target="never-seen.example")
    assert view["counts"]["target_entries"] == 0
    assert view["counts"]["pattern_db"] == 0  # 他目标 pattern 行不进入本目标视图


def test_technical_experience_keeps_id_conditions_and_observation_refs(tmp_path):
    _seed(tmp_path)
    view = build_recall_view(tmp_path, target="t.example", kinds=["useful_pattern"])
    entry = view["target_entries"][0]
    assert entry["entry_id"] == "primitive-graphql"
    assert entry["conditions"] == "anonymous session"
    assert entry["reopen_when"] == "session changes"
    assert entry["evidence"][0]["step"] == 0
    assert entry["evidence_refs"][0].endswith(":0")
    assert view["pattern_db"] == []


def test_cli_json_roundtrip(tmp_path, capsys):
    _seed(tmp_path)
    rc = main(["--repo-root", str(tmp_path), "--target", "t.example", "--json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema_version"] == 1
    assert payload["target"] == "t.example"


def test_cli_human_readable_contains_sources(tmp_path, capsys):
    _seed(tmp_path)
    rc = main(["--repo-root", str(tmp_path), "--target", "t.example"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "当前目标经验" in out
    assert "primitive-graphql" in out
    assert "conditions: anonymous session" in out
    assert "已晋升知识卡" in out
    assert "basket-idor.md" in out


def test_knowledge_cards_require_registry_registration(tmp_path):
    """审计 F5：目录里未登记的卡不得进入召回（准入 = registry，不是目录位置）。"""
    _seed(tmp_path)
    cards = tmp_path / "knowledge" / "cards"
    # 未登记 sentinel：与登记卡同目录、frontmatter 齐全，但不在 registry。
    (cards / "unregistered-sentinel.md").write_text(
        "---\nid: unregistered-sentinel\nmaturity: tested\ntrigger_tags:\n  - basket\n---\nbody",
        encoding="utf-8",
    )
    view = build_recall_view(tmp_path, target="t.example")
    refs = [e["ref"] for e in view["knowledge_cards"]]
    assert "knowledge/cards/basket-idor.md" in refs
    assert not any("unregistered-sentinel" in r for r in refs), (
        "unregistered card leaked into recall as reviewed knowledge"
    )


def test_knowledge_cards_empty_registry_returns_no_cards(tmp_path):
    """registry 缺失/为空：返回空知识列表，不退回 glob 目录。"""
    _seed(tmp_path)
    (tmp_path / "knowledge" / "capabilities.yaml").unlink()
    view = build_recall_view(tmp_path, target="t.example")
    assert view["counts"]["knowledge_cards"] == 0
    assert not any("basket-idor" in e.get("ref", "") for e in view["knowledge_cards"])


def test_recall_ignores_misfiled_legacy_target(tmp_path: Path) -> None:
    TargetStore(tmp_path, "alpha.test").initialize()
    misfiled = tmp_path / "memory" / "goals" / "targets" / "alpha.test.json"
    misfiled.parent.mkdir(parents=True)
    misfiled.write_text(json.dumps({
        "schema_version": 1, "target": "beta.test",
        "active_leads": [{"ts": "t", "text": "beta private lead"}],
    }))
    before = misfiled.read_bytes()
    view = build_recall_view(tmp_path, target="alpha.test")
    assert view["target_entries"] == []
    assert misfiled.read_bytes() == before


def test_truncation_marker_boundary_is_exact(tmp_path: Path) -> None:
    """三轮审计回归 4：截断提示的边界。旧实现存 6 条只返 5 条且不提示
    （提示条件 `len(matched) > len(seen_texts)` 在恰好 6 时假），存 7 条
    又把提示本身当成一条记录（counts 偏大）。正确语义：窗口填满后仍有
    未输出条目才出现提示，提示不占窗口、不计入 counts。"""
    for stored, want_count, want_marker in ((5, 5, 0), (6, 5, 1), (7, 5, 1)):
        repo = tmp_path / f"n{stored}"
        store = TargetStore(repo, "t.example")
        store.initialize()
        for index in range(stored):
            store.remember(command_id=f"lead-{index}", kind="hypothesis", statement=f"lead {index}",
                           conditions="test", reopen_when="", next_intent="", evidence=[], actor="test")
        view = build_recall_view(repo, target="t.example", kinds=["lead"])
        entries = view["target_entries"]
        markers = [e for e in entries if e.get("truncated")]
        assert markers == []  # pagination metadata never impersonates an experience
        assert view["target_page"]["remaining"] == stored - want_count
        assert view["counts"]["target_entries"] == want_count, stored
        assert view["counts"]["truncated_windows"] == want_marker, stored
