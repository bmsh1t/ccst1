"""experience_recall: unified episodic recall view (memory-loop step 2.1).

隔离边界 + 三来源聚合 + 词项粗筛 + legacy 文本形态兼容。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.experience_recall import build_recall_view, main


def _seed(repo: Path, *, target: str = "t.example", other: str = "other.example") -> None:
    tkey = target.replace(":", "-")
    okey = other.replace(":", "-")
    goals = repo / "memory" / "goals" / "targets"
    goals.mkdir(parents=True, exist_ok=True)
    (goals / f"{tkey}.json").write_text(json.dumps({
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
    # 知识卡
    cards = repo / "knowledge" / "cards"
    cards.mkdir(parents=True, exist_ok=True)
    (cards / "basket-idor.md").write_text(
        "---\nid: basket-idor\nmaturity: tested\ntrigger_tags:\n  - basket\n  - idor\n---\nbody",
        encoding="utf-8",
    )


def test_view_aggregates_three_sources_with_counts(tmp_path):
    _seed(tmp_path)
    view = build_recall_view(tmp_path, target="t.example")
    assert view["counts"]["target_entries"] == 4  # 2 leads + 1 dead-end + 1 next
    assert view["counts"]["pattern_db"] == 1  # 只收当前目标；跨目标行被隔离
    assert view["counts"]["knowledge_cards"] == 1
    kinds = {e["kind"] for e in view["target_entries"]}
    assert kinds == {"lead", "dead_end", "next_action"}


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
    # stringified-dict lead 被 query "sso" 命中（内层 text 提取后参与匹配）
    sso_view = build_recall_view(tmp_path, target="t.example", query="sso")
    assert any("sso bypass" in e["text"] for e in sso_view["target_entries"])


def test_legacy_stringified_dict_text_is_extracted(tmp_path):
    _seed(tmp_path)
    view = build_recall_view(tmp_path, target="t.example")
    texts = [e["text"] for e in view["target_entries"]]
    assert any(t.startswith("Evidence: Workflow lead: sso bypass") for t in texts)
    assert not any(t.startswith("{'schema_version'") for t in texts)


def test_kind_restriction(tmp_path):
    _seed(tmp_path)
    view = build_recall_view(tmp_path, target="t.example", kinds=["dead_end"])
    assert view["counts"]["target_entries"] == 1
    assert view["counts"]["pattern_db"] == 0
    assert view["counts"]["knowledge_cards"] == 0


def test_missing_target_memory_degrades_to_cross_target_only(tmp_path):
    (tmp_path / "hunt-memory").mkdir()
    (tmp_path / "hunt-memory" / "patterns.jsonl").write_text(
        json.dumps({"ts": "t", "target": "x.example", "vuln_class": "v",
                    "technique": "k", "tech_stack": ["s"], "schema_version": 1}) + "\n",
        encoding="utf-8",
    )
    view = build_recall_view(tmp_path, target="never-seen.example")
    assert view["counts"]["target_entries"] == 0
    assert view["counts"]["pattern_db"] == 0  # 他目标 pattern 行不进入本目标视图


def test_pattern_db_entries_carry_outcome_and_composite_id(tmp_path):
    _seed(tmp_path)
    view = build_recall_view(tmp_path, target="t.example")
    by_id = {e["entry_id"]: e for e in view["pattern_db"]}
    assert "t.example|idor|numeric id swap" in by_id
    assert "outcome=helped" in by_id["t.example|idor|numeric id swap"]["text"]
    assert "third.example|idor|jwt none alg" not in by_id  # 跨目标行被隔离


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
    assert "本目标技术经验" in out
    assert "已晋升知识卡" in out
    assert "basket-idor.md" in out
