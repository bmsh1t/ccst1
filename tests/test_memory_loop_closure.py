"""Memory-loop closure regression (2026-09-12 memory deep review breakpoints).

三个断点对应三组回归：
  A. 蒸馏→晋升契约：distill 草稿卡的 source_refs 必须能通过 registry 解析，
     mv 进 cards/ 后 audit 不再报错（原 target-evidence 内联形态不兼容）。
  B. 失败经验召回：patterns.jsonl 不再只收 confirmed+payout>0；三类 outcome
     都可写入、可 match 召回、payout 排序保持、legacy 无 outcome 条目兼容。
  C. 源归因：validate decision 声明 source_knowledge_refs 时，calibration
     额外记到被采用的来源 ID 上（跨目标经验拿到自己的反馈）。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def _seed_target_repo(tmp_path: Path, target: str = "t.example") -> None:
    key = target
    probe = tmp_path / "evidence" / key / "probe"
    probe.mkdir(parents=True)
    (probe / "probe-1.json").write_text(json.dumps({"kind": "probe"}), encoding="utf-8")
    led = tmp_path / "memory" / "evidence" / key
    led.mkdir(parents=True)
    (led / "ledger.jsonl").write_text(
        json.dumps({
            "event_id": "probe-1", "endpoint": "/rest/basket/1", "method": "GET",
            "vuln_class": "IDOR", "actor": "peer", "variant": "id_swap",
            "result": "lead", "evidence_ref": f"evidence/{key}/probe/probe-1.json",
        }) + "\n",
        encoding="utf-8",
    )


_TRIPLE = {
    "typology": "pattern",
    "pattern": "REST numeric-id cross-actor read",
    "trigger": "GET /rest/basket/<id> returns other user data",
    "action": "owner/peer id_swap diff",
}


# --- 断点 A：蒸馏 → 注册契约 -----------------------------------------------


def test_distilled_card_source_refs_pass_registry_contract(tmp_path):
    from distill_target import commit_triple
    from knowledge_registry import (
        TARGET_EVIDENCE_CORPUS,
        TARGET_EVIDENCE_REF_TYPE,
        parse_knowledge_document,
        parse_source_refs,
    )

    _seed_target_repo(tmp_path)
    result = commit_triple(
        tmp_path, "t.example",
        json.dumps({**_TRIPLE, "evidence_refs": ["evidence/t.example/probe/probe-1.json"]}),
    )
    card = Path(tmp_path, result["path"]).read_text(encoding="utf-8")
    parsed = parse_knowledge_document(card)
    refs = parse_source_refs(parsed.metadata, source_path=result["path"])
    assert len(refs) == 1
    assert refs[0].type == TARGET_EVIDENCE_REF_TYPE
    assert refs[0].corpus == TARGET_EVIDENCE_CORPUS
    assert "t.example|" in refs[0].id and "probe-1.json" in refs[0].id


def test_registry_rejects_malformed_target_evidence_refs():
    from knowledge_registry import KnowledgeRegistryError, parse_source_refs

    with pytest.raises(KnowledgeRegistryError, match="target"):
        parse_source_refs({"source_refs": [{"type": "target-evidence", "refs": ["a"]}]})
    with pytest.raises(KnowledgeRegistryError, match="refs"):
        parse_source_refs({"source_refs": [{"type": "target-evidence", "target": "t.example", "refs": []}]})
    with pytest.raises(KnowledgeRegistryError, match="未知字段"):
        parse_source_refs({"source_refs": [
            {"type": "target-evidence", "target": "t.example", "refs": ["a"], "extra": 1}
        ]})


def test_corpus_report_contract_unchanged():
    from knowledge_registry import (
        SOURCE_REF_CORPUS,
        SOURCE_REF_TYPE,
        KnowledgeRegistryError,
        parse_source_refs,
    )

    refs = parse_source_refs({"source_refs": [
        {"type": "corpus-report", "corpus": SOURCE_REF_CORPUS, "id": "158330"}
    ]})
    assert refs[0].type == SOURCE_REF_TYPE and refs[0].id == "158330"
    with pytest.raises(KnowledgeRegistryError):
        parse_source_refs({"source_refs": [
            {"type": "corpus-report", "corpus": SOURCE_REF_CORPUS, "id": "not-a-number"}
        ]})


# --- 断点 B：失败经验召回 ----------------------------------------------------


def test_pattern_db_accepts_all_outcome_kinds_and_matches(tmp_path):
    from memory.pattern_db import PatternDB

    db = PatternDB(tmp_path / "patterns.jsonl")
    assert db.save({"ts": "2026-09-12T00:00:00Z", "target": "a.example",
                    "vuln_class": "idor", "technique": "numeric id swap",
                    "tech_stack": ["node", "express"], "schema_version": 1,
                    "outcome": "false-positive"})
    assert db.save({"ts": "2026-09-12T00:00:01Z", "target": "b.example",
                    "vuln_class": "idor", "technique": "uuid brute",
                    "tech_stack": ["node"], "schema_version": 1,
                    "outcome": "no-signal"})
    assert db.save({"ts": "2026-09-12T00:00:02Z", "target": "c.example",
                    "vuln_class": "idor", "technique": "jwt none",
                    "tech_stack": ["node"], "schema_version": 1,
                    "payout": 500, "outcome": "helped"})

    hits = db.match(vuln_class="idor", tech_stack=["node"])
    outcomes = [h.get("outcome") for h in hits]
    assert set(outcomes) == {"helped", "no-signal", "false-positive"}
    assert hits[0]["outcome"] == "helped"  # payout 排序优先


def test_pattern_schema_rejects_unknown_outcome():
    from memory.schemas import SchemaError, validate_pattern_entry

    base = {"ts": "2026-09-12T00:00:00Z", "target": "t", "vuln_class": "v",
            "technique": "x", "tech_stack": ["s"], "schema_version": 1}
    with pytest.raises(SchemaError, match="outcome"):
        validate_pattern_entry({**base, "outcome": "bogus"})
    # legacy 条目（无 outcome）仍然合法
    assert validate_pattern_entry(dict(base)) == base


def test_remember_writes_false_positive_pattern(tmp_path):
    """rejected 结果 + technique + tech_stack → false-positive 模式可召回。"""
    from remember import remember_finding

    memory_dir = tmp_path / "memory"
    memory_dir.mkdir()
    result = remember_finding(
        memory_dir=memory_dir,
        target="t.example", endpoint="https://t.example/api/x",
        vuln_class="idor", result="rejected", technique="id swap",
        payout=0, tech_stack=["node"],
    )
    assert result["pattern_saved"] is True
    from memory.pattern_db import PatternDB
    hits = PatternDB(memory_dir / "patterns.jsonl").match(vuln_class="idor")
    assert hits and hits[0]["outcome"] == "false-positive"


# --- 断点 C：源归因 -----------------------------------------------------------


def test_validate_calibration_attributes_to_declared_source(tmp_path):
    from validate import record_validation_calibration

    summary = {
        "target": "current.example",
        "vuln_class": "idor",
        "result": "confirmed",
        "technique": "id swap",
        "source_knowledge_refs": ["source.example|idor|id swap"],
    }
    calib_path = tmp_path / "pattern_calibration.jsonl"
    record_validation_calibration(summary, session_id="s1", path=calib_path)
    rows = [json.loads(line) for line in calib_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    ids = [row["pattern_id"] for row in rows]
    # 当前 target 复合 ID + 声明的源 ID 都要有反馈行
    assert any(pid.startswith("current.example|") for pid in ids)
    assert "source.example|idor|id swap" in ids


def test_validate_calibration_without_source_keeps_legacy_behavior(tmp_path):
    from validate import record_validation_calibration

    summary = {"target": "t.example", "vuln_class": "idor", "result": "confirmed", "technique": ""}
    calib_path = tmp_path / "pattern_calibration.jsonl"
    record_validation_calibration(summary, session_id="s1", path=calib_path)
    rows = [json.loads(line) for line in calib_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(rows) == 1 and rows[0]["pattern_id"].startswith("t.example|")


def test_parse_source_knowledge_refs_validates_cards():
    from validate import _parse_source_knowledge_refs

    # 缺失卡路径拒绝（防笔误/伪造）
    with pytest.raises(ValueError, match="missing card"):
        _parse_source_knowledge_refs(["knowledge/cards/does-not-exist.md"])
    # PatternDB 复合 ID 原样保留
    assert _parse_source_knowledge_refs(["a.example|idor|swap"]) == ["a.example|idor|swap"]
    assert _parse_source_knowledge_refs(None) == []
