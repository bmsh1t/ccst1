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
import subprocess
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
    """AI 直写草稿（2026-09-13 后契约）：卡片 frontmatter 的 target-evidence
    source_refs 必须能通过 registry 契约解析——commit 中转退役后，这个契约
    由 AI 按 card-template 直写时遵守，由 audit 在晋升门检查。"""
    from knowledge_registry import (
        TARGET_EVIDENCE_CORPUS,
        TARGET_EVIDENCE_REF_TYPE,
        parse_knowledge_document,
        parse_source_refs,
    )

    _seed_target_repo(tmp_path)
    # AI 直写形态的草稿卡（即新 /distill 第②步的产物）
    card_path = tmp_path / "knowledge" / "candidates" / "t-card.md"
    card_path.parent.mkdir(parents=True, exist_ok=True)
    card_path.write_text(
        "---\n"
        "id: t-card\n"
        "type: technique-card\n"
        "related_skills: []\n"
        "trigger_tags:\n  - t-card\n"
        "risk: low\n"
        "maturity: draft\n"
        "load_priority: low\n"
        "source_refs:\n"
        "  - type: target-evidence\n"
        "    target: t.example\n"
        "    refs:\n"
        '      - "evidence/t.example/probe/probe-1.json"\n'
        "updated: 2026-09-13\n"
        "---\n\n"
        "# T\n\n## Quick Recall\n\n- 触发：t\n- 判定条件：c\n- 停止：s\n",
        encoding="utf-8",
    )
    card = card_path.read_text(encoding="utf-8")
    parsed = parse_knowledge_document(card)
    refs = parse_source_refs(parsed.metadata, source_path=str(card_path))
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


def test_historical_pattern_reader_preserves_outcomes_without_writer(tmp_path):
    from memory.pattern_db import PatternDB

    from legacy_fixtures import append_legacy_pattern

    db = PatternDB(tmp_path / "patterns.jsonl")
    assert not hasattr(db, "save")
    assert not db.path.exists()
    assert append_legacy_pattern(db.path, {"ts": "2026-09-12T00:00:00Z", "target": "a.example",
                    "vuln_class": "idor", "technique": "numeric id swap",
                    "tech_stack": ["node", "express"], "schema_version": 1,
                    "outcome": "false-positive"})
    assert append_legacy_pattern(db.path, {"ts": "2026-09-12T00:00:01Z", "target": "b.example",
                    "vuln_class": "idor", "technique": "uuid brute",
                    "tech_stack": ["node"], "schema_version": 1,
                    "outcome": "no-signal"})
    assert append_legacy_pattern(db.path, {"ts": "2026-09-12T00:00:02Z", "target": "c.example",
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


def test_remember_rejected_account_is_advisory_without_observation(tmp_path):
    from remember import remember_finding
    from tools.target_store import TargetStore
    from tools.experience_recall import build_recall_view
    from memory.hunt_journal import HuntJournal

    memory_dir = tmp_path / "hunt-memory"
    with pytest.raises(ValueError, match="not initialized"):
        remember_finding(memory_dir=memory_dir, repo_root=tmp_path, target="t.example",
                         endpoint="https://t.example/api/x", vuln_class="idor", result="rejected",
                         technique="id swap")
    assert not memory_dir.exists()
    TargetStore(tmp_path, "t.example").initialize()
    result = remember_finding(
        memory_dir=memory_dir, repo_root=tmp_path, target="t.example", endpoint="https://t.example/api/x",
        vuln_class="idor", result="rejected", technique="id swap", command_id="rejected-note",
    )
    assert result["experience_id"] == "rejected-note"
    entries = build_recall_view(tmp_path, target="t.example")["target_entries"]
    assert entries[0]["kind"] == "note"
    assert entries[0]["text"].startswith("Unverified rejected account")
    assert not (memory_dir / "patterns.jsonl").exists()
    assert len(HuntJournal(memory_dir / "journal.jsonl").read_all()) == 1


def test_remember_primary_records_unverified_experience_without_pattern_db(tmp_path):
    from remember import remember_finding
    from tools.experience_recall import build_recall_view
    from tools.target_store import StoreError, TargetStore

    store = TargetStore(tmp_path, "t.example")
    store.initialize()
    memory_dir = tmp_path / "hunt-memory"
    kwargs = dict(
        memory_dir=memory_dir, repo_root=tmp_path, target="t.example",
        endpoint="https://t.example/api/x", vuln_class="idor", result="rejected",
        technique="id swap", notes="No peer read in this session",
        tech_stack=["node"], command_id="remember-1", actor="operator",
    )
    before = store.binding()["revision"]
    result = remember_finding(**kwargs)
    assert result["experience_saved"] and not result["pattern_saved"]
    assert result["experience_id"] == "remember-1"
    assert store.binding()["revision"] == before + 1
    saved = store.experience("remember-1")
    assert saved["kind"] == "note"
    assert saved["conditions"] == "unknown"
    assert saved["statement"].startswith("Unverified rejected account:")
    assert not saved["evidence"]
    assert store.page("actions")["total"] == 0
    assert not (memory_dir / "patterns.jsonl").exists()
    assert not (memory_dir / "targets" / "t.example.json").exists()
    assert (memory_dir / "journal.jsonl").is_file()
    recalled = build_recall_view(tmp_path, target="t.example", kinds=["note"])
    assert recalled["target_entries"][0]["entry_id"] == "remember-1"
    assert recalled["target_entries"][0]["conditions"] == "unknown"

    remember_finding(**kwargs)
    assert store.binding()["revision"] == before + 1
    from memory.hunt_journal import HuntJournal
    assert len(HuntJournal(memory_dir / "journal.jsonl").read_all()) == 1
    with pytest.raises(StoreError, match="negative experience requires"):
        remember_finding(**{**kwargs, "command_id": "remember-2",
                            "operation_refs": ["operation-1:0"]})
    assert store.binding()["revision"] == before + 1
    with pytest.raises(StoreError, match="require technique, notes or operation refs"):
        remember_finding(**{**kwargs, "technique": None, "notes": None,
                            "command_id": "remember-empty", "conditions": "same tenant"})
    assert store.binding()["revision"] == before + 1
    from memory.schemas import SchemaError
    with pytest.raises(SchemaError, match="result"):
        remember_finding(**{**kwargs, "command_id": "remember-invalid", "result": "invalid"})
    assert store.binding()["revision"] == before + 1


def test_remember_primary_survives_new_process_recall(tmp_path):
    from tools.target_store import TargetStore

    store = TargetStore(tmp_path, "t.example")
    store.initialize()
    tools_dir = Path(__file__).resolve().parent.parent / "tools"
    saved = subprocess.run(
        [sys.executable, str(tools_dir / "remember.py"), "--repo-root", str(tmp_path),
         "--target", "t.example", "--vuln-class", "idor",
         "--endpoint", "https://t.example/api/x", "--result", "partial",
         "--technique", "peer-id comparison", "--conditions", "same tenant",
         "--command-id", "remember-process-1", "--json"],
        capture_output=True, text=True, check=True,
    )
    assert json.loads(saved.stdout)["experience_id"] == "remember-process-1"
    recalled = subprocess.run(
        [sys.executable, str(tools_dir / "experience_recall.py"), "--repo-root", str(tmp_path),
         "--target", "t.example", "--kind", "note"],
        capture_output=True, text=True, check=True,
    )
    assert "[remember-process-1]" in recalled.stdout
    assert "conditions: same tenant" in recalled.stdout
    assert "Unverified partial account" in recalled.stdout
    assert store.page("actions")["total"] == 0


def test_remember_primary_negative_binds_observation_and_reopen_condition(tmp_path):
    from remember import remember_finding
    from tools.target_store import TargetStore

    store = TargetStore(tmp_path, "t.example")
    store.initialize()
    response = tmp_path / ".private" / "validation" / "t.example" / "denied.txt"
    response.parent.mkdir(parents=True)
    response.write_text("HTTP/1.1 403 Forbidden\r\n\r\n")
    store.start_attempt(attempt_id="attempt-1", source="native", started_at="2026-09-23T00:00:00Z",
                        actor="operator")
    operation = store.record_execution(
        attempt_id="attempt-1", outcome="complete", actor="operator",
        observations=[{"endpoint": "https://t.example/api/x", "method": "GET", "family": "idor",
                       "observed_at": "2026-09-23T00:00:00Z", "description": "Peer read denied",
                       "artifacts": {"response": response.relative_to(tmp_path).as_posix()},
                       "state_changing": False}],
    )
    result = remember_finding(
        memory_dir=tmp_path / "hunt-memory", repo_root=tmp_path,
        target="t.example", endpoint="https://t.example/api/x", vuln_class="idor",
        result="rejected", technique="peer id comparison", conditions="same tenant",
        reopen_when="new peer session", operation_refs=[f"{operation['entity_id']}:0"],
        command_id="remember-negative-1",
    )
    saved = store.experience(result["experience_id"])
    assert saved["kind"] == "negative"
    assert saved["conditions"] == "same tenant"
    assert saved["reopen_when"] == "new peer session"
    assert saved["evidence"] == [{"operation_id": operation["entity_id"], "step": 0}]


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
