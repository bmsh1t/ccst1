"""跨词汇表漏洞类等价（lab-r5 撞墙根因的回归锁）。

scanner 词汇（finding_index：auth_bypass/idor/...）与 closure 词汇
（closure_resolver：Authz/IDOR/...）是同一概念的两套拼写。runner sync 和
validate 决策此前做裸字符串比较，把等价身份判成冲突——lab-r5 里三次手工
归一（claim_fb02b676f9a7 两次、request_diff-rest_basket_2 一次）。
现在三处守卫都经 closure 词汇 owner（canonical_vuln_class）归一后比较；
未知类回退裸比较保持 fail-open。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def test_runner_class_equivalence_table():
    from validation_runner import _classes_equivalent

    # 同一概念的两套拼写互相等价
    assert _classes_equivalent("auth_bypass", "Authz")
    assert _classes_equivalent("Authz", "auth_bypass")
    assert _classes_equivalent("auth_bypass", "authz")
    assert _classes_equivalent("IDOR", "idor")
    assert _classes_equivalent("idor", "IDOR")
    # 不同概念不等价
    assert not _classes_equivalent("auth_bypass", "IDOR")
    assert not _classes_equivalent("Authz", "sqli")
    # 未知类：回退裸比较（fail-open：同形通过，异形拒绝）
    assert _classes_equivalent("weird_unknown", "weird_unknown")
    assert not _classes_equivalent("weird_unknown", "other_unknown")
    # 大小写不敏感在两个分支都成立
    assert _classes_equivalent("Authz", "AUTHZ")
    assert _classes_equivalent("UNKNOWN_X", "unknown_x")


def test_runner_sync_accepts_scanner_vocab_against_closure_row(tmp_path):
    """canonical 行是 scanner 词汇（auth_bypass），runner 带 closure 词汇
    （Authz）时 sync 不再报 class conflict——lab-r5 的原始撞墙场景。"""
    from validation_runner import _classes_equivalent, _sync_finding_status

    # 直接验证守卫使用的判定函数（sync 全链路需要网络/facts，等价函数是守卫根）
    assert _classes_equivalent("auth_bypass", "Authz")
    # 反向同样成立（closure 行 vs scanner runner 输入）
    assert _classes_equivalent("Authz", "auth_bypass")


def _run_preflight(tmp_path: Path, vuln_class: str, finding_type: str) -> list[str]:
    """跑一次 preflight，返回收集到的错误列表（字段不全时其他错误共存）。"""
    import argparse

    from validate import MachineDecisionPreflightError, run_machine_preflight

    findings_dir = tmp_path / "findings" / "t.example"
    findings_dir.mkdir(parents=True, exist_ok=True)
    (findings_dir / "findings.json").write_text(json.dumps({
        "target": "t.example",
        "findings": [{"id": "F-1", "type": finding_type, "url": "http://t.example/x"}],
    }), encoding="utf-8")
    decision = {
        "schema_version": 2, "target": "t.example", "finding_id": "F-1",
        "endpoint": "http://t.example/x", "vuln_class": vuln_class, "method": "GET",
        "impact": "i",
        "gates": {k: {"passed": True, "notes": {}} for k in ("gate1", "gate2", "gate3", "gate4")},
        "seven_question_gate": {"questions": {}},
        "cvss": {"score": 0.0, "vector": ""},
        "evidence": {"summary": "s", "runner_summary": "", "refs": []},
        "report": {"path": "", "content": "c"},
    }
    decision_path = tmp_path / "decision.json"
    decision_path.write_text(json.dumps(decision), encoding="utf-8")
    args = argparse.Namespace(
        decision_json=str(decision_path), target="t.example",
        findings_dir=str(findings_dir), finding_id="F-1", preflight=True, json=True,
    )
    try:
        result = run_machine_preflight(args)
        return result.get("errors") or []
    except MachineDecisionPreflightError as exc:
        return list(exc.errors)


def test_validate_preflight_accepts_scanner_vs_closure_classes(tmp_path):
    """preflight：canonical type=auth_bypass（scanner 词汇）与 decision
    vuln_class=Authz（closure 词汇）不再判为不匹配（lab-r5 撞墙场景）。"""
    errors = _run_preflight(tmp_path, vuln_class="Authz", finding_type="auth_bypass")
    assert not any("vuln_class does not match" in e for e in errors), errors
    # 反向：closure 行 + scanner decision 同样通过
    errors_back = _run_preflight(tmp_path, vuln_class="auth_bypass", finding_type="Authz")
    assert not any("vuln_class does not match" in e for e in errors_back), errors_back


def test_validate_still_rejects_genuinely_different_classes(tmp_path):
    """等价归一不能放松真冲突：auth_bypass vs sqli 仍然拒绝。"""
    errors = _run_preflight(tmp_path, vuln_class="sqli", finding_type="auth_bypass")
    assert any("vuln_class does not match" in e for e in errors), errors
