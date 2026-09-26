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
    from tools.evidence_identity import normalize_family

    for left, right in (("auth_bypass", "Authz"), ("auth_bypass", "authz"),
                        ("IDOR", "idor"), ("Authz", "AUTHZ")):
        assert normalize_family(left) == normalize_family(right)
    assert normalize_family("UNKNOWN_X") == "UNKNOWN_X"
    assert normalize_family("unknown_x") == "unknown_x"
    for left, right in (("auth_bypass", "IDOR"), ("Authz", "sqli"), ("weird_unknown", "other_unknown")):
        assert normalize_family(left) != normalize_family(right)


def test_native_runner_accepts_scanner_finding_against_closure_action(tmp_path):
    from tools.target_store import TargetStore
    from tools.validation_runner import record_native_evidence, sync_runner_artifacts

    store = TargetStore(tmp_path, "t.example")
    store.initialize()
    store.create_finding(command_id="finding", finding_id="F-1", endpoint="http://t.example/x",
                         method="GET", family="auth_bypass", title="Claim", claim="Compare sessions", actor="test")
    store.create_action(command_id="create", action_id="A-1", endpoint="http://t.example/x",
                        family="Authz", intent="Compare sessions", execution_key="compare", actor="test")
    store.transition_action(command_id="claim", action_id="A-1", expected_version=1, status="claimed", actor="test")
    raw = tmp_path / ".private/validation/t.example"
    raw.mkdir(parents=True)
    (raw / "request.txt").write_text("GET /x HTTP/1.1\r\nHost: t.example\r\n\r\n")
    (raw / "response.txt").write_text("HTTP/1.1 403 Forbidden\r\n\r\n")
    summary = record_native_evidence(
        repo_root=tmp_path, target="t.example", finding_id="F-1", state_changing=False,
        action_id="A-1", claim_token="claim", command_actor="test", evidence={
            "schema_version": 1, "source": "native", "attempt_id": "native-1",
            "generated_at": "2026-09-24T00:00:00Z", "result": "candidate",
            "observed_difference": "Recorded session was denied; control comparison remains pending.",
            "runs": [{"url": "http://t.example/x", "method": "GET", "actor": "anonymous", "artifacts": {
                "request": ".private/validation/t.example/request.txt",
                "response": ".private/validation/t.example/response.txt",
            }}],
        },
    )
    assert summary["vuln_class"] == "Authz"
    assert sync_runner_artifacts(summary, repo_root=tmp_path)["status"] == "updated"
    assert store.page("operations")["total"] == 1
    assert store.finding("F-1")["assessment"] is None


def _run_preflight(tmp_path: Path, vuln_class: str, finding_type: str) -> list[str]:
    """跑一次 preflight，返回收集到的错误列表（字段不全时其他错误共存）。"""
    import argparse

    from validate import MachineDecisionPreflightError, run_machine_preflight

    from tools.target_store import TargetStore
    store = TargetStore(tmp_path, "t.example")
    store.initialize()
    store.create_finding(command_id="claim", finding_id="F-1", endpoint="http://t.example/x", method="GET",
                         family=finding_type, title="Claim", claim="Compare sessions", actor="test")
    findings_dir = tmp_path / "findings" / "t.example"
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
    errors_back = _run_preflight(tmp_path / "reverse", vuln_class="auth_bypass", finding_type="Authz")
    assert not any("vuln_class does not match" in e for e in errors_back), errors_back


def test_validate_still_rejects_genuinely_different_classes(tmp_path):
    """等价归一不能放松真冲突：auth_bypass vs sqli 仍然拒绝。"""
    errors = _run_preflight(tmp_path, vuln_class="sqli", finding_type="auth_bypass")
    assert any("vuln_class does not match" in e for e in errors), errors
