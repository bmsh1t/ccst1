"""Shared cross-owner contracts (stage-two #9): constants stay in sync."""

from __future__ import annotations

from tools.contracts import (
    CHECKPOINT_QUEUE_LOCK_ORDER,
    LEDGER_REDLINE_EVENTS,
    VALIDATE_TERMINAL_FINDING_STATES,
)


def test_validate_terminal_states_match_canonical_usage():
    """validate.py 的 canonical 终态必须是共享契约的子集（改一边编译期可见）。"""
    from tools.validate import MACHINE_DECISION_SCHEMA_VERSION  # noqa: F401
    import tools.finding_index  # noqa: F401  (import sanity)

    assert "validated" in VALIDATE_TERMINAL_FINDING_STATES
    assert "rejected" in VALIDATE_TERMINAL_FINDING_STATES


def test_checkpoint_queue_lock_order_is_documented_and_enforced():
    from tools.checkpoint import CHECKPOINT_QUEUE_LOCK_ORDER as cp_order  # re-export

    assert cp_order == ("checkpoint_witness_lock", "queue_mutation_lock")


def test_ledger_redline_events_are_never_clean():
    from tools.evidence_ledger import RESULTS

    assert LEDGER_REDLINE_EVENTS <= set(RESULTS)
    assert "tested_clean" not in LEDGER_REDLINE_EVENTS


def test_contracts_module_imports_only_stdlib():
    """纯常量/纯函数纪律：contracts.py 只 import 标准库（防新循环、防反向依赖）。"""
    import ast
    from pathlib import Path

    src = Path("tools/contracts.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("tools."):
            raise AssertionError(f"contracts.py must stay import-free, found: {node.module}")
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in ("hashlib", "json", "typing", "__future__"):
                    raise AssertionError(f"contracts.py must import only stdlib, found: {alias.name}")


def test_operation_id_contract_is_stable_and_shared():
    """runner operation ID 契约：纯函数、确定性、runner 旧名与契约新名同源。"""
    from tools.contracts import artifact_digest_material, runner_operation_id
    from tools import validation_runner

    bindings = [
        {"kind": "baseline_request", "sha256": "AA" * 32},
        {"kind": "variant_request", "sha256": "BB" * 32},
        {"kind": "baseline_response", "sha256": "CC" * 32},
        {"kind": "variant_response", "sha256": "DD" * 32},
        {"kind": "diff", "sha256": "EE" * 32},  # 派生文件不参与 operation 定义
        {"kind": "", "sha256": "FF" * 32},       # 缺 kind 不计
    ]
    material = artifact_digest_material(bindings)
    assert [item["kind"] for item in material] == [
        "baseline_request", "baseline_response", "variant_request", "variant_response",
    ]
    op_id = runner_operation_id({"artifact_bindings": material})
    assert op_id.startswith("runner:") and len(op_id) == len("runner:") + 24
    # 确定性 + 旧导出兼容（runner 私有名与契约函数必须恒等）
    assert op_id == runner_operation_id({"artifact_bindings": artifact_digest_material(bindings)})
    assert validation_runner._artifact_digest_material(bindings) == material
    assert validation_runner._runner_operation_id({"artifact_bindings": material}) == op_id
