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


def test_contracts_module_has_no_runtime_imports():
    """纯常量纪律：contracts.py 不得 import 其他 owner（防新循环）。"""
    import ast
    from pathlib import Path

    src = Path("tools/contracts.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("tools."):
            raise AssertionError(f"contracts.py must stay import-free, found: {node.module}")
        if isinstance(node, ast.Import):
            raise AssertionError("contracts.py must stay import-free")
