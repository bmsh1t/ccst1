#!/usr/bin/env python3
"""Decision-JSON scaffolds: machine-generated input skeletons for AI judgment.

validate.py 的 decision JSON 契约深（schema_version、runner 绑定、七问键名）
——AI 手写时格式试错占验证命令的一半以上（lab e2e 2026-09-12 实测 6 次撞墙）。
本模块把全部机械字段预填成骨架，AI 只填判断字段：

  validate --scaffold   → gates/seven_question_gate/impact 留空待判，
                          其余（target/finding_id/endpoint/runner_summary/
                          refs/report path）全部机器预填合规值

scaffold 是输出器不是入口：校验代码零改动，AI 可以随时手写全量 JSON。
判断字段永远不出现在预填里。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

try:
    from tools.contracts import (
        MACHINE_DECISION_SCHEMA_VERSION,
        SEVEN_QUESTION_DEFINITIONS,
    )
except ImportError:  # pragma: no cover - direct tools/ execution
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from contracts import (  # type: ignore
        MACHINE_DECISION_SCHEMA_VERSION,
        SEVEN_QUESTION_DEFINITIONS,
    )

try:
    from tools.target_paths import canonical_target_value, target_storage_key, validation_finding_key
    from tools.target_store import runtime_store, StoreError
except ImportError:  # pragma: no cover - direct tools/ execution
    from target_paths import canonical_target_value, target_storage_key, validation_finding_key  # type: ignore
    from target_store import runtime_store, StoreError


# validate scaffold 里永远留给 AI 的字段（判断字段，机器不预填值）
VALIDATE_AI_FIELDS_NOTE = (
    "impact / gates / seven_question_gate 是 AI 判断字段——"
    "本骨架留空占位，必须由 AI 显式填写后才可通过 preflight"
)


def _latest_runner_run(repo_root: Path, target: str, finding_id: str) -> str | None:
    """Choose the newest complete linked subject witness, keeping cleanup separate."""
    runs_dir = repo_root / "evidence" / target_storage_key(target) / "validation" / validation_finding_key(finding_id)
    if not runs_dir.is_dir():
        return None
    candidates = [
        path
        for path in runs_dir.glob("*/summary.json")
        if path.is_file()
    ]
    if not candidates:
        return None
    store = runtime_store(repo_root, target)
    finding = store.finding(finding_id)
    linked = {(ref["operation_id"], ref["step"]) for ref in finding["evidence"]}
    for path in sorted(candidates, key=lambda item: item.stat().st_mtime, reverse=True):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            if (not isinstance(payload, dict) or payload.get("finding_id") != finding_id
                    or not isinstance(payload.get("target"), str)
                    or canonical_target_value(payload["target"]) != canonical_target_value(target)
                    or payload.get("cleanup_only") or not payload.get("store_operation_id")):
                continue
            operation_id = payload["store_operation_id"]
            execution = store.execution(operation_id)
            if execution["outcome"] != "complete" or not any(
                (operation_id, row["step"]) in linked
                and (row["endpoint"], row["method"]) == (finding["endpoint"], finding["method"])
                and not row.get("detail", {}).get("cleanup_confirmation")
                for row in execution["observations"]
            ):
                continue
            store.verify_operation(operation_id)
        except (OSError, ValueError, StoreError):
            continue  # A damaged/partial witness cannot hide an earlier valid experiment.
        return str(path.relative_to(repo_root))
    return None


def build_validate_scaffold(
    repo_root: Path,
    findings_dir: Path,
    finding: dict[str, Any],
    *,
    target: str,
) -> dict[str, Any]:
    """Machine-fill every mechanical decision field; leave judgment fields empty."""
    finding_id = str(finding.get("id") or "")
    canonical_endpoint = str(finding.get("url") or finding.get("endpoint") or "")
    runner_summary = _latest_runner_run(repo_root, target, finding_id) or ""
    evidence_refs: list[str] = ([runner_summary] if runner_summary else [])

    scaffold: dict[str, Any] = {
        "schema_version": MACHINE_DECISION_SCHEMA_VERSION,
        "target": target,
        "finding_id": finding_id,
        "endpoint": canonical_endpoint,
        "vuln_class": str(finding.get("family") or finding.get("type") or ""),
        # method 是机械字段：canonical finding 已记录真实 verb，scaffold 照抄。
        # 硬编码 GET 会让原生 POST 发现（record-evidence 路径）永远过不了
        # validate 的 runner method 比对。
        "method": str(finding.get("method") or "GET").strip().upper() or "GET",
        "_scaffold_note": VALIDATE_AI_FIELDS_NOTE,
        "impact": "",
        "gates": {
            key: {"passed": None, "notes": {}}  # AI 显式布尔
            for key in ("gate1", "gate2", "gate3", "gate4")
        },
        "seven_question_gate": {
            "questions": {
                key: {"status": "unknown", "basis": ""}
                for key, _question in SEVEN_QUESTION_DEFINITIONS
            }
        },
        "evidence": {
            "summary": "",
            "runner_summary": runner_summary,
            "refs": evidence_refs,
        },
        "report": {
            # 唯一合规路径：报告必须落在该 finding 自己的目录下
            "path": str((findings_dir / f"{finding_id}-report.md").relative_to(repo_root)),
            "content": "",
        },
    }
    if not runner_summary:
        scaffold["_scaffold_warnings"] = [
            "no registered evidence summary recorded under this finding id — "
            "preserve the existing raw execution and register it with "
            f"`tools/validation_runner.py record-evidence --target {target} --finding-id {finding_id} "
            "--evidence-json FILE --attempt-id ORIGINAL_ATTEMPT` "
            "(add `--expected-operation ORIGINAL_OPERATION` if the attempt was already registered), "
            "then regenerate the scaffold; "
            "do not repeat an execution merely to obtain a summary"
        ]
    return scaffold
