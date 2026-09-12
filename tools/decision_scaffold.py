#!/usr/bin/env python3
"""Decision-JSON scaffolds: machine-generated input skeletons for AI judgment.

validate.py / action_queue resolve 的 decision JSON 契约深（schema_version、
runner 绑定、七问键名、continuation 四字段）——AI 手写时格式试错占验证命令的
一半以上（lab e2e 2026-09-12 实测 6 次撞墙）。本模块把全部机械字段预填成
骨架，AI 只填判断字段：

  validate --scaffold   → gates/seven_question_gate/cvss/impact 留空待判，
                          其余（target/finding_id/endpoint/runner_summary/
                          refs/report path）全部机器预填合规值
  resolve --scaffold    → continuation 四字段的骨架（dimension 从 metadata 预填）

scaffold 是输出器不是入口：校验代码零改动，AI 可以随时手写全量 JSON。
判断字段永远不出现在预填里（与 claim 模板同一分桶纪律）。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

try:
    from tools.validate import (
        MACHINE_DECISION_SCHEMA_VERSION,
        SEVEN_QUESTION_DEFINITIONS,
    )
except ImportError:  # pragma: no cover - direct tools/ execution
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from validate import (  # type: ignore
        MACHINE_DECISION_SCHEMA_VERSION,
        SEVEN_QUESTION_DEFINITIONS,
    )

try:
    from tools.target_paths import target_storage_key
except ImportError:  # pragma: no cover - direct tools/ execution
    from target_paths import target_storage_key  # type: ignore


# validate scaffold 里永远留给 AI 的字段（判断字段，机器不预填值）
VALIDATE_AI_FIELDS_NOTE = (
    "impact / gates / seven_question_gate / cvss 是 AI 判断字段——"
    "本骨架留空占位，必须由 AI 显式填写后才可通过 preflight"
)


def _latest_runner_run(repo_root: Path, target: str, finding_id: str) -> str | None:
    """Return the newest on-disk runner run recorded under this finding id."""
    runs_dir = repo_root / "evidence" / target_storage_key(target) / "validation" / finding_id
    if not runs_dir.is_dir():
        return None
    candidates = [
        path
        for path in runs_dir.glob("*/summary.json")
        if path.is_file()
    ]
    if not candidates:
        return None
    latest = max(candidates, key=lambda path: path.stat().st_mtime)
    try:
        payload = json.loads(latest.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return None
    if payload.get("finding_id") != finding_id:
        return None
    return str(latest.relative_to(repo_root))


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
        "vuln_class": str(finding.get("type") or ""),
        "method": "GET",
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
        "cvss": {"score": 0.0, "vector": ""},
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
            "no on-disk runner run recorded under this finding id — "
            f"run `tools/validation_runner.py request-diff --finding-id {finding_id}` "
            "first, then regenerate the scaffold"
        ]
    return scaffold


def build_resolve_scaffold(action: dict[str, Any]) -> dict[str, Any]:
    """Continuation skeleton with dimension pre-filled from action metadata."""
    metadata = action.get("metadata") if isinstance(action.get("metadata"), dict) else {}
    return {
        "_scaffold_note": (
            "continuation 四字段中 reason/expected_learning/question 是 AI 判断字段；"
            "dimension 从 action metadata 预填可覆盖"
        ),
        "continuation": {
            "kind": "sibling",
            "dimension": str(metadata.get("active_dimension") or ""),
            "question": "",
            "expected_learning": "",
            "reason": "",
        },
        "result": "",
        "evidence": "",
    }
