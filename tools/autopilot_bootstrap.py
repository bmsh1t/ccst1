#!/usr/bin/env python3
"""为 Claude inline `/autopilot` 生成只读启动契约。"""

from __future__ import annotations

import json
import shlex
import sys
from pathlib import Path
from typing import Any, Sequence

try:
    from tools.autopilot_args import parse_autopilot_args
    from tools.autopilot_state import build_autopilot_bootstrap_state
    from tools.capability_profile import (
        build_capability_profile,
        unknown_capability_profile,
    )
    from tools.runtime_config import is_ctf_mode_enabled
    from tools.runtime_doctor import KIND_ORDER, compare_runtime
except ModuleNotFoundError:  # 兼容 `python3 tools/autopilot_bootstrap.py` 直接执行
    from autopilot_args import parse_autopilot_args
    from autopilot_state import build_autopilot_bootstrap_state
    from capability_profile import build_capability_profile, unknown_capability_profile
    from runtime_config import is_ctf_mode_enabled
    from runtime_doctor import KIND_ORDER, compare_runtime


SCHEMA_VERSION = 1
REPO_ROOT = Path(__file__).resolve().parents[1]


def _runtime_projection(payload: dict[str, Any]) -> dict[str, Any]:
    """只保留 drift 决策需要的计数，避免把逐文件明细注入 prompt。"""
    kinds = {}
    for item in payload.get("kinds", []) or []:
        if not isinstance(item, dict):
            continue
        kind = str(item.get("kind") or "").strip()
        counts = item.get("counts") if isinstance(item.get("counts"), dict) else {}
        if kind:
            kinds[kind] = {
                key: int(counts.get(key, 0) or 0)
                for key in ("ok", "diff", "missing", "extra")
            }
    return {
        "checked": True,
        "clean": bool(payload.get("clean")),
        "drift_count": int(payload.get("drift_count", 0) or 0),
        "runtime_root": str(payload.get("runtime_root") or ""),
        "kinds": kinds,
    }


def _invocation_batch_projection(arguments: dict[str, Any]) -> dict[str, Any]:
    """Expose the parsed deep batch boundary without asking Claude to reparse flags."""
    raw = arguments.get("invocation_batch")
    batch = raw if isinstance(raw, dict) else {}
    max_lanes = batch.get("max_lanes")
    if not isinstance(max_lanes, int) or isinstance(max_lanes, bool):
        max_lanes = None
    bounded = bool(batch.get("bounded"))
    return {
        "bounded": bounded,
        "max_lanes": max_lanes,
        "handoff": str(
            batch.get("handoff")
            or ("checkpoint_and_handoff_after_max_lanes" if bounded else "normal_finish_condition")
        ),
    }


def _compact_candidate(item: dict[str, Any]) -> dict[str, Any]:
    """投影一个启动候选，丢弃完整 surface/runner payload。"""
    keys = (
        "id",
        "target",
        "url",
        "method",
        "type",
        "lane",
        "status",
        "priority",
        "score",
        "action",
        "command_hint",
        "evidence",
        "evidence_ref",
        "evidence_available",
        "claim_source_file",
        "source_file",
        "claim_target",
        "claim_status",
        "incomplete_fields",
        "title",
        "validation_status",
        "report_status",
        "stop_condition",
        "review_reason",
        "suggested",
        "report_draft_path",
        "report_draft_status",
        "report_draft_placeholder_count",
        "claimed_validation_status",
        "claimed_report_status",
        "lifecycle_status",
        "provenance_reason",
        "required_action",
    )
    compact = {
        key: item[key]
        for key in keys
        if key in item and item[key] not in (None, "", [], {})
    }
    # root-level JSON claims use ``evidence_rubric`` before checkpoint has
    # reconciled them into the canonical structured-finding projection.  Keep
    # the compact bootstrap contract uniform without exposing claim prose or
    # raw evidence payloads.
    rubric = item.get("rubric") if isinstance(item.get("rubric"), dict) else {}
    if not rubric and isinstance(item.get("evidence_rubric"), dict):
        rubric = item["evidence_rubric"]
    if rubric:
        compact["rubric"] = {
            "rubric_id": str(rubric.get("rubric_id") or ""),
            "status": str(rubric.get("status") or ""),
            "ready": bool(rubric.get("ready", False)),
            "score": int(rubric.get("score", 0) or 0),
            "satisfied_count": int(rubric.get("satisfied_count", 0) or 0),
            "total": int(rubric.get("total", 0) or 0),
            "missing_labels": [
                str(value)
                for value in (rubric.get("missing_labels") or [])[:3]
                if str(value).strip()
            ],
            "next_actions": [
                str(value)
                for value in (rubric.get("next_actions") or [])
                if str(value).strip()
            ][:1],
        }
    return compact


def _compact_intel_continuation(value: object) -> dict[str, Any]:
    """保留执行 Intel 下一步所需的最小事实，不注入完整 advisory。"""
    continuation = value if isinstance(value, dict) else {}
    recommended = []
    for item in continuation.get("recommended") or []:
        if not isinstance(item, dict):
            continue
        recommended.append({
            "subject": str(item.get("subject") or ""),
            "intent": str(item.get("intent") or ""),
            "query": str(item.get("query") or ""),
            "reasons": [
                str(reason)
                for reason in (item.get("reasons") or [])[:3]
                if str(reason).strip()
            ],
        })
        if len(recommended) >= 3:
            break

    raw_advisory = continuation.get("advisory")
    advisory = raw_advisory if isinstance(raw_advisory, dict) else {}
    raw_component = advisory.get("component")
    component = raw_component if isinstance(raw_component, dict) else {}
    source_refs = [
        {
            key: ref[key]
            for key in ("source", "id", "url")
            if ref.get(key) not in (None, "")
        }
        for ref in (advisory.get("source_refs") or [])[:3]
        if isinstance(ref, dict)
    ]
    compact_advisory = {}
    if advisory:
        compact_advisory = {
            "id": str(advisory.get("id") or ""),
            "aliases": list(advisory.get("aliases") or [])[:5],
            "component": {
                "name": str(component.get("name") or ""),
                "version": str(component.get("version") or ""),
                "hosts": list(component.get("hosts") or [])[:3],
                "ports": list(component.get("ports") or [])[:5],
            },
            "applicability": str(advisory.get("applicability") or "unknown"),
            "severity": str(advisory.get("severity") or "UNKNOWN"),
            "score_hint": advisory.get("score_hint", 0),
            "source_refs": source_refs,
        }
    return {
        "action": str(continuation.get("action") or "complete"),
        "reason": str(continuation.get("reason") or ""),
        "recommended": recommended,
        "blocked": [
            {
                key: item[key]
                for key in ("subject", "component", "version", "reason")
                if item.get(key) not in (None, "")
            }
            for item in (continuation.get("blocked") or [])[:3]
            if isinstance(item, dict)
        ],
        "advisory": compact_advisory,
    }


def compact_autopilot_state(state: dict[str, Any]) -> dict[str, Any]:
    """生成仅供 startup 路由使用的有界 state 视图。"""
    next_action = str(state.get("next_action") or "")
    structured = state.get("structured_findings") or {}
    structured_next = (
        structured.get("next_owner_revalidation")
        or structured.get("next_validation")
        or structured.get("next_draft_completion")
        or structured.get("next_report")
        or {}
    )
    if structured.get("next_owner_revalidation"):
        structured_next_kind = "owner_revalidation"
    elif structured.get("next_validation"):
        structured_next_kind = "validation"
    elif structured.get("next_draft_completion"):
        structured_next_kind = "draft_completion"
    elif structured.get("next_report"):
        structured_next_kind = "report"
    else:
        structured_next_kind = ""
    runner_next = state.get("validation_runner_next") or {}
    if not runner_next:
        runner_candidates = state.get("validation_runner_candidates") or []
        runner_next = runner_candidates[0] if runner_candidates else {}
    queue_next = state.get("action_queue_next") or {}
    memory_candidate_next = state.get("memory_candidate_next") or {}
    root_claim_next = state.get("root_finding_claim_next") or {}
    recon_artifacts = state.get("recon_artifacts") or {}
    surface_projection = state.get("surface_projection") or {}
    observation_inventory = state.get("observation_inventory") or {}
    batch = state.get("batch") or {}
    intel_continuation = _compact_intel_continuation(state.get("intel_continuation"))

    compact_batch: dict[str, Any] = {}
    if batch:
        for key in ("current_entries", "completed", "failed", "pending"):
            values = batch.get(key) or []
            compact_batch[key] = list(values[:20])
        compact_batch["candidates"] = [
            _compact_candidate(item)
            for item in (batch.get("candidates") or [])[:10]
            if isinstance(item, dict)
        ]
        compact_batch["blocker"] = str(batch.get("blocker") or "")

    return {
        "target_kind": str(state.get("target_kind") or "domain"),
        "next_action": next_action,
        "wait": next_action in {"wait_recon", "wait_scan"},
        "recon": {
            "has_recon": bool(state.get("has_recon")),
            "recon_in_progress": bool(state.get("recon_in_progress")),
            "scan_in_progress": bool(state.get("scan_in_progress")),
            "artifacts_available": bool(recon_artifacts.get("available")),
            "artifacts_ready": bool(recon_artifacts.get("ready")),
            "host_inventory_ready": bool(recon_artifacts.get("host_inventory_ready")),
            "fresh_recon_ready": bool(state.get("fresh_recon_ready")),
            "blocker": str(state.get("recon_blocker") or ""),
        },
        "structured_next": (
            _compact_candidate(structured_next)
            if isinstance(structured_next, dict)
            else {}
        ),
        "structured_next_kind": structured_next_kind,
        "runner_next": (
            _compact_candidate(runner_next)
            if isinstance(runner_next, dict)
            else {}
        ),
        "queue_next": (
            _compact_candidate(queue_next)
            if isinstance(queue_next, dict)
            else {}
        ),
        "memory_candidate_next": (
            _compact_candidate(memory_candidate_next)
            if isinstance(memory_candidate_next, dict)
            else {}
        ),
        # An unreconciled root JSON claim is not a validated finding.  It must
        # still be visible at startup so Claude can run checkpoint, which is
        # the only owner-approved bridge into findings.json/action_queue.
        "root_claim_next": (
            _compact_candidate(root_claim_next)
            if isinstance(root_claim_next, dict)
            else {}
        ),
        "batch": compact_batch,
        "intel_continuation": intel_continuation,
        "surface_projection": {
            key: surface_projection[key]
            for key in ("status", "reason", "path", "refresh_command")
            if surface_projection.get(key) not in (None, "")
        },
        "observation_inventory": {
            key: observation_inventory[key]
            for key in (
                "status",
                "reason",
                "needs_sync",
                "total",
                "present",
                "untouched",
                "reviewing",
                "reviewed",
                "parked",
                "stale",
            )
            if key in observation_inventory
        },
        "surface_candidates": [
            _compact_candidate(item)
            for item in (
                state.get("surface_review_candidates")
                or state.get("recommended_targets")
                or []
            )[:5]
            if isinstance(item, dict)
        ],
    }


def build_autopilot_bootstrap(
    argv: Sequence[str],
    *,
    cwd: str | Path | None = None,
    repo_root: str | Path | None = None,
    runtime_root: str | Path | None = None,
) -> dict[str, Any]:
    """按 args -> runtime drift -> target state 顺序构建只读启动结果。"""
    resolved_repo = Path(repo_root or REPO_ROOT).resolve()
    invocation_cwd = Path(cwd or Path.cwd()).resolve()
    arguments = parse_autopilot_args(argv, cwd=invocation_cwd)
    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "action": arguments["action"],
        "repo_root": str(resolved_repo),
        "repo_root_shell": shlex.quote(str(resolved_repo)),
        "arguments": arguments,
        # This is intentionally duplicated as a tiny top-level projection:
        # the command must consume the parser result, not reinterpret raw
        # slash tokens while deciding when a deep invocation hands off.
        "invocation_batch": _invocation_batch_projection(arguments),
        "runtime": {
            "checked": False,
            "clean": None,
            "drift_count": 0,
            "runtime_root": "",
            "kinds": {},
        },
        "capabilities": unknown_capability_profile(),
        "ctf_mode": False,
    }

    # 参数 gate 必须在 runtime/state 读取前结束，避免 invalid slash 触发目标工作流。
    if arguments["action"] != "continue":
        return payload

    runtime = compare_runtime(
        repo_root=resolved_repo,
        runtime_root=runtime_root,
        kinds=list(KIND_ORDER),
    )
    payload["runtime"] = _runtime_projection(runtime)
    if not runtime["clean"]:
        payload["action"] = "stop_runtime_drift"
        return payload

    try:
        payload["capabilities"] = build_capability_profile(resolved_repo)
    except Exception:
        # 能力快照只能影响推荐路径，任何探测异常都不能阻断 target state。
        payload["capabilities"] = unknown_capability_profile("profile-error")

    payload["ctf_mode"] = is_ctf_mode_enabled(resolved_repo)
    state = build_autopilot_bootstrap_state(
        str(resolved_repo),
        str(arguments["target"]),
    )
    payload["state"] = compact_autopilot_state(state)
    payload["action"] = "continue"
    return payload


def render_autopilot_bootstrap_json(payload: dict[str, Any]) -> str:
    """输出适合 Claude dynamic expansion 的单行稳定 JSON。"""
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def main(argv: Sequence[str] | None = None) -> int:
    cli_argv = list(sys.argv[1:] if argv is None else argv)
    compact = bool(cli_argv and cli_argv[0] == "--json")
    if compact:
        cli_argv.pop(0)
    if cli_argv and cli_argv[0] == "--":
        cli_argv.pop(0)

    payload = build_autopilot_bootstrap(cli_argv)
    if compact:
        print(render_autopilot_bootstrap_json(payload))
    else:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
