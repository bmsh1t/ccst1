#!/usr/bin/env python3
"""为 Claude inline `/autopilot` 生成只读启动契约。"""

from __future__ import annotations

import json
import shlex
import sys
from pathlib import Path
from typing import Any, Sequence

try:
    from tools.action_queue import activation_contract_projection
    from tools.autopilot_args import parse_autopilot_args
    from tools.autopilot_continuation import load_continuation
    from tools.autopilot_state import build_autopilot_bootstrap_state, describe_next_step
    from tools.capability_profile import (
        build_capability_profile,
        unknown_capability_profile,
    )
    from tools.runtime_config import is_ctf_mode_enabled
    from tools.runtime_doctor import KIND_ORDER, compare_runtime
    from tools.scope_context import ScopeContext, ScopeContextError
except ModuleNotFoundError:  # 兼容 `python3 tools/autopilot_bootstrap.py` 直接执行
    from action_queue import activation_contract_projection  # type: ignore
    from autopilot_args import parse_autopilot_args
    from autopilot_continuation import load_continuation
    from autopilot_state import build_autopilot_bootstrap_state, describe_next_step
    from capability_profile import build_capability_profile, unknown_capability_profile
    from runtime_config import is_ctf_mode_enabled
    from runtime_doctor import KIND_ORDER, compare_runtime
    from scope_context import ScopeContext, ScopeContextError


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
    def bounded_items(name: str) -> list[dict[str, str]]:
        return [
            {
                "kind": str(item.get("kind") or ""),
                "status": str(item.get("status") or ""),
                "relative_path": str(item.get("relative_path") or ""),
            }
            for item in (payload.get(name) or [])[:8]
            if isinstance(item, dict)
        ]

    manifest = payload.get("critical_manifest") if isinstance(payload.get("critical_manifest"), dict) else {}
    critical_clean = bool(payload.get("critical_clean", payload.get("clean")))
    return {
        "checked": True,
        "clean": bool(payload.get("clean")),
        "critical_clean": critical_clean,
        "drift_count": int(payload.get("drift_count", 0) or 0),
        "critical_drift_count": int(payload.get("critical_drift_count", 0) or 0),
        "advisory_drift_count": int(payload.get("advisory_drift_count", 0) or 0),
        "critical_manifest": {
            "schema_version": int(manifest.get("schema_version", 0) or 0),
            "status": str(manifest.get("status") or "unknown"),
            "sha256": str(manifest.get("sha256") or ""),
            "mcp_contracts": [str(item) for item in (manifest.get("mcp_contracts") or [])[:8]],
        },
        "critical_drift": bounded_items("critical_drift"),
        "missing_critical": bounded_items("missing_critical"),
        "advisory_drift": bounded_items("advisory_drift"),
        "runtime_root": str(payload.get("runtime_root") or ""),
        "kinds": kinds,
    }


def _scope_projection(context: ScopeContext) -> dict[str, Any]:
    """Expose only bounded scope identity; never load discovery artifacts."""
    summary = context.summary()
    return {
        "scope_ref": context.source_ref or context.root_target,
        "scope_hash": context.scope_hash,
        "summary": summary,
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
        "owner",
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
        "source",
        "category",
        "artifact",
        "next_action",
        "rationale",
        "parent_scope_ref",
        "parent_scope_hash",
        "continuation_create_args",
        "impact_hint",
        "expected_information_gain",
        "closure_blocking",
        "evidence_status",
        "continuity",
        "runnable",
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
    raw_group = continuation.get("review_group")
    group = raw_group if isinstance(raw_group, dict) else {}
    raw_component = group.get("component") if isinstance(group.get("component"), dict) else {}
    compact_group = {}
    if group:
        compact_group = {
            "group_key": str(group.get("group_key") or ""),
            "component": {
                "name": str(raw_component.get("name") or ""),
                "version": str(raw_component.get("version") or ""),
            },
            "advisory_count": int(group.get("advisory_count", 0) or 0),
            "representative_count": int(group.get("representative_count", 0) or 0),
            "omitted_count": int(group.get("omitted_count", 0) or 0),
            "reactivate_when": str(group.get("reactivate_when") or "")[:240],
            "owner_binding": group.get("owner_binding") if isinstance(group.get("owner_binding"), dict) else {},
            "query_command": str(group.get("query_command") or "")[:500],
            "queue_metadata": group.get("queue_metadata") if isinstance(group.get("queue_metadata"), dict) else {},
        }
    raw_projection = continuation.get("review_projection")
    projection = raw_projection if isinstance(raw_projection, dict) else {}
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
        "review_group": compact_group,
        "review_projection": {
            "available": bool(projection.get("available")),
            "path": str(projection.get("path") or "")[:300],
            "group_count": int(projection.get("group_count", 0) or 0),
            "advisory_count": int(projection.get("advisory_count", 0) or 0),
            "omitted_group_count": int(projection.get("omitted_group_count", 0) or 0),
            "owner_binding": projection.get("owner_binding") if isinstance(projection.get("owner_binding"), dict) else {},
        },
    }


_LANE_CONTRACTS = {
    "state-and-queue": (
        "docs/autopilot-lanes.md#state-and-queue",
        "durable state or Action Queue work is authoritative",
    ),
    "recon-surface": (
        "docs/autopilot-lanes.md#recon-and-surface",
        "discovery, surface, or evidence collection is next",
    ),
    "browser-source-js": (
        "docs/autopilot-lanes.md#browser-source-and-js",
        "browser, source, or JavaScript evidence is required",
    ),
    "software-intel": (
        "docs/autopilot-lanes.md#software-and-intel",
        "component or advisory intelligence is next",
    ),
    "workflow-case": (
        "docs/autopilot-lanes.md#workflow-timing-and-case-state",
        "workflow, timing, or case-state evidence is next",
    ),
    "controller": (
        "commands/autopilot.md#state-consumption-loop",
        "no specialized lane is selected by the current state",
    ),
}


def _lane_contract_projection(state: dict[str, Any]) -> dict[str, str]:
    """Return one on-demand lane reference instead of embedding every lane rule."""
    action = str(state.get("next_action") or "")
    if action in {
        "run_recon",
        "run_batch_recon",
        "select_completed_domain",
        "prepare_surface_context",
        "collect_candidate_evidence",
        "hunt_p1",
    }:
        lane = "recon-surface"
    elif action in {
        "wait_recon",
        "wait_scan",
        "revalidate_finding_owner",
        "validate_finding",
        "resume_action_queue",
        "review_validation_candidate",
        "complete_report_draft",
        "report_finding",
        "recon_no_live_hosts",
    }:
        lane = "state-and-queue"
    elif action == "resume_case_state":
        lane = "workflow-case"
    elif action in {"run_intel", "collect_web_intel", "test_advisory_applicability", "review_intel_group"}:
        lane = "software-intel"
    elif state.get("browser_required"):
        lane = "browser-source-js"
    else:
        lane = "controller"
    ref, reason = _LANE_CONTRACTS[lane]
    return {"id": lane, "ref": ref, "reason": reason}


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
    cidr_continuation = recon_artifacts.get("cidr_continuation") or {}
    surface_projection = state.get("surface_projection") or {}
    observation_inventory = state.get("observation_inventory") or {}
    json_inject = state.get("json_inject") or {}
    sql_matrix = state.get("sql_matrix") or {}
    js_intel = state.get("js_intel") or {}
    case_state = state.get("case_state") or {}
    batch = state.get("batch") or {}
    intel_continuation = _compact_intel_continuation(state.get("intel_continuation"))
    compact_surface_projection = {
        key: surface_projection[key]
        for key in ("status", "reason", "path", "refresh_command")
        if surface_projection.get(key) not in (None, "")
    }
    raw_surface_continuation = surface_projection.get("continuation")
    if isinstance(raw_surface_continuation, dict):
        bounded_surface_continuation = {
            key: raw_surface_continuation[key]
            for key in ("available", "next_cursor", "command")
            if raw_surface_continuation.get(key) not in (None, "")
        }
        if bounded_surface_continuation:
            compact_surface_projection["continuation"] = bounded_surface_continuation
    workflow_leads = []
    for raw in ((state.get("surface") or {}).get("workflow_leads") or [])[:3]:
        try:
            item = json.loads(raw) if isinstance(raw, str) else raw
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            workflow_leads.append(_compact_candidate(item))
    enrichment_hints = [
        {
            key: item[key]
            for key in ("tool", "mode", "reason")
            if item.get(key) not in (None, "")
        }
        for item in (state.get("enrichment_hints") or [])
        if isinstance(item, dict) and item.get("tool") == "recon-ranker"
    ][:1]

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
        if isinstance(batch.get("scope"), dict):
            compact_batch["scope"] = {
                key: batch["scope"][key]
                for key in ("status", "scope_ref", "scope_hash", "summary", "reason")
                if key in batch["scope"]
            }

    return {
        "target_kind": str(state.get("target_kind") or "domain"),
        "scope": {
            key: (state.get("scope") or {})[key]
            for key in ("status", "scope_ref", "scope_hash", "summary", "reason")
            if key in (state.get("scope") or {})
        },
        "continuation": {
            key: (state.get("continuation") or {})[key]
            for key in (
                "invocation_id",
                "selected_target",
                "parent_target",
                "scope_ref",
                "scope_hash",
                "auth_private_ref",
            )
            if key in (state.get("continuation") or {})
        },
        "next_action": next_action,
        "fallback_action": str(state.get("fallback_action") or next_action),
        "selection_mode": str(state.get("selection_mode") or "fallback"),
        "hard_gate": {
            key: (state.get("hard_gate") or {})[key]
            for key in ("action", "reason")
            if key in (state.get("hard_gate") or {})
        },
        "next_step": describe_next_step(state),
        "lane_contract": _lane_contract_projection(state),
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
            "cidr_continuation": {
                key: cidr_continuation.get(key)
                for key in ("status", "next_offset", "remaining_hosts", "reason")
                if cidr_continuation.get(key) not in (None, "")
            },
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
        "browser_required": bool(state.get("browser_required")),
        "browser_evidence": {
            key: (state.get("browser_evidence") or {})[key]
            for key in ("present", "ready", "status", "auth_required", "auth_state")
            if key in (state.get("browser_evidence") or {})
        },
        "surface_projection": compact_surface_projection,
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
                "by_kind",
            )
            if key in observation_inventory
        },
        "json_inject": {
            key: json_inject[key]
            for key in (
                "status", "reason", "path", "schema_version", "input_fingerprint",
                "endpoint_count", "probed_endpoint_count", "request_count", "hit_count",
                "waf_observation_count", "transport_error_count", "request_budget",
                "batch_start_endpoint_index", "batch_tested_endpoint_count", "resumed", "cursor",
                "waf_plan_ref", "waf_plan_sha256", "waf_plan_variant_count",
                "waf_ai_variants_executed", "budget_exhausted", "skipped",
            )
            if key in json_inject
        },
        "sql_matrix": {
            lane: {
                **{
                    key: item[key]
                    for key in (
                        "status", "reason", "path", "input_fingerprint",
                        "endpoint_count", "probed_endpoint_count", "request_count",
                        "request_budget", "hit_count", "candidate_count",
                        "batch_start_endpoint_index", "batch_tested_endpoint_count", "resumed", "cursor",
                        "waf_observation_count", "transport_error_count",
                        "waf_plan_ref", "waf_plan_sha256", "waf_plan_variant_count",
                        "waf_ai_variants_executed", "budget_exhausted", "source_paths",
                    )
                    if key in item
                },
                "candidates": [
                    {
                        key: candidate[key]
                        for key in ("endpoint", "field", "class", "signal")
                        if key in candidate
                    }
                    for candidate in (item.get("candidates") or [])[:5]
                    if isinstance(candidate, dict)
                ],
            }
            for lane, item in sql_matrix.items()
            if lane in {"query", "form"} and isinstance(item, dict)
        },
        "js_intel": {
            key: js_intel[key]
            for key in (
                "status", "reason", "path", "present", "hypotheses_path",
                "hypothesis_count", "disposition_path",
            )
            if key in js_intel
        },
        "case_state": {
            key: case_state[key]
            for key in (
                "status", "path", "actors", "sessions", "authz_coverage", "objects",
                "open_hypotheses", "pending_validation_backlog", "top_next_action",
            )
            if key in case_state
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
        "priority_frontier": [
            _compact_candidate(item)
            for item in (state.get("priority_frontier") or [])
            if isinstance(item, dict)
        ],
        "workflow_leads": workflow_leads,
        "enrichment_hints": enrichment_hints,
    }


def build_autopilot_bootstrap(
    argv: Sequence[str],
    *,
    cwd: str | Path | None = None,
    repo_root: str | Path | None = None,
    runtime_root: str | Path | None = None,
    round_defaults: bool = False,
) -> dict[str, Any]:
    """按 args -> runtime drift -> target state 顺序构建只读启动结果。"""
    resolved_repo = Path(repo_root or REPO_ROOT).resolve()
    invocation_cwd = Path(cwd or Path.cwd()).resolve()
    arguments = parse_autopilot_args(
        argv,
        cwd=invocation_cwd,
        round_defaults=round_defaults,
    )
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
        "scope": {},
        "continuation": {},
        "runtime": {
            "checked": False,
            "clean": None,
            "critical_clean": None,
            "drift_count": 0,
            "critical_drift_count": 0,
            "advisory_drift_count": 0,
            "critical_manifest": {},
            "critical_drift": [],
            "missing_critical": [],
            "advisory_drift": [],
            "runtime_root": "",
            "kinds": {},
        },
        "capabilities": unknown_capability_profile(),
        "ctf_mode": False,
        # The Queue remains the contract owner; expose its bounded projection
        # so the inline controller does not reconstruct claim fields from prose.
        "activation_contract": activation_contract_projection(),
    }

    # 参数 gate 必须在 runtime/state 读取前结束，避免 invalid slash 触发目标工作流。
    if arguments["action"] != "continue":
        return payload

    # Surface the repo-local lab flag before any later stop gate.  A runtime
    # drift must not make an enabled CTF workspace look like ordinary mode.
    payload["ctf_mode"] = is_ctf_mode_enabled(resolved_repo)

    continuation = None
    try:
        if arguments.get("context_file"):
            continuation = load_continuation(
                resolved_repo,
                str(arguments["context_file"]),
                selected_target=str(arguments["target"]),
            )
            scope_context = continuation["scope_context"]
            continuation_auth = str(continuation.get("auth_file") or "")
            if arguments.get("auth_file") and (
                not continuation_auth
                or Path(str(arguments["auth_file"])).resolve() != Path(continuation_auth)
            ):
                raise ValueError("explicit auth file conflicts with batch continuation")
            if continuation_auth:
                arguments["auth_file"] = continuation_auth
                arguments["auth_file_shell"] = shlex.quote(continuation_auth)
                arguments["hunt_auth_flags"] = ["--auth-file", continuation_auth]
            public_continuation = continuation["continuation"]
            payload["continuation"] = {
                key: public_continuation[key]
                for key in (
                    "invocation_id",
                    "selected_target",
                    "parent_target",
                    "scope_ref",
                    "scope_hash",
                    "auth_private_ref",
                )
                if public_continuation.get(key) not in (None, "")
            }
        else:
            scope_context = ScopeContext.from_target(arguments["target"])
    except ScopeContextError as exc:
        payload["action"] = "stop_invalid_scope"
        payload["error"] = {
            "type": type(exc).__name__,
            "reason": " ".join(str(exc).split())[:500],
        }
        return payload
    except ValueError as exc:
        payload["action"] = "stop_invalid_context"
        payload["error"] = {
            "type": type(exc).__name__,
            "reason": " ".join(str(exc).split())[:500],
        }
        return payload
    payload["scope"] = _scope_projection(scope_context)

    try:
        runtime = compare_runtime(
            repo_root=resolved_repo,
            runtime_root=runtime_root,
            kinds=list(KIND_ORDER),
        )
    except (OSError, ValueError) as exc:
        payload["action"] = "stop_runtime_error"
        payload["error"] = {
            "type": type(exc).__name__,
            "reason": " ".join(str(exc).split())[:500],
        }
        return payload
    payload["runtime"] = _runtime_projection(runtime)
    if not bool(runtime.get("critical_clean", runtime.get("clean"))):
        payload["action"] = "stop_runtime_drift"
        return payload

    try:
        payload["capabilities"] = build_capability_profile(resolved_repo)
    except Exception:
        # 能力快照只能影响推荐路径，任何探测异常都不能阻断 target state。
        payload["capabilities"] = unknown_capability_profile("profile-error")

    try:
        state = build_autopilot_bootstrap_state(
            str(resolved_repo),
            str(arguments["target"]),
        )
        if arguments.get("auth_file") and state.get("target_kind") == "list":
            for candidate in (state.get("batch") or {}).get("candidates") or []:
                candidate.setdefault("continuation_create_args", []).extend(
                    ["--auth-file", str(arguments["auth_file"])]
                )
        if continuation is not None:
            state["scope"] = {"status": "valid", **_scope_projection(scope_context)}
            state["continuation"] = payload["continuation"]
        payload["state"] = compact_autopilot_state(state)
    except (OSError, ValueError) as exc:
        payload["action"] = "stop_state_error"
        payload["error"] = {
            "type": type(exc).__name__,
            "reason": " ".join(str(exc).split())[:500],
        }
        return payload
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
    round_defaults = bool(cli_argv and cli_argv[0] == "--round-defaults")
    if round_defaults:
        cli_argv.pop(0)
    if cli_argv and cli_argv[0] == "--":
        cli_argv.pop(0)

    payload = build_autopilot_bootstrap(cli_argv, round_defaults=round_defaults)
    if compact:
        print(render_autopilot_bootstrap_json(payload))
    else:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
