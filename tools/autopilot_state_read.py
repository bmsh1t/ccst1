#!/usr/bin/env python3
"""Autopilot state artifact readers (extracted module).

从 autopilot_state.py 纯搬动（零逻辑变更，09-11-simple-efficient-refactor 批次 7）：
按 artifact 形态的磁盘读取与各自投影构建——json_inject/scanner/sql_matrix/
case_state/goal_memory/batch 清单。autopilot_state 保留 re-export。
"""

from __future__ import annotations

import json
from pathlib import Path

import hashlib
import os
import re

try:
    from tools.closure_resolver import canonical_endpoint_path
    from tools.target_case_state import (
        summary as build_case_state_summary,
    )
    from tools.target_memory import load_goal_memory
    from tools.target_paths import canonical_target_value, target_storage_key
    from tools.target_store import runtime_store
except ImportError:  # pragma: no cover - direct tools/ execution
    from closure_resolver import canonical_endpoint_path  # type: ignore
    from target_case_state import (  # type: ignore
        summary as build_case_state_summary,
    )
    from target_memory import load_goal_memory  # type: ignore
    from target_paths import canonical_target_value, target_storage_key  # type: ignore
    from target_store import runtime_store  # type: ignore

_SQL_MATRIX_STATUSES = {"complete_no_hit", "candidate_pending", "partial", "invalid_input"}
_SQL_MATRIX_LANES = {"query", "form"}


def _bounded_count(value: object) -> int:
    try:
        value = int(value or 0)
    except (TypeError, ValueError):
        return 0
    return max(0, min(value, 1_000_000))
def _probe_cursor_projection(value: object) -> dict:
    if not isinstance(value, dict):
        return {}
    deferred = value.get("deferred_endpoint_indices")
    return {
        "schema_version": _bounded_count(value.get("schema_version")),
        "input_fingerprint": str(value.get("input_fingerprint") or "")[:64],
        "endpoint_count": _bounded_count(value.get("endpoint_count")),
        "next_endpoint_index": _bounded_count(value.get("next_endpoint_index")),
        "deferred_endpoint_count": len(deferred) if isinstance(deferred, list) else 0,
        "remaining_endpoint_count": _bounded_count(value.get("remaining_endpoint_count")),
        "coverage_complete": bool(value.get("coverage_complete")),
    }
def _probe_cursor_valid(value: object, input_fingerprint: str, endpoint_count: int) -> bool:
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        return False
    if value.get("input_fingerprint") != input_fingerprint or value.get("endpoint_count") != endpoint_count:
        return False
    start_index = value.get("next_endpoint_index")
    deferred = value.get("deferred_endpoint_indices")
    if not isinstance(value.get("coverage_complete"), bool):
        return False
    if isinstance(start_index, bool) or not 0 <= start_index <= endpoint_count:
        return False
    if not isinstance(deferred, list) or any(
        isinstance(item, bool) or not isinstance(item, int) or not 0 <= item < endpoint_count
        for item in deferred
    ) or len(set(deferred)) != len(deferred):
        return False
    remaining = value.get("remaining_endpoint_count")
    expected = len(deferred) + max(0, endpoint_count - start_index)
    return (
        isinstance(remaining, int)
        and not isinstance(remaining, bool)
        and remaining == expected
        and value.get("coverage_complete") == (expected == 0)
    )
def _has_any_artifact(*paths: str) -> bool:
    """Return whether any provided artifact path exists and is non-empty."""
    for path in paths:
        if not path:
            continue
        if os.path.isfile(path):
            try:
                if os.path.getsize(path) > 0:
                    return True
            except OSError:
                continue
        elif os.path.isdir(path):
            return True
    return False


def _load_json_inject_projection(repo_root: str, target: str) -> dict:
    """Read only the bounded JSON probe summary; malformed data stays partial."""
    path = Path(repo_root) / "findings" / target_storage_key(target) / "poc" / "json_inject" / "summary.json"
    projection = {"status": "not_run", "path": str(path), "present": path.is_file()}
    if not path.is_file():
        return projection
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        projection.update({"status": "partial", "reason": "malformed_summary"})
        return projection
    if not isinstance(payload, dict) or payload.get("kind") != "json_inject_summary":
        projection.update({"status": "partial", "reason": "invalid_summary"})
        return projection
    if canonical_target_value(str(payload.get("target") or "")) != canonical_target_value(target):
        projection.update({"status": "partial", "reason": "target_mismatch"})
        return projection
    status = str(payload.get("status") or "partial")
    fingerprint = str(payload.get("input_fingerprint") or "")
    try:
        schema_version = int(payload.get("schema_version", 0) or 0)
    except (TypeError, ValueError):
        # 审计 F10：可选旧摘要的字段类型错误降级为 partial（带修复指针），
        # 不升级为整个状态视图读取失败。可选材料损坏 ≠ 状态不可用。
        projection.update({
            "status": "partial",
            "reason": "invalid_schema_version",
        })
        return projection
    if (
        schema_version < 2
        or status not in {"complete_no_hit", "candidate_pending", "partial", "invalid_input"}
        or not re.fullmatch(r"[0-9a-f]{64}", fingerprint)
        or (
            str(payload.get("waf_plan_sha256") or "")
            and not re.fullmatch(r"[0-9a-f]{64}", str(payload.get("waf_plan_sha256") or ""))
        )
    ):
        status = "partial"
    valid_source_paths: list[str] = []
    valid_source_refs: list[dict[str, str]] = []
    repo = Path(repo_root).resolve()
    target_key = target_storage_key(target)
    for binding in payload.get("source_bindings") or []:
        if not isinstance(binding, dict):
            status = "partial"
            projection["reason"] = "stale_source_binding"
            break
        source = Path(str(binding.get("path") or ""))
        source = source if source.is_absolute() else Path(repo_root) / source
        try:
            relative = source.resolve().relative_to(repo)
            current = hashlib.sha256(source.read_bytes()).hexdigest()
        except (OSError, ValueError):
            current = ""
            relative = None
        if (
            current != str(binding.get("sha256") or "")
            or relative is None
            or target_key not in relative.parts
        ):
            status = "partial"
            projection["reason"] = "stale_source_binding"
            break
        binding_path = str(binding.get("path") or "")[:300]
        valid_source_paths.append(binding_path)
        kind = str(binding.get("kind") or "").strip().lower()
        if kind in {"endpoints", "js-intel", "waf-plan"}:
            valid_source_refs.append({"kind": kind, "path": binding_path})
    source_bindings = payload.get("source_bindings")
    if not isinstance(source_bindings, list):
        source_bindings = []
    projection.update({
        "status": status,
        "schema_version": int(payload.get("schema_version", 0) or 0),
        "input_fingerprint": fingerprint,
        "endpoint_count": int(payload.get("endpoint_count", 0) or 0),
        "probed_endpoint_count": int(payload.get("probed_endpoint_count", 0) or 0),
        "request_count": int(payload.get("request_count", 0) or 0),
        "hit_count": int(payload.get("hit_count", 0) or 0),
        "waf_observation_count": int(payload.get("waf_observation_count", 0) or 0),
        "batch_start_endpoint_index": _bounded_count(payload.get("batch_start_endpoint_index")),
        "batch_tested_endpoint_count": _bounded_count(payload.get("batch_tested_endpoint_count")),
        "resumed": bool(payload.get("resumed")),
        "cursor": _probe_cursor_projection(payload.get("cursor")),
        "waf_plan_ref": str(payload.get("waf_plan_ref") or "")[:300],
        "waf_plan_sha256": str(payload.get("waf_plan_sha256") or ""),
        "waf_plan_variant_count": _bounded_count(payload.get("waf_plan_variant_count")),
        "waf_ai_variants_executed": _bounded_count(payload.get("waf_ai_variants_executed")),
        "transport_error_count": int(payload.get("transport_error_count", 0) or 0),
        "source_paths": valid_source_paths[:3],
        "source_refs": valid_source_refs[:3],
        "skipped": {
            key: int((payload.get("skipped") or {}).get(key, 0) or 0)
            for key in ("out_of_scope", "unsupported_method", "invalid_url", "out_of_scope_redirect")
        },
    })
    if payload.get("cursor") is not None and not _probe_cursor_valid(
        payload.get("cursor"), fingerprint, int(payload.get("endpoint_count", 0) or 0)
    ):
        projection["status"] = "partial"
        projection["reason"] = "invalid_cursor"
    return projection


def _scanner_lane_accounting(item: dict) -> tuple[int, int, int, bool]:
    """Normalize Scanner counts without truncation or erasing prior invalidity."""
    counts = []
    valid = item.get("accounting_valid", True) is True
    for key in ("input_total", "selected", "remaining"):
        try:
            value = item.get(key)
            if isinstance(value, bool) or not isinstance(value, (int, str)):
                raise ValueError
            counts.append(int(value))
        except ValueError:
            counts.append(0)
            valid = False
    input_total, selected, remaining = counts
    valid = valid and min(counts) >= 0 and input_total == selected + remaining
    return input_total, selected, remaining, valid


def _load_scanner_summary_projection(repo_root: str, target: str) -> dict:
    """Load bounded scanner lane accounting without treating candidates as tests."""
    path = Path(repo_root) / "findings" / target_storage_key(target) / "summary.json"
    projection = {"status": "missing", "path": str(path), "lanes": {}}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return projection
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {**projection, "status": "partial"}
    if not isinstance(payload, dict):
        return {**projection, "status": "partial"}
    try:
        if canonical_target_value(str(payload.get("target") or "")) != canonical_target_value(target):
            return {**projection, "status": "partial"}
    except ValueError:
        return {**projection, "status": "partial"}
    if "lane_coverage" not in payload:
        return projection
    raw_lanes = payload["lane_coverage"]
    if not isinstance(raw_lanes, dict):
        return {**projection, "status": "partial"}
    lanes = {}
    projection_status = "valid"
    for name, item in raw_lanes.items():
        if not isinstance(item, dict):
            projection_status = "partial"
            continue
        input_total, selected, remaining, accounting_valid = _scanner_lane_accounting(item)
        if not accounting_valid:
            projection_status = "partial"
        lanes[str(name)] = {
            "lane": str(item.get("lane") or name),
            "execution_kind": str(item.get("execution_kind") or "unknown"),
            "status": str(item.get("status") or "unknown"),
            "input_total": input_total,
            "selected": selected,
            "remaining": remaining,
            "continuation": " ".join(str(item.get("continuation") or "").split()),
            "closure_blocking": bool(item.get("closure_blocking")),
            "accounting_valid": accounting_valid,
        }
    return {"status": projection_status, "path": str(path), "lanes": lanes}


def _load_sql_matrix_projection(repo_root: str, target: str, lane: str | None = None) -> dict:
    """Read a secret-free query/form SQL summary and reject stale inputs."""
    if lane is None:
        return _load_sql_matrix_projections(repo_root, target)
    path = Path(repo_root) / "findings" / target_storage_key(target) / "poc" / "sql_matrix" / lane / "summary.json"
    projection = {"status": "not_run", "lane": lane, "path": str(path), "present": path.is_file()}
    if lane not in _SQL_MATRIX_LANES:
        return {"status": "partial", "lane": lane, "path": str(path), "reason": "invalid_lane", "present": False}
    if not path.is_file():
        return projection
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        projection.update({"status": "partial", "reason": "malformed_summary"})
        return projection
    if not isinstance(payload, dict) or payload.get("kind") != "sql_matrix_summary":
        projection.update({"status": "partial", "reason": "invalid_summary"})
        return projection
    if canonical_target_value(str(payload.get("target") or "")) != canonical_target_value(target):
        projection.update({"status": "partial", "reason": "target_mismatch"})
        return projection
    if str(payload.get("lane") or "").strip().lower() != lane:
        projection.update({"status": "partial", "reason": "lane_mismatch"})
        return projection
    status = str(payload.get("status") or "partial").strip().lower()
    fingerprint = str(payload.get("input_fingerprint") or "")
    reason = ""
    try:
        schema_version = int(payload.get("schema_version", 0) or 0)
    except (TypeError, ValueError):
        schema_version = 0
    if schema_version < 1:
        reason = "invalid_schema"
    elif status not in _SQL_MATRIX_STATUSES:
        reason = "invalid_status"
    elif not re.fullmatch(r"[0-9a-f]{64}", fingerprint):
        reason = "missing_input_fingerprint"
    elif str(payload.get("waf_plan_sha256") or "") and not re.fullmatch(
        r"[0-9a-f]{64}", str(payload.get("waf_plan_sha256") or "")
    ):
        reason = "invalid_waf_plan_hash"
    bindings = payload.get("source_bindings")
    if not isinstance(bindings, list) or not bindings:
        reason = reason or "missing_source_binding"
    else:
        for binding in bindings:
            if not isinstance(binding, dict) or not str(binding.get("path") or "") or not re.fullmatch(r"[0-9a-f]{64}", str(binding.get("sha256") or "")):
                reason = "invalid_source_binding"
                break
            source = Path(str(binding["path"]))
            source = source if source.is_absolute() else Path(repo_root) / source
            try:
                current = hashlib.sha256(source.read_bytes()).hexdigest()
            except OSError:
                current = ""
            if current != str(binding.get("sha256") or ""):
                reason = "stale_source_binding"
                break
    if payload.get("cursor") is not None and not _probe_cursor_valid(
        payload.get("cursor"), fingerprint, int(payload.get("endpoint_count", 0) or 0)
    ):
        reason = reason or "invalid_cursor"
    if reason:
        status = "partial"
    candidates = []
    for item in payload.get("hits") or []:
        if not isinstance(item, dict):
            continue
        endpoint = canonical_endpoint_path(str(item.get("url") or ""))
        if endpoint:
            candidates.append({
                "endpoint": endpoint,
                "field": str(item.get("field") or "")[:120],
                "class": str(item.get("class") or "")[:80],
                "signal": str(item.get("signal") or "")[:160],
            })
    projection.update({
        "status": status,
        "schema_version": _bounded_count(schema_version),
        "input_fingerprint": fingerprint,
        "endpoint_count": _bounded_count(payload.get("endpoint_count")),
        "probed_endpoint_count": _bounded_count(payload.get("probed_endpoint_count")),
        "request_count": _bounded_count(payload.get("request_count")),
        "request_budget": _bounded_count(payload.get("request_budget")),
        "hit_count": _bounded_count(payload.get("hit_count")),
        "candidate_count": _bounded_count(payload.get("hit_count")),
        "waf_observation_count": _bounded_count(payload.get("waf_observation_count")),
        "batch_start_endpoint_index": _bounded_count(payload.get("batch_start_endpoint_index")),
        "batch_tested_endpoint_count": _bounded_count(payload.get("batch_tested_endpoint_count")),
        "resumed": bool(payload.get("resumed")),
        "cursor": _probe_cursor_projection(payload.get("cursor")),
        "waf_plan_ref": str(payload.get("waf_plan_ref") or "")[:300],
        "waf_plan_sha256": str(payload.get("waf_plan_sha256") or ""),
        "waf_plan_variant_count": _bounded_count(payload.get("waf_plan_variant_count")),
        "waf_ai_variants_executed": _bounded_count(payload.get("waf_ai_variants_executed")),
        "transport_error_count": _bounded_count(payload.get("transport_error_count")),
        "budget_exhausted": bool(payload.get("budget_exhausted")),
        "candidates": candidates[:20],
        "source_paths": [
            str(binding.get("path") or "")[:300]
            for binding in (bindings or [])[:3]
            if isinstance(binding, dict) and str(binding.get("path") or "")
        ],
    })
    if reason:
        projection["reason"] = reason
    return projection


def _load_sql_matrix_projections(repo_root: str, target: str) -> dict:
    return {lane: _load_sql_matrix_projection(repo_root, target, lane) for lane in sorted(_SQL_MATRIX_LANES)}


def _load_case_state_projection(
    repo_root: str,
    target: str,
    *,
    case_state_summary: dict | None = None,
) -> dict:
    """Load the bounded, secret-free Case State continuation."""
    store = runtime_store(repo_root, target)
    path = store.path
    # Only private assembly forwards a summary acquired in this call.
    payload = case_state_summary if case_state_summary is not None else build_case_state_summary(repo_root, target)
    # Case 只提供上下文事实。行动身份/执行状态在唯一行动源，Case 侧的旧待办由
    # 迁移报告搬运，因此这里既不投影 next action，也不替它排序或宣布裁决冲突。
    return {
        "status": "valid",
        "path": str(path),
        "authz_coverage": payload.get("authz_coverage") if isinstance(payload.get("authz_coverage"), dict) else {},
        **{
            key: int(payload.get(key, 0) or 0)
            for key in (
                "actors", "sessions", "objects", "open_hypotheses",
            )
        },
    }


def load_target_goal_memory(repo_root: str, target: str) -> dict:
    """Load the four-layer target memory for autopilot bootstrapping."""
    return load_goal_memory(repo_root, target)


def _has_js_read_signal(recon_dir: str, surface_context: dict) -> bool:
    """Return whether raw JS artifacts exist for optional Claude-native reading."""
    if surface_context.get("js_endpoints"):
        return True
    return _has_any_artifact(
        os.path.join(recon_dir, "urls", "js_files.txt"),
        os.path.join(recon_dir, "js", "linkfinder_endpoints.txt"),
        os.path.join(recon_dir, "js", "potential_secrets.txt"),
    )


def _read_batch_lines(path: Path) -> list[str]:
    """Read a small batch index file with stable de-duplication."""
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    values = []
    for line in lines:
        value = line.strip().strip("\ufeff").rstrip("/").lower()
        if value.startswith("*."):
            value = value[2:]
        if value:
            values.append(value)
    return list(dict.fromkeys(values))


def _read_batch_manifest_completed(path: Path) -> list[str]:
    """Recover completed domains from JSONL when the compact list is absent."""
    completed = []
    try:
        handle = path.open(encoding="utf-8", errors="replace")
    except OSError:
        return completed
    with handle:
        for raw in handle:
            try:
                item = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if not isinstance(item, dict) or item.get("status") != "ok":
                continue
            target = str(item.get("target") or "").strip().rstrip("/").lower()
            if target.startswith("*."):
                target = target[2:]
            if target:
                completed.append(target)
    return list(dict.fromkeys(completed))


def _read_batch_ranked_targets(path: Path, completed: list[str]) -> list[dict]:
    """Return AI handoff candidates that are backed by completed recon."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        payload = []
    completed_set = set(completed)
    ranked = []
    for item in payload if isinstance(payload, list) else []:
        if not isinstance(item, dict):
            continue
        target = str(item.get("target") or "").strip().rstrip("/").lower()
        if target.startswith("*."):
            target = target[2:]
        if target not in completed_set:
            continue
        try:
            score = int(item.get("score", 0) or 0)
        except (TypeError, ValueError):
            score = 0
        ranked.append({
            "target": target,
            "score": score,
            "top_signals": item.get("top_signals") or [],
            "recon_dir": str(item.get("recon_dir") or f"recon/{target_storage_key(target)}"),
        })
    ranked_targets = {item["target"] for item in ranked}
    ranked.extend(
        {
            "target": target,
            "score": 0,
            "top_signals": [],
            "recon_dir": f"recon/{target_storage_key(target)}",
        }
        for target in completed
        if target not in ranked_targets
    )
    return ranked
