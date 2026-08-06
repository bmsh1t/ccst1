#!/usr/bin/env python3
"""
autopilot_state.py — combine resume + surface context into one practical state view.
"""

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)
TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
if TOOLS_DIR not in sys.path:
    sys.path.insert(0, TOOLS_DIR)

from memory.target_profile import default_memory_dir  # noqa: E402
try:
    from tools.action_queue import ACTIVE_STATUSES, FINAL_STATUSES, load_queue, select_next_action
except ImportError:  # pragma: no cover - direct tools/ execution
    from action_queue import ACTIVE_STATUSES, FINAL_STATUSES, load_queue, select_next_action
try:
    from tools.intel_continuation import apply_intel_continuation, inspect_intel_continuation
except ImportError:  # pragma: no cover - direct tools/ execution
    from intel_continuation import apply_intel_continuation, inspect_intel_continuation  # type: ignore
try:
    from tools.repo_source_artifacts import (
        list_repo_source_artifacts,
        load_repo_source_summary,
    )
except ImportError:  # pragma: no cover - direct tools/ execution
    from repo_source_artifacts import (
        list_repo_source_artifacts,
        load_repo_source_summary,
    )
try:
    from tools.request_guard import load_guard_status
    from tools.resume import load_resume_summary, load_structured_finding_followup
    from tools.surface import load_surface_context, rank_surface
    from tools.observation_inventory import peek_inventory_summary
    from tools.surface_projection import load_surface_projection
except ImportError:  # pragma: no cover - direct tools/ execution
    from request_guard import load_guard_status
    from resume import load_resume_summary, load_structured_finding_followup
    from surface import load_surface_context, rank_surface
    from observation_inventory import peek_inventory_summary  # type: ignore
    from surface_projection import load_surface_projection  # type: ignore
try:
    from tools.finding_index import (
        list_root_finding_claims,
        verify_finalized_finding_owner_provenance,
    )
    from tools.runtime_state import (
        inspect_recon_artifacts,
        inspect_recon_artifacts_fast,
        inspect_browser_evidence,
        load_runtime_state,
        runtime_phase_in_progress,
    )
    from tools.structured_findings import (
        format_structured_findings_lines,
        format_validation_runner_candidate_lines,
        load_validation_runner_candidate_pool,
    )
    from tools.target_paths import (
        canonical_target_value,
        classify_target,
        migrate_legacy_list_storage,
        target_list_entries,
        target_storage_key,
        url_belongs_to_target,
    )
except ImportError:  # pragma: no cover - direct tools/ execution
    from finding_index import (  # type: ignore
        list_root_finding_claims,
        verify_finalized_finding_owner_provenance,
    )
    from runtime_state import (  # type: ignore
        inspect_recon_artifacts,
        inspect_recon_artifacts_fast,
        inspect_browser_evidence,
        load_runtime_state,
        runtime_phase_in_progress,
    )
    from structured_findings import (
        format_structured_findings_lines,
        format_validation_runner_candidate_lines,
        load_validation_runner_candidate_pool,
    )
    from target_paths import (  # type: ignore
        canonical_target_value,
        classify_target,
        migrate_legacy_list_storage,
        target_list_entries,
        target_storage_key,
        url_belongs_to_target,
    )

try:
    from tools.coverage_matrix import (
        STATUS_VALUES,
        VULN_CLASSES,
        high_value_gaps_from_matrix,
        load_matrix,
        load_matrix_projection,
    )
    from tools.evidence_ledger import build_current_cell_projection, load_entries
except ImportError:  # pragma: no cover - direct tools/ execution
    from coverage_matrix import (  # type: ignore
        STATUS_VALUES,
        VULN_CLASSES,
        high_value_gaps_from_matrix,
        load_matrix,
        load_matrix_projection,
    )
    from evidence_ledger import build_current_cell_projection, load_entries  # type: ignore
try:
    from tools.closure_resolver import canonical_endpoint_path
except ImportError:  # pragma: no cover - direct tools/ execution
    from closure_resolver import canonical_endpoint_path  # type: ignore

try:
    from tools.recon_target_selector import load_rotation_status
except ImportError:  # pragma: no cover - direct tools/ execution
    from recon_target_selector import load_rotation_status  # type: ignore
try:
    from tools.scope_context import ScopeContext, ScopeContextError
except ImportError:  # pragma: no cover - direct tools/ execution
    from scope_context import ScopeContext, ScopeContextError  # type: ignore
try:
    from tools.target_case_state import case_state_path, summary as build_case_state_summary
except ImportError:  # pragma: no cover - direct tools/ execution
    from target_case_state import case_state_path, summary as build_case_state_summary  # type: ignore
try:
    from tools.target_memory import read_json as read_target_memory_json
except ImportError:  # pragma: no cover - direct tools/ execution
    from target_memory import read_json as read_target_memory_json  # type: ignore




PLACEHOLDER_OBJECT_SEGMENTS = {"nan", "undefined", "null", "none", "object", "[object object]"}
DECISION_PROJECTION_SCHEMA_VERSION = 1


def _normalise_endpoint_path(value: str) -> str:
    return canonical_endpoint_path(value)


def _has_placeholder_object_segment(value: str) -> bool:
    path = _normalise_endpoint_path(value).lower()
    segments = [segment for segment in path.split("/") if segment]
    return any(segment in PLACEHOLDER_OBJECT_SEGMENTS for segment in segments)


def _finalized_finding_paths(repo_root: str, resolved_target: str) -> set[str]:
    """Return finding URL paths that are already validated/rejected/reported.

    This is an egress guard for AI-facing next actions. It does not delete raw
    surface; it only prevents old finalized findings from steering startup.
    """
    path = Path(repo_root) / "findings" / target_storage_key(resolved_target) / "findings.json"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set()

    paths: set[str] = set()
    for item in payload.get("findings", []):
        if not isinstance(item, dict):
            continue
        validation_status = str(item.get("validation_status") or "").strip().lower()
        report_status = str(item.get("report_status") or "").strip().lower()
        if validation_status not in {"validated", "rejected"} and report_status != "generated":
            continue
        provenance = verify_finalized_finding_owner_provenance(
            path.parent,
            item,
            target=resolved_target,
        )
        if not provenance.get("valid"):
            # Direct JSON lifecycle claims must not hide a resume target.  The
            # structured state projects them as owner-revalidation candidates.
            continue
        endpoint_path = _normalise_endpoint_path(str(item.get("url") or item.get("endpoint") or ""))
        # Hash-route findings normalize to root; never hide the entire SPA root.
        if endpoint_path and endpoint_path != "/":
            paths.add(endpoint_path)
    return paths


def _is_placeholder_surface(item: dict) -> bool:
    url = str(item.get("url") or item.get("path") or "").strip()
    return _has_placeholder_object_segment(url)


def _filter_resume_targets_for_final_state(targets: list[str], finalized_paths: set[str]) -> list[str]:
    filtered: list[str] = []
    for target in targets:
        endpoint_path = _normalise_endpoint_path(target)
        if endpoint_path and endpoint_path in finalized_paths:
            continue
        if _has_placeholder_object_segment(target):
            continue
        filtered.append(target)
    return list(dict.fromkeys(filtered))[:3]


def _filter_ranked_placeholders(ranked: dict) -> dict:
    """只移除无法直接 replay 的占位对象，不按 finding/dead-end 隐藏 raw surface。"""
    filtered = dict(ranked or {})
    for key in ("review_pool", "p1", "p2"):
        items = ranked.get(key) or []
        filtered[key] = [
            item for item in items
            if isinstance(item, dict) and not _is_placeholder_surface(item)
        ]
    return filtered


APP_LIKE_HINT_TOKENS = (
    "login",
    "register",
    "signup",
    "signin",
    "dashboard",
    "portal",
    "account",
    "admin",
    "workspace",
    "graphql",
    "oauth",
    "sso",
    "session",
    "profile",
    "settings",
    "checkout",
    "billing",
    "websocket",
    "client-side",
)
HIGH_VALUE_OBSERVATION_KINDS = frozenset({"exposure", "infra"})


def _read_json_file(path: str) -> dict:
    """Read a JSON object from disk; return empty dict on missing or invalid data."""
    try:
        with open(path, encoding="utf-8") as f:
            payload = json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _load_checkpoint_witness(path: Path) -> dict:
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"unable to read checkpoint witness {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid checkpoint witness JSON {path}: {exc.msg}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"checkpoint witness {path} must contain one object")
    return payload


def _checkpoint_round_projection(witness: dict) -> dict:
    progress = witness.get("round_progress")
    if progress is None:
        return {}
    if (
        not isinstance(progress, dict)
        or progress.get("schema_version") != 1
        or progress.get("status") not in {"active", "completed"}
    ):
        raise ValueError("checkpoint round_progress is invalid")
    claimed = progress.get("claimed_lanes")
    limit = progress.get("max_lanes")
    if (
        isinstance(limit, bool)
        or not isinstance(limit, int)
        or limit < 1
        or not isinstance(claimed, list)
        or any(
            not isinstance(item, str)
            or not item
            or len(item) > 200
            or "\n" in item
            or "\r" in item
            for item in claimed
        )
        or len(claimed) > limit
        or len(set(claimed)) != len(claimed)
        or isinstance(progress.get("claimed_count"), bool)
        or not isinstance(progress.get("claimed_count"), int)
        or progress.get("claimed_count") != len(claimed)
        or isinstance(progress.get("remaining_lanes"), bool)
        or not isinstance(progress.get("remaining_lanes"), int)
        or progress.get("remaining_lanes") != limit - len(claimed)
        or not isinstance(progress.get("budget_reached"), bool)
        or progress.get("budget_reached") != (len(claimed) >= limit)
    ):
        raise ValueError("checkpoint round_progress budget fields are invalid")
    lanes = progress.get("lanes")
    if lanes is None:
        lanes = [{"schema_version": 1, "id": lane_id, "status": "started"} for lane_id in claimed]
    if not isinstance(lanes, list):
        raise ValueError("checkpoint round_progress lanes are invalid")
    projected_lanes = []
    for lane in lanes:
        if not isinstance(lane, dict) or lane.get("schema_version") != 1:
            raise ValueError("checkpoint round_progress lane is invalid")
        lane_id = lane.get("id")
        lane_status = lane.get("status")
        if (
            not isinstance(lane_id, str)
            or lane_id not in claimed
            or lane_status not in {"started", "completed", "blocked"}
        ):
            raise ValueError("checkpoint round_progress lane fields are invalid")
        item = {"id": lane_id, "status": lane_status}
        for field, field_limit in (("decision", 500), ("evidence_ref", 500), ("next_action", 1000)):
            value = lane.get(field, "")
            if not isinstance(value, str) or "\n" in value or "\r" in value or len(value) > field_limit:
                raise ValueError("checkpoint round_progress lane fields are invalid")
            if value:
                item[field] = value
        if lane_status == "started" and (
            any(item.get(field) for field in ("decision", "evidence_ref", "next_action"))
            or lane.get("finished_at")
        ):
            raise ValueError("checkpoint started round lane has terminal fields")
        if lane_status in {"completed", "blocked"} and (
            any(not item.get(field) for field in ("decision", "evidence_ref", "next_action"))
            or not isinstance(lane.get("finished_at"), str)
            or not lane.get("finished_at")
            or (lane_status == "completed" and item.get("evidence_ref") == "none")
        ):
            raise ValueError("checkpoint terminal round lane is incomplete")
        projected_lanes.append(item)
    if [item["id"] for item in projected_lanes] != claimed:
        raise ValueError("checkpoint round_progress lane identities are invalid")
    unfinished = [item["id"] for item in projected_lanes if item["status"] == "started"]
    if progress["status"] == "completed" and unfinished:
        raise ValueError("checkpoint completed round has unfinished lanes")
    return {
        "status": progress["status"],
        "round_id": str(progress.get("round_id") or ""),
        "max_lanes": limit,
        "claimed_count": len(claimed),
        "budget_reached": bool(progress.get("budget_reached")),
        "unfinished_lanes": unfinished,
        "latest_lane": projected_lanes[-1] if projected_lanes else {},
    }


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
    if (
        int(payload.get("schema_version", 0) or 0) < 2
        or status not in {"complete_no_hit", "candidate_pending", "partial", "invalid_input"}
        or not re.fullmatch(r"[0-9a-f]{64}", fingerprint)
        or (
            str(payload.get("waf_plan_sha256") or "")
            and not re.fullmatch(r"[0-9a-f]{64}", str(payload.get("waf_plan_sha256") or ""))
        )
    ):
        status = "partial"
    for binding in payload.get("source_bindings") or []:
        if not isinstance(binding, dict):
            status = "partial"
            projection["reason"] = "stale_source_binding"
            break
        source = Path(str(binding.get("path") or ""))
        source = source if source.is_absolute() else Path(repo_root) / source
        try:
            current = hashlib.sha256(source.read_bytes()).hexdigest()
        except OSError:
            current = ""
        if current != str(binding.get("sha256") or ""):
            status = "partial"
            projection["reason"] = "stale_source_binding"
            break
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
        endpoint = _normalise_endpoint_path(str(item.get("url") or ""))
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


_JS_TERMINAL_DISPOSITIONS = {"tested", "blocked", "dead_end", "not_applicable"}


def _load_js_intel_projection(repo_root: str, target: str) -> dict:
    """Keep js-reader's prepared and analyzed lifecycle distinct."""
    root = Path(repo_root) / "findings" / target_storage_key(target) / "js_intel"
    materials = root / "materials.json"
    summary = root / "materials_summary.md"
    hypotheses = root / "hypotheses.json"
    disposition = root / "disposition.json"
    projection = {"status": "not_run", "path": str(materials), "present": False}
    if materials.is_file() or summary.is_file():
        projection.update({"status": "prepared", "present": True, "path": str(materials if materials.is_file() else summary)})
    if materials.is_file():
        try:
            material_payload = json.loads(materials.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            projection.update({"status": "partial", "reason": "malformed_materials"})
            return projection
        if isinstance(material_payload, dict) and material_payload.get("target"):
            if canonical_target_value(str(material_payload.get("target"))) != canonical_target_value(target):
                projection.update({"status": "partial", "reason": "target_mismatch"})
                return projection
    if disposition.is_file():
        try:
            payload = json.loads(disposition.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            projection.update({"status": "partial", "reason": "malformed_disposition"})
            return projection
        disposition_status = str(payload.get("status") or "").strip().lower() if isinstance(payload, dict) else ""
        if disposition_status not in _JS_TERMINAL_DISPOSITIONS:
            projection.update({"status": "partial", "reason": "invalid_disposition"})
            return projection
        if not isinstance(payload, dict) or not str(payload.get("evidence_ref") or payload.get("reason") or "").strip():
            projection.update({"status": "partial", "reason": "disposition_missing_evidence"})
            return projection
        projection.update({"status": disposition_status, "disposition_path": str(disposition)})
        return projection
    payload = None
    if hypotheses.is_file():
        try:
            payload = json.loads(hypotheses.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            projection.update({"status": "partial", "reason": "malformed_hypotheses", "hypotheses_path": str(hypotheses)})
            return projection
        values = payload.get("hypotheses") if isinstance(payload, dict) else None
        if not isinstance(values, list) or not values:
            projection.update({"status": "partial", "reason": "hypotheses_empty", "hypotheses_path": str(hypotheses)})
            return projection
        bindings = payload.get("source_bindings") if isinstance(payload, dict) else None
        if bindings is not None:
            if not isinstance(bindings, list) or not bindings:
                projection.update({"status": "partial", "reason": "invalid_source_binding", "hypotheses_path": str(hypotheses)})
                return projection
            for binding in bindings:
                if not isinstance(binding, dict) or not str(binding.get("path") or ""):
                    projection.update({"status": "partial", "reason": "invalid_source_binding", "hypotheses_path": str(hypotheses)})
                    return projection
                source = Path(str(binding["path"]))
                source = source if source.is_absolute() else Path(repo_root) / source
                try:
                    current = hashlib.sha256(source.read_bytes()).hexdigest()
                except OSError:
                    current = ""
                if current != str(binding.get("sha256") or ""):
                    projection.update({"status": "partial", "reason": "stale_source_binding", "hypotheses_path": str(hypotheses)})
                    return projection
        projection.update({"status": "analyzed", "hypotheses_path": str(hypotheses), "hypothesis_count": min(len(values), 100)})
    return projection


def _load_case_state_projection(repo_root: str, target: str) -> dict:
    """Load the bounded, secret-free Case State continuation."""
    path = case_state_path(repo_root, target)
    if not path.is_file():
        return {"status": "missing", "path": str(path)}
    payload = build_case_state_summary(repo_root, target)
    top = payload.get("top_next_action") if isinstance(payload.get("top_next_action"), dict) else {}
    allowed = {
        "next_action", "ready", "score", "backlog_id", "runner", "hypothesis",
        "chain_context", "why_now", "vuln_class", "endpoint", "owner_actor",
        "peer_actor", "object_ref", "object_type", "required_evidence",
        "optional_evidence_gaps", "missing_evidence", "redacted_command",
        "downgrade_rule", "stop_condition", "chain_extensions_if_blocked", "write_back",
        "param", "baseline_value", "variant_value", "expect_marker", "method",
    }
    return {
        "status": "valid",
        "path": str(path),
        **{
            key: int(payload.get(key, 0) or 0)
            for key in (
                "actors", "sessions", "objects", "open_hypotheses",
                "pending_validation_backlog",
            )
        },
        "top_next_action": {key: value for key, value in top.items() if key in allowed},
    }


def load_target_goal_memory(repo_root: str, target: str) -> dict:
    """Load the four-layer target memory for autopilot bootstrapping."""
    resolved_target = canonical_target_value(target)
    goals_dir = os.path.join(repo_root, "memory", "goals")
    active = read_target_memory_json(Path(goals_dir) / "active.json")
    target_memory = read_target_memory_json(
        Path(goals_dir) / "targets" / f"{target_storage_key(resolved_target)}.json"
    )

    active_target = canonical_target_value(str(active.get("target", "") or ""))
    active_matches = bool(active_target and active_target == resolved_target)

    return {
        "active": active if active_matches else {},
        "target": target_memory,
        "active_matches": active_matches,
    }


def _matches_resume_target(url: str, resume_targets: list[str]) -> bool:
    """Check whether a ranked URL matches any remembered resume target path."""
    parsed = urlparse(url or "")
    normalized = parsed.path or "/"
    if parsed.query:
        normalized = f"{normalized}?{parsed.query}"

    for target in resume_targets:
        candidate = str(target or "").strip()
        if not candidate:
            continue
        if normalized == candidate or normalized.endswith(candidate):
            return True
    return False


def _build_recommended_targets(
    p1: list[dict],
    guard_status: dict,
    resume_targets: list[str] | None = None,
    *,
    prefer_resume_targets: bool = False,
) -> list[dict]:
    """Return advisory surface candidates; Claude chooses the final target."""
    host_status = {
        item.get("host", ""): item
        for item in guard_status.get("hosts", [])
        if item.get("host")
    }

    preferred = resume_targets or []
    recommended = []
    for index, item in enumerate(p1):
        status = host_status.get(item.get("host", ""), {})
        recommended.append({
            "url": item.get("url", ""),
            "host": item.get("host", ""),
            "suggested": item.get("suggested", ""),
            "score": item.get("score", 0),
            "review_reason": item.get("review_reason", ""),
            "review_index": index,
            "tripped": bool(status.get("tripped", False)),
            "remaining_seconds": float(status.get("remaining_seconds", 0.0) or 0.0),
            "matches_resume_target": _matches_resume_target(item.get("url", ""), preferred),
            "new_observation": bool(item.get("new_observation")),
        })

    recommended.sort(
        key=lambda item: (
            item["tripped"],
            0 if (prefer_resume_targets and item["matches_resume_target"]) else 1,
            item["review_index"],
        )
    )
    return recommended[:5]


def _build_resume_targets(summary: dict | None) -> list[str]:
    """Prefer continuing the latest session focus, then fall back to untested endpoints."""
    if not summary:
        return []

    latest_session = summary.get("latest_session_summary") or {}
    preview = [item for item in latest_session.get("endpoints_preview", []) if item]
    if preview:
        return list(dict.fromkeys(preview))[:3]

    untested = [item for item in summary.get("untested_endpoints", []) if item]
    if not untested:
        return []
    return untested[:3]


def _pick_next_action(
    has_recon: bool,
    ranked: dict,
    resume_summary: dict | None,
    structured_findings: dict | None = None,
    validation_runner_next: dict | None = None,
    action_queue_next: dict | None = None,
    resume_targets: list[str] | None = None,
    recon_in_progress: bool = False,
    scan_in_progress: bool = False,
    recon_completed_no_live_hosts: bool = False,
    memory_candidate_next: dict | None = None,
    root_finding_claim_next: dict | None = None,
    fresh_recon_ready: bool = False,
    surface_context_required: bool = False,
    cidr_continuation: dict | None = None,
    dir_fuzz_rotation_pending: bool = False,
    case_state_next: dict | None = None,
) -> str:
    """Bias toward resumable session context before widening to surface review candidates."""
    structured_findings = structured_findings or {}
    resume_targets = resume_targets if resume_targets is not None else _build_resume_targets(resume_summary)
    # 活跃 phase gate 必须优先于 validation/report/surface，避免第二个 Claude
    # loop 重启或忽略仍持有 flock 的长任务。
    if recon_in_progress:
        return "wait_recon"
    if scan_in_progress:
        return "wait_scan"

    if structured_findings.get("next_owner_revalidation"):
        return "revalidate_finding_owner"
    next_validation = structured_findings.get("next_validation") or {}
    if next_validation:
        rubric = (
            next_validation.get("rubric")
            if isinstance(next_validation, dict)
            and isinstance(next_validation.get("rubric"), dict)
            else {}
        )
        # 旧状态可能没有 rubric；只在显式 non-ready 时改走补证据流程。
        if rubric and "ready" in rubric and not bool(rubric.get("ready")):
            return "collect_candidate_evidence"
        return "validate_finding"
    if root_finding_claim_next:
        # 根目录裸 JSON 是人工/AI 的临时 claim，不是 canonical lifecycle。
        # 它必须先补 locatable raw evidence 并由 checkpoint 归档为 candidate；
        # 不能因为 prose PoC 而直接被称为 validated。
        return "collect_candidate_evidence"
    if validation_runner_next:
        return "review_validation_candidate"
    if action_queue_next:
        return "resume_action_queue"
    if str((case_state_next or {}).get("next_action") or "none") != "none":
        return "resume_case_state"
    if (cidr_continuation or {}).get("status") == "pending":
        return "run_recon"
    # Legacy target-memory is only a recovery bridge.  Canonical report
    # closure must remain reachable once live/resume work above is exhausted.
    if memory_candidate_next and not (
        structured_findings.get("draft_completion_pending")
        or structured_findings.get("validated_pending_report")
    ):
        # target memory 是兼容层，不是 durable owner。没有可定位原始证据时，
        # 它只能把下一会话带回补证据动作，不能直接把 prose 提升为 finding。
        if bool(memory_candidate_next.get("evidence_available")):
            return "validate_finding"
        return "collect_candidate_evidence"

    if not has_recon:
        if recon_completed_no_live_hosts:
            return "recon_no_live_hosts"
        return "run_recon"

    latest_session = (resume_summary or {}).get("latest_session_summary") or {}
    preview = [item for item in latest_session.get("endpoints_preview", []) if item]

    if latest_session and preview and resume_targets:
        return "continue_last_focus"
    if latest_session and resume_targets:
        return "resume_untested"

    if surface_context_required or fresh_recon_ready:
        return "prepare_surface_context"
    if ranked.get("review_pool") or ranked.get("p1"):
        return "hunt_p1"
    if dir_fuzz_rotation_pending:
        return "run_recon"
    if resume_targets:
        return "resume_untested"
    if structured_findings.get("draft_completion_pending"):
        return "complete_report_draft"
    # A validated finding is a closure/report asset, not the steering wheel.
    # Surface/replay/resume work above should stay available when current
    # evidence exposes stronger live leads; otherwise keep the report visible.
    if structured_findings.get("validated_pending_report"):
        return "report_finding"
    return "handoff"


def _should_guard_safe_pivot(next_action: str, guard_status: dict) -> bool:
    """Return whether live probing should pause and cached-evidence work should continue."""
    if next_action in {
        "run_recon",
        "wait_recon",
        "wait_scan",
        "revalidate_finding_owner",
        "collect_candidate_evidence",
        "validate_finding",
        "review_validation_candidate",
        "resume_action_queue",
        "prepare_surface_context",
        "complete_report_draft",
        "recon_no_live_hosts",
        "report_finding",
        "run_intel",
        "collect_web_intel",
        "test_advisory_applicability",
    }:
        return False
    tracked = int(guard_status.get("tracked_hosts", 0) or 0)
    tripped = int(guard_status.get("tripped_hosts", 0) or 0)
    ready = int(guard_status.get("ready_hosts", 0) or 0)
    return tracked > 0 and tripped > 0 and ready == 0


def _describe_next_step(state: dict) -> str:
    """Render a human-friendly next-step hint from the computed state."""
    action = state.get("next_action", "")
    target = state.get("target", "target")
    resume_targets = state.get("resume_targets", []) or []
    surface_review_candidates = (
        state.get("surface_review_candidates")
        or state.get("recommended_targets", [])
        or []
    )
    tripped_hosts = (state.get("guard_status", {}) or {}).get("tripped_hosts", []) or []
    recon_artifacts = state.get("recon_artifacts") or {}

    if action == "run_recon":
        continuation = recon_artifacts.get("cidr_continuation") or {}
        if continuation.get("status") == "pending":
            return (
                f"continue CIDR recon {target} from offset {continuation.get('next_offset')}; "
                "preserve prior CIDR pages."
            )
        missing = recon_artifacts.get("missing") or []
        if recon_artifacts.get("available") and missing:
            return f"rerun /recon {target}; cached recon is incomplete ({', '.join(missing[:2])})."
        return f"run /recon {target} first."
    if action == "wait_recon":
        return (
            f"wait/poll the existing /recon {target} run; do not launch another recon. "
            "Refresh state after the matching recon phase lock releases."
        )
    if action == "wait_scan":
        return (
            f"wait/poll the existing scan-only quick run for {target}; do not launch another "
            "scan-only quick. Refresh state after the matching scan phase lock releases."
        )
    if action == "revalidate_finding_owner":
        finding = (state.get("structured_findings") or {}).get("next_owner_revalidation") or {}
        return (
            "finding {id} claims {validation}/{report} without valid owner provenance "
            "({reason}); treat it only as a candidate, replay locatable raw evidence, then rerun "
            "/validate with its canonical id so finding_index records the lifecycle mutation. "
            "Do not report or suppress the endpoint from the claim alone."
        ).format(
            id=finding.get("id", "-"),
            validation=finding.get("claimed_validation_status", "-"),
            report=finding.get("claimed_report_status", "-"),
            reason=finding.get("provenance_reason", "owner-provenance-invalid"),
        )
    if action == "collect_candidate_evidence":
        followup = (state.get("structured_findings") or {}).get("next_validation") or {}
        memory_candidate = state.get("memory_candidate_next") or {}
        root_claim = state.get("root_finding_claim_next") or {}
        candidate = followup if followup else (root_claim if root_claim else memory_candidate)
        rubric = followup.get("rubric") if isinstance(followup.get("rubric"), dict) else {}
        missing = [
            str(item).strip()
            for item in (rubric.get("missing_labels") or [])[:3]
            if str(item).strip()
        ]
        evidence_step = next(
            (
                str(item).strip()
                for item in rubric.get("next_actions") or []
                if str(item).strip()
            ),
            "fill the first missing candidate evidence item",
        )
        if followup:
            return (
                "collect candidate evidence for finding {id} on {url}; rubric={status}, "
                "missing={missing}. Next evidence step: {step}. Rerun state before /validate.".format(
                    id=candidate.get("id", "-"),
                    url=candidate.get("url", ""),
                    status=rubric.get("status", "needs-evidence"),
                    missing=", ".join(missing) or "candidate evidence",
                    step=evidence_step,
                )
            )
        if root_claim:
            return (
                "inspect root JSON finding claim {id} at {source}; capture locatable raw "
                "request/response and run /checkpoint to reconcile it as a candidate. "
                "Missing fields: {missing}. Do not call it validated or report-ready "
                "from the claim alone. Never invent an endpoint from the target root."
            ).format(
                id=root_claim.get("id", "-"),
                source=root_claim.get("source_file", ""),
                missing=", ".join(str(item) for item in (root_claim.get("incomplete_fields") or []))
                or "none",
            )
        return (
            "collect raw request/response or a locatable evidence_ref for target-memory "
            "candidate {id}; do not call /validate from prose alone. Candidate: {action}".format(
                id=candidate.get("id", "-"),
                action=candidate.get("action", ""),
            )
        )
    if action == "validate_finding":
        followup = (state.get("structured_findings") or {}).get("next_validation") or {}
        if followup:
            return f"validate structured finding {followup.get('id')} on {followup.get('url')}."
        memory_candidate = state.get("memory_candidate_next") or {}
        if memory_candidate:
            return (
                "validate target-memory candidate {id} after reviewing its linked raw evidence: {action}."
            ).format(
                id=memory_candidate.get("id", "-"),
                action=memory_candidate.get("action", ""),
            )
        return "validate the highest-priority structured finding."
    if action == "review_validation_candidate":
        candidate = state.get("validation_runner_next") or {}
        if candidate:
            return (
                f"review validation-runner candidate {candidate.get('id')}; inspect raw evidence, "
                "then use /validate or record a ledger downgrade."
            )
        return "review the next validation-runner candidate before starting another long phase."
    if action == "resume_action_queue":
        item = state.get("action_queue_next") or {}
        if item:
            return f"resume durable action {item.get('id')}: {item.get('action') or item.get('command_hint')}."
        return "resume the highest-priority substantive durable action."
    if action == "resume_case_state":
        item = (state.get("case_state") or {}).get("top_next_action") or {}
        return (
            f"resume Case State action {item.get('next_action', 'enrich_case_state')}: "
            f"{item.get('hypothesis') or item.get('write_back') or 'refresh the validation backlog'}."
        )
    if action == "recon_no_live_hosts":
        return (
            "recon completed with no live hosts; review cached infra/exposure/offline evidence "
            "and record the blocker. Explicit refresh, stale artifacts, or contradictory fresh "
            "evidence is required; do not rerun recon automatically."
        )
    if action == "run_intel":
        continuation = state.get("intel_continuation") or {}
        return (
            "run /intel for the current software/service inventory before continuing generic "
            f"hunting; reason: {continuation.get('reason', 'Intel artifact is missing or stale')}."
        )
    if action == "collect_web_intel":
        continuation = state.get("intel_continuation") or {}
        recommended = continuation.get("recommended") or []
        subject = str((recommended[0] if recommended else {}).get("subject") or "the top Intel gap")
        return (
            f"collect and record provider-neutral Web Intel for {subject}; verify selected source "
            "bodies, then rerun /intel so the bounded claim projection is merged."
        )
    if action == "test_advisory_applicability":
        advisory = (state.get("intel_continuation") or {}).get("advisory") or {}
        component = advisory.get("component") if isinstance(advisory.get("component"), dict) else {}
        return (
            "test target reachability and version applicability for {id} on {name}@{version}; "
            "preserve raw evidence and resolve the durable action before moving on."
        ).format(
            id=advisory.get("id", "the top advisory"),
            name=component.get("name", "component"),
            version=component.get("version") or "unknown",
        )
    if action == "report_finding":
        followup = (state.get("structured_findings") or {}).get("next_report") or {}
        if followup:
            return f"generate a report for validated finding {followup.get('id')}."
        return "generate reports for validated structured findings."
    if action == "continue_last_focus":
        focus = ", ".join(resume_targets[:2]) if resume_targets else "the last focus endpoints"
        return f"continue testing the last focus first: {focus}."
    if action == "resume_untested":
        focus = ", ".join(resume_targets[:2]) if resume_targets else "cached untested endpoints"
        return f"resume the cached untested surface first: {focus}."
    if action == "guard_safe_pivot":
        return (
            "all tracked live hosts are cooling down or locked; continue automatically "
            "with cached recon/browser/JS/source evidence, context-pack, checkpoint, and "
            "coverage updates. Do not use IP rotation, WAF evasion, or social engineering."
        )
    if action == "hunt_p1":
        if surface_review_candidates:
            first_item = surface_review_candidates[0]
            first = first_item["url"]
            if first_item.get("tripped"):
                return (
                    f"the top advisory surface host is cooling down; prefer another surface until cooldown clears: "
                    f"{first}."
                )
            if tripped_hosts:
                return f"review the top ready surface candidate while other hosts cool down: {first}."
            return f"review the top surface candidate, then choose the next evidence step: {first}."
        return "review the surface candidates, then choose the next evidence step."
    if action == "hunt_p2":
        return "widen into follow-up surface hints after first-review candidates are exhausted."
    if action == "prepare_surface_context":
        return (
            "recon is ready but has no ranked replay candidate yet; run /surface and context-pack "
            "from the cached recon, then select the smallest evidence-producing hunt action."
        )
    if action == "complete_report_draft":
        draft = (state.get("structured_findings") or {}).get("next_draft_completion") or {}
        return (
            "complete report draft for validated finding {id} from its linked raw evidence; "
            "replace all placeholders before report generation, without reopening the validated replay. "
            "Draft: {path}".format(
                id=draft.get("id", "-"),
                path=draft.get("report_draft_path", ""),
            )
        )
    if action == "refresh_recon":
        return f"refresh recon before going deeper on {target}."
    if action == "handoff":
        return "no strong executable next action from cached state; use checkpoint or fresh evidence before continuing."
    return "follow the highest-confidence target shown below."


def describe_next_step(state: dict) -> str:
    """Return a single-line bounded next-step instruction for controllers."""
    return " ".join(_describe_next_step(state).split())[:500]


def _runtime_recon_in_progress(
    repo_root: str,
    target: str,
    runtime_state: dict,
    *,
    stale_after_seconds: int = 7200,
) -> bool:
    """兼容现有调用点的 shared runtime-state gate 包装。"""
    return runtime_phase_in_progress(
        repo_root,
        target,
        "recon",
        runtime_state,
        stale_after_seconds=stale_after_seconds,
    )


def _runtime_scan_in_progress(
    repo_root: str,
    target: str,
    runtime_state: dict,
    *,
    stale_after_seconds: int = 7200,
) -> bool:
    """兼容现有调用点的 shared runtime-state gate 包装。"""
    return runtime_phase_in_progress(
        repo_root,
        target,
        "scan",
        runtime_state,
        stale_after_seconds=stale_after_seconds,
    )


def _candidate_items_for_next_action(ranked: dict, next_action: str) -> list[dict]:
    if next_action == "hunt_p2":
        return ranked.get("p2", []) or []
    return ranked.get("review_pool", []) or ranked.get("p1", []) or []

def _build_guard_hint(guard_status: dict, recommended_targets: list[dict]) -> str:
    """Render an operator/agent-friendly guard hint for immediate action."""
    tripped_hosts = [item for item in (guard_status.get("tripped_hosts", []) or []) if item.get("host")]
    ready_target = next((item for item in recommended_targets if not item.get("tripped")), None)

    if tripped_hosts:
        cooling = ", ".join(
            f"{item['host']} ({float(item.get('remaining_seconds', 0.0) or 0.0):.1f}s)"
            for item in tripped_hosts[:3]
        )
        if ready_target:
            return (
                f"cooling hosts: {cooling}; prefer the ready host "
                f"{ready_target.get('host', '')} via {ready_target.get('url', '')}"
            )
        return (
            f"all tracked hot hosts are cooling down: {cooling}; do not rotate IPs, "
            f"evade detection, or use social engineering. Pivot to cached recon/browser/JS/source "
            f"artifacts, context-pack, checkpoint, and coverage updates until cooldown clears"
        )

    if ready_target and int(guard_status.get("tracked_hosts", 0) or 0) > 0:
        return f"prefer the ready host {ready_target.get('host', '')} via {ready_target.get('url', '')}"

    return ""


def _format_recent_guard_advisory(item: dict) -> str:
    """Render a compact human-readable summary for one recent guard advisory."""
    notes = str(item.get("notes", "") or "").strip()
    if notes:
        return notes
    endpoint = str(item.get("endpoint", "") or "").strip()
    action = str(item.get("action", "") or "").strip()
    if action and endpoint:
        return f"{action} :: {endpoint}"
    return endpoint or action


def _build_pivot_hint(
    *,
    tripped_hosts: list[dict],
    recent_guard_advisories: list[dict],
    repo_source_summary: dict,
) -> str:
    """Build one short advisory hint from current guard + repo-source signals."""
    secret_findings = int(repo_source_summary.get("secret_findings", 0) or 0)
    ci_findings = int(repo_source_summary.get("ci_findings", 0) or 0)
    has_live_guard_pressure = bool(tripped_hosts)
    has_repo_findings = secret_findings > 0 or ci_findings > 0

    if has_live_guard_pressure and has_repo_findings:
        return "live API has guard advisories; inspect repo source findings first."
    if has_live_guard_pressure:
        return "guard advisories are active; continue with the next ready target or quieter surface."
    if secret_findings > 0:
        return "repo source shows secrets; verify credential usability before widening live probing."
    if ci_findings > 0:
        return "repo source shows CI risks; review workflow attack surface before rerunning source hunt."
    return ""


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


def _has_browser_mcp_signal(surface_context: dict, ranked: dict) -> bool:
    """Return whether cached recon looks app-like enough to justify browser probing."""
    titles = [
        str(item.get("title", "") or "").lower()
        for item in (surface_context.get("hosts") or {}).values()
        if isinstance(item, dict)
    ]
    ranked_values = []
    for bucket in ("p1", "p2", "review_pool"):
        for item in ranked.get(bucket) or []:
            if not isinstance(item, dict):
                continue
            ranked_values.extend(str(item.get(key) or "").lower() for key in ("url", "title", "reason"))
            ranked_values.extend(str(value or "").lower() for value in item.get("tech_stack") or [])
    for item in ranked.get("workflow_leads") or []:
        if isinstance(item, str):
            ranked_values.append(item.lower())
        elif isinstance(item, dict):
            ranked_values.extend(str(item.get(key) or "").lower() for key in ("category", "title", "rationale", "next_action"))

    for value in titles + ranked_values:
        if any(token in value for token in APP_LIKE_HINT_TOKENS):
            return True
    return False


def _has_js_read_signal(recon_dir: str, surface_context: dict) -> bool:
    """Return whether cached JS artifacts exist and are worth handing to js-reader."""
    if surface_context.get("js_endpoints"):
        return True
    return _has_any_artifact(
        os.path.join(recon_dir, "urls", "js_files.txt"),
        os.path.join(recon_dir, "js", "linkfinder_endpoints.txt"),
        os.path.join(recon_dir, "js", "potential_secrets.txt"),
    )


EXPOSURE_SUMMARY_KEYS = (
    "config_exposures",
    "api_doc_candidates",
    "api_leak_candidates",
    "verified_secrets",
    "postman_leaks",
    "postleaks_urls",
    "swagger_leaks",
    "openapi_specs",
    "openapi_operations",
    "openapi_public_operations",
    "openapi_auth_boundary_candidates",
    "platform_metadata",
    "cloud_storage_candidates",
    "s3_bucket_candidates",
    "external_service_hosts",
    "host_pivot_candidates",
    "ai_asset_candidates",
    "identity_emails",
    "leaksearch_hits",
    "cloud_enum_hits",
)


def _count_value(counts: dict, key: str) -> int:
    """Safely read an integer count from recon artifact metadata."""
    try:
        return int(counts.get(key, 0) or 0)
    except (TypeError, ValueError):
        return 0


def _has_exposure_signals(recon_artifacts: dict) -> bool:
    """Return whether cached recon exposure artifacts contain actionable signal."""
    counts = recon_artifacts.get("counts") or {}
    return any(_count_value(counts, key) > 0 for key in EXPOSURE_SUMMARY_KEYS)


def _exposure_review_paths(target: str, recon_artifacts: dict) -> list[str]:
    """Build a short, priority-ordered review list for exposure artifacts."""
    counts = recon_artifacts.get("counts") or {}
    storage_key = target_storage_key(target)
    review = []

    def add_if(condition: bool, relative_path: str) -> None:
        if condition:
            review.append(f"recon/{storage_key}/{relative_path}")

    add_if(
        any(
            _count_value(counts, key) > 0
            for key in (
                "openapi_operations",
                "openapi_auth_boundary_candidates",
                "platform_metadata",
            )
        ),
        "api_specs/summary.md",
    )
    add_if(
        _count_value(counts, "api_doc_candidates") > 0,
        "exposure/api_doc_candidates.txt",
    )
    add_if(
        any(
            _count_value(counts, key) > 0
            for key in (
                "api_leak_candidates",
                "postman_leaks",
                "postleaks_urls",
                "swagger_leaks",
            )
        ),
        "exposure/api_leak_candidates.txt",
    )
    add_if(
        _count_value(counts, "verified_secrets") > 0,
        "exposure/api_leak_trufflehog_verified.jsonl",
    )
    add_if(
        _count_value(counts, "host_pivot_candidates") > 0,
        "exposure/host_pivot_candidates.jsonl",
    )
    add_if(
        _count_value(counts, "ai_asset_candidates") > 0,
        "exposure/ai_asset_candidates.jsonl",
    )
    add_if(
        _count_value(counts, "config_exposures") > 0,
        "exposure/config_files.txt",
    )
    add_if(
        any(
            _count_value(counts, key) > 0
            for key in (
                "cloud_storage_candidates",
                "s3_bucket_candidates",
                "external_service_hosts",
            )
        ),
        "exposure/cloud_storage_candidates.txt",
    )
    add_if(
        any(
            _count_value(counts, key) > 0
            for key in ("identity_emails", "leaksearch_hits", "cloud_enum_hits")
        ),
        "exposure/identity_intel/summary.md",
    )
    add_if(
        _count_value(counts, "cloud_enum_hits") > 0,
        "exposure/cloud/cloud_enum.txt",
    )
    return list(dict.fromkeys(review))[:6]


def _format_exposure_signal_lines(target: str, recon_artifacts: dict) -> list[str]:
    """Render exposure signals without turning them into mandatory next actions."""
    if not _has_exposure_signals(recon_artifacts):
        return []

    counts = recon_artifacts.get("counts") or {}
    lines = ["Exposure signals:"]
    lines.append(f"- API docs: {_count_value(counts, 'api_doc_candidates')}")
    lines.append(
        "- OpenAPI semantics: "
        f"specs={_count_value(counts, 'openapi_specs')}, "
        f"operations={_count_value(counts, 'openapi_operations')}, "
        f"public_or_optional={_count_value(counts, 'openapi_public_operations')}, "
        f"auth_boundaries={_count_value(counts, 'openapi_auth_boundary_candidates')}, "
        f"platform_metadata={_count_value(counts, 'platform_metadata')}"
    )
    lines.append(
        "- API leaks: "
        f"candidates={_count_value(counts, 'api_leak_candidates')}, "
        f"swagger={_count_value(counts, 'swagger_leaks')}, "
        f"postman={_count_value(counts, 'postman_leaks')}, "
        f"postleaks={_count_value(counts, 'postleaks_urls')}, "
        f"verified_secrets={_count_value(counts, 'verified_secrets')}"
    )
    lines.append(
        "- Config/cloud: "
        f"config={_count_value(counts, 'config_exposures')}, "
        f"cloud={_count_value(counts, 'cloud_storage_candidates')}, "
        f"s3={_count_value(counts, 's3_bucket_candidates')}, "
        f"external_hosts={_count_value(counts, 'external_service_hosts')}"
    )
    lines.append(
        "- Identity/cloud intel: "
        f"emails={_count_value(counts, 'identity_emails')}, "
        f"LeakSearch={_count_value(counts, 'leaksearch_hits')}, "
        f"cloud_enum={_count_value(counts, 'cloud_enum_hits')}"
    )
    lines.append(
        "- Routing candidates: "
        f"host_pivot={_count_value(counts, 'host_pivot_candidates')}, "
        f"ai_asset={_count_value(counts, 'ai_asset_candidates')}"
    )

    review_paths = _exposure_review_paths(target, recon_artifacts)
    if review_paths:
        lines.append("Next exposure review:")
        for path in review_paths:
            lines.append(f"- {path}")
    return lines


def _format_infra_signal_lines(target: str, recon_artifacts: dict) -> list[str]:
    """Render WAF/origin/port recon signals as soft review hints."""
    counts = recon_artifacts.get("counts") or {}
    waf_hits = _count_value(counts, "waf_hits")
    waf_context = _count_value(counts, "waf_context")
    origin_candidates = _count_value(counts, "origin_candidates")
    open_ports = _count_value(counts, "open_ports")
    if waf_hits <= 0 and waf_context <= 0 and origin_candidates <= 0 and open_ports <= 0:
        return []

    storage_key = target_storage_key(target)
    lines = [
        "Infra signals:",
        f"- WAF hits: {waf_hits}, WAF context: {waf_context}, "
        f"origin candidates: {origin_candidates}, open ports: {open_ports}",
    ]
    review_paths = []
    if waf_hits > 0:
        review_paths.append(f"recon/{storage_key}/live/wafw00f_hits.txt")
    if waf_context > 0:
        review_paths.append(f"recon/{storage_key}/live/waf_context.json")
    if origin_candidates > 0:
        review_paths.append(f"recon/{storage_key}/live/unwaf_bypass_ips.txt")
    if open_ports > 0:
        relative = (recon_artifacts.get("infra_paths") or {}).get(
            "open_ports",
            "ports/open_host_ports.txt",
        )
        review_paths.append(f"recon/{storage_key}/{relative}")
    if review_paths:
        lines.append("Next infra review:")
        lines.extend(f"- {path}" for path in review_paths[:4])
    return lines


def _build_enrichment_hints(
    *,
    repo_root: str,
    resolved_target: str,
    surface_context: dict,
    ranked: dict,
    repo_source_available: bool,
    next_action: str,
    browser_evidence: dict | None = None,
) -> tuple[str, list[dict]]:
    """Suggest the most useful enrichment tool before widening generic hunting."""
    if next_action in {
        "run_recon",
        "wait_recon",
        "wait_scan",
        "revalidate_finding_owner",
        "collect_candidate_evidence",
        "validate_finding",
        "review_validation_candidate",
        "resume_action_queue",
        "prepare_surface_context",
        "complete_report_draft",
        "recon_no_live_hosts",
        "report_finding",
        "run_intel",
        "collect_web_intel",
        "test_advisory_applicability",
    }:
        return "", []

    storage_key = target_storage_key(resolved_target)
    recon_dir = os.path.join(repo_root, "recon", storage_key)
    findings_dir = os.path.join(repo_root, "findings", storage_key)

    browser_evidence = browser_evidence or inspect_browser_evidence(repo_root, resolved_target)
    browser_ready = bool(browser_evidence.get("ready"))
    js_intel = _load_js_intel_projection(repo_root, resolved_target)
    js_intel_ready = str(js_intel.get("status") or "") in {
        "analyzed", *(_JS_TERMINAL_DISPOSITIONS - {"prepared"})
    }
    source_intel_ready = _has_any_artifact(
        os.path.join(findings_dir, "source_intel", "summary.md"),
        os.path.join(findings_dir, "source_intel", "hypotheses.jsonl"),
    )

    hints = []
    if next_action == "guard_safe_pivot":
        if repo_source_available and not source_intel_ready:
            hints.append({
                "tool": "run_source_intel",
                "reason": "live hosts are cooling down; source artifacts can still produce offline hypotheses",
            })
        if not js_intel_ready and _has_js_read_signal(recon_dir, surface_context):
            hints.append({
                "tool": "run_js_read",
                "reason": "live hosts are cooling down; cached JS can still produce endpoint and parameter leads",
            })
        hints.extend([
            {
                "tool": "context_pack",
                "reason": "select the safest cached-evidence route while live requests are paused",
            },
            {
                "tool": "checkpoint",
                "reason": "record the live lockout as blocked and preserve concrete next actions",
            },
        ])
        next_tool_hint = hints[0]["tool"] if hints else ""
        return next_tool_hint, hints

    if not browser_ready and _has_browser_mcp_signal(surface_context, ranked):
        reason = (
            "authenticated browser capture is missing persisted state; recapture Network and complete state"
            if browser_evidence.get("auth_required") and browser_evidence.get("auth_state") != "present"
            else "app-like or GraphQL surface signals were detected; use Chrome DevTools or Playwright MCP, then import the observed artifacts"
        )
        hints.append({
            "tool": "collect_browser_mcp_evidence",
            "reason": reason,
        })
    if repo_source_available and not source_intel_ready:
        hints.append({
            "tool": "run_source_intel",
            "reason": "repo source artifacts exist, but source_intel artifacts have not been generated yet",
        })
    if not js_intel_ready and _has_js_read_signal(recon_dir, surface_context):
        hints.append({
            "tool": "run_js_read",
            "reason": "cached JS artifacts exist, but js_intel materials have not been prepared yet",
        })

    next_tool_hint = hints[0]["tool"] if hints else ""
    return next_tool_hint, hints


def _memory_action_hint(text: str) -> str:
    lowered = str(text or "").lower()
    # This is a legacy command parser, not a fuzzy intent classifier:
    # `/validated` and prose such as "validation" must stay in the visible
    # memory queue without becoming candidate-evidence work.
    if re.search(r"(?<!\w)/validate(?![\w-])", lowered):
        return "/validate"
    if "/report" in lowered or "report" in lowered:
        return "/report"
    if "/recon" in lowered or "recon" in lowered:
        return "/recon"
    if "browser" in lowered or "xhr" in lowered:
        return "browser/playwright probe, then /surface"
    if "postman" in lowered or "leak" in lowered:
        return "review leak artifact, record evidence, then /surface"
    if "oauth" in lowered or "redirect_uri" in lowered:
        return "focused OAuth replay with red-line check"
    if "idor" in lowered or "auth" in lowered or "role" in lowered:
        return "role/object diff with low-risk replay"
    return "execute smallest safe evidence-producing step"


_NUCLEI_ACTION_RE = re.compile(r"\bnuclei\b", re.IGNORECASE)
_RAW_NUCLEI_CORPUS_RE = re.compile(
    r"(?:"
    r"\ball_historical\.txt\b|"
    r"\ball\.txt\b|"
    r"\bwith_params\.txt\b|"
    r"\b(?:gau|wayback|waymore)(?:urls)?\.txt\b|"
    r"\b(?:raw|historical)\s+(?:urls?|corpus|archive)\b|"
    r"\b(?:gau|wayback|waymore)\s+urls?\b|"
    r"历史\s*(?:URL|url|链接|语料|全集)"
    r")",
    re.IGNORECASE,
)


def _memory_nuclei_action_requires_replan(text: str) -> bool:
    """识别违反 broad-scanner 输入契约的旧 Nuclei 建议。"""
    value = str(text or "")
    return bool(_NUCLEI_ACTION_RE.search(value) and _RAW_NUCLEI_CORPUS_RE.search(value))


_MEMORY_EVIDENCE_REF_RE = re.compile(
    r"\b(?:evidence(?:_ref)?|raw_(?:request|response|artifact)(?:_path)?)\s*[:=]\s*([^\s,;]+)",
    re.IGNORECASE,
)


def _memory_evidence_ref(text: str) -> str:
    """Extract one explicit artifact pointer from legacy target-memory prose.

    Target memory is intentionally human-readable and is not a second evidence
    schema.  This narrow compatibility parser only recognises an explicit
    ``Evidence=...``/``evidence_ref=...`` token emitted by checkpoint helpers.
    Unknown prose remains evidence-missing and therefore cannot promote itself.
    """
    match = _MEMORY_EVIDENCE_REF_RE.search(str(text or ""))
    if not match:
        return ""
    return match.group(1).strip().strip("'\"").rstrip(".,;:)]}")


def _memory_evidence_available(repo_root: str | Path | None, evidence_ref: str) -> bool:
    """Return whether a legacy memory artifact pointer resolves on disk."""
    if not repo_root or not evidence_ref:
        return False
    path = Path(evidence_ref)
    if not path.is_absolute():
        path = Path(repo_root) / path
    try:
        return path.exists()
    except OSError:
        return False


def _build_memory_action_queue(
    target_goal_memory: dict,
    *,
    repo_root: str | Path | None = None,
) -> list[dict]:
    target_memory = target_goal_memory.get("target") or {}
    entries = target_memory.get("next_actions") or []
    if not isinstance(entries, list):
        return []

    queue: list[dict] = []
    for idx, item in enumerate(entries[-5:], 1):
        if isinstance(item, dict):
            text = str(item.get("text", "") or "").strip()
        else:
            text = str(item or "").strip()
        if not text:
            continue
        evidence_ref = _memory_evidence_ref(text)
        entry = {
            "id": f"M{idx}",
            "source": "target_memory",
            "action": text,
            "command_hint": _memory_action_hint(text),
        }
        if _memory_nuclei_action_requires_replan(text):
            entry.update(
                {
                    "status": "requires_replan",
                    "executable": False,
                    "command_hint": (
                        "use tools/hunt.py --target <target> --scan-only --quick for broad coverage, "
                        "or build an evidence-driven targeted list with explicit tags/templates"
                    ),
                    "replan_reason": "raw historical URL corpora are not general Nuclei inputs",
                }
            )
        if evidence_ref:
            entry["evidence_ref"] = evidence_ref
            entry["evidence_available"] = _memory_evidence_available(repo_root, evidence_ref)
        else:
            entry["evidence_available"] = False
        queue.append(entry)
    return queue


def _select_memory_candidate(memory_action_queue: list[dict]) -> dict:
    """Return the highest-priority legacy `/validate` handoff, if any.

    A durable action queue and structured finding remain authoritative.  This
    is only a recovery bridge for targets produced before checkpoint CLI queue
    synchronisation existed.
    """
    for item in memory_action_queue:
        if item.get("executable") is False:
            continue
        if str(item.get("command_hint") or "") == "/validate":
            return item
    return {}


def _is_substantive_queue_action(item: dict) -> bool:
    """仅让已有证据状态或明确 replay 命令抢占 fresh recon。"""
    status = str(item.get("status") or "queued").strip().lower()
    if status in {"running", "signal", "candidate"}:
        return True
    # focused-discovery 已经完成浏览器访问并生成 target-owned 增量证据；它不是
    # 泛化的 surface TODO，必须让 Autopilot 先审阅并选择最小 replay。
    if (
        status == "queued"
        and str(item.get("source") or "") == "browser-context-discovery"
        and str(item.get("evidence_type") or "") == "browser-context-discovery"
    ):
        return True
    # Normal Recon 会把完整 JS inventory 压成 bounded deep_candidates，并将
    # 深析交给 `/js-read`。这是已有 recon-artifact，不应被 fresh recon 过滤掉。
    action_type = str(item.get("type") or item.get("action_type") or "").strip()
    evidence_type = str(item.get("evidence_type") or "").strip()
    command_hint = str(item.get("command_hint") or "").strip()
    metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
    if (
        status in {"queued", "ready"}
        and action_type == "bypass-403"
        and evidence_type == "access-limit"
        and "summary.json" in str(item.get("evidence") or "")
    ):
        return True
    if (
        status in {"queued", "ready"}
        and action_type == "workflow-lead-review"
        and str(metadata.get("category") or "") == "asset-scope-review"
    ):
        return True
    if status == "queued" and action_type in {
        "candidate-evidence-gap",
        "actor-gap",
        "coverage-gap",
        "action-gated-review",
        "browser-enrichment",
    }:
        return True
    if status == "queued" and action_type in {"surface-review", "ranked-surface"}:
        metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
        return "validation_runner.py" in " ".join(
            (command_hint, str(metadata.get("replay_draft") or ""))
        )
    if (
        status == "queued"
        and action_type == "deep-js-review"
        and evidence_type == "recon-artifact"
        and command_hint.startswith("/js-read ")
    ):
        return True
    command = " ".join(
        str(value or "").strip()
        for value in (
            item.get("command_hint"),
            metadata.get("replay_draft"),
        )
    ).strip()
    return command.startswith(("python3 ", "/validate ", "curl "))


def _load_substantive_action_queue_next(repo_root: str, target: str) -> dict:
    """复用 action_queue 的公开 selector，不复制其排序与去重规则。"""
    queue = load_queue(repo_root, target)
    queue["actions"] = [
        item
        for item in queue.get("actions", [])
        if isinstance(item, dict)
        and (
            str(item.get("status") or "queued") not in ACTIVE_STATUSES
            or _is_substantive_queue_action(item)
        )
    ]
    selected = select_next_action(queue)
    return selected if isinstance(selected, dict) else {}


def _recon_completed_without_live_hosts(
    runtime_state: dict,
    recon_artifacts: dict,
    *,
    recon_in_progress: bool,
) -> bool:
    """识别已退出 recon 长阶段、但没有 HTTP live inventory 的终态。"""
    if recon_in_progress:
        return False
    if (
        not recon_artifacts.get("available")
        or recon_artifacts.get("host_inventory_ready")
        or recon_artifacts.get("surface_inputs_ready")
    ):
        return False
    probe = recon_artifacts.get("http_probe") or {}
    if probe.get("outcome") != "success_zero":
        # Legacy fixtures predating recon_manifest had no probe outcome. Keep
        # their explicit completed breadcrumb compatible; a present manifest
        # with missing/skipped/failed probing is never terminal.
        manifest = Path(str(recon_artifacts.get("recon_dir") or "")) / "recon_manifest.jsonl"
        if probe.get("outcome") != "missing" or manifest.exists():
            return False
    workflow = str(runtime_state.get("last_executed_workflow") or "").strip()
    # 没有完成 breadcrumb 时仍允许首次/损坏缓存执行一次 recon；所有 started
    # marker 都由 runtime gate 负责，不能误判成完成。
    return bool(workflow and not workflow.endswith("_started"))


def _fresh_recon_needs_surface_context(
    runtime_state: dict,
    *,
    has_recon: bool,
    has_memory: bool,
    recon_in_progress: bool,
) -> bool:
    """Identify the one-shot fresh recon -> surface/context handoff.

    A completed fresh recon can legitimately have only a live host inventory.
    Returning generic ``handoff`` in that state makes the next Claude session
    infer the continuation from prose.  Restrict this branch to the immediate
    recon breadcrumb so genuinely exhausted existing targets still hand off.
    """
    if not has_recon or has_memory or recon_in_progress:
        return False
    workflow = str(runtime_state.get("last_executed_workflow") or "").strip().lower()
    mode = str(runtime_state.get("mode") or "").strip().lower()
    return workflow in {"run_recon", "recon"} or mode == "recon_only"


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


def _build_batch_autopilot_state(repo_root: str, target: str, resolved_target: str) -> dict:
    """Build the list-only recon/handoff state without treating the index as a target."""
    storage_key = target_storage_key(resolved_target)
    batch_dir = Path(repo_root) / "recon" / storage_key
    manifest_path = batch_dir / "batch_manifest.jsonl"
    current_entries = target_list_entries(resolved_target)
    current_set = set(current_entries)
    completed = _read_batch_lines(batch_dir / "completed_targets.txt")
    if not completed:
        completed = _read_batch_manifest_completed(manifest_path)
    completed = [item for item in completed if item in current_set]
    failed = _read_batch_lines(batch_dir / "failed_targets.txt")
    failed = [item for item in failed if item in current_set and item not in set(completed)]
    artifact_pending = _read_batch_lines(batch_dir / "pending_targets.txt")
    processed = set(completed) | set(failed)
    # 当前 list 是 batch identity。旧 pending 仅提供顺序提示，新加入的输入也必须
    # 进入本轮 pending，不能因为同 stem 的历史 artifact 被漏掉。
    pending = [
        item
        for item in dict.fromkeys([*artifact_pending, *current_entries])
        if item in current_set and item not in processed
    ]
    runtime_state = load_runtime_state(repo_root, resolved_target)
    recon_in_progress = _runtime_recon_in_progress(repo_root, resolved_target, runtime_state)
    candidates = _read_batch_ranked_targets(
        batch_dir / "high_value_targets.json",
        completed,
    )
    scope = _scope_identity(resolved_target)
    scope_changed = False
    scope_metadata_path = batch_dir / "scope_context.json"
    if scope_metadata_path.is_file() and scope.get("scope_hash"):
        try:
            recorded_scope = json.loads(scope_metadata_path.read_text(encoding="utf-8"))
            scope_changed = bool(
                isinstance(recorded_scope, dict)
                and recorded_scope.get("scope_hash")
                and str(recorded_scope.get("scope_hash")) != str(scope["scope_hash"])
            )
        except (OSError, json.JSONDecodeError):
            scope_changed = True
    if scope_changed:
        completed = []
        failed = []
        candidates = []
        pending = list(current_entries)

    blocker = ""
    if not current_entries:
        next_action = "invalid_batch_target"
        blocker = "the current target list has no usable primary-domain entries"
    elif recon_in_progress:
        next_action = "wait_recon"
    elif candidates:
        next_action = "select_completed_domain"
    elif not pending and failed:
        next_action = "batch_failed"
        blocker = "all current batch entries failed and no pending target remains"
    else:
        next_action = "run_batch_recon"

    return {
        "target": target,
        "resolved_target": resolved_target,
        "target_kind": "list",
        "has_recon": bool(completed),
        "has_memory": False,
        "runtime_state": runtime_state,
        "recon_in_progress": recon_in_progress,
        "scan_in_progress": False,
        "scope": scope,
        "next_action": next_action,
        "batch": {
            "batch_dir": str(batch_dir),
            "manifest": str(manifest_path),
            "summary": str(batch_dir / "batch_summary.md"),
            "ai_handoff": str(batch_dir / "ai_handoff.md"),
            "surface_ranking": str(batch_dir / "surface_ranking.txt"),
            "high_value_targets": str(batch_dir / "high_value_targets.json"),
            "current_entries": current_entries,
            "completed": completed,
            "failed": failed,
            "pending": pending,
            "candidates": candidates,
            "blocker": blocker,
            "scope": scope,
            "scope_changed": scope_changed,
        },
    }


def _scope_identity(target: str) -> dict:
    """Project stable Scope identity without loading recon/discovery bodies."""
    try:
        context = ScopeContext.from_target(target)
    except ScopeContextError as exc:
        return {
            "status": "invalid",
            "scope_ref": str(target or ""),
            "scope_hash": "",
            "reason": " ".join(str(exc).split())[:300],
        }
    return {
        "status": "valid",
        "scope_ref": context.source_ref or context.root_target,
        "scope_hash": context.scope_hash,
        "summary": context.summary(),
    }


def _load_autopilot_control_facts(
    repo_root: str,
    resolved_target: str,
    resolved_memory_dir: str,
    *,
    fast_recon: bool,
) -> dict:
    """一次性读取 next-action 所需控制事实。

    Bootstrap 使用 ``fast_recon=True``，因此这里只 stat recon artifact，且
    finding reader 禁止 legacy migration。完整诊断路径复用同一事实集合，
    但保留精确 recon 计数。
    """
    resume_summary = load_resume_summary(resolved_memory_dir, resolved_target)
    finalized_paths = _finalized_finding_paths(repo_root, resolved_target)
    guard_status = load_guard_status(resolved_memory_dir, resolved_target)
    tripped_hosts = [item for item in guard_status.get("hosts", []) if item.get("tripped")]
    repo_source_artifacts = list_repo_source_artifacts(repo_root, resolved_target)
    repo_source_available = bool(repo_source_artifacts)
    repo_source_summary = (
        load_repo_source_summary(repo_root, resolved_target)
        if repo_source_available
        else {}
    )
    structured_findings = load_structured_finding_followup(
        repo_root,
        resolved_target,
        migrate_legacy=False,
    )
    root_finding_claims = list_root_finding_claims(
        Path(repo_root) / "findings" / target_storage_key(resolved_target),
        target=resolved_target,
    )
    root_finding_claim_next = root_finding_claims[0] if root_finding_claims else {}
    validation_runner_candidates = load_validation_runner_candidate_pool(
        repo_root,
        resolved_target,
    )
    validation_runner_next = (
        validation_runner_candidates[0]
        if validation_runner_candidates
        else {}
    )
    action_queue_next = _load_substantive_action_queue_next(repo_root, resolved_target)
    runtime_state = load_runtime_state(repo_root, resolved_target)
    recon_artifacts = (
        inspect_recon_artifacts_fast(repo_root, resolved_target)
        if fast_recon
        else inspect_recon_artifacts(repo_root, resolved_target)
    )
    dir_fuzz_rotation = load_rotation_status(repo_root, resolved_target)
    recon_in_progress = (
        _runtime_recon_in_progress(repo_root, resolved_target, runtime_state)
        and not bool(recon_artifacts.get("ready"))
    )
    scan_in_progress = _runtime_scan_in_progress(repo_root, resolved_target, runtime_state)
    recon_completed_no_live_hosts = _recon_completed_without_live_hosts(
        runtime_state,
        recon_artifacts,
        recon_in_progress=recon_in_progress,
    )
    target_goal_memory = load_target_goal_memory(repo_root, resolved_target)
    has_recon = bool(recon_artifacts.get("ready"))
    has_memory = resume_summary is not None
    fresh_recon_ready = _fresh_recon_needs_surface_context(
        runtime_state,
        has_recon=has_recon,
        has_memory=has_memory,
        recon_in_progress=recon_in_progress,
    )
    resume_targets = _filter_resume_targets_for_final_state(
        _build_resume_targets(resume_summary),
        finalized_paths,
    )
    recent_guard_advisories = list(
        (resume_summary or {}).get("recent_guard_advisories")
        or (resume_summary or {}).get("recent_guard_blocks", [])
        or []
    )
    memory_action_queue = _build_memory_action_queue(
        target_goal_memory,
        repo_root=repo_root,
    )
    intel_continuation = inspect_intel_continuation(repo_root, resolved_target)
    browser_evidence = inspect_browser_evidence(repo_root, resolved_target)
    json_inject = _load_json_inject_projection(repo_root, resolved_target)
    sql_matrix = _load_sql_matrix_projections(repo_root, resolved_target)
    js_intel = _load_js_intel_projection(repo_root, resolved_target)
    case_state = _load_case_state_projection(repo_root, resolved_target)
    return {
        "repo_root": repo_root,
        "resolved_target": resolved_target,
        "resolved_memory_dir": resolved_memory_dir,
        "resume_summary": resume_summary,
        "guard_status": guard_status,
        "tripped_hosts": tripped_hosts,
        "repo_source_artifacts": repo_source_artifacts,
        "repo_source_available": repo_source_available,
        "repo_source_summary": repo_source_summary,
        "structured_findings": structured_findings,
        "root_finding_claims": root_finding_claims,
        "root_finding_claim_next": root_finding_claim_next,
        "validation_runner_candidates": validation_runner_candidates,
        "validation_runner_next": validation_runner_next,
        "action_queue_next": action_queue_next,
        "runtime_state": runtime_state,
        "recon_artifacts": recon_artifacts,
        "dir_fuzz_rotation": dir_fuzz_rotation,
        "recon_in_progress": recon_in_progress,
        "scan_in_progress": scan_in_progress,
        "recon_completed_no_live_hosts": recon_completed_no_live_hosts,
        "target_goal_memory": target_goal_memory,
        "has_recon": has_recon,
        "has_memory": has_memory,
        "fresh_recon_ready": fresh_recon_ready,
        "resume_targets": resume_targets,
        "recent_guard_advisories": recent_guard_advisories,
        "memory_action_queue": memory_action_queue,
        "memory_candidate_next": _select_memory_candidate(memory_action_queue),
        "intel_continuation": intel_continuation,
        "browser_evidence": browser_evidence,
        "json_inject": json_inject,
        "sql_matrix": sql_matrix,
        "js_intel": js_intel,
        "case_state": case_state,
    }


def _build_domain_autopilot_state(
    target: str,
    facts: dict,
    ranked: dict,
    *,
    observation_inventory: dict,
    surface_projection: dict,
    surface_context: dict | None = None,
    surface_context_required: bool = False,
    include_enrichment: bool = True,
) -> dict:
    """由共享控制事实和一个 surface 视图生成兼容 state。"""
    resolved_target = str(facts["resolved_target"])
    resolved_memory_dir = str(facts["resolved_memory_dir"])
    ranked_for_next = _filter_ranked_placeholders(ranked)
    resume_summary = facts.get("resume_summary")
    has_recon = bool(facts.get("has_recon"))
    guard_status = facts.get("guard_status") or {}
    tripped_hosts = facts.get("tripped_hosts") or []
    resume_targets = facts.get("resume_targets") or []

    tech_stack = []
    if resume_summary and resume_summary.get("tech_stack"):
        tech_stack = resume_summary["tech_stack"]
    elif has_recon:
        review_pool = ranked_for_next.get("review_pool", []) or ranked_for_next.get("p1", [])
        if review_pool:
            tech_stack = review_pool[0].get("tech_stack", [])

    primary_next_action = _pick_next_action(
        has_recon,
        ranked_for_next,
        resume_summary,
        facts.get("structured_findings"),
        facts.get("validation_runner_next"),
        facts.get("action_queue_next"),
        resume_targets=resume_targets,
        recon_in_progress=bool(facts.get("recon_in_progress")),
        scan_in_progress=bool(facts.get("scan_in_progress")),
        recon_completed_no_live_hosts=bool(facts.get("recon_completed_no_live_hosts")),
        memory_candidate_next=facts.get("memory_candidate_next"),
        root_finding_claim_next=facts.get("root_finding_claim_next"),
        # fresh-recon handoff only requests surface preparation while no exact
        # projection exists. A valid empty/low-value projection is still a
        # completed review, otherwise bootstrap can loop on refresh forever.
        fresh_recon_ready=(
            bool(facts.get("fresh_recon_ready"))
            and surface_projection.get("status") != "valid"
        ),
        surface_context_required=surface_context_required,
        cidr_continuation=(facts.get("recon_artifacts") or {}).get("cidr_continuation"),
        dir_fuzz_rotation_pending=bool(
            (facts.get("dir_fuzz_rotation") or {}).get("pending")
        ),
        case_state_next=(facts.get("case_state") or {}).get("top_next_action") or {},
    )
    intel_continuation = facts.get("intel_continuation") or {}
    next_action = apply_intel_continuation(primary_next_action, intel_continuation)
    surface_review_candidates = (
        _build_recommended_targets(
            _candidate_items_for_next_action(ranked_for_next, next_action),
            guard_status,
            resume_targets,
            prefer_resume_targets=next_action == "continue_last_focus",
        )
        if has_recon and next_action not in {
            "run_intel",
            "collect_web_intel",
            "test_advisory_applicability",
        }
        else []
    )
    guard_state = {
        "tracked_hosts": guard_status.get("tracked_hosts", 0),
        "ready_hosts": guard_status.get("ready_hosts", 0),
        "tripped_hosts": tripped_hosts,
        "settings": guard_status.get("settings", {}),
    }
    if has_recon and _should_guard_safe_pivot(next_action, guard_status):
        next_action = "guard_safe_pivot"
    pivot_hint = _build_pivot_hint(
        tripped_hosts=tripped_hosts,
        recent_guard_advisories=facts.get("recent_guard_advisories") or [],
        repo_source_summary=facts.get("repo_source_summary") or {},
    )
    if include_enrichment:
        next_tool_hint, enrichment_hints = _build_enrichment_hints(
            repo_root=str(facts["repo_root"]),
            resolved_target=resolved_target,
            surface_context=surface_context or {},
            ranked=ranked_for_next,
            repo_source_available=bool(facts.get("repo_source_available")),
            next_action=next_action,
            browser_evidence=facts.get("browser_evidence") or {},
        )
    else:
        next_tool_hint, enrichment_hints = "", []
    if next_action in {"run_intel", "collect_web_intel", "test_advisory_applicability"}:
        next_tool_hint = next_action
        enrichment_hints = [{
            "tool": next_action,
            "reason": str(intel_continuation.get("reason") or "software intelligence continuation"),
        }]

    recon_completed_no_live_hosts = bool(facts.get("recon_completed_no_live_hosts"))
    recent_guard_advisories = facts.get("recent_guard_advisories") or []
    browser_required = bool(
        has_recon and _has_browser_mcp_signal(surface_context or {}, ranked_for_next)
    )
    return {
        "target": target,
        "resolved_target": resolved_target,
        "target_kind": classify_target(resolved_target)["kind"],
        "scope": _scope_identity(resolved_target),
        "memory_dir": resolved_memory_dir,
        "has_recon": has_recon,
        "has_memory": bool(facts.get("has_memory")),
        "repo_source_available": bool(facts.get("repo_source_available")),
        "repo_source_artifacts": facts.get("repo_source_artifacts") or [],
        "repo_source_summary": facts.get("repo_source_summary") or {},
        "browser_evidence": facts.get("browser_evidence") or {},
        "browser_required": browser_required,
        "json_inject": facts.get("json_inject") or {},
        "sql_matrix": facts.get("sql_matrix") or {},
        "js_intel": facts.get("js_intel") or {},
        "case_state": facts.get("case_state") or {},
        "runtime_state": facts.get("runtime_state") or {},
        "recon_artifacts": facts.get("recon_artifacts") or {},
        "dir_fuzz_rotation": facts.get("dir_fuzz_rotation") or {},
        "recon_in_progress": bool(facts.get("recon_in_progress")),
        "scan_in_progress": bool(facts.get("scan_in_progress")),
        "recon_completed_no_live_hosts": recon_completed_no_live_hosts,
        "fresh_recon_ready": bool(facts.get("fresh_recon_ready")),
        "recon_blocker": (
            "recon completed with no live host inventory"
            if recon_completed_no_live_hosts
            else ""
        ),
        "structured_findings": facts.get("structured_findings") or {},
        "root_finding_claims": facts.get("root_finding_claims") or [],
        "root_finding_claim_next": facts.get("root_finding_claim_next") or {},
        "validation_runner_candidates": facts.get("validation_runner_candidates") or [],
        "validation_runner_next": facts.get("validation_runner_next") or {},
        "action_queue_next": facts.get("action_queue_next") or {},
        "action_queue": {"next": facts.get("action_queue_next") or {}},
        "target_goal_memory": facts.get("target_goal_memory") or {},
        "memory_candidate_next": facts.get("memory_candidate_next") or {},
        "resume_summary": resume_summary,
        "surface": ranked_for_next if has_recon else None,
        "surface_projection": surface_projection,
        "observation_inventory": observation_inventory,
        "guard_status": guard_state,
        "guard_hint": _build_guard_hint(guard_state, surface_review_candidates),
        "pivot_hint": pivot_hint,
        "tech_stack": tech_stack,
        "next_action": next_action,
        "primary_next_action": primary_next_action,
        "intel_continuation": intel_continuation,
        "next_tool_hint": next_tool_hint,
        "enrichment_hints": enrichment_hints,
        "memory_action_queue": facts.get("memory_action_queue") or [],
        "resume_targets": resume_targets,
        "surface_review_candidates": surface_review_candidates,
        "recommended_targets": surface_review_candidates,
        "recent_guard_advisories": recent_guard_advisories[:3],
        "recent_guard_blocks": recent_guard_advisories[:3],
    }


def build_autopilot_bootstrap_state(
    repo_root: str,
    target: str,
    memory_dir: str | None = None,
) -> dict:
    """构建 slash expansion 专用的严格只读、bounded state。"""
    resolved_memory_dir = memory_dir or str(default_memory_dir(repo_root))
    resolved_target = canonical_target_value(target)
    if classify_target(resolved_target)["kind"] == "list":
        # Bootstrap 不执行 legacy storage migration；显式 owner 命令负责迁移。
        return _build_batch_autopilot_state(repo_root, target, resolved_target)

    facts = _load_autopilot_control_facts(
        repo_root,
        resolved_target,
        resolved_memory_dir,
        fast_recon=True,
    )
    observation_inventory = peek_inventory_summary(repo_root, resolved_target)
    projection = load_surface_projection(
        repo_root,
        resolved_target,
        memory_dir=resolved_memory_dir,
    )
    if projection.get("status") == "valid":
        ranked = dict(projection.get("surface") or {})
        ranked["available"] = bool(facts.get("has_recon"))
        ranked["target"] = resolved_target
        ranked["runtime_state"] = facts.get("runtime_state") or {}
        ranked["recon_artifacts"] = facts.get("recon_artifacts") or {}
        ranked["observation_inventory"] = observation_inventory
    else:
        ranked = {
            "available": bool(facts.get("has_recon")),
            "target": resolved_target,
            "runtime_state": facts.get("runtime_state") or {},
            "recon_artifacts": facts.get("recon_artifacts") or {},
            "observation_inventory": observation_inventory,
            "p1": [],
            "p2": [],
            "review_pool": [],
        }

    return _build_domain_autopilot_state(
        target,
        facts,
        ranked,
        observation_inventory=observation_inventory,
        surface_projection={
            "status": str(projection.get("status") or "invalid"),
            "reason": str(projection.get("reason") or ""),
            "path": str(projection.get("path") or ""),
            "refresh_command": f"python3 tools/surface.py --target {resolved_target} --refresh",
        },
        surface_context_required=(
            bool(facts.get("has_recon")) and projection.get("status") != "valid"
        ),
        include_enrichment=False,
    )


def build_autopilot_state(
    repo_root: str,
    target: str,
    memory_dir: str | None = None,
    *,
    bounded: bool = False,
) -> dict:
    """Build an autopilot state; bounded mode never rebuilds the full surface."""
    if bounded:
        return build_autopilot_bootstrap_state(repo_root, target, memory_dir=memory_dir)
    resolved_memory_dir = memory_dir or str(default_memory_dir(repo_root))
    resolved_target = canonical_target_value(target)
    if classify_target(resolved_target)["kind"] == "list":
        migrate_legacy_list_storage(repo_root, resolved_target)
        return _build_batch_autopilot_state(repo_root, target, resolved_target)
    facts = _load_autopilot_control_facts(
        repo_root,
        resolved_target,
        resolved_memory_dir,
        fast_recon=False,
    )
    projection = load_surface_projection(
        repo_root,
        resolved_target,
        memory_dir=resolved_memory_dir,
    )
    if projection.get("status") == "valid":
        # 完整诊断保留精确 recon metadata，但 surface 候选复用同一 exact-hit
        # projection，避免 checkpoint/context-pack 在同一 fingerprint 上重排。
        ranked = dict(projection.get("surface") or {})
        ranked["available"] = bool(facts.get("has_recon"))
        ranked["target"] = resolved_target
        ranked["runtime_state"] = facts.get("runtime_state") or {}
        ranked["recon_artifacts"] = facts.get("recon_artifacts") or {}
        surface_context = {
            "target": resolved_target,
            "available": bool(facts.get("has_recon")),
            "recon_dir": str(
                Path(repo_root) / "recon" / target_storage_key(resolved_target)
            ),
            "hosts": {},
            "js_endpoints": [],
        }
    else:
        # Legacy/missing cache compatibility：显式 full state 仍可重建；slash
        # bootstrap 永远不会走到这个无界 fallback。
        surface_context = load_surface_context(
            repo_root,
            resolved_target,
            memory_dir=resolved_memory_dir,
            write_probe_log=False,
        )
        ranked = rank_surface(surface_context)
    return _build_domain_autopilot_state(
        target,
        facts,
        ranked,
        observation_inventory=ranked.get("observation_inventory") or {},
        surface_projection={
            "status": str(projection.get("status") or "computed"),
            "reason": str(projection.get("reason") or ""),
            "path": str(projection.get("path") or ""),
        },
        surface_context_required=(
            bool(facts.get("has_recon")) and projection.get("status") != "valid"
        ),
        surface_context=surface_context,
    )


_TERMINAL_CLOSURE_ACTIONS = {
    "invalid_batch_target",
    "batch_failed",
    "recon_no_live_hosts",
}
_ROTATION_OUTCOMES = {"tested_clean", "dead_end"}
_LOOP_GUARD_ROTATABLE_ACTIONS = {
    "handoff",
    "continue_last_focus",
    "resume_untested",
    "hunt_p1",
    "hunt_p2",
    "guard_safe_pivot",
}
_UUID_SEGMENT_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_VARIABLE_PATH_SEGMENT_RE = re.compile(r"^(?:\d+|[0-9a-f]{12,})$", re.IGNORECASE)


def _endpoint_family(endpoint: object) -> str:
    """Collapse common object-id path segments for the advisory rotation check."""
    path = _normalise_endpoint_path(str(endpoint or ""))
    return "/".join(
        ":id" if _UUID_SEGMENT_RE.fullmatch(segment) or _VARIABLE_PATH_SEGMENT_RE.fullmatch(segment) else segment
        for segment in path.split("/")
    ) or "/"


def _rotation_hint(entries: list[dict]) -> dict:
    recent = entries[-3:]
    if len(recent) != 3 or not all(isinstance(item, dict) for item in recent):
        return {}
    outcomes = {str(item.get("result") or "").strip().lower() for item in recent}
    endpoints = [str(item.get("endpoint") or item.get("url") or "").strip() for item in recent]
    if not all(endpoints):
        return {}
    families = {_endpoint_family(endpoint) for endpoint in endpoints}
    vuln_classes = {str(item.get("vuln_class") or "").strip() for item in recent}
    if outcomes <= _ROTATION_OUTCOMES and len(families) == len(vuln_classes) == 1 and next(iter(vuln_classes)):
        return {
            "reason": "three_homogeneous_clean_outcomes",
            "endpoint_family": next(iter(families)),
            "vuln_class": next(iter(vuln_classes)),
            "action": "rotate_to_adjacent_high_value_lane",
        }
    return {}


def _rotation_target(state: dict, blocked_family: str) -> dict:
    """Choose one bounded adjacent Surface candidate without changing its rank."""
    candidates = state.get("surface_review_candidates") or state.get("recommended_targets") or []
    target = str(state.get("resolved_target") or state.get("target") or "")
    eligible = [
        item
        for item in candidates
        if isinstance(item, dict)
        and (url := str(item.get("url") or "").strip())
        and url_belongs_to_target(url, target)
        and _endpoint_family(url) != blocked_family
    ]
    if not eligible:
        return {}
    candidate = next((item for item in eligible if item.get("new_observation")), eligible[0])
    return {
        key: candidate[key]
        for key in ("url", "host", "suggested", "score", "review_reason", "new_observation")
        if key in candidate
    }


def _loop_guard_authoritative_reason(state: dict) -> str:
    """Keep a stale handoff from rotating past durable control-plane work."""
    if state.get("recon_in_progress") or state.get("scan_in_progress"):
        return "authoritative_runtime_work"
    if (
        state.get("active_action_queue_count")
        or state.get("action_queue_next")
        or state.get("validation_runner_next")
    ):
        return "authoritative_durable_work"
    case_state = state.get("case_state") or {}
    if (
        int(case_state.get("pending_validation_backlog", 0) or 0) > 0
        or int(case_state.get("open_hypotheses", 0) or 0) > 0
        or str((case_state.get("top_next_action") or {}).get("next_action") or "none") != "none"
    ):
        return "authoritative_case_state_work"
    if state.get("root_finding_claim_next") or state.get("memory_candidate_next"):
        return "authoritative_finding_work"
    findings = state.get("structured_findings") or {}
    if isinstance(findings, dict) and any(
        findings.get(key)
        for key in (
            "next_owner_revalidation",
            "next_validation",
            "draft_completion_pending",
            "validated_pending_report",
        )
    ):
        return "authoritative_finding_work"
    intel = state.get("intel_continuation") or {}
    if isinstance(intel, dict) and intel.get("blocked"):
        return "authoritative_intel_work"
    return ""


def build_loop_guard_projection(state: dict, ledger_entries: list[dict] | None = None) -> dict:
    """Return a read-only per-iteration rotation decision from recent evidence."""
    action = str(state.get("next_action") or "handoff")
    authoritative_reason = _loop_guard_authoritative_reason(state)
    if authoritative_reason:
        return {
            "verdict": "continue",
            "reason": authoritative_reason,
            "endpoint_family": "",
            "vuln_class": "",
            "next_action": action,
            "rotation_target": {},
        }
    hint = _rotation_hint(ledger_entries or [])
    if not hint:
        return {
            "verdict": "continue",
            "reason": "insufficient_homogeneous_outcomes",
            "endpoint_family": "",
            "vuln_class": "",
            "next_action": action,
            "rotation_target": {},
        }
    if action not in _LOOP_GUARD_ROTATABLE_ACTIONS:
        return {
            "verdict": "continue",
            "reason": "authoritative_next_action",
            "endpoint_family": hint["endpoint_family"],
            "vuln_class": hint["vuln_class"],
            "next_action": action,
            "rotation_target": {},
        }
    return {
        "verdict": "rotate",
        "reason": hint["reason"],
        "endpoint_family": hint["endpoint_family"],
        "vuln_class": hint["vuln_class"],
        "next_action": hint["action"],
        "rotation_target": _rotation_target(state, hint["endpoint_family"]),
    }


def _matrix_is_usable_for_closure(matrix: object) -> bool:
    """Reject damaged coverage rather than treating unknown cells as clean."""
    if not isinstance(matrix, dict):
        return False
    endpoints = matrix.get("endpoints")
    if not isinstance(endpoints, list) or not endpoints:
        return False
    if matrix.get("_coverage_projection"):
        summary = matrix.get("summary")
        gaps = matrix.get("_coverage_gaps")
        if not isinstance(summary, dict) or not isinstance(gaps, list):
            return False
        try:
            if int(summary.get("high_value_gaps_count", -1)) < 0:
                return False
        except (TypeError, ValueError):
            return False
    for endpoint in endpoints:
        if not isinstance(endpoint, dict) or not str(endpoint.get("endpoint") or "").strip():
            return False
        cells = endpoint.get("cells")
        if not isinstance(cells, dict) or (not cells and not matrix.get("_coverage_projection")):
            return False
        for vuln_class, cell in cells.items():
            if vuln_class not in VULN_CLASSES or not isinstance(cell, dict):
                return False
            if cell.get("status") not in STATUS_VALUES:
                return False
    return True


def _coverage_gaps(matrix: dict) -> list[dict]:
    if matrix.get("_coverage_projection"):
        return [item for item in matrix.get("_coverage_gaps") or [] if isinstance(item, dict)]
    return high_value_gaps_from_matrix(matrix)


def _coverage_has_high_value_gaps(matrix: dict) -> bool:
    if matrix.get("_coverage_projection"):
        try:
            return int((matrix.get("summary") or {}).get("high_value_gaps_count", 0)) > 0
        except (TypeError, ValueError):
            return True
    return bool(high_value_gaps_from_matrix(matrix))


def _final_queue_endpoint_paths(queue: dict) -> set[str]:
    """Return exact endpoint identities with a durable final queue outcome."""
    paths: set[str] = set()
    for action in queue.get("actions") or []:
        if not isinstance(action, dict):
            continue
        if str(action.get("status") or "").strip().lower() not in FINAL_STATUSES:
            continue
        metadata = action.get("metadata") if isinstance(action.get("metadata"), dict) else {}
        endpoint = _normalise_endpoint_path(
            str(metadata.get("endpoint") or metadata.get("url") or "")
        )
        if endpoint:
            paths.add(endpoint)
    return paths


def _closed_ledger_endpoint_paths(summary: dict) -> set[str]:
    """Return endpoint paths from the Ledger owner's current projection."""
    paths: set[str] = set()
    for cell in summary.get("closed_cells") or []:
        if not isinstance(cell, dict):
            continue
        endpoint = _normalise_endpoint_path(str(cell.get("endpoint") or ""))
        if endpoint:
            paths.add(endpoint)
    return paths


def _surface_review_completion(
    state: dict,
    matrix: dict | None,
    queue: dict,
    ledger_summary: dict,
) -> dict:
    """Project whether the current bounded Surface window still owns work.

    Surface keeps every raw URL visible.  This projection only releases the
    terminal gate when each currently offered URL has both a completed
    endpoint-level coverage view and a durable review outcome.  A single lane
    therefore cannot make a raw URL identity final.
    """
    candidates = state.get("surface_review_candidates") or state.get("recommended_targets") or []
    if not candidates:
        return {"status": "none", "unresolved": []}
    if not _matrix_is_usable_for_closure(matrix):
        return {"status": "unresolved", "unresolved": [{"reason": "coverage_unavailable"}]}

    matrix_by_path = {
        _normalise_endpoint_path(str(item.get("endpoint") or "")): item
        for item in matrix.get("endpoints") or []
        if isinstance(item, dict) and _normalise_endpoint_path(str(item.get("endpoint") or ""))
    }
    high_gap_paths = {
        _normalise_endpoint_path(str(gap.get("endpoint") or ""))
        for gap in _coverage_gaps(matrix)
        if isinstance(gap, dict)
    }
    final_paths = _final_queue_endpoint_paths(queue) | _closed_ledger_endpoint_paths(ledger_summary)
    unresolved = []
    for candidate in candidates:
        if not isinstance(candidate, dict):
            unresolved.append({"reason": "invalid_candidate"})
            continue
        url = str(candidate.get("url") or "").strip()
        endpoint = _normalise_endpoint_path(url)
        if not endpoint:
            unresolved.append({"url": url, "reason": "missing_endpoint"})
        elif endpoint not in matrix_by_path:
            unresolved.append({"url": url, "reason": "coverage_endpoint_missing"})
        elif endpoint in high_gap_paths:
            unresolved.append({"url": url, "reason": "coverage_gap_pending"})
        elif endpoint not in final_paths:
            unresolved.append({"url": url, "reason": "review_outcome_missing"})
    return {"status": "complete" if not unresolved else "unresolved", "unresolved": unresolved[:5]}


def _explicit_partial_reason(state: dict) -> str:
    """Keep a stale handoff state from hiding durable work owned elsewhere."""
    if state.get("recon_in_progress") or state.get("scan_in_progress"):
        return "runtime_phase_active"
    continuation = (state.get("recon_artifacts") or {}).get("cidr_continuation") or {}
    if continuation.get("status") == "invalid":
        return "cidr_continuation_invalid"
    if state.get("active_action_queue_count"):
        return "durable_work_pending"
    if state.get("action_queue_next") or state.get("validation_runner_next"):
        return "durable_work_pending"
    if state.get("root_finding_claim_next") or state.get("memory_candidate_next"):
        return "finding_work_pending"
    findings = state.get("structured_findings") or {}
    if isinstance(findings, dict) and any(
        findings.get(key)
        for key in (
            "next_owner_revalidation",
            "next_validation",
            "draft_completion_pending",
            "validated_pending_report",
        )
    ):
        return "finding_work_pending"
    surface_review = state.get("surface_review_completion") or {}
    if (
        state.get("surface_review_candidates") or state.get("recommended_targets")
    ) and surface_review.get("status") != "complete":
        return "surface_work_pending"
    if state.get("resume_targets"):
        return "surface_work_pending"

    return ""


def _observation_partial_reason(state: dict) -> str:
    """Return the bounded Observation prerequisite after actionable lanes."""
    inventory = state.get("observation_inventory") or {}
    inventory_status = str(inventory.get("status") or "")
    if inventory_status and inventory_status != "valid":
        return "observation_inventory_partial"
    by_kind = inventory.get("by_kind") if isinstance(inventory.get("by_kind"), dict) else {}
    if any(
        int((by_kind.get(kind) or {}).get("present_untouched", 0) or 0) > 0
        for kind in HIGH_VALUE_OBSERVATION_KINDS
    ):
        return "observation_high_value_pending"
    return ""


def build_closure_projection(
    state: dict,
    matrix: dict | None,
    ledger_entries: list[dict] | None = None,
    *,
    max_lanes_reached: bool = False,
) -> dict:
    """Return the explicit, read-only closure verdict for an existing state."""
    reasons: list[str] = []
    action = str(state.get("next_action") or "handoff")
    surface_review = state.get("surface_review_completion") or {}
    surface_projection = state.get("surface_projection")
    surface_projection_pending = bool(
        isinstance(surface_projection, dict)
        and surface_projection
        and bool(state.get("has_recon") or state.get("surface_context_required"))
        and str(surface_projection.get("status") or "").strip().lower() != "valid"
    )
    case_state = state.get("case_state") or {}
    case_state_pending = (
        str(case_state.get("status") or "missing") == "valid"
        and (
            int(case_state.get("pending_validation_backlog", 0) or 0) > 0
            or int(case_state.get("open_hypotheses", 0) or 0) > 0
            or str((case_state.get("top_next_action") or {}).get("next_action") or "none") != "none"
        )
    )
    if action in {"hunt_p1", "hunt_p2"} and surface_review.get("status") == "complete":
        action = "handoff"
    round_progress = state.get("round_progress") or {}
    round_active = round_progress.get("status") == "active"
    if round_active and round_progress.get("unfinished_lanes"):
        action = "resume_round_lane"
        verdict = "handoff"
        reasons.append("round_lane_unfinished")
    elif round_active and int(round_progress.get("claimed_count", 0) or 0) > 0:
        action = "complete_round_closure"
        verdict = "handoff"
        reasons.append("round_closure_pending")
    elif max_lanes_reached:
        verdict = "handoff"
        reasons.append("max_lanes_reached")
    elif action in _TERMINAL_CLOSURE_ACTIONS:
        verdict = "blocked"
        reasons.append(action)
    elif case_state_pending:
        verdict = "handoff"
        reasons.append("case_state_work_pending")
    elif surface_projection_pending:
        verdict = "handoff"
        reasons.append("surface_projection_pending")
    elif action != "handoff":
        verdict = "handoff"
        reasons.append("next_action_pending")
    elif matrix is None:
        verdict = "handoff"
        reasons.append("coverage_missing")
    elif not isinstance(matrix, dict) or not matrix.get("endpoints"):
        verdict = "handoff"
        reasons.append("coverage_empty")
    elif not _matrix_is_usable_for_closure(matrix):
        verdict = "handoff"
        reasons.append("coverage_invalid")
    elif _coverage_has_high_value_gaps(matrix):
        verdict = "handoff"
        reasons.append("coverage_high_value_gaps")
    else:
        browser = state.get("browser_evidence") or {}
        source = state.get("repo_source_summary") or {}
        intel = state.get("intel_continuation") or {}
        json_inject = state.get("json_inject") or {}
        sql_matrix = state.get("sql_matrix") or {}
        js_intel = state.get("js_intel") or {}
        enrichment_tools = {
            str(item.get("tool") or "")
            for item in state.get("enrichment_hints") or []
            if isinstance(item, dict)
        }
        source_status = str(source.get("status") or "").strip().lower()
        partial_reason = _explicit_partial_reason(state)
        observation_reason = _observation_partial_reason(state)
        if partial_reason:
            verdict = "handoff"
            reasons.append(partial_reason)
        elif str(json_inject.get("status") or "") == "candidate_pending":
            verdict = "handoff"
            reasons.append("json_candidate_pending")
        elif str(json_inject.get("status") or "") in {"partial", "invalid_input"}:
            verdict = "handoff"
            reasons.append("json_evidence_partial")
        elif any(
            str(item.get("status") or "") == "candidate_pending"
            for item in sql_matrix.values()
            if isinstance(item, dict)
        ):
            verdict = "handoff"
            reasons.append("sql_candidate_pending")
        elif any(
            str(item.get("status") or "") in {"partial", "invalid_input"}
            for item in sql_matrix.values()
            if isinstance(item, dict)
        ):
            verdict = "handoff"
            reasons.append("sql_evidence_partial")
        elif str(js_intel.get("status") or "") in {"prepared", "partial"}:
            verdict = "handoff"
            reasons.append("js_evidence_partial")
        elif browser.get("present") and not browser.get("ready"):
            verdict = "handoff"
            reasons.append("browser_evidence_partial")
        elif state.get("browser_required") and not browser.get("ready"):
            verdict = "handoff"
            reasons.append("browser_evidence_required")
        elif source_status in {
            "partial", "blocked", "failed", "error", "incomplete", "confirmation_required",
        }:
            verdict = "handoff"
            reasons.append("source_evidence_partial")
        elif "run_source_intel" in enrichment_tools:
            verdict = "handoff"
            reasons.append("source_evidence_partial")
        elif "run_js_read" in enrichment_tools:
            verdict = "handoff"
            reasons.append("js_evidence_partial")
        elif intel.get("blocked"):
            verdict = "handoff"
            reasons.append("intel_evidence_blocked")
        elif observation_reason:
            verdict = "handoff"
            reasons.append(observation_reason)
        else:
            verdict = "finish"

    result = {
        "verdict": verdict,
        "can_claim_exhausted": verdict == "finish",
        "reasons": reasons[:3],
        "next_action": action,
        "rotation_hint": _rotation_hint(ledger_entries or []),
        "surface_review": surface_review,
    }
    if round_progress:
        result["round_progress"] = round_progress
    return result


_STAGNANT_REASONS = {
    "browser_evidence_partial",
    "browser_evidence_required",
    "observation_inventory_partial",
    "observation_high_value_pending",
    "source_evidence_partial",
    "js_evidence_partial",
    "surface_projection_pending",
    "intel_evidence_blocked",
    "json_evidence_partial",
    "sql_evidence_partial",
}


def stagnation_fingerprint(state: dict, closure: dict) -> str:
    """Fingerprint only explicit prerequisite blockers; other handoffs never count."""
    projected = str(closure.get("stagnation_fingerprint") or "")
    if projected:
        return projected
    reasons = closure.get("reasons") or []
    reason = str(reasons[0] if reasons else "")
    if closure.get("verdict") != "handoff" or reason not in _STAGNANT_REASONS:
        return ""
    payload = {
        "target": str(state.get("resolved_target") or state.get("target") or ""),
        "reason": reason,
        "next_action": str(closure.get("next_action") or ""),
        "browser": {
            key: (state.get("browser_evidence") or {}).get(key)
            for key in ("present", "ready", "fingerprint", "status")
        },
        "source": {
            key: (state.get("repo_source_summary") or {}).get(key)
            for key in ("status", "fingerprint", "input_fingerprint")
        },
        "intel": {
            "blocked": (state.get("intel_continuation") or {}).get("blocked") or [],
            "reason": (state.get("intel_continuation") or {}).get("reason") or "",
        },
        "surface_projection": {
            key: (state.get("surface_projection") or {}).get(key)
            for key in ("status", "reason", "path")
        },
        "json": {
            key: (state.get("json_inject") or {}).get(key)
            for key in ("status", "input_fingerprint", "request_count", "transport_error_count")
        },
        "sql": {
            lane: {
                key: item.get(key)
                for key in ("status", "input_fingerprint", "request_count", "transport_error_count")
            }
            for lane, item in (state.get("sql_matrix") or {}).items()
            if isinstance(item, dict)
        },
        "js": {
            key: (state.get("js_intel") or {}).get(key)
            for key in ("status", "reason", "hypothesis_count")
        },
        "observations": {
            "status": (state.get("observation_inventory") or {}).get("status"),
            "by_kind": (state.get("observation_inventory") or {}).get("by_kind") or {},
        },
        "durable": {
            "active_actions": int(state.get("active_action_queue_count", 0) or 0),
            "queue_next": str((state.get("action_queue_next") or {}).get("id") or ""),
            "findings": {
                key: (state.get("structured_findings") or {}).get(key)
                for key in ("total", "pending_validation", "validated", "reported", "rejected")
            },
            "coverage": str(state.get("_stagnation_coverage") or ""),
            "ledger": str(state.get("_stagnation_ledger") or ""),
        },
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _semantic_coverage_fingerprint(matrix: dict | None) -> str:
    """Hash coverage meaning, not rebuild timestamps."""
    if not isinstance(matrix, dict):
        return ""
    semantic = {
        key: value
        for key, value in matrix.items()
        if key not in {"last_updated", "_coverage_projection"}
    }
    encoded = json.dumps(semantic, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def load_closure_projection(
    repo_root: str,
    state: dict,
    *,
    max_lanes_reached: bool,
    apply_round_guard: bool = True,
) -> dict:
    """Read existing closure inputs only for an explicit CLI request."""
    target = str(state.get("resolved_target") or state.get("target") or "")
    matrix_path = Path(repo_root) / "evidence" / target_storage_key(target) / "coverage_matrix.json"
    matrix = load_matrix_projection(target, repo_root)
    if matrix is None and matrix_path.is_file():
        matrix = load_matrix(target, repo_root)
    queue = load_queue(repo_root, target)
    _, artifact_hints = _build_enrichment_hints(
        repo_root=repo_root,
        resolved_target=target,
        surface_context={},
        ranked=state.get("surface") or {},
        repo_source_available=bool(state.get("repo_source_available")),
        next_action="handoff",
        browser_evidence={"ready": True},
    )
    enrichment_hints = [
        item
        for item in [*(state.get("enrichment_hints") or []), *artifact_hints]
        if isinstance(item, dict)
        and str(item.get("tool") or "") in {"run_source_intel", "run_js_read"}
    ]
    ledger_entries = load_entries(repo_root, target)
    ledger_summary = build_current_cell_projection(ledger_entries)
    witness_path = Path(repo_root) / "state" / target_storage_key(target) / "checkpoint_latest.json"
    witness = _load_checkpoint_witness(witness_path)
    round_progress = _checkpoint_round_projection(witness)
    closure_state = {
        **state,
        "round_progress": round_progress,
        "enrichment_hints": enrichment_hints,
        "active_action_queue_count": sum(
            isinstance(item, dict)
            and str(item.get("status") or "queued").strip().lower() in ACTIVE_STATUSES
            for item in queue.get("actions") or []
        ),
        "surface_review_completion": _surface_review_completion(
            state,
            matrix,
            queue,
            ledger_summary,
        ),
        "_stagnation_coverage": _semantic_coverage_fingerprint(matrix),
        "_stagnation_ledger": hashlib.sha256(
            json.dumps(ledger_entries, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        ).hexdigest(),
    }
    closure = build_closure_projection(
        closure_state,
        matrix,
        ledger_entries,
        max_lanes_reached=max_lanes_reached,
    )
    guard = witness.get("round_guard") if isinstance(witness.get("round_guard"), dict) else {}
    fingerprint = stagnation_fingerprint(closure_state, closure)
    if fingerprint:
        closure["stagnation_fingerprint"] = fingerprint
    if (
        apply_round_guard
        and fingerprint
        and fingerprint == str(guard.get("fingerprint") or "")
        and int(guard.get("consecutive", 0) or 0) >= 3
    ):
        closure.update({
            "verdict": "blocked",
            "can_claim_exhausted": False,
            "reasons": ["stagnant_prerequisite"],
            "round_guard": guard,
        })
    elif guard:
        closure["round_guard"] = guard
    return closure


_load_closure_projection = load_closure_projection


def _load_loop_guard_projection(repo_root: str, state: dict) -> dict:
    """Read the ledger only for an explicit per-iteration loop check."""
    target = str(state.get("resolved_target") or state.get("target") or "")
    return build_loop_guard_projection(state, load_entries(repo_root, target))


def _format_closure_line(state: dict) -> str:
    closure = state.get("closure") or {}
    if not closure:
        return ""
    reasons = ",".join(str(item) for item in closure.get("reasons") or []) or "-"
    rotation = closure.get("rotation_hint") or {}
    rotation_text = str(rotation.get("reason") or "-") if isinstance(rotation, dict) else str(rotation)
    return (
        "Closure: verdict={verdict} exhausted={exhausted} reasons={reasons} rotation={rotation}".format(
            verdict=closure.get("verdict", "handoff"),
            exhausted=str(bool(closure.get("can_claim_exhausted"))).lower(),
            reasons=reasons,
            rotation=rotation_text,
        )
    )


def _format_loop_guard_line(state: dict) -> str:
    guard = state.get("loop_guard") or {}
    if not guard:
        return ""
    return "Loop guard: verdict={verdict} reason={reason} next={next_action}".format(
        verdict=guard.get("verdict", "continue"),
        reason=guard.get("reason", "-"),
        next_action=guard.get("next_action", "handoff"),
    )


def _format_durable_action_lines(item: dict) -> list[str]:
    """Format the selected persistent action without dumping the full queue."""
    if not item:
        return []
    lines = [
        "Durable action queue next:",
        f"- {item.get('id', '-')}: {item.get('action') or item.get('type') or ''}",
    ]
    command_hint = str(item.get("command_hint") or "").strip()
    if command_hint:
        lines.append(f"  Command: {command_hint}")
    return lines


def _format_root_finding_claim_lines(claims: list[dict]) -> list[str]:
    """Render unindexed root JSON claims without promoting their lifecycle."""
    if not claims:
        return []
    lines = ["Unreconciled root finding claims (not validated):"]
    for item in claims[:3]:
        missing = ", ".join(str(value) for value in (item.get("incomplete_fields") or []))
        lines.append(
            "- {id} [{severity}] {type} {url} source={source} missing={missing}; collect raw proof, "
            "then run /checkpoint to create the canonical candidate.".format(
                id=item.get("id", "-"),
                severity=item.get("severity", "medium"),
                type=item.get("type", "finding"),
                url=item.get("url", ""),
                source=item.get("source_file", ""),
                missing=missing or "none",
            )
        )
    return lines


def format_autopilot_state(state: dict) -> str:
    """Format autopilot bootstrap state for terminal display."""
    if state.get("target_kind") == "list":
        batch = state.get("batch") or {}
        lines = [
            f"AUTOPILOT BATCH STATE: {state['target']}",
            "═══════════════════════════════════════",
            "",
            f"Next Action: {state['next_action']}",
            f"Recon: {'in progress' if state.get('recon_in_progress') else 'idle'}",
            f"Current Inputs: {len(batch.get('current_entries') or [])}",
            f"Completed: {len(batch.get('completed') or [])}",
            f"Failed: {len(batch.get('failed') or [])}",
            f"Pending: {len(batch.get('pending') or [])}",
            f"AI Handoff: {batch.get('ai_handoff', '')}",
            f"Surface Ranking: {batch.get('surface_ranking', '')}",
            f"Manifest: {batch.get('manifest', '')}",
        ]
        scope = batch.get("scope") or state.get("scope") or {}
        if scope:
            lines.append(f"Scope: {scope.get('scope_ref', '')} ({scope.get('scope_hash', '')})")
        blocker = str(batch.get("blocker") or "").strip()
        if blocker:
            lines.extend(["", f"Blocker: {blocker}"])
        if state.get("next_action") == "invalid_batch_target":
            lines.append("Stop: add at least one usable primary domain before batch recon.")
        elif state.get("next_action") == "batch_failed":
            lines.append("Stop: do not retry the failed batch automatically; review failure evidence or refresh explicitly.")
        candidates = batch.get("candidates") or []
        if candidates:
            lines.extend(["", "Completed-domain candidates:"])
            for index, item in enumerate(candidates[:10], 1):
                lines.append(
                    f"{index}. {item['target']} (score hint {item.get('score', 0)})"
                )
            lines.extend([
                "",
                "Select one completed domain, then rerun autopilot_state.py for that domain.",
                "Do not run surface, scan, or active hunting against the batch index.",
            ])
        closure_line = _format_closure_line(state)
        if closure_line:
            lines.append(closure_line)
        loop_guard_line = _format_loop_guard_line(state)
        if loop_guard_line:
            lines.append(loop_guard_line)
        return "\n".join(lines)

    summary = state.get("resume_summary") or {}
    latest_session = summary.get("latest_session_summary") or {}
    recent_guard_advisories = state.get("recent_guard_advisories") or state.get("recent_guard_blocks", []) or []
    repo_source_summary = state.get("repo_source_summary") or {}
    repo_source_hint = str(repo_source_summary.get("summary_hint", "") or "").strip()
    pivot_hint = str(state.get("pivot_hint", "") or "").strip()
    structured_findings = state.get("structured_findings") or {}
    runtime_state = state.get("runtime_state") or {}
    recon_artifacts = state.get("recon_artifacts") or {}
    target_goal_memory = state.get("target_goal_memory") or {}
    target_memory = target_goal_memory.get("target") or {}
    active_goal_memory = target_goal_memory.get("active") or {}
    workflow_leads = [
        json.loads(item) if isinstance(item, str) else item
        for item in ((state.get("surface") or {}).get("workflow_leads", []) or [])
    ]
    surface = state.get("surface") or {}
    observation_inventory = (
        state.get("observation_inventory")
        or surface.get("observation_inventory")
        or {}
    )

    if not state["has_recon"]:
        if state.get("recon_in_progress"):
            recon_label = "in progress"
        elif state.get("recon_completed_no_live_hosts"):
            recon_label = "completed; no live hosts"
        else:
            recon_label = "missing"
        lines = [
            f"AUTOPILOT STATE: {state['target']}",
            "═══════════════════════════════════════",
            "",
            f"Recon: {recon_label}",
            f"Memory: {'available' if state['has_memory'] else 'missing'}",
            f"Next action: {state['next_action']}",
        ]
        runtime_workflow = str(
            runtime_state.get("last_executed_workflow")
            or runtime_state.get("current_stage")
            or ""
        ).strip()
        runtime_mode = str(runtime_state.get("mode", "") or "").strip()
        if runtime_workflow:
            lines.append(f"Last Workflow: {runtime_workflow}" + (f" (mode: {runtime_mode})" if runtime_mode else ""))
        if state.get("scan_in_progress"):
            lines.append("Scan: in progress")
        if recon_artifacts.get("available"):
            missing = recon_artifacts.get("missing") or []
            warnings = recon_artifacts.get("warnings") or []
            if missing:
                lines.append(f"Recon cache issue: {', '.join(missing[:2])}")
            elif warnings:
                lines.append(f"Recon warning: {warnings[0]}")
            lines.extend(
                _format_exposure_signal_lines(
                    state.get("resolved_target") or state["target"],
                    recon_artifacts,
                )
            )
            lines.extend(
                _format_infra_signal_lines(
                    state.get("resolved_target") or state["target"],
                    recon_artifacts,
                )
            )
        if latest_session:
            tried = ", ".join(latest_session.get("vuln_classes", [])[:4]) or "none"
            lines.append(
                f"Last session: {int(latest_session.get('findings_count', 0) or 0)} finding(s), tried {tried}"
            )
        if repo_source_hint:
            lines.append(f"Repo source: {repo_source_hint}")
        elif state.get("repo_source_available"):
            lines.append("Repo source: available — use read_repo_source_summary")
        if active_goal_memory or target_memory:
            lines.extend(_format_target_goal_memory_lines(active_goal_memory, target_memory))
        inventory_error = str(observation_inventory.get("error") or "").strip()
        if inventory_error:
            lines.append(f"Observation inventory warning: {inventory_error}")
        elif observation_inventory.get("available"):
            lines.append(
                "Observation inventory: "
                f"total={observation_inventory.get('total', 0)}, "
                f"untouched={observation_inventory.get('untouched', 0)}, "
                f"stale={observation_inventory.get('stale', 0)}"
            )
        memory_action_queue = state.get("memory_action_queue") or []
        if memory_action_queue:
            lines.append("Memory action queue:")
            for item in memory_action_queue[:5]:
                contract = ""
                if item.get("status"):
                    contract = (
                        f" | status: {item.get('status')}"
                        f" | executable: {str(item.get('executable', True)).lower()}"
                    )
                lines.append(
                    f"- {item.get('id', '-')}: {item.get('action', '')} "
                    f"| hint: {item.get('command_hint', '')}{contract}"
                )
        memory_candidate = state.get("memory_candidate_next") or {}
        if memory_candidate:
            evidence_state = "available" if memory_candidate.get("evidence_available") else "missing"
            lines.append(
                "Memory candidate fallback: {id} raw-evidence={evidence}".format(
                    id=memory_candidate.get("id", "-"),
                    evidence=evidence_state,
                )
            )
        lines.extend(_format_root_finding_claim_lines(state.get("root_finding_claims") or []))
        lines.extend(_format_durable_action_lines(state.get("action_queue_next") or {}))
        lines.append(f"Next: {_describe_next_step(state)}")
        guard_hint = str(state.get("guard_hint", "") or "").strip()
        if guard_hint:
            lines.append(f"Guard hint: {guard_hint}")
        if pivot_hint:
            lines.append(f"Pivot hint: {pivot_hint}")
        if structured_findings.get("total"):
            lines.extend(
                format_structured_findings_lines(
                    structured_findings,
                    header="Structured findings:",
                    inline_header=True,
                )
            )
        runner_candidate_lines = format_validation_runner_candidate_lines(
            state.get("validation_runner_candidates") or [],
            header="Validation runner candidates (advisory; require /validate before report):",
            limit=4,
        )
        if runner_candidate_lines:
            lines.extend(runner_candidate_lines)
        if recent_guard_advisories:
            lines.append("Recent guard advisories:")
            for item in recent_guard_advisories[:3]:
                details = _format_recent_guard_advisory(item)
                if details:
                    lines.append(f"- {details}")
        closure_line = _format_closure_line(state)
        if closure_line:
            lines.append(closure_line)
        loop_guard_line = _format_loop_guard_line(state)
        if loop_guard_line:
            lines.append(loop_guard_line)
        return "\n".join(lines) + "\n"

    lines = [
        f"AUTOPILOT STATE: {state['target']}",
        "═══════════════════════════════════════",
        "",
        "Recon: ready",
        f"Memory: {'available' if state['has_memory'] else 'missing'}",
        f"Next action: {state['next_action']}",
        f"Next step: {_describe_next_step(state)}",
    ]
    if state.get("scan_in_progress"):
        lines.append("Scan: in progress")
    runtime_workflow = str(
        runtime_state.get("last_executed_workflow")
        or runtime_state.get("current_stage")
        or ""
    ).strip()
    runtime_mode = str(runtime_state.get("mode", "") or "").strip()
    if runtime_workflow:
        lines.append(f"Last Workflow: {runtime_workflow}" + (f" (mode: {runtime_mode})" if runtime_mode else ""))
    if active_goal_memory or target_memory:
        lines.extend(_format_target_goal_memory_lines(active_goal_memory, target_memory))
    next_tool_hint = str(state.get("next_tool_hint", "") or "").strip()
    enrichment_hints = state.get("enrichment_hints") or []
    if next_tool_hint:
        lines.append(f"Next tool hint: {next_tool_hint}")
    if enrichment_hints:
        lines.append("Enrichment hints:")
        for item in enrichment_hints[:3]:
            tool = str(item.get("tool", "") or "").strip()
            reason = str(item.get("reason", "") or "").strip()
            if tool and reason:
                lines.append(f"- {tool}: {reason}")
            elif tool:
                lines.append(f"- {tool}")
    memory_action_queue = state.get("memory_action_queue") or []
    if memory_action_queue:
        lines.append("Memory action queue:")
        for item in memory_action_queue[:5]:
            contract = ""
            if item.get("status"):
                contract = (
                    f" | status: {item.get('status')}"
                    f" | executable: {str(item.get('executable', True)).lower()}"
                )
            lines.append(
                f"- {item.get('id', '-')}: {item.get('action', '')} "
                f"| hint: {item.get('command_hint', '')}{contract}"
            )
    memory_candidate = state.get("memory_candidate_next") or {}
    if memory_candidate:
        evidence_state = "available" if memory_candidate.get("evidence_available") else "missing"
        lines.append(
            "Memory candidate fallback: {id} raw-evidence={evidence}".format(
                id=memory_candidate.get("id", "-"),
                evidence=evidence_state,
            )
        )
    lines.extend(_format_root_finding_claim_lines(state.get("root_finding_claims") or []))
    lines.extend(_format_durable_action_lines(state.get("action_queue_next") or {}))

    guard_status = state.get("guard_status", {})
    lines.append(
        f"Guard: {guard_status.get('tracked_hosts', 0)} tracked host(s), {len(guard_status.get('tripped_hosts', []))} tripped"
    )
    guard_hint = str(state.get("guard_hint", "") or "").strip()
    if guard_hint:
        lines.append(f"Guard hint: {guard_hint}")
    if pivot_hint:
        lines.append(f"Pivot hint: {pivot_hint}")
    if repo_source_hint:
        lines.append(f"Repo source: {repo_source_hint}")
    elif state.get("repo_source_available"):
        lines.append("Repo source: available — use read_repo_source_summary")
    if recon_artifacts.get("available"):
        warnings = recon_artifacts.get("warnings") or []
        counts = recon_artifacts.get("counts") or {}
        surface_counts = [
            counts.get(key)
            for key in (
                "api_urls",
                "param_urls",
                "js_endpoints",
                "browser_xhr_urls",
                "browser_api_urls",
            )
        ]
        surface_count = "?" if any(value is None for value in surface_counts) else sum(surface_counts)
        def display_count(key: str) -> object:
            return "?" if counts.get(key) is None else counts.get(key, 0)

        lines.append(
            "Recon cache: "
            f"hosts={display_count('hosts')}, "
            f"surface={surface_count}, "
            f"ports={display_count('open_ports')}, "
            f"waf={display_count('waf_hits')}, "
            f"origin={display_count('origin_candidates')}"
        )
        if warnings:
            lines.append(f"Recon warning: {warnings[0]}")
        lines.extend(
            _format_exposure_signal_lines(
                state.get("resolved_target") or state["target"],
                recon_artifacts,
            )
        )
        lines.extend(
            _format_infra_signal_lines(
                state.get("resolved_target") or state["target"],
                recon_artifacts,
            )
        )
    inventory_error = str(observation_inventory.get("error") or "").strip()
    if inventory_error:
        lines.append(f"Observation inventory warning: {inventory_error}")
    elif observation_inventory.get("available"):
        lines.append(
            "Observation inventory: "
            f"total={observation_inventory.get('total', 0)}, "
            f"untouched={observation_inventory.get('untouched', 0)}, "
            f"stale={observation_inventory.get('stale', 0)}, "
            f"reviewing={observation_inventory.get('reviewing', 0)}"
        )

    if state["tech_stack"]:
        lines.append(f"Tech stack: {', '.join(state['tech_stack'])}")

    if structured_findings.get("total"):
        lines.extend(
            format_structured_findings_lines(
                structured_findings,
                header="Structured findings:",
                inline_header=True,
            )
        )

    runner_candidate_lines = format_validation_runner_candidate_lines(
        state.get("validation_runner_candidates") or [],
        header="Validation runner candidates (advisory; require /validate before report):",
        limit=4,
    )
    if runner_candidate_lines:
        lines.extend(runner_candidate_lines)

    if workflow_leads:
        lines.append("Workflow leads:")
        for item in workflow_leads[:3]:
            lines.append(
                f"- [{item.get('priority', 'medium')}] {item.get('category', 'other')}: "
                f"{item.get('title', '-')}"
            )
            next_action = str(item.get("next_action", "") or "").strip()
            if next_action:
                lines.append(f"  Next: {next_action}")

    if summary:
        lines.append(f"Sessions: {summary.get('sessions', 0)}")
        lines.append(f"Untested endpoints: {len(summary.get('untested_endpoints', []))}")
        if latest_session:
            tried = ", ".join(latest_session.get("vuln_classes", [])[:4]) or "none"
            lines.append(
                f"Last session: {int(latest_session.get('findings_count', 0) or 0)} finding(s), tried {tried}"
            )
            if latest_session.get("endpoints_preview"):
                lines.append(
                    f"Last endpoints: {', '.join(latest_session['endpoints_preview'][:2])}"
                )
        if state.get("resume_targets"):
            lines.append(f"Resume targets: {', '.join(state['resume_targets'][:3])}")

    lines.append(f"Surface review candidates: {surface.get('stats', {}).get('review_pool', 0)}")
    lines.append(f"Advisory first-review score hints: {surface.get('stats', {}).get('p1', 0)}")
    lines.append(f"Advisory follow-up score hints: {surface.get('stats', {}).get('p2', 0)}")

    tripped_hosts = guard_status.get("tripped_hosts", [])
    if tripped_hosts:
        lines.append("Cooling down hosts:")
        for item in tripped_hosts[:3]:
            lines.append(
                f"- {item['host']} ({item['remaining_seconds']:.1f}s remaining)"
            )

    if recent_guard_advisories:
        lines.append("")
        lines.append("Recent guard advisories:")
        for item in recent_guard_advisories[:3]:
            details = _format_recent_guard_advisory(item)
            if details:
                lines.append(f"- {details}")

    surface_review_candidates = (
        state.get("surface_review_candidates")
        or state.get("recommended_targets")
        or []
    )
    if surface_review_candidates:
        lines.append("")
        lines.append("Surface review candidates (AI decides final priority):")
        for idx, item in enumerate(surface_review_candidates, 1):
            suffix = (
                f" [cooldown {item['remaining_seconds']:.1f}s]"
                if item.get("tripped")
                else ""
            )
            reason = f" [{item['review_reason']}]" if item.get("review_reason") else ""
            lines.append(
                f"{idx}. {item['url']} — {item['suggested']} (score hint {item['score']}){reason}{suffix}"
            )

    closure_line = _format_closure_line(state)
    if closure_line:
        lines.append(closure_line)
    loop_guard_line = _format_loop_guard_line(state)
    if loop_guard_line:
        lines.append(loop_guard_line)

    return "\n".join(lines)


def _format_target_goal_memory_lines(active: dict, target_memory: dict) -> list[str]:
    """Format compact target-memory context for autopilot output."""
    lines = ["Target memory:"]
    goal = str(active.get("active_goal") or target_memory.get("active_goal") or "").strip()
    hypothesis = str(
        active.get("current_hypothesis")
        or target_memory.get("current_hypothesis")
        or ""
    ).strip()
    if goal:
        lines.append(f"- Goal: {goal}")
    if hypothesis:
        lines.append(f"- Hypothesis: {hypothesis}")

    for label, field in (
        ("Active leads", "active_leads"),
        ("Next actions", "next_actions"),
        ("Dead ends", "dead_ends"),
    ):
        entries = target_memory.get(field) or []
        if not isinstance(entries, list):
            entries = []
        lines.append(f"- {label}: {len(entries)}")
        for item in entries[-2:]:
            if not isinstance(item, dict):
                continue
            text = str(item.get("text", "") or "").strip()
            if text:
                lines.append(f"  - {text}")

    handoffs = target_memory.get("session_handoffs") or []
    if isinstance(handoffs, list) and handoffs:
        latest = handoffs[-1]
        if isinstance(latest, dict):
            summary = str(latest.get("summary", "") or "").strip()
            path = str(latest.get("path", "") or "").strip()
            if summary:
                lines.append(f"- Latest handoff: {summary}")
            if path:
                lines.append(f"- Handoff path: {path}")
    return lines


def _error_state(target: str, error: Exception) -> dict:
    """Keep explicit control-plane reads machine-readable when canonical state is damaged."""
    return {
        "target": target,
        "next_action": "error",
        "closure": {
            "verdict": "error",
            "can_claim_exhausted": False,
            "reasons": ["state_read_error"],
            "next_action": "error",
            "rotation_hint": {},
            "error": {
                "type": type(error).__name__,
                "message": str(error),
            },
        },
    }


def build_decision_projection(state: dict, kind: str) -> dict:
    """Project only the fields consumed by the loop or closure controller."""
    target = str(state.get("resolved_target") or state.get("target") or "")
    projection = {
        "schema_version": DECISION_PROJECTION_SCHEMA_VERSION,
        "kind": f"autopilot_{kind}_projection",
        "target": target,
        "target_storage_key": target_storage_key(target) if target else "",
    }
    if isinstance(state.get("scope"), dict) and state.get("scope"):
        projection["scope"] = state["scope"]
    if kind == "loop_check":
        projection["loop_guard"] = state.get("loop_guard") or {}
        return projection
    if kind != "closure":
        raise ValueError(f"unsupported decision projection: {kind}")

    closure = state.get("closure") if isinstance(state.get("closure"), dict) else {}
    projection["closure"] = {
        key: closure[key]
        for key in (
            "verdict",
            "can_claim_exhausted",
            "reasons",
            "next_action",
            "rotation_hint",
            "stagnation_fingerprint",
            "error",
            "round_progress",
        )
        if key in closure
    }
    structured = (
        state.get("structured_findings")
        if isinstance(state.get("structured_findings"), dict)
        else {}
    )
    projection["structured_findings"] = {
        key: structured[key]
        for key in ("reported",)
        if key in structured
    }
    for field, keys in (
        ("browser_evidence", ("present", "ready")),
        ("repo_source_summary", ("status",)),
        ("observation_inventory", ("status", "reason", "untouched", "stale", "by_kind")),
        ("surface_projection", ("status", "reason", "refresh_command")),
        ("case_state", ("status", "actors", "sessions", "objects", "open_hypotheses", "pending_validation_backlog", "top_next_action")),
    ):
        value = state.get(field) if isinstance(state.get(field), dict) else {}
        projection[field] = {key: value[key] for key in keys if key in value}
    projection["sql_matrix"] = {
        lane: {
            key: item[key]
            for key in ("status", "reason", "path", "input_fingerprint", "endpoint_count", "probed_endpoint_count", "request_count", "hit_count", "candidate_count", "batch_start_endpoint_index", "batch_tested_endpoint_count", "resumed", "cursor", "candidates")
            if key in item
        }
        for lane, item in (state.get("sql_matrix") or {}).items()
        if isinstance(item, dict)
    }
    js_intel = state.get("js_intel") if isinstance(state.get("js_intel"), dict) else {}
    projection["js_intel"] = {
        key: js_intel[key]
        for key in ("status", "reason", "path", "hypotheses_path", "hypothesis_count", "disposition_path")
        if key in js_intel
    }
    for field in ("repo_source_available", "recon_blocker", "browser_required"):
        if field in state:
            projection[field] = state[field]
    return projection


def main() -> int:
    parser = argparse.ArgumentParser(description="Build combined autopilot state for a target")
    parser.add_argument("--target", required=True, help="Target domain")
    parser.add_argument("--memory-dir", default="", help="Optional hunt-memory directory")
    parser.add_argument(
        "--bounded",
        action="store_true",
        help="Consume only compact projections and bounded control-plane state",
    )
    parser.add_argument(
        "--closure",
        action="store_true",
        help="Read existing coverage and evidence owners for an explicit closure verdict",
    )
    parser.add_argument(
        "--max-lanes-reached",
        action="store_true",
        help="Mark this bounded invocation as a required handoff",
    )
    parser.add_argument(
        "--loop-check",
        action="store_true",
        help="Read recent ledger outcomes for an explicit per-iteration rotation decision",
    )
    parser.add_argument(
        "--projection-only",
        action="store_true",
        help="With JSON, emit only the requested loop-check or closure decision fields",
    )
    parser.add_argument("--json", action="store_true", help="Output JSON")
    args = parser.parse_args()
    if args.projection_only and (
        not args.json or args.closure == args.loop_check
    ):
        parser.error("--projection-only requires --json and exactly one of --closure or --loop-check")

    try:
        state = build_autopilot_state(
            BASE_DIR,
            args.target,
            memory_dir=args.memory_dir or None,
            bounded=args.bounded,
        )
        if args.closure:
            state["closure"] = load_closure_projection(
                BASE_DIR,
                state,
                max_lanes_reached=args.max_lanes_reached,
            )
        if args.loop_check:
            state["loop_guard"] = _load_loop_guard_projection(BASE_DIR, state)
    except (OSError, ValueError) as exc:
        if args.json:
            print(json.dumps(_error_state(args.target, exc), indent=2))
        else:
            print(f"autopilot_state: {exc}", file=sys.stderr)
        return 2
    if args.json:
        if args.projection_only:
            kind = "closure" if args.closure else "loop_check"
            state = build_decision_projection(state, kind)
        print(json.dumps(state, indent=2))
        return 0
    print(format_autopilot_state(state))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
