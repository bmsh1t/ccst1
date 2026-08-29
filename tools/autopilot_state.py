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
    from tools.action_queue import (
        ACTIVE_STATUSES,
        FINAL_STATUSES,
        _target_owned_nonempty_evidence_ref,
        load_queue,
        queue_path,
        queue_fingerprint,
        select_next_action,
    )
except ImportError:  # pragma: no cover - direct tools/ execution
    from action_queue import (  # type: ignore
        ACTIVE_STATUSES,
        FINAL_STATUSES,
        _target_owned_nonempty_evidence_ref,
        load_queue,
        queue_path,
        queue_fingerprint,
        select_next_action,
    )
try:
    from tools.checkpoint_witness import (
        is_canonical_coverage_lane_evidence_ref,
        load_checkpoint_witness as _load_checkpoint_witness,
        validate_round_progress,
    )
except ImportError:  # pragma: no cover - direct tools/ execution
    from checkpoint_witness import (  # type: ignore
        is_canonical_coverage_lane_evidence_ref,
        load_checkpoint_witness as _load_checkpoint_witness,
        validate_round_progress,
    )
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
        _derive_current_status,
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
        compact_url,
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
        _derive_current_status,
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
        compact_url,
        migrate_legacy_list_storage,
        target_list_entries,
        target_storage_key,
        url_belongs_to_target,
    )

try:
    from tools.coverage_matrix import (
        STATUS_VALUES,
        VULN_CLASSES,
        _route_template,
        actionable_coverage_gaps,
        class_relevance,
        high_value_gaps_from_matrix,
        load_matrix,
        load_matrix_projection,
    )
    from tools.evidence_ledger import (
        build_current_cell_projection,
        load_entries_diagnostic,
    )
except ImportError:  # pragma: no cover - direct tools/ execution
    from coverage_matrix import (  # type: ignore
        STATUS_VALUES,
        VULN_CLASSES,
        _route_template,
        actionable_coverage_gaps,
        class_relevance,
        high_value_gaps_from_matrix,
        load_matrix,
        load_matrix_projection,
    )
    from evidence_ledger import (  # type: ignore
        build_current_cell_projection,
        load_entries_diagnostic,
    )
try:
    from tools.closure_resolver import (
        canonical_endpoint_identity,
        canonical_endpoint_path,
    )
except ImportError:  # pragma: no cover - direct tools/ execution
    from closure_resolver import (  # type: ignore
        canonical_endpoint_identity,
        canonical_endpoint_path,
    )

try:
    from tools.recon_target_selector import load_rotation_status
except ImportError:  # pragma: no cover - direct tools/ execution
    from recon_target_selector import load_rotation_status  # type: ignore
try:
    from tools.scope_context import ScopeContext, ScopeContextError
except ImportError:  # pragma: no cover - direct tools/ execution
    from scope_context import ScopeContext, ScopeContextError  # type: ignore
try:
    from tools.target_case_state import case_state_path, project_hypothesis_metadata, summary as build_case_state_summary
except ImportError:  # pragma: no cover - direct tools/ execution
    from target_case_state import case_state_path, project_hypothesis_metadata, summary as build_case_state_summary  # type: ignore
try:
    from tools.target_memory import load_goal_memory
except ImportError:  # pragma: no cover - direct tools/ execution
    from target_memory import load_goal_memory  # type: ignore




PLACEHOLDER_OBJECT_SEGMENTS = {"nan", "undefined", "null", "none", "object", "[object object]"}
DECISION_PROJECTION_SCHEMA_VERSION = 1


def _normalise_endpoint_path(value: str) -> str:
    return canonical_endpoint_path(value)


def _has_placeholder_object_segment(value: str) -> bool:
    path = _normalise_endpoint_path(value).lower()
    segments = [segment for segment in path.split("/") if segment]
    return any(segment in PLACEHOLDER_OBJECT_SEGMENTS for segment in segments)


def _finalized_finding_identities(repo_root: str, resolved_target: str) -> set[str]:
    """Return exact finding identities already validated/rejected/reported.

    This is an egress guard for AI-facing next actions. It does not delete raw
    surface; it only prevents old finalized findings from steering startup.
    """
    path = Path(repo_root) / "findings" / target_storage_key(resolved_target) / "findings.json"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set()

    identities: set[str] = set()
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
        endpoint_identity = canonical_endpoint_identity(
            str(item.get("url") or item.get("endpoint") or "")
        )
        if endpoint_identity and endpoint_identity != "/":
            identities.add(endpoint_identity)
    return identities


def _is_placeholder_surface(item: dict) -> bool:
    url = str(item.get("url") or item.get("path") or "").strip()
    return _has_placeholder_object_segment(url)


def _filter_resume_targets_for_final_state(
    targets: list[str],
    finalized_identities: set[str],
) -> list[str]:
    filtered: list[str] = []
    for target in targets:
        endpoint_identity = canonical_endpoint_identity(target)
        if endpoint_identity and endpoint_identity in finalized_identities:
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


def _filter_legacy_memory_candidates(ranked: dict, resume_targets: list[str]) -> dict:
    """Keep stale target-memory hints visible, but out of active steering.

    Surface remains lossless.  Only candidates explicitly labeled as a legacy
    memory continuation are suppressed when the current session has no focus;
    scanner, browser, source, intel, and fresh-surface signals remain eligible.
    """
    filtered = dict(ranked or {})
    if resume_targets:
        return filtered
    for key in ("review_pool", "p1", "p2"):
        filtered[key] = [
            item
            for item in (ranked.get(key) or [])
            if not (
                isinstance(item, dict)
                and str(item.get("review_reason") or "").strip().lower()
                == "target-memory continuation"
            )
        ]
    return filtered


def _is_stale_finalized_scanner_candidate(item: dict) -> bool:
    """Return true only when scanner evidence has an explicit final disposition.

    This is deliberately evidence-based: a static-looking path or a low score is
    not enough to suppress a candidate. New browser/JS/source/intel evidence keeps
    the item active and lets Claude reassess it.
    """
    findings = item.get("scanner_findings")
    if not isinstance(findings, list) or not findings or item.get("new_observation"):
        return False
    if any(
        item.get(key)
        for key in (
            "evidence_convergence",
            "browser_observed",
            "js_intel_observed",
            "source_intel_observed",
        )
    ):
        return False
    # A version advisory from OSV/NVD is useful context, but does not bind a
    # static asset to reachable behavior. Keep only route/browser/source-bound
    # Intel signals in the active pool; generic dependency matches remain in a
    # bounded deferred packet for AI reactivation.
    for signal in item.get("intel_signals") or []:
        if not isinstance(signal, dict):
            continue
        if any(signal.get(key) for key in ("endpoint", "route", "browser_observed", "source_evidence")):
            return False
    for finding in findings:
        if not isinstance(finding, dict):
            return False
        validation = str(finding.get("validation_status") or "").strip().lower()
        report = str(finding.get("report_status") or "").strip().lower()
        if validation != "rejected" and report != "generated":
            return False
    return True


def _filter_stale_finalized_scanner_candidates(ranked: dict) -> dict:
    """Keep finalized scanner rows visible, but out of active AI steering."""
    filtered = dict(ranked or {})
    deferred = []
    seen = set()
    for key in ("review_pool", "p1", "p2"):
        kept = []
        for item in ranked.get(key) or []:
            if isinstance(item, dict) and _is_stale_finalized_scanner_candidate(item):
                url = str(item.get("url") or item.get("path") or "").strip()
                if url and url not in seen:
                    seen.add(url)
                    deferred_item = {
                        "url": url,
                        "reason": "scanner disposition finalized; generic Intel is advisory-only until route evidence exists",
                        "reactivate_when": "new observation, browser/JS/source evidence, route-bound Intel, or changed finding disposition",
                    }
                    signals = item.get("intel_signals") or []
                    if signals:
                        deferred_item["intel_packet"] = [
                            {
                                "id": str(signal.get("id") or ""),
                                "source": str(signal.get("source") or ""),
                                "applicability": str(signal.get("applicability") or "unknown"),
                            }
                            for signal in signals[:4]
                            if isinstance(signal, dict)
                        ]
                    deferred.append(deferred_item)
                continue
            kept.append(item)
        filtered[key] = kept
    filtered["deferred_surface_candidates"] = deferred[:8]
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


def _checkpoint_round_projection(
    witness: dict,
    *,
    repo_root: str | Path,
    target: str,
) -> dict:
    progress = validate_round_progress(
        witness,
        allow_invalid_completed_evidence=True,
    )
    if not progress:
        return {}
    projected_lanes: list[dict] = []
    for lane in progress["lanes"]:
        item = {"id": lane["id"], "status": lane["status"]}
        for field in ("decision", "evidence_ref", "next_action"):
            value = lane.get(field, "")
            if value:
                item[field] = value
        projected_lanes.append(item)
    unfinished = [item["id"] for item in projected_lanes if item["status"] == "started"]
    invalid_evidence = []
    for item in projected_lanes:
        if item["status"] != "completed":
            continue
        evidence_ref = _target_owned_nonempty_evidence_ref(
            repo_root,
            target,
            item.get("evidence_ref"),
        )
        if not evidence_ref or not is_canonical_coverage_lane_evidence_ref(
            item["id"],
            evidence_ref,
            target,
        ):
            invalid_evidence.append(item["id"])
    return {
        "status": progress["status"],
        "round_id": str(progress.get("round_id") or ""),
        "max_lanes": progress["max_lanes"],
        "claimed_count": len(progress["claimed_lanes"]),
        "budget_reached": bool(progress.get("budget_reached")),
        "unfinished_lanes": unfinished,
        "invalid_evidence_lanes": invalid_evidence,
        "latest_lane": projected_lanes[-1] if projected_lanes else {},
    }


def _checkpoint_queue_health(witness: dict, queue: dict) -> dict:
    """Reject a checkpoint cursor that no longer describes the durable Queue."""
    recorded = witness.get("action_queue") if isinstance(witness, dict) else None
    if not isinstance(recorded, dict) or not recorded:
        return {"status": "valid"}

    def recorded_action_is_final() -> bool:
        expected_id = str(recorded.get("next_id") or "").strip()
        if not expected_id:
            return False
        return any(
            isinstance(action, dict)
            and str(action.get("id") or "") == expected_id
            and str(action.get("status") or "").strip().lower() in FINAL_STATUSES
            for action in queue.get("actions", [])
        )

    current_fingerprint = queue_fingerprint(queue)
    expected_fingerprint = str(recorded.get("fingerprint") or "").strip()
    if expected_fingerprint:
        if expected_fingerprint != current_fingerprint:
            current_next = str((select_next_action(queue) or {}).get("id") or "").strip()
            if not current_next and recorded_action_is_final():
                return {
                    "status": "valid",
                    "fingerprint": current_fingerprint,
                    "reason": "queue advanced past the recorded checkpoint action",
                }
            return {
                "status": "stale",
                "reason": "checkpoint queue fingerprint differs from durable queue",
                "expected_fingerprint": expected_fingerprint,
                "current_fingerprint": current_fingerprint,
            }
        return {"status": "valid", "fingerprint": current_fingerprint}

    expected_next = str(recorded.get("next_id") or "").strip()
    current_next = str((select_next_action(queue) or {}).get("id") or "").strip()
    if expected_next and expected_next != current_next:
        if not current_next and recorded_action_is_final():
            return {
                "status": "valid",
                "reason": "queue advanced past the recorded checkpoint action",
            }
        return {
            "status": "stale",
            "reason": "legacy checkpoint next_id differs from durable queue",
            "expected_next_id": expected_next,
            "current_next_id": current_next,
        }
    return {"status": "unverified", "reason": "checkpoint predates queue fingerprint"}


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
        # The Claude js-reader contract is a structured report, not a generic
        # ``hypotheses`` list.  Treat its lead/endpoints fields as analysis
        # evidence so a valid report with no promoted lead is not misclassified
        # as an empty or malformed artifact.
        values = None
        analysis_format = "hypotheses"
        for field in ("hypotheses", "attack_surface_leads", "ranked_leads"):
            candidate = payload.get(field) if isinstance(payload, dict) else None
            if not isinstance(candidate, list):
                continue
            if values is None or not values:
                values = candidate
                analysis_format = field
            if candidate:
                break
        report_keys = {
            "endpoints",
            "auth_model",
            "sinks",
            "graphql_operations",
            "attack_surface_leads",
            "noise_observed",
        }
        canonical_report = isinstance(payload, dict) and bool(report_keys.intersection(payload))
        if values is None and canonical_report:
            values = []
        if not isinstance(values, list) or (not values and not canonical_report):
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
        projection.update({
            "status": "analyzed",
            "hypotheses_path": str(hypotheses),
            "hypothesis_count": min(len(values), 100),
            "analysis_format": analysis_format,
        })
    return projection


def _load_case_state_projection(
    repo_root: str,
    target: str,
    *,
    case_state_summary: dict | None = None,
) -> dict:
    """Load the bounded, secret-free Case State continuation."""
    path = case_state_path(repo_root, target)
    if not path.is_file():
        return {"status": "missing", "path": str(path)}
    if isinstance(case_state_summary, dict):
        snapshot_target = canonical_target_value(str(case_state_summary.get("target") or ""))
        if snapshot_target != canonical_target_value(target):
            raise ValueError("case state snapshot target does not match requested target")
    payload = (
        case_state_summary
        if isinstance(case_state_summary, dict)
        else build_case_state_summary(repo_root, target)
    )
    top = payload.get("top_next_action") if isinstance(payload.get("top_next_action"), dict) else {}
    canonical_conflict_count = int(payload.get("canonical_conflict_count", 0) or 0)
    if canonical_conflict_count and str(top.get("next_action") or "none") == "none":
        top = {
            "next_action": "reconcile_case_state",
            "ready": False,
            "why_now": "Case State marks a backlog terminal while canonical findings are finalized",
            "write_back": "reconcile the backlog outcome with the canonical finding owner before closure",
        }
    allowed = {
        "next_action", "ready", "score", "backlog_id", "hypothesis_id", "runner", "hypothesis",
        "chain_context", "why_now", "vuln_class", "endpoint", "owner_actor",
        "peer_actor", "object_ref", "object_type", "required_evidence",
        "optional_evidence_gaps", "missing_evidence", "redacted_command",
        "downgrade_rule", "stop_condition", "chain_extensions_if_blocked", "recovery_next_action", "write_back",
        "param", "baseline_value", "variant_value", "expect_marker", "method",
    }
    projected_top = {key: value for key, value in top.items() if key in allowed}
    metadata = project_hypothesis_metadata(top.get("metadata"))
    if metadata:
        projected_top["metadata"] = metadata
    return {
        "status": "valid",
        "path": str(path),
        "authz_coverage": payload.get("authz_coverage") if isinstance(payload.get("authz_coverage"), dict) else {},
        "canonical_conflict_count": canonical_conflict_count,
        "canonical_conflicts": payload.get("canonical_conflicts") if isinstance(payload.get("canonical_conflicts"), list) else [],
        **{
            key: int(payload.get(key, 0) or 0)
            for key in (
                "actors", "sessions", "objects", "open_hypotheses",
                "pending_validation_backlog",
            )
        },
        "top_next_action": projected_top,
    }


def load_target_goal_memory(repo_root: str, target: str) -> dict:
    """Load the four-layer target memory for autopilot bootstrapping."""
    return load_goal_memory(repo_root, target)


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
            "vuln_class": item.get("vuln_class", ""),
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
    """Return only the latest session's explicit focus for automatic continuation.

    ``untested_endpoints`` remains available in the read-only resume summary, but
    it is legacy inventory rather than proof that the next session should replay
    those paths.  Autopilot must use durable queue/finding/surface evidence for
    new work instead of reviving stale inventory indefinitely.
    """
    if not summary:
        return []

    latest_session = summary.get("latest_session_summary") or {}
    preview = [item for item in latest_session.get("endpoints_preview", []) if item]
    return list(dict.fromkeys(preview))[:3]


def _resume_targets_match_ranked_surface(
    resume_targets: list[str] | None,
    ranked: dict | None,
    *,
    target: str = "",
) -> bool:
    """Return whether a legacy preview still points at current Surface work."""
    targets = [str(item or "").strip() for item in (resume_targets or []) if str(item or "").strip()]
    if not targets or not isinstance(ranked, dict):
        return False
    for bucket in ("review_pool", "p1", "p2"):
        for item in ranked.get(bucket) or []:
            if not isinstance(item, dict):
                continue
            url = str(item.get("url") or "")
            if target and not url_belongs_to_target(url, target):
                continue
            if _matches_resume_target(url, targets):
                return True
    return False


def _resume_targets_bound_to_surface(state: dict) -> bool:
    """Treat legacy resume previews as advisory unless current Surface owns them."""
    targets = state.get("resume_targets") or []
    candidates = (
        state.get("surface_review_candidates")
        or state.get("recommended_targets")
        or []
    )
    target = str(state.get("resolved_target") or state.get("target") or "")
    if targets and isinstance(candidates, list) and any(
        isinstance(item, dict)
        and (
            not target
            or url_belongs_to_target(str(item.get("url") or ""), target)
        )
        and _matches_resume_target(str(item.get("url") or ""), targets)
        for item in candidates
    ):
        return True

    ranked = state.get("surface")
    if _resume_targets_match_ranked_surface(
        targets,
        ranked,
        target=str(state.get("resolved_target") or state.get("target") or ""),
    ):
        return True

    # Older state snapshots may omit the current Surface projection. A
    # target-owned Queue/Finding/Case item with the same endpoint and durable
    # evidence is still a valid binding; preview text alone is not.
    owners = []
    queue = state.get("action_queue_next")
    if not isinstance(queue, dict) or not queue:
        action_queue = state.get("action_queue")
        queue = action_queue.get("next") if isinstance(action_queue, dict) else None
    if isinstance(queue, dict):
        owners.append(queue)
        metadata = queue.get("metadata")
        if isinstance(metadata, dict):
            owners.append(metadata)
    findings = state.get("structured_findings")
    if isinstance(findings, dict):
        owners.extend(
            item for item in findings.values()
            if isinstance(item, dict)
        )
    case_state = state.get("case_state")
    if isinstance(case_state, dict):
        case_next = case_state.get("top_next_action")
        if isinstance(case_next, dict):
            owners.append(case_next)
    return any(
        isinstance(item, dict)
        and any(
            (
                not target or url_belongs_to_target(str(item.get(key) or ""), target)
            )
            and _matches_resume_target(str(item.get(key) or ""), targets)
            for key in ("url", "endpoint")
        )
        and any(str(item.get(key) or "").strip() for key in ("evidence_ref", "evidence", "summary_ref"))
        for item in owners
    )


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
    resume_targets_bound: bool = False,
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

    if latest_session and preview and resume_targets and resume_targets_bound:
        return "continue_last_focus"
    if latest_session and resume_targets and resume_targets_bound:
        return "resume_untested"

    if surface_context_required or fresh_recon_ready:
        return "prepare_surface_context"
    if ranked.get("review_pool") or ranked.get("p1"):
        return "hunt_p1"
    if dir_fuzz_rotation_pending:
        return "run_recon"
    if resume_targets and resume_targets_bound:
        return "resume_untested"
    if structured_findings.get("draft_completion_pending"):
        return "complete_report_draft"
    # A validated finding is a closure/report asset, not the steering wheel.
    # Surface/replay/resume work above should stay available when current
    # evidence exposes stronger live leads; otherwise keep the report visible.
    if structured_findings.get("validated_pending_report"):
        return "report_finding"
    return "handoff"


def _hard_gate_projection(state: dict) -> dict:
    """Return only target-state conditions that forbid cross-owner arbitration."""
    action = str(state.get("next_action") or "")
    if state.get("recon_in_progress"):
        return {
            "action": "wait_recon",
            "reason": "the target recon phase lock is still held",
        }
    if state.get("scan_in_progress"):
        return {
            "action": "wait_scan",
            "reason": "the target scan phase lock is still held",
        }
    if state.get("target_kind") == "list" and action in {
        "invalid_batch_target",
        "select_completed_domain",
        "batch_failed",
        "run_batch_recon",
    }:
        return {
            "action": action,
            "reason": "batch scope must resolve to one concrete target before hunting",
        }
    if action == "run_recon" and not state.get("has_recon"):
        return {
            "action": "run_recon",
            "reason": "no target-owned recon inventory exists yet",
        }
    if action == "recon_no_live_hosts":
        return {
            "action": action,
            "reason": "completed recon has no live host inventory",
        }
    return {}


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
        "review_intel_group",
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
                    url=compact_url(candidate.get("url", "")),
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
            return f"validate structured finding {followup.get('id')} on {compact_url(followup.get('url', ''))}."
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
    if action == "refresh_checkpoint":
        return "refresh the target checkpoint witness, then recompute the bounded Closure snapshot."
    if action == "repair_evidence_ledger":
        return "repair or reconcile the target Evidence Ledger, then recompute the bounded Closure snapshot."
    if action == "coverage-gap":
        return "review the selected high-value Coverage gap and record its owner-backed disposition."
    if action == "surface-review":
        return "review the selected Surface continuation and record its owner-backed disposition."
    if action == "browser-enrichment":
        return "complete the browser evidence import and refresh the bounded Surface context."
    if action == "source-enrichment":
        return "complete or disposition the repository-source evidence review."
    if action == "js-enrichment":
        return "read and disposition the prepared JavaScript evidence."
    if action == "json-inject-review":
        return "resume the bounded JSON input evidence lane and record its owner result."
    if action == "sql-matrix-review":
        return "resume the bounded SQL evidence lane and record its owner result."
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
    if action == "review_intel_group":
        group = (state.get("intel_continuation") or {}).get("review_group") or {}
        component = group.get("component") if isinstance(group.get("component"), dict) else {}
        return (
            "review omitted Intel group {group_key} for {name}@{version}: query the bounded "
            "raw advisory pages, then record one existing Action Queue final disposition or "
            "one exact applicability action before continuing. Query: {query}"
        ).format(
            group_key=group.get("group_key", "the group"),
            name=component.get("name", "component"),
            version=component.get("version") or "unknown",
            query=group.get("query_command", "python3 tools/intel_artifact.py query --target TARGET"),
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
                f"{ready_target.get('host', '')} via {compact_url(ready_target.get('url', ''))}"
            )
        return (
            f"all tracked hot hosts are cooling down: {cooling}; do not rotate IPs, "
            f"evade detection, or use social engineering. Pivot to cached recon/browser/JS/source "
            f"artifacts, context-pack, checkpoint, and coverage updates until cooldown clears"
        )

    if ready_target and int(guard_status.get("tracked_hosts", 0) or 0) > 0:
        return f"prefer the ready host {ready_target.get('host', '')} via {compact_url(ready_target.get('url', ''))}"

    return ""


def _format_recent_guard_advisory(item: dict) -> str:
    """Render a compact human-readable summary for one recent guard advisory."""
    notes = str(item.get("notes", "") or "").strip()
    if notes:
        return notes
    endpoint = compact_url(str(item.get("endpoint", "") or "").strip())
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
    "host_collision_observations",
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
        _count_value(counts, "host_collision_observations") > 0,
        "exposure/host_collision_observations.jsonl",
    )
    add_if(
        _count_value(counts, "host_ranking") > 0,
        "exposure/host_ranking.jsonl",
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
        f"host_collision={_count_value(counts, 'host_collision_observations')}, "
        f"ai_asset={_count_value(counts, 'ai_asset_candidates')}, "
        f"host_ranking={_count_value(counts, 'host_ranking')}"
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


def _build_ranker_advisory_hint(
    *,
    surface_projection: dict,
    ranked: dict,
    next_action: str,
    browser_pending: bool = False,
    source_pending: bool = False,
    js_pending: bool = False,
) -> dict:
    """Offer the optional read-only ranker only for evidence-rich long tails."""
    if str((surface_projection or {}).get("status") or "").strip().lower() != "valid":
        return {}
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
        "review_intel_group",
        "guard_safe_pivot",
    }:
        return {}
    if browser_pending or source_pending or js_pending:
        return {}

    stats = ranked.get("stats") if isinstance(ranked.get("stats"), dict) else {}
    review_count = int(stats.get("review_pool", 0) or 0)
    shape_count = max(
        int(stats.get("semantic_shape_count", 0) or 0),
        int(stats.get("semantic_shapes", 0) or 0),
    )
    raw_count = max(
        int(stats.get("raw_urls", 0) or 0),
        int(stats.get("exact_unique", 0) or 0),
    )
    untouched = int(stats.get("observation_untouched", 0) or 0)
    stale = int(stats.get("observation_stale", 0) or 0)
    long_tail = bool(
        untouched > 0
        or stale > 0
        or shape_count > max(review_count, 1)
        or raw_count > max(review_count, 1)
    )
    if not long_tail:
        return {}

    signal_groups = 0
    for section, keys in (
        ("browser", ("xhr_count", "api_count")),
        ("js_intel", ("endpoint_count", "lead_count", "graphql_count")),
        ("source_intel", ("hypothesis_count", "route_count", "graphql_count")),
        ("scanner", ("finding_count",)),
        ("intel", ("signal_count",)),
    ):
        value = ranked.get(section) if isinstance(ranked.get(section), dict) else {}
        if any(int(value.get(key, 0) or 0) > 0 for key in keys):
            signal_groups += 1
    if ranked.get("workflow_leads"):
        signal_groups += 1
    if any(
        isinstance(item, dict) and item.get("tech_stack")
        for item in (ranked.get("review_pool") or [])
    ):
        signal_groups += 1
    if signal_groups < 2:
        return {}

    tail_labels = []
    if untouched:
        tail_labels.append(f"{untouched} untouched observations")
    if stale:
        tail_labels.append(f"{stale} stale observations")
    if shape_count > max(review_count, 1):
        tail_labels.append(f"{shape_count} semantic shapes")
    if not tail_labels:
        tail_labels.append(f"{raw_count} exact surface entries")
    return {
        "tool": "recon-ranker",
        "mode": "advisory",
        "executable": False,
        "reason": (
            "valid Surface projection leaves "
            + ", ".join(tail_labels[:2])
            + f" and {signal_groups} evidence groups; use one read-only ranker review "
            "only if Claude needs a second opinion before selecting the next lane"
        ),
    }


def _build_enrichment_hints(
    *,
    repo_root: str,
    resolved_target: str,
    surface_context: dict,
    ranked: dict,
    surface_projection: dict | None = None,
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
        "review_intel_group",
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
    browser_pending = not browser_ready and _has_browser_mcp_signal(surface_context, ranked)
    source_pending = repo_source_available and not source_intel_ready
    js_pending = not js_intel_ready and _has_js_read_signal(recon_dir, surface_context)

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

    ranker_hint = _build_ranker_advisory_hint(
        surface_projection=surface_projection or {},
        ranked=ranked,
        next_action=next_action,
        browser_pending=browser_pending,
        source_pending=source_pending,
        js_pending=js_pending,
    )
    if ranker_hint:
        hints.append(ranker_hint)
    if browser_pending:
        reason = (
            "authenticated browser capture is missing persisted state; recapture Network and complete state"
            if browser_evidence.get("auth_required") and browser_evidence.get("auth_state") != "present"
            else "app-like or GraphQL surface signals were detected; use Chrome DevTools or Playwright MCP, then import the observed artifacts"
        )
        hints.append({
            "tool": "collect_browser_mcp_evidence",
            "reason": reason,
        })
    if source_pending:
        hints.append({
            "tool": "run_source_intel",
            "reason": "repo source artifacts exist, but source_intel artifacts have not been generated yet",
        })
    if js_pending:
        hints.append({
            "tool": "run_js_read",
            "reason": "cached JS artifacts exist, but js_intel materials have not been prepared yet",
        })

    next_tool_hint = next(
        (
            str(item.get("tool") or "")
            for item in hints
            if item.get("executable", True) and item.get("tool") != "recon-ranker"
        ),
        "",
    )
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
        "action-gated-review",
        "browser-enrichment",
        "case-state-enrichment",
    }:
        return True
    if status == "queued" and action_type == "coverage-gap":
        if str(item.get("source") or "") != "checkpoint" or evidence_type != "checkpoint-next-action":
            return True
        if int(item.get("attempts", 0) or 0) > 0:
            return True
        if any(metadata.get(key) for key in ("hypothesis_id", "evidence_ref", "last_outcome")):
            return True
        endpoint = str(metadata.get("coverage_endpoint") or metadata.get("endpoint") or "").strip()
        vuln_class = str(metadata.get("vuln_class") or "").strip()
        if not endpoint or not vuln_class:
            return True
        observed_params = metadata.get("observed_params")
        params = observed_params if isinstance(observed_params, list) else []
        relevance = class_relevance(endpoint, vuln_class, params)
        if int(relevance.get("relevance_score", 0) or 0) > 0:
            return True
        # Legacy checkpoint actions may have lost parameter names. Preserve a
        # parameter-backed action until the next checkpoint refresh can rewrite
        # its structured metadata instead of retiring a real input surface.
        return "parameter" in str(metadata.get("relevance_reason") or "").lower()
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


def _queue_snapshot_for_target(
    repo_root: str,
    target: str,
    queue_snapshot: dict | None = None,
) -> dict:
    """Return one validated Queue view for the current target."""
    if not isinstance(queue_snapshot, dict):
        return load_queue(repo_root, target)
    snapshot_target = canonical_target_value(str(queue_snapshot.get("target") or ""))
    if snapshot_target != canonical_target_value(target):
        raise ValueError("action queue snapshot target does not match requested target")
    return queue_snapshot


def _owner_source_markers(repo_root: str | Path, target: str) -> dict[str, tuple[object, ...]]:
    """Capture owner file metadata without reading another state projection."""
    resolved = canonical_target_value(target)
    key = target_storage_key(resolved)
    paths = {
        "action_queue": queue_path(repo_root, resolved),
        "coverage": Path(repo_root) / "evidence" / key / "coverage_matrix.json",
        "ledger": Path(repo_root) / "memory" / "evidence" / key / "ledger.jsonl",
        "surface": Path(repo_root) / "state" / key / "surface-projection.json",
        "checkpoint": Path(repo_root) / "state" / key / "checkpoint_latest.json",
        "target_memory": Path(repo_root) / "memory" / "goals" / "targets" / f"{key}.json",
    }
    markers: dict[str, tuple[object, ...]] = {}
    for name, path in paths.items():
        try:
            stat = path.stat()
        except FileNotFoundError:
            markers[name] = (False,)
        except OSError as exc:
            markers[name] = ("error", type(exc).__name__, str(exc)[:160])
        else:
            markers[name] = (True, stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns)
    return markers


def _load_substantive_action_queue_next(
    repo_root: str,
    target: str,
    *,
    queue_snapshot: dict | None = None,
) -> dict:
    """复用 action_queue 的公开 selector，不复制其排序与去重规则。"""
    queue = dict(_queue_snapshot_for_target(repo_root, target, queue_snapshot))
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
    recon_in_progress = runtime_phase_in_progress(
        repo_root, resolved_target, "recon", runtime_state
    )
    candidates = _read_batch_ranked_targets(
        batch_dir / "high_value_targets.json",
        completed,
    )
    scope = _scope_identity(resolved_target)
    for candidate in candidates:
        candidate["parent_scope_ref"] = str(scope.get("scope_ref") or "")
        candidate["parent_scope_hash"] = str(scope.get("scope_hash") or "")
        candidate["continuation_create_args"] = [
            "--parent-target",
            resolved_target,
            "--selected-target",
            str(candidate.get("target") or ""),
        ]
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

    state = {
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
    state["hard_gate"] = _hard_gate_projection(state)
    state["fallback_action"] = next_action
    state["priority_frontier"] = []
    state["selection_mode"] = "hard_gate"
    return state


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
    queue_snapshot: dict | None = None,
    case_state_summary: dict | None = None,
) -> dict:
    """一次性读取 next-action 所需控制事实。

    Bootstrap 使用 ``fast_recon=True``，因此这里只 stat recon artifact，且
    finding reader 禁止 legacy migration。完整诊断路径复用同一事实集合，
    但保留精确 recon 计数。
    """
    resume_summary = load_resume_summary(resolved_memory_dir, resolved_target)
    finalized_identities = _finalized_finding_identities(repo_root, resolved_target)
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
    queue = _queue_snapshot_for_target(repo_root, resolved_target, queue_snapshot)
    action_queue_next = _load_substantive_action_queue_next(
        repo_root,
        resolved_target,
        queue_snapshot=queue,
    )
    runtime_state = load_runtime_state(repo_root, resolved_target)
    recon_artifacts = (
        inspect_recon_artifacts_fast(repo_root, resolved_target)
        if fast_recon
        else inspect_recon_artifacts(repo_root, resolved_target)
    )
    dir_fuzz_rotation = load_rotation_status(repo_root, resolved_target)
    # An active phase lock wins over partial artifacts. Recon publishes files
    # incrementally, so readiness is not a completion signal while the runner
    # still owns the target lock.
    recon_in_progress = runtime_phase_in_progress(
        repo_root, resolved_target, "recon", runtime_state
    )
    scan_in_progress = runtime_phase_in_progress(
        repo_root, resolved_target, "scan", runtime_state
    )
    runtime_derived = _derive_current_status(
        Path(repo_root),
        resolved_target,
        runtime_state,
        recon_artifacts,
        {
            key: int((structured_findings or {}).get(key, 0) or 0)
            for key in (
                "pending_validation",
                "owner_revalidation_pending",
                "validated_pending_report",
            )
        },
    )
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
        finalized_identities,
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
    case_state = _load_case_state_projection(
        repo_root,
        resolved_target,
        case_state_summary=case_state_summary,
    )
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
        "action_queue_fingerprint": queue_fingerprint(queue),
        "runtime_state": runtime_state,
        "runtime_derived": runtime_derived,
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
    ranked_for_action = _filter_stale_finalized_scanner_candidates(
        _filter_legacy_memory_candidates(ranked_for_next, resume_targets)
    )
    resume_targets_bound = _resume_targets_match_ranked_surface(
        resume_targets,
        ranked_for_action,
        target=resolved_target,
    )

    tech_stack = []
    if resume_summary and resume_summary.get("tech_stack"):
        tech_stack = resume_summary["tech_stack"]
    elif has_recon:
        review_pool = ranked_for_next.get("review_pool", []) or ranked_for_next.get("p1", [])
        if review_pool:
            tech_stack = review_pool[0].get("tech_stack", [])

    primary_next_action = _pick_next_action(
        has_recon,
        ranked_for_action,
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
        resume_targets_bound=resume_targets_bound,
    )
    intel_continuation = facts.get("intel_continuation") or {}
    next_action = apply_intel_continuation(primary_next_action, intel_continuation)
    surface_review_candidates = (
        _build_recommended_targets(
            _candidate_items_for_next_action(ranked_for_action, next_action),
            guard_status,
            resume_targets,
            prefer_resume_targets=next_action == "continue_last_focus",
        )
        if has_recon and next_action not in {
            "run_intel",
            "collect_web_intel",
            "test_advisory_applicability",
            "review_intel_group",
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
            surface_projection=surface_projection,
            repo_source_available=bool(facts.get("repo_source_available")),
            next_action=next_action,
            browser_evidence=facts.get("browser_evidence") or {},
        )
    else:
        # Bounded bootstrap reuses the same readiness checks but exposes only
        # the non-executable specialist advisory.
        _, bounded_hints = _build_enrichment_hints(
            repo_root=str(facts["repo_root"]),
            resolved_target=resolved_target,
            surface_context=surface_context or {},
            ranked=ranked_for_next,
            surface_projection=surface_projection,
            repo_source_available=bool(facts.get("repo_source_available")),
            next_action=next_action,
            browser_evidence=facts.get("browser_evidence") or {},
        )
        next_tool_hint = ""
        enrichment_hints = [
            item for item in bounded_hints if item.get("tool") == "recon-ranker"
        ][:1]
    if next_action in {"run_intel", "collect_web_intel", "test_advisory_applicability", "review_intel_group"}:
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
    state = {
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
        "action_queue_fingerprint": str(facts.get("action_queue_fingerprint") or ""),
        "action_queue": {"next": facts.get("action_queue_next") or {}},
        "runtime_derived": facts.get("runtime_derived") or {},
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
        "deferred_surface_candidates": ranked_for_action.get("deferred_surface_candidates", []),
        "recent_guard_advisories": recent_guard_advisories[:3],
        "recent_guard_blocks": recent_guard_advisories[:3],
    }
    state["hard_gate"] = _hard_gate_projection(state)
    state["fallback_action"] = next_action
    actionable_frontier = (
        []
        if state["hard_gate"]
        else _build_actionable_frontier(state, None, limit=None)
    )
    state["priority_frontier"] = (
        []
        if state["hard_gate"]
        else _build_priority_frontier(
            state,
            ranked_for_action,
            actionable_frontier=actionable_frontier,
        )
    )
    state["selection_mode"] = (
        "hard_gate"
        if state["hard_gate"]
        else "ai_priority"
        if len(state["priority_frontier"]) > 1
        else "direct"
        if state["priority_frontier"]
        else "fallback"
    )
    return state


def _surface_projection_with_continuation(
    projection: dict,
    ranked: dict,
) -> dict:
    """Carry the bounded raw-surface cursor into Claude's bootstrap state."""
    result = dict(projection or {})
    index = ranked.get("surface_index") if isinstance(ranked, dict) else {}
    continuation = index.get("continuation") if isinstance(index, dict) else {}
    if isinstance(continuation, dict):
        bounded = {
            "available": bool(continuation.get("available")),
            "next_cursor": str(continuation.get("next_cursor") or "")[:512],
            "command": str(continuation.get("command") or "")[:800],
        }
        if bounded["available"] or bounded["next_cursor"] or bounded["command"]:
            result["continuation"] = bounded
    return result


def build_autopilot_bootstrap_state(
    repo_root: str,
    target: str,
    memory_dir: str | None = None,
    *,
    queue_snapshot: dict | None = None,
    case_state_summary: dict | None = None,
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
        queue_snapshot=queue_snapshot,
        case_state_summary=case_state_summary,
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
        surface_projection=_surface_projection_with_continuation({
            "status": str(projection.get("status") or "invalid"),
            "reason": str(projection.get("reason") or ""),
            "path": str(projection.get("path") or ""),
            "input_fingerprint": str(projection.get("input_fingerprint") or ""),
            "refresh_command": f"python3 tools/surface.py --target {resolved_target} --refresh",
        }, ranked),
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
    queue_snapshot: dict | None = None,
    case_state_summary: dict | None = None,
) -> dict:
    """Build an autopilot state; bounded mode never rebuilds the full surface."""
    if bounded:
        return build_autopilot_bootstrap_state(
            repo_root,
            target,
            memory_dir=memory_dir,
            queue_snapshot=queue_snapshot,
            case_state_summary=case_state_summary,
        )
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
        queue_snapshot=queue_snapshot,
        case_state_summary=case_state_summary,
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
        surface_projection=_surface_projection_with_continuation({
            "status": str(projection.get("status") or "computed"),
            "reason": str(projection.get("reason") or ""),
            "path": str(projection.get("path") or ""),
            "input_fingerprint": str(projection.get("input_fingerprint") or ""),
        }, ranked),
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


def _ledger_health_projection(diagnostic: dict) -> dict:
    """Keep Ledger damage visible without serializing raw rows or paths."""
    if not isinstance(diagnostic, dict):
        return {}
    status = str(diagnostic.get("status") or "missing").strip().lower()
    health = {
        "status": status,
        "invalid_count": int(diagnostic.get("invalid_count", 0) or 0),
        "invalid_rows": [
            item for item in (diagnostic.get("invalid_rows") or [])[:5]
            if isinstance(item, dict)
        ],
        "last_valid_offset": int(diagnostic.get("last_valid_offset", 0) or 0),
    }
    if status == "unreadable" and diagnostic.get("read_error"):
        health["read_error"] = " ".join(str(diagnostic["read_error"]).split())[:240]
    return health


def build_loop_guard_projection(state: dict, ledger_entries: list[dict] | None = None) -> dict:
    """Return a read-only per-iteration rotation decision from recent evidence."""
    action = str(state.get("next_action") or "handoff")
    ledger_health = state.get("_ledger_health") if isinstance(state.get("_ledger_health"), dict) else {}
    ledger_status = str(ledger_health.get("status") or "missing").strip().lower()
    if ledger_status in {"partial", "unreadable"}:
        result = {
            "verdict": "continue",
            "reason": f"ledger_{ledger_status}",
            "endpoint_family": "",
            "vuln_class": "",
            "next_action": action,
            "rotation_target": {},
        }
        result["ledger_health"] = ledger_health
        return result
    authoritative_reason = _loop_guard_authoritative_reason(state)
    if authoritative_reason:
        result = {
            "verdict": "continue",
            "reason": authoritative_reason,
            "endpoint_family": "",
            "vuln_class": "",
            "next_action": action,
            "rotation_target": {},
        }
        if ledger_health:
            result["ledger_health"] = ledger_health
        return result
    hint = _rotation_hint(ledger_entries or [])
    if not hint:
        result = {
            "verdict": "continue",
            "reason": "insufficient_homogeneous_outcomes",
            "endpoint_family": "",
            "vuln_class": "",
            "next_action": action,
            "rotation_target": {},
        }
        if ledger_health:
            result["ledger_health"] = ledger_health
        return result
    if action not in _LOOP_GUARD_ROTATABLE_ACTIONS:
        result = {
            "verdict": "continue",
            "reason": "authoritative_next_action",
            "endpoint_family": hint["endpoint_family"],
            "vuln_class": hint["vuln_class"],
            "next_action": action,
            "rotation_target": {},
        }
        if ledger_health:
            result["ledger_health"] = ledger_health
        return result
    result = {
        "verdict": "rotate",
        "reason": hint["reason"],
        "endpoint_family": hint["endpoint_family"],
        "vuln_class": hint["vuln_class"],
        "next_action": hint["action"],
        "rotation_target": _rotation_target(state, hint["endpoint_family"]),
    }
    if ledger_health:
        result["ledger_health"] = ledger_health
    return result


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
            gap_count = int(summary.get("high_value_gaps_count", -1))
            if gap_count < 0 or (gap_count > 0 and not gaps):
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


def _actionable_coverage_gaps(matrix: dict) -> list[dict]:
    return actionable_coverage_gaps(_coverage_gaps(matrix))


def _coverage_has_high_value_gaps(matrix: dict) -> bool:
    return bool(_actionable_coverage_gaps(matrix))


def _authz_context_reason(case_state: dict, matrix: dict) -> str:
    """Keep anonymous-only access-control review from claiming exhaustion."""
    if str(case_state.get("status") or "") != "valid":
        return ""
    coverage = case_state.get("authz_coverage")
    if not isinstance(coverage, dict) or str(coverage.get("status") or "") == "ready":
        return ""
    lanes = matrix.get("high_risk_lanes") if isinstance(matrix, dict) else None
    if not isinstance(lanes, dict):
        lanes = {}
    relevant = any(
        str((lanes.get(vuln_class) or {}).get("disposition") or "")
        not in {"", "not_observed", "not_applicable"}
        for vuln_class in ("IDOR", "Authz", "GraphQL")
    )
    if not lanes:
        relevant = any(
            isinstance(endpoint, dict)
            and any(
                isinstance((endpoint.get("cells") or {}).get(vuln_class), dict)
                and (endpoint["cells"][vuln_class].get("status") not in {None, "n_a"})
                for vuln_class in ("IDOR", "Authz", "GraphQL")
            )
            for endpoint in matrix.get("endpoints") or []
        )
    if not relevant:
        return ""
    return (
        "actor_context_missing"
        if str(coverage.get("status") or "") == "missing"
        else "actor_context_incomplete"
    )


def _final_queue_execution_specs(queue: dict) -> list[dict[str, str]]:
    """Return final Queue dimensions without collapsing vulnerability lanes."""
    specs: list[dict[str, str]] = []
    for action in queue.get("actions") or []:
        if not isinstance(action, dict):
            continue
        if str(action.get("status") or "").strip().lower() not in FINAL_STATUSES:
            continue
        metadata = action.get("metadata") if isinstance(action.get("metadata"), dict) else {}
        endpoint = canonical_endpoint_identity(
            str(metadata.get("endpoint") or metadata.get("url") or "")
        )
        if endpoint:
            specs.append({
                "endpoint": endpoint,
                "vuln_class": str(metadata.get("vuln_class") or "").strip().lower(),
                "semantic_shape_id": str(metadata.get("semantic_shape_id") or "").strip().lower(),
                "auth_context": str(metadata.get("auth_context") or "").strip().lower(),
            })
    return specs


def _surface_review_completion(
    state: dict,
    matrix: dict | None,
    queue: dict,
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
        for gap in _actionable_coverage_gaps(matrix)
        if isinstance(gap, dict)
    }
    final_specs = _final_queue_execution_specs(queue)
    unresolved = []
    for candidate in candidates:
        if not isinstance(candidate, dict):
            unresolved.append({"reason": "invalid_candidate"})
            continue
        url = str(candidate.get("url") or "").strip()
        endpoint = _normalise_endpoint_path(url)
        endpoint_identity = canonical_endpoint_identity(url)
        coverage_endpoint = (
            endpoint
            if endpoint in matrix_by_path
            else _normalise_endpoint_path(_route_template(endpoint))
        )
        if not endpoint or not endpoint_identity:
            unresolved.append({"url": url, "reason": "missing_endpoint"})
        elif coverage_endpoint not in matrix_by_path:
            unresolved.append({"url": url, "reason": "coverage_endpoint_missing"})
        elif coverage_endpoint in high_gap_paths:
            unresolved.append({"url": url, "reason": "coverage_gap_pending"})
        else:
            candidate_class = str(candidate.get("vuln_class") or "").strip().lower()
            candidate_shape = str(candidate.get("semantic_shape_id") or "").strip().lower()
            candidate_auth = str(candidate.get("auth_context") or "").strip().lower()
            matched = any(
                spec["endpoint"] == endpoint_identity
                and (not candidate_class or spec["vuln_class"] == candidate_class)
                and (not candidate_shape or not spec["semantic_shape_id"] or spec["semantic_shape_id"] == candidate_shape)
                and (not candidate_auth or not spec["auth_context"] or spec["auth_context"] == candidate_auth)
                for spec in final_specs
            )
            if not matched:
                unresolved.append({"url": url, "reason": "review_outcome_missing"})
    return {"status": "complete" if not unresolved else "unresolved", "unresolved": unresolved[:5]}


def _explicit_partial_reason(state: dict) -> str:
    """Keep a stale handoff state from hiding durable work owned elsewhere."""
    if state.get("recon_in_progress") or state.get("scan_in_progress"):
        return "runtime_phase_active"
    run_budget = (state.get("recon_artifacts") or {}).get("run_budget") or {}
    if run_budget.get("partial"):
        return "recon_budget_partial"
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
    if state.get("resume_targets") and _resume_targets_bound_to_surface(state):
        return "surface_work_pending"

    return ""


def _observation_partial_reason(state: dict) -> str:
    """Return the bounded Observation prerequisite after actionable lanes."""
    inventory = state.get("observation_inventory") or {}
    inventory_status = str(inventory.get("status") or "")
    if inventory_status and inventory_status != "valid":
        return "observation_inventory_partial"
    by_kind = inventory.get("by_kind") if isinstance(inventory.get("by_kind"), dict) else {}
    for kind in HIGH_VALUE_OBSERVATION_KINDS:
        try:
            untouched = int((by_kind.get(kind) or {}).get("present_untouched", 0) or 0)
        except (TypeError, ValueError):
            untouched = 0
        if untouched > 0:
            return "observation_high_value_pending"
    return ""


def _frontier_item(
    *,
    owner: str,
    action: str,
    evidence_ref: str,
    expected_information_gain: str,
    stop_condition: str,
    item_id: str = "",
    priority: int | None = None,
) -> dict:
    """Build a bounded read-only action handoff from an existing owner."""
    item = {
        "owner": owner,
        "id": " ".join(str(item_id or "").split())[:300],
        "action": " ".join(str(action or "").split())[:500],
        "evidence_ref": " ".join(str(evidence_ref or "").split())[:300],
        "expected_information_gain": " ".join(
            str(expected_information_gain or "").split()
        )[:300],
        "stop_condition": " ".join(str(stop_condition or "").split())[:300],
    }
    if priority is not None:
        item["priority"] = int(priority or 0)
    return item


def _build_actionable_frontier(
    state: dict,
    matrix: dict | None,
    *,
    limit: int | None = None,
) -> list[dict]:
    """Project executable work without creating a second state owner."""
    target = str(state.get("resolved_target") or state.get("target") or "")
    frontier: list[dict] = []

    queue_next = state.get("action_queue_next") if isinstance(state.get("action_queue_next"), dict) else {}
    if queue_next:
        metadata = queue_next.get("metadata") if isinstance(queue_next.get("metadata"), dict) else {}
        frontier.append(_frontier_item(
            owner="action_queue",
            item_id=str(queue_next.get("id") or ""),
            action=str(queue_next.get("action") or queue_next.get("type") or "resume queued action"),
            evidence_ref=str(
                queue_next.get("evidence_ref")
                or metadata.get("evidence_ref")
                or queue_next.get("evidence")
                or f"state/{target_storage_key(target)}/action_queue.json"
            ),
            expected_information_gain=str(
                queue_next.get("next_question")
                or "resolve the queued evidence question"
            ),
            stop_condition=str(
                queue_next.get("stop_condition")
                or "record a terminal owner result or a bounded blocker"
            ),
            priority=int(queue_next.get("priority", 0) or 0),
        ))

    findings = state.get("structured_findings") if isinstance(state.get("structured_findings"), dict) else {}
    for key, label in (
        ("next_owner_revalidation", "revalidate finding owner"),
        ("next_validation", "validate finding"),
        ("next_draft_completion", "complete finding report draft"),
        ("next_report", "report validated finding"),
    ):
        finding = findings.get(key) if isinstance(findings.get(key), dict) else {}
        if not finding:
            continue
        finding_id = str(finding.get("id") or "")
        evidence_ref = str(
            finding.get("evidence_ref")
            or finding.get("source_file")
            or (
                f"findings/{target_storage_key(target)}/findings.json#{finding_id}"
                if finding_id else f"findings/{target_storage_key(target)}/findings.json"
            )
        )
        frontier.append(_frontier_item(
            owner="finding",
            item_id=finding_id,
            action=str(
                finding.get("required_action")
                or finding.get("action")
                or label
            ),
            evidence_ref=evidence_ref,
            expected_information_gain=str(
                finding.get("next_question")
                or finding.get("missing_evidence")
                or "resolve the finding evidence gate"
            ),
            stop_condition=str(
                finding.get("downgrade_rule")
                or "record validated, candidate, dead-end, or blocked owner state"
            ),
            priority=100 if key in {"next_owner_revalidation", "next_validation"} else 90,
        ))
        break

    case_state = state.get("case_state") if isinstance(state.get("case_state"), dict) else {}
    case_next = case_state.get("top_next_action") if isinstance(case_state.get("top_next_action"), dict) else {}
    if str(case_next.get("next_action") or "none") != "none":
        frontier.append(_frontier_item(
            owner="case_state",
            item_id=str(case_next.get("backlog_id") or case_next.get("hypothesis_id") or ""),
            action=str(case_next.get("write_back") or case_next.get("next_action")),
            evidence_ref=str(case_state.get("path") or f"state/{target_storage_key(target)}/case_state.json"),
            expected_information_gain=str(
                case_next.get("why_now") or case_next.get("hypothesis") or "resolve the Case State prerequisite"
            ),
            stop_condition=str(
                case_next.get("stop_condition")
                or "record the backlog as tested, candidate, blocked, or dead-end"
            ),
            priority=95,
        ))
    else:
        case_obligation = ""
        if int(case_state.get("canonical_conflict_count", 0) or 0) > 0:
            case_obligation = "canonical-conflict"
            case_action = "Reconcile the Case State canonical conflict before closure"
            case_gain = "align Case State terminal records with the canonical finding owner"
            case_stop = "record the reconciliation or a bounded blocker, then recompute Closure"
        elif int(case_state.get("pending_validation_backlog", 0) or 0) > 0:
            case_obligation = "validation-backlog"
            case_action = "Resume the pending Case State validation backlog"
            case_gain = "produce the next owner-backed validation result"
            case_stop = "record the backlog result as tested, candidate, blocked, or dead-end"
        elif int(case_state.get("open_hypotheses", 0) or 0) > 0:
            case_obligation = "open-hypothesis"
            case_action = "Resolve the next open Case State hypothesis"
            case_gain = "turn the hypothesis into bounded actor, object, or replay evidence"
            case_stop = "record a bounded hypothesis result or an explicit blocker"
        if case_obligation:
            frontier.append(_frontier_item(
                owner="case_state",
                item_id=case_obligation,
                action=case_action,
                evidence_ref=str(
                    case_state.get("path")
                    or f"state/{target_storage_key(target)}/case_state.json"
                ),
                expected_information_gain=case_gain,
                stop_condition=case_stop,
                priority=95,
            ))

    observation_inventory = state.get("observation_inventory") if isinstance(state.get("observation_inventory"), dict) else {}
    observation_reason = _observation_partial_reason(state)
    if observation_reason:
        target = str(state.get("resolved_target") or state.get("target") or "")
        if observation_reason == "observation_high_value_pending":
            action = "Review the bounded high-value Observation inventory sample"
            expected_information_gain = "turn exposure/infra observations into a target-owned action or explicit disposition"
            stop_condition = "touch, review, park, or enqueue each sampled observation; never infer tested-clean from omission"
        else:
            action = "Synchronize or repair the target-owned Observation inventory"
            expected_information_gain = "restore a valid bound summary and expose the bounded untouched sample"
            stop_condition = "publish a valid inventory summary or record the missing, stale, or invalid blocker"
        frontier.append(_frontier_item(
            owner="observation",
            item_id=observation_reason,
            action=action,
            evidence_ref=str(
                observation_inventory.get("summary_path")
                or f"state/{target_storage_key(target)}/observations-summary.json"
            ),
            expected_information_gain=expected_information_gain,
            stop_condition=stop_condition,
            priority=72,
        ))

    gaps = _actionable_coverage_gaps(matrix) if isinstance(matrix, dict) else []
    if gaps:
        gap = gaps[0]
        coverage_endpoint = str(gap.get("endpoint") or "")
        endpoint = str(gap.get("representative_endpoint") or coverage_endpoint)
        vuln_class = str(gap.get("vuln_class") or "")
        frontier.append(_frontier_item(
            owner="coverage",
            item_id=f"{vuln_class}:{coverage_endpoint}",
            action=f"Review the high-value {vuln_class} coverage gap at {endpoint}",
            evidence_ref=str(
                state.get("_coverage_evidence_ref")
                or f"evidence/{target_storage_key(target)}/coverage_matrix.json"
            ),
            expected_information_gain=(
                f"obtain a disposition for {vuln_class} on {coverage_endpoint}"
            ),
            stop_condition="record tested, blocked, dead-end, not_applicable, or candidate with evidence",
            priority=80,
        ))

    json_inject = state.get("json_inject") if isinstance(state.get("json_inject"), dict) else {}
    if str(json_inject.get("status") or "") in {"partial", "invalid_input", "candidate_pending"}:
        frontier.append(_frontier_item(
            owner="json-inject",
            action="Resume the bounded JSON input evidence lane",
            evidence_ref=str(json_inject.get("path") or "findings/json_inject/summary.json"),
            expected_information_gain="resolve the pending JSON response or candidate signal",
            stop_condition="record candidate, tested-clean, dead-end, or the explicit input blocker",
            priority=75,
        ))
    for lane, item in (state.get("sql_matrix") or {}).items():
        if not isinstance(item, dict) or str(item.get("status") or "") not in {"partial", "invalid_input", "candidate_pending"}:
            continue
        frontier.append(_frontier_item(
            owner="sql-matrix",
            item_id=str(lane),
            action=f"Resume the bounded {lane} SQL evidence lane",
            evidence_ref=str(item.get("path") or f"findings/sql_matrix/{lane}/summary.json"),
            expected_information_gain="resolve the pending SQL response difference",
            stop_condition="record candidate, tested-clean, dead-end, or the explicit input blocker",
            priority=75,
        ))
    js_intel = state.get("js_intel") if isinstance(state.get("js_intel"), dict) else {}
    if str(js_intel.get("status") or "") in {"prepared", "partial"}:
        frontier.append(_frontier_item(
            owner="js-intel",
            action="Read and disposition the prepared JavaScript evidence",
            evidence_ref=str(js_intel.get("path") or js_intel.get("hypotheses_path") or "findings/js_intel/materials.json"),
            expected_information_gain="turn the prepared JS material into a bounded endpoint or parameter action",
            stop_condition="record analyzed, blocked, dead-end, or not-applicable disposition",
            priority=70,
        ))
    browser = state.get("browser_evidence") if isinstance(state.get("browser_evidence"), dict) else {}
    if browser.get("present") and not browser.get("ready"):
        frontier.append(_frontier_item(
            owner="browser",
            action="Repair or complete the existing browser evidence import",
            evidence_ref=str(browser.get("path") or "findings/browser/mcp-readiness.json"),
            expected_information_gain="persist the observed browser state and request evidence needed for replay",
            stop_condition="import complete evidence or record the bounded browser blocker",
            priority=70,
        ))
    source = state.get("repo_source_summary") if isinstance(state.get("repo_source_summary"), dict) else {}
    if str(source.get("status") or "").lower() in {"partial", "blocked", "failed", "error", "incomplete", "confirmation_required"}:
        artifacts = state.get("repo_source_artifacts") or []
        target = str(state.get("resolved_target") or state.get("target") or "")
        evidence_ref = str(
            artifacts[0] if artifacts else f"findings/{target_storage_key(target)}/exposure/repo_source_meta.json"
        )
        if artifacts and not evidence_ref.startswith("findings/"):
            evidence_ref = f"findings/{target_storage_key(target)}/exposure/{evidence_ref}"
        frontier.append(_frontier_item(
            owner="source-intel",
            action="Complete or disposition the repository-source evidence review",
            evidence_ref=evidence_ref,
            expected_information_gain="resolve the source exposure status and any target-owned lead",
            stop_condition="record source review complete, blocked, or confirmation-required",
            priority=65,
        ))

    for hint in state.get("enrichment_hints") or []:
        if not isinstance(hint, dict) or not hint.get("executable", True):
            continue
        tool = str(hint.get("tool") or "").strip()
        if not tool or tool == "recon-ranker":
            continue
        frontier.append(_frontier_item(
            owner="enrichment",
            action=tool,
            evidence_ref=str(
                hint.get("evidence_ref")
                or hint.get("path")
                or "enrichment_artifacts"
            ),
            expected_information_gain=str(hint.get("reason") or "produce the missing enrichment artifact"),
            stop_condition="artifact is written and its owner disposition is recorded",
            priority=60,
        ))

    deduped: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for item in sorted(frontier, key=lambda row: (-row["priority"], row["owner"], row["id"])):
        key = (str(item.get("owner") or ""), str(item.get("id") or item.get("action") or ""))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped if limit is None else deduped[:limit]


_FRONTIER_LANES = {
    "action_queue": "state-and-queue",
    "finding": "state-and-queue",
    "finding-claim": "state-and-queue",
    "validation-runner": "state-and-queue",
    "target-memory": "state-and-queue",
    "case_state": "workflow-timing-and-case-state",
    "observation": "recon-and-surface",
    "coverage": "recon-and-surface",
    "surface": "recon-and-surface",
    "surface-context": "recon-and-surface",
    "recon": "recon-and-surface",
    "intel": "software-and-intel",
    "browser": "browser-source-and-js",
    "source-intel": "browser-source-and-js",
    "js-intel": "browser-source-and-js",
    "json-inject": "sql-json-and-waf",
    "sql-matrix": "sql-json-and-waf",
    "enrichment": "recon-and-surface",
}


def _execution_frontier_item(item: dict, *, impact_hint: str = "") -> dict:
    """Remove controller ranking while retaining owner facts for AI arbitration."""
    projected = {key: value for key, value in item.items() if key != "priority"}
    owner = str(projected.get("owner") or "")
    projected.update({
        "lane": _FRONTIER_LANES.get(owner, "controller"),
        "impact_hint": " ".join(str(impact_hint or "").split())[:300],
        "evidence_status": "owner-backed",
        "closure_blocking": True,
        "continuity": False,
        "runnable": True,
    })
    return projected


# Closure reason order is deliberately explicit.  Terminal/active control
# state wins first, then durable owner work, then derived review signals.
_CLOSURE_REASON_PRIORITY = {
    "state_snapshot_stale": -1,
    "invalid_batch_target": 0,
    "batch_failed": 0,
    "recon_no_live_hosts": 0,
    "round_lane_evidence_invalid": 5,
    "round_lane_unfinished": 5,
    "round_closure_pending": 5,
    "round_lane_unclaimed": 5,
    "runtime_phase_active": 10,
    "checkpoint_invalid": 15,
    "checkpoint_stale": 15,
    "ledger_unreadable": 16,
    "ledger_partial": 16,
    "durable_work_pending": 20,
    "finding_work_pending": 25,
    "case_state_canonical_conflict": 30,
    "case_state_work_pending": 31,
    "actor_context_missing": 32,
    "actor_context_incomplete": 32,
    "surface_projection_pending": 35,
    "surface_work_pending": 36,
    "recon_budget_partial": 40,
    "cidr_continuation_invalid": 40,
    "next_action_pending": 50,
    "coverage_missing": 60,
    "coverage_empty": 60,
    "coverage_invalid": 60,
    "coverage_high_value_gaps": 61,
    "observation_inventory_partial": 70,
    "observation_high_value_pending": 70,
    "browser_evidence_partial": 71,
    "browser_evidence_required": 71,
    "source_evidence_partial": 72,
    "js_evidence_partial": 73,
    "json_evidence_partial": 74,
    "json_candidate_pending": 74,
    "sql_evidence_partial": 75,
    "sql_candidate_pending": 75,
    "intel_evidence_blocked": 76,
    "identity_v2_follow_up_pending": 77,
    "identity_v2_candidate_pending": 77,
    "identity_v2_incomplete": 77,
}

_CLOSURE_REASON_OWNERS = {
    "state_snapshot_stale": {"controller"},
    "durable_work_pending": {"action_queue"},
    "finding_work_pending": {"finding", "finding-claim", "target-memory"},
    "case_state_canonical_conflict": {"case_state"},
    "case_state_work_pending": {"case_state"},
    "actor_context_missing": {"case_state"},
    "actor_context_incomplete": {"case_state"},
    "surface_projection_pending": {"surface", "surface-context"},
    "surface_work_pending": {"surface"},
    "coverage_missing": {"coverage"},
    "coverage_empty": {"coverage"},
    "coverage_invalid": {"coverage"},
    "coverage_high_value_gaps": {"coverage"},
    "observation_inventory_partial": {"observation"},
    "observation_high_value_pending": {"observation"},
    "browser_evidence_partial": {"browser"},
    "browser_evidence_required": {"browser"},
    "source_evidence_partial": {"source-intel"},
    "js_evidence_partial": {"js-intel"},
    "json_evidence_partial": {"json-inject"},
    "json_candidate_pending": {"json-inject"},
    "sql_evidence_partial": {"sql-matrix"},
    "sql_candidate_pending": {"sql-matrix"},
    "intel_evidence_blocked": {"intel"},
    "identity_v2_follow_up_pending": {"evidence-ledger"},
    "identity_v2_candidate_pending": {"evidence-ledger"},
    "identity_v2_incomplete": {"evidence-ledger"},
    "cidr_continuation_invalid": {"recon"},
}


def _closure_primary_reason(reasons: list[str]) -> str:
    """Select one stable reason without losing the diagnostic list."""
    if not reasons:
        return ""
    return min(
        enumerate(reasons),
        key=lambda pair: (_CLOSURE_REASON_PRIORITY.get(pair[1], 90), pair[0]),
    )[1]


def _closure_frontier_matches(reason: str, item: dict) -> bool:
    owners = _CLOSURE_REASON_OWNERS.get(reason)
    if owners:
        return str(item.get("owner") or "") in owners
    return False


def _closure_reason_frontier(
    reason: str,
    state: dict,
    matrix: dict | None,
    current_action: str = "",
) -> dict | None:
    """Create a bounded fallback item when an owner has no projected head."""
    target = str(state.get("resolved_target") or state.get("target") or "")
    target_key = target_storage_key(target)
    if reason == "state_snapshot_stale":
        return _frontier_item(
            owner="controller",
            item_id="state_snapshot_stale",
            action="Refresh the owner state snapshot before continuing",
            evidence_ref=f"state/{target_key}/session.json",
            expected_information_gain=(
                "re-read Queue, Ledger, Coverage, Surface, Checkpoint, and Target Memory "
                "from one stable snapshot"
            ),
            stop_condition="recompute Closure with a stable snapshot or record the owner blocker",
            priority=100,
        )
    if reason == "surface_projection_pending":
        projection = state.get("surface_projection") if isinstance(state.get("surface_projection"), dict) else {}
        return _frontier_item(
            owner="surface",
            action="Refresh the target-owned Surface projection",
            evidence_ref=str(projection.get("path") or "surface_projection"),
            expected_information_gain="restore the bounded Surface index used for review",
            stop_condition="publish a valid projection or record the source blocker",
            priority=60,
        )
    if reason in {"durable_work_pending"}:
        return _frontier_item(
            owner="action_queue",
            item_id=str((state.get("action_queue_next") or {}).get("id") or reason),
            action="Resume substantive work from the durable Action Queue",
            evidence_ref=f"state/{target_key}/action_queue.json",
            expected_information_gain="resolve the selected owner-backed Queue action",
            stop_condition="record a terminal Queue result or bounded blocker",
            priority=85,
        )
    if reason in {"case_state_work_pending", "case_state_canonical_conflict", "actor_context_missing", "actor_context_incomplete"}:
        case_state = state.get("case_state") if isinstance(state.get("case_state"), dict) else {}
        return _frontier_item(
            owner="case_state",
            item_id="canonical-conflict" if reason == "case_state_canonical_conflict" else reason,
            action="Complete the Case State actor and session context required for coverage",
            evidence_ref=str(case_state.get("path") or f"state/{target_key}/case_state.json"),
            expected_information_gain="obtain the missing owner/peer actor and session context",
            stop_condition="record context ready, blocked, or not-applicable with evidence",
            priority=85,
        )
    if reason in {"checkpoint_stale", "checkpoint_invalid"}:
        return _frontier_item(
            owner="checkpoint",
            item_id=reason,
            action="Refresh or repair the target checkpoint witness before continuing",
            evidence_ref=f"state/{target_key}/checkpoint_latest.json",
            expected_information_gain="restore a trusted checkpoint binding for round and queue recovery",
            stop_condition="publish a valid witness or record the checkpoint read/queue mismatch",
            priority=85,
        )
    if reason in {"runtime_phase_active", "recon_budget_partial", "cidr_continuation_invalid"}:
        owner = "runtime" if reason == "runtime_phase_active" else "recon"
        action = "wait_scan" if state.get("scan_in_progress") else "wait_recon"
        if reason in {"recon_budget_partial", "cidr_continuation_invalid"}:
            action = "run_recon"
        continuation = (state.get("recon_artifacts") or {}).get("cidr_continuation") or {}
        if reason == "cidr_continuation_invalid":
            action = "run_recon"
            expected_information_gain = "repair the invalid CIDR cursor and resume target-owned Recon coverage"
            stop_condition = "publish a valid cursor or record the bounded Recon blocker"
        else:
            expected_information_gain = "obtain the owner-written phase result before selecting more work"
            stop_condition = "refresh after the matching phase completes or record its bounded blocker"
        return _frontier_item(
            owner=owner,
            item_id=action,
            action=(
                "Repair the invalid CIDR continuation before resuming Recon"
                if reason == "cidr_continuation_invalid"
                else describe_next_step({**state, "next_action": action})
            ),
            evidence_ref=(
                str(
                    continuation.get("path")
                    or f"recon/{target_key}/live/cidr_continuation.json"
                )
                if reason == "cidr_continuation_invalid"
                else f"recon/{target_key}/recon_manifest.jsonl"
                if owner == "recon"
                else f"state/{target_key}/session.json"
            ),
            expected_information_gain=expected_information_gain,
            stop_condition=stop_condition,
            priority=85,
        )
    if reason == "finding_work_pending":
        return _frontier_item(
            owner="finding",
            item_id="finding-work",
            action="Resolve the canonical Finding owner obligation",
            evidence_ref=f"findings/{target_key}/findings.json",
            expected_information_gain="resolve the pending Finding lifecycle state",
            stop_condition="record validated, candidate, dead-end, or blocked owner state",
            priority=85,
        )
    if reason in {"surface_work_pending"}:
        projection = state.get("surface_projection") if isinstance(state.get("surface_projection"), dict) else {}
        return _frontier_item(
            owner="surface",
            item_id=reason,
            action="Review the currently bound target-owned Surface continuation",
            evidence_ref=str(projection.get("path") or "surface_projection"),
            expected_information_gain="turn the retained Surface lead into a concrete owner action or disposition",
            stop_condition="record evidence-backed Queue/Ledger disposition or defer without tested-clean",
            priority=80,
        )
    evidence_specs = {
        "observation_inventory_partial": (
            "observation", "Synchronize or repair the target-owned Observation inventory",
            f"state/{target_key}/observations-summary.json",
        ),
        "observation_high_value_pending": (
            "observation", "Review the bounded high-value Observation inventory sample",
            f"state/{target_key}/observations-summary.json",
        ),
        "browser_evidence_partial": (
            "browser", "Repair or complete the existing browser evidence import",
            "findings/browser/mcp-readiness.json",
        ),
        "browser_evidence_required": (
            "browser", "Complete the browser evidence required for this surface",
            "findings/browser/mcp-readiness.json",
        ),
        "source_evidence_partial": (
            "source-intel", "Complete or disposition the repository-source evidence review",
            f"findings/{target_key}/exposure/repo_source_meta.json",
        ),
        "js_evidence_partial": (
            "js-intel", "Read and disposition the prepared JavaScript evidence",
            f"findings/{target_key}/js_intel/materials.json",
        ),
        "json_evidence_partial": (
            "json-inject", "Resume the bounded JSON input evidence lane",
            "findings/json_inject/summary.json",
        ),
        "json_candidate_pending": (
            "json-inject", "Resolve the pending JSON input candidate",
            "findings/json_inject/summary.json",
        ),
        "sql_evidence_partial": (
            "sql-matrix", "Resume the bounded SQL evidence lane",
            "findings/sql_matrix/summary.json",
        ),
        "sql_candidate_pending": (
            "sql-matrix", "Resolve the pending SQL response candidate",
            "findings/sql_matrix/summary.json",
        ),
        "intel_evidence_blocked": (
            "intel", "Resolve the bounded software intelligence evidence gap",
            f"findings/{target_key}/intel",
        ),
        "ledger_partial": (
            "evidence-ledger", "Repair or reconcile the target-owned Evidence Ledger before closure",
            f"memory/evidence/{target_key}/ledger.jsonl",
        ),
        "ledger_unreadable": (
            "evidence-ledger", "Repair or reconcile the target-owned Evidence Ledger before closure",
            f"memory/evidence/{target_key}/ledger.jsonl",
        ),
        "identity_v2_follow_up_pending": (
            "evidence-ledger", "Resolve the pending identity evidence follow-up",
            f"memory/evidence/{target_key}/ledger.jsonl",
        ),
        "identity_v2_candidate_pending": (
            "evidence-ledger", "Resolve the pending identity evidence candidate",
            f"memory/evidence/{target_key}/ledger.jsonl",
        ),
        "identity_v2_incomplete": (
            "evidence-ledger", "Complete the identity evidence required for closure",
            f"memory/evidence/{target_key}/ledger.jsonl",
        ),
    }
    if reason in evidence_specs:
        owner, action_text, evidence_ref = evidence_specs[reason]
        return _frontier_item(
            owner=owner,
            item_id=reason,
            action=action_text,
            evidence_ref=evidence_ref,
            expected_information_gain="restore the owner evidence needed for deterministic Closure",
            stop_condition="record a complete owner result or bounded blocker, then recompute Closure",
            priority=80,
        )
    if reason == "next_action_pending" and current_action not in {"", "handoff"}:
        owner = {
            "run_recon": "recon",
            "wait_recon": "runtime",
            "wait_scan": "runtime",
            "run_intel": "intel",
            "collect_web_intel": "intel",
            "test_advisory_applicability": "intel",
            "review_intel_group": "intel",
            "validate_finding": "finding",
            "collect_candidate_evidence": "finding",
            "review_validation_candidate": "validation-runner",
            "revalidate_finding_owner": "finding",
            "report_finding": "finding",
            "complete_report_draft": "finding",
            "resume_action_queue": "action_queue",
            "resume_case_state": "case_state",
            "prepare_surface_context": "surface-context",
            "hunt_p1": "surface",
            "hunt_p2": "surface",
        }.get(current_action)
        if owner:
            return _frontier_item(
                owner=owner,
                item_id=current_action,
                action=describe_next_step({**state, "next_action": current_action}),
                evidence_ref=f"state/{target_key}/session.json",
                expected_information_gain="resolve the selected owner action",
                stop_condition="record the owner result or a bounded blocker, then recompute Closure",
                priority=85,
            )
    if reason in {"coverage_missing", "coverage_empty", "coverage_invalid", "coverage_high_value_gaps"}:
        return _frontier_item(
            owner="coverage",
            item_id=reason,
            action="Rebuild the coverage matrix and record the resulting gap disposition",
            evidence_ref=str(
                state.get("_coverage_evidence_ref")
                or f"evidence/{target_key}/coverage_matrix.json"
            ),
            expected_information_gain="restore a valid bounded coverage projection",
            stop_condition="record the rebuild as complete or blocked with its reason",
            priority=80,
        )
    return None


def _closure_action_for_reason(reason: str, state: dict, current: str) -> str:
    """Map the selected owner continuation to an existing CLI action."""
    exact = {
        "state_snapshot_stale": "refresh_state",
        "surface_projection_pending": "prepare_surface_context",
        "durable_work_pending": "resume_action_queue",
        "case_state_work_pending": "resume_case_state",
        "case_state_canonical_conflict": "resume_case_state",
        "actor_context_missing": "resume_case_state",
        "actor_context_incomplete": "resume_case_state",
        "checkpoint_stale": "refresh_checkpoint",
        "checkpoint_invalid": "refresh_checkpoint",
        "ledger_partial": "repair_evidence_ledger",
        "ledger_unreadable": "repair_evidence_ledger",
        "surface_work_pending": "surface-review",
        "coverage_missing": "coverage-gap",
        "coverage_empty": "coverage-gap",
        "coverage_invalid": "coverage-gap",
        "coverage_high_value_gaps": "coverage-gap",
        "observation_inventory_partial": "surface-review",
        "observation_high_value_pending": "surface-review",
        "browser_evidence_partial": "browser-enrichment",
        "browser_evidence_required": "browser-enrichment",
        "source_evidence_partial": "source-enrichment",
        "js_evidence_partial": "js-enrichment",
        "json_evidence_partial": "json-inject-review",
        "json_candidate_pending": "json-inject-review",
        "sql_evidence_partial": "sql-matrix-review",
        "sql_candidate_pending": "sql-matrix-review",
        "intel_evidence_blocked": "run_intel",
        "identity_v2_follow_up_pending": "repair_evidence_ledger",
        "identity_v2_candidate_pending": "repair_evidence_ledger",
        "identity_v2_incomplete": "repair_evidence_ledger",
        "recon_budget_partial": "run_recon",
        "cidr_continuation_invalid": "run_recon",
        "runtime_phase_active": "wait_scan" if state.get("scan_in_progress") else "wait_recon",
    }
    if reason in exact:
        return exact[reason]
    if reason == "finding_work_pending":
        findings = state.get("structured_findings") if isinstance(state.get("structured_findings"), dict) else {}
        if findings.get("next_owner_revalidation"):
            return "revalidate_finding_owner"
        if findings.get("next_validation"):
            return "validate_finding"
        return "collect_candidate_evidence"
    if reason in {"round_lane_evidence_invalid", "round_lane_unfinished", "round_closure_pending", "round_lane_unclaimed"}:
        return current
    if reason in _TERMINAL_CLOSURE_ACTIONS:
        return current
    if reason == "next_action_pending" and current != "handoff":
        return current
    return current if current != "handoff" else "handoff"


def _finalize_closure_continuation(
    reasons: list[str],
    frontier: list[dict],
    state: dict,
    matrix: dict | None,
    current_action: str,
) -> tuple[list[str], list[dict], str]:
    """Bind primary reason, first frontier item, and next action together."""
    primary = _closure_primary_reason(reasons)
    matching_exists = any(_closure_frontier_matches(primary, item) for item in frontier)
    fallback = _closure_reason_frontier(primary, state, matrix, current_action) if primary else None
    force_fallback = primary in {
        "state_snapshot_stale",
        "surface_projection_pending",
        "checkpoint_stale",
        "checkpoint_invalid",
        "cidr_continuation_invalid",
    }
    if fallback and (force_fallback or not matching_exists):
        frontier = [fallback, *frontier]
    if primary:
        matching = next(
            (item for item in frontier if _closure_frontier_matches(primary, item)),
            None,
        )
        if matching is not None:
            frontier = [matching, *[item for item in frontier if item is not matching]]
    action = _closure_action_for_reason(primary, state, current_action)
    ordered_reasons = ([primary] if primary else []) + [
        reason for reason in reasons if reason != primary
    ]
    return ordered_reasons[:3], frontier, action


def _build_priority_frontier(
    state: dict,
    ranked: dict | None = None,
    *,
    actionable_frontier: list[dict] | None = None,
) -> list[dict]:
    """Expose bounded owner heads for cross-owner AI selection without new state."""
    target = str(state.get("resolved_target") or state.get("target") or "")
    queue_next = (
        state.get("action_queue_next")
        if isinstance(state.get("action_queue_next"), dict)
        else {}
    )
    case_next = (
        (state.get("case_state") or {}).get("top_next_action")
        if isinstance((state.get("case_state") or {}).get("top_next_action"), dict)
        else {}
    )
    structured = (
        state.get("structured_findings")
        if isinstance(state.get("structured_findings"), dict)
        else {}
    )

    other_items: list[dict] = []
    if actionable_frontier is None:
        actionable_frontier = _build_actionable_frontier(state, None, limit=None)
    for item in actionable_frontier:
        owner = str(item.get("owner") or "")
        impact_hint = ""
        if owner == "action_queue":
            metadata = (
                queue_next.get("metadata")
                if isinstance(queue_next.get("metadata"), dict)
                else {}
            )
            impact_hint = str(
                metadata.get("business_impact")
                or metadata.get("expected_learning")
                or queue_next.get("next_question")
                or queue_next.get("evidence")
                or ""
            )
        elif owner == "finding":
            finding_id = str(item.get("id") or "")
            finding = next(
                (
                    structured.get(key)
                    for key in (
                        "next_owner_revalidation",
                        "next_validation",
                        "next_draft_completion",
                        "next_report",
                    )
                    if isinstance(structured.get(key), dict)
                    and str(structured[key].get("id") or "") == finding_id
                ),
                {},
            )
            impact_hint = " ".join(
                str(finding.get(key) or "")
                for key in ("severity", "confidence", "title", "impact")
                if finding.get(key)
            )
        elif owner == "case_state":
            impact_hint = str(
                case_next.get("why_now")
                or case_next.get("hypothesis")
                or case_next.get("write_back")
                or ""
            )
        other_items.append(
            _execution_frontier_item(item, impact_hint=impact_hint)
        )

    runner = (
        state.get("validation_runner_next")
        if isinstance(state.get("validation_runner_next"), dict)
        else {}
    )
    if runner:
        other_items.append(_execution_frontier_item(_frontier_item(
            owner="validation-runner",
            item_id=str(runner.get("id") or runner.get("lane") or ""),
            action=str(
                runner.get("next_action")
                or "review validation candidate and apply the canonical evidence gate"
            ),
            evidence_ref=str(runner.get("summary_path") or runner.get("evidence_ref") or ""),
            expected_information_gain=str(
                runner.get("rubric_summary")
                or runner.get("classifier")
                or "determine whether the runner evidence supports canonical validation"
            ),
            stop_condition="validate through the Finding owner or record a bounded downgrade",
        ), impact_hint=str(
            runner.get("vuln_class")
            or runner.get("evidence_shape")
            or runner.get("result")
            or ""
        )))

    root_claim = (
        state.get("root_finding_claim_next")
        if isinstance(state.get("root_finding_claim_next"), dict)
        else {}
    )
    if root_claim:
        other_items.append(_execution_frontier_item(_frontier_item(
            owner="finding-claim",
            item_id=str(root_claim.get("id") or root_claim.get("claim_id") or ""),
            action="collect locatable evidence and reconcile the claim through checkpoint",
            evidence_ref=str(root_claim.get("source_file") or root_claim.get("claim_source_file") or ""),
            expected_information_gain="determine whether the claim can enter the canonical Finding lifecycle",
            stop_condition="record a canonical candidate or reject the unsupported claim",
        ), impact_hint=str(root_claim.get("title") or root_claim.get("severity") or "")))

    memory_candidate = (
        state.get("memory_candidate_next")
        if isinstance(state.get("memory_candidate_next"), dict)
        else {}
    )
    if memory_candidate:
        other_items.append(_execution_frontier_item(_frontier_item(
            owner="target-memory",
            item_id=str(memory_candidate.get("id") or ""),
            action=str(
                memory_candidate.get("action")
                or "collect evidence for the legacy target-memory candidate"
            ),
            evidence_ref=str(memory_candidate.get("evidence_ref") or "target-memory"),
            expected_information_gain="determine whether the legacy candidate has replayable evidence",
            stop_condition="reconcile through the canonical Finding owner or record evidence missing",
        ), impact_hint=str(memory_candidate.get("action") or "")))

    continuation = (
        (state.get("recon_artifacts") or {}).get("cidr_continuation")
        if isinstance((state.get("recon_artifacts") or {}).get("cidr_continuation"), dict)
        else {}
    )
    if continuation.get("status") in {"pending", "invalid"}:
        continuation_status = str(continuation.get("status") or "pending")
        continuation_action = (
            "Repair the invalid CIDR continuation before resuming Recon"
            if continuation_status == "invalid"
            else f"continue bounded CIDR recon from offset {continuation.get('next_offset', 0)}"
        )
        other_items.append(_execution_frontier_item(_frontier_item(
            owner="recon",
            item_id=f"cidr:{continuation.get('next_offset', continuation_status)}",
            action=continuation_action,
            evidence_ref=str(continuation.get("path") or f"recon/{target_storage_key(target)}/live/cidr_continuation.json"),
            expected_information_gain=(
                "repair the invalid CIDR cursor and resume target-owned Recon coverage"
                if continuation_status == "invalid"
                else f"cover the remaining {continuation.get('remaining_hosts', 'unknown')} CIDR hosts"
            ),
            stop_condition=(
                "publish a valid cursor or record the bounded Recon blocker"
                if continuation_status == "invalid"
                else "advance or complete the durable cursor, or record its explicit blocker"
            ),
        ), impact_hint="remaining target-owned CIDR coverage"))

    intel = (
        state.get("intel_continuation")
        if isinstance(state.get("intel_continuation"), dict)
        else {}
    )
    intel_action = str(intel.get("action") or "complete")
    if intel_action != "complete":
        advisory = intel.get("advisory") if isinstance(intel.get("advisory"), dict) else {}
        review = (
            intel.get("review_projection")
            if isinstance(intel.get("review_projection"), dict)
            else {}
        )
        other_items.append(_execution_frontier_item(_frontier_item(
            owner="intel",
            item_id=str(advisory.get("id") or intel_action),
            action=intel_action,
            evidence_ref=str(
                review.get("path")
                or intel.get("intel_path")
                or intel.get("inventory_path")
                or "software-intel"
            ),
            expected_information_gain=str(intel.get("reason") or "resolve the software intelligence gap"),
            stop_condition="record applicability, a bounded blocker, or a final owner disposition",
        ), impact_hint=" ".join(
            str(advisory.get(key) or "")
            for key in ("severity", "applicability", "id")
            if advisory.get(key)
        )))

    projection = (
        state.get("surface_projection")
        if isinstance(state.get("surface_projection"), dict)
        else {}
    )
    if state.get("has_recon") and str(projection.get("status") or "") != "valid":
        other_items.append(_execution_frontier_item(_frontier_item(
            owner="surface-context",
            action=str(projection.get("refresh_command") or "prepare the target-owned Surface context"),
            evidence_ref=str(projection.get("path") or "surface_projection"),
            expected_information_gain="produce the bounded Surface candidates needed for evidence-led selection",
            stop_condition="publish a valid projection or record the source blocker",
        ), impact_hint="required discovery context"))

    surface_items: list[dict] = []
    surface_candidates = (
        state.get("surface_review_candidates")
        or state.get("recommended_targets")
        or []
    )
    if not surface_candidates and isinstance(ranked, dict):
        surface_candidates = _candidate_items_for_next_action(ranked, "hunt_p1")
    for candidate in surface_candidates[:2]:
        if not isinstance(candidate, dict):
            continue
        url = str(candidate.get("url") or "")
        item = _execution_frontier_item(_frontier_item(
            owner="surface",
            item_id=url,
            action=str(candidate.get("suggested") or f"review {url}"),
            evidence_ref=str(projection.get("path") or "surface_projection"),
            expected_information_gain=str(
                candidate.get("review_reason")
                or "determine whether this Surface candidate supports a concrete hypothesis"
            ),
            stop_condition="record evidence-backed Queue/Ledger disposition or park it without tested-clean",
        ), impact_hint=str(
            candidate.get("review_reason")
            or candidate.get("suggested")
            or candidate.get("vuln_class")
            or ""
        ))
        item.update({
            "evidence_status": "discovery",
            "closure_blocking": False,
            "runnable": not bool(candidate.get("tripped")),
        })
        surface_items.append(item)

    deduped: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for item in [*other_items, *surface_items]:
        key = (str(item.get("owner") or ""), str(item.get("id") or item.get("action") or ""))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    by_owner: dict[str, dict] = {}
    owner_order: list[str] = []
    for item in deduped:
        owner = str(item.get("owner") or "controller")
        if owner in by_owner:
            continue
        by_owner[owner] = item
        owner_order.append(owner)

    # Keep the important control-plane heads visible even when lower-priority
    # owners produced a long list of actionable items. Remaining owners keep
    # their first local head; no cross-owner score or static total is applied.
    important_owners = (
        "action_queue",
        "finding",
        "validation-runner",
        "intel",
        "surface",
    )
    ordered_owners = [
        owner for owner in important_owners if owner in by_owner
    ] + [owner for owner in owner_order if owner not in important_owners]
    return [by_owner[owner] for owner in ordered_owners]


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
    ledger_health = state.get("_ledger_health") if isinstance(state.get("_ledger_health"), dict) else {}
    checkpoint_health = state.get("_checkpoint_health") if isinstance(state.get("_checkpoint_health"), dict) else {}
    ledger_projection = state.get("_ledger_projection") if isinstance(state.get("_ledger_projection"), dict) else {}
    run_budget = (state.get("recon_artifacts") or {}).get("run_budget") or {}
    recon_budget_partial = bool(run_budget.get("partial"))
    ledger_status = str(ledger_health.get("status") or "missing").strip().lower()
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
            int(case_state.get("canonical_conflict_count", 0) or 0) > 0
            or int(case_state.get("pending_validation_backlog", 0) or 0) > 0
            or int(case_state.get("open_hypotheses", 0) or 0) > 0
            or str((case_state.get("top_next_action") or {}).get("next_action") or "none") != "none"
        )
    )
    # A legacy session endpoint preview is advisory. It only becomes an
    # executable continuation when current Surface state still owns the path.
    if (
        action in {"continue_last_focus", "resume_untested"}
        and state.get("resume_targets")
        and not _resume_targets_bound_to_surface(state)
    ):
        action = "handoff"
    actionable_frontier = _build_actionable_frontier(state, matrix, limit=5)
    if action in {"hunt_p1", "hunt_p2"} and not actionable_frontier:
        action = "handoff"
    round_progress = state.get("round_progress") or {}
    round_active = round_progress.get("status") == "active"
    if round_progress.get("invalid_evidence_lanes"):
        action = "repair_round_lane_evidence"
        verdict = "handoff"
        reasons.append("round_lane_evidence_invalid")
    elif round_active and round_progress.get("unfinished_lanes"):
        action = "resume_round_lane"
        verdict = "handoff"
        reasons.append("round_lane_unfinished")
    elif round_active and int(round_progress.get("claimed_count", 0) or 0) > 0:
        action = "complete_round_closure"
        verdict = "handoff"
        reasons.append("round_closure_pending")
    elif round_active:
        action = "resume_round_lane"
        verdict = "handoff"
        reasons.append("round_lane_unclaimed")
    elif action in _TERMINAL_CLOSURE_ACTIONS:
        verdict = "blocked"
        reasons.append(action)
    elif case_state_pending:
        verdict = "handoff"
        reasons.append(
            "case_state_canonical_conflict"
            if int(case_state.get("canonical_conflict_count", 0) or 0) > 0
            else "case_state_work_pending"
        )
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
        elif (authz_reason := _authz_context_reason(case_state, matrix)):
            verdict = "handoff"
            reasons.append(authz_reason)
        elif ledger_projection.get("identity_v2_follow_up_actions"):
            verdict = "handoff"
            reasons.append("identity_v2_follow_up_pending")
        elif ledger_projection.get("open_candidates_v2"):
            verdict = "handoff"
            reasons.append("identity_v2_candidate_pending")
        elif int((ledger_projection.get("identity_v2_diagnostics") or {}).get("incomplete_count", 0) or 0) > 0:
            verdict = "handoff"
            reasons.append("identity_v2_incomplete")
        else:
            verdict = "finish"

    # Keep owner blockers that were masked by an earlier branch as secondary
    # diagnostics.  Primary selection below applies the stable precedence.
    for extra_reason in (
        _explicit_partial_reason(state),
        (
            "case_state_canonical_conflict"
            if case_state_pending and int(case_state.get("canonical_conflict_count", 0) or 0) > 0
            else "case_state_work_pending"
            if case_state_pending
            else ""
        ),
        "surface_projection_pending" if surface_projection_pending else "",
    ):
        if extra_reason and extra_reason not in reasons:
            reasons.append(extra_reason)

    if verdict == "handoff" and not actionable_frontier:
        reason = str(reasons[0] if reasons else "")
        if reason in {"coverage_missing", "coverage_empty", "coverage_invalid"}:
            target = str(state.get("resolved_target") or state.get("target") or "")
            actionable_frontier = [_frontier_item(
                owner="coverage",
                action="Rebuild the coverage matrix and record the resulting gap disposition",
                evidence_ref=str(
                    state.get("_coverage_evidence_ref")
                    or f"evidence/{target_storage_key(target)}/coverage_matrix.json"
                ),
                expected_information_gain="restore a valid bounded coverage projection",
                stop_condition="record the rebuild as complete or blocked with its reason",
                priority=80,
            )]
        elif reason == "surface_projection_pending":
            projection = state.get("surface_projection") if isinstance(state.get("surface_projection"), dict) else {}
            actionable_frontier = [_frontier_item(
                owner="surface",
                action="Refresh the target-owned Surface projection",
                evidence_ref=str(projection.get("path") or "surface_projection"),
                expected_information_gain="restore the bounded Surface index used for review",
                stop_condition="publish a valid projection or record the source blocker",
                priority=60,
            )]

    if ledger_status in {"partial", "unreadable"}:
        ledger_reason = f"ledger_{ledger_status}"
        if ledger_reason not in reasons:
            reasons.insert(0, ledger_reason)
        if verdict == "finish":
            verdict = "handoff"
    checkpoint_status = str(checkpoint_health.get("status") or "")
    if checkpoint_status in {"invalid", "stale"}:
        checkpoint_reason = "checkpoint_stale" if checkpoint_status == "stale" else "checkpoint_invalid"
        if checkpoint_reason not in reasons:
            reasons.insert(0, checkpoint_reason)
        if verdict == "finish":
            verdict = "handoff"

    if verdict == "handoff":
        reason = str(reasons[0] if reasons else "")
        target = str(state.get("resolved_target") or state.get("target") or "")
        checkpoint_ref = f"state/{target_storage_key(target)}/checkpoint_latest.json"
        if reason in {
            "round_lane_evidence_invalid",
            "round_lane_unfinished",
            "round_closure_pending",
            "round_lane_unclaimed",
        }:
            round_ids = [
                *list(round_progress.get("invalid_evidence_lanes") or []),
                *list(round_progress.get("unfinished_lanes") or []),
            ]
            label = ", ".join(str(item) for item in round_ids[:3]) or str(
                (round_progress.get("latest_lane") or {}).get("id") or round_progress.get("round_id") or "active round"
            )
            actionable_frontier = [_frontier_item(
                owner="round-progress",
                item_id=label,
                action={
                    "round_lane_evidence_invalid": "Repair the invalid evidence for round lane {label}",
                    "round_lane_unfinished": "Resume the unfinished round lane {label}",
                    "round_closure_pending": "Complete the active round closure for {label}",
                    "round_lane_unclaimed": "Claim the next owner-selected lane for {label}",
                }[reason].format(label=label),
                evidence_ref=checkpoint_ref,
                expected_information_gain="reconcile round progress with the durable lane evidence and current owner state",
                stop_condition="record a valid lane terminal state or a bounded blocker, then recompute Closure",
                priority=85,
            ), *actionable_frontier]
        elif reason in {"checkpoint_stale", "checkpoint_invalid"}:
            actionable_frontier = [_frontier_item(
                owner="checkpoint",
                item_id=reason,
                action="Refresh or repair the target checkpoint witness before continuing",
                evidence_ref=checkpoint_ref,
                expected_information_gain="restore a trusted checkpoint binding for round and queue recovery",
                stop_condition="publish a valid witness or record the checkpoint read/queue mismatch",
                priority=85,
            ), *actionable_frontier]

    if verdict == "handoff" and not actionable_frontier:
        target = str(state.get("resolved_target") or state.get("target") or "")
        target_key = target_storage_key(target)
        reason = str(reasons[0] if reasons else "")
        item_id = action or reason
        if reason in {"ledger_partial", "ledger_unreadable"}:
            owner = "evidence-ledger"
            evidence_ref = f"memory/evidence/{target_key}/ledger.jsonl"
            action_text = "Repair or reconcile the target-owned Evidence Ledger before closure"
            expected_gain = "restore the evidence owner needed to evaluate canonical closure cells"
            stop_condition = "publish a readable ledger or record the bounded ledger blocker"
        elif reason in {"checkpoint_stale", "checkpoint_invalid"}:
            owner = "checkpoint"
            evidence_ref = checkpoint_ref
            action_text = "Refresh or repair the target checkpoint witness before continuing"
            expected_gain = "restore a trusted checkpoint binding for round and queue recovery"
            stop_condition = "publish a valid witness or record the checkpoint read/queue mismatch"
        elif reason == "recon_budget_partial":
            owner = "recon"
            recon = state.get("recon_artifacts") if isinstance(state.get("recon_artifacts"), dict) else {}
            evidence_ref = str(
                recon.get("recon_dir")
                or f"recon/{target_key}/recon_manifest.jsonl"
            )
            action_text = "Resume the bounded Recon budget from its existing target-owned artifacts"
            expected_gain = "cover the remaining bounded Recon inputs without discarding prior pages"
            stop_condition = "record the completed or blocked Recon budget outcome, then recompute Closure"
        elif reason == "runtime_phase_active":
            owner = "runtime"
            phase = "scan" if state.get("scan_in_progress") else "recon"
            evidence_ref = f"state/{target_key}/session.json"
            action_text = f"Wait for the active {phase} phase to release its target runtime lock"
            expected_gain = "obtain the owner-written phase completion state before selecting more work"
            stop_condition = "refresh after the matching lock releases; never start a duplicate phase"
        elif reason in {"actor_context_missing", "actor_context_incomplete", "case_state_work_pending"}:
            owner = "case_state"
            case_state = state.get("case_state") if isinstance(state.get("case_state"), dict) else {}
            evidence_ref = str(
                case_state.get("path")
                or f"state/{target_key}/case_state.json"
            )
            action_text = "Complete the Case State actor and session context required for coverage"
            expected_gain = "obtain the missing owner/peer actor and session context"
            stop_condition = "record context ready, blocked, or not-applicable with evidence"
        elif reason == "finding_work_pending":
            root_claim = state.get("root_finding_claim_next") if isinstance(state.get("root_finding_claim_next"), dict) else {}
            memory_candidate = state.get("memory_candidate_next") if isinstance(state.get("memory_candidate_next"), dict) else {}
            if root_claim:
                owner = "finding-claim"
                item_id = str(root_claim.get("id") or root_claim.get("claim_id") or reason)
                action_text = "Collect locatable evidence and reconcile the Finding claim through checkpoint"
                evidence_ref = str(
                    root_claim.get("source_file")
                    or root_claim.get("claim_source_file")
                    or f"findings/{target_key}/claim.json"
                )
                expected_gain = "determine whether the claim can enter the canonical Finding lifecycle"
                stop_condition = "record a canonical candidate or reject the unsupported claim"
            elif memory_candidate:
                owner = "target-memory"
                item_id = str(memory_candidate.get("id") or reason)
                action_text = str(
                    memory_candidate.get("action")
                    or "Collect evidence for the legacy target-memory candidate"
                )
                evidence_ref = str(
                    memory_candidate.get("evidence_ref")
                    or f"memory/evidence/{target_key}/ledger.jsonl"
                )
                expected_gain = "determine whether the candidate has replayable evidence"
                stop_condition = "reconcile through the canonical Finding owner or record evidence missing"
            else:
                owner = "finding"
                item_id = reason
                action_text = "Resolve the canonical Finding owner obligation"
                evidence_ref = f"findings/{target_key}/findings.json"
                expected_gain = "resolve the pending Finding lifecycle state"
                stop_condition = "record validated, candidate, dead-end, or blocked owner state"
        elif reason == "durable_work_pending":
            owner = "action_queue"
            evidence_ref = f"state/{target_key}/action_queue.json"
            action_text = "Resume substantive work from the durable Action Queue"
            expected_gain = "resolve the selected owner-backed Queue action"
            stop_condition = "record a terminal Queue result or bounded blocker"
        elif reason == "surface_work_pending":
            owner = "surface"
            projection = state.get("surface_projection") if isinstance(state.get("surface_projection"), dict) else {}
            evidence_ref = str(projection.get("path") or "surface_projection")
            action_text = "Review the currently bound target-owned Surface continuation"
            expected_gain = "turn the retained Surface lead into a concrete owner action or disposition"
            stop_condition = "record evidence-backed Queue/Ledger disposition or defer without tested-clean"
        else:
            owner = {
                "run_recon": "recon",
                "wait_recon": "recon",
                "wait_scan": "recon",
                "run_intel": "intel",
                "collect_web_intel": "intel",
                "test_advisory_applicability": "intel",
                "review_intel_group": "intel",
                "revalidate_finding_owner": "finding",
                "collect_candidate_evidence": "finding",
                "validate_finding": "finding",
                "report_finding": "finding",
                "complete_report_draft": "finding",
                "resume_action_queue": "action_queue",
                "resume_case_state": "case_state",
                "prepare_surface_context": "surface-context",
            }.get(action, "controller")
            action_text = describe_next_step({**state, "next_action": action})
            expected_gain = {
                "recon": "restore or extend target-owned recon evidence",
                "intel": "resolve the bounded software or advisory evidence gap",
                "finding": "resolve the canonical Finding evidence gate",
                "action_queue": "resolve the selected durable Queue action",
                "case_state": "resolve the selected Case State obligation",
                "surface-context": "produce the bounded Surface context needed for selection",
            }.get(owner, "resolve the selected control-plane action")
            stop_condition = "record the existing owner result or a bounded blocker, then recompute Closure"
            if owner == "recon":
                recon = state.get("recon_artifacts") if isinstance(state.get("recon_artifacts"), dict) else {}
                evidence_ref = str(
                    recon.get("recon_dir")
                    or f"recon/{target_key}/recon_manifest.jsonl"
                )
            elif owner == "intel":
                intel = state.get("intel_continuation") if isinstance(state.get("intel_continuation"), dict) else {}
                evidence_ref = str(
                    intel.get("intel_path")
                    or intel.get("inventory_path")
                    or f"findings/{target_key}/intel"
                )
            elif owner == "finding":
                findings = state.get("structured_findings") if isinstance(state.get("structured_findings"), dict) else {}
                finding = next(
                    (item for item in findings.values() if isinstance(item, dict) and item),
                    {},
                )
                evidence_ref = str(
                    finding.get("evidence_ref")
                    or finding.get("source_file")
                    or f"findings/{target_key}/findings.json"
                )
            elif owner == "action_queue":
                queue_next = state.get("action_queue_next") if isinstance(state.get("action_queue_next"), dict) else {}
                evidence_ref = str(
                    queue_next.get("evidence_ref")
                    or queue_next.get("evidence")
                    or f"state/{target_key}/action_queue.json"
                )
            elif owner == "case_state":
                case_state = state.get("case_state") if isinstance(state.get("case_state"), dict) else {}
                evidence_ref = str(
                    case_state.get("path")
                    or f"state/{target_key}/case_state.json"
                )
            elif owner == "surface-context":
                projection = state.get("surface_projection") if isinstance(state.get("surface_projection"), dict) else {}
                evidence_ref = str(projection.get("path") or "surface_projection")
            else:
                evidence_ref = checkpoint_ref
        actionable_frontier = [_frontier_item(
            owner=owner,
            item_id=item_id,
            action=action_text,
            evidence_ref=evidence_ref,
            expected_information_gain=expected_gain,
            stop_condition=stop_condition,
            priority=85,
        )]

    reasons, actionable_frontier, action = _finalize_closure_continuation(
        reasons,
        actionable_frontier,
        state,
        matrix,
        action,
    )

    result = {
        "verdict": verdict,
        "can_claim_exhausted": verdict == "finish",
        "round_budget_reached": bool(
            max_lanes_reached or round_progress.get("budget_reached")
        ),
        "recon_budget_partial": recon_budget_partial,
        "reasons": reasons[:3],
        "next_action": action,
        "rotation_hint": _rotation_hint(ledger_entries or []),
        "surface_review": surface_review,
        "actionable_frontier": actionable_frontier,
        "identity_v2": {
            "closed_cells": ledger_projection.get("closed_cells_v2") or [],
            "open_candidates": ledger_projection.get("open_candidates_v2") or [],
            "follow_up_actions": ledger_projection.get("identity_v2_follow_up_actions") or [],
            "diagnostics": ledger_projection.get("identity_v2_diagnostics") or {},
            "shadow": ledger_projection.get("identity_v2_shadow") or {},
        },
    }
    coverage_policy_skips = dict((matrix or {}).get("policy_skips") or {})
    if coverage_policy_skips:
        result["coverage_policy_skips"] = coverage_policy_skips
    if isinstance(case_state.get("authz_coverage"), dict):
        result["authz_coverage"] = case_state["authz_coverage"]
    if round_progress:
        result["round_progress"] = round_progress
    if ledger_health:
        result["ledger_health"] = ledger_health
    if checkpoint_health:
        result["checkpoint_health"] = checkpoint_health
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
    "actor_context_missing",
    "actor_context_incomplete",
    "next_action_pending",
    "surface_work_pending",
    "coverage_high_value_gaps",
    "case_state_canonical_conflict",
}


def _stagnation_text(value: object, *, limit: int = 300) -> str:
    """Keep semantic owner text bounded and stable across formatting changes."""
    return " ".join(str(value or "").split())[:limit]


def _stagnation_dimensions(value: object) -> list[str]:
    if isinstance(value, (list, tuple, set)):
        values = value
    elif value:
        values = [value]
    else:
        values = []
    return sorted({
        _stagnation_text(item, limit=120)
        for item in values
        if _stagnation_text(item, limit=120)
    })[:8]


def _stagnation_outcome(value: object) -> dict:
    """Project outcome meaning while excluding operation/timestamp noise."""
    if not isinstance(value, dict):
        text = _stagnation_text(value)
        return {"result": text} if text else {}
    projected = {}
    for key in (
        "status",
        "result",
        "decision",
        "observation_kind",
        "observed_difference",
        "evidence_ref",
        "summary_ref",
        "kill_condition_met",
    ):
        item = value.get(key)
        if isinstance(item, bool):
            projected[key] = item
        elif item not in (None, "", [], {}):
            text = _stagnation_text(item)
            if text:
                projected[key] = text
    return projected


def _stagnation_obligation(item: object, *, kind: str) -> dict:
    """Return the small semantic contract for one current owner obligation."""
    if not isinstance(item, dict):
        return {}
    metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
    outcome = item.get("last_outcome")
    if not isinstance(outcome, dict):
        outcome = metadata.get("last_outcome")
    dimensions = item.get("tested_dimensions")
    if dimensions in (None, "", []):
        dimensions = metadata.get("tested_dimensions")
    result = {
        "kind": kind,
        "id": _stagnation_text(item.get("id") or item.get("finding_id") or item.get("backlog_id"), limit=160),
        "status": {
            key: _stagnation_text(item.get(key) or metadata.get(key), limit=120)
            for key in ("status", "validation_status", "report_status", "evidence_status", "rubric_status")
            if _stagnation_text(item.get(key) or metadata.get(key), limit=120)
        },
        "action": _stagnation_text(
            item.get("action")
            or item.get("required_action")
            or item.get("next_action")
            or item.get("write_back")
            or metadata.get("action"),
        ),
        "next_question": _stagnation_text(
            item.get("next_question")
            or metadata.get("next_question")
            or item.get("why_now"),
        ),
        "evidence": {
            key: _stagnation_text(item.get(key) or metadata.get(key), limit=240)
            for key in ("evidence", "evidence_ref", "summary_ref")
            if _stagnation_text(item.get(key) or metadata.get(key), limit=240)
        },
        "missing_evidence": _stagnation_dimensions(
            item.get("missing_evidence") or metadata.get("missing_evidence")
        ),
        "tested_dimensions": _stagnation_dimensions(dimensions),
        "last_outcome": _stagnation_outcome(outcome),
        "stop_condition": _stagnation_text(
            item.get("stop_condition")
            or metadata.get("stop_condition")
            or item.get("kill_condition")
            or metadata.get("kill_condition"),
        ),
    }
    return {
        key: value
        for key, value in result.items()
        if value not in ("", {}, [])
    }


def _stagnation_owner_obligations(state: dict) -> dict:
    """Collect bounded Queue/Finding/Case semantics for no-progress detection."""
    obligations = {}
    queue = state.get("action_queue_next")
    if not isinstance(queue, dict) or not queue:
        action_queue = state.get("action_queue")
        queue = action_queue.get("next") if isinstance(action_queue, dict) else None
    if isinstance(queue, dict) and queue:
        obligations["queue"] = _stagnation_obligation(queue, kind="action_queue")

    findings = state.get("structured_findings")
    if isinstance(findings, dict):
        finding_items = []
        for key in (
            "next_owner_revalidation",
            "next_validation",
            "next_draft_completion",
            "next_report",
        ):
            item = findings.get(key)
            if isinstance(item, dict) and item:
                finding_items.append(_stagnation_obligation(item, kind=key))
        if finding_items:
            obligations["findings"] = finding_items[:4]

    case_state = state.get("case_state")
    if isinstance(case_state, dict) and case_state:
        case_next = case_state.get("top_next_action")
        case_summary = _stagnation_obligation(
            case_next if isinstance(case_next, dict) else case_state,
            kind="case_state",
        )
        counts = {}
        for key in (
            "canonical_conflict_count",
            "pending_validation_backlog",
            "open_hypotheses",
        ):
            raw = case_state.get(key)
            if raw in (None, ""):
                continue
            try:
                counts[key] = int(raw or 0)
            except (TypeError, ValueError):
                counts[key] = _stagnation_text(raw, limit=80)
        if counts:
            case_summary["counts"] = counts
        if case_summary:
            obligations["case_state"] = case_summary
    return obligations


def stagnation_fingerprint(state: dict, closure: dict) -> str:
    """Fingerprint only explicit prerequisite blockers; other handoffs never count."""
    projected = str(closure.get("stagnation_fingerprint") or "")
    if projected:
        return projected
    reasons = closure.get("reasons") or []
    reason = str(reasons[0] if reasons else "")
    if closure.get("verdict") != "handoff" or reason not in _STAGNANT_REASONS:
        return ""
    target = str(state.get("resolved_target") or state.get("target") or "")
    payload = {
        "target": target,
        "reason": reason,
        "next_action": str(closure.get("next_action") or ""),
    }
    if reason.startswith("browser_evidence_"):
        payload["browser"] = {
            key: (state.get("browser_evidence") or {}).get(key)
            for key in ("present", "ready", "status")
        }
    elif reason == "source_evidence_partial":
        payload["source"] = {
            key: (state.get("repo_source_summary") or {}).get(key)
            for key in ("status", "input_fingerprint")
        }
    elif reason == "intel_evidence_blocked":
        payload["intel"] = {
            "blocked": (state.get("intel_continuation") or {}).get("blocked") or [],
            "reason": (state.get("intel_continuation") or {}).get("reason") or "",
        }
    elif reason == "surface_projection_pending":
        payload["surface_projection"] = {
            key: (state.get("surface_projection") or {}).get(key)
            for key in ("status", "reason", "input_fingerprint")
        }
    elif reason == "json_evidence_partial":
        payload["json"] = {
            key: (state.get("json_inject") or {}).get(key)
            for key in ("status", "input_fingerprint")
        }
    elif reason == "sql_evidence_partial":
        payload["sql"] = {
            lane: {
                key: item.get(key)
                for key in ("status", "input_fingerprint")
            }
            for lane, item in (state.get("sql_matrix") or {}).items()
            if isinstance(item, dict)
        }
    elif reason == "js_evidence_partial":
        payload["js"] = {
            key: (state.get("js_intel") or {}).get(key)
            for key in ("status", "reason", "hypothesis_count")
        }
    elif reason.startswith("observation_"):
        inventory = state.get("observation_inventory") or {}
        by_kind = inventory.get("by_kind") if isinstance(inventory.get("by_kind"), dict) else {}
        payload["observations"] = {
            "status": inventory.get("status"),
            "high_value_untouched": {
                kind: int((by_kind.get(kind) or {}).get("present_untouched", 0) or 0)
                for kind in HIGH_VALUE_OBSERVATION_KINDS
            },
        }
    elif reason.startswith("actor_context_"):
        payload["authz_coverage"] = (state.get("case_state") or {}).get("authz_coverage") or {}
    elif reason == "coverage_high_value_gaps":
        payload["coverage"] = str(state.get("_stagnation_coverage") or "")
    elif reason == "case_state_canonical_conflict":
        case_state = state.get("case_state") or {}
        payload["case_state"] = {
            "canonical_conflict_count": int(case_state.get("canonical_conflict_count", 0) or 0),
            "canonical_conflicts": case_state.get("canonical_conflicts") or [],
        }
    elif reason == "next_action_pending":
        findings = state.get("structured_findings") or {}
        finding = next(
            (
                findings.get(key)
                for key in (
                    "next_owner_revalidation",
                    "next_validation",
                    "draft_completion_pending",
                    "validated_pending_report",
                )
                if isinstance(findings.get(key), dict)
            ),
            {},
        )
        payload["owner"] = {
            "queue_id": str((state.get("action_queue_next") or {}).get("id") or ""),
            "finding_id": str(finding.get("id") or ""),
            "case_action": str(
                ((state.get("case_state") or {}).get("top_next_action") or {}).get("next_action")
                or ""
            ),
        }
        payload["owner_semantics"] = _stagnation_owner_obligations(state)
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _stagnation_continuation(state: dict, closure: dict) -> dict:
    """Project bounded work that can continue after a repeated lane blocker."""
    authoritative = _loop_guard_authoritative_reason(state)
    if authoritative:
        return {
            "reason": str((closure.get("reasons") or [authoritative])[0]),
            "next_action": str(closure.get("next_action") or "handoff"),
            "rotation_target": {},
        }
    return {}


def _semantic_coverage_fingerprint(matrix: dict | None) -> str:
    """Hash only unresolved high-value coverage meaning."""
    if not isinstance(matrix, dict):
        return ""
    semantic = [
        {
            key: gap.get(key)
            for key in (
                "endpoint",
                "vuln_class",
                "observed_params",
                "relevance_score",
                "identity_v2",
            )
            if key in gap
        }
        for gap in _actionable_coverage_gaps(matrix)
        if isinstance(gap, dict)
    ]
    encoded = json.dumps(semantic, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


_SNAPSHOT_VOLATILE_KEYS = frozenset({
    "at",
    "created_at",
    "updated_at",
    "generated_at",
    "recorded_at",
    "started_at",
    "finished_at",
    "completed_at",
    "mtime_ns",
    "ctime_ns",
})


def _snapshot_normalize(value: object) -> object:
    """Remove owner timestamps before hashing a read-only snapshot."""
    if isinstance(value, dict):
        return {
            str(key): _snapshot_normalize(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
            if str(key) not in _SNAPSHOT_VOLATILE_KEYS
        }
    if isinstance(value, (list, tuple)):
        return [_snapshot_normalize(item) for item in value]
    if isinstance(value, set):
        normalized = [_snapshot_normalize(item) for item in value]
        return sorted(
            normalized,
            key=lambda item: json.dumps(item, ensure_ascii=True, sort_keys=True),
        )
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    return str(value)


_CLOSURE_STATE_KEYS = (
    "next_action",
    "has_recon",
    "surface_context_required",
    "recon_in_progress",
    "scan_in_progress",
    "recon_completed_no_live_hosts",
    "recon_artifacts",
    "case_state",
    "structured_findings",
    "root_finding_claim_next",
    "validation_runner_next",
    "action_queue_next",
    "target_goal_memory",
    "memory_candidate_next",
    "resume_targets",
    "surface_review_candidates",
    "recommended_targets",
    "surface_projection",
    "observation_inventory",
    "browser_evidence",
    "browser_required",
    "repo_source_available",
    "repo_source_artifacts",
    "repo_source_summary",
    "json_inject",
    "sql_matrix",
    "js_intel",
    "intel_continuation",
    "enrichment_hints",
    "surface_review_completion",
    "round_progress",
)


def _closure_state_snapshot(state: dict) -> dict:
    """Keep every state projection that can affect the Closure decision."""
    return {
        key: state.get(key)
        for key in _CLOSURE_STATE_KEYS
        if key in state
    }


def _closure_snapshot_components(
    target: str,
    state: dict,
    queue: dict,
    matrix: dict | None,
    ledger_projection: dict,
    ledger_health: dict,
    checkpoint_health: dict,
    witness: dict,
) -> dict:
    """Expose small, non-secret generation hints alongside the digest."""
    surface_projection = state.get("surface_projection")
    surface_projection = surface_projection if isinstance(surface_projection, dict) else {}
    checkpoint_queue = witness.get("action_queue") if isinstance(witness, dict) else {}
    checkpoint_queue = checkpoint_queue if isinstance(checkpoint_queue, dict) else {}
    closure_state = _closure_state_snapshot(state)
    state_encoded = json.dumps(
        _snapshot_normalize(closure_state),
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    )
    return {
        "target": canonical_target_value(target),
        "queue_fingerprint": queue_fingerprint(queue),
        "coverage_fingerprint": str((matrix or {}).get("source_fingerprint") or "")
        or _semantic_coverage_fingerprint(matrix),
        "surface_input_fingerprint": str(surface_projection.get("input_fingerprint") or ""),
        "checkpoint_queue_fingerprint": str(checkpoint_queue.get("fingerprint") or ""),
        "ledger_status": str(ledger_health.get("status") or "missing"),
        "closure_state_fingerprint": hashlib.sha256(state_encoded.encode("utf-8")).hexdigest(),
    }


def _closure_snapshot_digest(
    target: str,
    state: dict,
    queue: dict,
    matrix: dict | None,
    ledger_projection: dict,
    ledger_health: dict,
    checkpoint_health: dict,
    witness: dict,
) -> tuple[str, dict]:
    """Bind Closure to normalized Queue and owner projections."""
    components = _closure_snapshot_components(
        target,
        state,
        queue,
        matrix,
        ledger_projection,
        ledger_health,
        checkpoint_health,
        witness,
    )
    material = {
        "components": components,
        "queue": queue,
        "ledger": {
            "health": ledger_health,
            "projection": ledger_projection,
        },
        "coverage": matrix,
        "surface": state.get("surface_projection") or {},
        "checkpoint": {
            "health": checkpoint_health,
            "witness": witness,
        },
        "closure_state": _closure_state_snapshot(state),
        "target_memory": {
            "goal": state.get("target_goal_memory") or {},
            "resume": state.get("resume_summary") or {},
        },
    }
    encoded = json.dumps(
        _snapshot_normalize(material),
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest(), components


def load_closure_projection(
    repo_root: str,
    state: dict,
    *,
    max_lanes_reached: bool,
    apply_round_guard: bool = True,
    include_round_projection: bool = True,
    queue_snapshot: dict | None = None,
) -> dict:
    """Read existing closure inputs only for an explicit CLI request."""
    target = str(state.get("resolved_target") or state.get("target") or "")
    source_markers_before = _owner_source_markers(repo_root, target)
    matrix_path = Path(repo_root) / "evidence" / target_storage_key(target) / "coverage_matrix.json"
    matrix = load_matrix_projection(target, repo_root)
    if matrix is None and matrix_path.is_file():
        matrix = load_matrix(target, repo_root)
    queue = _queue_snapshot_for_target(repo_root, target, queue_snapshot)
    queue_generation = queue_fingerprint(queue)
    state_queue_generation = str(state.get("action_queue_fingerprint") or "").strip()
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
    ledger_diagnostic = load_entries_diagnostic(repo_root, target)
    ledger_entries = list(ledger_diagnostic.get("entries") or [])
    ledger_projection = build_current_cell_projection(ledger_entries)
    ledger_health = _ledger_health_projection(ledger_diagnostic)
    if ledger_health.get("status") in {"partial", "unreadable"}:
        ledger_projection["closed_cells"] = []
        ledger_projection["closed_cells_v2"] = []
        identity_diagnostics = dict(ledger_projection.get("identity_v2_diagnostics") or {})
        identity_diagnostics["suppressed_closed_count"] = int(identity_diagnostics.get("closed_count", 0) or 0)
        identity_diagnostics["closed_count"] = 0
        ledger_projection["identity_v2_diagnostics"] = identity_diagnostics
        ledger_projection["identity_v2_shadow"] = {
            "status": "unavailable",
            "reason": f"ledger_{ledger_health.get('status')}",
        }
    witness_path = Path(repo_root) / "state" / target_storage_key(target) / "checkpoint_latest.json"
    checkpoint_health = {"status": "valid"}
    try:
        witness = _load_checkpoint_witness(witness_path)
        round_progress = (
            _checkpoint_round_projection(
                witness,
                repo_root=repo_root,
                target=target,
            )
            if include_round_projection
            else {}
        )
        checkpoint_health = _checkpoint_queue_health(witness, queue)
    except ValueError as exc:
        witness = {}
        round_progress = {}
        checkpoint_health = {
            "status": "invalid",
            "path": str(witness_path),
            "reason": str(exc),
        }
    closure_state = {
        **state,
        "round_progress": round_progress,
        "_ledger_health": ledger_health,
        "_checkpoint_health": checkpoint_health,
        "_ledger_projection": ledger_projection,
        "enrichment_hints": enrichment_hints,
        "_coverage_evidence_ref": f"evidence/{target_storage_key(target)}/coverage_matrix.json",
        # Closure must never use a preloaded next-action pointer: it may have
        # been produced before the durable Queue changed. Both this pointer
        # and the active count below come from the same Queue snapshot.
        "action_queue_next": _load_substantive_action_queue_next(
            repo_root,
            target,
            queue_snapshot=queue,
        ),
        "action_queue_fingerprint": queue_generation,
        "active_action_queue_count": sum(
            isinstance(item, dict)
            and str(item.get("status") or "queued").strip().lower() in ACTIVE_STATUSES
            and _is_substantive_queue_action(item)
            for item in queue.get("actions") or []
        ),
        "surface_review_completion": _surface_review_completion(
            state,
            matrix,
            queue,
        ),
        "_stagnation_coverage": _semantic_coverage_fingerprint(matrix),
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
    snapshot_digest, snapshot_components = _closure_snapshot_digest(
        target,
        closure_state,
        queue,
        matrix,
        ledger_projection,
        ledger_health,
        checkpoint_health,
        witness,
    )
    closure["snapshot_digest"] = snapshot_digest
    closure["snapshot_components"] = snapshot_components
    source_markers_after = _owner_source_markers(repo_root, target)
    stale_sources = [
        name
        for name, marker in source_markers_before.items()
        if marker != source_markers_after.get(name)
    ]
    if state_queue_generation and state_queue_generation != queue_generation:
        stale_sources.append("action_queue")
    if stale_sources:
        closure.update({
            "verdict": "handoff",
            "can_claim_exhausted": False,
            "reasons": ["state_snapshot_stale"],
            "next_action": "refresh_state",
            "snapshot_stale": True,
            "snapshot_stale_sources": list(dict.fromkeys(stale_sources)),
        })
        reasons, actionable_frontier, action = _finalize_closure_continuation(
            ["state_snapshot_stale"],
            closure.get("actionable_frontier") or [],
            closure_state,
            matrix,
            "refresh_state",
        )
        closure.update({
            "reasons": reasons,
            "actionable_frontier": actionable_frontier,
            "next_action": action,
        })
    if (
        apply_round_guard
        and not closure.get("snapshot_stale")
        and fingerprint
        and fingerprint == str(guard.get("fingerprint") or "")
        and int(guard.get("consecutive", 0) or 0) >= 3
    ):
        continuation = _stagnation_continuation(closure_state, closure)
        if continuation:
            closure.update({
                "verdict": "handoff",
                "can_claim_exhausted": False,
                "reasons": [continuation["reason"]],
                "next_action": continuation["next_action"],
                "rotation_target": continuation["rotation_target"],
                "round_guard": guard,
            })
        else:
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
    diagnostic = load_entries_diagnostic(repo_root, target)
    projected_state = dict(state)
    projected_state["_ledger_health"] = _ledger_health_projection(diagnostic)
    return build_loop_guard_projection(projected_state, list(diagnostic.get("entries") or []))


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
                url=compact_url(item.get("url", "")),
                source=item.get("source_file", ""),
                missing=missing or "none",
            )
        )
    return lines


def _format_priority_frontier_lines(state: dict) -> list[str]:
    """Render the bounded controller handoff without dumping owner payloads."""
    mode = str(state.get("selection_mode") or "").strip()
    hard_gate = state.get("hard_gate") if isinstance(state.get("hard_gate"), dict) else {}
    lines = [f"Selection mode: {mode or 'fallback'}"]
    if hard_gate:
        action = str(hard_gate.get("action") or state.get("next_action") or "handoff").strip()
        reason = " ".join(str(hard_gate.get("reason") or "").split())[:240]
        lines.append(f"Hard gate: {action}" + (f" ({reason})" if reason else ""))
        return lines

    frontier = [item for item in (state.get("priority_frontier") or []) if isinstance(item, dict)]
    if not frontier:
        fallback = str(state.get("fallback_action") or state.get("next_action") or "handoff").strip()
        lines.append(f"Fallback action: {fallback}")
        return lines

    lines.append("Priority frontier (AI selects; array order is not priority):")
    for item in frontier[:3]:
        owner = str(item.get("owner") or "controller").strip()
        action = " ".join(str(item.get("action") or "").split())[:180]
        item_id = str(item.get("id") or "").strip()
        if item_id.startswith(("http://", "https://")):
            item_id = compact_url(item_id)
        suffix = f" [{item_id[:120]}]" if item_id else ""
        status = "runnable" if item.get("runnable", True) else "blocked"
        if not item.get("closure_blocking", True):
            status += "; non-blocking"
        lines.append(f"- {owner}: {action or 'owner action'}{suffix} ({status})")
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
        lines.extend(_format_priority_frontier_lines(state))
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
    runtime_derived = state.get("runtime_derived") or {}
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
        lines.extend(_format_priority_frontier_lines(state))
        runtime_workflow = str(
            runtime_state.get("last_executed_workflow")
            or runtime_state.get("current_stage")
            or ""
        ).strip()
        runtime_mode = str(runtime_state.get("mode", "") or "").strip()
        if runtime_workflow:
            lines.append(f"Last Workflow: {runtime_workflow}" + (f" (mode: {runtime_mode})" if runtime_mode else ""))
        if runtime_derived:
            lines.append(f"Current Derived Status: {runtime_derived.get('status', 'unknown')} ({runtime_derived.get('reason', '')})")
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
    lines.extend(_format_priority_frontier_lines(state))
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
    if runtime_derived:
        lines.append(f"Current Derived Status: {runtime_derived.get('status', 'unknown')} ({runtime_derived.get('reason', '')})")
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
    surface_continuation = (surface.get("surface_index") or {}).get("continuation") or {}
    if surface_continuation.get("available") and surface_continuation.get("command"):
        lines.append(f"Surface continuation: {surface_continuation['command']}")

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
                f"{idx}. {compact_url(item['url'])} — {item['suggested']} (score hint {item['score']}){reason}{suffix}"
            )
    deferred_candidates = state.get("deferred_surface_candidates") or []
    if deferred_candidates:
        lines.append("")
        lines.append("Deferred scanner signals (raw evidence retained; AI reactivation conditions):")
        for item in deferred_candidates[:3]:
            lines.append(
                f"- {compact_url(item.get('url', ''))}: {item.get('reason', '')}; "
                f"reactivate when {item.get('reactivate_when', 'new evidence exists')}"
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
            "ledger_health",
            "checkpoint_health",
            "recon_budget_partial",
            "authz_coverage",
            "stagnation_fingerprint",
            "snapshot_digest",
            "snapshot_components",
            "snapshot_stale",
            "snapshot_stale_sources",
            "error",
            "round_progress",
            "coverage_policy_skips",
            "round_budget_reached",
            "surface_review",
            "actionable_frontier",
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
        ("surface_projection", ("status", "reason", "input_fingerprint", "refresh_command", "continuation")),
        ("case_state", ("status", "actors", "sessions", "authz_coverage", "objects", "canonical_conflict_count", "canonical_conflicts", "open_hypotheses", "pending_validation_backlog", "top_next_action")),
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
        queue_snapshot = load_queue(BASE_DIR, args.target) if args.closure else None
        state_kwargs = {
            "memory_dir": args.memory_dir or None,
            "bounded": args.bounded,
        }
        if queue_snapshot is not None:
            state_kwargs["queue_snapshot"] = queue_snapshot
        state = build_autopilot_state(
            BASE_DIR,
            args.target,
            **state_kwargs,
        )
        if args.closure:
            state["closure"] = load_closure_projection(
                BASE_DIR,
                state,
                max_lanes_reached=args.max_lanes_reached,
                queue_snapshot=queue_snapshot,
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
