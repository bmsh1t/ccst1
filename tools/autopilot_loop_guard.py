#!/usr/bin/env python3
"""Autopilot Loop Guard: rotation/stagnation projections (extracted module).

从 autopilot_state.py 纯搬动（零逻辑变更，09-11-simple-efficient-refactor 批次 7）：
Loop Guard 的独立职责——rotation hint/target、loop guard 投影、stagnation
指纹与义务投影。autopilot_state 保留 re-export，外部 import 零破坏。
"""

from __future__ import annotations


import hashlib
import json
import re

try:
    from tools.closure_resolver import canonical_endpoint_path
    from tools.evidence_ledger import load_entries_diagnostic
    from tools.target_paths import url_belongs_to_target
except ImportError:  # pragma: no cover - direct tools/ execution
    from closure_resolver import canonical_endpoint_path  # type: ignore
    from evidence_ledger import load_entries_diagnostic  # type: ignore
    from target_paths import url_belongs_to_target  # type: ignore

HIGH_VALUE_OBSERVATION_KINDS = frozenset({"exposure", "infra"})
_ROTATION_OUTCOMES = {"tested_clean", "dead_end"}
_LOOP_GUARD_ROTATABLE_ACTIONS = {
    "handoff",
    "continue_last_focus",
    "resume_untested",
    "hunt_p1",
    "hunt_p2",
    "guard_safe_pivot",
}
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
    "next_action_pending",
    "surface_work_pending",
    "coverage_high_value_gaps",
    "coverage_ledger_evidence_missing",
    "case_state_canonical_conflict",
    "actor_context_required",
}


_UUID_SEGMENT_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_VARIABLE_PATH_SEGMENT_RE = re.compile(r"^(?:\d+|[0-9a-f]{12,})$", re.IGNORECASE)

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
    elif reason == "coverage_high_value_gaps":
        payload["coverage"] = str(state.get("_stagnation_coverage") or "")
    elif reason == "coverage_ledger_evidence_missing":
        evidence = closure.get("coverage_terminal_evidence")
        missing = evidence.get("missing") if isinstance(evidence, dict) else []
        payload["coverage_ledger"] = [
            {
                "endpoint": str(item.get("endpoint") or ""),
                "vuln_class": str(item.get("vuln_class") or ""),
                "matrix_status": str(item.get("matrix_status") or ""),
            }
            for item in missing
            if isinstance(item, dict)
        ][:20]
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

def _load_loop_guard_projection(repo_root: str, state: dict) -> dict:
    """Read the ledger only for an explicit per-iteration loop check."""
    target = str(state.get("resolved_target") or state.get("target") or "")
    diagnostic = load_entries_diagnostic(repo_root, target)
    projected_state = dict(state)
    projected_state["_ledger_health"] = _ledger_health_projection(diagnostic)
    return build_loop_guard_projection(projected_state, list(diagnostic.get("entries") or []))

def _loop_control_projection(state: dict) -> dict:
    """Return the bounded post-lane control state with the loop decision."""
    def text(value: object, limit: int) -> str:
        return " ".join(str(value or "").split())[:limit]

    hard_gate = state.get("hard_gate") if isinstance(state.get("hard_gate"), dict) else {}
    frontier = []
    for item in state.get("priority_frontier") or []:
        if not isinstance(item, dict):
            continue
        frontier.append({
            "owner": text(item.get("owner"), 80),
            "id": text(item.get("id"), 300),
            "action": text(item.get("action"), 500),
            "evidence_ref": text(item.get("evidence_ref"), 300),
            "expected_information_gain": text(item.get("expected_information_gain"), 300),
            "stop_condition": text(item.get("stop_condition"), 300),
            "lane": text(item.get("lane"), 120),
            "impact_hint": text(item.get("impact_hint"), 300),
            "evidence_status": text(item.get("evidence_status"), 80),
            "closure_blocking": bool(item.get("closure_blocking", True)),
            "continuity": bool(item.get("continuity", False)),
            "runnable": bool(item.get("runnable", True)),
        })
    return {
        "next_action": text(state.get("next_action") or "handoff", 120),
        "fallback_action": text(
            state.get("fallback_action") or state.get("next_action") or "handoff", 120
        ),
        "selection_mode": text(state.get("selection_mode"), 80),
        "hard_gate": {
            "action": text(hard_gate.get("action"), 120),
            "reason": text(hard_gate.get("reason"), 300),
        } if hard_gate else {},
        "priority_frontier": frontier,
    }

def _format_loop_guard_line(state: dict) -> str:
    guard = state.get("loop_guard") or {}
    if not guard:
        return ""
    return "Loop guard: verdict={verdict} reason={reason} next={next_action}".format(
        verdict=guard.get("verdict", "continue"),
        reason=guard.get("reason", "-"),
        next_action=guard.get("next_action", "handoff"),
    )


def _endpoint_family(endpoint: object) -> str:
    """Collapse common object-id path segments for the advisory rotation check."""
    path = canonical_endpoint_path(str(endpoint or ""))
    return "/".join(
        ":id" if _UUID_SEGMENT_RE.fullmatch(segment) or _VARIABLE_PATH_SEGMENT_RE.fullmatch(segment) else segment
        for segment in path.split("/")
    ) or "/"

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
