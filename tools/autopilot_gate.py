#!/usr/bin/env python3
"""Autopilot frontier/gate projections (extracted module).

从 autopilot_state.py 纯搬动（零逻辑变更，09-11-simple-efficient-refactor 批次 7）：
priority frontier 构建、actionable frontier、hard gate 投影与 closure reason
frontier。autopilot_state 保留 re-export。
"""

from __future__ import annotations

import json
import re

try:
    from tools.autopilot_loop_guard import HIGH_VALUE_OBSERVATION_KINDS
    from tools.coverage_matrix import (
        coverage_gaps_with_observed_evidence,
        high_value_gaps_from_matrix,
    )
    from tools.target_paths import compact_url, target_storage_key
except ImportError:  # pragma: no cover - direct tools/ execution
    from autopilot_loop_guard import HIGH_VALUE_OBSERVATION_KINDS  # type: ignore
    from coverage_matrix import (  # type: ignore
        coverage_gaps_with_observed_evidence,
        high_value_gaps_from_matrix,
    )
    from target_paths import compact_url, target_storage_key  # type: ignore

_CLOSURE_REASON_OWNERS = {
    "state_snapshot_stale": {"controller"},
    "durable_work_pending": {"action_queue"},
    "finding_work_pending": {"finding", "finding-claim", "target-memory"},
    "case_state_canonical_conflict": {"case_state"},
    "case_state_work_pending": {"case_state"},
    "actor_context_required": {"case_state"},
    "surface_projection_pending": {"surface", "surface-context"},
    "surface_work_pending": {"surface"},
    "recon_phase_partial": {"recon"},
    "recon_phase_review_required": {"checkpoint"},
    "scanner_lane_review_required": {"checkpoint"},
    "coverage_missing": {"coverage"},
    "coverage_empty": {"coverage"},
    "coverage_invalid": {"coverage"},
    "coverage_stale": {"coverage"},
    "coverage_high_value_gaps": {"coverage"},
    "coverage_ledger_evidence_missing": {"evidence-ledger"},
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
    "global_review_required": {"checkpoint"},
    "global_review_stale": {"checkpoint"},
    "global_review_invalid": {"checkpoint"},
    "global_review_form_insufficient": {"checkpoint"},
    "cidr_continuation_pending": {"recon"},
    "cidr_continuation_invalid": {"recon"},
}


def describe_next_step(state: dict) -> str:
    """Return a single-line bounded next-step instruction for controllers."""
    return " ".join(_describe_next_step(state).split())[:500]

def _candidate_items_for_next_action(ranked: dict, next_action: str) -> list[dict]:
    if next_action == "hunt_p2":
        return ranked.get("p2", []) or []
    return ranked.get("review_pool", []) or ranked.get("p1", []) or []

def _recon_phase_residuals(
    state: dict,
    *,
    closure_blocking: bool | None = None,
) -> list[dict]:
    """Return bounded Recon residuals without hiding advisory samples."""
    phase_gates = (state.get("recon_artifacts") or {}).get("phase_gates") or {}
    latest = phase_gates.get("latest") if isinstance(phase_gates, dict) else {}
    residuals = []
    for phase, gate in (latest.items() if isinstance(latest, dict) else ()):
        if not isinstance(gate, dict):
            continue
        bounded = gate.get("bounded")
        status = str(gate.get("status") or "").strip().lower()
        if not isinstance(bounded, dict):
            if status == "complete":
                continue
            bounded = {}
        accounting_valid = True
        try:
            values = [bounded.get(key) for key in ("input_total", "selected", "remaining")]
            if any(isinstance(value, bool) for value in values):
                raise ValueError
            input_total, selected, remaining = (int(value) for value in values)
            accounting_valid = (
                input_total >= 0
                and selected >= 0
                and remaining >= 0
                and selected <= input_total
                and remaining <= input_total
                and input_total == selected + remaining
            )
        except (TypeError, ValueError):
            input_total = selected = 0
            try:
                remaining = max(0, int(bounded.get("remaining", 0) or 0))
            except (TypeError, ValueError):
                remaining = 0
            accounting_valid = False
        # A gate without bounded metadata still carries a trustworthy default:
        # build_phase_gate defaults closure_blocking to remaining>0, and a
        # skipped/blocked phase with no sampling budget is advisory, not a
        # Closure blocker. Only an invalid bounded dict (wrong types, torn
        # accounting) forces blocking so the anomaly reaches AI review.
        if accounting_valid:
            blocking = bool(bounded.get("closure_blocking"))
        elif bounded:
            blocking = bool(bounded.get("closure_blocking", True))
        else:
            blocking = remaining > 0
        residual = status != "complete" or not accounting_valid or remaining > 0
        if not residual or (closure_blocking is not None and blocking != closure_blocking):
            continue
        evidence_refs = gate.get("evidence_refs") if isinstance(gate.get("evidence_refs"), list) else []
        residuals.append({
            "phase": str(phase),
            "remaining": remaining,
            "continuation": " ".join(str(bounded.get("continuation") or "").split()),
            "closure_blocking": blocking,
            "evidence_ref": str(
                gate.get("artifact")
                or (evidence_refs[0] if evidence_refs else "")
            ),
            "review_token": f"recon:{phase}:remaining={remaining}",
            "gate": gate,
            "bounded": {
                **bounded,
                "input_total": input_total,
                "selected": selected,
                "remaining": remaining,
            },
            "accounting_valid": accounting_valid,
        })
    return sorted(residuals, key=lambda item: item["phase"])

def _blocking_recon_phase_gate(state: dict) -> tuple[str, dict, dict]:
    """Return the first owner-declared resumable Recon residual."""
    residuals = _recon_phase_residuals(state, closure_blocking=True)
    if residuals:
        item = residuals[0]
        return item["phase"], item["gate"], item["bounded"]
    return "", {}, {}

def _scanner_lane_residuals(state: dict) -> list[dict]:
    """Return scanner inputs that were sampled, skipped, or only classified."""
    summary = state.get("scanner_summary") if isinstance(state.get("scanner_summary"), dict) else {}
    path = str(summary.get("path") or "")
    summary_status = str(summary.get("status") or "").strip().lower()
    residuals = []
    for name, item in (summary.get("lanes") or {}).items():
        if not isinstance(item, dict):
            continue
        status = str(item.get("status") or "unknown").strip().lower()
        accounting_valid = item.get("accounting_valid", True)
        try:
            values = [item.get(key) for key in ("input_total", "selected", "remaining")]
            if any(isinstance(value, bool) for value in values):
                raise ValueError
            input_total, selected, remaining = (int(value) for value in values)
            accounting_valid = bool(accounting_valid) and (
                input_total >= 0
                and selected >= 0
                and remaining >= 0
                and selected <= input_total
                and remaining <= input_total
                and input_total == selected + remaining
            )
        except (TypeError, ValueError):
            input_total = selected = 0
            try:
                remaining = max(0, int(item.get("remaining", 0) or 0))
            except (TypeError, ValueError):
                remaining = 0
            accounting_valid = False
        terminal = status in {"complete", "completed", "ok", "success"}
        if status == "sampled" and remaining == 0 and accounting_valid:
            terminal = True
        if status in {"candidate_only", "skipped"} and input_total == 0 and accounting_valid:
            terminal = True
        if accounting_valid is not True or remaining > 0 or not terminal:
            lane = str(item.get("lane") or name)
            residuals.append({
                "lane": lane,
                "remaining": remaining,
                "execution_kind": str(item.get("execution_kind") or "unknown"),
                "status": str(item.get("status") or "unknown"),
                "continuation": str(item.get("continuation") or ""),
                "closure_blocking": bool(item.get("closure_blocking")),
                "evidence_ref": path,
                "review_token": f"scanner:{lane}:remaining={remaining}",
                "accounting_valid": accounting_valid,
            })
    if summary and summary_status not in {"", "missing", "valid", "complete", "ok"} and not residuals:
        residuals.append({
            "lane": "scanner_summary",
            "remaining": 0,
            "execution_kind": "unknown",
            "status": summary_status or "unknown",
            "continuation": "repair the scanner summary accounting",
            "closure_blocking": True,
            "evidence_ref": path,
            "review_token": f"scanner:summary:status={summary_status or 'unknown'}",
            "accounting_valid": False,
        })
    return sorted(residuals, key=lambda item: item["lane"])

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
    if reason in {
        "global_review_required",
        "global_review_stale",
        "global_review_invalid",
        "global_review_form_insufficient",
    }:
        return _frontier_item(
            owner="checkpoint",
            item_id=reason,
            action="Perform the target-wide cross-source review and record its owner-backed witness",
            evidence_ref=f"state/{target_key}/checkpoint_latest.json",
            expected_information_gain=(
                "reconcile the completed target Surface, Coverage, Ledger, Finding, and residual unknowns"
            ),
            stop_condition="record complete/follow_up review with current evidence or a bounded blocker",
            priority=75,
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
    if reason in {"case_state_work_pending", "case_state_canonical_conflict", "actor_context_required"}:
        case_state = state.get("case_state") if isinstance(state.get("case_state"), dict) else {}
        return _frontier_item(
            owner="case_state",
            item_id="canonical-conflict" if reason == "case_state_canonical_conflict" else reason,
            action=(
                "Import distinct owner/peer actor sessions with tools/target_case_state.py "
                "add-actor/add-session, then resume the affected role-based lane"
            ),
            evidence_ref=str(case_state.get("path") or f"state/{target_key}/case_state.json"),
            expected_information_gain="obtain the missing owner/peer actor and session context",
            stop_condition=(
                "record two distinct usable sessions, or an evidence-backed blocked/not-applicable "
                "disposition; never synthesize credentials"
            ),
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
    if reason == "recon_phase_partial":
        phase, gate, bounded = _blocking_recon_phase_gate(state)
        if not phase:
            return None
        continuation = " ".join(str(bounded.get("continuation") or "").split())
        evidence_refs = (
            gate.get("evidence_refs")
            if isinstance(gate.get("evidence_refs"), list)
            else []
        )
        return _frontier_item(
            owner="recon",
            item_id=phase,
            action=(
                f"Resume bounded Recon phase {phase}: {continuation}"
                if continuation
                else f"Resume bounded Recon phase {phase} from its preserved input"
            ),
            evidence_ref=str(
                gate.get("artifact")
                or (evidence_refs[0] if evidence_refs else "")
                or f"recon/{target_key}/recon_manifest.jsonl"
            ),
            expected_information_gain=(
                f"cover or disposition the remaining {bounded['remaining']} inputs for {phase}"
            ),
            stop_condition=(
                f"record {phase} with remaining=0 or an explicit owner-backed disposition, "
                "then recompute Closure"
            ),
            priority=85,
        )
    if reason == "recon_phase_review_required":
        residuals = _recon_phase_residuals(state, closure_blocking=False)
        if not residuals:
            return None
        item = residuals[0]
        return _frontier_item(
            owner="checkpoint",
            item_id=item["phase"],
            action=(
                "Review and explicitly disposition the bounded Recon residual "
                f"for {item['phase']}"
            ),
            evidence_ref=(
                item["evidence_ref"]
                or f"recon/{target_key}/recon_manifest.jsonl"
            ),
            expected_information_gain=(
                f"account for the remaining {item['remaining']} inputs without "
                "misstating target exhaustion"
            ),
            stop_condition=(
                f"record {item['review_token']} in the current global review or "
                "create an owner-backed follow-up Queue action"
            ),
            priority=84,
        )
    if reason == "scanner_lane_review_required":
        residuals = _scanner_lane_residuals(state)
        if not residuals:
            return None
        item = residuals[0]
        return _frontier_item(
            owner="checkpoint",
            item_id=item["lane"],
            action=f"Review and disposition the scanner residual for {item['lane']}",
            evidence_ref=(
                item["evidence_ref"]
                or f"findings/{target_key}/summary.json"
            ),
            expected_information_gain=(
                f"account for the remaining {item['remaining']} scanner inputs and "
                f"its {item['execution_kind']} evidence depth"
            ),
            stop_condition=(
                f"record {item['review_token']} in the current global review or "
                "create an owner-backed validation Queue action"
            ),
            priority=83,
        )
    if reason in {
        "runtime_phase_active",
        "recon_budget_partial",
        "cidr_continuation_pending",
        "cidr_continuation_invalid",
    }:
        owner = "runtime" if reason == "runtime_phase_active" else "recon"
        action = "wait_scan" if state.get("scan_in_progress") else "wait_recon"
        if reason in {
            "recon_budget_partial",
            "cidr_continuation_pending",
            "cidr_continuation_invalid",
        }:
            action = "run_recon"
        continuation = (state.get("recon_artifacts") or {}).get("cidr_continuation") or {}
        if reason == "cidr_continuation_invalid":
            action = "run_recon"
            expected_information_gain = "repair the invalid CIDR cursor and resume target-owned Recon coverage"
            stop_condition = "publish a valid cursor or record the bounded Recon blocker"
        elif reason == "cidr_continuation_pending":
            expected_information_gain = (
                f"cover the remaining {continuation.get('remaining_hosts', 'unknown')} CIDR hosts"
            )
            stop_condition = "advance or complete the durable cursor, or record its explicit blocker"
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
                if reason in {"cidr_continuation_pending", "cidr_continuation_invalid"}
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
        "coverage_ledger_evidence_missing": (
            "evidence-ledger", "Record a matching Evidence Ledger terminal for every projected Coverage cell",
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

def _actionable_coverage_gaps(matrix: dict) -> list[dict]:
    return _coverage_gaps_with_observed_evidence(_coverage_gaps(matrix), matrix)


def _coverage_gaps(matrix: dict) -> list[dict]:
    if matrix.get("_coverage_projection"):
        return [item for item in matrix.get("_coverage_gaps") or [] if isinstance(item, dict)]
    return high_value_gaps_from_matrix(matrix)

def _coverage_gaps_with_observed_evidence(gaps: list[dict], matrix: dict | None = None) -> list[dict]:
    return coverage_gaps_with_observed_evidence(gaps, matrix)
