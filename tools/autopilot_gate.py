#!/usr/bin/env python3
"""Autopilot governance projections.

Only explicit owner continuations and mechanical hard gates are projected;
observations remain input for the AI session, not machine-authored work.
"""

from __future__ import annotations

try:
    from tools.autopilot_state_read import _scanner_lane_accounting
    from tools.coverage_matrix import (
        coverage_gaps_with_observed_evidence,
        high_value_gaps_from_matrix,
    )
    from tools.target_paths import compact_url, target_storage_key
except ImportError:  # pragma: no cover - direct tools/ execution
    from autopilot_state_read import _scanner_lane_accounting  # type: ignore
    from coverage_matrix import (  # type: ignore
        coverage_gaps_with_observed_evidence,
        high_value_gaps_from_matrix,
    )
    from target_paths import compact_url, target_storage_key  # type: ignore

_CLOSURE_REASON_OWNERS = {
    "state_snapshot_stale": {"controller"},
    "durable_work_pending": {"action_queue"},
    "finding_work_pending": {"finding", "finding-claim", "target-memory"},
    "case_state_work_pending": {"case_state"},
    "actor_context_required": {"case_state"},
    "recon_phase_partial": {"recon"},
    "recon_phase_review_required": {"checkpoint"},
    "scanner_lane_review_required": {"checkpoint"},
    "coverage_missing": {"coverage"},
    "coverage_empty": {"coverage"},
    "coverage_invalid": {"coverage"},
    "coverage_stale": {"coverage"},
    "coverage_ledger_evidence_missing": {"evidence-ledger"},
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
    "round_lane_evidence_invalid": {"round-progress"},
    "round_lane_unfinished": {"round-progress"},
    "round_closure_pending": {"round-progress"},
    "round_lane_unclaimed": {"round-progress"},
    "store_partial": {"evidence-ledger"},
    "store_unreadable": {"evidence-ledger"},
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
        input_total, selected, remaining, accounting_valid = _scanner_lane_accounting(item)
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
    return item


def _build_actionable_frontier(
    state: dict,
    matrix: dict | None,
    *,
    limit: int | None = None,
) -> list[dict]:
    """Expose only explicit owner claims and durable continuations.

    Raw observations, coverage gaps, surface candidates, and browser readiness
    remain views/residuals; they never become controller-authored work here.
    """
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
                or f"state/{target_storage_key(target)}/metadata.sqlite3"
            ),
            expected_information_gain=str(queue_next.get("next_question") or "resolve the queued evidence question"),
            stop_condition=str(queue_next.get("stop_condition") or "record a terminal owner result or a bounded blocker"),
        ))

    findings = state.get("structured_findings") if isinstance(state.get("structured_findings"), dict) else {}
    for key, label in (("next_owner_revalidation", "revalidate finding owner"), ("next_validation", "validate finding"), ("next_draft_completion", "complete finding report draft"), ("next_report", "report validated finding")):
        finding = findings.get(key) if isinstance(findings.get(key), dict) else {}
        if not finding:
            continue
        finding_id = str(finding.get("id") or "")
        frontier.append(_frontier_item(
            owner="finding",
            item_id=finding_id,
            action=str(finding.get("required_action") or finding.get("action") or label),
            evidence_ref=str(finding.get("evidence_ref") or finding.get("source_file") or f"state/{target_storage_key(target)}/metadata.sqlite3#{finding_id}"),
            expected_information_gain=str(finding.get("next_question") or finding.get("missing_evidence") or "resolve the finding evidence gate"),
            stop_condition=str(finding.get("downgrade_rule") or "record validated, candidate, dead-end, or blocked owner state"),
        ))
        break

    for owner, item, default_action, default_gain in (
        ("validation-runner", state.get("validation_runner_next"), "review validation candidate", "apply the canonical evidence gate"),
        ("finding-claim", state.get("root_finding_claim_next"), "register the Finding claim", "determine whether the claim enters the canonical lifecycle"),
    ):
        if not isinstance(item, dict) or not item:
            continue
        item_id = str(item.get("id") or item.get("claim_id") or item.get("lane") or "")
        frontier.append(_frontier_item(
            owner=owner,
            item_id=item_id,
            action=str(item.get("next_action") or item.get("required_action") or default_action),
            evidence_ref=str(item.get("summary_path") or item.get("source_file") or item.get("evidence_ref") or ""),
            expected_information_gain=str(item.get("classifier") or item.get("title") or default_gain),
            stop_condition="record the owner result or a bounded downgrade",
        ))

    continuation = (state.get("recon_artifacts") or {}).get("cidr_continuation") if isinstance((state.get("recon_artifacts") or {}).get("cidr_continuation"), dict) else {}
    if continuation.get("status") in {"pending", "invalid"}:
        status = str(continuation.get("status"))
        frontier.append(_frontier_item(
            owner="recon",
            item_id=f"cidr:{continuation.get('next_offset', status)}",
            action=("Repair the invalid CIDR continuation before resuming Recon" if status == "invalid" else f"continue bounded CIDR recon from offset {continuation.get('next_offset', 0)}"),
            evidence_ref=str(continuation.get("path") or f"recon/{target_storage_key(target)}/live/cidr_continuation.json"),
            expected_information_gain=("repair the invalid CIDR cursor" if status == "invalid" else "cover the remaining target-owned CIDR hosts"),
            stop_condition="advance or complete the durable cursor, or record its explicit blocker",
        ))

    deduped: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for item in frontier:
        key = (str(item.get("owner") or ""), str(item.get("id") or item.get("action") or ""))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped if limit is None else deduped[:limit]


def _execution_frontier_item(item: dict, *, impact_hint: str = "") -> dict:
    """Remove controller ranking while retaining owner facts for AI arbitration."""
    projected = dict(item)
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
        )
    if reason in {
        "round_lane_evidence_invalid",
        "round_lane_unfinished",
        "round_closure_pending",
        "round_lane_unclaimed",
    }:
        round_progress = state.get("round_progress") if isinstance(state.get("round_progress"), dict) else {}
        round_ids = [
            *list(round_progress.get("invalid_evidence_lanes") or []),
            *list(round_progress.get("unfinished_lanes") or []),
        ]
        label = ", ".join(str(item) for item in round_ids[:3]) or str(
            (round_progress.get("latest_lane") or {}).get("id")
            or round_progress.get("round_id")
            or "active round"
        )
        return _frontier_item(
            owner="round-progress",
            item_id=label,
            action={
                "round_lane_evidence_invalid": "Repair the invalid evidence for round lane {label}",
                "round_lane_unfinished": "Resume the unfinished round lane {label}",
                "round_closure_pending": "Complete the active round closure for {label}",
                "round_lane_unclaimed": "Claim the next owner-selected lane for {label}",
            }[reason].format(label=label),
            evidence_ref=f"state/{target_key}/checkpoint_latest.json",
            expected_information_gain="reconcile round progress with the durable lane evidence and current owner state",
            stop_condition="record a valid lane terminal state or a bounded blocker, then recompute Closure",
        )
    if reason in {"durable_work_pending"}:
        return _frontier_item(
            owner="action_queue",
            item_id=str((state.get("action_queue_next") or {}).get("id") or reason),
            action="Resume substantive work from the durable Action Queue",
            evidence_ref=f"state/{target_key}/metadata.sqlite3",
            expected_information_gain="resolve the selected owner-backed Queue action",
            stop_condition="record a terminal Queue result or bounded blocker",
        )
    if reason in {"case_state_work_pending", "actor_context_required"}:
        case_state = state.get("case_state") if isinstance(state.get("case_state"), dict) else {}
        return _frontier_item(
            owner="case_state",
            item_id=reason,
            action=(
                "Import distinct owner/peer actor sessions with tools/target_case_state.py "
                "add-actor/add-session, then resume the affected role-based lane"
            ),
            evidence_ref=str(case_state.get("path") or f"state/{target_key}/metadata.sqlite3"),
            expected_information_gain="obtain the missing owner/peer actor and session context",
            stop_condition=(
                "record two distinct usable sessions, or an evidence-backed blocked/not-applicable "
                "disposition; never synthesize credentials"
            ),
        )
    if reason in {"checkpoint_stale", "checkpoint_invalid"}:
        return _frontier_item(
            owner="checkpoint",
            item_id=reason,
            action="Refresh or repair the target checkpoint witness before continuing",
            evidence_ref=f"state/{target_key}/checkpoint_latest.json",
            expected_information_gain="restore a trusted checkpoint binding for round and queue recovery",
            stop_condition="publish a valid witness or record the checkpoint read/queue mismatch",
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
        )
    if reason == "finding_work_pending":
        return _frontier_item(
            owner="finding",
            item_id="finding-work",
            action="Resolve the canonical Finding owner obligation",
            evidence_ref=f"state/{target_key}/metadata.sqlite3",
            expected_information_gain="resolve the pending Finding lifecycle state",
            stop_condition="record validated, candidate, dead-end, or blocked owner state",
        )
    evidence_specs = {
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
            "evidence-ledger", "Inspect the target Store and repair unavailable evidence before closure",
            f"state/{target_key}/metadata.sqlite3",
        ),
        "ledger_unreadable": (
            "evidence-ledger", "Inspect the target Store and repair unavailable evidence before closure",
            f"state/{target_key}/metadata.sqlite3",
        ),
        "store_partial": (
            "evidence-ledger", "Inspect the target Store and repair unavailable evidence before closure",
            f"state/{target_key}/metadata.sqlite3",
        ),
        "store_unreadable": (
            "evidence-ledger", "Inspect the target Store and repair unavailable evidence before closure",
            f"state/{target_key}/metadata.sqlite3",
        ),
        "coverage_ledger_evidence_missing": (
            "evidence-ledger", "Register the observed evidence supporting each projected Coverage cell",
            f"state/{target_key}/metadata.sqlite3",
        ),
        "identity_v2_follow_up_pending": (
            "evidence-ledger", "Resolve the pending identity evidence follow-up",
            f"state/{target_key}/metadata.sqlite3",
        ),
        "identity_v2_candidate_pending": (
            "evidence-ledger", "Resolve the pending identity evidence candidate",
            f"state/{target_key}/metadata.sqlite3",
        ),
        "identity_v2_incomplete": (
            "evidence-ledger", "Complete the identity evidence required for closure",
            f"state/{target_key}/metadata.sqlite3",
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
            )
    if reason in {"coverage_missing", "coverage_empty", "coverage_invalid"}:
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
        )
    return None


def _build_owner_continuations(
    state: dict,
    ranked: dict | None = None,
    *,
    actionable_frontier: list[dict] | None = None,
) -> list[dict]:
    """Compatibility view of explicit owner continuations; never ranks observations."""
    items = actionable_frontier if actionable_frontier is not None else _build_actionable_frontier(state, None, limit=None)
    return [_execution_frontier_item(item) for item in items]


def _format_owner_continuations_lines(state: dict) -> list[str]:
    """Render the bounded controller handoff without dumping owner payloads."""
    mode = str(state.get("selection_mode") or "").strip()
    hard_gate = state.get("hard_gate") if isinstance(state.get("hard_gate"), dict) else {}
    lines = [f"Selection mode: {mode or 'fallback'}"]
    if hard_gate:
        action = str(hard_gate.get("action") or state.get("next_action") or "handoff").strip()
        reason = " ".join(str(hard_gate.get("reason") or "").split())[:240]
        lines.append(f"Hard gate: {action}" + (f" ({reason})" if reason else ""))
        return lines

    frontier = [item for item in (state.get("owner_continuations") or []) if isinstance(item, dict)]
    if not frontier:
        fallback = str(state.get("fallback_action") or state.get("next_action") or "handoff").strip()
        lines.append(f"Fallback action: {fallback}")
        return lines

    lines.append("Owner continuations (AI selects; array order is not priority):")
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
        root_claim = state.get("root_finding_claim_next") or {}
        candidate = followup or root_claim
        if followup:
            return (
                "review candidate {id} on {url}; inspect its recorded evidence and decide the next action."
            ).format(id=candidate.get("id", "-"), url=compact_url(candidate.get("url", "")))
        if root_claim:
            return (
                "inspect root JSON finding claim {id} at {source}; capture locatable raw "
                "request/response and explicitly register the claim through its owner. "
                "Missing fields: {missing}. Do not call it validated or report-ready "
                "from the claim alone. Never invent an endpoint from the target root."
            ).format(
                id=root_claim.get("id", "-"),
                source=root_claim.get("source_file", ""),
                missing=", ".join(str(item) for item in (root_claim.get("incomplete_fields") or []))
                or "none",
            )
        return "Inspect the saved Finding claim and its evidence before choosing work."
    if action == "validate_finding":
        followup = (state.get("structured_findings") or {}).get("next_validation") or {}
        if followup:
            return f"validate structured finding {followup.get('id')} on {compact_url(followup.get('url', ''))}."
        return "Inspect the saved Finding and select an explicit assessment."
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
        return "Select an active Store action to resume."
    if action == "resume_case_state":
        return (
            "resume the Case State context obligation: resolve the open hypothesis into bounded "
            "actor/object/replay evidence, or record its explicit blocker; actions themselves come "
            "from the one action source."
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
    return high_value_gaps_from_matrix(matrix)

def _coverage_gaps_with_observed_evidence(gaps: list[dict], matrix: dict | None = None) -> list[dict]:
    return coverage_gaps_with_observed_evidence(gaps, matrix)
