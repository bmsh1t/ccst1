#!/usr/bin/env python3
"""自动生成 Claude CLI 目标 checkpoint 和目标记忆写回建议。

默认输出建议，并写入可派生 coverage、小型 runtime-v2 checkpoint witness，且通过
`action_queue` owner 幂等同步可执行的 next-action queue。只有传入
`--apply-target-memory` 时，才会把 lead / next / dead-end / handoff 追加写入目标
记忆层。知识库、Skills、Rules 永远只给建议，不在这里自动修改。
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import sys
import tempfile
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

BASE_DIR = Path(__file__).resolve().parents[1]
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

try:
    from tools.autopilot_args import MAX_LANES
    from tools.checkpoint_witness import (
        is_canonical_coverage_lane_evidence_ref,
        load_checkpoint_witness as _load_checkpoint_witness,
        new_round_lane as _round_lane,
        validate_round_progress as _round_progress,
    )
    from tools.action_queue import (
        ACTIVE_STATUSES as ACTION_QUEUE_ACTIVE_STATUSES,
        FINAL_STATUSES as ACTION_QUEUE_FINAL_STATUSES,
        _action_identities as action_queue_action_identities,
        _candidate_dedupe_key as action_queue_candidate_dedupe_key,
        _checkpoint_item_to_action as action_queue_checkpoint_item_to_action,
        _dedupe_key as action_queue_dedupe_key,
        _knowledge_signal_identity as action_queue_knowledge_signal_identity,
        _target_owned_nonempty_evidence_ref as action_queue_target_owned_nonempty_evidence_ref,
        _target_owned_evidence_ref as action_queue_target_owned_evidence_ref,
        ingest_checkpoint as ingest_action_queue_checkpoint,
        load_queue as load_action_queue,
        queue_mutation_lock,
        queue_fingerprint as action_queue_fingerprint,
        select_next_action as action_queue_select_next_action,
    )
    from tools.autopilot_state import build_autopilot_state, load_closure_projection, stagnation_fingerprint
    from tools.context_pack import build_context_pack
    from tools.coverage_matrix import _route_template, actionable_coverage_gaps, class_relevance, high_risk_lane_summary, high_value_gaps_from_matrix, load_matrix, load_matrix_projection, matrix_is_fresh, normalize_vuln_class, rebuild_matrix, save_matrix, save_matrix_projection
    from tools.evidence_rubric import evaluate_candidate_evidence, first_missing_action
    from tools.evidence_ledger import ACTOR_MATRIX_VULN_CLASSES, build_summary as build_evidence_summary, record_command as evidence_record_command
    from tools.case_state_seed import build_case_state_seed
    from tools.closure_resolver import ClosureResolver, canonical_endpoint_identity, canonical_endpoint_path, extract_endpoint_path
    from tools.finding_index import list_root_finding_claims, reconcile_root_finding_claims
    from tools.structured_findings import format_validation_runner_candidate_lines
    from tools.target_case_state import summary as build_case_state_summary
    from tools.target_memory import (
        load_target_memory_file,
        new_target_memory,
        target_memory_mutation_lock,
        write_handoff_file,
        write_json as write_target_memory_json,
    )
    from tools.target_paths import canonical_target_value, target_storage_key, url_belongs_to_target
    from tools.experience_schema import make_entry_id
except ImportError:  # pragma: no cover - direct tools/ execution
    from autopilot_args import MAX_LANES  # type: ignore
    from checkpoint_witness import (  # type: ignore
        is_canonical_coverage_lane_evidence_ref,
        load_checkpoint_witness as _load_checkpoint_witness,
        new_round_lane as _round_lane,
        validate_round_progress as _round_progress,
    )
    from action_queue import (  # type: ignore
        ACTIVE_STATUSES as ACTION_QUEUE_ACTIVE_STATUSES,
        FINAL_STATUSES as ACTION_QUEUE_FINAL_STATUSES,
        _action_identities as action_queue_action_identities,
        _candidate_dedupe_key as action_queue_candidate_dedupe_key,
        _checkpoint_item_to_action as action_queue_checkpoint_item_to_action,
        _dedupe_key as action_queue_dedupe_key,
        _knowledge_signal_identity as action_queue_knowledge_signal_identity,
        _target_owned_nonempty_evidence_ref as action_queue_target_owned_nonempty_evidence_ref,
        _target_owned_evidence_ref as action_queue_target_owned_evidence_ref,
        ingest_checkpoint as ingest_action_queue_checkpoint,
        load_queue as load_action_queue,
        queue_mutation_lock,
        queue_fingerprint as action_queue_fingerprint,
        select_next_action as action_queue_select_next_action,
    )
    from autopilot_state import build_autopilot_state, load_closure_projection, stagnation_fingerprint  # type: ignore
    from context_pack import build_context_pack  # type: ignore
    from coverage_matrix import _route_template, actionable_coverage_gaps, class_relevance, high_risk_lane_summary, high_value_gaps_from_matrix, load_matrix, load_matrix_projection, matrix_is_fresh, normalize_vuln_class, rebuild_matrix, save_matrix, save_matrix_projection  # type: ignore
    from evidence_rubric import evaluate_candidate_evidence, first_missing_action  # type: ignore
    from evidence_ledger import ACTOR_MATRIX_VULN_CLASSES, build_summary as build_evidence_summary, record_command as evidence_record_command  # type: ignore
    from case_state_seed import build_case_state_seed  # type: ignore
    from closure_resolver import ClosureResolver, canonical_endpoint_identity, canonical_endpoint_path, extract_endpoint_path  # type: ignore
    from finding_index import list_root_finding_claims, reconcile_root_finding_claims  # type: ignore
    from structured_findings import format_validation_runner_candidate_lines  # type: ignore
    from target_case_state import summary as build_case_state_summary  # type: ignore
    from target_memory import (  # type: ignore
        load_target_memory_file,
        new_target_memory,
        target_memory_mutation_lock,
        write_handoff_file,
        write_json as write_target_memory_json,
    )
    from target_paths import canonical_target_value, target_storage_key, url_belongs_to_target  # type: ignore
    from experience_schema import make_entry_id  # type: ignore


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _write_json_atomic(path: Path, payload: dict) -> None:
    """Write a runtime witness without exposing a partial JSON document."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=str(path.parent),
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temp_path = Path(handle.name)
            handle.write(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        temp_path.replace(path)
    except Exception:
        if temp_path is not None:
            try:
                temp_path.unlink()
            except FileNotFoundError:
                pass
        raise


def _checkpoint_witness_path(repo_root: Path | str, target: str) -> Path:
    resolved = canonical_target_value(target)
    return Path(repo_root) / "state" / target_storage_key(resolved) / "checkpoint_latest.json"


_CHECKPOINT_LOCK_STATE = threading.local()


@contextmanager
def checkpoint_witness_lock(repo_root: Path | str, target: str):
    lock_path = _checkpoint_witness_path(repo_root, target).parent / "locks" / "checkpoint.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    locks = getattr(_CHECKPOINT_LOCK_STATE, "locks", None)
    if locks is None or getattr(_CHECKPOINT_LOCK_STATE, "pid", None) != os.getpid():
        locks = {}
        _CHECKPOINT_LOCK_STATE.locks = locks
        _CHECKPOINT_LOCK_STATE.pid = os.getpid()
    key = str(lock_path.resolve())
    existing = locks.get(key)
    if existing is not None:
        existing["depth"] += 1
        try:
            yield
        finally:
            existing["depth"] -= 1
        return
    with lock_path.open("a+", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        locks[key] = {"depth": 1}
        try:
            yield
        finally:
            locks.pop(key, None)
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _new_checkpoint_witness(target: str) -> dict:
    resolved = canonical_target_value(target)
    return {
        "schema_version": 1,
        "kind": "autopilot_checkpoint_witness",
        "generated_at": now_utc(),
        "target": resolved,
        "target_key": target_storage_key(resolved),
        "context_pack": {},
    }


def _new_round_progress(max_lanes: int) -> dict:
    if (
        isinstance(max_lanes, bool)
        or not isinstance(max_lanes, int)
        or not 1 <= max_lanes <= MAX_LANES
    ):
        raise ValueError(f"max_lanes must be an integer from 1 to {MAX_LANES}")
    return {
        "schema_version": 1,
        "round_id": f"round-{os.urandom(8).hex()}",
        "status": "active",
        "max_lanes": int(max_lanes),
        "claimed_lanes": [],
        "lanes": [],
        "claimed_count": 0,
        "remaining_lanes": int(max_lanes),
        "budget_reached": False,
        "started_at": now_utc(),
        "updated_at": now_utc(),
    }


def _round_lane_text(value: str, field: str, *, max_length: int) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"round lane {field} is required")
    if "\n" in text or "\r" in text:
        raise ValueError(f"round lane {field} must be one line")
    if len(text) > max_length:
        raise ValueError(f"round lane {field} exceeds {max_length} characters")
    return text


def _is_passive_round_lane(lane_id: str) -> bool:
    """Reject explicit idle/monitoring identities without blocking real verification."""
    normalized = lane_id.lower()
    return (
        normalized.startswith(("idle:", "monitor:", "verify:idle", "verify:no-change"))
        or "idle-no-change" in normalized
    )


def _invalid_completed_lane_evidence(
    repo_root: Path | str,
    target: str,
    lanes: list[dict],
) -> list[str]:
    invalid: list[str] = []
    for lane in lanes:
        if lane.get("status") != "completed":
            continue
        lane_id = str(lane.get("id") or "")
        evidence_ref = action_queue_target_owned_nonempty_evidence_ref(
            repo_root,
            target,
            lane.get("evidence_ref"),
        )
        if not evidence_ref or not is_canonical_coverage_lane_evidence_ref(
            lane_id,
            evidence_ref,
            target,
        ):
            invalid.append(lane_id)
    return invalid


def begin_round(repo_root: Path | str, target: str, *, max_lanes: int) -> dict:
    """Start a round or resume the active round after an interrupted invocation."""
    path = _checkpoint_witness_path(repo_root, target)
    with checkpoint_witness_lock(repo_root, target):
        payload = _load_checkpoint_witness(path) or _new_checkpoint_witness(target)
        progress = _round_progress(payload)
        invalid_evidence = _invalid_completed_lane_evidence(
            repo_root,
            target,
            progress.get("lanes") or [],
        )
        if invalid_evidence:
            raise ValueError(
                "cannot start or resume a round with invalid completed lane evidence: "
                + ", ".join(invalid_evidence)
            )
        if progress.get("status") == "active":
            status = "resumed"
        else:
            progress = _new_round_progress(max_lanes)
            payload["round_progress"] = progress
            status = "started"
        _write_json_atomic(path, payload)
        return {"status": status, "path": str(path), "round_progress": dict(progress)}


def record_round_lane(
    repo_root: Path | str,
    target: str,
    *,
    lane: str,
    max_lanes: int,
) -> dict:
    """Atomically claim one stable lane ID against the active round budget."""
    if (
        isinstance(max_lanes, bool)
        or not isinstance(max_lanes, int)
        or not 1 <= max_lanes <= MAX_LANES
    ):
        raise ValueError(f"max_lanes must be an integer from 1 to {MAX_LANES}")
    lane_id = _round_lane_text(" ".join(str(lane or "").split()), "id", max_length=200)
    path = _checkpoint_witness_path(repo_root, target)
    with checkpoint_witness_lock(repo_root, target):
        payload = _load_checkpoint_witness(path)
        if not payload:
            raise ValueError("round lane claim requires an active round; run --round-begin first")
        progress = _round_progress(payload)
        if progress.get("status") != "active":
            raise ValueError("round lane claim requires an active round; run --round-begin first")
        claimed = progress.get("claimed_lanes") if isinstance(progress.get("claimed_lanes"), list) else []
        lanes = progress["lanes"]
        if lane_id in claimed:
            lane_record = next(item for item in lanes if item.get("id") == lane_id)
            lane_status = str(lane_record.get("status") or "started")
            status = "already_claimed" if lane_status == "started" else f"already_{lane_status}"
            allowed = lane_status == "started"
        elif _is_passive_round_lane(lane_id):
            return {
                "status": "passive_lane_rejected",
                "allowed": False,
                "reason": "passive_lane_not_substantive",
                "path": str(path),
                "lane": {},
                "round_progress": dict(progress),
            }
        elif len(claimed) >= int(progress.get("max_lanes", max_lanes) or max_lanes):
            lane_record = {}
            status, allowed = "budget_exhausted", False
        else:
            claimed.append(lane_id)
            lane_record = _round_lane(lane_id)
            lanes.append(lane_record)
            status, allowed = "claimed", True
        limit = int(progress.get("max_lanes", max_lanes) or max_lanes)
        progress.update({
            "claimed_lanes": claimed,
            "claimed_count": len(claimed),
            "remaining_lanes": max(0, limit - len(claimed)),
            "budget_reached": len(claimed) >= limit,
            "updated_at": now_utc(),
        })
        _write_json_atomic(path, payload)
        return {
            "status": status,
            "allowed": allowed,
            "path": str(path),
            "lane": dict(lane_record),
            "round_progress": dict(progress),
        }


def record_round_lane_result(
    repo_root: Path | str,
    target: str,
    *,
    lane: str,
    status: str,
    decision: str,
    evidence_ref: str,
    next_action: str,
) -> dict:
    """Atomically finish one claimed lane with bounded recovery context."""
    lane_id = _round_lane_text(" ".join(str(lane or "").split()), "id", max_length=200)
    terminal_status = _round_lane_text(status, "status", max_length=20)
    if terminal_status not in {"completed", "blocked"}:
        raise ValueError("round lane status must be completed or blocked")
    terminal_decision = _round_lane_text(decision, "decision", max_length=500)
    terminal_evidence = _round_lane_text(evidence_ref, "evidence_ref", max_length=500)
    terminal_next = _round_lane_text(next_action, "next_action", max_length=1000)
    path = _checkpoint_witness_path(repo_root, target)
    with checkpoint_witness_lock(repo_root, target):
        payload = _load_checkpoint_witness(path)
        progress = _round_progress(payload)
        if progress.get("status") != "active":
            raise ValueError("round lane result requires an active round")
        lanes = progress["lanes"]
        lane_record = next((item for item in lanes if item.get("id") == lane_id), None)
        if lane_record is None:
            raise ValueError(f"round lane was not claimed: {lane_id}")
        if terminal_status == "completed":
            terminal_evidence = action_queue_target_owned_nonempty_evidence_ref(
                repo_root,
                target,
                terminal_evidence,
            )
            if not terminal_evidence:
                raise ValueError(
                    "completed round lane requires target-owned, non-empty evidence_ref"
                )
            if not is_canonical_coverage_lane_evidence_ref(
                lane_id,
                terminal_evidence,
                target,
            ):
                raise ValueError(
                    "completed coverage lane requires canonical Coverage Matrix, "
                    "Action Queue, or Evidence Ledger evidence_ref"
                )
        expected = {
            "status": terminal_status,
            "decision": terminal_decision,
            "evidence_ref": terminal_evidence,
            "next_action": terminal_next,
        }
        if lane_record.get("status") in {"completed", "blocked"}:
            if any(lane_record.get(field) != value for field, value in expected.items()):
                raise ValueError(f"terminal round lane cannot be rewritten: {lane_id}")
            result_status = "already_recorded"
        else:
            timestamp = now_utc()
            lane_record.update(expected)
            lane_record["finished_at"] = timestamp
            lane_record["updated_at"] = timestamp
            progress["updated_at"] = timestamp
            result_status = "recorded"
        _write_json_atomic(path, payload)
        return {
            "status": result_status,
            "path": str(path),
            "lane": dict(lane_record),
            "round_progress": dict(progress),
        }


def write_checkpoint_witness(
    repo_root: Path | str,
    target: str,
    checkpoint: dict,
) -> dict:
    """Persist the minimal runtime-v2 proof that checkpoint routing ran."""
    repo = Path(repo_root)
    resolved_target = canonical_target_value(target)
    context = checkpoint.get("context_pack") if isinstance(checkpoint.get("context_pack"), dict) else {}
    path = _checkpoint_witness_path(repo, resolved_target)
    payload = {
        "schema_version": 1,
        "kind": "autopilot_checkpoint_witness",
        "generated_at": now_utc(),
        "target": resolved_target,
        "target_key": target_storage_key(resolved_target),
        "context_pack": {
            "selected_skill": context.get("selected_skill", ""),
            "skill_route": context.get("skill_route", {}),
            "knowledge_cards": context.get("knowledge_cards", []),
            "knowledge_card_recall": [
                item
                for item in (context.get("knowledge_card_recall") or [])[:8]
                if isinstance(item, dict)
            ],
            "reference_hints": context.get("reference_hints", []),
            "required_checks": context.get("required_checks", []),
        },
    }
    queue_sync = checkpoint.get("action_queue_sync")
    if isinstance(queue_sync, dict):
        queue_path = str(queue_sync.get("path") or "").strip()
        if queue_path:
            candidate_path = Path(queue_path)
            try:
                queue_path = str(candidate_path.relative_to(repo))
            except ValueError:
                pass
        stats = queue_sync.get("stats") if isinstance(queue_sync.get("stats"), dict) else {}
        next_action = queue_sync.get("next") if isinstance(queue_sync.get("next"), dict) else {}
        expected_fingerprint = str(
            queue_sync.get("fingerprint")
            or (queue_sync.get("summary") or {}).get("fingerprint")
            or ""
        )
        if expected_fingerprint:
            current_queue = load_action_queue(repo, resolved_target)
            current_fingerprint = action_queue_fingerprint(current_queue)
            if current_fingerprint != expected_fingerprint:
                raise ValueError(
                    "checkpoint queue changed before witness write; refresh checkpoint"
                )
        payload["action_queue"] = {
            "synchronized": True,
            "path": queue_path,
            "added": int(stats.get("added", 0) or 0),
            "updated": int(stats.get("updated", 0) or 0),
            "next_id": str(next_action.get("id") or ""),
            "fingerprint": expected_fingerprint,
        }
    with checkpoint_witness_lock(repo, resolved_target):
        previous = _load_checkpoint_witness(path)
        progress = _round_progress(previous)
        if isinstance(previous.get("round_guard"), dict):
            payload["round_guard"] = previous["round_guard"]
        if progress:
            payload["round_progress"] = progress
        _write_json_atomic(path, payload)
    return {"path": str(path), "payload": payload}


def record_round_closure(repo_root: Path | str, target: str) -> dict:
    """Record one completed round only when closure is the same explicit prerequisite blocker."""
    repo = Path(repo_root)
    resolved_target = canonical_target_value(target)
    path = _checkpoint_witness_path(repo, resolved_target)
    with checkpoint_witness_lock(repo, resolved_target):
        # Lock order is checkpoint -> queue, matching round settle. This binds
        # the guard fingerprint to the queue snapshot used by Closure.
        with queue_mutation_lock(repo, resolved_target):
            queue_snapshot = load_action_queue(repo, resolved_target)
            state = build_autopilot_state(
                str(repo),
                resolved_target,
                bounded=True,
                queue_snapshot=queue_snapshot,
            )
            closure = load_closure_projection(
                str(repo),
                state,
                max_lanes_reached=False,
                apply_round_guard=False,
                include_round_projection=False,
                queue_snapshot=queue_snapshot,
            )
            fingerprint = stagnation_fingerprint(state, closure)
            payload = _load_checkpoint_witness(path)
            if not payload:
                raise ValueError(f"checkpoint witness missing or invalid: {path}")
            previous = payload.get("round_guard") if isinstance(payload.get("round_guard"), dict) else {}
            if fingerprint:
                consecutive = (
                    min(int(previous.get("consecutive", 0) or 0) + 1, 3)
                    if fingerprint == str(previous.get("fingerprint") or "")
                    else 1
                )
                payload["round_guard"] = {
                    "schema_version": 1,
                    "fingerprint": fingerprint,
                    "reason": str((closure.get("reasons") or [""])[0]),
                    "consecutive": consecutive,
                    "threshold": 3,
                    "recorded_at": now_utc(),
                }
            else:
                payload.pop("round_guard", None)
            progress = _round_progress(payload)
            invalid_evidence = _invalid_completed_lane_evidence(
                repo,
                resolved_target,
                progress.get("lanes") or [],
            )
            if invalid_evidence:
                raise ValueError(
                    "cannot close round with invalid completed lane evidence: "
                    + ", ".join(invalid_evidence)
                )
            unfinished = [
                str(item.get("id") or "")
                for item in (progress.get("lanes") or [])
                if item.get("status") == "started"
            ]
            if progress.get("status") == "active" and unfinished:
                raise ValueError(
                    "cannot close round with unfinished lanes: " + ", ".join(unfinished)
                )
            if progress.get("status") == "active":
                progress["status"] = "completed"
                progress["completed_at"] = now_utc()
                progress["updated_at"] = now_utc()
            _write_json_atomic(path, payload)
            return {
                "path": str(path),
                "round_guard": payload.get("round_guard") or {},
                "round_progress": dict(progress),
            }


def sync_checkpoint_action_queue(
    repo_root: Path | str,
    checkpoint: dict,
) -> dict:
    """Persist checkpoint proposals through the action-queue owner.

    ``build_checkpoint`` intentionally remains a reusable projection builder.
    The CLI boundary is the runtime handoff: once a real `/checkpoint` command
    has produced executable proposals, it must not rely on Claude remembering a
    second ``ingest-checkpoint`` command before the next session.
    """
    repo = Path(repo_root)
    target = str(checkpoint.get("target") or "").strip()
    if not target:
        raise ValueError("checkpoint action queue sync requires a target")
    result = ingest_action_queue_checkpoint(repo, target, checkpoint=checkpoint)
    if not isinstance(result, dict):
        raise ValueError("action queue owner returned an invalid sync result")
    checkpoint["action_queue_sync"] = result
    queue = load_action_queue(repo, target)
    queue_sync = checkpoint["action_queue_sync"]
    queue_summary = queue_sync.setdefault("summary", {})
    queue_summary["fingerprint"] = action_queue_fingerprint(queue)
    queue_sync["fingerprint"] = queue_summary["fingerprint"]
    queue_sync["next"] = action_queue_select_next_action(queue)
    checkpoint["knowledge_effect_trace"] = _project_knowledge_effect_trace(
        checkpoint,
        queue.get("actions", []),
    )
    witness = write_checkpoint_witness(repo, target, checkpoint)
    checkpoint["runtime_witness"] = {
        "schema_version": witness["payload"]["schema_version"],
        "path": str(Path(witness["path"]).relative_to(repo))
        if Path(witness["path"]).is_relative_to(repo)
        else str(witness["path"]),
    }
    return result


def _append_root_claim_queue_items(checkpoint: dict, claims: list[dict], target: str) -> None:
    """Keep every reconciled root claim recoverable through the durable queue."""
    queue = checkpoint.get("next_action_queue")
    if not isinstance(queue, list):
        return
    queued_ids = {
        str((item.get("metadata") or {}).get("finding_id") or "")
        for item in queue
        if isinstance(item, dict) and isinstance(item.get("metadata"), dict)
    }
    for claim in claims:
        finding_id = str(claim.get("id") or "").strip()
        if not finding_id or finding_id in queued_ids:
            continue
        source_file = str(claim.get("claim_source_file") or "root JSON claim").strip()
        location = str(claim.get("url") or source_file).strip()
        missing = ", ".join(str(item) for item in (claim.get("incomplete_fields") or []) if str(item).strip())
        queue.extend(
            _build_next_action_queue(
                [
                    "Candidate evidence gap for finding {id} on {location}: root JSON claim "
                    "from {source} needs locatable raw evidence{missing}. Then rerun /validate "
                    "with the canonical finding id.".format(
                        id=finding_id,
                        location=location,
                        source=source_file,
                        missing=f"; missing={missing}" if missing else "",
                    )
                ],
                target,
            )
        )
        queued_ids.add(finding_id)


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        value = str(item or "").strip()
        if not value or value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def _json_list(items: object) -> list[dict]:
    out: list[dict] = []
    if not isinstance(items, list):
        return out
    for item in items:
        if isinstance(item, str):
            try:
                item = json.loads(item)
            except json.JSONDecodeError:
                item = {"title": item}
        if isinstance(item, dict):
            out.append(item)
    return out


def _matrix_gaps(matrix: dict, min_weight: float = 3.0) -> list[dict]:
    return high_value_gaps_from_matrix(matrix, min_weight=min_weight)


def _actionable_coverage_gaps(coverage_gaps: list[dict]) -> list[dict]:
    """Return coverage gaps with concrete semantic fit for immediate action.

    The coverage matrix intentionally tracks broad high-impact cells, but the
    action queue should not be driven by generic "endpoint × vuln class" pairs
    with no path/parameter/source/browser signal.  Keep those gaps visible in
    coverage statistics; only promote semantically relevant cells into the
    next-action loop.
    """
    return actionable_coverage_gaps(coverage_gaps)


def _gap_observed_params(gap: dict) -> list[str]:
    params = gap.get("observed_params") or []
    if not isinstance(params, list):
        return []
    return [str(item).strip() for item in params if str(item or "").strip()]


def _is_path_only_authz_gap(gap: dict) -> bool:
    """Return true for Authz gaps backed only by path semantics.

    `/admin`-like paths are useful leads, but without an observed parameter,
    exact browser request, existing finding, or body evidence they are not yet a
    two-actor replay candidate. Treat them as baseline-classification work so
    checkpoint does not turn every admin-looking parent path into a noisy
    authorization task.
    """
    vuln_class = str(gap.get("vuln_class") or "").strip().lower()
    if vuln_class != "authz" or _gap_observed_params(gap):
        return False
    reason = str(gap.get("relevance_reason") or "").lower()
    try:
        relevance = int(gap.get("relevance_score", 0) or 0)
    except (TypeError, ValueError):
        relevance = 0
    return "admin/internal path" in reason or relevance <= 5


def _coverage_gap_validation_path(gap: dict) -> str:
    """Return the first evidence-producing step for a coverage gap.

    Coverage gaps are discovery tasks, but autopilot should immediately know
    what proof would promote the lead to a candidate.  Reuse the same evidence
    rubric that `/validate` uses so discovery and validation stay aligned.
    """
    vuln_class = str(gap.get("vuln_class") or "").strip()
    endpoint = str(
        gap.get("representative_endpoint") or gap.get("endpoint") or ""
    ).strip()
    reason = str(gap.get("relevance_reason") or "").strip()
    if not vuln_class:
        return ""
    if _is_path_only_authz_gap(gap):
        return (
            "First run an anonymous baseline GET or observed-method replay and "
            "classify status/body before any role-diff work. If 200 with "
            "body-backed sensitive/admin/config markers, run "
            "`python3 tools/validation_runner.py authz-public-exposure --target "
            "<target> --url <target>{endpoint}` and preserve raw evidence. If "
            "401/403, record the auth boundary. If 404/5xx/framework error or "
            "SPA fallback, record tested_clean/dead-end and pivot to "
            "browser-observed sibling endpoints."
        ).format(endpoint=endpoint)
    evaluation = evaluate_candidate_evidence({
        "type": vuln_class,
        "url": endpoint,
        "summary": reason,
    })
    return first_missing_action(evaluation)


def _matrix_summary(matrix: dict, gaps: list[dict]) -> dict:
    endpoints = matrix.get("endpoints") or []
    lane_summary = matrix.get("high_risk_lanes")
    if not isinstance(lane_summary, dict):
        lane_summary = high_risk_lane_summary(matrix)
    stored = matrix.get("summary") if isinstance(matrix.get("summary"), dict) else {}
    if stored and matrix.get("_coverage_projection"):
        return {
            "endpoints": len([item for item in endpoints if isinstance(item, dict)]),
            "total_cells": int(stored.get("total_cells", 0) or 0),
            "tested_clean": int(stored.get("tested_clean", 0) or 0),
            "tested_finding": int(stored.get("tested_finding", 0) or 0),
            "untested": int(stored.get("untested", 0) or 0),
            "n_a": int(stored.get("n_a", 0) or 0),
            "high_value_gaps_count": int(stored.get("high_value_gaps_count", len(gaps)) or 0),
            "actionable_high_value_gaps_count": len(_actionable_coverage_gaps(gaps)),
            "high_risk_lanes": lane_summary,
        }
    total_cells = 0
    counts = {
        "tested_clean": 0,
        "tested_finding": 0,
        "untested": 0,
        "n_a": 0,
    }
    for endpoint in endpoints:
        if not isinstance(endpoint, dict):
            continue
        cells = endpoint.get("cells") or {}
        if not isinstance(cells, dict):
            continue
        for cell in cells.values():
            if not isinstance(cell, dict):
                continue
            total_cells += 1
            status = str(cell.get("status") or "untested")
            if status in counts:
                counts[status] += 1
    return {
        "endpoints": len([item for item in endpoints if isinstance(item, dict)]),
        "total_cells": total_cells,
        **counts,
        "high_value_gaps_count": len(gaps),
        "actionable_high_value_gaps_count": len(_actionable_coverage_gaps(gaps)),
        "high_risk_lanes": lane_summary,
    }


def _surface_stats(state: dict) -> dict:
    surface = state.get("surface") or {}
    stats = surface.get("stats") or {}
    return {
        "p1": int(stats.get("p1", 0) or 0),
        "p2": int(stats.get("p2", 0) or 0),
        "review_pool": int(stats.get("review_pool", 0) or 0),
        "workflow_leads": len(_json_list(surface.get("workflow_leads"))),
        "observation_total": int(stats.get("observation_total", 0) or 0),
        "observation_untouched": int(stats.get("observation_untouched", 0) or 0),
        "observation_stale": int(stats.get("observation_stale", 0) or 0),
    }


def _structured_findings(state: dict) -> dict:
    payload = state.get("structured_findings") or {}
    return payload if isinstance(payload, dict) else {}


def _unsafe_leads(state: dict) -> list[dict]:
    surface = state.get("surface") or {}
    leads = _json_list(surface.get("workflow_leads"))
    return [
        item for item in leads
        if str(item.get("category") or "").lower() in {"unsafe-skipped", "action-gated"}
    ]


def _unsafe_skipped_proposals(state: dict) -> list[str]:
    proposals: list[str] = []
    for lead in _unsafe_leads(state)[:3]:
        artifact = str(lead.get("artifact") or "").strip()
        unsafe_id = str(lead.get("unsafe_skipped_id") or "").strip()
        evidence = str(lead.get("evidence") or "").strip()
        if not artifact and not unsafe_id:
            continue
        proposals.append(
            "Review action-gated scanner lane {unsafe_id}: {evidence}. "
            "Artifact={artifact}. Decide tested, blocked, dead-end, n/a, or candidate; "
            "record the selected outcome before continuing.".format(
                unsafe_id=unsafe_id or "-",
                evidence=evidence or "side-effect-capable scanner probe was skipped",
                artifact=artifact or "findings/<target>/manual_review/unsafe_skipped.txt",
            )
        )
    return proposals


SECONDARY_SWEEP_CATEGORIES = {"open-200-api-review", "public-metadata"}
SECONDARY_SWEEP_REQUIRED_LEDGER_CLASSES = {
    "open-200-api-review": {"Authz"},
    # Standard metadata review is about "is this ordinary public metadata or an
    # unusual chain pivot?", not a single vuln class.  Any explicit final ledger
    # row for the artifact endpoint is enough to stop repeating the same review.
    "public-metadata": set(),
}
URL_IN_ARTIFACT_RE = re.compile(r"https?://[^\s\]\"'<>]+")


def _secondary_sweep_leads(state: dict) -> list[dict]:
    surface = state.get("surface") or {}
    leads = _json_list(surface.get("workflow_leads"))
    return [
        item for item in leads
        if str(item.get("category") or "").lower() in SECONDARY_SWEEP_CATEGORIES
    ]


def _artifact_endpoints(repo_root: Path | None, target: str, artifact: str) -> list[str]:
    """Extract target-owned endpoint paths from a manual-review artifact.

    This is a state-closure helper, not an attack-surface classifier: the raw
    artifact stays on disk, and unreadable/unknown artifacts remain visible to
    Claude instead of being silently closed.
    """
    if repo_root is None:
        return []
    artifact_value = str(artifact or "").strip()
    if not artifact_value:
        return []
    path = Path(artifact_value)
    if not path.is_absolute():
        path = repo_root / path
    if not path.is_file():
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    endpoints: list[str] = []
    for match in URL_IN_ARTIFACT_RE.finditer(text):
        url = match.group(0).rstrip(".,;)]}'\"")
        if target and not url_belongs_to_target(url, target):
            continue
        endpoint = _normalise_endpoint_path(url)
        if endpoint:
            endpoints.append(endpoint)
    return _dedupe(endpoints)


def _secondary_sweep_closed_by_ledger(
    lead: dict,
    *,
    repo_root: Path | None,
    target: str,
    evidence_summary: dict,
) -> bool:
    category = str(lead.get("category") or "").strip().lower()
    artifact = str(lead.get("artifact") or "").strip()
    endpoints = _artifact_endpoints(repo_root, target, artifact)
    if not endpoints:
        return False

    required_classes = SECONDARY_SWEEP_REQUIRED_LEDGER_CLASSES.get(category, set())
    return ClosureResolver(evidence_summary).are_endpoints_closed(endpoints, required_classes)


def _secondary_sweep_proposals(
    state: dict,
    *,
    repo_root: Path | None = None,
    target: str = "",
    evidence_summary: dict | None = None,
) -> list[str]:
    proposals: list[str] = []
    for lead in _secondary_sweep_leads(state)[:3]:
        if _secondary_sweep_closed_by_ledger(
            lead,
            repo_root=repo_root,
            target=target,
            evidence_summary=evidence_summary or {},
        ):
            continue
        category = str(lead.get("category") or "").strip() or "secondary-sweep"
        title = str(lead.get("title") or "").strip()
        artifact = str(lead.get("artifact") or "").strip() or "findings/<target>/manual_review/<artifact>.txt"
        next_action = str(lead.get("next_action") or "").strip()
        rationale = str(lead.get("rationale") or "").strip()
        evidence = str(lead.get("evidence") or "").strip()
        if not title:
            continue
        proposals.append(
            "Secondary-sweep lead [{category}]: {title}. "
            "Artifact={artifact}. Why it matters: {rationale}. "
            "Next action: {next_action}. "
            "Stop condition: either promote to candidate/chain-intel with concrete evidence, "
            "or keep demoted with a written reason after reviewing the raw artifact.".format(
                category=category,
                title=title[:180],
                artifact=artifact,
                rationale=(rationale or evidence or category)[:220],
                next_action=(next_action or "inspect the raw manual_review artifact for chain, secret, or pivot signals")[:220],
            )
        )
    return proposals


def _evidence_focus_endpoints(state: dict, coverage_gaps: list[dict]) -> list[str]:
    surface = state.get("surface") or {}
    endpoints: list[str] = []
    for item in (surface.get("p1") or [])[:4] + (surface.get("p2") or [])[:2]:
        if isinstance(item, dict):
            endpoints.append(str(item.get("url") or item.get("path") or ""))
    for gap in coverage_gaps[:5]:
        endpoints.append(str(gap.get("endpoint") or ""))
    for item in (state.get("recommended_targets") or [])[:3]:
        if isinstance(item, dict):
            endpoints.append(str(item.get("url") or ""))
    return _dedupe(endpoints)[:8]


def _evidence_vuln_classes(
    coverage_gaps: list[dict],
    case_state: dict | None = None,
    queue_snapshot: dict | None = None,
) -> list[str]:
    """Collect only explicit canonical families from state owners."""
    classes: list[str] = []
    for gap in coverage_gaps[:8]:
        classes.append(str(gap.get("vuln_class") or ""))
    top = (case_state or {}).get("top_next_action") if isinstance(case_state, dict) else {}
    if isinstance(top, dict):
        metadata = top.get("metadata") if isinstance(top.get("metadata"), dict) else {}
        classes.extend([str(metadata.get("family") or ""), str(top.get("vuln_class") or "")])
    actions = (queue_snapshot or {}).get("actions") if isinstance(queue_snapshot, dict) else []
    for action in actions if isinstance(actions, list) else []:
        if (
            not isinstance(action, dict)
            or str(action.get("status") or "queued") not in ACTION_QUEUE_ACTIVE_STATUSES
        ):
            continue
        metadata = action.get("metadata") if isinstance(action.get("metadata"), dict) else {}
        classes.extend([
            str(metadata.get("family") or ""),
            str(metadata.get("vuln_class") or action.get("vuln_class") or ""),
        ])

    canonical_by_name = {item.casefold(): item for item in ACTOR_MATRIX_VULN_CLASSES}
    return _dedupe([
        canonical_by_name[item.strip().casefold()]
        for item in classes
        if item.strip().casefold() in canonical_by_name
    ])


def _actor_gaps(evidence_summary: dict) -> list[dict]:
    matrix = evidence_summary.get("actor_matrix") or {}
    return [
        item for item in matrix.get("gaps", [])
        if isinstance(item, dict) and item.get("status") in {"missing", "pending", "blocked"}
    ]


def _case_state_count(case_state: dict | None, key: str) -> int:
    if not isinstance(case_state, dict):
        return 0
    try:
        return int(case_state.get(key, 0) or 0)
    except (TypeError, ValueError):
        return 0


def _actor_gap_ready(gap: dict, case_state: dict | None) -> bool:
    """判断 actor-gap 是否具备进入可执行队列的运行态前置条件。

    anonymous baseline 不依赖目标运行态，可直接验证匿名访问行为。owner/peer/
    low_role/cross_tenant 这类角色差异验证必须先有 case state 中的 actor、
    session、object，否则 checkpoint 会生成“看起来可执行、实际缺上下文”的队列。
    """
    actor = str(gap.get("actor") or "").strip().lower()
    if actor == "anonymous":
        return True

    actors = _case_state_count(case_state, "actors")
    sessions = _case_state_count(case_state, "sessions")
    objects = _case_state_count(case_state, "objects")
    if actor == "owner":
        return actors >= 1 and sessions >= 1 and objects >= 1
    if actor in {"peer", "low_role", "cross_tenant"}:
        return actors >= 2 and sessions >= 2 and objects >= 1
    return actors >= 1 and sessions >= 1


def _actionable_actor_gaps(evidence_summary: dict, case_state: dict | None = None) -> list[dict]:
    return [
        gap for gap in _actor_gaps(evidence_summary)
        if _actor_gap_ready(gap, case_state)
    ]


def _actor_gap_enrichment_proposal(
    evidence_summary: dict,
    case_state: dict | None = None,
    ignored_endpoints: set[str] | None = None,
) -> str:
    ignored = ignored_endpoints or set()
    blocked = [
        gap for gap in _actor_gaps(evidence_summary)
        if not _actor_gap_ready(gap, case_state)
        and canonical_endpoint_identity(str(gap.get("endpoint") or "")) not in ignored
    ]
    if not blocked:
        return ""

    first = blocked[0]
    missing: list[str] = []
    actors = _case_state_count(case_state, "actors")
    sessions = _case_state_count(case_state, "sessions")
    objects = _case_state_count(case_state, "objects")
    actor = str(first.get("actor") or "").strip().lower()
    if actor in {"peer", "low_role", "cross_tenant"} and actors < 2:
        missing.append("second actor")
    elif actors < 1:
        missing.append("actor")
    if actor in {"peer", "low_role", "cross_tenant"} and sessions < 2:
        missing.append("peer/second session")
    elif sessions < 1:
        missing.append("session")
    if objects < 1:
        missing.append("business object")
    missing = _dedupe(missing) or ["case-state actor/session/object"]

    return (
        "Case-state enrichment lead: actor matrix has {count} role/object gap(s) "
        "that are not executable until runtime context is registered. Example: "
        "{endpoint} x {vuln} with {actor}/{scope}/{variant}. Missing evidence: "
        "{missing}. Next: register actor/session/object with tools/target_case_state.py "
        "or use tools/case_state_seed.py suggestions; keep anonymous baselines and "
        "ranked-surface discovery moving while enrichment is missing."
    ).format(
        count=len(blocked),
        endpoint=first.get("endpoint", ""),
        vuln=first.get("vuln_class", ""),
        actor=first.get("actor", ""),
        scope=first.get("object_scope", ""),
        variant=first.get("variant", ""),
        missing=", ".join(missing),
    )


def _case_state_summary(repo_root: Path | str, target: str) -> dict:
    """Load sanitized target case state summary for checkpoint routing.

    缺失文件仍表示尚未建立 case state；已存在但损坏的状态必须向上报错，
    避免 checkpoint 把丢失的 actor/session/object/backlog 误判为空状态。
    """
    payload = build_case_state_summary(repo_root, target)
    return payload if isinstance(payload, dict) else {}


def _case_state_top_next(case_state: dict) -> dict:
    top = case_state.get("top_next_action") or {}
    return top if isinstance(top, dict) else {}


def _list_clause(values: object) -> str:
    if not isinstance(values, list):
        return ""
    clean = [str(item or "").strip() for item in values if str(item or "").strip()]
    return ", ".join(clean)


def _case_state_proposal(case_state: dict) -> str:
    top = _case_state_top_next(case_state)
    action = str(top.get("next_action") or "").strip().lower()
    if not action or action == "none":
        return ""

    backlog_id = str(top.get("backlog_id") or "").strip()
    label = "Case-state next action"
    if action == "run_validation_runner":
        label = "Case-state validation backlog"
    elif action == "enrich_case_state":
        label = "Case-state enrichment backlog"
    elif action == "recover_hypothesis":
        label = "Case-state recovery backlog"
    elif action == "create_validation_backlog":
        label = "Case-state backlog creation"

    headline = f"{label} {backlog_id}".strip()
    if headline.endswith("backlog creation"):
        headline = headline.rstrip()

    parts = [headline + ":"]
    hypothesis = str(top.get("hypothesis") or "").strip()
    if hypothesis:
        parts.append(f"Hypothesis: {hypothesis}.")
    hypothesis_id = str(top.get("hypothesis_id") or "").strip()
    if hypothesis_id:
        parts.append(f"Hypothesis ID: {hypothesis_id}.")
    why_now = str(top.get("why_now") or "").strip()
    if why_now:
        parts.append(f"Why now: {why_now}.")

    runner = str(top.get("runner") or "").strip()
    owner_actor = str(top.get("owner_actor") or "").strip()
    peer_actor = str(top.get("peer_actor") or "").strip()
    object_ref = str(top.get("object_ref") or "").strip()
    endpoint = str(top.get("endpoint") or "").strip()
    if runner:
        parts.append(f"Runner: {runner}.")
    if owner_actor or peer_actor:
        parts.append(
            "Actors: owner={owner}, peer={peer}.".format(
                owner=owner_actor or "-",
                peer=peer_actor or "-",
            )
        )
    if object_ref:
        parts.append(f"Object ref: {object_ref}.")
    if endpoint:
        parts.append(f"Endpoint: {endpoint}.")

    replay_draft = str(top.get("redacted_command") or top.get("command") or "").strip()
    if action == "run_validation_runner" and replay_draft:
        parts.append(f"Exact replay draft: {replay_draft}.")

    required = _list_clause(top.get("required_evidence"))
    if required:
        parts.append(f"Required evidence: {required}.")
    missing = _list_clause(top.get("missing_evidence"))
    if missing:
        parts.append(f"Missing evidence: {missing}.")
    optional = _list_clause(top.get("optional_evidence_gaps"))
    if optional:
        parts.append(f"Optional evidence gaps: {optional}.")

    downgrade_rule = str(top.get("downgrade_rule") or "").strip()
    if downgrade_rule:
        parts.append(f"Downgrade rule: {downgrade_rule}.")
    stop_condition = str(top.get("stop_condition") or "").strip()
    if stop_condition:
        parts.append(f"Stop condition: {stop_condition}.")
    write_back = str(top.get("write_back") or "").strip()
    if write_back:
        parts.append(f"Write-back: {write_back}.")
    chain_extensions = _list_clause(top.get("chain_extensions_if_blocked"))
    if chain_extensions:
        parts.append(f"Chain extensions if blocked: {chain_extensions}.")
    recovery_next = str(top.get("recovery_next_action") or "").strip()
    if recovery_next:
        parts.append(f"Recovery next action: {recovery_next}.")
    return " ".join(parts).strip()


def _case_state_seed_summary(repo_root: Path | str, target: str) -> dict:
    """Load suggestion-only case_state seed opportunities."""
    try:
        payload = build_case_state_seed(repo_root, target, limit=3)
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def _case_state_seed_proposal(seed: dict) -> str:
    if str(seed.get("status") or "") != "suggestions":
        return ""
    raw_objects = seed.get("suggested_objects") if isinstance(seed.get("suggested_objects"), list) else []
    raw_backlog = seed.get("suggested_backlog") if isinstance(seed.get("suggested_backlog"), list) else []
    actionable_refs = {
        str(item.get("object_ref") or "")
        for item in raw_objects
        if isinstance(item, dict) and str(item.get("confidence") or "") != "low"
    }
    objects = [
        item for item in raw_objects
        if isinstance(item, dict) and str(item.get("object_ref") or "") in actionable_refs
    ]
    backlog = [
        item for item in raw_backlog
        if isinstance(item, dict) and str(item.get("object_ref") or "") in actionable_refs
    ]
    if not objects and not backlog:
        return ""
    selected_index = 0
    for index, item in enumerate(backlog):
        if not isinstance(item, dict):
            continue
        missing = {str(value).strip().lower() for value in item.get("missing") or []}
        if "object endpoint" not in missing:
            selected_index = index
            break
    first_object = objects[selected_index] if selected_index < len(objects) and isinstance(objects[selected_index], dict) else {}
    first_backlog = backlog[selected_index] if selected_index < len(backlog) and isinstance(backlog[selected_index], dict) else {}
    target = str(seed.get("target") or "").strip()
    command = f"python3 tools/case_state_seed.py --target {_quote(target)} --json" if target else "python3 tools/case_state_seed.py --target <target> --json"
    missing = ", ".join(str(item) for item in (first_backlog.get("missing") or [])[:4])
    endpoint = str(first_object.get("endpoint") or "").strip()
    if "object endpoint" in {part.strip().lower() for part in (first_backlog.get("missing") or [])}:
        return (
            "Case-state endpoint discovery lead: Found object candidate {object_ref} "
            "type={object_type} endpoint=<missing>. Runner: {runner}. "
            "Missing evidence: {missing}. Next action: identify a concrete "
            "object-specific endpoint from browser XHR, source routes, or MCP "
            "observations before adding IDOR backlog. Seed command: {command}. "
            "Stop condition: no endpoint can be tied to the object ID without "
            "substring or collection-only guessing."
        ).format(
            object_ref=first_object.get("object_ref", "-"),
            object_type=first_object.get("type", "-"),
            runner=first_backlog.get("runner", "idor-actor-pair"),
            missing=missing or "object endpoint",
            command=command,
        )
    return (
        "Case-state seed opportunity: Found object candidate {object_ref} "
        "type={object_type} endpoint={endpoint}. Runner: {runner}. "
        "Missing evidence: {missing}. Next: {command}. "
        "Review suggested add-actor/add-object/add-backlog commands; do not treat "
        "seed suggestions as validated findings."
    ).format(
        object_ref=first_object.get("object_ref", "-"),
        object_type=first_object.get("type", "-"),
        endpoint=endpoint or "-",
        runner=first_backlog.get("runner", "idor-actor-pair"),
        missing=missing or "review required",
        command=command,
    )


ACTION_DECISIONS = {
    "wait_recon": "wait_recon",
    "wait_scan": "wait_scan",
    "validation": "validate",
    "validate_finding": "validate",
    "candidate-evidence-gap": "validate",
    "report": "report",
    "report_finding": "report",
    "complete_report_draft": "report",
    "recon": "refresh-recon",
    "run_recon": "refresh-recon",
    "hunt_p1": "hunt",
    "hunt_p2": "hunt",
    "prepare_surface_context": "hunt",
    "surface-review": "hunt",
    "ranked-surface": "hunt",
    "evidence-convergence": "hunt",
    "workflow-lead-review": "hunt",
    "sibling-chain-review": "hunt",
    "capability-chain-review": "continue",
    "knowledge-signal-review": "continue",
    "source-enrichment": "enrich",
    "js-enrichment": "enrich",
    "browser-enrichment": "enrich",
    "run_intel": "enrich",
    "collect_web_intel": "enrich",
    "test_advisory_applicability": "enrich",
    "review_intel_group": "enrich",
    "context-review": "checkpoint",
    "action-gated-review": "checkpoint",
    "high-risk-lane-review": "validate",
    "viewstate-integrity-review": "validate",
    "handoff": "handoff",
    "recon_no_live_hosts": "handoff",
    "revalidate_finding_owner": "continue",
    "collect_candidate_evidence": "continue",
    "review_validation_candidate": "continue",
    "resume_action_queue": "continue",
    "resume_case_state": "continue",
    "refresh_checkpoint": "checkpoint",
    "repair_evidence_ledger": "checkpoint",
    "continue_last_focus": "continue",
    "resume_untested": "continue",
    "case-state-validation": "continue",
    "case-state-enrichment": "continue",
    "case-state-backlog-create": "continue",
    "case-state-seed": "continue",
    "actor-gap": "continue",
    "coverage-gap": "continue",
    "secondary-sweep": "continue",
    "secret-verification": "continue",
    "json-inject-review": "continue",
    "sql-matrix-review": "continue",
    "next-action": "continue",
}


def _decision_for_action(action: str) -> str:
    return ACTION_DECISIONS.get(str(action or "").strip().lower(), "handoff")


def _lead_proposals(
    state: dict,
    context_pack: dict,
    *,
    repo_root: Path | None = None,
    target: str = "",
    evidence_summary: dict | None = None,
    case_state: dict | None = None,
) -> list[str]:
    proposals: list[str] = []
    surface = state.get("surface") or {}
    for lead in _json_list(surface.get("workflow_leads"))[:3]:
        if _secondary_sweep_closed_by_ledger(
            lead,
            repo_root=repo_root,
            target=target,
            evidence_summary=evidence_summary or {},
        ):
            continue
        title = str(lead.get("title") or "").strip()
        next_action = str(lead.get("next_action") or "").strip()
        why = str(lead.get("rationale") or lead.get("category") or "workflow lead").strip()
        category = str(lead.get("category") or "workflow").strip()
        artifact = str(lead.get("artifact") or lead.get("evidence_ref") or "").strip()
        if title:
            proposals.append(
                "Evidence: Workflow lead: {title}. Why it matters: {why}. "
                "Category={category}. {artifact_clause}Next action: {next_action}. Stop condition: no reproducible "
                "behavior difference or new evidence after focused replay.".format(
                    title=title[:180],
                    why=why[:180],
                    category=category[:80],
                    artifact_clause=(f"Artifact={artifact}. " if artifact else ""),
                    next_action=next_action[:180] or "inspect the linked artifact",
                )
            )

    for item in (surface.get("p1") or [])[:2]:
        url = str(item.get("url") or "").strip()
        reasons = ", ".join(str(reason) for reason in (item.get("reasons") or [])[:2])
        suggested = str(item.get("suggested") or "").strip()
        if url:
            endpoint_path = _normalise_endpoint_path(url)
            vuln_hint = _ranked_surface_vuln_hint(item, url)
            if _ledger_covers_cell(
                _ledger_covered_cells(evidence_summary or {}),
                endpoint_path,
                vuln_hint,
                item.get("identity_v2"),
            ):
                continue
            proposals.append(
                "Evidence: Surface review candidate {url} ({reasons}). Why it matters: "
                "interesting attack-surface evidence from cached recon/browser/source signals. "
                "Next action: {suggested}. Stop condition: no authz/data/state "
                "difference after minimal replay.".format(
                    url=url,
                    reasons=reasons or "ranked surface",
                    suggested=suggested or "run focused authz and workflow checks",
                )
            )

    return _dedupe(proposals)[:3]


def _canonicalize_url_path(value: str) -> str:
    return extract_endpoint_path(value)


def _normalise_endpoint_path(value: str) -> str:
    return canonical_endpoint_path(value)


PLACEHOLDER_OBJECT_SEGMENTS = {"nan", "undefined", "null", "none", "object", "[object object]"}


def _path_segments(value: str) -> list[str]:
    path = _canonicalize_url_path(value)
    return [segment for segment in path.split("/") if segment]


def _non_concrete_object_segments(value: str) -> list[str]:
    """Return high-confidence placeholder path segments that must not be replayed directly."""
    out: list[str] = []
    for segment in _path_segments(value):
        lowered = segment.strip().lower()
        if lowered in PLACEHOLDER_OBJECT_SEGMENTS:
            out.append(segment)
        elif lowered.startswith(":") or (lowered.startswith("{") and lowered.endswith("}")):
            out.append(segment)
        elif lowered.startswith("<") and lowered.endswith(">"):
            out.append(segment)
    return out


def _case_state_object_for_surface(url: str, case_state: dict | None) -> dict:
    """Find a concrete case_state object whose type appears in the surface path."""
    if not isinstance(case_state, dict):
        return {}
    samples = case_state.get("object_samples") if isinstance(case_state.get("object_samples"), list) else []
    segments = [segment.lower().replace("_", "-") for segment in _path_segments(url)]
    for obj in samples:
        if not isinstance(obj, dict):
            continue
        object_type = str(obj.get("type") or "").strip().lower().replace("_", "-")
        if not object_type:
            continue
        aliases = {object_type, f"{object_type}s"}
        if object_type == "basket":
            aliases.add("cart")
        if object_type == "cart":
            aliases.add("basket")
        if aliases.intersection(segments):
            return obj
    return {}


def _placeholder_object_replay_guidance(url: str, case_state: dict | None, target: str = "") -> str:
    placeholders = _non_concrete_object_segments(url)
    if not placeholders:
        return ""
    matched = _case_state_object_for_surface(url, case_state)
    placeholder_text = ", ".join(placeholders)
    if matched and matched.get("endpoint"):
        target_arg = _quote(target or "<target>")
        object_ref = str(matched.get("object_ref") or "")
        endpoint = str(matched.get("endpoint") or "")
        command = ""
        if object_ref:
            command = (
                f"`python3 tools/validation_runner.py idor-actor-pair --target {target_arg} "
                f"--from-case-state --object-ref {_quote(object_ref)} --repeat 2`"
            )
        return (
            f"observed URL contains non-concrete object value {placeholder_text}; "
            f"do not replay it directly. Substitute case_state object {object_ref or matched.get('type')} "
            f"endpoint {endpoint} and run {command or 'owner/peer replay on the concrete endpoint'}"
        )
    return (
        f"observed URL contains non-concrete object value {placeholder_text}; do not replay it directly. "
        "First capture a browser/MCP request with a real object ID or register a concrete "
        "case_state object, then replay the underlying API"
    )


def _placeholder_concrete_endpoint(url: str, case_state: dict | None) -> str:
    if not _non_concrete_object_segments(url):
        return ""
    matched = _case_state_object_for_surface(url, case_state)
    return str(matched.get("endpoint") or "").strip() if matched else ""


def _is_parent_endpoint(parent: str, child: str) -> bool:
    parent_path = _normalise_endpoint_path(parent)
    child_path = _normalise_endpoint_path(child)
    if not parent_path or not child_path or parent_path == "/" or parent_path == child_path:
        return False
    return child_path.startswith(parent_path + "/")


def _ranked_surface_entry(state: dict, url: str) -> dict:
    surface = state.get("surface") or {}
    for bucket in ("p1", "p2"):
        for item in (surface.get(bucket) or []):
            if isinstance(item, dict) and str(item.get("url") or "").strip() == str(url or "").strip():
                return item
    return {}


def _ranked_surface_query_keys(url: str) -> list[str]:
    return [key.lower() for key in re.findall(r"[?&]([^=&]+)=", str(url or ""))]


def _path_only_authz_gap_for_url(url: str, vuln_hint: str = "Authz") -> dict:
    endpoint = _canonicalize_url_path(url)
    query_keys = _ranked_surface_query_keys(url)
    rel = class_relevance(endpoint, "Authz", query_keys)
    return {
        "endpoint": endpoint,
        "vuln_class": vuln_hint,
        "weight": "",
        "relevance_score": rel.get("relevance_score", 0),
        "relevance_reason": rel.get("relevance_reason", ""),
        "observed_params": query_keys,
    }


def _ranked_surface_vuln_hint(entry: dict, url: str) -> str:
    scanner_types = [
        str(item.get("type") or "").strip()
        for item in (entry.get("scanner_findings") or [])
        if isinstance(item, dict) and str(item.get("type") or "").strip()
    ]
    if scanner_types:
        return scanner_types[0]

    source_types = [
        str(item.get("type") or "").strip()
        for item in (entry.get("source_intel_hypotheses") or [])
        if isinstance(item, dict) and str(item.get("type") or "").strip()
    ]
    if source_types:
        return source_types[0]

    endpoint = _canonicalize_url_path(url)
    query_keys = _ranked_surface_query_keys(url)
    candidates = ["Authz", "IDOR", "SQLi", "SSRF", "Race", "Upload", "GraphQL", "RCE"]
    if re.search(r"/(?:[a-z0-9_-]*dom|reflected)(?:/|$)", endpoint, re.I):
        candidates.append("XSS")
    scored = [
        (klass, class_relevance(endpoint, klass, query_keys))
        for klass in candidates
    ]
    scored.sort(key=lambda item: int(item[1].get("relevance_score", 0) or 0), reverse=True)
    best_class, best_rel = scored[0]
    if int(best_rel.get("relevance_score", 0) or 0) > 0:
        return best_class
    return "generic"


def _canonical_vuln_for_ledger(vuln_hint: str) -> str:
    try:
        return normalize_vuln_class(vuln_hint)
    except ValueError:
        return ""


def _case_state_has_role_replay_context(case_state: dict | None) -> bool:
    return (
        _case_state_count(case_state, "actors") >= 2
        and _case_state_count(case_state, "sessions") >= 2
        and _case_state_count(case_state, "objects") >= 1
    )


def _ranked_surface_needs_role_context(vuln_class: str, baseline_first: bool) -> bool:
    if baseline_first:
        return False
    return vuln_class in {"IDOR", "Authz", "GraphQL", "CSRF"}


def _ranked_surface_role_replay_ready(vuln_class: str, baseline_first: bool, case_state: dict | None) -> bool:
    return (
        _ranked_surface_needs_role_context(vuln_class, baseline_first)
        and _case_state_has_role_replay_context(case_state)
    )


def _ranked_surface_browser_state_first(url: str, vuln_class: str, query_keys: list[str]) -> bool:
    """Return true for client-side page routes where raw GET replay is low-value.

    页面路由不能丢：`/orders`、`/order-summary` 这类入口经常是复杂链路的门。
    但直接对 SPA shell 做 owner/peer HTTP GET replay 通常只得到同一份 HTML。
    这里仅改变下一步执行方式：先抓浏览器态真实 XHR/对象 ID，再 replay 底层 API。
    """
    if vuln_class not in {"Authz", "IDOR"}:
        return False
    if query_keys:
        return False
    path = urlparse(str(url or "")).path.lower() or "/"
    api_prefixes = (
        "/api",
        "/rest",
        "/graphql",
        "/socket.io",
        "/oauth",
        "/.well-known",
    )
    if any(path == prefix or path.startswith(prefix + "/") for prefix in api_prefixes):
        return False
    # 静态资源/下载类路径保留普通 replay；无扩展或 .html 更像客户端路由。
    suffix = Path(path).suffix.lower()
    return suffix in {"", ".html", ".htm"}


def _ranked_surface_auth_workflow_first(url: str, js_methods: list[str]) -> bool:
    """Auth workflow actions need exact method/body before replay.

    Login/reset/token 类端点通常不是 GET 资源读面；没有浏览器/source 捕获到
    method、body、CSRF/CAPTCHA、会话语义前，默认 owner/peer GET 只会制造
    dead-end 噪声。这里不裁剪攻击面，只把下一步改为 exact-request capture。
    """
    path = urlparse(str(url or "")).path.lower()
    if not path:
        return False
    segments = [segment for segment in re.split(r"[/._-]+", path) if segment]
    action_terms = {
        "login",
        "logout",
        "signin",
        "signout",
        "register",
        "signup",
        "reset",
        "forgot",
        "password",
        "change",
        "token",
        "session",
        "authenticate",
        "authentication",
    }
    if not any(term in segments for term in action_terms):
        return False
    # 已有明确 GET/HEAD 观测时，按真实观测走；否则先捕获真实 workflow 请求。
    return not any(method in {"GET", "HEAD"} for method in js_methods)


def _ranked_surface_parameter_behavior_first(url: str, query_keys: list[str]) -> bool:
    """URL/redirect/fetch 参数应先做参数行为验证，而不是 role replay。"""
    path = urlparse(str(url or "")).path.lower()
    keys = {str(key or "").lower().replace("-", "_") for key in query_keys}
    redirect_keys = {
        "to",
        "url",
        "uri",
        "redirect",
        "redirect_url",
        "redirect_uri",
        "return",
        "return_url",
        "next",
        "continue",
        "callback",
        "target",
        "dest",
        "destination",
    }
    if keys & redirect_keys:
        return True
    return any(segment in {"redirect", "callback"} for segment in path.split("/") if segment)


def _matrix_endpoint_paths(matrix: dict) -> set[str]:
    """提取 coverage matrix 中的端点路径，供 checkpoint 做父子关系 hint。

    这里不是用 matrix 给端点下结论，只补足 ranked surface 窗口看不到的
    child endpoint。最终仍只生成 route-prefix triage 建议，由 AI/操作者
    根据 baseline/body/browser 证据决定是否 mark-endpoint-kind。
    """
    paths: set[str] = set()
    for item in matrix.get("endpoints") or []:
        if not isinstance(item, dict):
            continue
        endpoint = str(item.get("endpoint") or "").strip()
        if not endpoint:
            continue
        path = _normalise_endpoint_path(endpoint).rstrip("/")
        if path:
            paths.add(path)
    return paths


def _ranked_surface_state_with_matrix_paths(state: dict, matrix: dict) -> dict:
    """给 ranked-surface 判读补充 matrix 端点全集，避免窗口截断误导。"""
    paths = _matrix_endpoint_paths(matrix)
    if not paths:
        return state
    enriched = dict(state)
    existing = enriched.get("_matrix_endpoint_paths")
    merged = set(existing) if isinstance(existing, (set, list, tuple)) else set()
    merged.update(paths)
    enriched["_matrix_endpoint_paths"] = merged
    return enriched


def _ranked_surface_route_prefix_first(state: dict, url: str, query_keys: list[str]) -> bool:
    """父级容器路径先做 handler/triage，不直接进入 role replay。"""
    if query_keys:
        return False
    path = _canonicalize_url_path(url).rstrip("/")
    if not path or path == "/":
        return False
    suffix = Path(path).suffix.lower()
    if suffix:
        return False
    child_paths: set[str] = set()
    surface = state.get("surface") if isinstance(state.get("surface"), dict) else {}
    for bucket in ("p1", "p2"):
        for item in surface.get(bucket) or []:
            if isinstance(item, dict):
                child_paths.add(_canonicalize_url_path(str(item.get("url") or "")).rstrip("/"))
    for item in state.get("recommended_targets") or []:
        if isinstance(item, dict):
            child_paths.add(_canonicalize_url_path(str(item.get("url") or "")).rstrip("/"))
    extra_paths = state.get("_matrix_endpoint_paths")
    if isinstance(extra_paths, (set, list, tuple)):
        child_paths.update(str(item or "").rstrip("/") for item in extra_paths if str(item or "").strip())
    return any(child and child != path and child.startswith(path + "/") for child in child_paths)


def _ranked_surface_context_prereq(state: dict, item: dict, case_state: dict | None = None) -> bool:
    url = str(item.get("url") or "").strip()
    if not url:
        return False
    entry = _ranked_surface_entry(state, url)
    vuln_hint = _ranked_surface_vuln_hint(entry, url)
    vuln_class = _canonical_vuln_for_ledger(vuln_hint)
    if not vuln_class:
        return False
    authz_gap = _path_only_authz_gap_for_url(url, vuln_hint)
    baseline_first = _is_path_only_authz_gap(authz_gap)
    return (
        _ranked_surface_needs_role_context(vuln_class, baseline_first)
        and not _case_state_has_role_replay_context(case_state)
    )


def _recent_anonymous_authz_clean_count(evidence_summary: dict) -> int:
    count = 0
    for entry in evidence_summary.get("recent_entries") or []:
        if not isinstance(entry, dict):
            continue
        result = str(entry.get("result") or "")
        vuln_class = _canonical_vuln_for_ledger(str(entry.get("vuln_class") or ""))
        actor = str(entry.get("actor") or "").strip().lower()
        object_scope = str(entry.get("object_scope") or "").strip().lower()
        if (
            result in {"tested_clean", "dead_end", "not_applicable"}
            and vuln_class == "Authz"
            and actor == "anonymous"
            and object_scope in {"none", ""}
        ):
            count += 1
    return count


def _case_state_acquisition_proposal(deferred_count: int, clean_count: int) -> str:
    return (
        "Case-state acquisition lead: {clean_count} recent anonymous Authz "
        "baseline(s) are already clean, and {deferred_count} ranked role/object "
        "surface(s) need runtime actor/session/object context before meaningful "
        "owner/peer replay. Next: capture a real browser session or create test-owned "
        "actors where authorized, then register actors/sessions/objects with "
        "tools/target_case_state.py; if no authorized session path exists, record "
        "no-auth-context and pivot to unauth/source-intel lanes instead of testing "
        "more identical 401 baselines."
    ).format(clean_count=clean_count, deferred_count=deferred_count)


def _ranked_surface_replay_draft(
    state: dict,
    item: dict,
    case_state: dict | None = None,
    *,
    target: str = "",
) -> str:
    url = str(item.get("url") or "").strip()
    if not url:
        return ""
    entry = _ranked_surface_entry(state, url)
    query_keys = _ranked_surface_query_keys(url)
    js_methods = [
        str(js.get("method") or "").upper()
        for js in (entry.get("js_intel_endpoints") or [])
        if isinstance(js, dict) and str(js.get("method") or "").strip()
    ]
    js_methods = list(dict.fromkeys([method for method in js_methods if method]))
    source_types = [
        str(src.get("type") or "").lower()
        for src in (entry.get("source_intel_hypotheses") or [])
        if isinstance(src, dict) and str(src.get("type") or "").strip()
    ]
    source_types = list(dict.fromkeys([value for value in source_types if value]))

    vuln_hint = _ranked_surface_vuln_hint(entry, url)
    evidence_text = " ".join([
        str(entry.get("suggested") or item.get("suggested") or ""),
        " ".join(query_keys),
        " ".join(source_types),
        "browser observed" if entry.get("browser_observed") else "",
        " ".join(js_methods),
    ])
    authz_gap = _path_only_authz_gap_for_url(url, vuln_hint)
    vuln_class = _canonical_vuln_for_ledger(vuln_hint)
    baseline_first = _is_path_only_authz_gap(authz_gap)
    browser_state_first = _ranked_surface_browser_state_first(url, vuln_class, query_keys)
    auth_workflow_first = _ranked_surface_auth_workflow_first(url, js_methods)
    parameter_behavior_first = (
        vuln_class != "XSS"
        and _ranked_surface_parameter_behavior_first(url, query_keys)
    )
    route_prefix_first = _ranked_surface_route_prefix_first(state, url, query_keys)
    placeholder_guidance = _placeholder_object_replay_guidance(url, case_state, target)
    role_replay_ready = (
        _ranked_surface_role_replay_ready(vuln_class, baseline_first, case_state)
        and not browser_state_first
        and not auth_workflow_first
        and not parameter_behavior_first
        and not route_prefix_first
        and not placeholder_guidance
    )
    if placeholder_guidance:
        validation_path = placeholder_guidance
    elif baseline_first:
        validation_path = _coverage_gap_validation_path(authz_gap)
    elif browser_state_first:
        validation_path = (
            "Use browser-state first for this page route: open it as owner and peer, "
            "capture/import MCP browser artifacts, extract the real XHR/object IDs, "
            "then run validation_runner authz-role-replay or idor-actor-pair on the "
            "underlying API instead of replaying the raw SPA HTML shell"
        )
    elif auth_workflow_first:
        validation_path = (
            "Capture the exact auth workflow request first: browser/source observed "
            "method, headers, body, CSRF/CAPTCHA/session state, and success/failure "
            "signal; then choose authn/business-logic/credential-lane or bounded "
            "marker replay. Do not run default GET role replay on this action endpoint"
        )
    elif parameter_behavior_first:
        validation_path = (
            "Run parameter-behavior validation first: anonymous baseline vs controlled "
            "variant for the observed URL/redirect parameter, compare status, Location "
            "header, body reflection, and target normalization; then choose open-redirect, "
            "SSRF, cache, or browser-boundary lane. Do not run owner/peer role replay "
            "until a real auth boundary appears"
        )
    elif route_prefix_first:
        validation_path = (
            "Treat this as a possible route-prefix/container path: run one anonymous "
            "handler baseline, compare it to concrete child endpoints, and if it is "
            "only a prefix or 404/500 container, mark endpoint_kind=route_prefix and "
            "focus replay on concrete child handlers. Do not run owner/peer role replay "
            "against the parent prefix"
        )
    elif role_replay_ready:
        target_arg = _quote(target or "<target>")
        url_arg = _quote(url)
        validation_path = (
            "Run authenticated role replay from case_state: "
            f"`python3 tools/validation_runner.py authz-role-replay --target {target_arg} "
            f"--url {url_arg} --from-case-state --repeat 2`; compare anonymous/owner/peer "
            "status, JSON shape, and body diff; only promote body-backed public exposure "
            "or role/object-specific authorization delta"
        )
    elif _ranked_surface_context_prereq(state, item, case_state):
        validation_path = (
            "First capture/register actor, session, and object context in "
            "tools/target_case_state.py; until owner/peer context exists, only run "
            "anonymous or exact browser baseline classification and do not claim "
            "two-actor replay evidence"
        )
    else:
        validation_path = first_missing_action(evaluate_candidate_evidence({
            "type": vuln_hint,
            "url": url,
            "summary": evidence_text,
        }))

    parts: list[str] = []
    if entry.get("browser_observed"):
        parts.append("capture the exact browser-observed request/response baseline first")
    if js_methods:
        parts.append("prefer " + "/".join(js_methods[:2]) + " replay")
    if query_keys:
        parts.append("reuse observed parameters: " + ", ".join(query_keys[:4]))
    if source_types:
        parts.append("follow source hints: " + ", ".join(source_types[:3]))
    if vuln_hint and vuln_hint != "generic":
        parts.append(f"focus {vuln_hint} evidence")
    if role_replay_ready:
        parts.append("use registered case_state owner/peer sessions")
    if browser_state_first:
        parts.append("browser-state-first page route; avoid treating identical SPA HTML as clean")
    if auth_workflow_first:
        parts.append("auth-workflow endpoint; exact method/body required before replay")
    if parameter_behavior_first:
        parts.append("parameter-behavior-first redirect/url input; avoid role replay")
    if route_prefix_first:
        parts.append("route-prefix-first parent path; validate concrete child handlers")
    if placeholder_guidance:
        parts.append("placeholder object path; require concrete object ID before replay")
    if validation_path:
        parts.append(validation_path)
    return "; ".join(parts)


def _ranked_surface_ledger_skeleton(
    state: dict,
    item: dict,
    target: str,
    replay_draft: str,
    case_state: dict | None = None,
) -> str:
    """Build a copyable ledger record command for the suggested ranked-surface replay.

    This is intentionally a skeleton, not an auto-write: the operator/agent should
    run it after the replay and adjust `--result` / `--evidence-ref` to the actual
    evidence captured.
    """
    url = str(item.get("url") or "").strip()
    if not url:
        return ""
    entry = _ranked_surface_entry(state, url)
    endpoint = _canonicalize_url_path(url)
    js_methods = [
        str(js.get("method") or "").upper()
        for js in (entry.get("js_intel_endpoints") or [])
        if isinstance(js, dict) and str(js.get("method") or "").strip()
    ]
    method = next((value for value in js_methods if value), "GET")
    vuln_hint = _ranked_surface_vuln_hint(entry, url)
    vuln_class = _canonical_vuln_for_ledger(vuln_hint)
    if not vuln_class:
        return ""
    authz_gap = _path_only_authz_gap_for_url(url, vuln_hint)
    baseline_first = _is_path_only_authz_gap(authz_gap)
    context_prereq = _ranked_surface_context_prereq(state, item, case_state)
    query_keys = _ranked_surface_query_keys(url)
    browser_state_first = _ranked_surface_browser_state_first(url, vuln_class, query_keys)
    auth_workflow_first = _ranked_surface_auth_workflow_first(url, js_methods)
    parameter_behavior_first = _ranked_surface_parameter_behavior_first(url, query_keys)
    route_prefix_first = _ranked_surface_route_prefix_first(state, url, query_keys)
    placeholder_guidance = _placeholder_object_replay_guidance(url, case_state, target)
    placeholder_object = _case_state_object_for_surface(url, case_state) if placeholder_guidance else {}
    role_replay_ready = (
        _ranked_surface_role_replay_ready(vuln_class, baseline_first, case_state)
        and not browser_state_first
        and not auth_workflow_first
        and not parameter_behavior_first
        and not route_prefix_first
        and not placeholder_guidance
    )
    actor = (
        "anonymous"
        if baseline_first or context_prereq or auth_workflow_first or parameter_behavior_first or route_prefix_first
        else "owner"
    )
    object_scope = (
        "none"
        if baseline_first or context_prereq or auth_workflow_first or parameter_behavior_first or route_prefix_first
        else "unknown"
    )
    if placeholder_object.get("object_ref"):
        object_scope = "own_object"
    if placeholder_object.get("endpoint"):
        endpoint = _normalise_endpoint_path(str(placeholder_object.get("endpoint") or ""))
    if placeholder_guidance:
        variant = "id_swap" if placeholder_object.get("endpoint") else "baseline"
    elif baseline_first or context_prereq:
        variant = "baseline"
    elif browser_state_first:
        variant = "browser_observed"
    elif auth_workflow_first:
        variant = "baseline"
    elif parameter_behavior_first:
        variant = "replay"
    elif route_prefix_first:
        variant = "baseline"
    elif role_replay_ready:
        variant = "role_diff"
    else:
        variant = "browser_observed" if entry.get("browser_observed") else "replay"
    evidence_ref = ""
    if entry.get("browser_observed"):
        evidence_ref = f"recon/{target_storage_key(canonical_target_value(target))}/browser/xhr_endpoints.txt"
    notes = (
        "Checkpoint ranked-surface replay skeleton; update result/evidence-ref "
        "after baseline/variant evidence is captured."
    )
    if context_prereq:
        notes = (
            "Checkpoint ranked-surface context prerequisite; register actor/session/object "
            "before owner/peer replay, or update this record after baseline classification."
        )
    elif placeholder_guidance:
        notes = (
            "Checkpoint ranked-surface placeholder object path; do not replay the observed "
            "placeholder URL directly. Replace it with a concrete case_state/browser object "
            "endpoint before recording final result."
        )
    elif browser_state_first:
        notes = (
            "Checkpoint ranked-surface browser-state-first page route; capture/import MCP "
            "browser artifacts, extract underlying XHR/object IDs, then replay the API."
        )
    elif auth_workflow_first:
        notes = (
            "Checkpoint ranked-surface auth workflow; capture exact observed method, "
            "headers, body, CSRF/CAPTCHA/session state, and success/failure signal before "
            "recording replay or role-diff evidence."
        )
    elif parameter_behavior_first:
        notes = (
            "Checkpoint ranked-surface URL/redirect parameter behavior; compare anonymous "
            "baseline and controlled variants for status, Location, reflection, and target "
            "normalization before choosing open-redirect/SSRF/browser-boundary follow-up."
        )
    elif route_prefix_first:
        notes = (
            "Checkpoint ranked-surface route prefix triage; run one anonymous handler "
            "baseline and, if this is only a parent/container path, mark endpoint_kind="
            "route_prefix and focus concrete child endpoints."
        )
    elif role_replay_ready:
        notes = (
            "Checkpoint ranked-surface authenticated role replay; run validation_runner "
            "authz-role-replay and update result/evidence-ref from the generated summary."
        )
    parts = [
        "python3 tools/evidence_ledger.py record",
        "--target", _quote(target),
        "--endpoint", _quote(endpoint),
        "--method", _quote(method),
        "--vuln-class", _quote(vuln_class),
        "--actor", _quote(actor),
        "--object-scope", _quote(object_scope),
        "--variant", _quote(variant),
        "--source", _quote("checkpoint-ranked-surface"),
        "--result", _quote("signal"),
        "--replayed",
    ]
    if entry.get("browser_observed"):
        parts.append("--browser-observed")
    if entry.get("state_changing") is True:
        parts.append("--state-changing")
    if entry.get("redline_checked") is True:
        parts.append("--redline-checked")
    if evidence_ref:
        parts.extend(["--evidence-ref", _quote(evidence_ref)])
    parts.extend(["--notes", _quote(notes)])
    return " ".join(parts)


def _tested_finding_endpoints(matrix: dict) -> set[str]:
    endpoints: set[str] = set()
    for endpoint in matrix.get("endpoints") or []:
        if not isinstance(endpoint, dict):
            continue
        path = str(endpoint.get("endpoint") or "").strip()
        cells = endpoint.get("cells") or {}
        if not path or not isinstance(cells, dict):
            continue
        if any(
            isinstance(cell, dict) and str(cell.get("status") or "") == "tested_finding"
            for cell in cells.values()
        ):
            endpoints.add(path)
    return endpoints


def _ledger_covered_cells(evidence_summary: dict, matrix: dict | None = None) -> ClosureResolver:
    """Return the unified closure resolver for endpoint/vuln cells."""
    return ClosureResolver(evidence_summary or {}, matrix or {})


def _ledger_covers_cell(
    covered_cells: ClosureResolver,
    endpoint: str,
    vuln_class: str,
    identity_v2: dict | None = None,
) -> bool:
    return covered_cells.is_cell_closed(endpoint, vuln_class, identity_v2=identity_v2)


def _ledger_candidate_proposals(evidence_summary: dict, *, limit: int = 3) -> list[str]:
    """把 Evidence Ledger 里的开放 candidate 变成 AI-facing 验证动作。

    这里不判断 candidate 是否“该报”，只防止 AI 手工验证出的复杂链路
    被 ledger 吃掉后从 checkpoint 视野里消失。最终升降级仍交给 Claude
    结合原始证据、7-Question Gate 和四个验证门判断。
    """
    proposals: list[str] = []
    for action in (evidence_summary.get("identity_v2_follow_up_actions") or [])[:limit]:
        if not isinstance(action, dict):
            continue
        endpoint = str(action.get("endpoint") or "").strip()
        family = str(action.get("family") or "").strip()
        missing = ", ".join(str(item) for item in (action.get("missing_fields") or []) if str(item))
        conflicts = ", ".join(str(item) for item in (action.get("conflicts") or []) if str(item))
        if not endpoint or not family:
            continue
        reason = "; ".join(item for item in (f"missing={missing}" if missing else "", f"conflicts={conflicts}" if conflicts else "") if item)
        proposals.append(
            f"Resolve closure identity for {endpoint} x {family}: {reason or 'deterministic identity gate pending'}. "
            "Review the referenced evidence and record a linked complete identity or retain the fail-open state."
        )
    candidates = [
        item
        for item in [
            *(evidence_summary.get("open_candidates") or []),
            *(evidence_summary.get("open_candidates_v2") or []),
        ]
        if isinstance(item, dict)
    ]
    seen: set[str] = set()
    for entry in candidates:
        identity_key = json.dumps(
            entry.get("identity_v2") or {
                "endpoint": entry.get("endpoint"),
                "vuln_class": entry.get("vuln_class"),
                "method": entry.get("method"),
                "variant": entry.get("variant"),
            },
            sort_keys=True,
        )
        if identity_key in seen:
            continue
        seen.add(identity_key)
        if len(proposals) >= limit:
            break
        if not isinstance(entry, dict):
            continue
        endpoint = str(entry.get("endpoint") or entry.get("raw_endpoint") or "").strip()
        vuln_class = str(entry.get("vuln_class") or "").strip()
        method = str(entry.get("method") or "GET").strip().upper()
        evidence_ref = str(entry.get("evidence_ref") or "").strip()
        notes = str(entry.get("notes") or "").strip()
        identity = entry.get("identity_v2") if isinstance(entry.get("identity_v2"), dict) else {}
        identity_dimensions = identity.get("dimensions") or {}
        identity_suffix = (
            f" IdentityV2={json.dumps(identity_dimensions, sort_keys=True, ensure_ascii=True)}."
            if isinstance(identity_dimensions, dict) and identity_dimensions
            else ""
        )
        if not endpoint or not vuln_class:
            continue
        evidence_suffix = f" Evidence={evidence_ref}." if evidence_ref else ""
        notes_suffix = f" Notes={notes[:220]}." if notes else ""
        proposals.append(
            "Run /validate for ledger candidate {method} {endpoint} x {vuln_class}. "
            "AI task: review raw evidence, impact, replayability, and side-effect/risk status; "
            "then promote to finding/report or downgrade with evidence ledger update."
            "{evidence}{notes} Stop condition: validated finding, tested_clean, "
            "dead_end, or blocked_redline is recorded.".format(
                method=method,
                endpoint=endpoint,
                vuln_class=vuln_class,
                evidence=evidence_suffix,
                notes=notes_suffix,
            ) + identity_suffix
        )
    return proposals


def _workflow_lead_queue_items(
    state: dict,
    *,
    repo_root: Path | None,
    target: str,
) -> list[dict]:
    """Project only artifact-backed critical/high leads into durable work."""
    if repo_root is None:
        return []
    items: list[dict] = []
    for lead in _json_list((state.get("surface") or {}).get("workflow_leads")):
        priority_name = str(lead.get("priority") or "medium").strip().lower()
        if priority_name not in {"critical", "high"}:
            continue
        artifact = str(lead.get("artifact") or lead.get("evidence_ref") or "").strip()
        if not artifact:
            continue
        artifact_path = Path(artifact)
        if not artifact_path.is_absolute():
            artifact_path = repo_root / artifact_path
        try:
            stat = artifact_path.stat()
        except OSError:
            # A lead without a locatable artifact remains advisory; do not
            # create durable work that can never be resumed or audited.
            continue
        source_id = str(lead.get("id") or "").strip()
        if not source_id:
            source_id = hashlib.sha256(
                json.dumps(
                    {
                        "category": lead.get("category", ""),
                        "title": lead.get("title", ""),
                        "artifact": artifact,
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest()[:20]
        generation = hashlib.sha256(
            f"{artifact}:{stat.st_size}:{stat.st_mtime_ns}".encode("utf-8")
        ).hexdigest()[:24]
        title = str(lead.get("title") or lead.get("category") or "workflow lead").strip()
        next_action = str(lead.get("next_action") or "inspect the linked artifact").strip()
        evidence = str(lead.get("evidence") or lead.get("rationale") or "").strip()
        items.append({
            "id": f"LEAD-{source_id}",
            "priority": 98 if priority_name == "critical" else 88,
            "type": "workflow-lead-review",
            "status": "ready",
            "action": (
                f"Review high-value workflow lead: {title}. {next_action}. "
                f"Artifact={artifact}. Evidence={evidence[:180]}"
            ),
            "command_hint": "",
            "redline_required": False,
            "stop_condition": (
                "record tested, blocked, dead-end, candidate, or validated finding "
                "with a locatable evidence reference"
            ),
            "source": "workflow-lead",
            "source_id": source_id,
            "metadata": {
                "generation": generation,
                "category": str(lead.get("category") or "workflow").strip(),
                "priority": priority_name,
                "artifact": artifact,
                "evidence_ref": str(lead.get("evidence_ref") or artifact),
            },
        })
    return items


def _sibling_queue_item(
    state: dict,
    *,
    repo_root: Path | None,
    target: str,
) -> dict:
    """Queue one bounded lateral probe after a durable candidate result."""
    if repo_root is None:
        return {}
    findings = state.get("structured_findings") or {}
    candidates = [
        findings.get("next_validation") or {},
        findings.get("next_report") or {},
    ]
    for finding in candidates:
        if not isinstance(finding, dict):
            continue
        status = str(finding.get("validation_status") or "").strip().lower()
        if status not in {"candidate", "validated"}:
            continue
        finding_id = str(finding.get("id") or "").strip()
        endpoint = str(finding.get("url") or "").strip()
        source_file = str(finding.get("source_file") or "").strip()
        if not finding_id or not endpoint or not url_belongs_to_target(endpoint, target):
            continue
        if source_file:
            source_path = Path(source_file)
            if not source_path.is_absolute():
                source_path = repo_root / source_path
            try:
                source_stat = source_path.stat()
            except OSError:
                continue
            source_generation = f"{source_file}:{source_stat.st_size}:{source_stat.st_mtime_ns}"
        else:
            source_generation = ""
        generation = hashlib.sha256(
            f"{finding_id}:{endpoint}:{source_generation}".encode("utf-8")
        ).hexdigest()[:24]
        return {
            "id": f"SIBLING-{finding_id}",
            "priority": 68 if status == "candidate" else 60,
            "type": "sibling-chain-review",
            "status": "ready",
            "action": (
                f"Generate one bounded sibling probe for finding {finding_id} at {endpoint}; "
                "review the generated queue and validate only same-target endpoints."
            ),
            "command_hint": (
                "python3 tools/sibling_generator.py --target "
                f"{_quote(target)} --finding-id {_quote(finding_id)} "
                f"--endpoint {_quote(endpoint)} --max-count 20"
            ),
            "redline_required": False,
            "stop_condition": (
                "record sibling queue reviewed, blocked, dead-end, candidate, or validated; "
                "do not treat sibling discovery alone as a finding"
            ),
            "source": "primary-finding-sibling",
            "source_id": finding_id,
            "metadata": {
                "generation": generation,
                "finding_id": finding_id,
                "endpoint": endpoint,
                "validation_status": status,
                "evidence_ref": source_file,
            },
        }
    return {}


def _runner_candidate_proposals(state: dict, *, limit: int = 2) -> list[str]:
    """Expose runner evidence as AI review work when no finding row owns it yet."""
    proposals: list[str] = []
    for item in (state.get("validation_runner_candidates") or [])[:limit]:
        if not isinstance(item, dict):
            continue
        candidate_id = str(item.get("id") or "").strip()
        lane = str(item.get("lane") or "").strip()
        method = str(item.get("method") or "GET").strip().upper()
        url = str(item.get("url") or "").strip()
        evidence_ref = str(item.get("summary_path") or "").strip()
        rubric = str(item.get("rubric_status") or "").strip()
        missing = ", ".join(str(value) for value in (item.get("missing_evidence") or [])[:3])
        if not url:
            continue
        rubric_suffix = f" rubric={rubric}" if rubric else ""
        missing_suffix = f" missing={missing}" if missing else ""
        evidence_suffix = f" Evidence={evidence_ref}." if evidence_ref else ""
        proposals.append(
            "Review validation-runner candidate {id} [{lane}] {method} {url}.{rubric}{missing} "
            "AI task: read raw request/response evidence, impact, replayability, and policy context; "
            "then run /validate if reportable, or record tested_clean/dead_end in evidence ledger."
            "{evidence} Stop condition: validated finding, tested_clean, dead_end, or blocked_redline is recorded.".format(
                id=candidate_id or "-",
                lane=lane or "runner",
                method=method,
                url=url,
                rubric=rubric_suffix,
                missing=missing_suffix,
                evidence=evidence_suffix,
            )
        )
    return proposals


def _is_parent_closure_gap(gap: dict, tested_endpoints: set[str]) -> bool:
    """Return true when a path-only gap is only a parent of validated evidence.

    If `/rest/admin/application-configuration` is already validated, the parent
    `/rest/admin` may still be interesting as a route-enumeration clue, but it
    should not consume the immediate checkpoint queue as another Authz replay
    unless it has its own params/body/browser evidence.
    """
    endpoint = str(gap.get("endpoint") or "").strip()
    if not endpoint or not _is_path_only_authz_gap(gap):
        return False
    return any(_is_parent_endpoint(endpoint, tested) for tested in tested_endpoints)


def _coverage_family_shape(endpoint: str) -> tuple[str, str]:
    path = _normalise_endpoint_path(endpoint)
    if not path:
        return "", ""
    parts = [part for part in path.strip("/").split("/") if part]
    template_parts = [
        part for part in _route_template(path).strip("/").split("/") if part
    ]
    shape_parts: list[str] = []
    prefix_parts: list[str] = []
    dynamic_seen = False
    for index, part in enumerate(parts):
        template_part = template_parts[index] if index < len(template_parts) else part
        # Route discovery often emits tokens such as ``role-0`` that are
        # dynamic in practice but not normalized by the canonical template.
        segment_dynamic = template_part.startswith("{") or bool(
            re.search(r"(?:^|[-_])\d+$", part)
        )
        if segment_dynamic:
            shape_parts.append("{dynamic}")
            dynamic_seen = True
            continue
        if dynamic_seen:
            # Keep post-identifier resource names in the family key; two
            # different child resources must not collapse into one sample.
            shape_parts.append(part.casefold())
        else:
            shape_parts.append("{static}")
            prefix_parts.append(part.casefold())

    if dynamic_seen:
        # A path with no stable prefix is too ambiguous for structural merging.
        if not prefix_parts:
            return "/".join(shape_parts), ""
    else:
        # For static endpoint leaves, preserve the existing resource-parent
        # grouping (for example /api/orders/list and /api/orders/export).
        prefix_parts = [part.casefold() for part in parts[:2]]
    return "/".join(shape_parts), "/" + "/".join(prefix_parts)


def _coverage_family_key(gap: dict, template_count: dict[str, int]) -> tuple:
    endpoint = str(gap.get("endpoint") or "").strip()
    vuln_class = str(gap.get("vuln_class") or "").strip().casefold()
    reason = re.sub(r"\s+", " ", str(gap.get("relevance_reason") or "")).strip().casefold()
    template = _route_template(endpoint)
    if template_count.get(template, 0) > 1:
        return ("route-template", vuln_class, reason, template)
    shape, prefix = _coverage_family_shape(endpoint)
    if not vuln_class or not reason or not shape or not prefix:
        return ()
    return ("structural", vuln_class, reason, shape, prefix)


_STRUCTURAL_COVERAGE_FAMILY_MIN_MEMBERS = 3
_COVERAGE_FAMILY_MEMBER_PREVIEW = 12


def _checkpoint_coverage_gaps(coverage_gaps: list[dict], matrix: dict, limit: int = 2) -> list[dict]:
    """Select coverage gaps for the immediate checkpoint queue.

    Coverage itself keeps all untested cells.  The execution queue is stricter:
    it skips parent-only Authz closure gaps that are already represented by a
    validated child endpoint, and emits one representative for an existing
    route-template or high-volume structural family. This prevents noisy loops
    while preserving other high-signal gaps for Claude to reason over. The
    ``_projection_family`` field is advisory queue metadata; it never mutates a
    sibling Matrix cell or changes exact Action Queue identity.
    """
    tested_endpoints = _tested_finding_endpoints(matrix)
    eligible: list[dict] = []
    for gap in _actionable_coverage_gaps(coverage_gaps):
        if _is_parent_closure_gap(gap, tested_endpoints):
            continue
        eligible.append(gap)

    template_count: dict[str, int] = {}
    for gap in eligible:
        template = _route_template(str(gap.get("endpoint") or "").strip())
        template_count[template] = template_count.get(template, 0) + 1

    groups: dict[tuple, list[dict]] = {}
    order: list[tuple] = []
    for index, gap in enumerate(eligible):
        family_key = _coverage_family_key(gap, template_count)
        key = family_key or ("single", index)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(gap)

    selected: list[dict] = []
    for key in order:
        members = groups[key]
        if (
            key[0] == "structural"
            and len(members) < _STRUCTURAL_COVERAGE_FAMILY_MIN_MEMBERS
        ):
            for member in members:
                selected.append(dict(member))
                if len(selected) >= limit:
                    return selected
            continue
        representative = dict(members[0])
        if len(members) > 1 and key[0] in {"route-template", "structural"}:
            endpoints = [
                str(item.get("endpoint") or "").strip()
                for item in members
                if str(item.get("endpoint") or "").strip()
            ]
            representative["_projection_family"] = {
                "key": ":".join(str(value) for value in key),
                "kind": key[0],
                "size": len(members),
                "template": _route_template(endpoints[0]) if endpoints else "",
                # Keep queue context bounded; the family size tells AI whether
                # this is only a preview, and raw Coverage remains expandable.
                "members": endpoints[:_COVERAGE_FAMILY_MEMBER_PREVIEW],
            }
        selected.append(representative)
        if len(selected) >= limit:
            break
    return selected


def _next_proposals(
    state: dict,
    coverage_gaps: list[dict],
    matrix: dict,
    target: str,
    context_pack: dict,
    evidence_summary: dict,
    case_state: dict | None = None,
    repo_root: Path | None = None,
    ignored_actor_gap_endpoints: set[str] | None = None,
) -> list[str]:
    proposals: list[str] = []
    # Contradictions are Claude-facing advisory context, not executable work.
    # Promoting them into the action queue makes the tool steer the hunt back to
    # meta-review whenever a fresh dead-end shares tokens with cached evidence.
    # Keep them visible in checkpoint output and let the model decide whether
    # they matter for the next hypothesis.

    findings = _structured_findings(state)
    next_owner_revalidation = findings.get("next_owner_revalidation") or {}
    next_validation = findings.get("next_validation") or {}
    next_report = findings.get("next_report") or {}
    if next_owner_revalidation:
        proposals.append(
            "Owner-provenance recovery for finding {id} on {url}: it claims "
            "{validation}/{report} but provenance is {reason}. Treat it as a "
            "candidate, replay locatable raw evidence, then rerun /validate with "
            "the canonical finding id so finding_index records the transition. "
            "Do not report or resolve this claim from JSON alone.".format(
                id=next_owner_revalidation.get("id", "-"),
                url=next_owner_revalidation.get("url", ""),
                validation=next_owner_revalidation.get("claimed_validation_status", "-"),
                report=next_owner_revalidation.get("claimed_report_status", "-"),
                reason=next_owner_revalidation.get("provenance_reason", "owner-provenance-invalid"),
            )
        )
    if next_validation:
        rubric = next_validation.get("rubric") if isinstance(next_validation.get("rubric"), dict) else {}
        missing_items = []
        if rubric:
            missing_items = [
                str(item)
                for item in (rubric.get("missing_labels") or rubric.get("missing") or [])[:3]
                if str(item).strip()
            ]
        if rubric and (not rubric.get("ready", False) or missing_items):
            missing = ", ".join(missing_items)
            evidence_step = ""
            for action in rubric.get("next_actions") or []:
                evidence_step = str(action or "").strip()
                if evidence_step:
                    break
            proposals.append(
                "Candidate evidence gap for finding {id} on {url}: rubric={status}, "
                "missing={missing}. Next evidence step: {step}. Then rerun /validate "
                "when the smallest replayable impact proof is captured.".format(
                    id=next_validation.get("id", "-"),
                    url=next_validation.get("url", ""),
                    status=rubric.get("status", "needs-evidence"),
                    missing=missing or "candidate evidence",
                    step=evidence_step or "fill the missing candidate evidence item",
                )
            )
        proposals.append(
            "Run /validate for finding {id} on {url}; verify replay, A/B diff, "
            "impact, evidence rubric, and red-line safety before report.".format(
                id=next_validation.get("id", "-"),
                url=next_validation.get("url", ""),
            )
        )
    if next_report:
        proposals.append(
            "Draft report for validated finding {id}; do not submit without human review.".format(
                id=next_report.get("id", "-"),
            )
        )
    proposals.extend(_ledger_candidate_proposals(evidence_summary))
    proposals.extend(_runner_candidate_proposals(state))
    if not state.get("has_recon"):
        proposals.append(f"Run /recon {target}, then /surface {target}, then rerun /checkpoint {target}.")

    next_tool_hint = str(state.get("next_tool_hint") or "").strip()
    if next_tool_hint:
        hint = (state.get("enrichment_hints") or [{}])[0] or {}
        proposals.append(
            f"Run enrichment {next_tool_hint}: {str(hint.get('reason') or '').strip()}"
        )

    proposals.extend(_unsafe_skipped_proposals(state))
    proposals.extend(
        _secondary_sweep_proposals(
            state,
            repo_root=repo_root,
            target=target,
            evidence_summary=evidence_summary,
        )
    )
    covered_ledger_cells = _ledger_covered_cells(evidence_summary, matrix)

    source_summary = (
        context_pack.get("source_summary")
        if isinstance(context_pack.get("source_summary"), dict)
        else {}
    )
    if source_summary.get("viewstate_signal") is True:
        proposals.append(
            "ViewState integrity review: browser evidence exposes __VIEWSTATE. "
            "Save one target-owned fresh same-page GET baseline with __VIEWSTATEGENERATOR/__EVENTVALIDATION; first run tools/aspnet_viewstate_knownkey.py offline, then replay only a format control and single-byte __VIEWSTATE tamper without submitting a business action. "
            "Telerik absence only closes the Telerik branch and cannot make ViewState/deserialization N/A. Stop condition: the known-key branch has no match and tamper is uniformly rejected with no repeatable consume/state difference."
        )

    repo_source_summary = state.get("repo_source_summary") or {}
    secret_findings = int(repo_source_summary.get("secret_findings", 0) or 0)
    if secret_findings > 0:
        proposals.append(
            "Secret verification lane: repo/source artifacts contain {count} secret "
            "finding(s). Triage provider/type/source ownership, then run only the "
            "minimal safe identity/capability check or record a verification blocker; "
            "promote to Candidate only with validity/usability and impact path.".format(
                count=secret_findings,
            )
        )

    surface = state.get("surface") or {}
    for lead in _json_list(surface.get("workflow_leads"))[:5]:
        if str(lead.get("source") or "") != "evidence_convergence":
            continue
        title = str(lead.get("title") or "").strip()
        next_action = str(lead.get("next_action") or "").strip()
        evidence = str(lead.get("evidence") or lead.get("category") or "").strip()
        if title:
            proposals.append(
                "Cross-evidence high-value surface {title}: {evidence}. "
                "Next action: {next_action}. Stop condition: record tested, "
                "blocked, dead-end, signal, or candidate after focused replay.".format(
                    title=title,
                    evidence=evidence[:180],
                    next_action=next_action[:180] or "focused replay with source/JS/browser evidence",
                )
            )

    lane_summary = matrix.get("high_risk_lanes")
    if not isinstance(lane_summary, dict):
        lane_summary = high_risk_lane_summary(matrix)
    lane_order = (
        "SQLi", "SSRF", "XXE", "RCE", "Path", "Upload", "IDOR", "Authz",
        "GraphQL", "OAuth", "JWT", "CSRF", "Race", "Webhook", "XSS",
    )
    lane_review = []
    for name in lane_order:
        lane = lane_summary.get(name)
        if (
            not isinstance(lane, dict)
            or lane.get("disposition") not in {"queued", "unassessed", "not_observed", "blocked"}
        ):
            continue
        techniques = [str(value) for value in lane.get("techniques", []) if str(value).strip()]
        label = f"{name}[{','.join(techniques)}]" if techniques else name
        lane_review.append(f"{label}={lane.get('disposition')}")
    if lane_review and state.get("has_recon") and matrix.get("endpoints"):
        proposals.append(
            "High-risk lane review: {lanes}. For every listed family, use the smallest "
            "evidence-producing interface test (SQLi/NoSQLi, SSRF URL-fetch/OAST, "
            "XXE XML parser, RCE/SSTI/command/deserialization/upload, authz/IDOR, "
            "GraphQL/OAuth/JWT, Path/LFI/RFI, CSRF/Race/Webhook/XSS) or record an "
            "explicit blocked/not_applicable reason; never treat unassessed as clean."
            .format(lanes=", ".join(lane_review))
        )

    for gap in _checkpoint_coverage_gaps(coverage_gaps, matrix):
        if _ledger_covers_cell(
            covered_ledger_cells,
            str(gap.get("endpoint") or ""),
            str(gap.get("vuln_class") or ""),
            gap.get("identity_v2"),
        ):
            continue
        relevance = ""
        if int(gap.get("relevance_score", 0) or 0) > 0:
            reason = str(gap.get("relevance_reason") or "").strip()
            relevance = ", relevance={score}{reason}".format(
                score=gap.get("relevance_score", 0),
                reason=f": {reason}" if reason else "",
            )
        validation_path = _coverage_gap_validation_path(gap)
        validation_suffix = f" Validation path: {validation_path}" if validation_path else ""
        coverage_endpoint = str(gap.get("endpoint") or "")
        endpoint = str(gap.get("representative_endpoint") or coverage_endpoint)
        coverage_suffix = (
            f", coverage_endpoint={coverage_endpoint}"
            if endpoint != coverage_endpoint else ""
        )
        family = gap.get("_projection_family") if isinstance(gap.get("_projection_family"), dict) else {}
        family_suffix = ""
        if family:
            family_members = ",".join(
                str(value).strip()
                for value in family.get("members") or []
                if str(value).strip()
            )
            family_size = int(family.get("size", 0) or 0)
            preview_truncated = family_size > len(family.get("members") or [])
            expansion_suffix = (
                " The preview is incomplete; query the raw Coverage gap window "
                "before choosing another member."
                if preview_truncated else ""
            )
            family_suffix = (
                " Queue projection only: this representative is advisory and does "
                "not assert family equivalence. AI remains the judgment owner and "
                "may choose or expand any listed member; sibling Matrix cells stay "
                "unclosed until owner evidence.{expansion_suffix} Family projection: "
                "key={key}; kind={kind}; size={size}; "
                "members={members}.".format(
                    key=family.get("key", "family"),
                    kind=family.get("kind", "route-template"),
                    size=family_size,
                    members=family_members or coverage_endpoint,
                    expansion_suffix=expansion_suffix,
                )
            )
        proposals.append(
            "Cover high-value matrix gap: {endpoint} x {vuln_class} "
            "(weight={weight}{coverage_suffix}{relevance}).{validation_suffix} If concrete side-effect risk appears, mark blocked "
            "and use low-risk evidence instead.{family_suffix}".format(
                endpoint=endpoint,
                vuln_class=gap.get("vuln_class", ""),
                weight=gap.get("weight", ""),
                coverage_suffix=coverage_suffix,
                relevance=relevance,
                validation_suffix=validation_suffix,
                family_suffix=family_suffix,
            )
        )
    for gap in _actionable_actor_gaps(evidence_summary, case_state)[:3]:
        proposals.append(
            "Cover actor matrix gap: {endpoint} x {vuln} with {actor}/{scope}/{variant} "
            "expected={expected} status={status}. Record result with: {cmd}".format(
                endpoint=gap.get("endpoint", ""),
                vuln=gap.get("vuln_class", ""),
                actor=gap.get("actor", ""),
                scope=gap.get("object_scope", ""),
                variant=gap.get("variant", ""),
                expected=gap.get("expected", ""),
                status=gap.get("status", ""),
                cmd=evidence_record_command(target, gap),
            )
        )
    actor_enrichment = _actor_gap_enrichment_proposal(
        evidence_summary,
        case_state,
        ignored_actor_gap_endpoints,
    )
    if actor_enrichment:
        proposals.append(actor_enrichment)

    clean_authz_baselines = _recent_anonymous_authz_clean_count(evidence_summary)
    defer_role_ranked = (
        clean_authz_baselines >= 3
        and not _case_state_has_role_replay_context(case_state)
    )
    deferred_role_ranked = 0
    ranked_surface_added = 0
    ranked_state = _ranked_surface_state_with_matrix_paths(state, matrix)
    for item in (ranked_state.get("recommended_targets") or []):
        # Generate a small candidate window, not just the first two. Persistent
        # action_queue final-state filtering happens after this function; if
        # the first P1 items were already closed, we still need fresh ranked
        # surfaces behind them so /autopilot does not hand off prematurely.
        if ranked_surface_added >= 4:
            break
        url = str(item.get("url") or "").strip()
        suggested = str(item.get("suggested") or "").strip()
        endpoint_path = _normalise_endpoint_path(url)
        if url:
            entry = _ranked_surface_entry(ranked_state, item.get("url") or "")
            vuln_hint = _ranked_surface_vuln_hint(entry, url)
            concrete_endpoint = _placeholder_concrete_endpoint(url, case_state)
            concrete_endpoint_path = _normalise_endpoint_path(concrete_endpoint)
            placeholder_object_closed = bool(
                concrete_endpoint_path
                and _non_concrete_object_segments(url)
                and _ledger_covers_cell(covered_ledger_cells, concrete_endpoint_path, "IDOR")
            )
            if (
                _ledger_covers_cell(covered_ledger_cells, endpoint_path, vuln_hint)
                or _ledger_covers_cell(covered_ledger_cells, concrete_endpoint_path, vuln_hint)
                or placeholder_object_closed
            ):
                continue
            if defer_role_ranked and _ranked_surface_context_prereq(ranked_state, item, case_state):
                deferred_role_ranked += 1
                continue
            replay_draft = _ranked_surface_replay_draft(ranked_state, item, case_state, target=target)
            replay_suffix = f". Replay draft: {replay_draft.rstrip('.')}" if replay_draft else ""
            ledger_skeleton = _ranked_surface_ledger_skeleton(ranked_state, item, target, replay_draft, case_state)
            ledger_suffix = f". Ledger skeleton: {ledger_skeleton}" if ledger_skeleton else ""
            reason = str(item.get("review_reason") or "advisory surface evidence").strip()
            proposals.append(
                f"Review surface candidate {url}: {suggested}. "
                f"Reason: {reason}. AI decision required: choose the exact lane, "
                f"capture missing browser/source/actor evidence, or defer with evidence"
                f"{replay_suffix}{ledger_suffix}"
            )
            ranked_surface_added += 1
    if deferred_role_ranked:
        proposals.append(_case_state_acquisition_proposal(deferred_role_ranked, clean_authz_baselines))
    # 先按 action 类型保留代表，再填满窗口；同类 finding/runner 条目不能把
    # coverage、actor 或 ranked-surface 永久挤出 durable queue。
    return _bounded_next_proposals(proposals, target)


def _classify_next_action(text: str, target: str = "") -> tuple[str, int, str]:
    """把 checkpoint 的自然语言建议归类成 Claude 可消费的执行队列。"""
    value = str(text or "").strip()
    lowered = value.lower()
    replay_match = re.search(
        r"Exact replay draft:\s+(?P<cmd>.*?)(?:\.\s+(?:Required evidence|Missing evidence|Downgrade rule|Stop condition|Write-back|Chain extensions if blocked):|$)",
        value,
        re.I,
    )
    replay_hint = replay_match.group("cmd").strip() if replay_match else ""
    if "case-state validation backlog" in lowered:
        return "case-state-validation", 110, replay_hint or "python3 tools/validation_runner.py ... --from-case-state"
    if "case-state enrichment backlog" in lowered:
        return "case-state-enrichment", 108, "enrich actor/session/object/private-marker evidence in case_state"
    if "case-state recovery backlog" in lowered:
        return "case-state-enrichment", 108, "complete the recorded hypothesis recovery step before creating a fresh backlog"
    if "case-state acquisition lead" in lowered:
        return "case-state-enrichment", 66, "capture/register actors, sessions, and owned objects with tools/target_case_state.py"
    if "case-state enrichment lead" in lowered:
        return "case-state-enrichment", 54, "register actor/session/object with tools/target_case_state.py or review tools/case_state_seed.py"
    if "case-state backlog creation" in lowered:
        return "case-state-backlog-create", 103, "promote the active hypothesis into validation backlog"
    if "case-state endpoint discovery lead" in lowered:
        return "case-state-enrichment", 66, "identify concrete object endpoint from browser/source evidence, then update case_state"
    if "case-state seed opportunity" in lowered:
        seed_match = re.search(r"Next:\s+(?P<cmd>python3\s+tools/case_state_seed\.py\s+.*?)(?:\.\s+Review|$)", value, re.I)
        return "case-state-seed", 99, seed_match.group("cmd").strip() if seed_match else "python3 tools/case_state_seed.py --target <target> --json"
    if "candidate evidence gap" in lowered:
        return "candidate-evidence-gap", 105, "fill missing rubric evidence, then /validate"
    if "run /validate" in lowered:
        return "validation", 100, "/validate"
    if "draft report" in lowered:
        return "report", 90, "/report"
    if "review context contradiction" in lowered:
        quoted_target = _quote(target) if target else "target.com"
        return "context-review", 90, f"python3 tools/context_pack.py --target {quoted_target}"
    if "run /recon" in lowered:
        quoted_target = _quote(target) if target else "target.com"
        return (
            "recon",
            85,
            "python3 tools/hunt.py --target {target} --recon-only && "
            "python3 tools/surface.py --target {target} && "
            "python3 tools/checkpoint.py --target {target}".format(target=quoted_target),
        )
    if "actor matrix gap" in lowered:
        return "actor-gap", 96, "focused replay + tools/evidence_ledger.py record"
    if "action-gated scanner lane" in lowered or "unsafe-skipped scanner lane" in lowered:
        return "action-gated-review", 93, "review legacy unsafe_skipped.txt; resolve queue with tested/blocked/dead-end/n/a/candidate"
    if "high-risk lane review" in lowered:
        return "high-risk-lane-review", 92, "focused interface test or explicit blocked/not_applicable disposition"
    if "viewstate integrity review" in lowered:
        return "viewstate-integrity-review", 93, "offline project machineKey check, then one format control and one-byte ViewState tamper; Telerik absence is not N/A"
    if "secondary-sweep lead" in lowered:
        if "[public-metadata]" in lowered:
            return "secondary-sweep", 52, "review public metadata only for unusual fields or chain pivots"
        return "secondary-sweep", 72, "review demoted raw artifact; re-promote only with concrete secret/chain evidence"
    if "high-value matrix gap" in lowered:
        return "coverage-gap", 94, "focused low-risk probe + evidence ledger"
    if "cross-evidence high-value surface" in lowered:
        return "evidence-convergence", 98, "focused replay with browser/JS/source evidence"
    if "secret verification lane" in lowered:
        return "secret-verification", 86, "python3 tools/secret_triage.py --file findings/<target>/exposure/repo_secrets.json"
    if "collect_browser_mcp_evidence" in lowered:
        return "browser-enrichment", 70, "Chrome DevTools/Playwright MCP capture, import artifacts, then /surface"
    if "run enrichment run_source_intel" in lowered:
        return "source-enrichment", 70, "python3 tools/source_intel.py"
    if "run enrichment run_js_read" in lowered:
        return "js-enrichment", 70, "python3 tools/js_reader.py"
    if "review surface candidate" in lowered:
        return "surface-review", 70, "AI reviews surface evidence, then chooses the exact lane"
    if "continue top ranked surface" in lowered:
        return "ranked-surface", 70, "AI reviews ranked surface evidence, then chooses the exact lane"
    return "next-action", 50, "execute the smallest safe evidence-producing step"


def _bounded_next_proposals(
    proposals: list[str],
    target: str,
    limit: int = 8,
) -> list[str]:
    """保留 action 类型多样性，再用既有优先级填充固定窗口。"""
    deduped = _dedupe(proposals)
    classified = [
        (index, proposal, *_classify_next_action(proposal, target)[:2])
        for index, proposal in enumerate(deduped)
    ]
    first_by_type: dict[str, tuple[int, str, str, int]] = {}
    for item in classified:
        first_by_type.setdefault(item[2], item)

    representatives = sorted(
        first_by_type.values(),
        key=lambda item: (-item[3], item[0]),
    )[:limit]
    selected = {item[0] for item in representatives}
    if len(selected) < limit:
        for item in sorted(classified, key=lambda value: (-value[3], value[0])):
            selected.add(item[0])
            if len(selected) >= limit:
                break
    return [proposal for index, proposal in enumerate(deduped) if index in selected]


def _extract_action_metadata(text: str) -> dict:
    """从 checkpoint 的动作文本中提取可机器消费的轻量字段。

    target_write_back 仍保持人类可读文本；action queue 额外保存这些字段，
    让后续执行/resolve 不必重新从自然语言猜 endpoint 和漏洞类型。
    """
    value = str(text or "").strip()
    metadata: dict = {}
    hypothesis_id_match = re.search(r"Hypothesis ID:\s+(?P<value>[A-Za-z0-9_-]+)", value, re.I)
    if hypothesis_id_match:
        metadata["hypothesis_id"] = hypothesis_id_match.group("value")
    case_state_match = re.search(
        r"Case-state\s+(?:validation backlog|enrichment backlog|recovery backlog|backlog creation)\s+(?P<backlog_id>[A-Za-z0-9_-]+)",
        value,
        re.I,
    )
    if case_state_match:
        metadata["backlog_id"] = case_state_match.group("backlog_id")
        for key, pattern in (
            ("runner", r"Runner:\s+(?P<value>[^.]+)"),
            ("object_ref", r"Object ref:\s+(?P<value>[^.]+)"),
            ("endpoint", r"Endpoint:\s+(?P<value>\S+)"),
            ("downgrade_rule", r"Downgrade rule:\s+(?P<value>.*?)(?:\.\s+(?:Stop condition|Write-back|Chain extensions if blocked):|$)"),
            ("stop_condition", r"Stop condition:\s+(?P<value>.*?)(?:\.\s+(?:Write-back|Chain extensions if blocked):|$)"),
            ("write_back", r"Write-back:\s+(?P<value>.*?)(?:\.\s+(?:Chain extensions if blocked|Recovery next action):|$)"),
            ("hypothesis", r"Hypothesis:\s+(?P<value>.*?)(?:\.\s+(?:Hypothesis ID|Why now):|$)"),
            ("why_now", r"Why now:\s+(?P<value>.*?)(?:\.\s+(?:Runner|Actors|Object ref|Endpoint|Exact replay draft|Write-back|Chain extensions if blocked|Recovery next action):|$)"),
            ("recovery_next_action", r"Recovery next action:\s+(?P<value>.*?)(?:\.$|$)"),
        ):
            match = re.search(pattern, value, re.I)
            if match:
                clean = match.group("value").strip()
                if key == "endpoint":
                    clean = clean.rstrip(".")
                metadata[key] = clean

        actors_match = re.search(
            r"Actors:\s+owner=(?P<owner>[^,]+),\s+peer=(?P<peer>[^.]+)",
            value,
            re.I,
        )
        if actors_match:
            metadata["owner_actor"] = actors_match.group("owner").strip()
            metadata["peer_actor"] = actors_match.group("peer").strip()

        for key, pattern in (
            ("replay_draft", r"Exact replay draft:\s+(?P<value>.*?)(?:\.\s+(?:Required evidence|Missing evidence|Downgrade rule|Stop condition|Write-back|Chain extensions if blocked):|$)"),
            ("required_evidence", r"Required evidence:\s+(?P<value>.*?)(?:\.\s+(?:Missing evidence|Optional evidence gaps|Downgrade rule|Stop condition|Write-back|Chain extensions if blocked):|$)"),
            ("missing_evidence", r"Missing evidence:\s+(?P<value>.*?)(?:\.\s+(?:Optional evidence gaps|Downgrade rule|Stop condition|Write-back|Chain extensions if blocked):|$)"),
            ("optional_evidence_gaps", r"Optional evidence gaps:\s+(?P<value>.*?)(?:\.\s+(?:Downgrade rule|Stop condition|Write-back|Chain extensions if blocked):|$)"),
            ("chain_extensions_if_blocked", r"Chain extensions if blocked:\s+(?P<value>.*?)(?:\.\s+Recovery next action:|\.$|$)"),
        ):
            match = re.search(pattern, value, re.I)
            if match:
                raw = match.group("value").strip()
                if key in {"required_evidence", "missing_evidence", "optional_evidence_gaps", "chain_extensions_if_blocked"}:
                    metadata[key] = [part.strip() for part in raw.split(",") if part.strip()]
                else:
                    metadata[key] = raw
        return metadata

    seed_match = re.search(
        r"Case-state seed opportunity:\s+Found object candidate\s+(?P<object_ref>\S+)\s+"
        r"type=(?P<object_type>\S+)\s+endpoint=(?P<endpoint>\S+)\.\s+"
        r"Runner:\s+(?P<runner>\S+)\.\s+Missing evidence:\s+(?P<missing>.*?)(?:\.\s+Next:|$)",
        value,
        re.I,
    )
    if seed_match:
        metadata.update({
            "object_ref": seed_match.group("object_ref"),
            "object_type": seed_match.group("object_type"),
            "endpoint": seed_match.group("endpoint"),
            "runner": seed_match.group("runner"),
            "missing_evidence": [
                part.strip()
                for part in seed_match.group("missing").split(",")
                if part.strip() and part.strip() != "review required"
            ],
        })
        command_match = re.search(r"Next:\s+(?P<cmd>python3\s+tools/case_state_seed\.py\s+.*?)(?:\.\s+Review|$)", value, re.I)
        if command_match:
            metadata["seed_command"] = command_match.group("cmd").strip()
        return metadata

    endpoint_seed_match = re.search(
        r"Case-state endpoint discovery lead:\s+Found object candidate\s+(?P<object_ref>\S+)\s+"
        r"type=(?P<object_type>\S+)\s+endpoint=(?P<endpoint>\S+)\.\s+"
        r"Runner:\s+(?P<runner>\S+)\.\s+Missing evidence:\s+(?P<missing>.*?)(?:\.\s+Next action:|$)",
        value,
        re.I,
    )
    if endpoint_seed_match:
        metadata.update({
            "object_ref": endpoint_seed_match.group("object_ref"),
            "object_type": endpoint_seed_match.group("object_type"),
            "endpoint": endpoint_seed_match.group("endpoint"),
            "runner": endpoint_seed_match.group("runner"),
            "missing_evidence": [
                part.strip()
                for part in endpoint_seed_match.group("missing").split(",")
                if part.strip() and part.strip() != "review required"
            ],
        })
        command_match = re.search(r"Seed command:\s+(?P<cmd>python3\s+tools/case_state_seed\.py\s+.*?)(?:\.\s+Stop condition:|$)", value, re.I)
        if command_match:
            metadata["seed_command"] = command_match.group("cmd").strip()
        return metadata

    enrichment_match = re.search(
        r"Case-state enrichment lead:.*?Example:\s+"
        r"(?P<endpoint>\S+)\s+x\s+(?P<vuln>[A-Za-z0-9_-]+)\s+with\s+"
        r"(?P<actor>[^/]+)/(?P<object_scope>[^/]+)/(?P<variant>\S+).*?"
        r"Missing evidence:\s+(?P<missing>.*?)(?:\.\s+Next:|$)",
        value,
        re.I,
    )
    if enrichment_match:
        metadata.update({
            "endpoint": enrichment_match.group("endpoint"),
            "vuln_class": enrichment_match.group("vuln"),
            "actor": enrichment_match.group("actor"),
            "object_scope": enrichment_match.group("object_scope"),
            "variant": enrichment_match.group("variant").rstrip("."),
            "missing_evidence": [
                part.strip()
                for part in enrichment_match.group("missing").split(",")
                if part.strip()
            ],
        })
        return metadata

    acquisition_match = re.search(
        r"Case-state acquisition lead:\s+(?P<clean>\d+)\s+recent anonymous Authz "
        r"baseline\(s\).*?and\s+(?P<deferred>\d+)\s+ranked role/object surface\(s\)",
        value,
        re.I,
    )
    if acquisition_match:
        metadata.update({
            "clean_authz_baselines": int(acquisition_match.group("clean")),
            "deferred_role_surfaces": int(acquisition_match.group("deferred")),
            "missing_evidence": ["actor", "session", "business object"],
        })
        return metadata

    validation_match = re.search(
        r"Validation path:\s+(?P<path>.*?)(?:\s+If red-line|"
        r"\s+If concrete side-effect|\s+Queue projection only:|"
        r"\s+Family projection:|"
        r"\s+Stop condition:|$)",
        value,
        re.I,
    )

    match = re.search(
        r"Cover high-value matrix gap:\s+(?P<endpoint>\S+)\s+x\s+"
        r"(?P<vuln>[A-Za-z0-9_-]+)\s+\(weight=(?P<weight>[^,\)]+)"
        r"(?:,\s*coverage_endpoint=(?P<coverage_endpoint>[^,\)]+))?"
        r"(?:,\s*relevance=(?P<score>\d+)(?::\s*(?P<reason>[^\)]+))?)?\)",
        value,
    )
    if match:
        metadata.update({
            "endpoint": match.group("endpoint"),
            "vuln_class": match.group("vuln"),
            "weight": match.group("weight"),
        })
        if match.group("score"):
            metadata["relevance_score"] = int(match.group("score"))
        if match.group("coverage_endpoint"):
            metadata["coverage_endpoint"] = match.group("coverage_endpoint").strip()
        if match.group("reason"):
            metadata["relevance_reason"] = match.group("reason").strip()
        if validation_match:
            metadata["validation_path"] = validation_match.group("path").strip()
        family_match = re.search(
            r"Family projection:\s+key=(?P<key>.*?);\s+kind=(?P<kind>[^;]+);"
            r"\s+size=(?P<size>\d+);\s+(?:members|samples)=(?P<members>.*?)\.\s*$",
            value,
            re.I,
        )
        if family_match:
            metadata.update({
                "family_key": family_match.group("key").strip(),
                "family_projection": family_match.group("kind").strip(),
                "family_size": int(family_match.group("size")),
                "family_members": [
                    part.strip()
                    for part in family_match.group("members").split(",")
                    if part.strip()
                ],
            })
        return metadata

    match = re.search(
        r"Cover actor matrix gap:\s+(?P<endpoint>\S+)\s+x\s+"
        r"(?P<vuln>[A-Za-z0-9_-]+)\s+with\s+"
        r"(?P<actor>[^/]+)/(?P<object_scope>[^/]+)/(?P<variant>\S+)",
        value,
    )
    if match:
        metadata.update({
            "endpoint": match.group("endpoint"),
            "vuln_class": match.group("vuln"),
            "actor": match.group("actor"),
            "object_scope": match.group("object_scope"),
            "variant": match.group("variant"),
        })

    match = re.search(
        r"Review (?:action-gated|unsafe-skipped) scanner lane\s+(?P<unsafe_id>[a-f0-9]{8,64}|-)"
        r".*?Artifact=(?P<artifact>\S*unsafe_skipped\.txt)",
        value,
        re.I,
    )
    if match:
        unsafe_id = match.group("unsafe_id")
        metadata.update({
            "unsafe_skipped_id": "" if unsafe_id == "-" else unsafe_id,
            "artifact": match.group("artifact"),
        })

    match = re.search(
        r"(?:Candidate evidence gap|Run /validate) for finding\s+(?P<finding_id>[^;\s]+)",
        value,
        re.I,
    )
    if match:
        metadata["finding_id"] = match.group("finding_id").strip().rstrip(".")

    match = re.search(r"Draft report for validated finding\s+(?P<finding_id>[^;\s]+)", value, re.I)
    if match:
        metadata["finding_id"] = match.group("finding_id").strip().rstrip(".")

    match = re.search(
        r"Secondary-sweep lead\s+\[(?P<category>[^\]]+)\]:\s+(?P<title>.*?)[.]\s+Artifact=(?P<artifact>\S+)",
        value,
        re.I,
    )
    if match:
        metadata.update({
            "lead_category": match.group("category").strip(),
            "lead_title": match.group("title").strip(),
            "artifact": match.group("artifact").strip().rstrip("."),
        })

    match = re.search(
        r"Evidence:\s+Workflow lead:\s+(?P<title>.*?)[.]\s+Why it matters:.*?"
        r"Category=(?P<category>[^.\s]+)\.\s+(?:Artifact=(?P<artifact>\S+)\.\s+)?"
        r"Next action:",
        value,
        re.I,
    )
    if match:
        metadata.update({
            "lead_category": match.group("category").strip(),
            "lead_title": match.group("title").strip(),
        })
        if match.group("artifact"):
            metadata["artifact"] = match.group("artifact").strip().rstrip(".")

    match = re.match(
        r"(?:Continue top ranked surface|Review surface candidate)\s+(?P<url>\S+):\s*(?P<rest>.*)$",
        value,
        re.I,
    )
    if match:
        rest = match.group("rest").strip()
        ledger_skeleton = ""
        if "Ledger skeleton:" in rest:
            rest, ledger_skeleton = rest.split("Ledger skeleton:", 1)
        suggested = rest
        replay_draft = ""
        if "Replay draft:" in rest:
            suggested, replay_draft = rest.split("Replay draft:", 1)
        metadata.update({
            "url": match.group("url"),
            "endpoint": _canonicalize_url_path(match.group("url")),
            "suggested": suggested.strip().rstrip("."),
        })
        if replay_draft.strip():
            metadata["replay_draft"] = replay_draft.strip().rstrip(".")
        if ledger_skeleton.strip():
            metadata["ledger_record_skeleton"] = ledger_skeleton.strip()

    return metadata


def _artifact_category_identity(item: dict) -> str:
    metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
    artifact = str(metadata.get("artifact") or "").strip()
    category = str(
        metadata.get("category")
        or metadata.get("lead_category")
        or ""
    ).strip().lower()
    if not artifact or not category:
        return ""
    normalized_artifact = artifact.replace("\\", "/").strip().rstrip("/").lower()
    return f"{normalized_artifact}::{category}"


def _dedupe_artifact_category_items(items: list[dict]) -> list[dict]:
    """Keep one queue projection for each artifact/category lead."""
    result: list[dict] = []
    positions: dict[str, int] = {}
    for item in items:
        identity = _artifact_category_identity(item)
        if not identity or identity not in positions:
            if identity:
                positions[identity] = len(result)
            result.append(item)
            continue
        index = positions[identity]
        existing = result[index]
        if (
            str(item.get("source") or "") == "workflow-lead"
            and str(existing.get("source") or "") != "workflow-lead"
        ):
            result[index] = item
    return result


def _build_next_action_queue(next_items: list[str], target: str = "") -> list[dict]:
    queue: list[dict] = []
    for idx, item in enumerate(next_items, 1):
        action_type, priority, command_hint = _classify_next_action(item, target)
        metadata = _extract_action_metadata(item)
        row = {
            "id": f"A{idx}",
            "priority": priority,
            "type": action_type,
            "status": "ready",
            "action": item,
            "command_hint": command_hint,
            # Checkpoint projects an explicit flag; it does not infer a
            # red-line requirement from an action type or its wording.
            "redline_required": False,
            "stop_condition": (
                "record tested, blocked, dead-end, candidate, or validated finding "
                "before moving to the next queued action"
            ),
        }
        if metadata:
            row["metadata"] = metadata
        queue.append(row)
    queue.sort(key=lambda item: (-int(item["priority"]), str(item["id"])))
    return queue

_ACTIVATABLE_ACTION_TYPES = {
    "validation", "candidate-evidence-gap", "case-state-validation", "actor-gap",
    "coverage-gap", "evidence-convergence", "json-inject-review", "sql-matrix-review",
}
_ACTIVATION_EVIDENCE_ROOTS = {".private", "evidence", "findings", "recon", "reports"}


def _capability_chain_review_item(
    repo: Path,
    target: str,
    queue: dict | None = None,
) -> dict:
    """Project one unreviewed, evidence-backed primitive from the durable Queue."""
    queue = queue if queue is not None else load_action_queue(repo, target)
    actions = [item for item in queue.get("actions", []) if isinstance(item, dict)]
    reviews = [item for item in actions if str(item.get("type") or "") == "capability-chain-review"]
    if any(str(item.get("status") or "queued") in ACTION_QUEUE_ACTIVE_STATUSES for item in reviews):
        return {}

    reviewed = {
        (
            str(item.get("source_id") or ""),
            str((item.get("metadata") or {}).get("generation") or ""),
        )
        for item in reviews
        if str(item.get("status") or "") in ACTION_QUEUE_ACTIVE_STATUSES | ACTION_QUEUE_FINAL_STATUSES
        and isinstance(item.get("metadata"), dict)
    }
    chain_parents = {
        str((item.get("metadata") or {}).get("parent_action_id") or "")
        for item in actions
        if isinstance(item.get("metadata"), dict)
        and str((item.get("metadata") or {}).get("continuation_kind") or "").lower() == "chain"
    }
    candidates: list[tuple[str, str, dict, dict]] = []
    for parent in actions:
        parent_id = str(parent.get("id") or "").strip()
        metadata = parent.get("metadata") if isinstance(parent.get("metadata"), dict) else {}
        continuation = metadata.get("continuation") if isinstance(metadata.get("continuation"), dict) else {}
        if (
            not parent_id
            or metadata.get("depth_contract_version") != 1
            or str(parent.get("status") or "") not in ACTION_QUEUE_FINAL_STATUSES
            or str(continuation.get("kind") or "").lower() == "chain"
            or parent_id in chain_parents
        ):
            continue
        primitives = metadata.get("capability_primitives")
        if not isinstance(primitives, list):
            continue
        for raw in primitives:
            if not isinstance(raw, dict):
                continue
            capability = re.sub(r"\s+", " ", str(raw.get("capability") or "")).strip()[:240]
            hint = re.sub(r"\s+", " ", str(raw.get("continuation_hint") or "")).strip()[:300]
            evidence_ref = action_queue_target_owned_evidence_ref(repo, target, raw.get("evidence_ref"))
            if not capability or not hint or not evidence_ref:
                continue
            primitive = {
                "capability": capability,
                "evidence_ref": evidence_ref,
                "continuation_hint": hint,
            }
            normalized = {
                "capability": capability.casefold(),
                "evidence_ref": evidence_ref,
                "continuation_hint": hint.casefold(),
            }
            fingerprint = hashlib.sha256(
                json.dumps(normalized, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            if (parent_id, fingerprint) not in reviewed:
                candidates.append((parent_id, fingerprint, parent, primitive))

    if not candidates:
        return {}
    parent_id, fingerprint, parent, primitive = min(candidates, key=lambda item: (item[0], item[1]))
    parent_metadata = parent.get("metadata") if isinstance(parent.get("metadata"), dict) else {}
    return {
        "id": f"CHAIN-{parent_id}-{fingerprint[:12]}",
        "priority": 40,
        "type": "capability-chain-review",
        "status": "ready",
        "action": (
            f"Review capability primitive from {parent_id}: {primitive['capability']}. "
            f"Assess one bounded continuation: {primitive['continuation_hint']}"
        ),
        "command_hint": "add one normal versioned chain action before resolving this review, or record dead-end/blocked",
        "redline_required": False,
        "stop_condition": "materialize at most one evidence-backed chain action or record dead-end/blocked",
        "source": "hypothesis-loop",
        "source_id": parent_id,
        "metadata": {
            "generation": fingerprint,
            "parent_action_id": parent_id,
            "parent_hypothesis_id": str(parent_metadata.get("hypothesis_id") or "")[:160],
            "primitive_lineage": primitive,
            "primitive_fingerprint": fingerprint,
        },
    }


def _target_owned_context_refs(repo: Path, target: str, action: dict, context: dict) -> list[str]:
    metadata = action.get("metadata") if isinstance(action.get("metadata"), dict) else {}
    candidates = [
        metadata.get("evidence_ref"),
        metadata.get("summary_path"),
        metadata.get("artifact"),
        *(context.get("must_read") or []),
    ]
    target_key = target_storage_key(canonical_target_value(target))
    candidates.extend([
        f"recon/{target_key}/surface/summary.json",
        f"evidence/{target_key}/coverage_matrix.json",
    ])
    refs: list[str] = []
    for raw in candidates:
        value = str(raw or "").strip()
        if not value:
            continue
        path = Path(value)
        if not path.is_absolute():
            path = repo / path
        try:
            relative = path.resolve().relative_to(repo.resolve())
        except (OSError, ValueError):
            continue
        if (
            not relative.parts
            or relative.parts[0] not in _ACTIVATION_EVIDENCE_ROOTS
            or target_key not in relative.parts
            or not path.is_file()
        ):
            continue
        ref = str(relative)
        if ref not in refs:
            refs.append(ref)
        if len(refs) >= 4:
            break
    return refs


def _activation_endpoint(action: dict, *, repo: Path | None = None, refs: list[str] | None = None) -> str:
    metadata = action.get("metadata") if isinstance(action.get("metadata"), dict) else {}
    endpoint = str(metadata.get("endpoint") or metadata.get("url") or "").strip()
    if not endpoint:
        candidates = metadata.get("candidates") if isinstance(metadata.get("candidates"), list) else []
        if candidates and isinstance(candidates[0], dict):
            endpoint = str(candidates[0].get("endpoint") or "").strip()
    if endpoint:
        return endpoint.rstrip(".,;)")
    text = " ".join(str(action.get(key) or "") for key in ("action", "command_hint"))
    match = re.search(r"https?://[^\s,;]+|(?<![A-Za-z0-9])/[A-Za-z0-9][^\s,;]*", text)
    if match:
        return match.group(0).rstrip(".,;)")
    for ref in refs or []:
        if repo is None:
            break
        try:
            evidence = (repo / ref).read_text(encoding="utf-8", errors="ignore")[:120_000]
        except OSError:
            continue
        match = re.search(r"https?://[^\s\"',;]+|\"(?:path|route|endpoint)\"\s*:\s*\"([^\"]+)\"", evidence)
        if match:
            return (match.group(1) or match.group(0)).rstrip(".,;)")
    return ""


def _activation_method(action: dict, *, repo: Path | None = None, refs: list[str] | None = None) -> str:
    metadata = action.get("metadata") if isinstance(action.get("metadata"), dict) else {}
    method = str(metadata.get("method") or "").strip().upper()
    text = " ".join(
        str(value or "")
        for value in (metadata.get("replay_draft"), action.get("action"), action.get("command_hint"))
    )
    if not method:
        match = re.search(r"(?:--method\s+|\b)(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\b", text, re.I)
        method = match.group(1).upper() if match else ""
    if not method and str(action.get("type") or "") == "json-inject-review":
        method = "POST"
    if not method and str(action.get("type") or "") == "sql-matrix-review":
        method = "POST" if str(metadata.get("lane") or "") == "form" else "GET"
    if not method and "validation_runner.py" in text:
        method = "GET"
    if not method:
        for ref in refs or []:
            if repo is None:
                break
            try:
                evidence = (repo / ref).read_text(encoding="utf-8", errors="ignore")[:120_000]
            except OSError:
                continue
            match = re.search(r"\"method\"\s*:\s*\"(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\"", evidence, re.I)
            if match:
                method = match.group(1).upper()
                break
    return method


def _activation_input_boundary(action: dict, endpoint: str) -> str:
    metadata = action.get("metadata") if isinstance(action.get("metadata"), dict) else {}
    for key in ("input_boundary", "field", "object_ref", "backlog_id", "vuln_class"):
        value = str(metadata.get(key) or "").strip()
        if value:
            return value[:160]
    parsed = urlparse(endpoint)
    query = parsed.query if parsed.scheme or parsed.netloc else endpoint.partition("?")[2]
    if query:
        return query.split("=", 1)[0][:160]
    return "endpoint" if endpoint else ""


def _attach_activation_context(
    actions: list[dict],
    *,
    repo: Path,
    target: str,
    context: dict,
) -> list[dict]:
    knowledge_refs = [str(value) for value in (context.get("knowledge_cards") or []) if str(value).strip()][:4]
    for action in actions:
        if not isinstance(action, dict) or str(action.get("type") or "") not in _ACTIVATABLE_ACTION_TYPES:
            continue
        metadata = action.setdefault("metadata", {})
        if not isinstance(metadata, dict):
            continue
        refs = _target_owned_context_refs(repo, target, action, context)
        endpoint = _activation_endpoint(action, repo=repo, refs=refs)
        method = _activation_method(action, repo=repo, refs=refs)
        boundary = _activation_input_boundary(action, endpoint)
        action_type = str(action.get("type") or "")
        if action_type == "evidence-convergence" and len(refs) < 2:
            continue
        if not refs or not endpoint or not method or not boundary:
            continue
        metadata.update({
            "activation_required": True,
            "knowledge_refs": knowledge_refs,
            "evidence_ref": refs[-1],
            "evidence_refs": refs,
            "baseline_ref": refs[0],
            "max_hypothesis_actions_cap": 4,
            "endpoint": endpoint,
            "method": method,
            "input_boundary": boundary,
        })
        action["activation_required"] = True
    return actions

def _json_inject_queue_item(state: dict, target: str = "") -> dict:
    projection = state.get("json_inject") or {}
    status = str(projection.get("status") or "")
    generation = str(projection.get("input_fingerprint") or "")
    if status not in {"candidate_pending", "partial", "invalid_input"} or not generation:
        return {}
    action = {
        "candidate_pending": "Review JSON injection candidates and validate locatable raw evidence.",
        "partial": "Resume the JSON injection lane after resolving its recorded transport or evidence blocker.",
        "invalid_input": "Review the rejected JSON endpoint input and supply an in-scope POST endpoint.",
    }[status]
    plan_ref = str(projection.get("waf_plan_ref") or "").strip()
    resolved_target = str(target or state.get("resolved_target") or state.get("target") or "").strip()
    raw_source_paths = projection.get("source_paths")
    source_paths = [
        str(path).strip()
        for path in (raw_source_paths if isinstance(raw_source_paths, list) else [])
        if str(path).strip()
    ][:3]
    raw_source_refs = projection.get("source_refs")
    source_refs = [
        ref for ref in (raw_source_refs if isinstance(raw_source_refs, list) else [])
        if isinstance(ref, dict) and str(ref.get("path") or "").strip()
    ][:3]
    command_hint = (
        "python3 -m tools.json_inject_probe --target "
        f"{_quote(resolved_target)}"
    )
    emitted_sources = False
    emitted_waf_plan = False
    for ref in source_refs:
        kind = str(ref.get("kind") or "").strip().lower()
        path = str(ref.get("path") or "").strip()
        flag = {"endpoints": "--endpoints-file", "js-intel": "--js-intel", "waf-plan": "--waf-plan"}.get(kind)
        if flag and path:
            command_hint += f" {flag} {_quote(path)}"
            emitted_sources = True
            emitted_waf_plan = emitted_waf_plan or kind == "waf-plan"
    if source_paths and not emitted_sources:
        command_hint += f" --endpoints-file {_quote(source_paths[0])}"
    if plan_ref and not emitted_waf_plan:
        command_hint += f" --waf-plan {_quote(plan_ref)}"
    return {
        "id": "JSON-INJECT",
        "priority": 88 if status == "candidate_pending" else 62,
        "type": "json-inject-review",
        "status": "ready",
        "action": action,
        "command_hint": command_hint,
        "redline_required": False,
        "stop_condition": "record candidate validation, complete_no_hit, or the explicit blocker",
        "source": "json-inject",
        "source_id": "json-inject-lane",
        "metadata": {
            "generation": generation,
            "summary_path": str(projection.get("path") or ""),
            "summary_status": status,
            "source_paths": source_paths,
            "source_refs": source_refs,
            "waf_plan_ref": plan_ref,
            "waf_plan_sha256": str(projection.get("waf_plan_sha256") or ""),
            "waf_ai_variants_executed": int(projection.get("waf_ai_variants_executed", 0) or 0),
        },
    }


def _sql_matrix_queue_items(state: dict, target: str) -> list[dict]:
    """Project unfinished query/form SQL summaries into durable work."""
    matrix = state.get("sql_matrix") if isinstance(state.get("sql_matrix"), dict) else {}
    items: list[dict] = []
    for lane in ("query", "form"):
        projection = matrix.get(lane)
        if not isinstance(projection, dict):
            continue
        status = str(projection.get("status") or "").strip().lower()
        generation = str(projection.get("input_fingerprint") or "").strip()
        if status not in {"candidate_pending", "partial", "invalid_input"} or not generation:
            continue
        if status == "candidate_pending":
            action = f"Review {lane} SQL matrix candidates and validate each locatable raw evidence path."
            priority = 92
        elif status == "invalid_input":
            action = f"Repair rejected {lane} SQL matrix input, then rerun the bounded lane."
            priority = 62
        else:
            action = f"Resume the {lane} SQL matrix after resolving its recorded evidence or transport blocker."
            priority = 64
        source_paths = [str(path) for path in (projection.get("source_paths") or []) if str(path).strip()][:2]
        input_hint = source_paths[0] if source_paths else "FILE"
        option = "--urls-file" if lane == "query" else "--form-file"
        plan_ref = str(projection.get("waf_plan_ref") or "").strip()
        command_hint = (
            "python3 tools/sql_parameter_probe.py --target {target} {option} {input}"
            .format(target=_quote(target), option=option, input=_quote(input_hint))
        )
        if plan_ref:
            command_hint += f" --waf-plan {_quote(plan_ref)}"
        candidates = [
            {
                key: candidate[key]
                for key in ("endpoint", "field", "class", "signal")
                if key in candidate
            }
            for candidate in (projection.get("candidates") or [])[:5]
            if isinstance(candidate, dict)
        ]
        items.append({
            "id": f"SQL-MATRIX-{lane.upper()}",
            "priority": priority,
            "type": "sql-matrix-review",
            "status": "ready",
            "action": action,
            "command_hint": command_hint,
            "redline_required": False,
            "stop_condition": "record candidate validation, complete_no_hit, invalid_input, or the explicit blocker",
            "source": "sql-matrix",
            "source_id": f"sql-matrix-{lane}",
            "metadata": {
                "generation": generation,
                "lane": lane,
                "summary_path": str(projection.get("path") or ""),
                "summary_status": status,
                "reason": str(projection.get("reason") or ""),
                "candidate_count": int(projection.get("candidate_count", 0) or 0),
                "candidates": candidates,
                "waf_plan_ref": plan_ref,
                "waf_plan_sha256": str(projection.get("waf_plan_sha256") or ""),
                "waf_ai_variants_executed": int(projection.get("waf_ai_variants_executed", 0) or 0),
            },
        })
    return items


def _filter_final_action_queue_items(
    repo_root: Path,
    target: str,
    items: list[dict],
    existing: dict | None = None,
) -> list[dict]:
    """Remove checkpoint actions already closed in persistent action_queue state."""
    if existing is None:
        try:
            existing = load_action_queue(repo_root, target)
        except Exception:  # pragma: no cover - checkpoint should stay best-effort
            return items

    def is_final_for_checkpoint(action: dict) -> bool:
        """Return whether a persisted action should suppress checkpoint work.

        validation_runner historically synced ``tested_finding`` to
        ``status=validated``. Under the current AI-first contract that only
        means runner evidence exists; `/validate` must still run the
        seven-question + four-gate report-readiness audit. Treat those legacy
        runner-only rows as non-final so they do not hide the real validate
        action.
        """
        status = str(action.get("status") or "")
        if status not in ACTION_QUEUE_FINAL_STATUSES:
            return False
        metadata = action.get("metadata") if isinstance(action.get("metadata"), dict) else {}
        if metadata.get("dedupe_retired") is True:
            return False
        result = str(action.get("result") or "").strip()
        if status == "validated" and result.startswith("validation-runner-result="):
            return False
        return True

    def action_identities(action: dict) -> set[str]:
        """Return stable finding/endpoint identities for stale candidate suppression."""
        return action_queue_action_identities(action)

    def from_existing_action(action: dict) -> dict:
        """把持久队列里的候选动作投影回 checkpoint item。"""
        item = {
            "id": str(action.get("id") or ""),
            "priority": int(action.get("priority", 50) or 50),
            "type": str(action.get("type") or "next-action"),
            "status": str(action.get("status") or "queued"),
            "action": str(action.get("action") or action.get("evidence") or ""),
            "command_hint": str(action.get("command_hint") or ""),
            "redline_required": bool(action.get("redline_required", False)),
            "stop_condition": str(action.get("stop_condition") or ""),
        }
        metadata = action.get("metadata") if isinstance(action.get("metadata"), dict) else {}
        if metadata:
            item["metadata"] = metadata
        return item

    final_keys = {
        str(action.get("dedupe_key") or action_queue_dedupe_key(action))
        for action in existing.get("actions", [])
        if isinstance(action, dict)
        and is_final_for_checkpoint(action)
    }
    final_identities: set[str] = set()
    final_signal_identities: set[str] = set()
    for action in existing.get("actions", []):
        if not isinstance(action, dict):
            continue
        if not is_final_for_checkpoint(action):
            continue
        final_identities.update(action_identities(action))
        signal_identity = action_queue_knowledge_signal_identity(action)
        if signal_identity:
            final_signal_identities.add(signal_identity)

    active_candidate_by_key: dict[str, dict] = {}
    active_candidate_key_by_identity: dict[str, str] = {}
    for action in existing.get("actions", []):
        if not isinstance(action, dict):
            continue
        if str(action.get("status") or "") != "candidate" or str(action.get("type") or "") != "candidate-evidence-gap":
            continue
        if action_identities(action) & final_identities:
            continue
        key = str(
            action_queue_candidate_dedupe_key(action)
            or action.get("dedupe_key")
            or action_queue_dedupe_key(action)
        )
        active_candidate_by_key.setdefault(key, from_existing_action(action))
        for identity in action_identities(action):
            active_candidate_key_by_identity.setdefault(identity, key)
    if not final_keys and not final_signal_identities and not active_candidate_by_key:
        return items

    filtered: list[dict] = []
    emitted_candidate_keys: set[str] = set()
    for item in items:
        try:
            queue_shape = action_queue_checkpoint_item_to_action(target, item)
            key = str(queue_shape.get("dedupe_key") or action_queue_dedupe_key(queue_shape))
        except Exception:  # pragma: no cover - keep item if matching fails
            filtered.append(item)
            continue
        signal_identity = action_queue_knowledge_signal_identity(queue_shape)
        if signal_identity and signal_identity in final_signal_identities:
            continue
        candidate_key = ""
        if str(queue_shape.get("type") or "") in {
            "surface-review",
            "ranked-surface",
            "coverage-gap",
            "evidence-convergence",
        }:
            candidate_key = next(
                (
                    active_candidate_key_by_identity[identity]
                    for identity in action_identities(queue_shape)
                    if identity in active_candidate_key_by_identity
                ),
                "",
            )
        if candidate_key:
            key = candidate_key
        if key not in final_keys:
            if key in active_candidate_by_key:
                if key not in emitted_candidate_keys:
                    filtered.append(active_candidate_by_key[key])
                    emitted_candidate_keys.add(key)
                continue
            filtered.append(item)
    for key, candidate in active_candidate_by_key.items():
        if key not in emitted_candidate_keys:
            filtered.append(candidate)
    return filtered


def _select_default_candidate(target: str, items: list[dict]) -> dict:
    """用 action_queue 的真实选择规则挑 checkpoint 默认项。

    checkpoint 的 `next_action_queue` 是候选集；`recommended_executable_action`
    只是兼容字段。如果这里单纯取 priority 最高项，report 会因为分数高而压过
    已有 replay 草案的 surface-review，和 `/autopilot` 的“report 是阶段收束”
    规则冲突。这里复用 action_queue 的选择器，只把选中的 queue action 映射回
    原始 checkpoint item，避免两套排序语义漂移。
    """
    if not items:
        return {}
    try:
        converted: list[dict] = []
        by_key: dict[str, dict] = {}
        for item in items:
            queue_item = action_queue_checkpoint_item_to_action(target, item)
            key = str(queue_item.get("dedupe_key") or action_queue_dedupe_key(queue_item))
            converted.append(queue_item)
            by_key.setdefault(key, item)
        selected = action_queue_select_next_action({"actions": converted})
        if selected:
            selected_key = str(selected.get("dedupe_key") or action_queue_dedupe_key(selected))
            if selected_key in by_key:
                return by_key[selected_key]
    except Exception:
        # checkpoint 必须保持 best-effort；选择器异常时退回旧行为。
        pass
    return items[0]


def _runtime_wait_candidate(wait_action: str, target: str) -> dict:
    """Return a transient status pointer for an active long-running phase lock."""
    if wait_action == "wait_recon":
        action = (
            f"Wait/poll the existing /recon {target} run; do not launch another recon. "
            "Rerun checkpoint after the matching recon phase lock releases."
        )
    else:
        action = (
            f"Wait/poll the existing scan-only quick run for {target}; do not launch "
            "another scan-only quick. Rerun checkpoint after the matching scan phase "
            "lock releases."
        )
    return {
        "id": "runtime-wait",
        "priority": 1000,
        "type": wait_action,
        "status": "transient",
        "action": action,
        "command_hint": "poll existing run; do not enqueue persistent validation/report work yet",
        "redline_required": False,
        "stop_condition": "completed workflow is written or the matching phase lock releases",
    }


def _dead_end_proposals(state: dict, coverage_gaps: list[dict]) -> list[str]:
    if state.get("has_recon") and not coverage_gaps:
        stats = _surface_stats(state)
        if (
            not stats["review_pool"]
            and not stats["p1"]
            and not stats["p2"]
            and not stats["observation_untouched"]
            and not _unsafe_leads(state)
        ):
            return [
                "Evidence: cached surface has no review candidates and no high-value matrix gaps. "
                "Why it matters: broad cached recon is currently low-signal. "
                "Next action: only reopen after new recon, browser, source, or target-memory evidence. "
                "Stop condition: no new evidence source appears."
            ]
    return []


def _handoff_summary(
    *,
    target: str,
    decision: str,
    state: dict,
    coverage_summary: dict,
    evidence_summary: dict,
    next_action: str = "",
    note: str = "",
) -> str:
    stats = _surface_stats(state)
    findings = _structured_findings(state)
    actor_matrix = evidence_summary.get("actor_matrix") or {}
    lane_summary = coverage_summary.get("high_risk_lanes") or {}
    lane_counts = {
        status: sum(
            1 for item in lane_summary.values()
            if isinstance(item, dict) and item.get("disposition") == status
        )
        for status in ("candidate", "tested", "queued", "blocked", "not_applicable", "unassessed", "not_observed")
    }
    parts = [
        f"Decision={decision}",
        f"next_action={next_action or state.get('next_action', '-')}",
        f"review_pool={stats['review_pool']}",
        f"advisory_first_review={stats['p1']}",
        f"advisory_follow_up={stats['p2']}",
        f"workflow_leads={stats['workflow_leads']}",
        f"observation_total={stats['observation_total']}",
        f"observation_untouched={stats['observation_untouched']}",
        f"observation_stale={stats['observation_stale']}",
        f"coverage_gaps={coverage_summary.get('high_value_gaps_count', 0)}",
        f"actionable_coverage_gaps={coverage_summary.get('actionable_high_value_gaps_count', 0)}",
        "high_risk_lanes=" + ",".join(f"{key}:{value}" for key, value in lane_counts.items()),
        f"actor_gaps={actor_matrix.get('gap_count', 0)}",
        f"runner_candidates={len(state.get('validation_runner_candidates') or [])}",
    ]
    if findings.get("pending_validation"):
        next_validation = findings.get("next_validation") or {}
        parts.append(f"pending_validation={next_validation.get('id', findings.get('pending_validation'))}")
    if findings.get("validated_pending_report"):
        next_report = findings.get("next_report") or {}
        parts.append(f"pending_report={next_report.get('id', findings.get('validated_pending_report'))}")
    if note:
        parts.append(f"operator_note={note.strip()[:180]}")
    return f"{target} checkpoint: " + "; ".join(parts)


def _target_memory_path(repo_root: Path, target: str) -> Path:
    return repo_root / "memory" / "goals" / "targets" / f"{target_storage_key(target)}.json"


def _append_unique_entries(memory: dict, field: str, entries: list[str], target: str) -> int:
    existing = {
        str(item.get("text") or "").strip()
        for item in (memory.get(field) or [])
        if isinstance(item, dict)
    }
    added = 0
    for text in entries:
        clean = str(text or "").strip()
        if not clean or clean in existing:
            continue
        item = {"ts": now_utc(), "text": clean}
        if field in {"dead_ends", "useful_patterns"}:
            item.update(
                {
                    "entry_id": make_entry_id(
                        target=target,
                        field=field,
                        text=clean,
                        evidence_refs=[],
                    ),
                    "kind": "dead-end" if field == "dead_ends" else "useful-pattern",
                    "evidence_refs": [],
                }
            )
        memory.setdefault(field, []).append(item)
        existing.add(clean)
        added += 1
    return added


def apply_target_memory(repo_root: Path | str, target: str, checkpoint: dict) -> dict:
    repo = Path(repo_root)
    resolved_target = canonical_target_value(target)
    path = _target_memory_path(repo, resolved_target)
    with target_memory_mutation_lock(path):
        memory = load_target_memory_file(path, expected_target=resolved_target) or new_target_memory(resolved_target)
        memory.setdefault("target", resolved_target)

        added = {
            "lead": _append_unique_entries(
                memory,
                "active_leads",
                checkpoint.get("target_write_back", {}).get("lead", [])[:3],
                resolved_target,
            ),
            "next": _append_unique_entries(
                memory,
                "next_actions",
                checkpoint.get("target_write_back", {}).get("next", [])[:5],
                resolved_target,
            ),
            "dead_end": _append_unique_entries(
                memory,
                "dead_ends",
                checkpoint.get("target_write_back", {}).get("dead_end", [])[:2],
                resolved_target,
            ),
        }

        handoff = str(checkpoint.get("target_write_back", {}).get("handoff") or "").strip()
        session_path = ""
        if handoff:
            sessions_dir = repo / "memory" / "goals" / "sessions"
            session_file = write_handoff_file(
                sessions_dir,
                target_storage_key(resolved_target),
                "\n".join([
                    f"# Target Handoff: {resolved_target}",
                    "",
                    f"- Time: {now_utc()}",
                    f"- Decision: {checkpoint.get('decision', '-')}",
                    "",
                    "## Summary",
                    handoff,
                    "",
                ]),
            )
            try:
                session_path = str(session_file.relative_to(repo))
            except ValueError:
                session_path = str(session_file)
            handoff_entry = {"ts": now_utc(), "path": session_path, "summary": handoff}
            existing_handoffs = memory.setdefault("session_handoffs", [])
            if not any(isinstance(item, dict) and item.get("summary") == handoff for item in existing_handoffs):
                existing_handoffs.append(handoff_entry)
                added["handoff"] = 1
            else:
                added["handoff"] = 0
        else:
            added["handoff"] = 0

        memory["updated_at"] = now_utc()
        write_target_memory_json(path, memory)
    return {
        "target_memory_path": str(path.relative_to(repo)) if path.is_relative_to(repo) else str(path),
        "session_path": session_path,
        "added": added,
    }


def build_checkpoint(
    repo_root: Path | str = BASE_DIR,
    *,
    target: str,
    note: str = "",
    memory_dir: str | None = None,
    refresh_coverage: bool = True,
) -> dict:
    repo = Path(repo_root)
    resolved_target = canonical_target_value(target)
    coverage_target = target_storage_key(resolved_target)
    queue_snapshot = load_action_queue(repo, resolved_target)
    case_state = _case_state_summary(repo, resolved_target)
    state = build_autopilot_state(
        str(repo),
        resolved_target,
        memory_dir=memory_dir,
        queue_snapshot=queue_snapshot,
        case_state_summary=case_state,
    )
    matrix = load_matrix_projection(coverage_target, repo_root=repo)
    coverage_rebuilt = False
    if matrix is None:
        matrix = load_matrix(coverage_target, repo_root=repo)
        if refresh_coverage and not matrix_is_fresh(coverage_target, matrix, repo_root=repo):
            matrix = rebuild_matrix(coverage_target, repo_root=repo)
            save_matrix(coverage_target, matrix, repo_root=repo)
            coverage_rebuilt = True
        elif matrix_is_fresh(coverage_target, matrix, repo_root=repo):
            save_matrix_projection(coverage_target, matrix, repo_root=repo)
    gaps = list(matrix.get("_coverage_gaps") or _matrix_gaps(matrix))
    context = build_context_pack(
        repo,
        target=resolved_target,
        memory_dir=memory_dir,
        surface_state=state.get("surface") if isinstance(state.get("surface"), dict) else None,
        coverage_state=(gaps, matrix),
        validation_runner_candidates=(
            state.get("validation_runner_candidates")
            if isinstance(state.get("validation_runner_candidates"), list)
            else None
        ),
    )
    coverage_summary = _matrix_summary(matrix, gaps)
    evidence_summary = build_evidence_summary(
        repo,
        target=resolved_target,
        focus_endpoints=_evidence_focus_endpoints(state, gaps),
        vuln_classes=_evidence_vuln_classes(gaps, case_state, queue_snapshot),
    )
    actor_gaps = _actor_gaps(evidence_summary)
    case_state_proposal = _case_state_proposal(case_state)
    case_state_seed = _case_state_seed_summary(repo, resolved_target) if not case_state_proposal else {}
    case_state_seed_proposal = _case_state_seed_proposal(case_state_seed)
    ignored_actor_gap_endpoints = {
        canonical_endpoint_identity(str(item.get("endpoint") or ""))
        for item in case_state_seed.get("suggested_objects") or []
        if isinstance(item, dict)
        and str(item.get("confidence") or "").lower() == "low"
        and item.get("endpoint")
    }

    lead = _lead_proposals(
        state,
        context,
        repo_root=repo,
        target=resolved_target,
        evidence_summary=evidence_summary,
        case_state=case_state,
    )
    next_items = _next_proposals(
        state,
        gaps,
        matrix,
        resolved_target,
        context,
        evidence_summary,
        case_state,
        repo_root=repo,
        ignored_actor_gap_endpoints=ignored_actor_gap_endpoints,
    )
    if case_state_proposal:
        next_items = [case_state_proposal, *next_items]
    elif case_state_seed_proposal:
        next_items = [case_state_seed_proposal, *next_items]
    next_action_queue = _build_next_action_queue(next_items, resolved_target)
    case_top = _case_state_top_next(case_state)
    case_metadata = case_top.get("metadata") if isinstance(case_top.get("metadata"), dict) else {}
    if case_metadata:
        for action in next_action_queue:
            if str(action.get("type") or "").startswith("case-state-"):
                metadata = action.setdefault("metadata", {})
                if isinstance(metadata, dict):
                    metadata.update(case_metadata)
                    metadata.setdefault("hypothesis_id", str(case_top.get("hypothesis_id") or ""))
                break
    json_inject_item = _json_inject_queue_item(state, resolved_target)
    if json_inject_item:
        next_action_queue.append(json_inject_item)
    next_action_queue.extend(_sql_matrix_queue_items(state, resolved_target))
    next_action_queue.extend(
        _workflow_lead_queue_items(
            state,
            repo_root=repo,
            target=resolved_target,
        )
    )
    sibling_item = _sibling_queue_item(
        state,
        repo_root=repo,
        target=resolved_target,
    )
    if sibling_item:
        next_action_queue.append(sibling_item)
    _attach_activation_context(
        next_action_queue,
        repo=repo,
        target=resolved_target,
        context=context,
    )
    chain_review = _capability_chain_review_item(repo, resolved_target, queue_snapshot)
    if chain_review:
        next_action_queue.append(chain_review)
    next_action_queue = _dedupe_artifact_category_items(next_action_queue)
    next_action_queue = _filter_final_action_queue_items(
        repo,
        resolved_target,
        next_action_queue,
        queue_snapshot,
    )
    dead_ends = _dead_end_proposals(state, gaps)
    runtime_wait_action = str(state.get("next_action") or "")
    if runtime_wait_action in {"wait_recon", "wait_scan"}:
        # 活跃 phase gate 属于瞬时执行态，不是持久 queue 工作。只要匹配 flock
        # 仍被持有，就不要 enqueue validation/report/surface candidates。
        decision = _decision_for_action(runtime_wait_action)
        lead = []
        next_items = []
        dead_ends = []
        next_action_queue = []
        default_candidate = {}
        recommended_executable_action = _runtime_wait_candidate(runtime_wait_action, resolved_target)
    else:
        queue_next = (
            state.get("action_queue_next")
            if isinstance(state.get("action_queue_next"), dict)
            else {}
        )
        default_candidate = (
            queue_next
            if str(queue_next.get("status") or "") == "running"
            else _select_default_candidate(resolved_target, next_action_queue)
        )
        effective_action = str(default_candidate.get("type") or runtime_wait_action)
        decision = _decision_for_action(effective_action if default_candidate else "handoff")
        # Backward compatibility: older command docs and tests still consume the
        # historical field name. This remains an advisory pointer; an already
        # claimed Queue action stays visible instead of being re-ranked here.
        recommended_executable_action = default_candidate
    next_action_label = str(
        recommended_executable_action.get("type")
        or decision
        or ""
    )
    handoff = _handoff_summary(
        target=resolved_target,
        decision=decision,
        state=state,
        coverage_summary=coverage_summary,
        evidence_summary=evidence_summary,
        next_action=next_action_label,
        note=note,
    )

    checkpoint = {
        "target": resolved_target,
        "decision": decision,
        "phase": context.get("phase", "unknown"),
        "next_action": next_action_label,
        "context_pack": {
            "selected_skill": context.get("selected_skill", ""),
            "skill_route": context.get("skill_route", {}),
            "knowledge_cards": context.get("knowledge_cards", []),
            "knowledge_card_recall": [
                item
                for item in (context.get("knowledge_card_recall") or [])[:8]
                if isinstance(item, dict)
            ],
            "evidence_anchors": context.get("evidence_anchors", []),
            "hypothesis_seeds": context.get("hypothesis_seeds", []),
            "reference_hints": context.get("reference_hints", []),
            "required_checks": context.get("required_checks", []),
            "contradictions": context.get("contradictions", []),
        },
        "evidence_reviewed": {
            "autopilot_state": True,
            "context_pack": True,
            "coverage_rebuilt": coverage_rebuilt,
            "surface": bool(state.get("surface")),
        },
        "coverage": {
            "summary": coverage_summary,
            "high_risk_lanes": coverage_summary.get("high_risk_lanes", {}),
            "high_value_gaps": gaps[:10],
            "window": {
                "total": len(gaps),
                "returned": min(len(gaps), 10),
                "remaining": max(0, len(gaps) - 10),
                "digest": hashlib.sha256(
                    json.dumps(gaps, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
                ).hexdigest()[:16],
            },
        },
        "case_state": {
            "actors": case_state.get("actors", 0),
            "sessions": case_state.get("sessions", 0),
            "objects": case_state.get("objects", 0),
            "pending_validation_backlog": case_state.get("pending_validation_backlog", 0),
            "top_next_action": _case_state_top_next(case_state),
        },
        "case_state_seed": {
            "status": case_state_seed.get("status", ""),
            "suggested_objects": (case_state_seed.get("suggested_objects") or [])[:3],
            "suggested_backlog": (case_state_seed.get("suggested_backlog") or [])[:3],
        },
        "evidence_ledger": {
            "path": evidence_summary.get("path", ""),
            "entry_count": evidence_summary.get("entry_count", 0),
            "redline_unchecked_count": evidence_summary.get("redline_unchecked_count", 0),
            "open_candidates": (evidence_summary.get("open_candidates") or [])[:10],
            "actor_matrix": {
                "gap_count": (evidence_summary.get("actor_matrix") or {}).get("gap_count", 0),
                "covered_count": (evidence_summary.get("actor_matrix") or {}).get("covered_count", 0),
                "gaps": actor_gaps[:8],
            },
            "record_commands": (evidence_summary.get("record_commands") or [])[:5],
        },
        "surface": _surface_stats(state),
        "structured_findings": _structured_findings(state),
        "validation_runner_candidates": state.get("validation_runner_candidates") or [],
        "unsafe_skipped": _unsafe_leads(state),
        "target_write_back": {
            "lead": lead,
            "next": next_items,
            "dead_end": dead_ends,
            "handoff": handoff,
        },
        "next_action_queue": next_action_queue,
        "default_candidate": default_candidate,
        "recommended_executable_action": recommended_executable_action,
        "commands": _write_back_commands(resolved_target, lead, next_items, dead_ends, handoff),
        "retrospect": f"/retrospect {resolved_target}",
        "apply_status": "not applied; rerun with --apply-target-memory to write target memory",
    }
    witness = write_checkpoint_witness(repo, resolved_target, checkpoint)
    witness_path = Path(witness["path"])
    checkpoint["runtime_witness"] = {
        "schema_version": witness["payload"]["schema_version"],
        "path": str(witness_path.relative_to(repo)) if witness_path.is_relative_to(repo) else str(witness_path),
    }
    return checkpoint


def _quote(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _write_back_commands(
    target: str,
    leads: list[str],
    next_items: list[str],
    dead_ends: list[str],
    handoff: str,
) -> list[str]:
    commands: list[str] = []
    quoted_target = _quote(target)
    for item in leads[:3]:
        commands.append(f"python3 tools/target_memory.py lead {_quote(item)} --target {quoted_target}")
    for item in next_items[:5]:
        commands.append(f"python3 tools/target_memory.py next {_quote(item)} --target {quoted_target}")
    for item in dead_ends[:2]:
        commands.append(f"python3 tools/target_memory.py dead-end {_quote(item)} --target {quoted_target}")
    if handoff:
        commands.append(f"python3 tools/target_memory.py handoff {_quote(handoff)} --target {quoted_target}")
    return commands


def _fmt_list(items: list[str]) -> list[str]:
    if not items:
        return ["  - none"]
    return [f"  - {item}" for item in items]


def _fmt_nested(items: list[str]) -> list[str]:
    if not items:
        return ["    - none"]
    return [f"    - {item}" for item in items]


def _fmt_action_queue(items: list[dict]) -> list[str]:
    if not items:
        return ["  - none"]
    lines: list[str] = []
    for item in items[:5]:
        redline = " red-line-first" if item.get("redline_required") else ""
        lines.append(
            "  - {id} [{type} p{priority}{redline}] {action} | hint: {hint}".format(
                id=item.get("id", ""),
                type=item.get("type", ""),
                priority=item.get("priority", ""),
                redline=redline,
                action=item.get("action", ""),
                hint=item.get("command_hint", ""),
            )
        )
    return lines


def _project_knowledge_effect_trace(checkpoint: dict, actions: list[dict]) -> dict:
    context = checkpoint.get("context_pack") if isinstance(checkpoint.get("context_pack"), dict) else {}
    cards = [str(item).strip() for item in context.get("knowledge_cards", []) if str(item).strip()]
    if not cards:
        return {}

    matched: list[tuple[str, int, dict]] = []
    for index, action in enumerate(actions):
        if not isinstance(action, dict):
            continue
        metadata = action.get("metadata") if isinstance(action.get("metadata"), dict) else {}
        selected = [str(item).strip() for item in metadata.get("selected_knowledge_refs", []) if str(item).strip()]
        if not set(selected).intersection(cards):
            continue
        if str(action.get("status") or "queued") == "queued":
            continue
        matched.append((str(action.get("updated_at") or action.get("created_at") or ""), index, action))

    selected_action = max(matched, default=("", -1, {}))[-1]
    metadata = (
        selected_action.get("metadata")
        if isinstance(selected_action.get("metadata"), dict)
        else {}
    )
    selected_refs = [
        str(item).strip()
        for item in metadata.get("selected_knowledge_refs", [])
        if str(item).strip() in cards
    ]
    card = selected_refs[0] if selected_refs else cards[0]
    seeds = [str(item).strip() for item in context.get("hypothesis_seeds", []) if str(item).strip()]
    seed = str(metadata.get("hypothesis_seed") or (seeds[0] if seeds else "")).strip()
    suggestion = card + (f" / {re.sub(r'\s+', ' ', seed)[:80]}" if seed else "")

    action_text = "pending"
    result_text = "pending"
    if selected_action:
        action_text = "{id} / {action}".format(
            id=selected_action.get("id", ""),
            action=re.sub(r"\s+", " ", str(selected_action.get("action") or "")).strip()[:100],
        ).rstrip(" / ")
        outcome = metadata.get("last_outcome") if isinstance(metadata.get("last_outcome"), dict) else {}
        outcome_status = str(outcome.get("status") or "").strip()
        evidence_ref = str(
            outcome.get("summary_ref") or outcome.get("evidence_ref") or ""
        ).strip()[:160]
        if outcome_status or evidence_ref:
            result_text = outcome_status or str(selected_action.get("status") or "observed")
            if evidence_ref:
                result_text += f" / {evidence_ref}"
        elif str(selected_action.get("status") or "") in ACTION_QUEUE_FINAL_STATUSES:
            result_text = str(selected_action.get("status"))

    return {"suggestion": suggestion, "action": action_text, "result": result_text}


def format_checkpoint(checkpoint: dict) -> str:
    coverage = checkpoint.get("coverage") or {}
    summary = coverage.get("summary") or {}
    write_back = checkpoint.get("target_write_back") or {}
    context = checkpoint.get("context_pack") or {}
    case_state = checkpoint.get("case_state") or {}
    case_state_next = case_state.get("top_next_action") or {}
    evidence = checkpoint.get("evidence_ledger") or {}
    actor_matrix = evidence.get("actor_matrix") or {}
    queue_sync = checkpoint.get("action_queue_sync") or {}
    knowledge_trace = checkpoint.get("knowledge_effect_trace")
    if not isinstance(knowledge_trace, dict):
        knowledge_trace = _project_knowledge_effect_trace(checkpoint, [])
    claim_sync = checkpoint.get("root_finding_claim_sync") or {}
    queue_sync_text = "not run"
    if queue_sync:
        queue_sync_text = "path={path} added={added} updated={updated} next={next_id}".format(
            path=queue_sync.get("path", "-"),
            added=(queue_sync.get("stats") or {}).get("added", 0),
            updated=(queue_sync.get("stats") or {}).get("updated", 0),
            next_id=(queue_sync.get("next") or {}).get("id", "none"),
        )

    lines = [
        "CHECKPOINT DECISION",
        f"- Target: {checkpoint.get('target', '')}",
        f"- Phase: {checkpoint.get('phase', '')}",
        f"- Decision: {checkpoint.get('decision', '')}",
        f"- Next action: {checkpoint.get('next_action', '')}",
        f"- Recommended skill: {context.get('selected_skill', '')}",
        "- Recommended knowledge cards:",
        *_fmt_list([str(item) for item in context.get("knowledge_cards", [])]),
        "- Knowledge effect: {suggestion} -> {action} -> {result}".format(
            suggestion=knowledge_trace.get("suggestion", "pending"),
            action=knowledge_trace.get("action", "pending"),
            result=knowledge_trace.get("result", "pending"),
        ),
        "- Contradictions:",
        *_fmt_list([
            str(item) for item in context.get("contradictions", [])
            if str(item).strip() and str(item).strip().lower() != "none detected."
        ]),
        "- Root finding claim reconciliation:",
        "  - status={status} created={created} updated={updated} claims={claims}".format(
            status=claim_sync.get("status", "not run"),
            created=claim_sync.get("created", 0),
            updated=claim_sync.get("updated", 0),
            claims=len(claim_sync.get("claims") or []),
        ),
        "- Coverage:",
        f"  - endpoints: {summary.get('endpoints', 0)}",
        f"  - high-value gaps: {summary.get('high_value_gaps_count', 0)}",
        f"  - actionable high-value gaps: {summary.get('actionable_high_value_gaps_count', 0)}",
        "  - high-risk lanes: " + ", ".join(
            f"{name}={item.get('disposition', 'unknown')}"
            for name, item in (coverage.get("high_risk_lanes") or {}).items()
            if isinstance(item, dict)
        ),
        "- Case state:",
        f"  - actors: {case_state.get('actors', 0)}",
        f"  - sessions: {case_state.get('sessions', 0)}",
        f"  - objects: {case_state.get('objects', 0)}",
        f"  - pending backlog: {case_state.get('pending_validation_backlog', 0)}",
        "  - top next action:",
        *_fmt_nested([
            "{action} backlog={backlog} runner={runner} object={object_ref} owner={owner} peer={peer}".format(
                action=case_state_next.get("next_action", "none"),
                backlog=case_state_next.get("backlog_id", "-"),
                runner=case_state_next.get("runner", "-"),
                object_ref=case_state_next.get("object_ref", "-"),
                owner=case_state_next.get("owner_actor", "-"),
                peer=case_state_next.get("peer_actor", "-"),
            ) if case_state_next else "none"
        ]),
        "- Evidence ledger:",
        f"  - entries: {evidence.get('entry_count', 0)}",
        f"  - open candidates: {len(evidence.get('open_candidates') or [])}",
        f"  - actor matrix gaps: {actor_matrix.get('gap_count', 0)}",
        f"  - red-line unchecked: {evidence.get('redline_unchecked_count', 0)}",
        "  - candidate validation:",
        *_fmt_nested([
            "{method} {endpoint} x {vuln} evidence={evidence}".format(
                method=item.get("method", ""),
                endpoint=item.get("endpoint", ""),
                vuln=item.get("vuln_class", ""),
                evidence=item.get("evidence_ref", ""),
            )
            for item in (evidence.get("open_candidates") or [])[:3]
        ]),
        "  - actor gaps:",
        *_fmt_nested([
            "{endpoint} x {vuln}: {actor}/{scope}/{variant} expected={expected} status={status}".format(
                endpoint=item.get("endpoint", ""),
                vuln=item.get("vuln_class", ""),
                actor=item.get("actor", ""),
                scope=item.get("object_scope", ""),
                variant=item.get("variant", ""),
                expected=item.get("expected", ""),
                status=item.get("status", ""),
            )
            for item in actor_matrix.get("gaps", [])[:5]
        ]),
        "  - record commands:",
        *_fmt_nested(evidence.get("record_commands", [])[:3]),
        "- Validation runner candidates (advisory; require /validate before report):",
        *_fmt_list(format_validation_runner_candidate_lines(
            checkpoint.get("validation_runner_candidates") or [],
            limit=5,
        )),
        "- Next action queue:",
        *_fmt_action_queue(checkpoint.get("next_action_queue", [])),
        "- Durable action queue sync:",
        f"  - {queue_sync_text}",
        "- Default candidate (compat pointer):",
        f"  - {((checkpoint.get('default_candidate') or checkpoint.get('recommended_executable_action') or {}).get('action') or 'none')}",
        "- Target write-back:",
        "  - lead:",
        *_fmt_nested(write_back.get("lead", [])),
        "  - next:",
        *_fmt_nested(write_back.get("next", [])),
        "  - dead-end:",
        *_fmt_nested(write_back.get("dead_end", [])),
        f"  - handoff: {write_back.get('handoff', '') or 'none'}",
        "- Commands:",
        *_fmt_list(checkpoint.get("commands", [])),
        f"- Retrospect: {checkpoint.get('retrospect', '')}",
        f"- Apply status: {checkpoint.get('apply_status', '')}",
    ]
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build an autopilot checkpoint write-back proposal.")
    parser.add_argument("--target", required=True)
    parser.add_argument("--repo-root", default=str(BASE_DIR))
    parser.add_argument("--memory-dir", default="")
    parser.add_argument("--note", default="")
    parser.add_argument("--no-refresh-coverage", action="store_true")
    parser.add_argument("--apply-target-memory", action="store_true")
    round_operation = parser.add_mutually_exclusive_group()
    round_operation.add_argument("--round-begin", action="store_true")
    round_operation.add_argument("--record-round-lane", action="store_true")
    round_operation.add_argument("--record-round-lane-result", action="store_true")
    parser.add_argument("--lane", default="")
    parser.add_argument("--max-lanes", type=int, default=0)
    parser.add_argument("--lane-status", default="")
    parser.add_argument("--decision", default="")
    parser.add_argument("--evidence-ref", default="")
    parser.add_argument("--next-action", default="")
    round_operation.add_argument("--record-round-closure", action="store_true")
    parser.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    repo = Path(args.repo_root)
    resolved_target = canonical_target_value(args.target)
    if args.round_begin or args.record_round_lane or args.record_round_lane_result:
        try:
            if args.record_round_lane_result:
                result = record_round_lane_result(
                    repo,
                    resolved_target,
                    lane=args.lane,
                    status=args.lane_status,
                    decision=args.decision,
                    evidence_ref=args.evidence_ref,
                    next_action=args.next_action,
                )
            else:
                if args.max_lanes < 1:
                    raise ValueError("--max-lanes must be a positive integer")
                result = (
                    begin_round(repo, resolved_target, max_lanes=args.max_lanes)
                    if args.round_begin
                    else record_round_lane(
                        repo,
                        resolved_target,
                        lane=args.lane,
                        max_lanes=args.max_lanes,
                    )
                )
        except (OSError, ValueError, KeyError) as exc:
            print(f"checkpoint round budget failed: {exc}", file=sys.stderr)
            return 2
        print(json.dumps(result, ensure_ascii=False, indent=2) if args.json else result["path"])
        return 0
    if args.record_round_closure:
        try:
            result = record_round_closure(repo, resolved_target)
        except (OSError, ValueError, KeyError) as exc:
            print(f"checkpoint round closure record failed: {exc}", file=sys.stderr)
            return 2
        print(json.dumps(result, ensure_ascii=False, indent=2) if args.json else result["path"])
        return 0
    # Durable handoff 损坏时必须在 root-claim reconciliation 等写入前停止，避免把
    # “无法读取旧 queue”误当作可从空状态继续构建 checkpoint。
    try:
        load_action_queue(repo, resolved_target)
    except (OSError, ValueError, KeyError) as exc:
        print(f"checkpoint action queue preflight failed: {exc}", file=sys.stderr)
        return 2
    try:
        claim_sync = reconcile_root_finding_claims(
            repo / "findings" / target_storage_key(resolved_target),
            target=resolved_target,
        )
    except (OSError, ValueError, KeyError) as exc:
        print(f"checkpoint finding-claim reconciliation failed: {exc}", file=sys.stderr)
        return 2
    try:
        checkpoint = build_checkpoint(
            repo,
            target=args.target,
            note=args.note,
            memory_dir=args.memory_dir or None,
            refresh_coverage=not args.no_refresh_coverage,
        )
    except (OSError, ValueError, KeyError) as exc:
        print(f"checkpoint state build failed: {exc}", file=sys.stderr)
        return 2
    checkpoint["root_finding_claim_sync"] = claim_sync
    root_claims = list_root_finding_claims(
        repo / "findings" / target_storage_key(resolved_target),
        target=resolved_target,
        include_reconciled=True,
    )
    _append_root_claim_queue_items(checkpoint, root_claims, resolved_target)
    try:
        sync_checkpoint_action_queue(repo, checkpoint)
    except (OSError, ValueError, KeyError) as exc:
        print(f"checkpoint action queue sync failed: {exc}", file=sys.stderr)
        return 2
    if args.apply_target_memory:
        result = apply_target_memory(repo, checkpoint["target"], checkpoint)
        checkpoint["apply_status"] = "applied target memory"
        checkpoint["apply_result"] = result

    if args.json:
        print(json.dumps(checkpoint, ensure_ascii=False, indent=2))
    else:
        print(format_checkpoint(checkpoint))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
