#!/usr/bin/env python3
"""从活动 Store 读取目标 checkpoint，不生成行动或写回目标记忆。

普通查询不发布 Coverage 缓存或 checkpoint witness。轮次、heartbeat 和全局
review 通过各自显式命令记录。
`browser:` 前缀 round lane 完成时，若其 evidence_ref 指向 focused MCP capture
manifest（`{"captures": [...]}`），会自动调用 `browser_mcp_import` 的导入函数；
导入失败只作为 warning 记入 lane 记录，不阻断 heartbeat。知识库、Skills、Rules
永远只给建议，不在这里自动修改。
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import shlex
import sys
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

try:
    from tools.artifact_io import write_json_atomic as _write_json_atomic
except ImportError:  # pragma: no cover - direct tools/ execution
    from artifact_io import write_json_atomic as _write_json_atomic


try:
    from tools.autopilot_args import MAX_LANES
    from tools.checkpoint_witness import (
        is_canonical_coverage_lane_evidence_ref,
        load_checkpoint_witness as _load_checkpoint_witness,
        new_round_lane as _round_lane,
        validate_round_progress as _round_progress,
    )
    from tools.action_queue import ACTIVE_STATUSES as ACTION_QUEUE_ACTIVE_STATUSES, FINAL_STATUSES as ACTION_QUEUE_FINAL_STATUSES, load_queue as load_action_queue, load_queue_summary, queue_mutation_lock, queue_fingerprint as action_queue_fingerprint
    from tools.autopilot_state import (
        _global_review_basis,
        _queue_snapshot_for_target,
        build_autopilot_state,
        _build_autopilot_state,
        load_closure_projection,
        stagnation_fingerprint,
        validate_global_review,
    )
    from tools.context_pack import build_context_pack, _build_context_pack, format_source_queries, format_target_experiences
    from tools.coverage_matrix import coverage_gaps_with_observed_evidence, high_risk_lane_summary, high_value_gaps_from_matrix, read_matrix, require_matching_truth
    from tools.current_truth import current_cell_projection
    from tools.evidence_ledger import ACTOR_MATRIX_VULN_CLASSES, build_summary as build_evidence_summary
    from tools.case_state_seed import build_case_state_seed
    from tools.structured_findings import format_validation_runner_candidate_lines
    from tools.target_case_state import summary as build_case_state_summary
    from tools.target_paths import canonical_target_value, open_target_lock_file, target_storage_key, target_owned_nonempty_evidence_ref
    from tools.target_store import TargetStore, runtime_store
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
        load_queue as load_action_queue, load_queue_summary,
        queue_mutation_lock,
        queue_fingerprint as action_queue_fingerprint,
    )
    from autopilot_state import (  # type: ignore
        _global_review_basis,
        _queue_snapshot_for_target,
        build_autopilot_state,
        _build_autopilot_state,
        load_closure_projection,
        stagnation_fingerprint,
        validate_global_review,
    )
    from context_pack import build_context_pack, _build_context_pack, format_source_queries, format_target_experiences  # type: ignore
    from coverage_matrix import coverage_gaps_with_observed_evidence, high_risk_lane_summary, high_value_gaps_from_matrix, read_matrix, require_matching_truth  # type: ignore
    from current_truth import current_cell_projection  # type: ignore
    from evidence_ledger import ACTOR_MATRIX_VULN_CLASSES, build_summary as build_evidence_summary  # type: ignore  # type: ignore
    from case_state_seed import build_case_state_seed  # type: ignore
    from structured_findings import format_validation_runner_candidate_lines  # type: ignore
    from target_case_state import summary as build_case_state_summary  # type: ignore
    from target_paths import canonical_target_value, open_target_lock_file, target_storage_key, target_owned_nonempty_evidence_ref  # type: ignore
    from target_store import TargetStore, runtime_store  # type: ignore


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _checkpoint_witness_path(repo_root: Path | str, target: str) -> Path:
    resolved = canonical_target_value(target)
    return Path(repo_root) / "state" / target_storage_key(resolved) / "checkpoint_latest.json"


_CHECKPOINT_LOCK_STATE = threading.local()


@contextmanager
def checkpoint_witness_lock(repo_root: Path | str, target: str):
    lock_path = Path(repo_root) / "state" / target_storage_key(target) / "locks" / "checkpoint.lock"
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
    with open_target_lock_file(repo_root, target, "checkpoint.lock") as handle:
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
        evidence_ref = target_owned_nonempty_evidence_ref(
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


def _browser_lane_import_result(
    repo_root: Path | str,
    target: str,
    lane_id: str,
    evidence_ref: str,
) -> dict | None:
    """Auto-import a focused MCP browser manifest recorded as browser lane evidence.

    Returns ``None`` when the lane/evidence shape does not opt in (lane id not
    browser-prefixed, or evidence not a ``{"captures": [...]}`` manifest). The
    import itself is delegated to the ``browser_mcp_import`` owner function
    (no subprocess); its own duplicate skip keeps repeat imports bounded.
    Import failure is returned as a ``failed`` status with a reason - it must
    never raise, because a browser evidence import failure must not make the
    lane heartbeat fail.
    """
    if not lane_id.lower().startswith("browser"):
        return None
    repo = Path(repo_root)
    manifest_path = repo / evidence_ref
    # Only the documented pending-import manifest shape opts in. The importer's
    # own output (recon/<target>/browser/context_discovery.json) also carries a
    # "captures" list; re-feeding it as lane evidence must not re-import (it
    # would create duplicate capture directories and extra context snapshots).
    normalized_ref = str(evidence_ref or "").strip().replace("\\", "/").lstrip("./")
    if not normalized_ref.startswith(
        f"evidence/{target_storage_key(target)}/browser/"
    ):
        return None
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict) or not isinstance(payload.get("captures"), list):
        return None
    try:
        from tools.browser_mcp_import import import_focused_mcp_manifest
    except ImportError:  # pragma: no cover - direct tools/ execution
        from browser_mcp_import import import_focused_mcp_manifest  # type: ignore
    try:
        result = import_focused_mcp_manifest(
            target=target,
            manifest_path=manifest_path,
            evidence_root=repo / "evidence",
            recon_root=repo / "recon",
            repo_root=repo,
        )
    except Exception as exc:  # defensive: the heartbeat above is already durable
        return {
            "status": "failed",
            "reason": " ".join(f"{type(exc).__name__}: {exc}".split())[:400],
        }
    return {
        "status": str(result.get("status") or "unknown"),
        "artifact": str(result.get("artifact") or ""),
        "counts": dict(result.get("counts") or {}),
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
            terminal_evidence = target_owned_nonempty_evidence_ref(
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
                    "completed coverage lane requires canonical Coverage Matrix "
                    "or current TargetStore evidence_ref"
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
            # B3: browser lane finish auto-imports its focused MCP manifest.
            # Only fires on the fresh terminal transition: an `already_recorded`
            # replay must not re-create capture directories. Import failure is
            # recorded as a warning on the lane, never raised - the heartbeat
            # itself stays durable even when evidence import fails.
            if terminal_status == "completed":
                import_result = _browser_lane_import_result(
                    repo_root,
                    target,
                    lane_id,
                    terminal_evidence,
                )
                if import_result is not None:
                    lane_record["browser_import"] = import_result
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
            "knowledge_cards": context.get("knowledge_cards", []),
            "card_catalog": context.get("card_catalog", []),
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
        if str(queue_sync.get("status") or "").strip().lower() == "skipped":
            payload["action_queue"] = {
                "synchronized": False,
                "reason": str(queue_sync.get("reason") or "").strip(),
                "backend": "primary",
            }
            queue_sync = None
    if isinstance(queue_sync, dict):
        queue_path = str(queue_sync.get("path") or "").strip()
        if queue_path:
            candidate_path = Path(queue_path)
            try:
                queue_path = str(candidate_path.relative_to(repo))
            except ValueError:
                pass
        stats = queue_sync.get("stats") if isinstance(queue_sync.get("stats"), dict) else {}
        active_ids = queue_sync.get("active") if isinstance(queue_sync.get("active"), list) else []
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
            "active_ids": [str(value) for value in active_ids],
            "fingerprint": expected_fingerprint,
        }
    with checkpoint_witness_lock(repo, resolved_target):
        previous = _load_checkpoint_witness(path)
        progress = _round_progress(previous)
        if isinstance(previous.get("round_guard"), dict):
            payload["round_guard"] = previous["round_guard"]
        if isinstance(previous.get("global_review"), dict):
            payload["global_review"] = previous["global_review"]
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


def record_global_review(
    repo_root: Path | str,
    target: str,
    *,
    status: str,
    snapshot_digest: str,
    evidence_refs: list[str],
    cross_source_links: list[object] | None = None,
    residual_unknowns: list[str] | None = None,
    decision: str,
    next_action: str = "",
) -> dict:
    """Persist the target-wide review witness through the Checkpoint owner."""
    repo = Path(repo_root)
    resolved_target = canonical_target_value(target)
    path = _checkpoint_witness_path(repo, resolved_target)
    with checkpoint_witness_lock(repo, resolved_target):
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
                queue_snapshot=queue_snapshot,
            )
            expected_digest = str(closure.get("snapshot_digest") or "")
            expected_components = (
                closure.get("snapshot_components")
                if isinstance(closure.get("snapshot_components"), dict)
                else None
            )
            review = {
                "status": status,
                "snapshot_digest": snapshot_digest,
                "evidence_refs": evidence_refs,
                "cross_source_links": cross_source_links or [],
                "residual_unknowns": residual_unknowns or [],
                "decision": decision,
                "next_action": next_action,
            }
            checked = validate_global_review(
                repo,
                resolved_target,
                review,
                queue_snapshot,
                expected_digest=expected_digest,
                expected_components=expected_components,
            )
            if checked.get("status") != "valid":
                diagnostics = {
                    "status": checked.get("status") or "invalid",
                    "reason": checked.get("reason") or "global_review_invalid",
                    "state_changes": checked.get("state_changes") or [],
                    "action_required": checked.get("action_required") or "Correct the review and retry.",
                }
                raise ValueError(
                    "global review cannot be recorded: "
                    + json.dumps(diagnostics, ensure_ascii=False, separators=(",", ":"))
                )
            payload = _load_checkpoint_witness(path)
            if not payload:
                raise ValueError(f"checkpoint witness missing or invalid: {path}")
            # The persisted review keeps the whole-snapshot digest for audit
            # and the claim basis for scoping later validations: unrelated
            # owner writes (ledger telemetry, witness details) will no longer
            # invalidate a still-correct review.
            recorded_review = dict(checked["review"])
            if expected_components:
                recorded_review["basis"] = _global_review_basis(expected_components)
            payload["global_review"] = recorded_review
            _write_json_atomic(path, payload)
            return {
                "path": str(path),
                "global_review": recorded_review,
                "snapshot_digest": expected_digest,
            }


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


def _matrix_gaps(matrix: dict) -> list[dict]:
    return high_value_gaps_from_matrix(matrix)


def _actionable_coverage_gaps(coverage_gaps: list[dict]) -> list[dict]:
    """Return coverage gaps that at least one observed fact points at.

    Qualification by word lists is retired: any observed parameter, source,
    or route-kind fact makes a gap evidence-backed (queue-visible); grid
    enumeration cells with no observation stay advisory in the matrix and
    remain AI-selectable. The lane budget, not this filter, bounds how many
    gaps get executed.
    """
    return coverage_gaps_with_observed_evidence(coverage_gaps)


def _matrix_summary(matrix: dict, gaps: list[dict]) -> dict:
    endpoints = matrix.get("endpoints") or []
    lane_summary = matrix.get("high_risk_lanes")
    if not isinstance(lane_summary, dict):
        lane_summary = high_risk_lane_summary(matrix)
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
    evidence_records: list[dict],
    queue_snapshot: dict | None = None,
) -> list[str]:
    """Collect only explicit canonical families from state owners."""
    classes: list[str] = []
    for record in evidence_records:
        classes.append(str(record.get("vuln_class") or ""))
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

    classes.extend((queue_snapshot or {}).get("active_families", []))
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


def _case_state_summary(repo_root: Path | str, target: str) -> dict:
    """Load sanitized target case state summary for checkpoint routing.

    缺失文件仍表示尚未建立 case state；已存在但损坏的状态必须向上报错，
    避免 checkpoint 把丢失的 actor/session/object/backlog 误判为空状态。
    """
    payload = build_case_state_summary(repo_root, target)
    return payload if isinstance(payload, dict) else {}


def _case_state_seed_summary(repo_root: Path | str, target: str) -> dict:
    """Load read-only object observations; they do not generate Queue actions."""
    try:
        payload = build_case_state_seed(repo_root, target, limit=3)
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


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
    # Case 不再生产行动：这三个类型只用于路由**已经落在持久队列里的历史行**
    # （队列快照仍可能把在跑的旧行动作为 action_queue_next 报回来）。新 checkpoint
    # 不再生成它们；迁移验收后应随旧行一起消失，不需要第二套逻辑。
    "case-state-validation": "continue",
    "case-state-backlog-create": "continue",
    "case-state-seed": "continue",
    "case-state-enrichment": "continue",
    "actor-gap": "continue",
    "coverage-gap": "continue",
    "secondary-sweep": "continue",
    "secret-verification": "continue",
    "json-inject-review": "continue",
    "sql-matrix-review": "continue",
    "global-review": "checkpoint",
    "next-action": "continue",
}


def _decision_for_action(action: str) -> str:
    return ACTION_DECISIONS.get(str(action or "").strip().lower(), "handoff")


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
    summary = f"{target} checkpoint: " + "; ".join(parts)
    # The operator note is the user-intent ledger: it must stay a distinct,
    # un-truncated field instead of dissolving into the stats string.
    if note:
        summary = f"{target} checkpoint [intent={note.strip()[:300]}]: " + "; ".join(parts)
    return summary


def apply_target_memory(repo_root: Path | str, target: str, checkpoint: dict) -> dict:
    """Compatibility response: checkpoint projections never write back experience."""
    resolved_target = canonical_target_value(target)
    from tools.target_store import runtime_store
    runtime_store(repo_root, resolved_target)
    return {
        "status": "skipped",
        "reason": "primary store owns experience and case context; checkpoint is read-only",
        "target": resolved_target,
    }


def build_checkpoint(
    repo_root: Path | str = BASE_DIR,
    *,
    target: str,
    note: str = "",
    memory_dir: str | None = None,
    refresh_coverage: bool = True,
) -> dict:
    return _build_checkpoint(repo_root, target=target, note=note, memory_dir=memory_dir,
                             refresh_coverage=refresh_coverage)[0]


def _build_checkpoint(
    repo_root: Path | str = BASE_DIR,
    *,
    target: str,
    note: str = "",
    memory_dir: str | None = None,
    refresh_coverage: bool = True,
    full_domain_context: bool = False,
) -> tuple[dict, dict]:
    repo = Path(repo_root)
    resolved_target = canonical_target_value(target)
    store_binding = runtime_store(repo, resolved_target).binding()
    queue_snapshot = load_queue_summary(repo, resolved_target)
    case_state = _case_state_summary(repo, resolved_target)
    matrix = read_matrix(resolved_target, repo_root=repo, current_only=True)
    state, ranked_surface = _build_autopilot_state(
        str(repo),
        resolved_target,
        memory_dir=memory_dir,
        queue_snapshot=queue_snapshot,
        case_state_summary=case_state,
        coverage_state=matrix,
        full_domain_context=full_domain_context,
    )
    coverage_rebuilt = False
    gaps = list(matrix.get("_coverage_gaps") or _matrix_gaps(matrix))
    # Recheck raw evidence and reject revision drift before publishing this view.
    evidence_truth = current_cell_projection(repo, resolved_target)
    require_matching_truth(matrix, evidence_truth)
    context = _build_context_pack(
        repo,
        target=resolved_target,
        memory_dir=memory_dir,
        surface_state=state["surface"] if isinstance(state.get("surface"), dict) else ranked_surface,
        coverage_state=(gaps, matrix),
        validation_runner_candidates=(
            state.get("validation_runner_candidates")
            if isinstance(state.get("validation_runner_candidates"), list)
            else None
        ),
        ledger_truth=evidence_truth,
    )
    coverage_summary = _matrix_summary(matrix, gaps)
    evidence_summary = build_evidence_summary(
        repo,
        target=resolved_target,
        focus_endpoints=_evidence_focus_endpoints(state, gaps),
        vuln_classes=_evidence_vuln_classes(evidence_truth["records"], queue_snapshot),
        _truth=evidence_truth,
    )
    actor_gaps = _actor_gaps(evidence_summary)
    case_state_seed = _case_state_seed_summary(repo, resolved_target)

    pending = [row for row in queue_snapshot["actions"]
               if row["status"] in ACTION_QUEUE_ACTIVE_STATUSES | {"blocked"}]
    pending.sort(key=lambda row: str(row["id"]))
    next_action_queue = pending[:5]
    action_queue_window = {
        **store_binding, "order": "id", "scope": "nonterminal actions", "selection_owner": "ai",
        "total": queue_snapshot["pending_total"], "returned": len(next_action_queue),
        "remaining": queue_snapshot["pending_total"] - len(next_action_queue),
        "expand_command": shlex.join([
            "python3", "tools/action_queue.py", "--repo-root", str(repo.resolve()),
            "list", "--target", resolved_target, "--json",
        ]),
        "expansion_scope": "fresh query of all stored actions, including terminal history",
    }
    runtime_wait_action = str(state.get("next_action") or "")
    if runtime_wait_action in {"wait_recon", "wait_scan"}:
        # 活跃 phase gate 属于瞬时执行态，不是持久 queue 工作。只要匹配 flock
        # 仍被持有，就不要 enqueue validation/report/surface candidates。
        decision = _decision_for_action(runtime_wait_action)
        default_candidate = {}
        recommended_executable_action = _runtime_wait_candidate(runtime_wait_action, resolved_target)
    else:
        default_candidate = queue_snapshot["running_action"]
        recommended_executable_action = default_candidate
        decision = "continue"
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

    material_sources = {
        "root_claims": state.get("root_finding_claims") or [],
        "workflow_leads": _json_list((state.get("surface") or {}).get("workflow_leads")),
        "repo_source": [f"findings/{target_storage_key(resolved_target)}/exposure/{name}"
                        for name in state.get("repo_source_artifacts") or []],
    }
    material_windows = {
        name: {"items": rows[:5], "total": len(rows), "remaining": max(0, len(rows) - 5)}
        for name, rows in material_sources.items()
    }
    surface_projection = state.get("surface_projection") or {}
    workflow_window = material_windows["workflow_leads"]
    workflow_window.update({
        key: surface_projection.get(key, "")
        for key in ("status", "reason", "refresh_command")
    })
    if surface_projection.get("status") != "valid":
        workflow_window.update({"items": [], "total": None, "remaining": None})
    checkpoint = {
        "target": resolved_target,
        "material_sources": {
            "sources": material_windows,
            "expand_command": shlex.join([
                "python3", "tools/autopilot_state.py", "--repo-root", str(repo.resolve()),
                "--target", resolved_target, "--json",
            ]),
        },
        "decision": decision,
        "phase": context.get("phase", "unknown"),
        "next_action": next_action_label,
        # User-intent ledger: preserves the operator's instruction for this
        # checkpoint so compaction/resume rebuilds intent, not just state.
        "user_intent": note.strip()[:2000] if note.strip() else "",
        "context_pack": {
            **({
                "active_goal": context["active_goal"],
                "target_experiences": context["target_experiences"],
            }),
            "knowledge_cards": context.get("knowledge_cards", []),
            "card_catalog": context.get("card_catalog", []),
            "knowledge_card_recall": [
                item
                for item in (context.get("knowledge_card_recall") or [])[:8]
                if isinstance(item, dict)
            ],
            "evidence_anchors": context.get("evidence_anchors", []),
            "source_queries": context.get("source_queries", {}),
            "hypothesis_seeds": context.get("hypothesis_seeds", []),
            "reference_hints": context.get("reference_hints", []),
            "required_checks": context.get("required_checks", []),
            "contradictions": context.get("contradictions", []),
        },
        "evidence_reviewed": {
            "autopilot_state": True,
            "context_pack": True,
            "coverage_rebuilt": coverage_rebuilt,
            "surface": surface_projection.get("status") == "valid",
        },
        "coverage": {
            "summary": coverage_summary,
            "high_risk_lanes": coverage_summary.get("high_risk_lanes", {}),
            "high_value_gaps": gaps[:10],
            "window": {
                "total": len(gaps),
                "returned": min(len(gaps), 10),
                "remaining": max(0, len(gaps) - 10),
                "order": "endpoint,vuln_class",
                "expand_command": shlex.join([
                    "python3", "tools/coverage_matrix.py", "find-gaps", "--repo-root",
                    str(repo.resolve()), "--target", resolved_target,
                ]),
                "digest": hashlib.sha256(
                    json.dumps(gaps, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
                ).hexdigest()[:16],
            },
        },
        "case_state": {
            "actors": case_state.get("actors", 0),
            "sessions": case_state.get("sessions", 0),
            "objects": case_state.get("objects", 0),
            "open_hypotheses": case_state.get("open_hypotheses", 0),
        },
        "case_state_seed": {
            "status": case_state_seed.get("status", ""),
            "suggested_objects": (case_state_seed.get("suggested_objects") or [])[:3],
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
            "lead": [],
            "next": [],
            "dead_end": [],
            "handoff": handoff,
        },
        "next_action_queue": next_action_queue,
        "action_queue_window": action_queue_window,
        "default_candidate": default_candidate,
        "recommended_executable_action": recommended_executable_action,
        "retrospect": f"/retrospect {resolved_target}",
        "apply_status": "read-only Store view; persist changes through explicit owner commands",
    }
    if TargetStore(repo, resolved_target).binding() != store_binding:
        raise ValueError("primary checkpoint inputs changed during assembly")
    checkpoint["runtime_witness"] = {
        "status": "not_published",
        "reason": "primary checkpoint build is read-only; publish via explicit CLI command",
        "path": str(_checkpoint_witness_path(repo, resolved_target).relative_to(repo)),
    }
    return checkpoint, state["resume_summary"]


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
            "  - {id} [{type} p{priority}{redline}] {action} | status: {status} | hint: {hint}".format(
                id=item.get("id", ""),
                type=item.get("type", ""),
                priority=item.get("priority", ""),
                redline=redline,
                action=item.get("action", ""),
                status=item.get("status", ""),
                hint=item.get("command_hint", ""),
            )
        )
        if item.get("result") or item.get("evidence"):
            lines.append(f"    reason/evidence: {item.get('result') or item.get('evidence')}")
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
    # Word-list signal cards carry the same suggestion visibility as selected
    # cards: the trace reports what was recommended, not what a token table
    # auto-loaded (that behavior is retired).
    if not selected_refs:
        signal_cards = [
            str(entry.get("file") or "").strip()
            for entry in context.get("knowledge_card_recall", [])
            if isinstance(entry, dict) and entry.get("status") == "signal"
        ]
        if signal_cards:
            card = signal_cards[0]
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
    evidence = checkpoint.get("evidence_ledger") or {}
    actor_matrix = evidence.get("actor_matrix") or {}
    action_window = checkpoint.get("action_queue_window") or {}
    action_window_lines = ([
        f"  - Stored nonterminal actions: total={action_window['total']}, "
        f"returned={action_window['returned']}, remaining={action_window['remaining']}; order=id; AI chooses",
        f"  - Expand all stored actions (includes terminal history): {action_window['expand_command']}",
    ] if action_window else [])
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

    material_lines = []
    materials = checkpoint.get("material_sources") or {}
    for name, window in (materials.get("sources") or {}).items():
        if window.get("status", "valid") != "valid":
            material_lines.append(
                f"  - {name}: {window['status']} ({window['reason']}); count unknown"
            )
            material_lines.append(f"    - Refresh: {window['refresh_command']}")
            continue
        if not window["total"]:
            continue
        material_lines.append(f"  - {name}: total={window['total']}, remaining={window['remaining']}")
        for item in window["items"]:
            if isinstance(item, dict):
                label = str(item.get("title") or item.get("category") or item.get("id") or "material")
                if item.get("category") and item["category"] != label:
                    label += f" [{item['category']}]"
                ref = str(item.get("source_file") or item.get("artifact") or item.get("source") or "")
                material_lines.append(f"    - {label} source={ref}")
            else:
                material_lines.append(f"    - {item}")
    if material_lines:
        material_lines = ["- Discovery material (advisory; AI chooses work):", *material_lines,
                          f"  - Expand: {materials['expand_command']}"]
    lines = [
        "CHECKPOINT DECISION",
        f"- Target: {checkpoint.get('target', '')}",
        f"- Phase: {checkpoint.get('phase', '')}",
        f"- Decision: {checkpoint.get('decision', '')}",
        f"- Next action: {checkpoint.get('next_action', '')}",
        *([f"- Active goal: {context['active_goal'] or '-'}"] if "active_goal" in context else []),
        *format_target_experiences(context.get("target_experiences") or {}),
        *format_source_queries({"surface": (context.get("source_queries") or {}).get("surface")}),
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
        *([f"  - Full coverage query: {coverage['window']['expand_command']}"]
          if (coverage.get("window") or {}).get("expand_command") else []),
        "  - high-risk lanes: " + ", ".join(
            f"{name}={item.get('disposition', 'unknown')}"
            for name, item in (coverage.get("high_risk_lanes") or {}).items()
            if isinstance(item, dict)
        ),
        "- Case state:",
        f"  - actors: {case_state.get('actors', 0)}",
        f"  - sessions: {case_state.get('sessions', 0)}",
        f"  - objects: {case_state.get('objects', 0)}",
        f"  - open hypotheses: {case_state.get('open_hypotheses', 0)}",
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
        *_fmt_nested(evidence.get("record_commands", [])[:3]),
        "- Validation runner candidates (advisory; require /validate before report):",
        *_fmt_list(format_validation_runner_candidate_lines(
            checkpoint.get("validation_runner_candidates") or [],
            limit=5,
        )),
        *material_lines,
        "- Next action queue:",
        *_fmt_action_queue(checkpoint.get("next_action_queue", [])),
        *action_window_lines,
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
        f"- Retrospect: {checkpoint.get('retrospect', '')}",
        f"- Apply status: {checkpoint.get('apply_status', '')}",
    ]
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Read an autopilot checkpoint from the active target Store.")
    parser.add_argument("--target", required=True)
    parser.add_argument("--repo-root", default=str(BASE_DIR))
    parser.add_argument("--memory-dir", default="")
    parser.add_argument("--note", default="")
    parser.add_argument("--no-refresh-coverage", action="store_true")
    parser.add_argument(
        "--apply-target-memory",
        dest="apply_target_memory",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Compatibility option; checkpoint never writes memory. Use explicit target_memory commands.",
    )
    round_operation = parser.add_mutually_exclusive_group()
    round_operation.add_argument("--round-begin", action="store_true")
    round_operation.add_argument("--record-round-lane", action="store_true")
    round_operation.add_argument("--record-round-lane-result", action="store_true")
    round_operation.add_argument("--record-global-review", action="store_true")
    parser.add_argument("--lane", default="")
    parser.add_argument("--max-lanes", type=int, default=0)
    parser.add_argument("--lane-status", default="")
    parser.add_argument("--review-status", default="")
    parser.add_argument("--decision", default="")
    parser.add_argument("--evidence-ref", default=None)
    parser.add_argument("--snapshot-digest", default="")
    parser.add_argument("--evidence-refs-json", default="[]")
    parser.add_argument("--cross-source-links-json", default="[]")
    parser.add_argument("--residual-unknowns-json", default="[]")
    parser.add_argument("--next-action", default="")
    round_operation.add_argument(
        "--record-round-closure",
        action="store_true",
        help=(
            "Record one completed round. Writes round progress into the checkpoint witness, "
            "which changes the closure state a recorded global review asserts over: a recorded "
            "review goes stale when this runs."
        ),
    )
    parser.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    repo = Path(args.repo_root)
    resolved_target = canonical_target_value(args.target)
    if args.record_global_review:
        try:
            if args.evidence_ref is not None:
                raise ValueError("--record-global-review requires --evidence-refs-json, not --evidence-ref")
            evidence_refs = json.loads(args.evidence_refs_json)
            cross_source_links = json.loads(args.cross_source_links_json)
            residual_unknowns = json.loads(args.residual_unknowns_json)
            result = record_global_review(
                repo,
                resolved_target,
                status=args.review_status or args.lane_status,
                snapshot_digest=args.snapshot_digest,
                evidence_refs=evidence_refs,
                cross_source_links=cross_source_links,
                residual_unknowns=residual_unknowns,
                decision=args.decision,
                next_action=args.next_action,
            )
        except (OSError, ValueError, KeyError, json.JSONDecodeError, TypeError) as exc:
            print(f"checkpoint global review failed: {exc}", file=sys.stderr)
            return 2
        print(json.dumps(result, ensure_ascii=False, indent=2) if args.json else result["path"])
        return 0
    if args.round_begin or args.record_round_lane or args.record_round_lane_result:
        try:
            if args.record_round_lane_result:
                result = record_round_lane_result(
                    repo,
                    resolved_target,
                    lane=args.lane,
                    status=args.lane_status,
                    decision=args.decision,
                    evidence_ref=args.evidence_ref or "",
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
    checkpoint["action_queue_sync"] = {
        "status": "skipped",
        "reason": "primary store action projection is read-only",
    }
    checkpoint["runtime_witness"] = {
        "status": "not_published",
        "reason": "primary checkpoint command is read-only; publish via explicit witness command",
        "path": str(_checkpoint_witness_path(repo, resolved_target).relative_to(repo)),
    }
    if args.apply_target_memory:
        result = apply_target_memory(repo, checkpoint["target"], checkpoint)
        checkpoint["apply_result"] = result

    if args.json:
        print(json.dumps(checkpoint, ensure_ascii=False, indent=2))
    else:
        print(format_checkpoint(checkpoint))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
