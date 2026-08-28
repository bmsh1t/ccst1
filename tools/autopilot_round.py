#!/usr/bin/env python3
"""Deterministic orchestration for one bounded Autopilot round.

Round persistence remains owned by ``checkpoint`` and its existing state
readers.  This module only fixes the order in which those owners are called.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    from tools.autopilot_args import MAX_LANES
    from tools.action_queue import load_queue
    from tools.autopilot_state import (
        _finalize_closure_continuation,
        _owner_source_markers,
        build_autopilot_state,
        load_closure_projection,
    )
    from tools.checkpoint import (
        _append_root_claim_queue_items,
        begin_round,
        build_checkpoint,
        checkpoint_witness_lock,
        record_round_closure,
        sync_checkpoint_action_queue,
    )
    from tools.finding_index import list_root_finding_claims, reconcile_root_finding_claims
    from tools.surface import build_surface_review
    from tools.surface_index import SurfaceIndexError
    from tools.target_paths import canonical_target_value, target_storage_key
except ImportError:  # pragma: no cover - direct tools/ execution
    from autopilot_args import MAX_LANES  # type: ignore
    from action_queue import load_queue  # type: ignore
    from autopilot_state import (  # type: ignore
        _finalize_closure_continuation,
        _owner_source_markers,
        build_autopilot_state,
        load_closure_projection,
    )
    from checkpoint import (  # type: ignore
        _append_root_claim_queue_items,
        begin_round,
        build_checkpoint,
        checkpoint_witness_lock,
        record_round_closure,
        sync_checkpoint_action_queue,
    )
    from finding_index import list_root_finding_claims, reconcile_root_finding_claims  # type: ignore
    from surface import build_surface_review  # type: ignore
    from surface_index import SurfaceIndexError  # type: ignore
    from target_paths import canonical_target_value, target_storage_key  # type: ignore


def _closure_snapshot(repo_root: Path | str, target: str) -> tuple[dict, dict]:
    """Read the bounded owner projections used by both coordinator stages."""
    for attempt in range(2):
        source_markers_before = _owner_source_markers(repo_root, target)
        queue_snapshot = load_queue(repo_root, target)
        state = build_autopilot_state(
            str(repo_root),
            target,
            bounded=True,
            queue_snapshot=queue_snapshot,
        )
        closure = load_closure_projection(
            str(repo_root),
            state,
            max_lanes_reached=False,
            queue_snapshot=queue_snapshot,
        )
        if source_markers_before != _owner_source_markers(repo_root, target):
            closure = {
                **closure,
                "verdict": "handoff",
                "can_claim_exhausted": False,
                "reasons": ["state_snapshot_stale"],
                "next_action": "refresh_state",
                "snapshot_stale": True,
                "snapshot_stale_sources": ["owner_state"],
            }
            reasons, frontier, next_action = _finalize_closure_continuation(
                ["state_snapshot_stale"],
                closure.get("actionable_frontier") or [],
                state,
                None,
                "refresh_state",
            )
            closure.update({
                "reasons": reasons,
                "actionable_frontier": frontier,
                "next_action": next_action,
            })
        if not closure.get("snapshot_stale") or attempt:
            return state, closure
    return state, closure


def _round_progress(closure: dict) -> dict:
    progress = closure.get("round_progress")
    return dict(progress) if isinstance(progress, dict) else {}


def _surface_projection_pending(state: dict, closure: dict) -> bool:
    reasons = closure.get("reasons") if isinstance(closure, dict) else []
    if "surface_projection_pending" in (reasons or []):
        return True
    projection = state.get("surface_projection") if isinstance(state, dict) else {}
    return (
        isinstance(projection, dict)
        and bool(projection)
        and bool(state.get("has_recon") or state.get("surface_context_required"))
        and str(projection.get("status") or "").strip().lower() != "valid"
    )


def _refresh_surface_if_pending(
    repo_root: Path,
    target: str,
    state: dict,
    closure: dict,
) -> tuple[dict, dict]:
    """Refresh the Surface owner before closure when owner writes changed it.

    Lane work and checkpoint write-back can publish inputs after the previous
    Surface build. Rebuilding after those writes keeps the final closure bound
    to the same manifest without making every owner remember a refresh command.
    A malformed or unavailable Surface remains an explicit handoff; checkpoint
    write-back may persist, but the round itself stays open until the projection
    is valid again.
    """
    if not _surface_projection_pending(state, closure):
        return state, closure
    try:
        build_surface_review(repo_root, target, refresh=True)
    except (OSError, ValueError, SurfaceIndexError):
        return state, closure
    return _closure_snapshot(repo_root, target)


def _result(
    operation: str,
    target: str,
    *,
    status: str,
    state: dict,
    closure: dict,
    round_progress: dict,
    checkpoint: dict | None = None,
) -> dict:
    findings = state.get("structured_findings")
    payload = {
        "schema_version": 1,
        "operation": operation,
        "target": target,
        "status": status,
        "round_progress": round_progress,
        "closure": closure,
        "structured_findings": {
            "reported": int(findings.get("reported", 0) or 0)
            if isinstance(findings, dict)
            else 0,
        },
    }
    if checkpoint is not None:
        payload["checkpoint"] = {
            key: checkpoint[key]
            for key in ("target", "decision", "next_action", "runtime_witness", "action_queue_sync")
            if key in checkpoint
        }
    return payload


def prepare_round(
    repo_root: Path | str,
    target: str,
    max_lanes: int,
) -> dict:
    """Preflight Closure and start or resume the checkpoint-owned round.

    A terminal owner verdict is returned without creating a round witness.
    Repeating this operation while the round is active delegates to
    ``begin_round`` which preserves its round id and budget.
    """
    if (
        isinstance(max_lanes, bool)
        or not isinstance(max_lanes, int)
        or not 1 <= max_lanes <= MAX_LANES
    ):
        raise ValueError(f"max_lanes must be an integer from 1 to {MAX_LANES}")
    repo = Path(repo_root)
    resolved_target = canonical_target_value(target)
    state, closure = _closure_snapshot(repo, resolved_target)
    if closure.get("verdict") in {"finish", "blocked"}:
        return _result(
            "prepare",
            resolved_target,
            status="terminal",
            state=state,
            closure=closure,
            round_progress=_round_progress(closure),
        )
    started = begin_round(repo, resolved_target, max_lanes=max_lanes)
    return _result(
        "prepare",
        resolved_target,
        status=str(started.get("status") or "resumed"),
        state=state,
        closure=closure,
        round_progress=dict(started.get("round_progress") or {}),
    )


def settle_round(
    repo_root: Path | str,
    target: str,
    *,
    note: str = "",
    refresh_coverage: bool = True,
) -> dict:
    """Persist checkpoint/Queue state, close the round, and project Closure.

    The preflight is deliberately before checkpoint construction.  A started
    lane therefore fails without changing the witness, Queue, or coverage.
    A completed round is a read-only idempotent replay.
    """
    repo = Path(repo_root)
    resolved_target = canonical_target_value(target)
    with checkpoint_witness_lock(repo, resolved_target):
        state, closure = _closure_snapshot(repo, resolved_target)
        progress = _round_progress(closure)
        if not progress:
            raise ValueError("round settle requires an active or completed round")
        unfinished = list(progress.get("unfinished_lanes") or [])
        if unfinished:
            raise ValueError("cannot settle round with unfinished lanes: " + ", ".join(map(str, unfinished)))
        if progress.get("status") == "completed":
            return _result(
                "settle",
                resolved_target,
                status="already_settled",
                state=state,
                closure=closure,
                round_progress=progress,
            )
        if progress.get("invalid_evidence_lanes"):
            raise ValueError(
                "cannot settle round with invalid completed lane evidence: "
                + ", ".join(map(str, progress["invalid_evidence_lanes"]))
            )

        findings_dir = repo / "findings" / target_storage_key(resolved_target)
        claim_sync = reconcile_root_finding_claims(findings_dir, target=resolved_target)
        checkpoint = build_checkpoint(
            repo,
            target=resolved_target,
            note=note,
            refresh_coverage=refresh_coverage,
        )
        checkpoint["root_finding_claim_sync"] = claim_sync
        _append_root_claim_queue_items(
            checkpoint,
            list_root_finding_claims(
                findings_dir,
                target=resolved_target,
                include_reconciled=True,
            ),
            resolved_target,
        )
        sync_checkpoint_action_queue(repo, checkpoint)
        state, closure = _closure_snapshot(repo, resolved_target)
        state, closure = _refresh_surface_if_pending(
            repo,
            resolved_target,
            state,
            closure,
        )
        if _surface_projection_pending(state, closure):
            return _result(
                "settle",
                resolved_target,
                status="handoff",
                state=state,
                closure=closure,
                round_progress=progress,
                checkpoint=checkpoint,
            )
        closed = record_round_closure(repo, resolved_target)
        final_state, final_closure = _closure_snapshot(repo, resolved_target)
        return _result(
            "settle",
            resolved_target,
            status="settled",
            state=final_state,
            closure=final_closure,
            round_progress=dict(closed.get("round_progress") or {}),
            checkpoint=checkpoint,
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Prepare or settle one Autopilot round")
    parser.add_argument("operation", choices=("prepare", "settle"))
    parser.add_argument("--target", required=True)
    parser.add_argument("--repo-root", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--max-lanes", type=int, default=0)
    parser.add_argument("--note", default="")
    parser.add_argument("--no-refresh-coverage", action="store_true")
    parser.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    operation = args.operation
    if operation == "prepare" and args.max_lanes < 1:
        parser.error("--max-lanes must be a positive integer for prepare")
    try:
        result = (
            prepare_round(args.repo_root, args.target, args.max_lanes)
            if operation == "prepare"
            else settle_round(
                args.repo_root,
                args.target,
                note=args.note,
                refresh_coverage=not args.no_refresh_coverage,
            )
        )
    except (OSError, ValueError, KeyError) as exc:
        print(f"autopilot round {operation} failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2) if args.json else result["status"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
