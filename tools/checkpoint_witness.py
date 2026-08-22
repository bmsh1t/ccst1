"""Shared structural reader for the checkpoint round witness."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

try:
    from tools.autopilot_args import MAX_LANES
except ImportError:  # pragma: no cover - direct tools/ execution
    from autopilot_args import MAX_LANES  # type: ignore


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_checkpoint_witness(path: Path) -> dict:
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


def new_round_lane(lane_id: str, *, started_at: str | None = None) -> dict:
    timestamp = started_at or _now_utc()
    return {
        "schema_version": 1,
        "id": lane_id,
        "status": "started",
        "decision": "",
        "evidence_ref": "",
        "next_action": "",
        "started_at": timestamp,
        "updated_at": timestamp,
    }


def validate_round_progress(
    payload: dict,
    *,
    allow_invalid_completed_evidence: bool = False,
) -> dict:
    """Return validated progress, normalizing legacy witnesses without lanes."""
    progress = payload.get("round_progress")
    if progress is None:
        return {}
    if (
        not isinstance(progress, dict)
        or progress.get("schema_version") != 1
        or progress.get("status") not in {"active", "completed"}
    ):
        raise ValueError("checkpoint round_progress is invalid")

    limit = progress.get("max_lanes")
    claimed = progress.get("claimed_lanes")
    if (
        isinstance(limit, bool)
        or not isinstance(limit, int)
        or not 1 <= limit <= MAX_LANES
        or not isinstance(claimed, list)
        or any(
            not isinstance(item, str)
            or not item
            or len(item) > 200
            or "\n" in item
            or "\r" in item
            for item in claimed
        )
        or len(set(claimed)) != len(claimed)
        or len(claimed) > limit
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
        started_at = str(progress.get("started_at") or _now_utc())
        lanes = [new_round_lane(lane_id, started_at=started_at) for lane_id in claimed]
        progress["lanes"] = lanes
    if not isinstance(lanes, list):
        raise ValueError("checkpoint round_progress lanes are invalid")

    lane_ids = []
    for lane in lanes:
        if not isinstance(lane, dict) or lane.get("schema_version") != 1:
            raise ValueError("checkpoint round_progress lane is invalid")
        lane_id = lane.get("id")
        status = lane.get("status")
        if (
            not isinstance(lane_id, str)
            or not lane_id
            or lane_id not in claimed
            or status not in {"started", "completed", "blocked"}
        ):
            raise ValueError("checkpoint round_progress lane fields are invalid")
        for field, limit in (("decision", 500), ("evidence_ref", 500), ("next_action", 1000)):
            value = lane.get(field, "")
            if not isinstance(value, str) or "\n" in value or "\r" in value or len(value) > limit:
                raise ValueError("checkpoint round_progress lane fields are invalid")
        for field in ("started_at", "updated_at"):
            if not isinstance(lane.get(field), str) or not lane.get(field):
                raise ValueError("checkpoint round_progress lane timestamps are invalid")
        if status == "started":
            if any(lane.get(field) for field in ("decision", "evidence_ref", "next_action", "finished_at")):
                raise ValueError("checkpoint started round lane has terminal fields")
        elif (
            not isinstance(lane.get("finished_at"), str)
            or not lane.get("finished_at")
            or "\n" in lane.get("finished_at")
            or "\r" in lane.get("finished_at")
            or not lane.get("decision")
            or not lane.get("evidence_ref")
            or not lane.get("next_action")
            or (
                not allow_invalid_completed_evidence
                and status == "completed"
                and lane.get("evidence_ref") == "none"
            )
        ):
            raise ValueError("checkpoint terminal round lane is incomplete")
        lane_ids.append(lane_id)

    if lane_ids != claimed:
        raise ValueError("checkpoint round_progress lane identities are invalid")
    if progress["status"] == "completed" and any(
        lane.get("status") == "started" for lane in lanes
    ):
        raise ValueError("checkpoint completed round has unfinished lanes")
    return progress
