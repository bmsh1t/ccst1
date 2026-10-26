"""Shared structural reader for the checkpoint round witness."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

try:
    from tools.autopilot_args import MAX_LANES
    from tools.target_paths import canonical_target_value, target_storage_key, target_owned_nonempty_evidence_ref
    from tools.target_store import runtime_store, ConflictError
except ImportError:  # pragma: no cover - direct tools/ execution
    from autopilot_args import MAX_LANES  # type: ignore
    from target_paths import canonical_target_value, target_storage_key, target_owned_nonempty_evidence_ref  # type: ignore
    from target_store import runtime_store, ConflictError


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


def is_canonical_coverage_lane_evidence_ref(
    lane_id: str,
    evidence_ref: str,
    target: str,
) -> bool:
    """Require coverage completion to point at an existing canonical owner."""
    if not str(lane_id or "").strip().lower().startswith("coverage:"):
        return True
    key = target_storage_key(canonical_target_value(target))
    normalized = str(evidence_ref or "").strip().replace("\\", "/").lstrip("./")
    return normalized in {
        f"evidence/{key}/coverage_matrix.json",
        f"state/{key}/metadata.sqlite3",
    }


def validate_report_binding(binding: dict) -> dict:
    fields = {"store_id", "finding_id", "assessment_id", "delivery_id"}
    if not isinstance(binding, dict) or set(binding) != fields or any(
        not isinstance(value, str) or not value or value != value.strip()
        or len(value) > 200 or "\n" in value or "\r" in value
        for value in binding.values()
    ):
        raise ValueError("round report binding requires Store, Finding, assessment and delivery IDs")
    return dict(binding)


def effective_round_lane(lane: dict) -> dict:
    """Project the latest explicit evidence correction, retaining the original lane."""
    result = dict(lane)
    corrections = lane.get("evidence_corrections") or []
    if corrections:
        last = corrections[-1]
        result["evidence_ref"] = last["evidence_ref"]
        if "report_binding" in last:
            result["report_binding"] = last["report_binding"]
        result["evidence_contract"] = 2
        result["correction_id"] = last["id"]
    return result


def round_lane_evidence_ref(repo_root, target, lane: dict) -> str:
    """One evidence-ownership check for heartbeat, recovery and Closure."""
    item = effective_round_lane(lane)
    ref = target_owned_nonempty_evidence_ref(repo_root, target, item.get("evidence_ref"))
    if not ref:
        raise ValueError("completed round lane requires target-owned, non-empty evidence_ref")
    if not is_canonical_coverage_lane_evidence_ref(item["id"], ref, target):
        raise ValueError("completed coverage lane requires canonical Coverage Matrix or current TargetStore evidence_ref")
    binding = item.get("report_binding")
    if binding is None:
        if item.get("evidence_contract") == 2 and Path(ref).parts[0] == "reports":
            raise ValueError("report evidence requires Finding/assessment/delivery binding at lane claim")
        return ref
    binding = validate_report_binding(binding)
    store = runtime_store(repo_root, target)
    before = store.binding()
    if before["store_id"] != binding["store_id"]:
        raise ValueError("round lane report belongs to a different Store generation")
    finding = store.finding(binding["finding_id"])
    report = next((report for report in finding["reports"] if (
        report["assessment_id"], report["delivery_id"], report["artifact_ref"]
    ) == (binding["assessment_id"], binding["delivery_id"], ref)), None)
    if not report or not report["artifact_available"] or not report["artifact_authorized"]:
        raise ValueError("evidence_ref is not an intact registered report for this lane's Finding/assessment/delivery")
    if store.binding() != before:
        raise ConflictError("report owner changed during lane verification; retry")
    return ref


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
        or type(progress.get("schema_version")) is not int
        or progress.get("schema_version") not in {1, 2}
        or progress.get("status") not in {"active", "completed"}
    ):
        raise ValueError("checkpoint round_progress is invalid")

    limit = progress.get("max_lanes")
    unlimited = progress["schema_version"] == 2 and "max_lanes" in progress and limit is None
    claimed = progress.get("claimed_lanes")
    if (
        (not unlimited and (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= MAX_LANES
        ))
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
        or (not unlimited and len(claimed) > limit)
        or isinstance(progress.get("claimed_count"), bool)
        or not isinstance(progress.get("claimed_count"), int)
        or progress.get("claimed_count") != len(claimed)
        or (unlimited and (
            "remaining_lanes" not in progress or progress["remaining_lanes"] is not None
        ))
        or (not unlimited and (
            isinstance(progress.get("remaining_lanes"), bool)
            or not isinstance(progress.get("remaining_lanes"), int)
            or progress.get("remaining_lanes") != limit - len(claimed)
        ))
        or not isinstance(progress.get("budget_reached"), bool)
        or progress.get("budget_reached") != (not unlimited and len(claimed) >= limit)
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
        if "evidence_contract" in lane and (type(lane["evidence_contract"]) is not int or lane["evidence_contract"] != 2):
            raise ValueError("unsupported round lane evidence contract")
        if "report_binding" in lane:
            validate_report_binding(lane["report_binding"])
        corrections = lane.get("evidence_corrections", [])
        if not isinstance(corrections, list) or corrections and status != "completed":
            raise ValueError("only completed round lanes may have evidence corrections")
        previous, correction_ids = None, set()
        fixed_binding = lane.get("report_binding")
        for correction in corrections:
            required = {"id", "previous", "evidence_ref", "reason", "actor", "recorded_at"}
            if not isinstance(correction, dict) or not required <= set(correction) or set(correction) - required - {"report_binding"}:
                raise ValueError("invalid round lane evidence correction")
            for field, size in (("id", 200), ("evidence_ref", 500), ("reason", 500), ("actor", 200), ("recorded_at", 100)):
                value = correction[field]
                if not isinstance(value, str) or not value.strip() or len(value) > size or "\n" in value or "\r" in value:
                    raise ValueError("invalid round lane evidence correction fields")
            if correction["id"] in correction_ids or correction["previous"] != previous:
                raise ValueError("invalid round lane evidence correction history")
            if "report_binding" in correction:
                validate_report_binding(correction["report_binding"])
                if fixed_binding and correction["report_binding"] != fixed_binding:
                    raise ValueError("evidence correction cannot change the claimed report owner")
                fixed_binding = correction["report_binding"]
            elif fixed_binding:
                raise ValueError("evidence correction must retain the report owner")
            previous = correction["id"]
            correction_ids.add(previous)
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
                and effective_round_lane(lane).get("evidence_ref") == "none"
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
