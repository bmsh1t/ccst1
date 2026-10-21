"""Explicit review receipts for one Runner candidate; no Finding judgments."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

try:
    from tools.artifact_io import write_json_atomic
    from tools.browser_evidence import read_target_artifact
    from tools.contracts import runner_summary_lane
    from tools.target_paths import target_storage_key
    from tools.target_store import ConflictError, StoreError, runtime_store, target_mutation_lock
except ImportError:  # pragma: no cover - direct tools/ execution
    from artifact_io import write_json_atomic
    from browser_evidence import read_target_artifact
    from contracts import runner_summary_lane
    from target_paths import target_storage_key
    from target_store import ConflictError, StoreError, runtime_store, target_mutation_lock


class CandidateMaterialChanged(ValueError):
    """A review receipt no longer covers intact candidate material."""


def _text(value, name, limit=500):
    if not isinstance(value, str) or not value.strip() or value != value.strip() or len(value) > limit:
        raise ValueError(f"candidate review {name} requires nonempty text (at most {limit} characters)")
    if "\n" in value or "\r" in value:
        raise ValueError(f"candidate review {name} must be one line")
    return value


def _review_path(store, summary_ref):
    path = Path(summary_ref)
    path = path if path.is_absolute() else store.root / path
    relative = path.relative_to(store.root)
    prefix = ("evidence", target_storage_key(store.target), "validation")
    if relative.parts[:3] != prefix or path.name != "summary.json":
        raise ValueError("candidate review requires a target validation summary.json")
    return path.with_name("candidate-review.json")


def _read_history(store, path):
    if not path.exists() and not path.is_symlink():
        return []
    raw, _ = read_target_artifact(store.root, store.target, str(path))
    payload = json.loads(raw)
    if not isinstance(payload, dict) or set(payload) != {"schema_version", "events"} or type(payload["schema_version"]) is not int or payload["schema_version"] != 1:
        raise ValueError("invalid candidate review receipt")
    events = payload["events"]
    if not isinstance(events, list) or not events:
        raise ValueError("candidate review receipt requires events")
    previous, ids = None, set()
    for event in events:
        if not isinstance(event, dict) or set(event) != {"id", "previous", "status", "reason", "actor", "recorded_at", "binding"}:
            raise ValueError("invalid candidate review event")
        for field in ("id", "reason", "actor", "recorded_at"):
            _text(event[field], field)
        if event["id"] in ids or event["previous"] != previous or event["status"] not in {"closed", "open"}:
            raise ValueError("invalid candidate review history")
        binding = event["binding"]
        if not isinstance(binding, dict) or set(binding) != {
            "target", "store_id", "finding_id", "attempt_id", "operation_id", "summary_ref", "summary_sha256"
        } or any(not isinstance(value, str) or not value for value in binding.values()):
            raise ValueError("invalid candidate review binding")
        if binding["target"] != store.target or binding["summary_ref"] != str(path.with_name("summary.json").relative_to(store.root)):
            raise ValueError("candidate review receipt belongs to a different summary")
        ids.add(event["id"])
        previous = event["id"]
    return events


def _capture_candidate(store, summary_ref):
    before = store.binding()
    raw, ref = read_target_artifact(store.root, store.target, str(summary_ref))
    summary = json.loads(raw)
    if not isinstance(summary, dict) or not runner_summary_lane(summary) or runner_summary_lane(summary) == "native_observation":
        raise ValueError("review requires a Runner candidate summary")
    if summary.get("result") not in {"candidate", "tested_finding"} and summary.get("candidate_ready") is not True:
        raise ValueError("summary is not a Runner review candidate")
    expected = {key: str(before[key]) for key in ("target", "backend", "store_id")}
    if summary.get("target") != store.target or summary.get("backend_binding") != expected:
        raise ValueError("candidate summary belongs to another target or Store generation")
    finding_id = _text(summary.get("finding_id"), "finding_id")
    operation_id = _text(summary.get("store_operation_id"), "store_operation_id")
    attempt_id = _text(summary.get("attempt_id"), "attempt_id")
    finding = store.finding(finding_id)
    execution = store.execution(operation_id)
    if execution["attempt_id"] != attempt_id or execution["outcome"] != "complete" or not any(
        item["operation_id"] == operation_id for item in finding["evidence"]
    ):
        raise ValueError("candidate review requires its complete, Finding-linked Store operation")
    # Validate the summary's complete artifact manifest, including top-level diff.
    bindings = summary.get("artifact_bindings")
    if not isinstance(bindings, list) or not bindings:
        raise ValueError("candidate review requires artifact_bindings")
    bound = {}
    for item in bindings:
        if (not isinstance(item, dict) or set(item) != {"kind", "ref", "sha256"}
                or any(not isinstance(value, str) or not value for value in item.values())
                or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"])):
            raise ValueError("invalid candidate artifact binding")
        key = (item["kind"], item["ref"])
        if key in bound:
            raise ValueError("duplicate candidate artifact binding")
        bound[key] = item["sha256"]
        try:
            data, _ = read_target_artifact(store.root, store.target, item["ref"])
        except (OSError, ValueError) as exc:
            raise CandidateMaterialChanged("candidate artifact unavailable or unsafe: " + item["ref"]) from exc
        if hashlib.sha256(data).hexdigest() != item["sha256"]:
            raise CandidateMaterialChanged("candidate artifact changed: " + item["ref"])
    try:
        store.verify_operation(operation_id)
    except StoreError as exc:
        if str(exc).startswith("registered evidence "):
            raise CandidateMaterialChanged(str(exc)) from exc
        raise
    registered = {item["ref"]: item["sha256"] for observation in execution["observations"] for item in observation["artifacts"]}
    runs = summary.get("runs")
    if not isinstance(runs, list) or not runs:
        raise ValueError("candidate review requires recorded runs")
    for run in runs:
        artifacts = run.get("artifacts") if isinstance(run, dict) else None
        if not isinstance(artifacts, dict) or not artifacts:
            raise ValueError("candidate run requires registered artifacts")
        for kind, artifact in artifacts.items():
            if not isinstance(artifact, str) or not artifact:
                raise ValueError("candidate artifact must be a nonempty reference")
            data, artifact_ref = read_target_artifact(store.root, store.target, artifact)
            if bound.get((kind, artifact)) != hashlib.sha256(data).hexdigest():
                raise ValueError("candidate run artifact is absent from artifact_bindings")
            if registered.get(artifact_ref) != hashlib.sha256(data).hexdigest():
                raise ValueError("candidate run material does not match its registered operation")
    top_level = summary.get("artifacts", {})
    if not isinstance(top_level, dict):
        raise ValueError("candidate top-level artifacts must be an object")
    for kind, artifact in top_level.items():
        if not isinstance(artifact, str) or (kind, artifact) not in bound:
            raise ValueError("candidate top-level artifact is absent from artifact_bindings")
    if store.binding() != before or read_target_artifact(store.root, store.target, ref)[0] != raw:
        raise ConflictError("candidate changed during review; reread the candidate")
    return {
        "target": store.target, "store_id": before["store_id"], "finding_id": finding_id,
        "attempt_id": attempt_id, "operation_id": operation_id,
        "summary_ref": ref, "summary_sha256": hashlib.sha256(raw).hexdigest(),
    }


def candidate_review_state(store, summary_ref, *, summary_sha256=None):
    """Return explicit review state; changed material stays visible for review."""
    path = _review_path(store, summary_ref)
    events = _read_history(store, path)
    if not events:
        return None
    latest = events[-1]
    raw, _ = read_target_artifact(store.root, store.target, str(path.with_name("summary.json")))
    if (latest["binding"]["store_id"] != store.binding()["store_id"]
            or latest["binding"]["summary_sha256"] != hashlib.sha256(raw).hexdigest()
            or summary_sha256 is not None and summary_sha256 != hashlib.sha256(raw).hexdigest()):
        return {"status": "stale", "review_id": latest["id"], "reason": "candidate material or Store generation changed"}
    try:
        current = _capture_candidate(store, str(path.with_name("summary.json")))
    except CandidateMaterialChanged as exc:
        return {"status": "stale", "review_id": latest["id"], "reason": str(exc)}
    if current != latest["binding"]:
        return {"status": "stale", "review_id": latest["id"], "reason": "candidate binding changed"}
    return {"status": latest["status"], "review_id": latest["id"], "reason": latest["reason"]}


def review_candidate(repo_root, target, *, summary_ref, review_id, status, reason,
                     expected_summary_sha256, actor="validation-runner", expected_review_id=None):
    """Close/reopen exactly one reviewed bundle, retaining prior receipts."""
    review_id = _text(review_id, "id", 200)
    reason = _text(reason, "reason")
    actor = _text(actor, "actor", 200)
    if status not in {"closed", "open"}:
        raise ValueError("candidate review status must be closed or open")
    if expected_review_id is not None:
        _text(expected_review_id, "expected_review_id", 200)
    if not isinstance(expected_summary_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_summary_sha256):
        raise ValueError("candidate review requires expected_summary_sha256 from the reviewed candidate")
    store = runtime_store(Path(repo_root).resolve(), target)
    with target_mutation_lock(store.root, store.target):
        path = _review_path(store, summary_ref)
        events = _read_history(store, path)
        existing = next((event for event in events if event["id"] == review_id), None)
        # Reopening revokes an existing review receipt, even if its raw bytes are damaged.
        prior = existing or (events[-1] if events and status == "open" else None)
        binding = prior["binding"] if prior else _capture_candidate(store, summary_ref)
        if binding["summary_sha256"] != expected_summary_sha256:
            raise ConflictError("candidate material changed; reread its summary_sha256 before review")
        requested = {"id": review_id, "previous": expected_review_id, "status": status,
                     "reason": reason, "actor": actor, "binding": binding}
        if existing:
            if any(existing[key] != value for key, value in requested.items()):
                raise ConflictError("candidate review ID already has different content")
            return {"status": "already_recorded", "receipt": existing, "current_review_id": events[-1]["id"], "path": str(path)}
        previous = events[-1]["id"] if events else None
        if expected_review_id != previous:
            raise ConflictError(f"candidate review changed; expected_review_id must be {previous!r}")
        event = {**requested, "recorded_at": datetime.now(timezone.utc).isoformat()}
        write_json_atomic(path, {"schema_version": 1, "events": [*events, event]})
        return {"status": "recorded", "receipt": event, "current_review_id": review_id, "path": str(path)}
