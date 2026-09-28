#!/usr/bin/env python3
"""Persistent action queue for capability-first autopilot runs.

The queue turns evidence-backed next steps into durable state so Claude CLI can
keep executing instead of ending on natural-language TODOs.
"""

from __future__ import annotations

import argparse
import copy
import fcntl
import hashlib
import json
import os
import re
import sys
import tempfile
import urllib.parse
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parents[1]
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

try:
    from tools.target_paths import canonical_target_value, target_storage_key, target_owned_nonempty_evidence_ref
    from tools.target_store import ConflictError, StoreError, TargetStore, runtime_store, target_switch_lock
except ImportError:  # pragma: no cover - direct tools/ execution
    from target_paths import canonical_target_value, target_storage_key, target_owned_nonempty_evidence_ref  # type: ignore
    from target_store import ConflictError, StoreError, TargetStore, runtime_store, target_switch_lock  # type: ignore


SCHEMA_VERSION = 1
ACTION_CONTEXT_FIELDS = (
    "type", "source", "source_id", "evidence", "next_question", "command_hint",
    "evidence_type", "safety", "stop_condition",
)
ACTIVE_STATUSES = {"queued", "running", "lead", "signal", "candidate"}
FINAL_STATUSES = {"tested", "dead-end", "blocked", "validated", "reported", "n/a"}
ALLOWED_STATUSES = ACTIVE_STATUSES | FINAL_STATUSES
STATUS_ALIASES = {
    # coverage_matrix/evidence_ledger vocabulary -> action_queue vocabulary
    "tested_clean": "tested",
    "tested-clean": "tested",
    "clean": "tested",
    "tested_finding": "candidate",
    "tested-finding": "candidate",
    "finding": "candidate",
    # Common operator shorthand
    "na": "n/a",
    "n.a.": "n/a",
    "not-applicable": "n/a",
    "not_applicable": "n/a",
}
DEFAULT_STOP_CONDITION = (
    "record tested, dead-end, blocked, lead, signal, candidate, or validated "
    "before moving to the next queued action"
)
COVERAGE_STATUS_BY_ACTION_STATUS = {
    "tested": "tested_clean",
    "n/a": "n_a",
    "candidate": "tested_finding",
    "validated": "tested_finding",
    "reported": "tested_finding",
}
UNSAFE_REVIEW_FINAL_STATUSES = {"tested", "dead-end", "blocked", "n/a", "candidate", "validated", "reported"}
TERMINAL_EVIDENCE_STATUSES = {"validated", "reported"}
REPORT_ACTION_TYPES = {"report"}
ADVISORY_REVIEW_ACTION_TYPES = {
    "surface-review", "capability-chain-review", "knowledge-signal-review",
}
LOW_EVIDENCE_SURFACE_REVIEW_MARKERS = (
    "reason: top advisory score",
    "reason: top advisory score (low-evidence fallback)",
)
SENSITIVE_METADATA_KEYS = {
    "access_token",
    "api_key",
    "authorization",
    "bearer",
    "client_secret",
    "cookie",
    "credentials",
    "credential",
    "csrf_token",
    "header_value",
    "headers",
    "id_token",
    "password",
    "private_key",
    "private_marker",
    "refresh_token",
    "secret",
    "secret_value",
    "session_cookie",
    "set_cookie",
}
RUNNER_OBSERVATION_FIELDS = {"last_outcome", "tested_dimensions", "runner_operation_id"}
DEPTH_CONTRACT_VERSION = 1
RISK_TIERS = {"low", "medium", "high", "critical"}
# The runaway bound for an executing hypothesis. The security property is
# "an executing hypothesis has a bound", not "the bound was minted by the
# checkpoint path": an AI-discovered candidate added outside the checkpoint
# gets the same default bound at claim time instead of being unclaimable.
DEFAULT_HYPOTHESIS_ACTIONS_CAP = 4
CONTINUATION_KINDS = {
    "sibling", "bypass", "identity", "object", "parser", "transport",
    "workflow", "chain", "rotation", "blocked",
}
MAX_CAPABILITY_PRIMITIVES = 3


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _validate_action_metadata(metadata: dict | None) -> dict:
    if metadata is None:
        return {}
    if not isinstance(metadata, dict):
        raise ValueError("Action Queue metadata must be a JSON object")

    def visit(value: Any, path: str) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                normalized = re.sub(r"[^a-z0-9]+", "_", str(key).lower()).strip("_")
                child_path = f"{path}.{key}"
                if normalized in SENSITIVE_METADATA_KEYS and child not in (None, "", [], {}):
                    raise ValueError(f"Action Queue metadata cannot contain sensitive field {child_path}")
                visit(child, child_path)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, f"{path}[{index}]")

    visit(metadata, "metadata")
    return metadata


def queue_path(repo_root: Path | str, target: str) -> Path:
    repo = Path(repo_root)
    resolved = canonical_target_value(target)
    return repo / "state" / target_storage_key(resolved) / "action_queue.json"


def _primary_action_projection(store: TargetStore, *, statuses: tuple[str, ...] | None = None, action_type: str | None = None) -> dict:
    """Expose Store actions in the legacy CLI shape without creating a file owner."""
    page = store.action_page(statuses=statuses, action_type=action_type, limit=1000)
    rows = list(page.get("items") or [])
    while page.get("has_more"):
        page = store.action_page(statuses=statuses, action_type=action_type, limit=1000, cursor=page.get("next_cursor"))
        rows.extend(page.get("items") or [])
    return {
        "schema_version": SCHEMA_VERSION,
        "target": canonical_target_value(store.target),
        "backend": "primary",
        "store_id": page.get("store_id", ""),
        "revision": page.get("revision", 0),
        "actions": _project_actions(rows),
    }


def _project_actions(rows: list[dict]) -> list[dict]:
    status_map = {
        "ready": "queued",
        "claimed": "running",
        "blocked": "blocked",
        "completed": "tested",
        "cancelled": "n/a",
    }
    actions = []
    for row in rows:
        metadata = {
            "execution_key": str(row.get("execution_key") or ""),
            "store_status": str(row.get("status") or ""),
        }
        stored_metadata = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
        metadata.update(copy.deepcopy(stored_metadata))
        # Older callers may use this open metadata key for unrelated values.
        # Only descriptive strings project; the original metadata stays visible.
        context = metadata.get("action_context")
        context = {key: value for key, value in context.items()
                   if key in ACTION_CONTEXT_FIELDS and isinstance(value, str)} if isinstance(context, dict) else {}
        for key in ("endpoint", "family", "subject_artifact_id", "subject_finding_id", "subject_experience_id"):
            if row.get(key) not in (None, ""):
                metadata[key] = row[key]
        if row.get("claim_token"):
            metadata["claim_token"] = row["claim_token"]
        actions.append({
            "id": row.get("id", ""),
            "type": str(row.get("kind") or "work"),
            "status": status_map.get(str(row.get("status") or ""), "blocked"),
            "priority": row.get("priority"),
            "action": row.get("intent", ""),
            "evidence": row.get("reason", ""),
            "metadata": metadata,
            "created_at": row.get("created_at", ""),
            "updated_at": row.get("updated_at", ""),
            "source": "target_store",
            "result": str(row.get("reason") or ""),
            **context,
        })
    return actions


def load_queue_summary(repo_root: Path | str, target: str, *, limit: int = 5) -> dict:
    """Bounded work view; full list/closure readers keep load_queue()."""
    store = runtime_store(repo_root, target)
    snapshot = store.action_summary(limit=limit)
    return {
        "schema_version": SCHEMA_VERSION, "target": canonical_target_value(store.target),
        "backend": "primary", "store_id": snapshot["store_id"], "revision": snapshot["revision"],
        "actions": _project_actions(snapshot["items"]),
        "total": snapshot["counts"]["total"], "pending_total": snapshot["counts"]["pending"],
        "active_families": snapshot["active_families"],
        **{key: _project_actions([snapshot[key]])[0] if snapshot[key] else {}
           for key in ("next_action", "running_action")},
    }


def _primary_action_id(target: str, action_id: str, built: dict) -> str:
    explicit = str(action_id or "").strip()
    if explicit:
        return explicit
    material = {
        "target": canonical_target_value(target),
        "source": built.get("source", ""),
        "source_id": built.get("source_id", ""),
        "type": built.get("type", ""),
        "action": built.get("action", ""),
        "next_question": built.get("next_question", ""),
        "metadata": built.get("metadata") or {},
    }
    return "action:" + hashlib.sha256(
        json.dumps(material, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()[:24]


def _primary_action_intent(built: dict) -> str:
    return _compact_text(built.get("action") or built.get("next_question") or built.get("type") or "work", 1000)


def _primary_create_action(
    repo_root: Path | str,
    target: str,
    built: dict,
    *,
    action_id: str = "",
    actor: str = "action-queue",
) -> dict:
    store = runtime_store(repo_root, target)
    metadata = copy.deepcopy(built.get("metadata") or {})
    metadata["action_context"] = {key: built[key] for key in ACTION_CONTEXT_FIELDS}
    endpoint = str(metadata.get("endpoint") or metadata.get("url") or "").strip()
    family = str(metadata.get("family") or metadata.get("vuln_class") or "").strip()
    evidence_ref = target_owned_nonempty_evidence_ref(repo_root, target, metadata.get("evidence_ref"))
    if endpoint and family:
        kind = "execution"
        subject = None
    elif endpoint:
        kind = "work"
        subject = {"url": endpoint}
        endpoint = ""
    elif evidence_ref:
        kind = "work"
        subject = {"artifact": evidence_ref}
    else:
        kind = "work"
        subject = {"target": canonical_target_value(target)}
    execution_key = str(metadata.get("execution_key") or "").strip()
    if not execution_key:
        execution_key = "intent:" + hashlib.sha256(
            json.dumps(
                {"target": canonical_target_value(target), "action_id": _primary_action_id(target, action_id, built),
                 "intent": _primary_action_intent(built)},
                ensure_ascii=True, sort_keys=True, separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()[:24]
    store_action_id = _primary_action_id(target, action_id, built)
    command_id = "action:add:" + hashlib.sha256(
        json.dumps(
            {"action_id": store_action_id, "intent": _primary_action_intent(built), "kind": kind,
             "endpoint": endpoint, "family": family, "subject": subject, "execution_key": execution_key,
             "priority": built.get("priority")},
            ensure_ascii=True, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()[:24]
    arguments = dict(
        command_id=command_id,
        action_id=store_action_id,
        intent=_primary_action_intent(built),
        execution_key=execution_key,
        actor=actor,
        endpoint=endpoint or None,
        family=family if kind == "execution" else None,
        kind=kind,
        subject=subject,
        priority=int(built.get("priority", 50) or 50),
    )
    try:
        receipt = store.create_action(**arguments, metadata=metadata)
    except ConflictError:
        # Pre-context receipts bind the original metadata. Replay that exact
        # payload, never backfill descriptions or weaken new command conflicts.
        original_metadata = built.get("metadata") or {}
        if "action_context" in original_metadata:
            raise
        receipt = store.create_action(**arguments, metadata=original_metadata)
    return {
        "backend": "primary",
        "receipt": receipt,
        "action": store.action(store_action_id),
        "queue": _primary_action_projection(store),
        "stats": {"added": 0 if receipt.get("replayed") else 1, "updated": 0, "skipped_final": 0},
    }


def _primary_completion(result: str) -> dict:
    text = str(result or "").strip()
    for key in ("operation_id", "artifact", "command_id"):
        match = re.search(rf"(?:^|[;\s]){re.escape(key)}=([^;\s]+)", text)
        if match:
            return {key: match.group(1).strip("`'\"()[]{}<>,")}
    raise StoreError(
        "primary action completion requires an explicit operation_id=, artifact=, or command_id= proof"
    )


def _primary_claim(
    repo_root: Path | str,
    target: str,
    *,
    action_id: str,
    metadata: dict | None,
    actor: str,
) -> dict:
    store = runtime_store(repo_root, target)
    current = store.action(action_id)
    status = str(current.get("status") or "")
    if status == "claimed":
        if current.get("claimed_by") != actor:
            raise StoreError(f"action {action_id} is claimed by another operator")
        if metadata:
            store.transition_action(
                command_id=current["claim_token"], action_id=action_id,
                expected_version=int(current["version"]) - 1,
                status="claimed", actor=actor, metadata=metadata,
            )
        return {**current, "claim_status": "resumed", "previous_status": "claimed"}
    if status != "ready":
        raise StoreError(f"action {action_id} is not ready for claim: {status}")
    command_id = f"action:claim:{action_id}:{current.get('version', 0)}"
    receipt = store.transition_action(
        command_id=command_id, action_id=action_id, expected_version=int(current["version"]),
        status="claimed", actor=actor, metadata=metadata,
    )
    return {**store.action(action_id), "receipt": receipt,
            "claim_status": "resumed" if receipt["replayed"] else "claimed", "previous_status": "ready"}


def _primary_resolve(
    repo_root: Path | str,
    target: str,
    *,
    action_id: str,
    status: str,
    result: str,
    notes: str,
    metadata: dict | None,
    actor: str,
) -> dict:
    store = runtime_store(repo_root, target)
    current = store.action(action_id)
    requested = _normalize_status(status)
    mapped = {
        "queued": "ready", "running": "claimed", "blocked": "blocked",
        "dead-end": "cancelled", "n/a": "cancelled", "tested": "completed",
        "validated": "completed", "reported": "completed",
    }.get(requested)
    if mapped is None:
        raise StoreError(
            f"primary action status {status!r} is observation state; record Store evidence before resolving the action"
        )
    if mapped == "claimed":
        raise StoreError("primary action re-claim is explicit: use claim, not resolve running")
    completion = _primary_completion(result) if mapped == "completed" else None
    def command_id_for(version: int) -> str:
        return "action:resolve:" + hashlib.sha256(
            json.dumps(
                {"action_id": action_id, "version": version, "status": mapped,
                 "result": result, "notes": notes, "completion": completion,
                 "metadata": metadata, "actor": actor},
                ensure_ascii=True, sort_keys=True, separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()[:24]

    if current["status"] == mapped:
        receipt = store.command_receipt(command_id_for(int(current["version"]) - 1))
        if receipt:
            return {**current, "receipt": {**receipt, "replayed": True}, "replayed": True}
    if current["status"] in {"completed", "cancelled"}:
        raise StoreError(f"action {action_id} is terminal; only the original resolve command can be replayed")
    claim_token = current.get("claim_token")
    if current["status"] == "claimed" and current.get("claimed_by") != actor:
        raise StoreError(f"action {action_id} is claimed by another operator")
    command_id = command_id_for(int(current["version"]))
    receipt = store.transition_action(
        command_id=command_id, action_id=action_id, expected_version=int(current["version"]),
        status=mapped, actor=actor, reason=_compact_text(notes or result or "", 1000),
        claim_token=claim_token, completion=completion, metadata=metadata,
    )
    return {**store.action(action_id), "receipt": receipt}


@contextmanager
def queue_mutation_lock(repo_root: Path | str, target: str):
    """串行化同一 target 的完整 action queue read-modify-write。"""
    with target_switch_lock(repo_root, target):
        path = queue_path(repo_root, target).parent / "locks" / "action_queue.lock"
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a+", encoding="utf-8") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _empty_queue(target: str) -> dict:
    ts = now_utc()
    return {
        "schema_version": SCHEMA_VERSION,
        "target": canonical_target_value(target),
        "created_at": ts,
        "updated_at": ts,
        "actions": [],
    }


def load_queue(repo_root: Path | str, target: str, *, statuses: tuple[str, ...] | None = None, action_type: str | None = None) -> dict:
    return _primary_action_projection(runtime_store(repo_root, target), statuses=statuses, action_type=action_type)


def load_legacy_queue(repo_root: Path | str, target: str) -> dict:
    """Read frozen queue material for explicit migration or historical inspection."""
    path = queue_path(repo_root, target)
    if not path.is_file():
        return _empty_queue(target)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"unable to read action queue {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid action queue JSON {path}: {exc.msg}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"action queue {path} must contain one object")
    schema_version = payload.get("schema_version", SCHEMA_VERSION)
    if schema_version != SCHEMA_VERSION:
        raise ValueError(
            f"action queue {path} schema_version must be {SCHEMA_VERSION}, got {schema_version!r}"
        )
    payload.setdefault("schema_version", SCHEMA_VERSION)
    payload.setdefault("target", canonical_target_value(target))
    payload.setdefault("actions", [])
    if not isinstance(payload["actions"], list):
        raise ValueError(f"action queue {path} actions must be a list")
    return payload


def _semantic_action(value: Any) -> Any:
    if isinstance(value, dict):
        return copy.deepcopy({key: item for key, item in value.items() if key != "updated_at"})
    return value


def _semantic_queue_value(value: Any) -> Any:
    """只忽略 queue/action 自身时间戳，保留 metadata 内的证据字段。"""
    if not isinstance(value, dict):
        return value
    semantic = {
        key: item
        for key, item in value.items()
        if key not in {"created_at", "updated_at"}
    }
    semantic["actions"] = [_semantic_action(action) for action in value.get("actions", [])]
    return semantic


def queue_fingerprint(queue: dict) -> str:
    """Return a stable generation for the semantic queue projection."""
    # Store commands advance revision atomically. A window and the full queue
    # describe the same generation; legacy material still uses its content hash.
    generation = ({key: queue[key] for key in ("target", "store_id", "revision")}
                  if queue.get("backend") == "primary" else _semantic_queue_value(queue))
    encoded = json.dumps(
        generation,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _compact_text(value: Any, limit: int = 800) -> str:
    text = str(value or "").strip()
    text = re.sub(r"\s+", " ", text)
    return text[:limit]


def _dedupe_key(action: dict) -> str:
    candidate_key = _candidate_dedupe_key(action)
    if candidate_key:
        return candidate_key
    metadata = action.get("metadata") if isinstance(action.get("metadata"), dict) else {}
    action_text = str(action.get("action", ""))
    evidence_text = str(action.get("evidence", ""))
    if str(action.get("type") or "") == "coverage-gap":
        projection_re = r"\s+(?:Queue projection only:|Family projection:).*$"
        action_text = re.sub(projection_re, "", action_text, flags=re.I)
        evidence_text = re.sub(projection_re, "", evidence_text, flags=re.I)
    parts = [
        action.get("type", ""),
        action.get("evidence_type", ""),
        evidence_text,
        action.get("next_question", ""),
        action_text,
        action.get("command_hint", ""),
        metadata.get("generation", ""),
        metadata.get("endpoint", ""),
        metadata.get("vuln_class", ""),
        metadata.get("method", ""),
        metadata.get("semantic_shape_id", ""),
        metadata.get("auth_context", ""),
        metadata.get("actor", ""),
        metadata.get("object_scope", ""),
    ]
    raw = " ".join(_compact_text(part, limit=300).lower() for part in parts if part)
    return re.sub(r"[^a-z0-9:/?&._=-]+", " ", raw).strip()


def _normalise_identity_endpoint(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    parsed = urllib.parse.urlparse(raw)
    endpoint = parsed.path if parsed.scheme or parsed.netloc else raw.split("?", 1)[0]
    endpoint = re.sub(r"/+", "/", endpoint or "/")
    if not endpoint.startswith("/"):
        endpoint = "/" + endpoint
    return endpoint.rstrip("/").lower() or "/"


def _action_identity_dimensions(metadata: dict) -> dict[str, str]:
    """Return the execution dimensions that distinguish one lane from another."""
    semantic_shape = metadata.get("semantic_shape_id")
    if not semantic_shape and isinstance(metadata.get("semantic_shape"), dict):
        semantic_shape = metadata["semantic_shape"].get("id")
    return {
        "method": str(metadata.get("method") or "").strip().upper(),
        "vuln_class": str(metadata.get("vuln_class") or "").strip().lower(),
        "semantic_shape_id": str(semantic_shape or "").strip().lower(),
        "auth_context": str(metadata.get("auth_context") or "").strip().lower(),
        "actor": str(metadata.get("actor") or "").strip().lower(),
        "object_scope": str(metadata.get("object_scope") or "").strip().lower(),
    }


def _action_identities(action: dict) -> set[str]:
    """Stable identities used to suppress stale duplicate candidate actions."""
    metadata = action.get("metadata") if isinstance(action.get("metadata"), dict) else {}
    if metadata.get("dedupe_retired") is True:
        return set()
    identities: set[str] = set()
    finding_id = str(metadata.get("finding_id") or "").strip().lower()
    if finding_id:
        identities.add(f"finding:{finding_id}")
    endpoint = ""
    for key in ("endpoint", "url"):
        endpoint = _normalise_identity_endpoint(str(metadata.get(key) or ""))
        if endpoint:
            break
    if not endpoint:
        return identities

    dimensions = _action_identity_dimensions(metadata)
    if any(dimensions.values()):
        encoded = json.dumps(
            {"endpoint": endpoint, **dimensions},
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
        identities.add(
            f"execution:{hashlib.sha256(encoded.encode('utf-8')).hexdigest()[:24]}"
        )
    else:
        # Legacy rows predate vuln-class/auth/shape metadata. Keep their
        # endpoint identity so old queues remain suppressible without making
        # new, dimensioned lanes supersede one another.
        identities.add(f"endpoint:{endpoint}")
    return identities


def _candidate_dedupe_key(action: dict) -> str:
    """Use finding/endpoint identity instead of candidate prose."""
    if str(action.get("type") or "") != "candidate-evidence-gap":
        return ""
    if str(action.get("status") or "queued") not in ACTIVE_STATUSES:
        return ""
    metadata = action.get("metadata") if isinstance(action.get("metadata"), dict) else {}
    finding_id = str(metadata.get("finding_id") or "").strip().lower()
    if finding_id:
        return f"candidate-evidence-gap finding:{finding_id}"
    identities = sorted(
        identity
        for identity in _action_identities(action)
        if not identity.startswith("finding:")
    )
    return f"candidate-evidence-gap {identities[0]}" if identities else ""


def _is_runner_only_validated(action: dict) -> bool:
    """Return whether a legacy row was closed by validation_runner only.

    validation_runner saves replay/diff evidence. It must not satisfy the
    `/validate` report-readiness gate by itself.
    """
    return (
        str(action.get("status") or "") == "validated"
        and str(action.get("result") or "").strip().startswith("validation-runner-result=")
    )


def _status_rank(status: str) -> int:
    if status == "running":
        return 0
    if status == "candidate":
        return 1
    if status == "signal":
        return 2
    if status == "lead":
        return 3
    if status == "queued":
        return 4
    return 9


def _action_sort_key(action: dict) -> tuple:
    """Stable display order for the stored action list.

    The 2026-09-14 dumb-queue refactor deleted the priority selector that
    used to consume this key as an ordering authority: the AI chooses work
    (autopilot.md priority_frontier contract makes machine ordering advisory),
    so the only requirement left for the on-disk list is a deterministic
    order. Status-then-created_at keeps running work visible at the top
    without implying a recommendation.
    """
    try:
        priority = int(action.get("priority", 50) or 50)
    except (TypeError, ValueError):
        priority = 50
    return (
        _status_rank(str(action.get("status") or "queued")),
        -priority,
        str(action.get("created_at") or ""),
        str(action.get("id") or ""),
    )


def _normalize_status(status: str) -> str:
    value = (status or "").strip().lower()
    value = STATUS_ALIASES.get(value, value)
    if value not in ALLOWED_STATUSES:
        raise ValueError(f"invalid status: {status!r}")
    return value


def build_action(
    *,
    target: str,
    action_type: str,
    evidence: str,
    next_question: str,
    action: str,
    priority: int = 50,
    command_hint: str = "",
    evidence_type: str = "generic",
    source: str = "manual",
    source_id: str = "",
    safety: str = "non_destructive",
    redline_required: bool | None = None,
    stop_condition: str = DEFAULT_STOP_CONDITION,
    metadata: dict | None = None,
) -> dict:
    metadata = _validate_action_metadata(metadata)
    ts = now_utc()
    built = {
        "schema_version": SCHEMA_VERSION,
        "id": "",
        "target": canonical_target_value(target),
        "status": "queued",
        "type": _compact_text(action_type, 80) or "next-action",
        "priority": int(priority),
        "evidence_type": _compact_text(evidence_type, 80) or "generic",
        "evidence": _compact_text(evidence),
        "next_question": _compact_text(next_question),
        "action": _compact_text(action),
        "command_hint": _compact_text(command_hint, 300),
        "source": _compact_text(source, 80),
        "source_id": _compact_text(source_id, 80),
        "safety": _compact_text(safety, 120) or "non_destructive",
        "redline_required": bool(redline_required),
        "stop_condition": _compact_text(stop_condition, 400) or DEFAULT_STOP_CONDITION,
        "attempts": 0,
        "created_at": ts,
        "updated_at": ts,
        "result": "",
        "notes": "",
    }
    if metadata:
        built["metadata"] = {
            _compact_text(key, 80): value
            for key, value in metadata.items()
            if _compact_text(key, 80)
        }
    built["dedupe_key"] = _dedupe_key(built)
    return built


def add_manual_action(
    repo_root: Path | str,
    *,
    target: str,
    action_type: str,
    evidence: str,
    next_question: str,
    action: str,
    priority: int = 50,
    command_hint: str = "",
    evidence_type: str = "manual",
    source: str = "manual",
    source_id: str = "",
    generation: str = "",
    safety: str = "non_destructive",
    stop_condition: str = DEFAULT_STOP_CONDITION,
    metadata: dict | None = None,
    action_id: str = "",
    actor: str = "action-queue",
) -> dict:
    action_metadata = dict(_validate_action_metadata(metadata))
    # Runner-owned observation fields are anti-forgery on every AI-facing
    # write path (add included): only the runner writes its own observations.
    runner_fields = RUNNER_OBSERVATION_FIELDS.intersection(action_metadata)
    if runner_fields:
        raise ValueError(
            "Action Queue metadata cannot supply Runner-owned observation fields: "
            + ", ".join(sorted(runner_fields))
        )
    if generation:
        action_metadata["generation"] = generation
    built = build_action(
        target=target,
        action_type=action_type,
        evidence=evidence,
        next_question=next_question,
        action=action,
        priority=priority,
        command_hint=command_hint,
        evidence_type=evidence_type,
        source=source,
        source_id=source_id,
        safety=safety,
        stop_condition=stop_condition,
        metadata=action_metadata or None,
    )
    return _primary_create_action(repo_root, target, built, action_id=action_id, actor=actor)


def add_material_review(
    repo_root: Path | str, *, target: str, source: str, source_id: str,
    action_type: str, summary_path: Path | str, material: dict, safety: str = "read_only",
) -> dict:
    """Publish an immutable review snapshot, then register work without a verdict."""
    root = Path(repo_root).resolve()
    path = Path(summary_path)
    path = (path if path.is_absolute() else root / path).resolve()
    key = target_storage_key(canonical_target_value(target))
    if not any(path.is_relative_to(root / kind / key) for kind in ("recon", "findings")):
        raise StoreError("review summary must belong to this target's material directories")
    if not path.is_file() or path.stat().st_size == 0:
        raise StoreError("review summary must be a published nonempty file")
    payload = {"source_summary": path.relative_to(root).as_posix(), "material": material}
    encoded = (json.dumps(payload, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n").encode()
    generation = hashlib.sha256(encoded).hexdigest()
    snapshot = path.with_name(f"{path.stem}.review-{generation}.json")
    with target_switch_lock(root, target):
        runtime_store(root, target)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile("wb", dir=path.parent, delete=False) as handle:
                temporary = Path(handle.name)
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.link(temporary, snapshot)
            except FileExistsError:
                if snapshot.is_symlink() or not snapshot.is_file() or snapshot.read_bytes() != encoded:
                    raise StoreError("existing review snapshot differs from its recorded material")
            directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if temporary is not None:
                temporary.unlink()
        ref = snapshot.relative_to(root).as_posix()
    return add_manual_action(
        root, target=target, action_type=action_type, source=source, source_id=source_id,
        generation=generation, evidence=f"Recorded material: {ref}",
        next_question="What does the recorded material establish?",
        action=f"Review the recorded {source} material before deciding further work.",
        evidence_type="material-review", safety=safety,
        metadata={"summary_path": ref, "source_summary_path": payload["source_summary"], "evidence_ref": ref},
    )


def active_action_ids(queue: dict, *, limit: int = 20) -> list[str]:
    """Stable-order bounded view of active action ids (no recommendation).

    Display replacement for the retired priority headline: consumers render
    "active: N items [queued×a, running×b] — id list", and the AI applies its
    own selection criteria. Order is the on-disk display order.
    """
    candidates = [
        item for item in queue.get("actions", [])
        if isinstance(item, dict) and str(item.get("status") or "queued") in ACTIVE_STATUSES
    ]
    candidates.sort(key=_action_sort_key)
    return [str(item.get("id") or "") for item in candidates[:limit] if str(item.get("id") or "")]


def claim_next_action(
    repo_root: Path | str,
    target: str,
    *,
    action_id: str = "",
    metadata: dict | None = None,
    actor: str = "action-queue",
) -> dict:
    """Claim one explicitly named action (dumb queue interface).

    The AI selects the work; this function only atomically applies an
    explicit ``--id`` claim. There is no implicit select-next path — a claim
    without ``--id`` is an error, never a guess (the 2026-09-14 chimera bug
    came from silently merging a new hypothesis into whatever the selector
    picked).

    """
    if not action_id:
        raise ValueError(
            "Action Queue claim requires --id (or add a new action); "
            "the queue does not select work for you"
        )
    metadata = _validate_action_metadata(metadata)
    return _primary_claim(
        repo_root, target, action_id=action_id, metadata=metadata,
        actor=actor,
    )


def resolve_action(
    repo_root: Path | str,
    *,
    target: str,
    action_id: str,
    status: str,
    result: str = "",
    notes: str = "",
    metadata: dict | None = None,
    actor: str = "action-queue",
) -> dict:
    metadata = _validate_action_metadata(metadata)
    return _primary_resolve(
        repo_root, target, action_id=action_id, status=status,
        result=result, notes=notes, metadata=metadata, actor=actor,
    )


def summarize_queue(
    queue: dict,
    *,
    repo_root: Path | str | None = None,
    target: str | None = None,
) -> dict:
    actions = [item for item in queue.get("actions", []) if isinstance(item, dict)]
    legacy_missing_id = sum(1 for item in actions if not str(item.get("id") or "").strip())
    by_status = Counter(str(item.get("status") or "queued") for item in actions)
    by_type = Counter(str(item.get("type") or "next-action") for item in actions)
    active = [item for item in actions if str(item.get("status") or "queued") in ACTIVE_STATUSES]
    final = [item for item in actions if str(item.get("status") or "") in FINAL_STATUSES]
    return {
        "target": queue.get("target", ""),
        "total": len(actions),
        "active": len(active),
        "final": len(final),
        "by_status": dict(sorted(by_status.items())),
        "by_type": dict(sorted(by_type.items())),
        "legacy_missing_id": legacy_missing_id,
        "active_ids": active_action_ids(queue),
        "fingerprint": queue_fingerprint(queue),
    }


def format_action(action: dict) -> str:
    if not action:
        return "No active queued action."
    redline = " red-line-first" if action.get("redline_required") else ""
    lines = [
        f"{action.get('id')} [{action.get('type')} p{action.get('priority')}{redline}]",
        f"- Status: {action.get('status')}",
        f"- Evidence: {action.get('evidence')}",
        f"- Next question: {action.get('next_question')}",
        f"- Action: {action.get('action')}",
        f"- Hint: {action.get('command_hint') or 'smallest safe evidence-producing step'}",
        f"- Stop condition: {action.get('stop_condition')}",
    ]
    metadata = action.get("metadata")
    if isinstance(metadata, dict) and metadata:
        summary = ", ".join(f"{key}={value}" for key, value in metadata.items())
        lines.insert(5, f"- Metadata: {summary}")
    return "\n".join(lines)


def format_summary(queue: dict, *, repo_root: Path | str | None = None, target: str | None = None) -> str:
    summary = summarize_queue(queue)
    lines = [
        "ACTION QUEUE",
        f"- Target: {summary.get('target')}",
        f"- Total: {summary.get('total')}",
        f"- Active: {summary.get('active')}",
        f"- Final: {summary.get('final')}",
        f"- By status: {summary.get('by_status')}",
        f"- By type: {summary.get('by_type')}",
        f"- Active ids: {summary.get('active_ids')}",
    ]
    return "\n".join(lines)


def _print(payload: Any, *, as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    elif isinstance(payload, str):
        print(payload)
    else:
        print(json.dumps(payload, ensure_ascii=False, indent=2))


def _parse_metadata_json(raw: str | None) -> dict | None:
    if raw is None:
        return None
    try:
        metadata = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"--metadata-json must be valid JSON: {exc.msg}") from exc
    if not isinstance(metadata, dict):
        raise ValueError("--metadata-json must be a JSON object")
    return _validate_action_metadata(metadata)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Persistent action queue for autopilot runs.")
    parser.add_argument("--repo-root", default=str(BASE_DIR), help="Repository root.")
    sub = parser.add_subparsers(dest="command", required=True)

    add = sub.add_parser("add", help="Add one manual/evidence-backed action.")
    add.add_argument("--target", required=True)
    add.add_argument("--type", default="next-action")
    add.add_argument("--evidence-type", default="manual")
    add.add_argument("--source", default="manual")
    add.add_argument("--source-id", default="")
    add.add_argument("--generation", default="")
    add.add_argument(
        "--metadata-json",
        default=None,
        help="JSON object merged into the existing Action Queue metadata.",
    )
    add.add_argument("--evidence", required=True)
    add.add_argument("--next-question", required=True)
    add.add_argument("--action", required=True)
    add.add_argument("--priority", type=int, default=50)
    add.add_argument("--command-hint", default="")
    add.add_argument("--safety", default="non_destructive")
    add.add_argument(
        "--stop-condition",
        default=DEFAULT_STOP_CONDITION,
        help="Explicit condition for when this action is tested, blocked, dead-end, signal, candidate, or validated.",
    )
    add.add_argument("--id", default="", help="Explicit action id for the transactional primary store.")
    add.add_argument("--actor", default="action-queue", help="Command actor for primary-store actions.")
    add.add_argument("--json", action="store_true")

    claim = sub.add_parser("claim", help="Claim one explicitly named active action (dumb queue interface).")
    claim.add_argument("--target", required=True)
    claim.add_argument("--id", required=True, help="Explicit action id to claim; the queue never selects for you.")
    claim.add_argument(
        "--metadata-json",
        default=None,
        help=(
            "Full AI judgment write, applied wholesale to the action's "
            "metadata (no required-field gate). Only the six mechanical "
            "write-time invariants are enforced (runner-field rejection, "
            "identity guard, hypothesis cap, evidence binding, execution "
            "dedup, sensitive-value rejection)."
        ),
    )
    claim.add_argument("--actor", default="action-queue", help="Command actor for primary-store actions.")
    claim.add_argument("--json", action="store_true")

    resolve = sub.add_parser("resolve", help="Resolve or reclassify one action.")
    resolve.add_argument("--target", required=True)
    resolve.add_argument("--id", required=True)
    resolve.add_argument("--status", required=True, choices=sorted(ALLOWED_STATUSES | set(STATUS_ALIASES), key=str), help="terminal/interim status")
    resolve.add_argument("--result", default="")
    resolve.add_argument(
        "--evidence",
        default="",
        help="Alias for --result; kept for command docs and Claude CLI muscle memory.",
    )
    resolve.add_argument(
        "--metadata-json",
        default=None,
        help="JSON object merged into the existing Action Queue metadata.",
    )
    resolve.add_argument("--notes", default="")
    resolve.add_argument("--actor", default="action-queue", help="Command actor for primary-store actions.")
    resolve.add_argument("--json", action="store_true")

    summary = sub.add_parser("summary", help="Print queue summary.")
    summary.add_argument("--target", required=True)
    summary.add_argument("--json", action="store_true")

    list_cmd = sub.add_parser("list", help="List actions.")
    list_cmd.add_argument("--target", required=True)
    list_cmd.add_argument("--status", default="")
    list_cmd.add_argument("--json", action="store_true")

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    repo = Path(args.repo_root)

    try:
        if args.command == "add":
            metadata = _parse_metadata_json(args.metadata_json)
            result = add_manual_action(
                repo,
                target=args.target,
                action_type=args.type,
                evidence_type=args.evidence_type,
                source=args.source,
                source_id=args.source_id,
                generation=args.generation,
                evidence=args.evidence,
                next_question=args.next_question,
                action=args.action,
                priority=args.priority,
                command_hint=args.command_hint,
                safety=args.safety,
                stop_condition=args.stop_condition,
                metadata=metadata,
                action_id=args.id,
                actor=args.actor,
            )
            _print(
                result if args.json else format_summary(result.get("queue") or load_queue(repo, args.target), repo_root=repo, target=args.target),
                as_json=args.json,
            )
            return 0

        if args.command == "claim":
            metadata = _parse_metadata_json(args.metadata_json)
            action = claim_next_action(
                repo,
                args.target,
                action_id=args.id,
                metadata=metadata,
                actor=args.actor,
            )
            _print(action if args.json else format_action(action), as_json=args.json)
            return 0 if action else 1

        if args.command == "resolve":
            metadata = _parse_metadata_json(args.metadata_json)
            result = resolve_action(
                repo,
                target=args.target,
                action_id=args.id,
                status=args.status,
                result=args.result or args.evidence,
                notes=args.notes,
                metadata=metadata,
                actor=args.actor,
            )
            _print(
                result if args.json else format_summary(load_queue(repo, args.target), repo_root=repo, target=args.target),
                as_json=args.json,
            )
            return 0

        if args.command == "summary":
            queue = load_queue(repo, args.target)
            _print(
                summarize_queue(queue, repo_root=repo, target=args.target)
                if args.json else format_summary(queue, repo_root=repo, target=args.target),
                as_json=args.json,
            )
            return 0

        if args.command == "list":
            queue = load_queue(repo, args.target)
            actions = [item for item in queue.get("actions", []) if isinstance(item, dict)]
            if args.status:
                actions = [item for item in actions if str(item.get("status") or "") == args.status]
            actions.sort(key=_action_sort_key)
            _print(actions if args.json else "\n\n".join(format_action(item) for item in actions), as_json=args.json)
            return 0
    except (KeyError, OSError, ValueError) as exc:
        print(f"action_queue: {exc}", file=sys.stderr)
        return 2

    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
