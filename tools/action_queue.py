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
    from tools.high_value_signals import classify_high_value_signal
    from tools.runtime_state import runtime_wait_action
    from tools.target_paths import canonical_target_value, target_storage_key
except ImportError:  # pragma: no cover - direct tools/ execution
    from high_value_signals import classify_high_value_signal  # type: ignore
    from runtime_state import runtime_wait_action  # type: ignore
    from target_paths import canonical_target_value, target_storage_key  # type: ignore


SCHEMA_VERSION = 1
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
EVIDENCE_REF_KEYS = {
    "artifact",
    "evidence",
    "evidence_ref",
    "report",
    "report_file",
    "summary",
    "validation-summary",
    "validation_summary",
}
EVIDENCE_ROOTS = {".private", "evidence", "findings", "recon", "reports"}
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
STRUCTURED_METADATA_LIST_FIELDS = {"tested_dimensions", "pivot_hints"}
RUNNER_OBSERVATION_FIELDS = {"last_outcome", "tested_dimensions", "runner_operation_id"}
DEPTH_CONTRACT_VERSION = 1
RISK_TIERS = {"low", "medium", "high", "critical"}
ACTIVATION_REQUIRED_FIELDS = (
    "hypothesis_id",
    "family",
    "technique",
    "active_dimension",
    "expected_learning",
    "kill_condition",
    "decision_reason",
    "input_boundary",
)
ACTIVATION_ROUTE_FIELDS = ("skill_id", "skill_path", "required_dimensions")
ACTIVATION_REQUIRED_CLAIM_FIELDS = (
    "depth_contract_version",
    *ACTIVATION_REQUIRED_FIELDS,
    "endpoint",
    "method",
    "skill_route",
    "evidence_ref",
    "baseline_ref",
    "risk_tier",
    "max_hypothesis_actions",
)
ACTIVATION_OPTIONAL_FIELDS = ("selected_knowledge_refs",)
ACTIVATION_QUEUE_OWNED_FIELDS = ("activation_required", "max_hypothesis_actions_cap")
CONTINUATION_KINDS = {
    "sibling", "bypass", "identity", "object", "parser", "transport",
    "workflow", "chain", "rotation", "blocked",
}
MAX_CAPABILITY_PRIMITIVES = 3
SENSITIVE_OBSERVATION_VALUE_RE = re.compile(
    r"\b(?:authorization|cookie|set-cookie|x-api-key)\b\s*[\"']?\s*[:=]\s*[\"']?\s*\S+|"
    r"\bbearer\s+[A-Za-z0-9._~+/=-]{3,}|"
    r"\b(?:(?:access|id|refresh)[_-]?token|token|password|api[-_ ]?key)\b"
    r"\s*[\"']?\s*[:=]\s*[\"']?\s*\S+",
    re.I,
)


def activation_contract_projection() -> dict[str, Any]:
    """Return the bounded machine contract used by versioned Queue claims."""
    return {
        "version": DEPTH_CONTRACT_VERSION,
        "required_fields": list(ACTIVATION_REQUIRED_CLAIM_FIELDS),
        "skill_route": {
            "required_fields": list(ACTIVATION_ROUTE_FIELDS),
            "skill_path_template": "skills/{skill_id}/SKILL.md",
        },
        "target_owned_fields": ["evidence_ref", "baseline_ref"],
        "optional_fields": list(ACTIVATION_OPTIONAL_FIELDS),
        "conditional_fields": {
            "skill_override_reason": "skill_route_changes",
            "knowledge_override_reason": "selected_knowledge_refs_outside_available",
            "repeat_reason": "execution_identity_repeats_with_new_evidence",
        },
        "risk_tiers": sorted(RISK_TIERS),
        "queue_owned_fields": list(ACTIVATION_QUEUE_OWNED_FIELDS),
        "runner_owned_fields": sorted(RUNNER_OBSERVATION_FIELDS),
        "limits": {
            "max_hypothesis_actions": "positive_integer <= max_hypothesis_actions_cap",
        },
    }


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
    route = metadata.get("skill_route")
    if route is None:
        if metadata.get("route_required"):
            raise ValueError("Action Queue metadata requires a skill_route")
    elif not isinstance(route, dict):
        raise ValueError("Action Queue metadata skill_route must be an object")
    else:
        skill_id = str(route.get("skill_id") or "").strip()
        skill_path = str(route.get("skill_path") or "").strip()
        dimensions = route.get("required_dimensions")
        if not skill_id:
            raise ValueError("Action Queue metadata skill_route requires skill_id")
        expected_path = f"skills/{skill_id}/SKILL.md"
        if not skill_path:
            raise ValueError(
                "Action Queue metadata skill_route requires "
                f"skill_path={expected_path}"
            )
        if skill_path != expected_path:
            raise ValueError(
                "Action Queue metadata skill_route skill_path must be "
                f"{expected_path}"
            )
        if not isinstance(dimensions, list) or not dimensions or any(not str(item).strip() for item in dimensions):
            raise ValueError("Action Queue metadata skill_route requires test dimensions")
    return metadata


def _merge_action_metadata(existing: Any, incoming: dict | None) -> dict:
    """Merge structured write-back metadata without duplicating pivot hints."""
    incoming = _validate_action_metadata(incoming)
    merged = copy.deepcopy(existing) if isinstance(existing, dict) else {}
    for key, value in incoming.items():
        if key in STRUCTURED_METADATA_LIST_FIELDS and isinstance(value, list):
            prior = merged.get(key)
            values = list(prior) if isinstance(prior, list) else []
            merged[key] = values + [item for item in value if item not in values]
        elif key == "last_outcome" and isinstance(value, dict) and isinstance(merged.get(key), dict):
            outcome = copy.deepcopy(merged[key])
            outcome.update(copy.deepcopy(value))
            merged[key] = outcome
        else:
            merged[key] = copy.deepcopy(value)
    return _validate_action_metadata(merged)


def _bounded_metadata_text(value: Any, field: str, *, limit: int = 500) -> str:
    text = _compact_text(value, limit + 1)
    if not text:
        raise ValueError(f"Action Queue depth contract requires {field}")
    if len(text) > limit:
        raise ValueError(f"Action Queue depth contract {field} exceeds {limit} characters")
    return text


def _validate_observed_difference(value: Any) -> str:
    text = _bounded_metadata_text(value, "last_outcome.observed_difference")
    if SENSITIVE_OBSERVATION_VALUE_RE.search(text):
        raise ValueError("Action Queue observed difference cannot contain credential or header values")
    return text


def _target_owned_evidence_ref(repo_root: Path | str, target: str, value: Any) -> str:
    ref = _locatable_evidence_ref(repo_root, str(value or ""))
    if not ref:
        return ""
    repo = Path(repo_root).resolve()
    try:
        relative = Path(ref).resolve().relative_to(repo)
    except (OSError, ValueError):
        return ""
    if target_storage_key(canonical_target_value(target)) not in relative.parts:
        return ""
    return str(relative)


def _target_owned_nonempty_evidence_ref(
    repo_root: Path | str,
    target: str,
    value: Any,
) -> str:
    """Return a target-owned evidence file only when it contains bytes."""
    ref = _target_owned_evidence_ref(repo_root, target, value)
    if not ref:
        return ""
    try:
        if (Path(repo_root) / ref).stat().st_size <= 0:
            return ""
    except OSError:
        return ""
    return ref


def _execution_key(metadata: dict) -> str:
    endpoint = str(metadata.get("endpoint") or metadata.get("url") or "").strip()
    parsed_endpoint = urllib.parse.urlsplit(endpoint)
    if parsed_endpoint.scheme and parsed_endpoint.netloc:
        endpoint = (
            f"{parsed_endpoint.scheme.lower()}://{parsed_endpoint.netloc.lower()}"
            f"{parsed_endpoint.path.rstrip('/') or '/'}"
            f"{('?' + parsed_endpoint.query) if parsed_endpoint.query else ''}"
        )
    else:
        endpoint = endpoint.split("#", 1)[0].rstrip("/") or "/"
    fields = {
        "endpoint": endpoint,
        "method": str(metadata.get("method") or "").strip().upper(),
        "family": str(metadata.get("family") or "").strip().lower(),
        "technique": str(metadata.get("technique") or "").strip().lower(),
        "actor": str(metadata.get("actor") or "").strip().lower(),
        "object_scope": str(metadata.get("object_scope") or "").strip().lower(),
        "workflow": str(metadata.get("workflow") or "").strip().lower(),
        "active_dimension": str(metadata.get("active_dimension") or "").strip().lower(),
    }
    if not all(fields[key] for key in ("endpoint", "method", "family", "technique", "active_dimension")):
        raise ValueError("Action Queue depth contract lacks execution identity fields")
    encoded = json.dumps(fields, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return f"depth-v1:{hashlib.sha256(encoded.encode('utf-8')).hexdigest()[:24]}"


def _validate_execution_repeat(queue: dict, item: dict, metadata: dict) -> None:
    key = str(metadata.get("execution_key") or "")
    evidence_ref = str(metadata.get("evidence_ref") or "")
    for other in queue.get("actions", []):
        if not isinstance(other, dict) or str(other.get("id") or "") == str(item.get("id") or ""):
            continue
        other_metadata = other.get("metadata") if isinstance(other.get("metadata"), dict) else {}
        if str(other_metadata.get("execution_key") or "") != key:
            continue
        if str(other_metadata.get("evidence_ref") or "") == evidence_ref:
            raise ValueError("Action Queue depth contract refuses duplicate execution with the same evidence")
        if not _compact_text(metadata.get("repeat_reason"), 500):
            raise ValueError("Action Queue depth contract requires repeat_reason for changed evidence")


def _prepare_claim_metadata(
    repo_root: Path | str,
    target: str,
    queue: dict,
    item: dict,
    incoming: dict | None,
) -> dict:
    existing = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
    incoming = incoming or {}
    if (
        "activation_required" in incoming
        and incoming.get("activation_required") != existing.get("activation_required")
    ):
        raise ValueError("Action Queue claim cannot override activation_required")
    versioned_claim = (
        existing.get("activation_required")
        or existing.get("depth_contract_version") == DEPTH_CONTRACT_VERSION
        or incoming.get("depth_contract_version") == DEPTH_CONTRACT_VERSION
    )
    if (
        versioned_claim
        and "max_hypothesis_actions_cap" in incoming
        and incoming.get("max_hypothesis_actions_cap") != existing.get("max_hypothesis_actions_cap")
    ):
        raise ValueError(
            "Action Queue claim cannot override Queue-owned max_hypothesis_actions_cap; "
            "read the stored cap or refresh and re-ingest a missing checkpoint action"
        )
    runner_fields = RUNNER_OBSERVATION_FIELDS.intersection(incoming)
    if versioned_claim and runner_fields:
        raise ValueError(
            "Action Queue claim cannot supply Runner-owned observation fields: "
            + ", ".join(sorted(runner_fields))
        )
    merged = _merge_action_metadata(existing, incoming)
    if not merged.get("activation_required") and merged.get("depth_contract_version") != DEPTH_CONTRACT_VERSION:
        return merged

    if merged.get("depth_contract_version") != DEPTH_CONTRACT_VERSION:
        raise ValueError("Action Queue claim requires depth_contract_version=1 activation metadata")
    missing_activation_fields = [
        field for field in ACTIVATION_REQUIRED_FIELDS
        if not _compact_text(merged.get(field))
    ]
    if missing_activation_fields:
        raise ValueError(
            "Action Queue depth contract requires activation fields: "
            + ", ".join(missing_activation_fields)
        )
    for field in ACTIVATION_REQUIRED_FIELDS:
        merged[field] = _bounded_metadata_text(merged.get(field), field)
    merged["endpoint"] = _bounded_metadata_text(
        merged.get("endpoint") or merged.get("url"), "endpoint"
    )
    merged["method"] = _bounded_metadata_text(merged.get("method"), "method", limit=16).upper()

    route = merged.get("skill_route") if isinstance(merged.get("skill_route"), dict) else {}
    if not route:
        raise ValueError("Action Queue depth contract requires a selected skill_route")
    required_dimensions = [
        str(value).strip() for value in route.get("required_dimensions", []) if str(value).strip()
    ]
    if merged["active_dimension"] not in required_dimensions and not merged.get("decision_reason"):
        raise ValueError("Action Queue active_dimension must come from the selected Skill route")
    original_route = existing.get("skill_route") if isinstance(existing.get("skill_route"), dict) else {}
    if original_route and route != original_route and not _compact_text(merged.get("skill_override_reason"), 500):
        raise ValueError("Action Queue Skill override requires skill_override_reason")

    available_refs = {
        str(value).strip() for value in existing.get("knowledge_refs", []) if str(value).strip()
    }
    selected_refs = merged.get("selected_knowledge_refs", [])
    if not isinstance(selected_refs, list) or any(not str(value).strip() for value in selected_refs):
        raise ValueError("Action Queue selected_knowledge_refs must be a list of non-empty references")
    selected_refs = list(dict.fromkeys(str(value).strip() for value in selected_refs))
    knowledge_override_reason = _compact_text(merged.get("knowledge_override_reason"), 500)
    if selected_refs and not available_refs and not knowledge_override_reason:
        raise ValueError("Action Queue depth contract requires activation knowledge_refs")
    if selected_refs and available_refs and not set(selected_refs).issubset(available_refs) and not knowledge_override_reason:
        raise ValueError("Action Queue knowledge override requires knowledge_override_reason")
    merged["selected_knowledge_refs"] = selected_refs

    evidence_ref = _target_owned_evidence_ref(repo_root, target, merged.get("evidence_ref"))
    baseline_ref = _target_owned_evidence_ref(repo_root, target, merged.get("baseline_ref"))
    if not evidence_ref or not baseline_ref:
        raise ValueError("Action Queue depth contract requires target-owned evidence_ref and baseline_ref")
    merged["evidence_ref"] = evidence_ref
    merged["baseline_ref"] = baseline_ref

    risk_tier = str(merged.get("risk_tier") or "").strip().lower()
    if risk_tier not in RISK_TIERS:
        raise ValueError("Action Queue depth contract risk_tier is invalid")
    merged["risk_tier"] = risk_tier
    cap = merged.get("max_hypothesis_actions")
    stored_cap = existing.get("max_hypothesis_actions_cap")
    if isinstance(cap, bool) or not isinstance(cap, int) or cap < 1:
        raise ValueError("Action Queue depth contract max_hypothesis_actions must be a positive integer")
    if stored_cap is None:
        raise ValueError(
            f"Action Queue queued item {item.get('id', '')} lacks max_hypothesis_actions_cap; "
            "refresh or re-ingest the queued action before claim"
        )
    if isinstance(stored_cap, bool) or not isinstance(stored_cap, int) or stored_cap < 1:
        raise ValueError(
            f"Action Queue queued item {item.get('id', '')} has invalid max_hypothesis_actions_cap; "
            "preserve it for Action Queue owner repair before claim"
        )
    if cap > stored_cap:
        raise ValueError("Action Queue depth contract exceeds the stored hypothesis action cap")

    hypothesis_id = merged["hypothesis_id"]
    current_count = sum(
        isinstance(action, dict)
        and str((action.get("metadata") or {}).get("hypothesis_id") or "") == hypothesis_id
        and str(action.get("id") or "") != str(item.get("id") or "")
        for action in queue.get("actions", [])
    )
    if not existing.get("hypothesis_id") and current_count >= cap:
        raise ValueError("Action Queue hypothesis action budget is exhausted")

    merged["execution_key"] = _execution_key(merged)
    merged["activation_required"] = False
    merged["hypothesis_status"] = "open"
    _validate_execution_repeat(queue, item, merged)
    return _validate_action_metadata(merged)


def _hypothesis_pivot_actions(item: dict, *, status: str, result: str) -> list[dict]:
    """Project bounded follow-up actions from an explicitly declared hypothesis.

    The model still supplies the hypothesis and pivot dimensions. The queue
    only materializes those inert, evidence-backed continuations and dedupes
    them through its existing owner.
    """
    if status not in {"tested", "dead-end"}:
        return []
    metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
    if metadata.get("kill_condition_met") is True:
        return []
    hypothesis_id = str(metadata.get("hypothesis_id") or "").strip()
    hints = metadata.get("pivot_hints")
    if not hypothesis_id or not isinstance(hints, list):
        return []
    tested = {
        str(value).strip().lower()
        for value in metadata.get("tested_dimensions", [])
        if str(value).strip()
    }
    expected_learning = str(metadata.get("expected_learning") or "").strip()
    kill_condition = str(metadata.get("kill_condition") or "").strip()
    route = metadata.get("skill_route") if isinstance(metadata.get("skill_route"), dict) else None
    actions: list[dict] = []
    for raw_hint in hints:
        hint = str(raw_hint or "").strip()
        if not hint or hint.lower() in tested:
            continue
        question = f"Does the {hint} dimension change the result for hypothesis {hypothesis_id}?"
        pivot_metadata = {
            "hypothesis_id": hypothesis_id,
            "parent_action_id": str(item.get("id") or ""),
            "pivot_hint": hint,
            "tested_dimensions": sorted(tested),
            "expected_learning": expected_learning,
            "kill_condition": kill_condition,
            "hypothesis_status": "open",
        }
        if route:
            pivot_metadata["skill_route"] = copy.deepcopy(route)
            if metadata.get("route_required"):
                pivot_metadata["route_required"] = True
        actions.append(
            build_action(
                target=str(item.get("target") or ""),
                action_type="hypothesis-pivot",
                evidence=(
                    f"Negative result for {hypothesis_id}: "
                    f"{_compact_text(result or item.get('result') or item.get('evidence') or '', 700)}"
                ),
                next_question=question,
                action=f"Run one bounded, target-owned {hint} follow-up and record its raw evidence.",
                priority=max(50, int(item.get("priority", 50) or 50) - 5),
                evidence_type="hypothesis-continuation",
                source="hypothesis-loop",
                source_id=f"{item.get('id', '')}:{hypothesis_id}:{hint}",
                stop_condition=kill_condition or DEFAULT_STOP_CONDITION,
                metadata=pivot_metadata,
            )
        )
    return actions


def _validate_capability_primitives(
    repo_root: Path | str,
    target: str,
    value: Any,
) -> list[dict]:
    if value in (None, []):
        return []
    if not isinstance(value, list) or len(value) > MAX_CAPABILITY_PRIMITIVES:
        raise ValueError(f"Action Queue accepts at most {MAX_CAPABILITY_PRIMITIVES} capability primitives")
    primitives: list[dict] = []
    for raw in value:
        if not isinstance(raw, dict):
            raise ValueError("Action Queue capability primitive must be an object")
        evidence_ref = _target_owned_evidence_ref(repo_root, target, raw.get("evidence_ref"))
        if not evidence_ref:
            raise ValueError("Action Queue capability primitive requires target-owned evidence_ref")
        primitive = {
            "capability": _bounded_metadata_text(raw.get("capability"), "capability", limit=240),
            "evidence_ref": evidence_ref,
        }
        hint = _compact_text(raw.get("continuation_hint"), 300)
        if hint:
            primitive["continuation_hint"] = hint
        primitives.append(primitive)
    return primitives


def _versioned_continuation_action(item: dict, metadata: dict, continuation: dict) -> dict:
    kind = str(continuation.get("kind") or "").strip().lower()
    dimension = _bounded_metadata_text(continuation.get("dimension"), "continuation.dimension", limit=120)
    question = _bounded_metadata_text(continuation.get("question"), "continuation.question")
    expected_learning = _bounded_metadata_text(
        continuation.get("expected_learning"), "continuation.expected_learning"
    )
    reason = _bounded_metadata_text(continuation.get("reason"), "continuation.reason")
    child_metadata = copy.deepcopy(metadata)
    for key in (
        "continuation", "kill_condition_met", "kill_reason", "last_outcome",
        "tested_dimensions", "runner_operation_id", "execution_key",
    ):
        child_metadata.pop(key, None)
    child_metadata.update({
        # Keep the child on the versioned path.  The prior AI resolve supplies
        # the bounded activation context; claim still validates it before the
        # child becomes executable.
        "activation_required": True,
        "active_dimension": dimension,
        "expected_learning": expected_learning,
        "decision_reason": reason,
        "parent_action_id": str(item.get("id") or ""),
        "continuation_kind": kind,
        "next_question": question,
        "hypothesis_status": "open",
    })
    last_outcome = metadata.get("last_outcome") if isinstance(metadata.get("last_outcome"), dict) else {}
    child_metadata["baseline_ref"] = str(last_outcome.get("summary_ref") or metadata.get("baseline_ref") or "")
    child_metadata["evidence_ref"] = str(last_outcome.get("evidence_ref") or last_outcome.get("summary_ref") or "")
    child_metadata["execution_key"] = _execution_key(child_metadata)
    return build_action(
        target=str(item.get("target") or ""),
        action_type="hypothesis-continuation",
        evidence=f"{kind} continuation from {item.get('id', '')}: {reason}",
        next_question=question,
        action=f"Execute one bounded {kind} continuation for dimension {dimension} and preserve replay evidence.",
        priority=max(50, int(item.get("priority", 50) or 50) - 5),
        evidence_type="hypothesis-continuation",
        source="hypothesis-loop",
        source_id=f"{item.get('id', '')}:{metadata.get('hypothesis_id', '')}:{kind}:{dimension}",
        stop_condition=str(metadata.get("kill_condition") or DEFAULT_STOP_CONDITION),
        metadata=child_metadata,
    )


def _versioned_terminal_plan(
    repo_root: Path | str,
    target: str,
    queue: dict,
    item: dict,
    normalized_status: str,
    incoming: dict,
    merged: dict,
) -> dict:
    if merged.get("depth_contract_version") != DEPTH_CONTRACT_VERSION or normalized_status not in FINAL_STATUSES:
        return {}

    outcome = merged.get("last_outcome") if isinstance(merged.get("last_outcome"), dict) else {}
    summary_ref = _target_owned_evidence_ref(repo_root, target, outcome.get("summary_ref"))
    evidence_ref = _target_owned_evidence_ref(
        repo_root, target, outcome.get("evidence_ref") or outcome.get("summary_ref")
    )
    if not summary_ref or not evidence_ref:
        raise ValueError("Action Queue versioned resolve requires replayable last_outcome evidence")
    observed = _validate_observed_difference(outcome.get("observed_difference"))
    _bounded_metadata_text(outcome.get("operation_id"), "last_outcome.operation_id", limit=160)
    _bounded_metadata_text(outcome.get("at"), "last_outcome.at", limit=80)
    active_dimension = str(merged.get("active_dimension") or "").strip()
    tested = {
        str(value).strip() for value in merged.get("tested_dimensions", []) if str(value).strip()
    }
    if not active_dimension or active_dimension not in tested:
        raise ValueError("Action Queue versioned resolve requires the active dimension in tested_dimensions")
    outcome["summary_ref"] = summary_ref
    outcome["evidence_ref"] = evidence_ref
    outcome["observed_difference"] = observed
    merged["last_outcome"] = outcome

    kill = incoming.get("kill_condition_met") is True
    continuation = incoming.get("continuation") if isinstance(incoming.get("continuation"), dict) else None
    if kill == bool(continuation):
        raise ValueError("Action Queue versioned resolve requires exactly one continuation or supported kill")
    if kill and str(outcome.get("observation_kind") or "").strip().lower() == "baseline_only":
        raise ValueError("Action Queue baseline-only observation requires a continuation before kill")
    merged["capability_primitives"] = _validate_capability_primitives(
        repo_root, target, incoming.get("capability_primitives", merged.get("capability_primitives"))
    )
    if kill:
        merged["kill_reason"] = _bounded_metadata_text(
            incoming.get("kill_reason") or incoming.get("decision_reason"), "kill_reason"
        )
        return {"decision": "kill"}

    kind = str(continuation.get("kind") or "").strip().lower()
    if kind not in CONTINUATION_KINDS:
        raise ValueError("Action Queue continuation kind is invalid")
    continuation = copy.deepcopy(continuation)
    continuation["kind"] = kind
    for field in ("dimension", "question", "expected_learning", "reason"):
        _bounded_metadata_text(continuation.get(field), f"continuation.{field}")
    merged["continuation"] = continuation
    if kind == "rotation":
        return {"decision": "rotation"}

    cap = int(merged.get("max_hypothesis_actions", 0) or 0)
    hypothesis_id = str(merged.get("hypothesis_id") or "")
    action_count = sum(
        isinstance(action, dict)
        and str((action.get("metadata") or {}).get("hypothesis_id") or "") == hypothesis_id
        for action in queue.get("actions", [])
    )
    if action_count >= cap:
        raise ValueError("Action Queue hypothesis action budget is exhausted")
    child = _versioned_continuation_action(item, merged, continuation)
    return {"decision": "continuation", "child": child}


def queue_path(repo_root: Path | str, target: str) -> Path:
    repo = Path(repo_root)
    resolved = canonical_target_value(target)
    return repo / "state" / target_storage_key(resolved) / "action_queue.json"


@contextmanager
def queue_mutation_lock(repo_root: Path | str, target: str):
    """串行化同一 target 的完整 action queue read-modify-write。"""
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


def load_queue(repo_root: Path | str, target: str) -> dict:
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
    encoded = json.dumps(
        _semantic_queue_value(queue),
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def save_queue(repo_root: Path | str, target: str, queue: dict) -> Path:
    path = queue_path(repo_root, target)
    queue["target"] = canonical_target_value(target)
    if path.is_file():
        existing = load_queue(repo_root, target)
        if _semantic_queue_value(existing) == _semantic_queue_value(queue):
            # 保留磁盘字节和调用方内存视图，避免无变化 sync 打 stale Surface。
            queue.clear()
            queue.update(existing)
            return path
    queue["updated_at"] = now_utc()
    _write_json_atomic(path, queue)
    return path


def _write_json_atomic(path: Path, payload: dict) -> None:
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


def _compact_text(value: Any, limit: int = 800) -> str:
    text = str(value or "").strip()
    text = re.sub(r"\s+", " ", text)
    return text[:limit]


def _locatable_evidence_ref(repo_root: Path | str, result: str) -> str:
    """Return one existing repo-local evidence path embedded in a result."""
    repo = Path(repo_root).resolve()
    text = str(result or "").strip()
    if not text:
        return ""
    candidates: list[str] = []
    for match in re.finditer(r"(?:^|[;\s])([A-Za-z][A-Za-z0-9_-]*)=(\S+)", text):
        if match.group(1).lower() in EVIDENCE_REF_KEYS:
            candidates.append(match.group(2))
    candidates.extend(re.split(r"[;\s]+", text))
    for value in candidates:
        ref = str(value or "").strip().strip("`'\"()[]{}<>,")
        if not ref or ref.endswith("="):
            continue
        path = Path(ref)
        if not path.is_absolute():
            path = repo / path
        try:
            resolved = path.resolve()
            relative = resolved.relative_to(repo)
        except (OSError, ValueError):
            continue
        if relative.parts and relative.parts[0] in EVIDENCE_ROOTS and resolved.is_file():
            return str(resolved)
    return ""


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


def _coverage_family_projection(action: dict) -> str:
    if str(action.get("type") or "") != "coverage-gap":
        return ""
    match = re.search(
        r"\s+Family projection:.*$",
        str(action.get("action") or ""),
        flags=re.I,
    )
    return match.group(0) if match else ""


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


def _coalesce_candidate_duplicates(queue: dict) -> int:
    """Retire historical active candidate duplicates without deleting evidence."""
    owners: dict[str, dict] = {}
    retired = 0

    def rank(item: dict) -> tuple[int, str]:
        status = str(item.get("status") or "queued")
        return ({"running": 0, "candidate": 1, "queued": 2}.get(status, 3), str(item.get("id") or ""))

    def retire(item: dict, owner: dict) -> None:
        nonlocal retired
        metadata = item.setdefault("metadata", {})
        if not isinstance(metadata, dict):
            metadata = {}
            item["metadata"] = metadata
        metadata["dedupe_retired"] = True
        metadata["dedupe_kept_action_id"] = str(owner.get("id") or "")
        item["status"] = "n/a"
        item["dedupe_key"] = f"candidate-evidence-gap-retired-{item.get('id') or retired}"
        item["result"] = (
            "Retired duplicate candidate projection; kept action "
            f"{owner.get('id') or '-'} as the active finding lane."
        )
        item["updated_at"] = now_utc()
        retired += 1

    for item in queue.get("actions", []):
        if not isinstance(item, dict):
            continue
        key = _candidate_dedupe_key(item)
        if not key:
            continue
        owner = owners.get(key)
        if owner is None:
            owners[key] = item
            continue
        if owner is item:
            continue
        if rank(item) < rank(owner):
            retire(owner, item)
            owners[key] = item
        else:
            retire(item, owner)
    return retired


def _knowledge_signal_identity(action: dict) -> str:
    """Return the stable identity used only by knowledge-signal reviews."""
    if str(action.get("type") or "") != "knowledge-signal-review":
        return ""
    metadata = action.get("metadata") if isinstance(action.get("metadata"), dict) else {}
    return str(metadata.get("signal_identity") or "").strip()


def _is_runner_only_validated(action: dict) -> bool:
    """Return whether a legacy row was closed by validation_runner only.

    validation_runner saves replay/diff evidence. It must not satisfy the
    `/validate` report-readiness gate by itself.
    """
    return (
        str(action.get("status") or "") == "validated"
        and str(action.get("result") or "").strip().startswith("validation-runner-result=")
    )


def _is_final_action(action: dict) -> bool:
    metadata = action.get("metadata") if isinstance(action.get("metadata"), dict) else {}
    if metadata.get("dedupe_retired") is True:
        return False
    status = str(action.get("status") or "")
    return status in FINAL_STATUSES and not _is_runner_only_validated(action)


def _final_action_identities(queue: dict) -> set[str]:
    identities: set[str] = set()
    for action in queue.get("actions", []):
        if not isinstance(action, dict):
            continue
        if not _is_final_action(action):
            continue
        identities.update(_action_identities(action))
    return identities


def _is_superseded_candidate(action: dict, final_identities: set[str]) -> bool:
    if str(action.get("status") or "") != "candidate":
        return False
    if str(action.get("type") or "") != "candidate-evidence-gap":
        return False
    identities = _action_identities(action)
    return bool(identities and identities & final_identities)


def _next_id(actions: list[dict]) -> str:
    highest = 0
    for action in actions:
        match = re.fullmatch(r"AQ-(\d+)", str(action.get("id") or ""))
        if match:
            highest = max(highest, int(match.group(1)))
    return f"AQ-{highest + 1:04d}"


def _legacy_action_id(action: dict, index: int) -> str:
    """Stable in-memory identity for legacy rows that predate ``id``."""
    material = "|".join(
        str(value or "")
        for value in (
            _dedupe_key(action),
            action.get("source_id"),
            action.get("created_at"),
            index,
        )
    )
    return f"LEGACY-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:12]}"


def _ensure_active_action_ids(queue: dict) -> int:
    """Attach stable IDs only to active legacy rows in the current projection."""
    assigned = 0
    for index, item in enumerate(queue.get("actions", [])):
        if (
            isinstance(item, dict)
            and not str(item.get("id") or "").strip()
            and str(item.get("status") or "queued") in ACTIVE_STATUSES
        ):
            item["id"] = _legacy_action_id(item, index)
            item.setdefault("metadata", {})["legacy_identity"] = True
            assigned += 1
    return assigned


def _action_identity(item: dict, index: int) -> str:
    value = str(item.get("id") or "").strip()
    return value or _legacy_action_id(item, index)


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
    try:
        priority = int(action.get("priority", 50) or 50)
    except (TypeError, ValueError):
        priority = 50
    evidence = " ".join([
        str(action.get("type") or ""),
        str(action.get("evidence_type") or ""),
        str(action.get("evidence") or ""),
        str(action.get("next_question") or ""),
        str(action.get("action") or ""),
        str(action.get("command_hint") or ""),
    ])
    metadata = action.get("metadata") if isinstance(action.get("metadata"), dict) else {}
    high_value = classify_high_value_signal(
        path=str(metadata.get("endpoint") or action.get("action") or ""),
        query_keys=[],
        item_type=str(metadata.get("vuln_class") or action.get("type") or ""),
        evidence=evidence,
    )
    try:
        relevance = int(metadata.get("relevance_score", 0) or 0)
    except (TypeError, ValueError):
        relevance = 0
    return (
        _status_rank(str(action.get("status") or "queued")),
        -priority,
        -relevance,
        -high_value.score,
        str(action.get("created_at") or ""),
        str(action.get("id") or ""),
    )


def _is_advisory_review_action(action: dict) -> bool:
    """Return True for advisory review items that are not exact runner work.

    Older queues may still contain `ranked-surface` items from before the
    AI-first rename. Treat them as advisory unless the command hint already
    contains an exact validation runner command; otherwise stale p92 legacy
    items can keep steering /autopilot away from the current review pack.
    """
    action_type = str(action.get("type") or "")
    if action_type in ADVISORY_REVIEW_ACTION_TYPES:
        metadata = action.get("metadata") if isinstance(action.get("metadata"), dict) else {}
        replay_draft = str(metadata.get("replay_draft") or "")
        command_hint = str(action.get("command_hint") or "")
        # AI-first surface review stays advisory until checkpoint has converted
        # it into a concrete replay draft. Once it contains an exact runner
        # command, it is executable validation work and should not be preempted
        # by report closure actions.
        return "validation_runner.py" not in " ".join([replay_draft, command_hint])
    if action_type != "ranked-surface":
        return False
    command_hint = str(action.get("command_hint") or "")
    return "validation_runner.py" not in command_hint


def _is_low_evidence_surface_review_action(action: dict) -> bool:
    """Return True for stale score-only surface reviews that should not drive next.

    `/surface` keeps score-only candidates visible in P1/P2 for recall, but the
    AI Review Pool is now evidence-first. Older checkpoint queues can still
    contain `surface-review` actions whose only reason was "top advisory score";
    selecting those via `action_queue next` reintroduces the stale regex/score
    steering we intentionally removed from `/surface`.

    Do not hide executable reviews: once a review contains an exact
    `validation_runner.py` replay, `_is_advisory_review_action` returns False
    and this helper leaves it selectable.
    """
    if str(action.get("type") or "") not in ADVISORY_REVIEW_ACTION_TYPES:
        return False
    if not _is_advisory_review_action(action):
        return False

    metadata = action.get("metadata") if isinstance(action.get("metadata"), dict) else {}
    blob = " ".join(
        str(part or "")
        for part in (
            action.get("evidence"),
            action.get("action"),
            action.get("command_hint"),
            metadata.get("suggested"),
            metadata.get("replay_draft"),
        )
    ).lower()
    return any(marker in blob for marker in LOW_EVIDENCE_SURFACE_REVIEW_MARKERS)


def _normalize_status(status: str) -> str:
    value = (status or "").strip().lower()
    value = STATUS_ALIASES.get(value, value)
    if value not in ALLOWED_STATUSES:
        raise ValueError(f"invalid status: {status!r}")
    return value


def _sync_coverage_matrix_for_action(
    repo_root: Path | str,
    target: str,
    action: dict,
    normalized_status: str,
) -> dict:
    """把 coverage-gap 队列动作的最终状态回写到 coverage matrix。

    action_queue 的状态比 coverage_matrix 更细。只有明确 tested/candidate/
    validated/reported/n-a 才能改变矩阵事实；dead-end 和 blocked 只关闭当前
    queue action，不能伪装成 tested_clean 或 not-applicable。精确 action 的
    去重由持久 queue/closure gate 负责。
    """
    if str(action.get("type") or "") != "coverage-gap":
        return {}
    coverage_status = COVERAGE_STATUS_BY_ACTION_STATUS.get(normalized_status)
    if not coverage_status:
        return {
            "status": "skipped",
            "reason": f"action status {normalized_status!r} does not close a coverage cell",
        }
    metadata = action.get("metadata") if isinstance(action.get("metadata"), dict) else {}
    endpoint = str(
        metadata.get("coverage_endpoint") or metadata.get("endpoint") or ""
    ).strip()
    vuln_class = str(metadata.get("vuln_class") or "").strip()
    if not endpoint or not vuln_class:
        return {
            "status": "skipped",
            "reason": "coverage-gap action is missing endpoint/vuln_class metadata",
        }

    try:
        from tools.coverage_matrix import mark_cell
    except ImportError:  # pragma: no cover - direct tools/ execution
        from coverage_matrix import mark_cell  # type: ignore

    reason_source = (
        action.get("result")
        or action.get("notes")
        or action.get("evidence")
        or action.get("action")
        or ""
    )
    reason = _compact_text(f"{normalized_status}: {reason_source}", 500)
    cell = mark_cell(
        target,
        endpoint,
        vuln_class,
        coverage_status,
        reason=reason,
        repo_root=repo_root,
        write_finding=False,
    )
    return {
        "status": "updated",
        "endpoint": endpoint,
        "vuln_class": vuln_class,
        "coverage_status": coverage_status,
        "cell": cell,
    }


def _unsafe_review_path(repo_root: Path | str, target: str) -> Path:
    repo = Path(repo_root)
    resolved = canonical_target_value(target)
    return repo / "state" / target_storage_key(resolved) / "unsafe_skipped_reviews.json"


@contextmanager
def _unsafe_review_mutation_lock(repo_root: Path | str, target: str):
    path = _unsafe_review_path(repo_root, target)
    lock_path = path.parent / "locks" / "unsafe_review.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _sync_unsafe_skipped_review_for_action(
    repo_root: Path | str,
    target: str,
    action: dict,
    normalized_status: str,
) -> dict:
    """Persist resolution for action-gated scanner manual-review leads."""
    if str(action.get("type") or "") not in {"action-gated-review", "unsafe-skipped-review"}:
        return {}
    if normalized_status not in UNSAFE_REVIEW_FINAL_STATUSES:
        return {
            "status": "skipped",
            "reason": f"action status {normalized_status!r} does not resolve action-gated review",
        }
    metadata = action.get("metadata") if isinstance(action.get("metadata"), dict) else {}
    unsafe_id = str(metadata.get("unsafe_skipped_id") or "").strip()
    artifact = str(metadata.get("artifact") or "").strip()
    if not unsafe_id:
        return {
            "status": "skipped",
            "reason": "action-gated review is missing unsafe_skipped_id metadata",
        }

    path = _unsafe_review_path(repo_root, target)
    with _unsafe_review_mutation_lock(repo_root, target):
        try:
            payload = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
        except (OSError, json.JSONDecodeError):
            payload = {}
        if not isinstance(payload, dict):
            payload = {}
        resolved = payload.setdefault("resolved", {})
        if not isinstance(resolved, dict):
            resolved = {}
            payload["resolved"] = resolved
        resolved[unsafe_id] = {
            "status": normalized_status,
            "artifact": artifact,
            "result": _compact_text(action.get("result") or "", 1000),
            "notes": _compact_text(action.get("notes") or "", 1000),
            "resolved_at": now_utc(),
        }
        payload["schema_version"] = SCHEMA_VERSION
        payload["target"] = canonical_target_value(target)
        payload["updated_at"] = now_utc()
        _write_json_atomic(path, payload)
    return {
        "status": "updated",
        "unsafe_skipped_id": unsafe_id,
        "path": str(path),
    }


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


def _checkpoint_item_to_action(target: str, item: dict) -> dict:
    action_text = _compact_text(item.get("action", ""))
    action_type = _compact_text(item.get("type", "next-action"), 80) or "next-action"
    command_hint = _compact_text(item.get("command_hint", ""), 300)
    next_question = (
        "Execute this evidence-backed checkpoint action and classify the lane "
        "instead of leaving it as a TODO."
    )
    built = build_action(
        target=target,
        action_type=action_type,
        evidence=action_text,
        next_question=next_question,
        action=action_text,
        priority=int(item.get("priority", 50) or 50),
        command_hint=command_hint,
        evidence_type="checkpoint-next-action",
        source=str(item.get("source") or "checkpoint"),
        source_id=str(item.get("source_id") or item.get("id") or ""),
        redline_required=bool(item.get("redline_required", False)),
        stop_condition=str(item.get("stop_condition") or DEFAULT_STOP_CONDITION),
        metadata=item.get("metadata") if isinstance(item.get("metadata"), dict) else None,
    )
    status = str(item.get("status") or "").strip().lower()
    if status in ALLOWED_STATUSES:
        built["status"] = status
    return built


def upsert_actions(queue: dict, actions: list[dict]) -> dict:
    retired_duplicates = _coalesce_candidate_duplicates(queue)
    existing_by_key: dict[str, dict] = {}
    for item in queue.get("actions", []):
        if not isinstance(item, dict):
            continue
        key = _candidate_dedupe_key(item) or str(item.get("dedupe_key") or _dedupe_key(item))
        existing_by_key[key] = item
    stats = {"added": 0, "updated": retired_duplicates, "skipped_final": 0}

    for action in actions:
        key = _candidate_dedupe_key(action) or str(action.get("dedupe_key") or _dedupe_key(action))
        if not key:
            continue
        existing = existing_by_key.get(key)
        if existing:
            if _is_final_action(existing):
                stats["skipped_final"] += 1
                continue
            before = _semantic_action(existing)
            if _is_runner_only_validated(existing):
                existing["status"] = str(action.get("status") or "queued")
                previous_result = str(existing.get("result") or "").strip()
                existing["notes"] = _compact_text(
                    (
                        f"{existing.get('notes', '')} "
                        "Reopened: validation_runner evidence is candidate-only; "
                        "run /validate gates before treating this as validated. "
                        f"Previous result: {previous_result}"
                    ),
                    1000,
                )
            if existing.get("source") == "checkpoint" and action.get("source") == "checkpoint":
                # checkpoint 队列是当前状态投影；允许上游重新排序，避免旧优先级
                # 把 enrichment lead 压在真正可执行 replay 前面。
                existing["priority"] = int(action.get("priority", 50) or 50)
            else:
                existing["priority"] = max(int(existing.get("priority", 50) or 50), int(action.get("priority", 50) or 50))
            existing["command_hint"] = existing.get("command_hint") or action.get("command_hint", "")
            if existing.get("source") == "checkpoint" and action.get("source") == "checkpoint":
                # checkpoint 是可重复生成的投影；当上游风险判定收窄时，允许清掉
                # 旧队列里的误报 red-line 标记，避免“actor/role”类文案长期限制执行。
                existing["redline_required"] = bool(action.get("redline_required"))
                if (
                    str(existing.get("status") or "") == "queued"
                    and str(action.get("type") or "") == "coverage-gap"
                    and _coverage_family_projection(existing) != _coverage_family_projection(action)
                ):
                    for field in ("action", "evidence", "next_question"):
                        if field in action:
                            existing[field] = action[field]
                    existing_metadata = existing.setdefault("metadata", {})
                    incoming_metadata = action.get("metadata") if isinstance(action.get("metadata"), dict) else {}
                    if isinstance(existing_metadata, dict):
                        for field in ("family_key", "family_projection", "family_size", "family_members"):
                            if field in incoming_metadata:
                                existing_metadata[field] = copy.deepcopy(incoming_metadata[field])
                            else:
                                existing_metadata.pop(field, None)
            else:
                existing["redline_required"] = bool(existing.get("redline_required") or action.get("redline_required"))
            if isinstance(action.get("metadata"), dict):
                metadata = existing.setdefault("metadata", {})
                if isinstance(metadata, dict):
                    metadata.update({k: v for k, v in action["metadata"].items() if k not in metadata})
            # Candidate projections may have matched by stable finding/endpoint
            # identity even though their presentation-specific dedupe keys differ.
            # Store the latest key so the next replay is key-idempotent too.
            existing["dedupe_key"] = key
            if _semantic_action(existing) != before:
                existing["updated_at"] = now_utc()
                stats["updated"] += 1
            existing_by_key[key] = existing
            continue

        action["id"] = _next_id(queue.setdefault("actions", []))
        action["dedupe_key"] = key
        queue["actions"].append(action)
        existing_by_key[key] = action
        stats["added"] += 1

    queue["actions"].sort(key=_action_sort_key)
    if stats["added"] or stats["updated"]:
        queue["updated_at"] = now_utc()
    return stats


def upsert_generated_action(queue: dict, action: dict) -> dict:
    """同一生成源只保留一个 queued 动作；新一代证据可越过旧终态。"""
    source = str(action.get("source") or "")
    source_id = str(action.get("source_id") or "")
    metadata = action.get("metadata") if isinstance(action.get("metadata"), dict) else {}
    generation = str(metadata.get("generation") or "")
    signal_identity = _knowledge_signal_identity(action)
    if not source or not source_id or not generation:
        return upsert_actions(queue, [action])

    matches = [
        item
        for item in queue.get("actions", [])
        if isinstance(item, dict)
        and str(item.get("source") or "") == source
        and str(item.get("source_id") or "") == source_id
    ]
    for existing in matches:
        existing_metadata = (
            existing.get("metadata")
            if isinstance(existing.get("metadata"), dict)
            else {}
        )
        same_generation = str(existing_metadata.get("generation") or "") == generation
        same_signal = bool(signal_identity) and (
            _knowledge_signal_identity(existing) == signal_identity
        )
        if _is_final_action(existing) and (same_generation or same_signal):
            return {"added": 0, "updated": 0, "skipped_final": 1}

    queued = next(
        (item for item in matches if str(item.get("status") or "") == "queued"),
        None,
    )
    if queued is not None:
        preserved = {
            key: queued.get(key)
            for key in ("id", "status", "attempts", "created_at", "result", "notes")
        }
        queued.clear()
        queued.update(action)
        queued.update(
            {
                key: value
                for key, value in preserved.items()
                if value not in (None, "")
            }
        )
        queued["dedupe_key"] = _dedupe_key(queued)
        queued["updated_at"] = now_utc()
        queue["actions"].sort(key=_action_sort_key)
        queue["updated_at"] = now_utc()
        return {"added": 0, "updated": 1, "skipped_final": 0}

    return upsert_actions(queue, [action])


def _retire_stale_checkpoint_actions(queue: dict, fresh_actions: list[dict]) -> int:
    """Retire unclaimed checkpoint TODOs that disappeared from the latest checkpoint.

    只处理仍未分类的 checkpoint 源 action，避免旧噪声在 queue 里长期滞留。
    candidate-evidence-gap/validated/manual 等人工推进过的条目不自动改状态。
    例外：/validate 跑完但未过 gate 的 validation action 会被标为 candidate；
    如果最新 checkpoint 已经转向其它候选，它不应继续用旧的“再跑 /validate”
    文案劫持下一步。finding 自身仍保留 partial/candidate 状态，AI 可随时重开。
    """
    fresh_keys = {
        str(action.get("dedupe_key") or _dedupe_key(action))
        for action in fresh_actions
        if isinstance(action, dict)
    }
    retired = 0
    ts = now_utc()
    for item in queue.get("actions", []):
        if not isinstance(item, dict):
            continue
        if str(item.get("source") or "") != "checkpoint":
            continue
        status = str(item.get("status") or "queued")
        action_type = str(item.get("type") or "")
        metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
        # Only activated versioned work survives a checkpoint refresh.  Legacy
        # running TODO retirement keeps its existing behavior.
        if status == "running" and metadata.get("depth_contract_version") == DEPTH_CONTRACT_VERSION:
            continue
        stale_checkpoint_todo = status in {"queued", "running"}
        stale_partial_validation = status == "candidate" and action_type == "validation"
        if not (stale_checkpoint_todo or stale_partial_validation):
            continue
        key = str(item.get("dedupe_key") or _dedupe_key(item))
        if key in fresh_keys:
            continue
        item["status"] = "n/a"
        item["updated_at"] = ts
        if not item.get("result"):
            item["result"] = (
                "Retired automatically after checkpoint refresh: the action is no longer "
                "present in the current evidence-backed next_action_queue."
            )
        retired += 1
    return retired


def _retire_superseded_candidate_actions(queue: dict) -> int:
    """Close candidate evidence gaps already superseded by final evidence.

    Runner sync can validate a surface action whose earlier candidate follow-up
    was also re-ingested under a different checkpoint projection. Keep the raw
    history, but stop the stale candidate from steering /autopilot again.
    """
    final_identities = _final_action_identities(queue)
    if not final_identities:
        return 0
    retired = 0
    ts = now_utc()
    for item in queue.get("actions", []):
        if not isinstance(item, dict):
            continue
        if not _is_superseded_candidate(item, final_identities):
            continue
        item["status"] = "n/a"
        item["updated_at"] = ts
        item["result"] = (
            "Retired automatically: this candidate evidence gap is superseded "
            "by final validation evidence for the same finding or endpoint."
        )
        retired += 1
    return retired


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
) -> dict:
    action_metadata = dict(_validate_action_metadata(metadata))
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
    with queue_mutation_lock(repo_root, target):
        queue = load_queue(repo_root, target)
        stats = (
            upsert_generated_action(queue, built)
            if generation
            else upsert_actions(queue, [built])
        )
        path = save_queue(repo_root, target, queue)
    return {"path": str(path), "stats": stats, "queue": queue}


def ingest_checkpoint(repo_root: Path | str, target: str, *, checkpoint: dict | None = None) -> dict:
    if checkpoint is None:
        try:
            from tools.checkpoint import build_checkpoint
        except ImportError:  # pragma: no cover - direct tools/ execution
            from checkpoint import build_checkpoint  # type: ignore
        checkpoint = build_checkpoint(repo_root, target=target)

    actions = [
        _checkpoint_item_to_action(target, item)
        for item in checkpoint.get("next_action_queue", []) or []
        if isinstance(item, dict)
    ]
    with queue_mutation_lock(repo_root, target):
        queue = load_queue(repo_root, target)
        current_runtime_wait = runtime_wait_action(repo_root, target)
        runtime_wait_projection = current_runtime_wait in {"wait_recon", "wait_scan"} or str(
            checkpoint.get("decision") or checkpoint.get("next_action") or ""
        ) in {"wait_recon", "wait_scan"}
        stats = {"added": 0, "updated": _coalesce_candidate_duplicates(queue), "skipped_final": 0}
        for action in actions:
            result = (
                upsert_generated_action(queue, action)
                if str((action.get("metadata") or {}).get("generation") or "")
                else upsert_actions(queue, [action])
            )
            for key, value in result.items():
                stats[key] = stats.get(key, 0) + int(value or 0)
        if runtime_wait_projection:
            # wait_* 是临时执行态，不代表旧 action 过时。
            stats["retired_stale"] = 0
            stats["retired_superseded"] = 0
        else:
            stats["retired_stale"] = _retire_stale_checkpoint_actions(queue, actions)
            stats["retired_superseded"] = _retire_superseded_candidate_actions(queue)
        queue["actions"].sort(key=_action_sort_key)
        path = save_queue(repo_root, target, queue)
    return {
        "path": str(path),
        "target": canonical_target_value(target),
        "stats": stats,
        "next": select_next_action_for_target(repo_root, target, queue),
        "summary": summarize_queue(queue, repo_root=repo_root, target=target),
    }


def _runtime_wait_queue_action(wait_action: str, target: str) -> dict:
    """Build a transient queue-shaped pointer for active long-running phases."""
    resolved = canonical_target_value(target)
    if wait_action == "wait_recon":
        action = (
            f"Wait/poll the existing /recon {resolved} run; do not launch another recon. "
            "Resume the queued action after the matching recon phase lock releases."
        )
    else:
        action = (
            f"Wait/poll the existing scan-only quick run for {resolved}; do not launch another "
            "scan-only quick. Resume the queued action after the matching scan phase lock releases."
        )
    return {
        "id": "runtime-wait",
        "target": resolved,
        "status": "transient",
        "type": wait_action,
        "priority": 1000,
        "evidence_type": "runtime-state",
        "evidence": "Matching long-running phase marker and flock are active.",
        "next_question": "Has the existing long-running phase completed or released its matching phase lock?",
        "action": action,
        "command_hint": "poll existing run; do not dequeue or start another long-running phase",
        "source": "runtime_state",
        "redline_required": False,
        "stop_condition": "completed workflow is written or the matching phase lock releases",
    }


def select_next_action(queue: dict) -> dict:
    _ensure_active_action_ids(queue)
    final_identities = _final_action_identities(queue)
    candidates = [
        item for item in queue.get("actions", [])
        if isinstance(item, dict) and str(item.get("status") or "queued") in ACTIVE_STATUSES
        and not _is_superseded_candidate(item, final_identities)
        and not _is_low_evidence_surface_review_action(item)
    ]
    if not candidates:
        return {}
    running = [item for item in candidates if str(item.get("status") or "") == "running"]
    if running:
        running.sort(key=_action_sort_key)
        return running[0]
    # 报告是阶段收束，不应抢在仍未处理的验证、深挖、coverage、action-gated
    # lead 前面。surface-review 则只是 Claude 审阅候选池，不应反过来压住
    # 已验证 finding 的报告收束；只有没有其它实质动作时才浮上来。
    substantive_non_report_candidates = [
        item for item in candidates
        if str(item.get("type") or "") not in REPORT_ACTION_TYPES
        and not _is_advisory_review_action(item)
    ]
    if substantive_non_report_candidates:
        candidates = substantive_non_report_candidates
    else:
        non_advisory_candidates = [
            item for item in candidates
            if not _is_advisory_review_action(item)
        ]
        if non_advisory_candidates:
            candidates = non_advisory_candidates
        else:
            current_surface_review = [
                item for item in candidates
                if str(item.get("type") or "") in ADVISORY_REVIEW_ACTION_TYPES
            ]
            if current_surface_review:
                candidates = current_surface_review
    candidates.sort(key=_action_sort_key)
    return candidates[0]


def select_next_action_for_target(
    repo_root: Path | str,
    target: str,
    queue: dict | None = None,
) -> dict:
    """Select next action, but let fresh runtime wait markers preempt old queue rows.

    The preemption is transient and non-destructive: queued validation/report/
    surface work remains on disk and becomes selectable again when the marker
    clears or expires.
    """
    wait_action = runtime_wait_action(repo_root, target)
    if wait_action in {"wait_recon", "wait_scan"}:
        return _runtime_wait_queue_action(wait_action, target)
    return select_next_action(queue if queue is not None else load_queue(repo_root, target))


def claim_next_action(
    repo_root: Path | str,
    target: str,
    *,
    action_id: str = "",
    metadata: dict | None = None,
) -> dict:
    """Atomically claim queued work or resume the current running action."""
    metadata = _validate_action_metadata(metadata)
    with queue_mutation_lock(repo_root, target):
        queue = load_queue(repo_root, target)
        wait_action = runtime_wait_action(repo_root, target)
        if wait_action in {"wait_recon", "wait_scan"}:
            selected = _runtime_wait_queue_action(wait_action, target)
        elif action_id:
            selected = next(
                (
                    item for index, item in enumerate(queue.get("actions", []))
                    if isinstance(item, dict)
                    and _action_identity(item, index) == action_id
                    and str(item.get("status") or "queued") in ACTIVE_STATUSES
                ),
                None,
            )
            if selected is None:
                raise KeyError(f"active action not found: {action_id}")
            if not str(selected.get("id") or "").strip():
                selected["id"] = action_id
                selected.setdefault("metadata", {})["legacy_identity"] = True
        else:
            selected = select_next_action(queue)
        if not selected:
            return {}
        if selected.get("id") == "runtime-wait":
            return {**selected, "claim_status": "transient", "previous_status": "transient"}

        previous = str(selected.get("status") or "queued")
        claim_status = "resumed" if previous == "running" else "selected"
        prepared_metadata = _prepare_claim_metadata(
            repo_root, target, queue, selected, metadata
        )
        metadata_changed = prepared_metadata != (
            selected.get("metadata") if isinstance(selected.get("metadata"), dict) else {}
        )
        if prepared_metadata:
            selected["metadata"] = prepared_metadata
        if previous == "queued":
            selected["status"] = "running"
            selected["attempts"] = int(selected.get("attempts", 0) or 0) + 1
            selected["updated_at"] = now_utc()
            queue["actions"].sort(key=_action_sort_key)
            save_queue(repo_root, target, queue)
            claim_status = "claimed"
        elif metadata_changed:
            selected["updated_at"] = now_utc()
            save_queue(repo_root, target, queue)
        return {
            **copy.deepcopy(selected),
            "claim_status": claim_status,
            "previous_status": previous,
        }


def resolve_action(
    repo_root: Path | str,
    *,
    target: str,
    action_id: str,
    status: str,
    result: str = "",
    notes: str = "",
    metadata: dict | None = None,
) -> dict:
    metadata = _validate_action_metadata(metadata)
    with queue_mutation_lock(repo_root, target):
        queue = load_queue(repo_root, target)
        response = _resolve_action_in_queue(
            repo_root,
            target=target,
            queue=queue,
            action_id=action_id,
            status=status,
            result=result,
            notes=notes,
            metadata=metadata,
        )
        path = save_queue(repo_root, target, queue)
        response["path"] = str(path)
        return response


def _resolve_action_in_queue(
    repo_root: Path | str,
    *,
    target: str,
    queue: dict,
    action_id: str,
    status: str,
    result: str = "",
    notes: str = "",
    metadata: dict | None = None,
    runner_observation: bool = False,
) -> dict:
    """在调用方已持有 queue lock 时修改一个 action。"""
    normalized = _normalize_status(status)
    metadata = _validate_action_metadata(metadata)
    for index, item in enumerate(queue.get("actions", [])):
        if not isinstance(item, dict):
            continue
        if _action_identity(item, index) != action_id:
            continue
        previous = str(item.get("status") or "queued")
        existing_metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
        versioned = (
            existing_metadata.get("depth_contract_version") == DEPTH_CONTRACT_VERSION
            or metadata.get("depth_contract_version") == DEPTH_CONTRACT_VERSION
        )
        runner_fields = RUNNER_OBSERVATION_FIELDS.intersection(metadata)
        if versioned and runner_fields and not runner_observation:
            raise ValueError(
                "Action Queue resolve cannot supply Runner-owned observation fields: "
                + ", ".join(sorted(runner_fields))
            )
        merged_metadata = _merge_action_metadata(item.get("metadata"), metadata)
        if (
            merged_metadata.get("depth_contract_version") == DEPTH_CONTRACT_VERSION
            and normalized in FINAL_STATUSES
            and previous != "running"
        ):
            raise ValueError("Action Queue versioned resolve requires a running claimed action")
        terminal_plan = _versioned_terminal_plan(
            repo_root,
            target,
            queue,
            item,
            normalized,
            metadata,
            merged_metadata,
        )
        # A claimed/running action represents real execution; closing it as
        # tested must point at target-owned evidence. Versioned runners already
        # store that evidence in last_outcome, so a free-form resolve note can
        # close the action after the continuation/kill contract is checked.
        requires_tested_evidence = (
            normalized == "tested"
            and previous == "running"
            and str(item.get("source") or "") != "manual"
        )
        if normalized in TERMINAL_EVIDENCE_STATUSES or requires_tested_evidence:
            evidence_ref = _locatable_evidence_ref(repo_root, result)
            if not evidence_ref and requires_tested_evidence:
                outcome = merged_metadata.get("last_outcome")
                if isinstance(outcome, dict):
                    evidence_ref = _target_owned_evidence_ref(
                        repo_root,
                        target,
                        outcome.get("evidence_ref") or outcome.get("summary_ref"),
                    )
            if not evidence_ref:
                raise ValueError(
                    f"action status {normalized!r} requires a locatable evidence reference in result"
                )
        item["status"] = normalized
        item["updated_at"] = now_utc()
        item["result"] = _compact_text(result or item.get("result", ""), 1000)
        item["notes"] = _compact_text(notes or item.get("notes", ""), 1000)
        if metadata and merged_metadata != item.get("metadata"):
            item["metadata"] = merged_metadata
        if previous != "running" and normalized in {"running", "tested", "dead-end", "blocked", "lead", "signal", "candidate", "validated"}:
            item["attempts"] = int(item.get("attempts", 0) or 0) + 1
        if terminal_plan:
            child = terminal_plan.get("child")
            pivot_stats = upsert_actions(queue, [child]) if isinstance(child, dict) else {
                "added": 0, "updated": 0, "skipped_final": 0,
            }
            item.setdefault("metadata", {})["hypothesis_status"] = {
                "kill": "closed",
                "rotation": "rotated",
                "continuation": "open",
            }[terminal_plan["decision"]]
        else:
            pivot_actions = _hypothesis_pivot_actions(
                item,
                status=normalized,
                result=item.get("result", ""),
            )
            pivot_stats = upsert_actions(queue, pivot_actions) if pivot_actions else {
                "added": 0, "updated": 0, "skipped_final": 0,
            }
            if pivot_actions:
                item.setdefault("metadata", {})["hypothesis_status"] = "open"
            elif isinstance(item.get("metadata"), dict) and item["metadata"].get("kill_condition_met") is True:
                item["metadata"]["hypothesis_status"] = "closed"
        coverage_update = _sync_coverage_matrix_for_action(repo_root, target, item, normalized)
        unsafe_review_update = _sync_unsafe_skipped_review_for_action(repo_root, target, item, normalized)
        queue["actions"].sort(key=_action_sort_key)
        response = {
            "id": action_id,
            "previous_status": previous,
            "status": normalized,
            "next": select_next_action_for_target(repo_root, target, queue),
            "summary": summarize_queue(queue, repo_root=repo_root, target=target),
        }
        if coverage_update:
            response["coverage_update"] = coverage_update
        if unsafe_review_update:
            response["unsafe_review_update"] = unsafe_review_update
        if pivot_stats["added"]:
            response["hypothesis_continuation"] = pivot_stats
        return response
    raise KeyError(f"action not found: {action_id}")


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
    selected = (
        select_next_action_for_target(repo_root, target, queue)
        if repo_root is not None and target
        else select_next_action(queue)
    )
    return {
        "target": queue.get("target", ""),
        "total": len(actions),
        "active": len(active),
        "final": len(final),
        "by_status": dict(sorted(by_status.items())),
        "by_type": dict(sorted(by_type.items())),
        "legacy_missing_id": legacy_missing_id,
        "next_id": (selected or {}).get("id", ""),
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
    summary = summarize_queue(queue, repo_root=repo_root, target=target)
    next_action = (
        select_next_action_for_target(repo_root, target, queue)
        if repo_root is not None and target
        else select_next_action(queue)
    )
    lines = [
        "ACTION QUEUE",
        f"- Target: {summary.get('target')}",
        f"- Total: {summary.get('total')}",
        f"- Active: {summary.get('active')}",
        f"- Final: {summary.get('final')}",
        f"- By status: {summary.get('by_status')}",
        f"- By type: {summary.get('by_type')}",
        "- Next:",
        format_action(next_action),
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

    ingest = sub.add_parser("ingest-checkpoint", help="Ingest checkpoint next_action_queue into persistent action queue.")
    ingest.add_argument("--target", required=True)
    ingest.add_argument("--json", action="store_true")

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
    add.add_argument("--json", action="store_true")

    next_cmd = sub.add_parser("next", help="Print the highest-priority active action.")
    next_cmd.add_argument("--target", required=True)
    next_cmd.add_argument("--json", action="store_true")

    claim = sub.add_parser("claim", help="Atomically claim or resume the highest-priority action.")
    claim.add_argument("--target", required=True)
    claim.add_argument("--id", default="", help="Claim one explicit active action instead of the default.")
    claim.add_argument(
        "--metadata-json",
        default=None,
        help="Versioned AI activation metadata merged atomically before claim.",
    )
    claim.add_argument("--json", action="store_true")

    resolve = sub.add_parser("resolve", help="Resolve or reclassify one action.")
    resolve.add_argument("--target", required=True)
    resolve.add_argument("--id", required=True)
    resolve.add_argument("--status", required=True, choices=sorted(ALLOWED_STATUSES | set(STATUS_ALIASES)))
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
        if args.command == "ingest-checkpoint":
            result = ingest_checkpoint(repo, args.target)
            _print(result, as_json=args.json)
            return 0

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
            )
            _print(
                result if args.json else format_summary(result["queue"], repo_root=repo, target=args.target),
                as_json=args.json,
            )
            return 0

        if args.command == "next":
            queue = load_queue(repo, args.target)
            action = select_next_action_for_target(repo, args.target, queue)
            _print(action if args.json else format_action(action), as_json=args.json)
            return 0 if action else 1

        if args.command == "claim":
            metadata = _parse_metadata_json(args.metadata_json)
            action = claim_next_action(
                repo,
                args.target,
                action_id=args.id,
                metadata=metadata,
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
