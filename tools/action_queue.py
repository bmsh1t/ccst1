#!/usr/bin/env python3
"""Persistent action queue for capability-first autopilot runs.

The queue turns evidence-backed next steps into durable state so Claude CLI can
keep executing instead of ending on natural-language TODOs.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.parse
from collections import Counter
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
REPORT_ACTION_TYPES = {"report"}
ADVISORY_REVIEW_ACTION_TYPES = {"surface-review"}
LOW_EVIDENCE_SURFACE_REVIEW_MARKERS = (
    "reason: top advisory score",
    "reason: top advisory score (low-evidence fallback)",
)


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def queue_path(repo_root: Path | str, target: str) -> Path:
    repo = Path(repo_root)
    resolved = canonical_target_value(target)
    return repo / "state" / target_storage_key(resolved) / "action_queue.json"


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
    except (OSError, json.JSONDecodeError):
        return _empty_queue(target)
    if not isinstance(payload, dict):
        return _empty_queue(target)
    payload.setdefault("schema_version", SCHEMA_VERSION)
    payload.setdefault("target", canonical_target_value(target))
    payload.setdefault("actions", [])
    if not isinstance(payload["actions"], list):
        payload["actions"] = []
    return payload


def save_queue(repo_root: Path | str, target: str, queue: dict) -> Path:
    path = queue_path(repo_root, target)
    queue["target"] = canonical_target_value(target)
    queue["updated_at"] = now_utc()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(queue, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path


def _compact_text(value: Any, limit: int = 800) -> str:
    text = str(value or "").strip()
    text = re.sub(r"\s+", " ", text)
    return text[:limit]


def _dedupe_key(action: dict) -> str:
    metadata = action.get("metadata") if isinstance(action.get("metadata"), dict) else {}
    parts = [
        action.get("type", ""),
        action.get("evidence_type", ""),
        action.get("evidence", ""),
        action.get("next_question", ""),
        action.get("action", ""),
        action.get("command_hint", ""),
        metadata.get("endpoint", ""),
        metadata.get("vuln_class", ""),
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


def _action_identities(action: dict) -> set[str]:
    """Stable identities used to suppress stale duplicate candidate actions."""
    metadata = action.get("metadata") if isinstance(action.get("metadata"), dict) else {}
    identities: set[str] = set()
    finding_id = str(metadata.get("finding_id") or "").strip().lower()
    if finding_id:
        identities.add(f"finding:{finding_id}")
    for key in ("endpoint", "url"):
        endpoint = _normalise_identity_endpoint(str(metadata.get(key) or ""))
        if endpoint:
            identities.add(f"endpoint:{endpoint}")
    return identities


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


def _status_rank(status: str) -> int:
    if status == "candidate":
        return 0
    if status == "signal":
        return 1
    if status == "lead":
        return 2
    if status == "queued":
        return 3
    if status == "running":
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
    """Return True for surface review items that are not exact runner work.

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
    endpoint = str(metadata.get("endpoint") or "").strip()
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
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return {
        "status": "updated",
        "unsafe_skipped_id": unsafe_id,
        "path": str(path),
    }


def _redline_required(text: str) -> bool:
    lowered = text.lower()
    tokens = (
        "red-line",
        "unsafe",
        "mutation",
        "state-changing",
        "write",
        "delete",
        "credential",
        "spray",
        "race",
        "actor",
        "role",
        "payment",
        "order",
    )
    return any(token in lowered for token in tokens)


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
    text_for_redline = " ".join([action_type, evidence, next_question, action, command_hint])
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
        "redline_required": _redline_required(text_for_redline) if redline_required is None else bool(redline_required),
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
        source="checkpoint",
        source_id=str(item.get("id") or ""),
        redline_required=bool(item.get("redline_required", False)),
        stop_condition=str(item.get("stop_condition") or DEFAULT_STOP_CONDITION),
        metadata=item.get("metadata") if isinstance(item.get("metadata"), dict) else None,
    )
    status = str(item.get("status") or "").strip().lower()
    if status in ALLOWED_STATUSES:
        built["status"] = status
    return built


def upsert_actions(queue: dict, actions: list[dict]) -> dict:
    existing_by_key = {
        str(item.get("dedupe_key") or _dedupe_key(item)): item
        for item in queue.get("actions", [])
        if isinstance(item, dict)
    }
    stats = {"added": 0, "updated": 0, "skipped_final": 0}

    for action in actions:
        key = str(action.get("dedupe_key") or _dedupe_key(action))
        if not key:
            continue
        existing = existing_by_key.get(key)
        if existing:
            if _is_final_action(existing):
                stats["skipped_final"] += 1
                continue
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
            else:
                existing["redline_required"] = bool(existing.get("redline_required") or action.get("redline_required"))
            if isinstance(action.get("metadata"), dict):
                metadata = existing.setdefault("metadata", {})
                if isinstance(metadata, dict):
                    metadata.update({k: v for k, v in action["metadata"].items() if k not in metadata})
            existing["updated_at"] = now_utc()
            stats["updated"] += 1
            continue

        action["id"] = _next_id(queue.setdefault("actions", []))
        action["dedupe_key"] = key
        queue["actions"].append(action)
        existing_by_key[key] = action
        stats["added"] += 1

    queue["actions"].sort(key=_action_sort_key)
    queue["updated_at"] = now_utc()
    return stats


def _retire_stale_checkpoint_actions(queue: dict, fresh_actions: list[dict]) -> int:
    """Retire queued/running checkpoint TODOs that disappeared from the latest checkpoint.

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
    safety: str = "non_destructive",
    stop_condition: str = DEFAULT_STOP_CONDITION,
) -> dict:
    queue = load_queue(repo_root, target)
    built = build_action(
        target=target,
        action_type=action_type,
        evidence=evidence,
        next_question=next_question,
        action=action,
        priority=priority,
        command_hint=command_hint,
        evidence_type=evidence_type,
        source="manual",
        safety=safety,
        stop_condition=stop_condition,
    )
    stats = upsert_actions(queue, [built])
    path = save_queue(repo_root, target, queue)
    return {"path": str(path), "stats": stats, "queue": queue}


def ingest_checkpoint(repo_root: Path | str, target: str, *, checkpoint: dict | None = None) -> dict:
    if checkpoint is None:
        try:
            from tools.checkpoint import build_checkpoint
        except ImportError:  # pragma: no cover - direct tools/ execution
            from checkpoint import build_checkpoint  # type: ignore
        checkpoint = build_checkpoint(repo_root, target=target)

    queue = load_queue(repo_root, target)
    current_runtime_wait = runtime_wait_action(repo_root, target)
    runtime_wait_projection = current_runtime_wait in {"wait_recon", "wait_scan"} or str(
        checkpoint.get("decision") or checkpoint.get("next_action") or ""
    ) in {
        "wait_recon",
        "wait_scan",
    }
    actions = [
        _checkpoint_item_to_action(target, item)
        for item in checkpoint.get("next_action_queue", []) or []
        if isinstance(item, dict)
    ]
    stats = upsert_actions(queue, actions)
    if runtime_wait_projection:
        # wait_* 是临时执行态，不代表旧 action 过时；不要因为 checkpoint
        # 暂时输出空队列就把可恢复的验证/报告/深挖项标成 n/a。
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
    final_identities = _final_action_identities(queue)
    candidates = [
        item for item in queue.get("actions", [])
        if isinstance(item, dict) and str(item.get("status") or "queued") in ACTIVE_STATUSES
        and not _is_superseded_candidate(item, final_identities)
        and not _is_low_evidence_surface_review_action(item)
    ]
    if not candidates:
        return {}
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


def resolve_action(
    repo_root: Path | str,
    *,
    target: str,
    action_id: str,
    status: str,
    result: str = "",
    notes: str = "",
) -> dict:
    queue = load_queue(repo_root, target)
    normalized = _normalize_status(status)
    for item in queue.get("actions", []):
        if not isinstance(item, dict):
            continue
        if str(item.get("id") or "") != action_id:
            continue
        previous = str(item.get("status") or "queued")
        item["status"] = normalized
        item["updated_at"] = now_utc()
        item["result"] = _compact_text(result or item.get("result", ""), 1000)
        item["notes"] = _compact_text(notes or item.get("notes", ""), 1000)
        if normalized in {"running", "tested", "dead-end", "blocked", "lead", "signal", "candidate", "validated"}:
            item["attempts"] = int(item.get("attempts", 0) or 0) + 1
        coverage_update = _sync_coverage_matrix_for_action(repo_root, target, item, normalized)
        unsafe_review_update = _sync_unsafe_skipped_review_for_action(repo_root, target, item, normalized)
        queue["actions"].sort(key=_action_sort_key)
        path = save_queue(repo_root, target, queue)
        response = {
            "path": str(path),
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
        return response
    raise KeyError(f"action not found: {action_id}")


def summarize_queue(
    queue: dict,
    *,
    repo_root: Path | str | None = None,
    target: str | None = None,
) -> dict:
    actions = [item for item in queue.get("actions", []) if isinstance(item, dict)]
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
        "next_id": (selected or {}).get("id", ""),
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
            result = add_manual_action(
                repo,
                target=args.target,
                action_type=args.type,
                evidence_type=args.evidence_type,
                evidence=args.evidence,
                next_question=args.next_question,
                action=args.action,
                priority=args.priority,
                command_hint=args.command_hint,
                safety=args.safety,
                stop_condition=args.stop_condition,
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

        if args.command == "resolve":
            result = resolve_action(
                repo,
                target=args.target,
                action_id=args.id,
                status=args.status,
                result=args.result or args.evidence,
                notes=args.notes,
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
    except (KeyError, ValueError) as exc:
        print(f"action_queue: {exc}", file=sys.stderr)
        return 2

    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
