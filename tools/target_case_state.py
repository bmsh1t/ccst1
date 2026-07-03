#!/usr/bin/env python3
"""Target-scoped actor/session/object state for high-value validation.

Target Case State is runtime memory, not knowledge.  It stores which test
actors, sessions, objects, private markers, hypotheses, and validation backlog
items are available for one target, then emits the next highest-value replay
action for Claude to reason about and execute through validation_runner.
"""

from __future__ import annotations

import argparse
import json
import shlex
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parents[1]
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

try:
    from tools.target_paths import canonical_target_value, target_storage_key
except ImportError:  # pragma: no cover - direct tools/ execution
    from target_paths import canonical_target_value, target_storage_key  # type: ignore


SCHEMA_VERSION = 1
ACTIVE_BACKLOG_STATUSES = {"pending", "running", "candidate", "blocked"}
FINAL_BACKLOG_STATUSES = {"tested_clean", "tested_finding", "dead_end"}
BACKLOG_STATUSES = ACTIVE_BACKLOG_STATUSES | FINAL_BACKLOG_STATUSES
PRIORITY_SCORE = {"critical": 120, "high": 100, "medium": 60, "low": 30, "info": 10}
SESSION_INVALID = {"invalid", "expired", "revoked"}
SESSION_KINDS = {"cookie", "bearer", "browser_state", "api_key", "custom_header", "unknown"}
ACTOR_ROLES = {"anonymous", "user", "low_role", "admin_like", "service", "unknown"}
HIGH_IMPACT_OBJECT_TYPES = {
    "order",
    "invoice",
    "address",
    "report",
    "export",
    "workspace",
    "organization",
    "tenant",
    "payment",
    "billing",
    "file",
}


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def case_state_path(repo_root: str | Path, target: str) -> Path:
    resolved = canonical_target_value(target)
    return Path(repo_root) / "state" / target_storage_key(resolved) / "case_state.json"


def _empty_state(target: str) -> dict[str, Any]:
    ts = now_utc()
    resolved = canonical_target_value(target)
    return {
        "schema_version": SCHEMA_VERSION,
        "target": resolved,
        "target_key": target_storage_key(resolved),
        "created_at": ts,
        "updated_at": ts,
        "actors": {},
        "sessions": {},
        "objects": {},
        "hypotheses": [],
        "validation_backlog": [],
    }


def _ensure_shape(state: dict[str, Any], target: str) -> dict[str, Any]:
    resolved = canonical_target_value(target)
    state.setdefault("schema_version", SCHEMA_VERSION)
    state["target"] = state.get("target") or resolved
    state["target_key"] = state.get("target_key") or target_storage_key(resolved)
    state.setdefault("created_at", now_utc())
    state.setdefault("updated_at", now_utc())
    for key, default in (
        ("actors", {}),
        ("sessions", {}),
        ("objects", {}),
        ("hypotheses", []),
        ("validation_backlog", []),
    ):
        if not isinstance(state.get(key), type(default)):
            state[key] = default
    return state


def load_case_state(repo_root: str | Path, target: str) -> dict[str, Any]:
    path = case_state_path(repo_root, target)
    if not path.is_file():
        return _empty_state(target)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return _empty_state(target)
    if not isinstance(payload, dict):
        return _empty_state(target)
    return _ensure_shape(payload, target)


def save_case_state(repo_root: str | Path, target: str, state: dict[str, Any]) -> Path:
    state = _ensure_shape(state, target)
    state["schema_version"] = SCHEMA_VERSION
    state["updated_at"] = now_utc()
    path = case_state_path(repo_root, target)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _require_non_empty(value: str, field: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{field} is required")
    return text


def _next_id(items: list[dict[str, Any]], prefix: str) -> str:
    highest = 0
    for item in items:
        raw = str(item.get("id") or "")
        if raw.startswith(prefix):
            suffix = raw[len(prefix):]
            if suffix.isdigit():
                highest = max(highest, int(suffix))
    return f"{prefix}{highest + 1:03d}"


def _quote(value: Any) -> str:
    return shlex.quote(str(value or ""))


def add_actor(
    repo_root: str | Path,
    target: str,
    *,
    actor: str,
    role: str = "unknown",
    label: str = "",
    notes: str = "",
) -> dict[str, Any]:
    state = load_case_state(repo_root, target)
    actor_id = _require_non_empty(actor, "actor")
    role_value = str(role or "unknown").strip() or "unknown"
    if role_value not in ACTOR_ROLES:
        raise ValueError(f"unknown role: {role_value}. Allowed: {', '.join(sorted(ACTOR_ROLES))}")
    ts = now_utc()
    current = state["actors"].get(actor_id, {})
    state["actors"][actor_id] = {
        "role": role_value,
        "label": str(label or current.get("label", "") or ""),
        "notes": str(notes or current.get("notes", "") or ""),
        "created_at": current.get("created_at") or ts,
        "last_seen": ts,
    }
    save_case_state(repo_root, target, state)
    return state["actors"][actor_id]


def add_session(
    repo_root: str | Path,
    target: str,
    *,
    session: str,
    actor: str,
    kind: str = "unknown",
    header_name: str = "",
    header_value: str = "",
    source: str = "manual",
    validity: str = "unknown",
    notes: str = "",
) -> dict[str, Any]:
    state = load_case_state(repo_root, target)
    session_id = _require_non_empty(session, "session")
    actor_id = _require_non_empty(actor, "actor")
    if actor_id not in state["actors"]:
        raise ValueError(f"actor does not exist: {actor_id}")
    kind_value = str(kind or "unknown").strip() or "unknown"
    if kind_value not in SESSION_KINDS:
        raise ValueError(f"unknown session kind: {kind_value}. Allowed: {', '.join(sorted(SESSION_KINDS))}")
    if not header_name and kind_value == "bearer":
        header_name = "Authorization"
    if not header_name and kind_value == "cookie":
        header_name = "Cookie"
    ts = now_utc()
    current = state["sessions"].get(session_id, {})
    state["sessions"][session_id] = {
        "actor": actor_id,
        "kind": kind_value,
        "header_name": str(header_name or current.get("header_name", "") or ""),
        "header_value": str(header_value or current.get("header_value", "") or ""),
        "source": str(source or current.get("source", "manual") or "manual"),
        "validity": str(validity or current.get("validity", "unknown") or "unknown"),
        "last_checked": current.get("last_checked", ""),
        "notes": str(notes or current.get("notes", "") or ""),
        "created_at": current.get("created_at") or ts,
        "last_seen": ts,
    }
    save_case_state(repo_root, target, state)
    return state["sessions"][session_id]


def add_object(
    repo_root: str | Path,
    target: str,
    *,
    object_ref: str,
    object_type: str,
    object_id: str = "",
    owner_actor: str = "",
    endpoint: str = "",
    private_marker: str = "",
    status: str = "active",
    notes: str = "",
) -> dict[str, Any]:
    state = load_case_state(repo_root, target)
    ref = _require_non_empty(object_ref, "object")
    if owner_actor and owner_actor not in state["actors"]:
        raise ValueError(f"owner actor does not exist: {owner_actor}")
    ts = now_utc()
    current = state["objects"].get(ref, {})
    state["objects"][ref] = {
        "type": _require_non_empty(object_type, "type"),
        "object_id": str(object_id or current.get("object_id", "") or ""),
        "owner_actor": str(owner_actor or current.get("owner_actor", "") or ""),
        "endpoint": str(endpoint or current.get("endpoint", "") or ""),
        "private_marker": str(private_marker or current.get("private_marker", "") or ""),
        "status": str(status or current.get("status", "active") or "active"),
        "notes": str(notes or current.get("notes", "") or ""),
        "created_at": current.get("created_at") or ts,
        "last_seen": ts,
    }
    save_case_state(repo_root, target, state)
    return state["objects"][ref]


def add_hypothesis(
    repo_root: str | Path,
    target: str,
    *,
    vuln_class: str,
    endpoint: str = "",
    object_ref: str = "",
    actors: list[str] | None = None,
    why_now: str = "",
    next_action: str = "",
    status: str = "open",
    hypothesis_id: str = "",
) -> dict[str, Any]:
    state = load_case_state(repo_root, target)
    actors = actors or []
    for actor in actors:
        if actor not in state["actors"]:
            raise ValueError(f"actor does not exist: {actor}")
    if object_ref and object_ref not in state["objects"]:
        raise ValueError(f"object_ref does not exist: {object_ref}")
    record = {
        "id": hypothesis_id or _next_id(state["hypotheses"], "hyp_"),
        "vuln_class": _require_non_empty(vuln_class, "vuln_class"),
        "endpoint": str(endpoint or ""),
        "object_ref": str(object_ref or ""),
        "actors": list(actors),
        "status": str(status or "open"),
        "why_now": str(why_now or ""),
        "next_action": str(next_action or ""),
        "created_at": now_utc(),
    }
    state["hypotheses"].append(record)
    save_case_state(repo_root, target, state)
    return record


def add_backlog(
    repo_root: str | Path,
    target: str,
    *,
    runner: str,
    endpoint: str = "",
    owner_actor: str = "",
    peer_actor: str = "",
    object_ref: str = "",
    priority: str = "medium",
    required_evidence: list[str] | None = None,
    stop_condition: str = "",
    chain_extensions_if_blocked: list[str] | None = None,
    status: str = "pending",
    backlog_id: str = "",
) -> dict[str, Any]:
    state = load_case_state(repo_root, target)
    for actor in (owner_actor, peer_actor):
        if actor and actor not in state["actors"]:
            raise ValueError(f"actor does not exist: {actor}")
    if object_ref and object_ref not in state["objects"]:
        raise ValueError(f"object_ref does not exist: {object_ref}")
    status_value = str(status or "pending")
    if status_value not in BACKLOG_STATUSES:
        raise ValueError(f"unknown backlog status: {status_value}")
    record = {
        "id": backlog_id or _next_id(state["validation_backlog"], "val_"),
        "runner": _require_non_empty(runner, "runner"),
        "endpoint": str(endpoint or ""),
        "owner_actor": str(owner_actor or ""),
        "peer_actor": str(peer_actor or ""),
        "object_ref": str(object_ref or ""),
        "status": status_value,
        "priority": str(priority or "medium"),
        "required_evidence": list(required_evidence or []),
        "stop_condition": str(stop_condition or ""),
        "chain_extensions_if_blocked": list(chain_extensions_if_blocked or []),
        "created_at": now_utc(),
    }
    state["validation_backlog"].append(record)
    save_case_state(repo_root, target, state)
    return record


def _session_for_actor(state: dict[str, Any], actor: str) -> tuple[str, dict[str, Any]] | tuple[None, None]:
    for session_id, session in state.get("sessions", {}).items():
        if session.get("actor") != actor:
            continue
        if str(session.get("validity") or "unknown").lower() in SESSION_INVALID:
            continue
        if not session.get("header_name") or not session.get("header_value"):
            continue
        return str(session_id), session
    return None, None


def _impact_weight(state: dict[str, Any], item: dict[str, Any]) -> int:
    obj = state.get("objects", {}).get(item.get("object_ref") or "", {})
    object_type = str(obj.get("type") or "").lower()
    endpoint = str(item.get("endpoint") or obj.get("endpoint") or "").lower()
    score = 0
    if object_type in HIGH_IMPACT_OBJECT_TYPES:
        score += 30
    if any(token in endpoint for token in ("order", "invoice", "address", "report", "export", "admin", "billing")):
        score += 20
    if item.get("runner") == "idor-actor-pair":
        score += 15
    return score


def _readiness(
    state: dict[str, Any],
    item: dict[str, Any],
) -> tuple[int, list[str], dict[str, Any]]:
    missing: list[str] = []
    details: dict[str, Any] = {}
    obj = state.get("objects", {}).get(item.get("object_ref") or "", {})
    endpoint = item.get("endpoint") or obj.get("endpoint")
    if item.get("runner") == "idor-actor-pair":
        owner = item.get("owner_actor") or obj.get("owner_actor")
        peer = item.get("peer_actor")
        owner_session_id, owner_session = _session_for_actor(state, owner) if owner else (None, None)
        peer_session_id, peer_session = _session_for_actor(state, peer) if peer else (None, None)
        if not endpoint:
            missing.append("object endpoint")
        if not owner:
            missing.append("owner actor")
        elif not owner_session:
            missing.append("owner session")
        if not peer:
            missing.append("peer actor")
        elif not peer_session:
            missing.append("peer session")
        if not obj.get("private_marker"):
            missing.append("owner private marker")
        details.update({
            "endpoint": endpoint,
            "object": obj,
            "owner_actor": owner,
            "peer_actor": peer,
            "owner_session_id": owner_session_id,
            "peer_session_id": peer_session_id,
            "owner_session": owner_session,
            "peer_session": peer_session,
        })
        return max(0, 60 - 15 * len(missing)), missing, details
    if not endpoint:
        missing.append("endpoint")
    details["endpoint"] = endpoint
    return max(0, 30 - 10 * len(missing)), missing, details


def _build_idor_actor_pair_command(target: str, item: dict[str, Any], details: dict[str, Any], *, redact: bool) -> str:
    parts = [
        "python3",
        "tools/validation_runner.py",
        "idor-actor-pair",
        "--target",
        target,
        "--from-case-state",
    ]
    if item.get("id"):
        parts.extend(["--backlog-id", item.get("id")])
    else:
        parts.extend([
            "--owner-actor",
            details.get("owner_actor") or item.get("owner_actor") or "",
            "--peer-actor",
            details.get("peer_actor") or item.get("peer_actor") or "",
            "--object-ref",
            item.get("object_ref") or "",
        ])
    parts.extend(["--repeat", "2"])
    return " ".join(_quote(part) for part in parts if part != "")


def _build_generic_command(target: str, item: dict[str, Any], details: dict[str, Any]) -> str:
    endpoint = details.get("endpoint") or item.get("endpoint") or ""
    parts = ["python3", "tools/validation_runner.py", item.get("runner") or "", "--target", target]
    if endpoint:
        parts.extend(["--url", endpoint])
    return " ".join(_quote(part) for part in parts if part != "")


def _chain_context(state: dict[str, Any], item: dict[str, Any], details: dict[str, Any]) -> list[str]:
    context: list[str] = []
    obj = details.get("object") or {}
    if details.get("endpoint"):
        context.append("object endpoint is known")
    if obj.get("private_marker"):
        context.append("object has private marker")
    if details.get("owner_session"):
        context.append("owner session is available")
    if details.get("peer_session"):
        context.append("peer session is available")
    if item.get("runner") == "idor-actor-pair":
        context.append("actor/object replay can be executed by validation_runner")
    return context


def _score_backlog_item(state: dict[str, Any], item: dict[str, Any]) -> tuple[int, list[str], dict[str, Any]]:
    readiness_score, missing, details = _readiness(state, item)
    priority = PRIORITY_SCORE.get(str(item.get("priority") or "medium").lower(), 50)
    impact = _impact_weight(state, item)
    chain_potential = 10 * len(item.get("chain_extensions_if_blocked") or [])
    risk_cost = 20 if item.get("state_changing") else 0
    status_penalty = 15 if item.get("status") == "blocked" else 0
    score = priority + impact + readiness_score + chain_potential - risk_cost - status_penalty
    return score, missing, details


def next_action(repo_root: str | Path, target: str) -> dict[str, Any]:
    state = load_case_state(repo_root, target)
    active = [
        item for item in state.get("validation_backlog", [])
        if str(item.get("status") or "pending") in ACTIVE_BACKLOG_STATUSES
    ]
    if not active:
        open_hypotheses = [
            item for item in state.get("hypotheses", [])
            if str(item.get("status") or "open") == "open"
        ]
        if open_hypotheses:
            hyp = open_hypotheses[0]
            return {
                "next_action": "create_validation_backlog",
                "hypothesis": hyp.get("next_action") or hyp.get("why_now") or "open hypothesis needs validation backlog",
                "why_now": hyp.get("why_now", ""),
                "vuln_class": hyp.get("vuln_class", ""),
                "endpoint": hyp.get("endpoint", ""),
                "object_ref": hyp.get("object_ref", ""),
                "actors": hyp.get("actors", []),
                "write_back": "add-backlog for this hypothesis after choosing the runner",
            }
        return {
            "next_action": "none",
            "reason": "no active validation backlog or open hypothesis",
        }

    ranked: list[tuple[int, list[str], dict[str, Any], dict[str, Any]]] = []
    for item in active:
        score, missing, details = _score_backlog_item(state, item)
        ranked.append((score, missing, details, item))
    ranked.sort(key=lambda row: row[0], reverse=True)
    score, missing, details, item = ranked[0]
    ready = not missing
    target_value = state.get("target") or canonical_target_value(target)
    runner = item.get("runner")
    if runner == "idor-actor-pair":
        command = _build_idor_actor_pair_command(target_value, item, details, redact=False) if not missing else ""
        redacted_command = _build_idor_actor_pair_command(target_value, item, details, redact=True) if details.get("endpoint") else ""
    else:
        command = _build_generic_command(target_value, item, details) if not missing else ""
        redacted_command = command
    obj = details.get("object") or {}
    hypothesis = (
        f"peer {details.get('peer_actor')} may access {item.get('object_ref')} "
        f"owned by {details.get('owner_actor')}"
        if runner == "idor-actor-pair"
        else f"validate {runner} on {details.get('endpoint') or item.get('endpoint')}"
    )
    extensions = list(item.get("chain_extensions_if_blocked") or [])
    if runner == "idor-actor-pair" and not extensions:
        extensions = [
            "try export/report endpoint for the same object",
            "try mobile/versioned API equivalent",
            "try GraphQL node/global id if discovered",
        ]
    return {
        "next_action": "run_validation_runner" if ready else "enrich_case_state",
        "ready": ready,
        "score": score,
        "backlog_id": item.get("id"),
        "runner": runner,
        "hypothesis": hypothesis,
        "chain_context": _chain_context(state, item, details),
        "why_now": (
            "highest-ranked active backlog by priority, impact, readiness, chain potential, and risk cost"
        ),
        "endpoint": details.get("endpoint") or item.get("endpoint") or "",
        "owner_actor": details.get("owner_actor") or item.get("owner_actor") or "",
        "peer_actor": details.get("peer_actor") or item.get("peer_actor") or "",
        "object_ref": item.get("object_ref") or "",
        "object_type": obj.get("type", ""),
        "required_evidence": item.get("required_evidence") or [
            "owner session",
            "peer session",
            "owner private marker",
        ],
        "missing_evidence": missing,
        "command": command,
        "redacted_command": redacted_command,
        "downgrade_rule": "peer denied or response lacks owner-private marker",
        "stop_condition": item.get("stop_condition") or "peer 403/404 or no owner-private marker",
        "chain_extensions_if_blocked": extensions,
        "write_back": f"complete-backlog {item.get('id')} with tested_finding/tested_clean/candidate",
    }


def complete_backlog(
    repo_root: str | Path,
    target: str,
    *,
    backlog_id: str,
    result: str,
    evidence_ref: str = "",
    notes: str = "",
) -> dict[str, Any]:
    if result not in BACKLOG_STATUSES:
        raise ValueError(f"unknown result/status: {result}")
    state = load_case_state(repo_root, target)
    for item in state.get("validation_backlog", []):
        if item.get("id") == backlog_id:
            item["status"] = result
            item["evidence_ref"] = str(evidence_ref or item.get("evidence_ref", "") or "")
            item["notes"] = str(notes or item.get("notes", "") or "")
            item["completed_at"] = now_utc()
            save_case_state(repo_root, target, state)
            return item
    raise ValueError(f"backlog id not found: {backlog_id}")


def summary(repo_root: str | Path, target: str) -> dict[str, Any]:
    state = load_case_state(repo_root, target)
    next_item = next_action(repo_root, target)
    pending = [
        item for item in state.get("validation_backlog", [])
        if str(item.get("status") or "pending") in ACTIVE_BACKLOG_STATUSES
    ]
    return {
        "target": state.get("target"),
        "target_key": state.get("target_key"),
        "actors": len(state.get("actors", {})),
        "sessions": len(state.get("sessions", {})),
        "objects": len(state.get("objects", {})),
        "open_hypotheses": len([h for h in state.get("hypotheses", []) if h.get("status") == "open"]),
        "pending_validation_backlog": len(pending),
        "top_next_action": next_item,
    }


def _print_json(payload: Any) -> None:
    print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))


def _print_summary(payload: dict[str, Any]) -> None:
    print(f"Target: {payload.get('target')}")
    print(f"Actors: {payload.get('actors', 0)}")
    print(f"Sessions: {payload.get('sessions', 0)}")
    print(f"Objects: {payload.get('objects', 0)}")
    print(f"Open hypotheses: {payload.get('open_hypotheses', 0)}")
    print(f"Pending validation backlog: {payload.get('pending_validation_backlog', 0)}")
    top = payload.get("top_next_action") or {}
    if top.get("next_action") != "none":
        print(f"Top next action: {top.get('runner') or top.get('next_action')} {top.get('object_ref', '')} {top.get('owner_actor', '')} -> {top.get('peer_actor', '')}".strip())
        if top.get("redacted_command"):
            print(f"Replay draft: {top.get('redacted_command')}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Manage target-scoped actor/session/object validation state")
    sub = parser.add_subparsers(dest="cmd", required=True)

    def common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--target", required=True)
        p.add_argument("--repo-root", default=str(BASE_DIR))

    p = sub.add_parser("summary")
    common(p)
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("add-actor")
    common(p)
    p.add_argument("--actor", required=True)
    p.add_argument("--role", default="unknown")
    p.add_argument("--label", default="")
    p.add_argument("--notes", default="")

    p = sub.add_parser("add-session")
    common(p)
    p.add_argument("--session", required=True)
    p.add_argument("--actor", required=True)
    p.add_argument("--kind", default="unknown")
    p.add_argument("--header-name", default="")
    p.add_argument("--header-value", default="")
    p.add_argument("--source", default="manual")
    p.add_argument("--validity", default="unknown")
    p.add_argument("--notes", default="")

    p = sub.add_parser("add-object")
    common(p)
    p.add_argument("--object", required=True)
    p.add_argument("--type", required=True)
    p.add_argument("--object-id", default="")
    p.add_argument("--owner-actor", default="")
    p.add_argument("--endpoint", default="")
    p.add_argument("--private-marker", default="")
    p.add_argument("--status", default="active")
    p.add_argument("--notes", default="")

    p = sub.add_parser("add-hypothesis")
    common(p)
    p.add_argument("--id", default="")
    p.add_argument("--vuln-class", required=True)
    p.add_argument("--endpoint", default="")
    p.add_argument("--object-ref", default="")
    p.add_argument("--actor", action="append", default=[])
    p.add_argument("--why-now", default="")
    p.add_argument("--next-action", default="")
    p.add_argument("--status", default="open")

    p = sub.add_parser("add-backlog")
    common(p)
    p.add_argument("--id", default="")
    p.add_argument("--runner", required=True)
    p.add_argument("--endpoint", default="")
    p.add_argument("--owner-actor", default="")
    p.add_argument("--peer-actor", default="")
    p.add_argument("--object-ref", default="")
    p.add_argument("--priority", default="medium")
    p.add_argument("--required-evidence", action="append", default=[])
    p.add_argument("--stop-condition", default="")
    p.add_argument("--chain-extension", action="append", default=[])
    p.add_argument("--status", default="pending")

    p = sub.add_parser("next")
    common(p)

    p = sub.add_parser("complete-backlog")
    common(p)
    p.add_argument("--id", required=True)
    p.add_argument("--result", required=True)
    p.add_argument("--evidence-ref", default="")
    p.add_argument("--notes", default="")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    repo_root = Path(args.repo_root)
    if args.cmd == "summary":
        payload = summary(repo_root, args.target)
        _print_json(payload) if args.json else _print_summary(payload)
    elif args.cmd == "add-actor":
        _print_json(add_actor(repo_root, args.target, actor=args.actor, role=args.role, label=args.label, notes=args.notes))
    elif args.cmd == "add-session":
        _print_json(add_session(
            repo_root,
            args.target,
            session=args.session,
            actor=args.actor,
            kind=args.kind,
            header_name=args.header_name,
            header_value=args.header_value,
            source=args.source,
            validity=args.validity,
            notes=args.notes,
        ))
    elif args.cmd == "add-object":
        _print_json(add_object(
            repo_root,
            args.target,
            object_ref=args.object,
            object_type=args.type,
            object_id=args.object_id,
            owner_actor=args.owner_actor,
            endpoint=args.endpoint,
            private_marker=args.private_marker,
            status=args.status,
            notes=args.notes,
        ))
    elif args.cmd == "add-hypothesis":
        _print_json(add_hypothesis(
            repo_root,
            args.target,
            hypothesis_id=args.id,
            vuln_class=args.vuln_class,
            endpoint=args.endpoint,
            object_ref=args.object_ref,
            actors=args.actor,
            why_now=args.why_now,
            next_action=args.next_action,
            status=args.status,
        ))
    elif args.cmd == "add-backlog":
        _print_json(add_backlog(
            repo_root,
            args.target,
            backlog_id=args.id,
            runner=args.runner,
            endpoint=args.endpoint,
            owner_actor=args.owner_actor,
            peer_actor=args.peer_actor,
            object_ref=args.object_ref,
            priority=args.priority,
            required_evidence=args.required_evidence,
            stop_condition=args.stop_condition,
            chain_extensions_if_blocked=args.chain_extension,
            status=args.status,
        ))
    elif args.cmd == "next":
        _print_json(next_action(repo_root, args.target))
    elif args.cmd == "complete-backlog":
        _print_json(complete_backlog(
            repo_root,
            args.target,
            backlog_id=args.id,
            result=args.result,
            evidence_ref=args.evidence_ref,
            notes=args.notes,
        ))
    else:  # pragma: no cover - argparse guards this
        raise ValueError(f"unknown command: {args.cmd}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
