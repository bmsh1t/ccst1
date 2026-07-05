#!/usr/bin/env python3
"""Suggest Target Case State seeds from existing recon/browser/source artifacts.

This tool is suggestion-only by default: it reads cached artifacts, extracts
concrete object-shaped endpoints, and emits copyable `target_case_state.py`
commands.  It does not write runtime state unless a future explicit apply mode
is added.
"""

from __future__ import annotations

import argparse
import json
import re
import shlex
import sys
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, unquote, urlparse

BASE_DIR = Path(__file__).resolve().parents[1]
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

try:
    from tools.target_case_state import load_case_state
    from tools.target_paths import canonical_target_value, target_storage_key
except ImportError:  # pragma: no cover - direct tools/ execution
    from target_case_state import load_case_state  # type: ignore
    from target_paths import canonical_target_value, target_storage_key  # type: ignore


OBJECT_TOKEN_MAP = {
    "order": "order",
    "orders": "order",
    "order-history": "order",
    "order_history": "order",
    "track-order": "order",
    "track_order": "order",
    "invoice": "invoice",
    "invoices": "invoice",
    "address": "address",
    "addresses": "address",
    "report": "report",
    "reports": "report",
    "export": "export",
    "exports": "export",
    "download": "export",
    "downloads": "export",
    "user": "user",
    "users": "user",
    "account": "account",
    "accounts": "account",
    "org": "organization",
    "orgs": "organization",
    "organization": "organization",
    "organizations": "organization",
    "tenant": "tenant",
    "tenants": "tenant",
    "workspace": "workspace",
    "workspaces": "workspace",
    "file": "file",
    "files": "file",
    "cart": "cart",
    "carts": "cart",
    "basket": "basket",
    "baskets": "basket",
    "payment": "payment",
    "payments": "payment",
    "billing": "billing",
}

JSON_OBJECT_FIELD_TYPES = {
    "address-id": "address",
    "basket-id": "basket",
    "cart-id": "cart",
    "invoice-id": "invoice",
    "order-confirmation": "order",
    "order-id": "order",
    "payment-id": "payment",
    "report-id": "report",
    "user-id": "user",
}

HIGH_PRIORITY_TYPES = {
    "order",
    "invoice",
    "address",
    "report",
    "export",
    "organization",
    "tenant",
    "workspace",
    "payment",
    "billing",
    "file",
}

GENERIC_ID_KEYS = {"id", "uuid", "guid"}
NON_OBJECT_QUERY_KEYS = {
    "_",
    "cachebuster",
    "csrf",
    "csrf_token",
    "eio",
    "jwt",
    "nonce",
    "refresh_token",
    "session",
    "session_id",
    "sessionid",
    "sid",
    "t",
    "timestamp",
    "token",
    "transport",
}
NON_OBJECT_ID_STEMS = {"s", "sid", "session", "csrf", "token", "jwt"}
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,80}$")
NUMERIC_OR_UUID_RE = re.compile(
    r"^(?:\d{1,12}|[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}|[0-9a-fA-F]{16,64})$"
)


def _quote(value: Any) -> str:
    return shlex.quote(str(value or ""))


def _read_lines(path: Path) -> list[str]:
    if not path.is_file():
        return []
    try:
        return [
            line.strip()
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
            if line.strip()
        ]
    except OSError:
        return []


def _load_json(path: Path) -> Any:
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _dedupe_by_key(items: list[dict[str, Any]], key: str) -> list[dict[str, Any]]:
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for item in items:
        value = str(item.get(key) or "").strip()
        if not value or value in seen:
            continue
        seen.add(value)
        out.append(item)
    return out


def _dedupe_objects(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Dedupe object suggestions while preserving richer evidence fields."""
    merged: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for item in items:
        ref = str(item.get("object_ref") or "").strip()
        if not ref:
            continue
        current = merged.get(ref)
        if current is None:
            merged[ref] = dict(item)
            order.append(ref)
            continue
        # Prefer candidates with concrete endpoints/private markers/sources.
        for field in ("endpoint", "private_marker", "source"):
            if not current.get(field) and item.get(field):
                current[field] = item[field]
        if item.get("reason") and item["reason"] not in str(current.get("reason") or ""):
            current["reason"] = f"{current.get('reason', '')}; {item['reason']}".strip("; ")
    return [merged[ref] for ref in order]


def _default_host(target: str) -> str:
    value = canonical_target_value(target)
    if value.startswith(("http://", "https://")):
        return value.rstrip("/")
    return f"https://{value}".rstrip("/")


def _endpoint_to_url(endpoint: str, target: str) -> str:
    value = str(endpoint or "").strip()
    if not value:
        return ""
    if value.startswith(("http://", "https://", "ws://", "wss://")):
        return value
    if not value.startswith("/"):
        value = "/" + value
    return _default_host(target) + value


def _artifact_url_from_line(line: str) -> str:
    value = str(line or "").strip()
    if not value:
        return ""
    # browser_params.txt stores: "<url> :: <param>"
    if " :: " in value:
        value = value.split(" :: ", 1)[0].strip()
    return value


def _source_artifact(path: Path, repo_root: Path) -> str:
    try:
        return str(path.relative_to(repo_root))
    except ValueError:
        return str(path)


def collect_artifact_endpoints(repo_root: str | Path, target: str) -> list[dict[str, str]]:
    """Collect endpoint strings from recon/browser/js/source artifacts."""
    repo = Path(repo_root)
    resolved = canonical_target_value(target)
    key = target_storage_key(resolved)
    endpoints: list[dict[str, str]] = []

    line_sources = [
        repo / "recon" / key / "browser" / "xhr_endpoints.txt",
        repo / "recon" / key / "browser" / "api_endpoints.txt",
        repo / "recon" / key / "browser" / "browser_params.txt",
        repo / "recon" / key / "urls" / "api_endpoints.txt",
        repo / "recon" / key / "urls" / "with_params.txt",
        repo / "recon" / key / "urls" / "all.txt",
    ]
    for path in line_sources:
        for line in _read_lines(path):
            url = _artifact_url_from_line(line)
            if url:
                endpoints.append({
                    "endpoint": _endpoint_to_url(url, resolved),
                    "source": _source_artifact(path, repo),
                })

    js_path = repo / "findings" / key / "js_intel" / "hypotheses.json"
    js_payload = _load_json(js_path)
    if isinstance(js_payload, dict):
        for item in js_payload.get("endpoints", []) or []:
            if isinstance(item, dict) and item.get("path"):
                endpoints.append({
                    "endpoint": _endpoint_to_url(str(item.get("path")), resolved),
                    "source": _source_artifact(js_path, repo),
                })

    routes_path = repo / "findings" / key / "source_intel" / "routes.json"
    routes_payload = _load_json(routes_path)
    if isinstance(routes_payload, dict):
        for item in routes_payload.get("routes", []) or []:
            if isinstance(item, dict) and item.get("route"):
                endpoints.append({
                    "endpoint": _endpoint_to_url(str(item.get("route")), resolved),
                    "source": _source_artifact(routes_path, repo),
                })

    hypotheses_path = repo / "findings" / key / "source_intel" / "hypotheses.jsonl"
    for line in _read_lines(hypotheses_path):
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict) and item.get("candidate"):
            endpoints.append({
                "endpoint": _endpoint_to_url(str(item.get("candidate")), resolved),
                "source": _source_artifact(hypotheses_path, repo),
            })

    return _dedupe_by_key(endpoints, "endpoint")


def _object_type_from_token(token: str) -> str:
    normalized = str(token or "").strip().lower().replace("_", "-")
    if normalized in OBJECT_TOKEN_MAP:
        return OBJECT_TOKEN_MAP[normalized]
    for suffix in ("id", "-id", "_id"):
        if normalized.endswith(suffix) and len(normalized) > len(suffix):
            stem = normalized[: -len(suffix)].strip("-_")
            if len(stem) < 3 or stem in NON_OBJECT_ID_STEMS:
                return ""
            return OBJECT_TOKEN_MAP.get(stem, stem)
    return ""


def _normalise_json_key(key: str) -> str:
    """Normalize JSON field names such as orderId / order_id / order-id."""
    value = re.sub(r"([a-z0-9])([A-Z])", r"\1-\2", str(key or ""))
    value = re.sub(r"[^A-Za-z0-9]+", "-", value).strip("-").lower()
    return value


def _object_type_from_json_key(key: str) -> str:
    normalized = _normalise_json_key(key)
    if normalized in JSON_OBJECT_FIELD_TYPES:
        return JSON_OBJECT_FIELD_TYPES[normalized]
    return _object_type_from_token(normalized)


def _safe_id(value: str) -> str:
    raw = str(value or "").strip().strip("{}[]()'\"")
    if not raw or raw.startswith(":") or raw.startswith("<"):
        return ""
    if not ID_RE.match(raw):
        return ""
    # Concrete IDs are useful; broad words from routes are not.
    if not NUMERIC_OR_UUID_RE.match(raw) and not re.search(r"\d", raw):
        return ""
    return raw


def _object_ref(object_type: str, object_id: str) -> str:
    safe_type = re.sub(r"[^A-Za-z0-9_]+", "_", object_type).strip("_") or "object"
    safe_id = re.sub(r"[^A-Za-z0-9_.:-]+", "_", object_id).strip("._:-") or "unknown"
    return f"{safe_type}_{safe_id}"


def _endpoint_has_exact_object_id(endpoint: str, object_id: str) -> bool:
    """Return True only when the ID is an exact path segment or query value."""
    parsed = urlparse(endpoint)
    expected = str(object_id or "")
    if not expected:
        return False
    segments = [unquote(part) for part in parsed.path.split("/") if part]
    if expected in segments:
        return True
    for _, value in parse_qsl(parsed.query, keep_blank_values=True):
        if unquote(str(value)) == expected:
            return True
    return False


def _endpoint_has_object_type_hint(endpoint: str, object_type: str) -> bool:
    """Check whether path/query names point to the same object type.

    This keeps JSON-derived IDs from being attached to unrelated endpoints that
    merely contain the same short number somewhere in the URL.
    """
    expected = str(object_type or "").strip().lower()
    if not expected:
        return True
    parsed = urlparse(endpoint)
    path_segments = [unquote(part) for part in parsed.path.split("/") if part]
    for segment in path_segments:
        if _object_type_from_token(segment) == expected:
            return True
    for key, _ in parse_qsl(parsed.query, keep_blank_values=True):
        if _object_type_from_json_key(key) == expected:
            return True
        if key.strip().lower() in GENERIC_ID_KEYS and path_segments:
            if _object_type_from_token(path_segments[-1]) == expected:
                return True
    return False


def _match_endpoint_for_object(object_type: str, object_id: str, endpoints: list[dict[str, str]]) -> str:
    """Find an observed object-specific endpoint for a JSON-derived object.

    Matching intentionally avoids substring fallbacks. Short numeric IDs such as
    `7` are common across a target, so endpoint binding requires the ID as an
    exact path segment/query value plus an object-type hint in path/query names.
    """
    if not str(object_id or "").strip():
        return ""
    for item in endpoints:
        endpoint = str(item.get("endpoint") or "")
        if _endpoint_has_exact_object_id(endpoint, str(object_id)):
            if _endpoint_has_object_type_hint(endpoint, object_type):
                return endpoint
            # Exact short IDs are still ambiguous without a typed path/query.
            continue
    return ""


def _json_object_candidates(
    payload: Any,
    *,
    source: str,
    endpoints: list[dict[str, str]],
    path: tuple[str, ...] = (),
) -> list[dict[str, Any]]:
    """Extract concrete object IDs from cached JSON artifacts.

    JSON artifacts often contain owner-observed object fields that URLs alone
    cannot expose, for example `orderId`, `addressId`, or checkout confirmation
    fields. This parser is intentionally conservative: it only accepts concrete
    scalar IDs and only attaches an endpoint if that endpoint was observed
    elsewhere in recon/browser artifacts.
    """
    candidates: list[dict[str, Any]] = []
    if isinstance(payload, dict):
        for key, value in payload.items():
            current_path = (*path, str(key))
            object_type = _object_type_from_json_key(str(key))
            if object_type and not isinstance(value, (dict, list)):
                object_id = _safe_id(str(value))
                if object_id:
                    candidates.append({
                        "object_ref": _object_ref(object_type, object_id),
                        "type": object_type,
                        "object_id": object_id,
                        "endpoint": _match_endpoint_for_object(object_type, object_id, endpoints),
                        "private_marker": object_id,
                        "confidence": "medium",
                        "reason": "json field {!r} carries concrete {} id {!r}".format(
                            ".".join(current_path),
                            object_type,
                            object_id,
                        ),
                        "source": source,
                    })
            candidates.extend(
                _json_object_candidates(value, source=source, endpoints=endpoints, path=current_path)
            )
    elif isinstance(payload, list):
        for index, value in enumerate(payload):
            candidates.extend(
                _json_object_candidates(value, source=source, endpoints=endpoints, path=(*path, str(index)))
            )
    return candidates


def collect_json_object_candidates(
    repo_root: str | Path,
    target: str,
    endpoints: list[dict[str, str]],
) -> list[dict[str, Any]]:
    """Collect object candidates from cached browser JSON artifacts."""
    repo = Path(repo_root)
    resolved = canonical_target_value(target)
    key = target_storage_key(resolved)
    browser_dir = repo / "recon" / key / "browser"
    candidates: list[dict[str, Any]] = []
    if not browser_dir.is_dir():
        return candidates
    for path in sorted(browser_dir.glob("*.json")):
        payload = _load_json(path)
        if payload in ({}, []):
            continue
        candidates.extend(
            _json_object_candidates(
                payload,
                source=_source_artifact(path, repo),
                endpoints=endpoints,
            )
        )
    return _dedupe_objects(candidates)


def object_candidates_from_endpoint(endpoint: str, source: str = "") -> list[dict[str, Any]]:
    """Extract concrete object candidates from one endpoint."""
    parsed = urlparse(endpoint)
    segments = [part for part in parsed.path.split("/") if part]
    candidates: list[dict[str, Any]] = []

    for index, segment in enumerate(segments):
        object_type = _object_type_from_token(segment)
        if not object_type:
            continue
        nearby_values = []
        if index + 1 < len(segments):
            nearby_values.append(segments[index + 1])
        if index > 0:
            nearby_values.append(segments[index - 1])
        for raw_id in nearby_values:
            object_id = _safe_id(raw_id)
            if not object_id:
                continue
            candidates.append({
                "object_ref": _object_ref(object_type, object_id),
                "type": object_type,
                "object_id": object_id,
                "endpoint": endpoint,
                "confidence": "high",
                "reason": f"path segment {segment!r} is adjacent to concrete object id {object_id!r}",
                "source": source,
            })

    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        if key.strip().lower() in NON_OBJECT_QUERY_KEYS:
            continue
        object_type = _object_type_from_token(key)
        object_id = _safe_id(value)
        if not object_type or not object_id:
            continue
        if key.lower() in GENERIC_ID_KEYS and segments:
            object_type = _object_type_from_token(segments[-1]) or object_type
        candidates.append({
            "object_ref": _object_ref(object_type, object_id),
            "type": object_type,
            "object_id": object_id,
            "endpoint": endpoint,
            "confidence": "high",
            "reason": f"query parameter {key!r} carries concrete object id {object_id!r}",
            "source": source,
        })

    return _dedupe_by_key(candidates, "object_ref")


def _existing_actor_ids(state: dict[str, Any]) -> set[str]:
    actors = state.get("actors") if isinstance(state.get("actors"), dict) else {}
    return {str(actor_id) for actor_id in actors.keys()}


def _existing_session_actors(state: dict[str, Any]) -> set[str]:
    sessions = state.get("sessions") if isinstance(state.get("sessions"), dict) else {}
    actors: set[str] = set()
    for session in sessions.values():
        headers = session.get("headers") if isinstance(session, dict) and isinstance(session.get("headers"), dict) else {}
        has_header = bool(headers) or bool(isinstance(session, dict) and session.get("header_value"))
        if isinstance(session, dict) and session.get("actor") and has_header:
            actors.add(str(session.get("actor")))
    return actors


def _existing_object_refs(state: dict[str, Any]) -> set[str]:
    objects = state.get("objects") if isinstance(state.get("objects"), dict) else {}
    return {str(object_ref) for object_ref in objects.keys()}


def _existing_backlog_keys(state: dict[str, Any]) -> set[tuple[str, str]]:
    keys: set[tuple[str, str]] = set()
    for item in state.get("validation_backlog", []) or []:
        if not isinstance(item, dict):
            continue
        keys.add((str(item.get("runner") or ""), str(item.get("object_ref") or "")))
    return keys


def _actor_suggestions(state: dict[str, Any], has_object_candidates: bool) -> list[dict[str, str]]:
    if not has_object_candidates:
        return []
    existing = _existing_actor_ids(state)
    suggestions = []
    if "user_a" not in existing:
        suggestions.append({"actor": "user_a", "role": "user", "label": "owner account candidate"})
    if "user_b" not in existing:
        suggestions.append({"actor": "user_b", "role": "user", "label": "peer account candidate"})
    return suggestions


def _actor_command(target: str, actor: dict[str, str]) -> str:
    return " ".join([
        "python3",
        "tools/target_case_state.py",
        "add-actor",
        "--target",
        _quote(target),
        "--actor",
        _quote(actor.get("actor", "")),
        "--role",
        _quote(actor.get("role", "user")),
        "--label",
        _quote(actor.get("label", "")),
    ])


def _object_command(target: str, item: dict[str, Any], owner_actor: str) -> str:
    parts = [
        "python3",
        "tools/target_case_state.py",
        "add-object",
        "--target",
        _quote(target),
        "--object",
        _quote(item.get("object_ref", "")),
        "--type",
        _quote(item.get("type", "")),
        "--object-id",
        _quote(item.get("object_id", "")),
        "--endpoint",
        _quote(item.get("endpoint", "")),
    ]
    if owner_actor:
        parts.extend(["--owner-actor", _quote(owner_actor)])
    if item.get("private_marker"):
        parts.extend(["--private-marker", _quote(item.get("private_marker", ""))])
    return " ".join(parts)


def _backlog_command(target: str, item: dict[str, Any], owner_actor: str, peer_actor: str) -> str:
    priority = str(item.get("priority") or ("high" if item.get("type") in HIGH_PRIORITY_TYPES else "medium"))
    return " ".join([
        "python3",
        "tools/target_case_state.py",
        "add-backlog",
        "--target",
        _quote(target),
        "--runner",
        "idor-actor-pair",
        "--owner-actor",
        _quote(owner_actor),
        "--peer-actor",
        _quote(peer_actor),
        "--object-ref",
        _quote(item.get("object_ref", "")),
        "--priority",
        _quote(priority),
        "--required-evidence",
        _quote("owner session"),
        "--required-evidence",
        _quote("peer session"),
        "--required-evidence",
        _quote("owner private marker"),
        "--stop-condition",
        _quote("peer 403/404 or no owner-private marker"),
        "--chain-extension",
        _quote("try export/report/mobile/API sibling for the same object"),
    ])


def build_case_state_seed(repo_root: str | Path, target: str, *, limit: int = 8) -> dict[str, Any]:
    """Build suggestion-only case_state seed payload."""
    repo = Path(repo_root)
    resolved = canonical_target_value(target)
    state = load_case_state(repo, resolved)
    endpoints = collect_artifact_endpoints(repo, resolved)

    object_candidates: list[dict[str, Any]] = []
    for item in endpoints:
        object_candidates.extend(
            object_candidates_from_endpoint(item["endpoint"], source=item.get("source", ""))
        )
    object_candidates.extend(collect_json_object_candidates(repo, resolved, endpoints))
    object_candidates = _dedupe_objects(object_candidates)

    existing_objects = _existing_object_refs(state)
    object_candidates = [
        item for item in object_candidates
        if str(item.get("object_ref") or "") not in existing_objects
    ][:limit]

    actor_suggestions = _actor_suggestions(state, bool(object_candidates))
    existing_actors = _existing_actor_ids(state)
    session_actors = _existing_session_actors(state)
    owner_actor = "user_a" if ("user_a" in existing_actors or actor_suggestions) else ""
    peer_actor = "user_b" if ("user_b" in existing_actors or actor_suggestions) else ""
    existing_backlogs = _existing_backlog_keys(state)

    backlog_candidates = []
    for item in object_candidates:
        object_ref = str(item.get("object_ref") or "")
        if ("idor-actor-pair", object_ref) in existing_backlogs:
            continue
        missing = []
        if not owner_actor:
            missing.append("owner actor")
        if owner_actor and owner_actor not in session_actors:
            missing.append("owner session")
        if not peer_actor:
            missing.append("peer actor")
        if peer_actor and peer_actor not in session_actors:
            missing.append("peer session")
        if not item.get("endpoint"):
            missing.append("object endpoint")
        if not item.get("private_marker"):
            missing.append("owner private marker")
        backlog_candidates.append({
            "runner": "idor-actor-pair",
            "owner_actor": owner_actor or "user_a",
            "peer_actor": peer_actor or "user_b",
            "object_ref": object_ref,
            "priority": "high" if item.get("type") in HIGH_PRIORITY_TYPES else "medium",
            "missing": list(dict.fromkeys(missing)),
            "reason": f"{item.get('type')} object candidate from {item.get('source') or 'cached artifact'}",
        })

    commands = []
    for actor in actor_suggestions:
        commands.append(_actor_command(resolved, actor))
    for item in object_candidates:
        commands.append(_object_command(resolved, item, owner_actor or "user_a"))
    for item in backlog_candidates:
        commands.append(_backlog_command(resolved, item, item["owner_actor"], item["peer_actor"]))

    return {
        "target": resolved,
        "target_key": target_storage_key(resolved),
        "status": "suggestions" if (object_candidates or backlog_candidates or actor_suggestions) else "no_seed_candidates",
        "artifact_endpoints": len(endpoints),
        "suggested_actors": actor_suggestions,
        "suggested_objects": object_candidates,
        "suggested_backlog": backlog_candidates,
        "commands": commands,
        "notes": [
            "Suggestion-only output; review commands before applying.",
            "Private markers and real sessions must come from observed owner-controlled evidence.",
        ],
    }


def format_seed(payload: dict[str, Any]) -> str:
    lines = [
        "CASE STATE SEED SUGGESTIONS",
        f"- Target: {payload.get('target', '')}",
        f"- Status: {payload.get('status', '')}",
        f"- Artifact endpoints reviewed: {payload.get('artifact_endpoints', 0)}",
        "- Suggested objects:",
    ]
    objects = payload.get("suggested_objects") or []
    if not objects:
        lines.append("  - none")
    for item in objects:
        lines.append(
            "  - {ref} type={typ} endpoint={endpoint} reason={reason}".format(
                ref=item.get("object_ref", ""),
                typ=item.get("type", ""),
                endpoint=item.get("endpoint", ""),
                reason=item.get("reason", ""),
            )
        )
    lines.append("- Suggested backlog:")
    backlog = payload.get("suggested_backlog") or []
    if not backlog:
        lines.append("  - none")
    for item in backlog:
        missing = ", ".join(item.get("missing") or [])
        lines.append(
            "  - {runner} object={object_ref} owner={owner} peer={peer} missing={missing}".format(
                runner=item.get("runner", ""),
                object_ref=item.get("object_ref", ""),
                owner=item.get("owner_actor", ""),
                peer=item.get("peer_actor", ""),
                missing=missing or "-",
            )
        )
    lines.append("- Commands:")
    commands = payload.get("commands") or []
    if not commands:
        lines.append("  - none")
    for command in commands:
        lines.append(f"  - {command}")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Suggest target_case_state seeds from cached artifacts.")
    parser.add_argument("--target", required=True)
    parser.add_argument("--repo-root", default=str(BASE_DIR))
    parser.add_argument("--limit", type=int, default=8)
    parser.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    payload = build_case_state_seed(args.repo_root, args.target, limit=max(1, args.limit))
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(format_seed(payload))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
