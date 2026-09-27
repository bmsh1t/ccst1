#!/usr/bin/env python3
"""Target-scoped actor/session/object context for high-value validation.

Target Case State is runtime memory, not knowledge and not a queue.  It records
which test actors, sessions, objects, private markers and hypotheses exist for
one target.  Actions -- their identity, claim and execution state -- live in the
one action source; Case never copies them into a second backlog and never ranks
them, because the route decision belongs to Claude, not to a stored score.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parents[1]
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

try:
    from tools.action_queue import SENSITIVE_OBSERVATION_VALUE_RE
    from tools.auth_session import AuthSession
    from tools.private_artifacts import private_artifact_dir, write_private_json
    from tools.target_paths import canonical_target_value, target_storage_key
    from tools.target_store import _identifier, _text, runtime_store
except ImportError:  # pragma: no cover - direct tools/ execution
    from action_queue import SENSITIVE_OBSERVATION_VALUE_RE  # type: ignore
    from auth_session import AuthSession  # type: ignore
    from private_artifacts import private_artifact_dir, write_private_json  # type: ignore
    from target_paths import canonical_target_value, target_storage_key  # type: ignore
    from target_store import _identifier, _text, runtime_store  # type: ignore


SCHEMA_VERSION = 1
SESSION_KINDS = {"cookie", "bearer", "browser_state", "api_key", "custom_header", "unknown"}
ACTOR_ROLES = {"anonymous", "user", "low_role", "admin_like", "service", "unknown"}

_SENSITIVE_METADATA_PARTS = {
    "access_key", "access_token", "api_key", "apikey", "auth", "authorization", "bearer",
    "client_secret", "cookie", "credential", "credentials", "csrf_token", "header",
    "header_value", "headers", "id_token", "jwt", "nonce", "otp", "password", "private",
    "private_key", "private_marker", "refresh_token", "secret", "secret_key", "secret_value",
    "session", "session_cookie", "session_id", "set_cookie", "token", "verification_code",
}
_SAFE_TOKEN_METADATA_KEYS = {
    "token_algorithm", "token_audience", "token_binding", "token_claim", "token_issuer",
    "token_location", "token_type",
}


def _sensitive_metadata_key(key: str) -> bool:
    value = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(key or ""))
    normalized = re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")
    if normalized in _SENSITIVE_METADATA_PARTS:
        return True
    if normalized.startswith((
        "authorization_", "bearer_", "cookie_", "credential_", "credentials_",
        "password_", "secret_", "session_",
    )):
        return True
    if normalized.startswith("token_") and normalized not in _SAFE_TOKEN_METADATA_KEYS:
        return True
    if normalized.endswith((
        "_access_token", "_api_key", "_client_secret", "_cookie", "_credential",
        "_credentials", "_header_value", "_id_token", "_password", "_private_key",
        "_refresh_token", "_secret", "_secret_key", "_session_cookie", "_token",
    )):
        return True
    parts = set(normalized.split("_"))
    if normalized.endswith(("_header", "_headers")) and parts.intersection({
        "auth", "authorization", "bearer", "cookie", "credential", "session", "token",
    }):
        return True
    return normalized.endswith("_key") and bool(parts.intersection({
        "access", "api", "client", "encryption", "private", "secret", "signing",
    }))


def _validate_hypothesis_metadata(metadata: dict[str, Any] | None) -> dict[str, Any]:
    if metadata is None:
        return {}
    if not isinstance(metadata, dict):
        raise ValueError("hypothesis metadata must be a JSON object")

    def visit(value: Any, path: str) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                child_path = f"{path}.{key}"
                if _sensitive_metadata_key(str(key)) and child not in (None, "", [], {}):
                    raise ValueError(f"hypothesis metadata cannot contain sensitive field {child_path}")
                visit(child, child_path)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, f"{path}[{index}]")
        elif isinstance(value, str) and SENSITIVE_OBSERVATION_VALUE_RE.search(value):
            raise ValueError(
                f"hypothesis metadata cannot contain credential-bearing value at {path}"
            )

    visit(metadata, "metadata")
    return metadata


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def case_state_path(repo_root: str | Path, target: str) -> Path:
    resolved = canonical_target_value(target)
    return Path(repo_root) / "state" / target_storage_key(resolved) / "case_state.json"


def _private_digest(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _case_command_id(kind: str, entity_id: str, material: dict[str, Any], revision: int) -> str:
    """Repeated material transitions at later revisions are new mutations."""
    return f"{kind}:{entity_id}:at-{revision}:to-{_private_digest(material)[:16]}"


def _same_case_material(store, previous: dict | None, material: dict) -> bool:
    """Compare the material as the Store persists and projects it."""
    normalized = {}
    for field, value in material.items():
        if field == "actors":
            normalized[field] = sorted(_identifier(item, "actor_id") for item in value)
        elif field == "metadata":
            normalized[field] = json.loads(json.dumps(value, sort_keys=True, allow_nan=False))
        elif field == "endpoint" and value:
            normalized[field] = store._endpoint(value)
        else:
            normalized[field] = _text(value, field, empty=True)
    return previous is not None and _private_digest(previous) == _private_digest(normalized)


def _object_private_path(repo_root: str | Path, target: str, object_ref: str, digest: str) -> Path:
    directory = private_artifact_dir(repo_root, "case-state", target_storage_key(canonical_target_value(target)), "objects")
    object_digest = hashlib.sha256(object_ref.encode("utf-8")).hexdigest()[:20]
    return directory / f"{object_digest}-{digest[:16]}.json"


def _session_private_path(
    repo_root: str | Path,
    target: str,
    session_id: str,
    content_digest: str = "",
) -> Path:
    target_key = target_storage_key(canonical_target_value(target))
    directory = private_artifact_dir(repo_root, "case-state", target_key, "sessions")
    session_digest = hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:20]
    suffix = f"-{content_digest[:16]}" if content_digest else ""
    return directory / f"{session_digest}{suffix}.json"


def _load_private_session(
    repo_root: str | Path,
    target: str,
    session_id: str,
    session: dict[str, Any],
) -> None:
    ref = str(session.get("private_ref") or "").strip()
    if not ref:
        return
    expected = _session_private_path(repo_root, target, session_id)
    path = Path(repo_root) / ref
    if path.resolve().parent != expected.resolve().parent or not path.name.startswith(expected.stem + "-"):
        raise ValueError(f"invalid case-state private_ref for session {session_id}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"unable to read private case-state session {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid private case-state session JSON {path}: {exc.msg}") from exc
    if not isinstance(payload, dict) or payload.get("session_id") != session_id:
        raise ValueError(f"private case-state session identity mismatch: {path}")
    if payload.get("schema_version") != SCHEMA_VERSION or payload.get("target") != canonical_target_value(target):
        raise ValueError(f"private case-state session metadata mismatch: {path}")
    if payload.get("actor") != str(session.get("actor") or "") or payload.get("kind") != str(session.get("kind") or "unknown"):
        raise ValueError(f"private case-state session owner mismatch: {path}")
    digest = payload.get("content_sha256")
    unsigned = dict(payload)
    unsigned.pop("content_sha256", None)
    if not isinstance(digest, str) or _private_digest(unsigned) != digest or not path.name.endswith(f"-{digest[:16]}.json"):
        raise ValueError(f"private case-state session digest mismatch: {path}")
    headers = payload.get("headers") if isinstance(payload.get("headers"), dict) else {}
    session["headers"] = _normalize_headers({str(k): str(v) for k, v in headers.items()})
    session["header_name"], session["header_value"] = next(iter(session["headers"].items()), ("", ""))


def load_case_state(repo_root: str | Path, target: str) -> dict[str, Any]:
    store = runtime_store(repo_root, target)
    state = store.case_state()
    for session_id, session in state.get("sessions", {}).items():
        if isinstance(session, dict):
            _load_private_session(repo_root, target, str(session_id), session)
    return state


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


def _normalize_headers(headers: dict[str, str] | None) -> dict[str, str]:
    """Normalize a header map through AuthSession so CR/LF and malformed names fail fast."""
    session = AuthSession()
    for name, value in (headers or {}).items():
        if str(name or "").strip() and str(value or "").strip():
            session.add_header(f"{name}: {value}")
    return session.headers_dict()


def _infer_session_kind(kind: str, headers: dict[str, str]) -> str:
    explicit = str(kind or "unknown").strip() or "unknown"
    if explicit != "unknown":
        return explicit
    names = {name.lower() for name in headers}
    if "authorization" in names:
        value = str(headers.get("Authorization") or headers.get("authorization") or "")
        if value.lower().startswith("bearer "):
            return "bearer"
        return "custom_header"
    if "cookie" in names:
        return "cookie"
    if headers:
        return "custom_header"
    return "unknown"


def add_actor(
    repo_root: str | Path,
    target: str,
    *,
    actor: str,
    role: str = "unknown",
    label: str = "",
    notes: str = "",
) -> dict[str, Any]:
    actor_id = _require_non_empty(actor, "actor")
    role_value = str(role or "unknown").strip() or "unknown"
    if role_value not in ACTOR_ROLES:
        raise ValueError(f"unknown role: {role_value}. Allowed: {', '.join(sorted(ACTOR_ROLES))}")
    store = runtime_store(repo_root, target)
    current = store.case_context()
    existing = next((item for item in current["actors"] if item["id"] == actor_id), {})
    role_value = role_value if role_value != "unknown" or not existing else str(existing.get("role") or "unknown")
    label = label or str(existing.get("label") or "")
    notes = notes or str(existing.get("notes") or "")
    actor_material = {"role": role_value, "label": label, "notes": notes}
    previous = ({"role": existing.get("role", "unknown"), "label": existing.get("label", ""),
                 "notes": existing.get("notes", "")} if existing else None)
    if not _same_case_material(store, previous, actor_material):
        store.upsert_case_actor(
            command_id=_case_command_id("case-actor", actor_id, actor_material, current["revision"]),
            actor_id=actor_id, role=role_value, label=label, notes=notes, actor=actor_id)
    return store.case_state()["actors"][actor_id]


def add_session(
    repo_root: str | Path,
    target: str,
    *,
    session: str,
    actor: str,
    kind: str = "unknown",
    header_name: str = "",
    header_value: str = "",
    headers: dict[str, str] | None = None,
    source: str = "manual",
    validity: str = "unknown",
    notes: str = "",
) -> dict[str, Any]:
    session_id = _require_non_empty(session, "session")
    actor_id = _require_non_empty(actor, "actor")
    kind_hint = str(kind or "unknown").strip() or "unknown"
    store = runtime_store(repo_root, target)
    context = store.case_context()
    current = next((item for item in context["sessions"] if item["id"] == session_id), {})
    loaded_session = dict(current)
    if current:
        _load_private_session(repo_root, target, session_id, loaded_session)
    header_map = _normalize_headers(loaded_session.get("headers"))
    header_map.update(_normalize_headers(headers))
    if header_value:
        header_map.update(_normalize_headers({header_name or ("Authorization" if kind_hint == "bearer" else "Cookie" if kind_hint == "cookie" else "Authorization"): header_value}))
    kind_value = _infer_session_kind(kind_hint, header_map)
    if not header_map and kind_hint == "unknown" and current:
        kind_value = str(current.get("kind") or "unknown")
    if kind_value not in SESSION_KINDS:
        raise ValueError(f"unknown session kind: {kind_value}")
    private_ref = str(current.get("private_ref") or "")
    if header_map:
        private_base = {"schema_version": SCHEMA_VERSION, "target": canonical_target_value(target),
                        "session_id": session_id, "actor": actor_id, "kind": kind_value, "headers": header_map}
        content_digest = _private_digest(private_base)
        private_payload = {**private_base, "content_sha256": content_digest}
        private_path = _session_private_path(repo_root, target, session_id, content_digest)
        write_private_json(private_path, private_payload)
        private_ref = private_path.relative_to(Path(repo_root)).as_posix()
    source_value = source or str(current.get("source") or "manual")
    if source == "manual" and current:
        source_value = str(current.get("source") or "manual")
    validity_value = validity or str(current.get("validity") or "unknown")
    if validity == "unknown" and current:
        validity_value = str(current.get("validity") or "unknown")
    notes_value = notes or str(current.get("notes") or "")
    session_material = {"actor": actor_id, "kind": kind_value, "source": source_value,
                        "validity": validity_value, "notes": notes_value, "private_ref": private_ref,
                        "last_checked": str(current.get("last_checked") or "")}
    previous = ({"actor": current.get("actor", ""), "kind": current.get("kind", "unknown"),
                 "source": current.get("source", ""), "validity": current.get("validity", ""),
                 "notes": current.get("notes", ""), "private_ref": current.get("private_ref", ""),
                 "last_checked": str(current.get("last_checked") or "")} if current else None)
    if not _same_case_material(store, previous, session_material):
        store.upsert_case_session(
            command_id=_case_command_id("case-session", session_id, session_material, context["revision"]),
            session_id=session_id, actor_id=actor_id, kind=kind_value, source=source_value,
            validity=validity_value, last_checked=session_material["last_checked"], notes=notes_value,
            private_ref=private_ref, actor=actor_id)
    return load_case_state(repo_root, target)["sessions"][session_id]


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
    ref = _require_non_empty(object_ref, "object")
    type_value = _require_non_empty(object_type, "type")
    store = runtime_store(repo_root, target)
    context = store.case_context()
    current = next((item for item in context["objects"] if item["ref"] == ref), {})
    private_ref = str(current.get("private_ref") or "")
    if private_marker:
        private_base = {"schema_version": SCHEMA_VERSION, "target": canonical_target_value(target),
                        "object_ref": ref, "owner_actor": owner_actor or str(current.get("owner_actor") or ""),
                        "private_marker": private_marker}
        content_digest = _private_digest(private_base)
        private_payload = {**private_base, "content_sha256": content_digest}
        private_path = _object_private_path(repo_root, target, ref, content_digest)
        write_private_json(private_path, private_payload)
        private_ref = private_path.relative_to(Path(repo_root)).as_posix()
    object_material = {"type": type_value, "object_id": object_id or str(current.get("object_id") or ""),
                       "owner": owner_actor or str(current.get("owner_actor") or ""),
                       "endpoint": endpoint or str(current.get("endpoint") or ""),
                       "status": str(current.get("status") or "active") if status == "active" and current else status,
                       "notes": notes or str(current.get("notes") or ""), "private_ref": private_ref}
    previous = ({"type": current.get("type", ""), "object_id": current.get("object_id", ""),
                 "owner": current.get("owner_actor") or "", "endpoint": current.get("endpoint", ""),
                 "status": current.get("status", ""), "notes": current.get("notes", ""),
                 "private_ref": current.get("private_ref", "")} if current else None)
    if not _same_case_material(store, previous, object_material):
        store.upsert_case_object(
            command_id=_case_command_id("case-object", ref, object_material, context["revision"]),
            object_ref=ref, object_type=type_value, object_id=object_material["object_id"],
            owner_actor=object_material["owner"], endpoint=object_material["endpoint"],
            status=object_material["status"], notes=object_material["notes"],
            private_ref=private_ref, actor=owner_actor or "case")
    return next(item for item in store.case_context()["objects"] if item["ref"] == ref)


def add_hypothesis(
    repo_root: str | Path,
    target: str,
    *,
    vuln_class: str,
    endpoint: str = "",
    object_ref: str = "",
    actors: list[str] | None = None,
    why_now: str = "",
    status: str = "open",
    hypothesis_id: str = "",
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    actors = actors or []
    vuln_class_value = _require_non_empty(vuln_class, "vuln_class")
    metadata_value = _validate_hypothesis_metadata(metadata)
    store = runtime_store(repo_root, target)
    context = store.case_context()
    record_id = _identifier(hypothesis_id, "hypothesis_id") if hypothesis_id else _next_id(context["hypotheses"], "hyp_")
    hypothesis_material = {"vuln_class": vuln_class_value, "endpoint": endpoint, "object_ref": object_ref,
                           "actors": actors, "why_now": why_now, "status": status, "metadata": metadata_value}
    existing = next((item for item in context["hypotheses"] if item["id"] == record_id), {})
    previous = ({"vuln_class": existing.get("vuln_class", ""), "endpoint": existing.get("endpoint", ""),
                 "object_ref": existing.get("object_ref", ""), "actors": existing.get("actors", []),
                 "why_now": existing.get("why_now", ""), "status": existing.get("status", ""),
                 "metadata": existing.get("metadata", {})} if existing else None)
    if not _same_case_material(store, previous, hypothesis_material):
        store.remember_hypothesis(
            command_id=_case_command_id("case-hypothesis", record_id, hypothesis_material, context["revision"]),
            hypothesis_id=record_id, vuln_class=vuln_class_value, endpoint=endpoint, object_ref=object_ref,
            actor_ids=actors, why_now=why_now, status=status, metadata=metadata_value, actor="case")
    return next(item for item in store.case_context()["hypotheses"] if item["id"] == record_id)


def summary(repo_root: str | Path, target: str) -> dict[str, Any]:
    """Answer Case context facts: actors, sessions, objects, hypotheses.

    不回答“下一步做什么”：行动身份与执行状态在唯一行动源，Case 既不再复制一份
    待办，也不给候选排序。旧文件的 validation_backlog 只作为迁移材料存在，这里
    不读它，避免旧裁决看起来仍像活的行动来源。
    """
    return runtime_store(repo_root, target).case_summary()


def _print_json(payload: Any) -> None:
    def redact(value: Any, key: str = "") -> Any:
        normalized = key.lower().replace("-", "_")
        if normalized == "headers" and isinstance(value, dict):
            return {str(name): "<redacted>" for name in value}
        if _sensitive_metadata_key(normalized):
            return "<redacted>" if value not in (None, "") else value
        if isinstance(value, dict):
            return {str(name): redact(item, str(name)) for name, item in value.items()}
        if isinstance(value, list):
            return [redact(item, key) for item in value]
        return value

    print(json.dumps(redact(payload), ensure_ascii=False, indent=2, sort_keys=True))


def _print_summary(payload: dict[str, Any]) -> None:
    print(f"Target: {payload.get('target')}")
    print(f"Actors: {payload.get('actors', 0)}")
    print(f"Sessions: {payload.get('sessions', 0)}")
    print(f"Objects: {payload.get('objects', 0)}")
    print(f"Open hypotheses: {payload.get('open_hypotheses', 0)}")


def _parse_metadata_json(raw: str | None) -> dict[str, Any] | None:
    if raw is None:
        return None
    try:
        metadata = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"--metadata-json must be valid JSON: {exc.msg}") from exc
    if not isinstance(metadata, dict):
        raise ValueError("--metadata-json must be a JSON object")
    return metadata


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Manage target-scoped actor/session/object validation context (no backlog, no route score)"
    )
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
    p.add_argument("--header", action="append", default=[], help="Additional 'Name: value' header; repeatable")
    p.add_argument("--auth-file", default="", help="AuthSession JSON/.env file to import into this actor session")
    p.add_argument("--cookie", default="", help="Shorthand for Cookie header")
    p.add_argument("--bearer", default="", help="Shorthand for Authorization: Bearer header")
    p.add_argument("--api-key", default="", help="Shorthand for X-API-Key header")
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
    p.add_argument("--status", default="open")
    p.add_argument("--metadata-json", default=None)

    return parser


def _run_command(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    repo_root = Path(args.repo_root)
    if args.cmd == "summary":
        payload = summary(repo_root, args.target)
        _print_json(payload) if args.json else _print_summary(payload)
    elif args.cmd == "add-actor":
        _print_json(add_actor(repo_root, args.target, actor=args.actor, role=args.role, label=args.label, notes=args.notes))
    elif args.cmd == "add-session":
        imported_session = AuthSession.from_sources(
            env={},
            file=args.auth_file or None,
            headers=args.header,
            cookie=args.cookie or None,
            bearer=args.bearer or None,
            api_key=args.api_key or None,
            target=args.target,
        )
        imported_headers = imported_session.bind_target(args.target).headers_dict()
        _print_json(add_session(
            repo_root,
            args.target,
            session=args.session,
            actor=args.actor,
            kind=args.kind,
            header_name=args.header_name,
            header_value=args.header_value,
            headers=imported_headers,
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
            status=args.status,
            metadata=_parse_metadata_json(args.metadata_json),
        ))
    else:  # pragma: no cover - argparse guards this
        raise ValueError(f"unknown command: {args.cmd}")
    return 0


def main(argv: list[str] | None = None) -> int:
    try:
        return _run_command(argv)
    except (OSError, ValueError, KeyError) as exc:
        print(f"target case state command failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
