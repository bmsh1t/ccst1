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
import copy
import fcntl
import hashlib
import json
import os
import re
import sys
import tempfile
from contextlib import contextmanager
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
    from tools.target_store import StoreError, TargetStore, target_backend, target_switch_lock
except ImportError:  # pragma: no cover - direct tools/ execution
    from action_queue import SENSITIVE_OBSERVATION_VALUE_RE  # type: ignore
    from auth_session import AuthSession  # type: ignore
    from private_artifacts import private_artifact_dir, write_private_json  # type: ignore
    from target_paths import canonical_target_value, target_storage_key  # type: ignore
    from target_store import StoreError, TargetStore, target_backend, target_switch_lock  # type: ignore


SCHEMA_VERSION = 1
# 旧文件里的 validation_backlog 是迁移前 Case 自己持有的第二份待办；它的裁决、
# 关联和冲突由 tools/target_migration.py 报告并按明确映射搬运，本模块只原样保留。
LEGACY_BACKLOG_KEY = "validation_backlog"
SESSION_INVALID = {"invalid", "expired", "revoked"}
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


def _primary_store(repo_root: str | Path, target: str, *, write: bool = False) -> TargetStore | None:
    backend = target_backend(repo_root, target)
    if backend == "primary":
        return TargetStore(repo_root, target)
    if backend == "preview" and write:
        raise StoreError("case-state JSON writer is disabled while the target backend is preview")
    return None


def _private_digest(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _object_private_path(repo_root: str | Path, target: str, object_ref: str, digest: str) -> Path:
    directory = private_artifact_dir(repo_root, "case-state", target_storage_key(canonical_target_value(target)), "objects")
    object_digest = hashlib.sha256(object_ref.encode("utf-8")).hexdigest()[:20]
    return directory / f"{object_digest}-{digest[:16]}.json"


@contextmanager
def case_state_mutation_lock(repo_root: str | Path, target: str):
    """串行化同一目标的完整 case-state read-modify-write。"""
    with target_switch_lock(repo_root, target):
        lock_path = case_state_path(repo_root, target).parent / "locks" / "case_state.lock"
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        with lock_path.open("a+", encoding="utf-8") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


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
    session["header_name"] = str(payload.get("header_name") or "")
    session["header_value"] = str(payload.get("header_value") or "")


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
    }


def _ensure_shape(state: dict[str, Any], target: str) -> dict[str, Any]:
    resolved = canonical_target_value(target)
    schema_version = state.get("schema_version", SCHEMA_VERSION)
    if schema_version != SCHEMA_VERSION:
        raise ValueError(
            f"target case state schema_version must be {SCHEMA_VERSION}, got {schema_version!r}"
        )
    state.setdefault("schema_version", SCHEMA_VERSION)
    if state.get("target") not in (None, "", resolved):
        raise ValueError(f"target case state target mismatch: {state.get('target')!r}")
    if state.get("target_key") not in (None, "", target_storage_key(resolved)):
        raise ValueError(f"target case state target_key mismatch: {state.get('target_key')!r}")
    state["target"] = resolved
    state["target_key"] = target_storage_key(resolved)
    state.setdefault("created_at", now_utc())
    state.setdefault("updated_at", now_utc())
    for key, default in (
        ("actors", {}),
        ("sessions", {}),
        ("objects", {}),
        ("hypotheses", []),
    ):
        if key not in state:
            state[key] = default
        elif not isinstance(state.get(key), type(default)):
            raise ValueError(
                f"target case state field {key!r} must be {type(default).__name__}"
            )
    # 旧 validation_backlog 原样保留：Case 不再是它的 owner，因此既不把它归一化，
    # 也不替迁移器判断它的形状；它带着原裁决等迁移搬运或隔离。这里只校验 Case
    # 自己拥有的 hypotheses 身份。
    record_ids: set[str] = set()
    for index, item in enumerate(state["hypotheses"]):
        if not isinstance(item, dict):
            raise ValueError(f"target case state field 'hypotheses'[{index}] must be object")
        record_id = str(item.get("id") or "").strip()
        if record_id in record_ids:
            raise ValueError(f"target case state field 'hypotheses' has duplicate id: {record_id}")
        if record_id:
            record_ids.add(record_id)
    for session in state["sessions"].values():
        if not isinstance(session, dict):
            continue
        headers = session.get("headers")
        if not isinstance(headers, dict):
            headers = {}
        header_name = str(session.get("header_name") or "").strip()
        header_value = str(session.get("header_value") or "").strip()
        if header_name and header_value and header_name not in headers:
            headers[header_name] = header_value
        session["headers"] = {str(k): str(v) for k, v in headers.items() if str(k).strip() and str(v).strip()}
    return state


def load_case_state(repo_root: str | Path, target: str) -> dict[str, Any]:
    store = _primary_store(repo_root, target)
    if store is not None:
        state = store.case_state()
        for session_id, session in state.get("sessions", {}).items():
            if isinstance(session, dict):
                _load_private_session(repo_root, target, str(session_id), session)
        return state
    path = case_state_path(repo_root, target)
    if not path.is_file():
        return _empty_state(target)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"unable to read target case state {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid target case state JSON {path}: {exc.msg}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"target case state {path} must contain one object")
    state = _ensure_shape(payload, target)
    for session_id, session in state.get("sessions", {}).items():
        if isinstance(session, dict):
            _load_private_session(repo_root, target, str(session_id), session)
    return state


def save_case_state(repo_root: str | Path, target: str, state: dict[str, Any]) -> Path:
    if _primary_store(repo_root, target, write=True) is not None:
        raise StoreError("case_state.json is read-only after primary backend activation")
    state = _ensure_shape(state, target)
    state["schema_version"] = SCHEMA_VERSION
    state["updated_at"] = now_utc()
    path = case_state_path(repo_root, target)
    path.parent.mkdir(parents=True, exist_ok=True)
    public_state = copy.deepcopy(state)
    for session_id, session in list(state.get("sessions", {}).items()):
        if not isinstance(session, dict):
            continue
        headers = session.get("headers") if isinstance(session.get("headers"), dict) else {}
        header_name = str(session.get("header_name") or "").strip()
        header_value = str(session.get("header_value") or "").strip()
        if not headers and header_name and header_value:
            headers = {header_name: header_value}
        if headers:
            private_payload = {
                "schema_version": SCHEMA_VERSION,
                "target": canonical_target_value(target),
                "session_id": str(session_id),
                "actor": str(session.get("actor") or ""),
                "kind": str(session.get("kind") or "unknown"),
                "header_name": header_name,
                "header_value": header_value,
                "headers": {str(k): str(v) for k, v in headers.items()},
            }
            content_digest = _private_digest(private_payload)
            private_payload["content_sha256"] = content_digest
            private_path = _session_private_path(repo_root, target, str(session_id), content_digest)
            write_private_json(private_path, private_payload)
            public_session = public_state["sessions"][session_id]
            public_session["private_ref"] = private_path.relative_to(Path(repo_root)).as_posix()
            public_session.pop("header_name", None)
            public_session.pop("header_value", None)
            public_session.pop("headers", None)
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
            handle.write(json.dumps(public_state, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
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
    return path


def _mutate_case_state(repo_root: str | Path, target: str, mutation):
    """在目标锁内完成一次完整的状态读改写。"""
    with case_state_mutation_lock(repo_root, target):
        state = load_case_state(repo_root, target)
        result = mutation(state)
        save_case_state(repo_root, target, state)
        return result


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


def _primary_header(headers: dict[str, str]) -> tuple[str, str]:
    for name, value in headers.items():
        if str(name or "").strip() and str(value or "").strip():
            return str(name).strip(), str(value).strip()
    return "", ""


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
    store = _primary_store(repo_root, target, write=True)
    if store is not None:
        current = store.case_context()
        existing = next((item for item in current["actors"] if item["id"] == actor_id), {})
        role_value = role_value if role_value != "unknown" or not existing else str(existing.get("role") or "unknown")
        label = label or str(existing.get("label") or "")
        notes = notes or str(existing.get("notes") or "")
        actor_material = {"role": role_value, "label": label, "notes": notes}
        store.upsert_case_actor(command_id=f"case-actor:{actor_id}:{_private_digest(actor_material)[:16]}",
                                actor_id=actor_id, role=role_value, label=label, notes=notes, actor=actor_id)
        return store.case_state()["actors"][actor_id]
    def mutate(state):
        ts = now_utc()
        current = state["actors"].get(actor_id, {})
        effective_role = role_value if role != "unknown" or not current else str(current.get("role") or "unknown")
        state["actors"][actor_id] = {
            "role": effective_role,
            "label": str(label or current.get("label", "") or ""),
            "notes": str(notes or current.get("notes", "") or ""),
            "created_at": current.get("created_at") or ts,
            "last_seen": ts,
        }
        return state["actors"][actor_id]
    return _mutate_case_state(repo_root, target, mutate)


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
    store = _primary_store(repo_root, target, write=True)
    if store is not None:
        current = next((item for item in store.case_context()["sessions"] if item["id"] == session_id), {})
        header_map = _normalize_headers(headers)
        if header_value:
            header_map.update(_normalize_headers({header_name or ("Authorization" if kind_hint == "bearer" else "Cookie" if kind_hint == "cookie" else "Authorization"): header_value}))
        kind_value = _infer_session_kind(kind_hint, header_map)
        if not header_map and kind_hint == "unknown" and current:
            kind_value = str(current.get("kind") or "unknown")
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
                            "validity": validity_value, "notes": notes_value, "private_ref": private_ref}
        store.upsert_case_session(
            command_id=f"case-session:{session_id}:{_private_digest(session_material)[:16]}", session_id=session_id, actor_id=actor_id,
            kind=kind_value, source=source_value, validity=validity_value,
            last_checked=str(current.get("last_checked") or ""), notes=notes_value,
            private_ref=private_ref, actor=actor_id)
        return next(item for item in store.case_context()["sessions"] if item["id"] == session_id)
    def mutate(state):
        nonlocal header_name
        if actor_id not in state["actors"]:
            raise ValueError(f"actor does not exist: {actor_id}")
        current = state["sessions"].get(session_id, {})
        current_headers = current.get("headers") if isinstance(current.get("headers"), dict) else {}
        header_map = _normalize_headers({str(k): str(v) for k, v in current_headers.items()})
        if not header_name and kind_hint == "bearer":
            header_name = "Authorization"
        if not header_name and kind_hint == "cookie":
            header_name = "Cookie"
        header_map.update(_normalize_headers(headers))
        if header_value:
            if not header_name and kind_hint == "bearer":
                header_name = "Authorization"
            if not header_name and kind_hint == "cookie":
                header_name = "Cookie"
            header_map.update(_normalize_headers({header_name or "Authorization": header_value}))
        elif header_name and current.get("header_value"):
            header_map.update(_normalize_headers({header_name: str(current.get("header_value"))}))
        header_name_value, header_value_value = _primary_header(header_map)
        kind_value = _infer_session_kind(kind, header_map)
        if kind_value not in SESSION_KINDS:
            raise ValueError(f"unknown session kind: {kind_value}. Allowed: {', '.join(sorted(SESSION_KINDS))}")
        ts = now_utc()
        source_value = str(source if source != "manual" or not current else current.get("source", "manual") or "manual")
        validity_value = str(validity if validity != "unknown" or not current else current.get("validity", "unknown") or "unknown")
        state["sessions"][session_id] = {
            "actor": actor_id,
            "kind": kind_value,
            "header_name": header_name_value,
            "header_value": header_value_value,
            "headers": header_map,
            "source": source_value,
            "validity": validity_value,
            "last_checked": current.get("last_checked", ""),
            "notes": str(notes or current.get("notes", "") or ""),
            "created_at": current.get("created_at") or ts,
            "last_seen": ts,
        }
        return state["sessions"][session_id]
    return _mutate_case_state(repo_root, target, mutate)


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
    store = _primary_store(repo_root, target, write=True)
    if store is not None:
        current = next((item for item in store.case_context()["objects"] if item["ref"] == ref), {})
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
        store.upsert_case_object(
            command_id=f"case-object:{ref}:{_private_digest({'type': type_value, 'object_id': object_id, 'owner': owner_actor, 'endpoint': endpoint, 'status': status, 'notes': notes, 'private_ref': private_ref})[:16]}",
            object_ref=ref, object_type=type_value,
            object_id=object_id or str(current.get("object_id") or ""), owner_actor=owner_actor or str(current.get("owner_actor") or ""),
            endpoint=endpoint or str(current.get("endpoint") or ""), status=status or str(current.get("status") or "active"),
            notes=notes or str(current.get("notes") or ""), private_ref=private_ref, actor=owner_actor or "case")
        return next(item for item in store.case_context()["objects"] if item["ref"] == ref)
    def mutate(state):
        if owner_actor and owner_actor not in state["actors"]:
            raise ValueError(f"owner actor does not exist: {owner_actor}")
        ts = now_utc()
        current = state["objects"].get(ref, {})
        status_value = str(status if status != "active" or not current else current.get("status", "active") or "active")
        state["objects"][ref] = {
            "type": type_value,
            "object_id": str(object_id or current.get("object_id", "") or ""),
            "owner_actor": str(owner_actor or current.get("owner_actor", "") or ""),
            "endpoint": str(endpoint or current.get("endpoint", "") or ""),
            "private_marker": str(private_marker or current.get("private_marker", "") or ""),
            "status": status_value,
            "notes": str(notes or current.get("notes", "") or ""),
            "created_at": current.get("created_at") or ts,
            "last_seen": ts,
        }
        return state["objects"][ref]
    return _mutate_case_state(repo_root, target, mutate)


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
    store = _primary_store(repo_root, target, write=True)
    if store is not None:
        record_id = hypothesis_id or _next_id(store.case_context()["hypotheses"], "hyp_")
        hypothesis_material = {"vuln_class": vuln_class_value, "endpoint": endpoint, "object_ref": object_ref,
                               "actors": actors, "why_now": why_now, "status": status, "metadata": metadata_value}
        store.remember_hypothesis(command_id=f"case-hypothesis:{record_id}:{_private_digest(hypothesis_material)[:16]}", hypothesis_id=record_id,
                                  vuln_class=vuln_class_value, endpoint=endpoint, object_ref=object_ref,
                                  actor_ids=actors, why_now=why_now, status=status,
                                  metadata=metadata_value, actor="case")
        return next(item for item in store.case_context()["hypotheses"] if item["id"] == record_id)
    def mutate(state):
        for actor in actors:
            if actor not in state["actors"]:
                raise ValueError(f"actor does not exist: {actor}")
        if object_ref and object_ref not in state["objects"]:
            raise ValueError(f"object_ref does not exist: {object_ref}")
        record_id = hypothesis_id or _next_id(state["hypotheses"], "hyp_")
        if any(item.get("id") == record_id for item in state["hypotheses"]):
            raise ValueError(f"hypothesis id already exists: {record_id}")
        record = {
            "id": record_id,
            "vuln_class": vuln_class_value,
            "endpoint": str(endpoint or ""),
            "object_ref": str(object_ref or ""),
            "actors": list(actors),
            "status": str(status or "open"),
            # why_now 是假设自身的理由；"下一步做什么"属于唯一行动源，Case 不存它。
            "why_now": str(why_now or ""),
            "created_at": now_utc(),
        }
        if metadata_value:
            record["metadata"] = dict(metadata_value)
        state["hypotheses"].append(record)
        return record
    return _mutate_case_state(repo_root, target, mutate)


def summary(repo_root: str | Path, target: str) -> dict[str, Any]:
    """Answer Case context facts: actors, sessions, objects, hypotheses.

    不回答“下一步做什么”：行动身份与执行状态在唯一行动源，Case 既不再复制一份
    待办，也不给候选排序。旧文件的 validation_backlog 只作为迁移材料存在，这里
    不读它，避免旧裁决看起来仍像活的行动来源。
    """
    store = _primary_store(repo_root, target)
    if store is not None:
        context = store.case_context()
        objects = context["objects"]
        return {
            "target": context["target"],
            "target_key": context["target_key"],
            "actors": len(context["actors"]),
            "sessions": len(context["sessions"]),
            "authz_coverage": context["authz_coverage"],
            "objects": len(objects),
            "open_hypotheses": len([item for item in context["hypotheses"] if item.get("status") == "open"]),
            "object_samples": [
                {"object_ref": item["ref"], "type": item["type"], "object_id": item["object_id"],
                 "endpoint": item["endpoint"], "owner_actor": item["owner_actor"],
                 "private_marker": "<redacted>" if item.get("private_ref") else ""}
                for item in objects[:8]
            ],
        }
    state = load_case_state(repo_root, target)
    objects = state.get("objects") if isinstance(state.get("objects"), dict) else {}
    authenticated_sessions = []
    for session in state.get("sessions", {}).values():
        if not isinstance(session, dict):
            continue
        actor_id = str(session.get("actor") or "")
        actor = state.get("actors", {}).get(actor_id)
        if not isinstance(actor, dict) or str(actor.get("role") or "anonymous").lower() == "anonymous":
            continue
        if str(session.get("validity") or "unknown").lower() in SESSION_INVALID:
            continue
        if session.get("headers") or (session.get("header_name") and session.get("header_value")):
            authenticated_sessions.append(session)
    authenticated_actor_ids = {
        str(session.get("actor") or "") for session in authenticated_sessions
    }
    authenticated_session_count = len(authenticated_sessions)
    if len(authenticated_actor_ids) >= 2:
        authz_status = "ready"
    elif authenticated_actor_ids:
        authz_status = "partial"
    else:
        authz_status = "missing"
    return {
        "target": state.get("target"),
        "target_key": state.get("target_key"),
        "actors": len(state.get("actors", {})),
        "sessions": len(state.get("sessions", {})),
        "authz_coverage": {
            "status": authz_status,
            "authenticated_actor_count": len(authenticated_actor_ids),
            "authenticated_session_count": authenticated_session_count,
        },
        "objects": len(state.get("objects", {})),
        "open_hypotheses": len([h for h in state.get("hypotheses", []) if h.get("status") == "open"]),
        "object_samples": [
            {
                "object_ref": str(ref),
                "type": str(obj.get("type") or ""),
                "object_id": str(obj.get("object_id") or ""),
                "endpoint": str(obj.get("endpoint") or ""),
                "owner_actor": str(obj.get("owner_actor") or ""),
                "private_marker": str(obj.get("private_marker") or ""),
            }
            for ref, obj in list(objects.items())[:8]
            if isinstance(obj, dict)
        ],
    }


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
