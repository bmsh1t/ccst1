#!/usr/bin/env python3
"""Spray 适配器共用的输入绑定、审计与恢复契约。"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import ssl
import stat
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlparse

try:
    from tools.target_paths import target_storage_key
except ImportError:  # pragma: no cover - 支持 python3 tools/x.py 直接调用
    from target_paths import target_storage_key


SCHEMA_VERSION = 1
PREFLIGHT_TTL = timedelta(hours=24)
SECRET_KEY_RE = re.compile(
    r"(?:pass(?:word)?|secret|token|authorization|cookie|session)",
    re.IGNORECASE,
)
AUDIT_SECRET_KEY_RE = re.compile(
    r"^(?:pass|password|secret|access_token|refresh_token|id_token|authorization|cookie|session)$",
    re.IGNORECASE,
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_utc(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_text(value: str) -> str:
    return _sha256_bytes(value.encode("utf-8"))


def password_hash_prefix(value: str) -> str:
    return sha256_text(value)[:12]


def insecure_enabled() -> bool:
    value = os.environ.get("SPRAY_INSECURE", "false").strip().lower()
    if value not in {"true", "false"}:
        raise ValueError("SPRAY_INSECURE must be true or false")
    return value == "true"


def build_ssl_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    if insecure_enabled():
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


def read_unique_lines(path: str | Path, *, label: str) -> list[str]:
    source = Path(path)
    if not source.is_file():
        raise ValueError(f"{label} file not found: {source}")
    values = list(
        dict.fromkeys(
            line.strip()
            for line in source.read_text(encoding="utf-8", errors="replace").splitlines()
            if line.strip()
        )
    )
    if not values:
        raise ValueError(f"{label} file contains no non-empty entries: {source}")
    return values


def _shortlist_metadata_digest(passes_source: Path, passwords: list[str]) -> str:
    if passes_source.name.lower() != "spray-shortlist.txt":
        return ""
    metadata_path = passes_source.with_name("spray-shortlist.jsonl")
    if not metadata_path.is_file():
        raise ValueError(f"AI shortlist requires companion metadata: {metadata_path}")
    if stat.S_IMODE(metadata_path.stat().st_mode) & 0o077:
        raise ValueError(f"shortlist metadata must be owner-only (chmod 600): {metadata_path}")

    prefixes: list[str] = []
    with metadata_path.open(encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            try:
                payload = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid shortlist metadata JSONL at {metadata_path}:{line_no}") from exc
            if not isinstance(payload, dict) or payload.get("schema_version") != SCHEMA_VERSION:
                raise ValueError(f"invalid shortlist metadata schema at {metadata_path}:{line_no}")
            if any(AUDIT_SECRET_KEY_RE.fullmatch(str(key)) for key in payload):
                raise ValueError(f"shortlist metadata contains a secret-like field at {metadata_path}:{line_no}")
            if any(password in line for password in passwords):
                raise ValueError(f"shortlist metadata contains plaintext password at {metadata_path}:{line_no}")
            prefix = payload.get("pwd_sha256_prefix")
            if not isinstance(prefix, str) or not prefix:
                raise ValueError(f"missing pwd_sha256_prefix at {metadata_path}:{line_no}")
            if not isinstance(payload.get("source"), str) or not payload["source"].strip():
                raise ValueError(f"missing shortlist source at {metadata_path}:{line_no}")
            if not isinstance(payload.get("reason"), str) or not payload["reason"].strip():
                raise ValueError(f"missing shortlist reason at {metadata_path}:{line_no}")
            if payload.get("hibp_bucket") not in {"sweet", "zero", "unknown", "common"}:
                raise ValueError(f"invalid shortlist HIBP bucket at {metadata_path}:{line_no}")
            if not isinstance(payload.get("hibp_count"), int):
                raise ValueError(f"invalid shortlist HIBP count at {metadata_path}:{line_no}")
            prefixes.append(prefix)

    expected = [password_hash_prefix(password) for password in passwords]
    if prefixes != expected:
        raise ValueError("spray-shortlist metadata does not match password input order/digest")
    return _sha256_bytes(metadata_path.read_bytes())


def parse_non_negative_int(value: str, *, label: str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} must be a non-negative integer") from exc
    if parsed < 0:
        raise ValueError(f"{label} must be a non-negative integer")
    return parsed


def _canonical_digest(value: Any) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return sha256_text(raw)


def _lines_digest(values: list[str]) -> str:
    return sha256_text("".join(f"{value}\n" for value in values))


def _write_json_atomic(path: Path, payload: dict[str, Any], *, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp, mode)
        temp.replace(path)
    finally:
        if temp.exists():
            temp.unlink()


def _load_json_object(path: Path, *, label: str) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"{label} not found: {path}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid {label}: {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"invalid {label}: expected JSON object: {path}")
    return payload


def _new_run_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    return f"{stamp}-{os.getpid()}"


def _redact_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): "[REDACTED]" if SECRET_KEY_RE.search(str(key)) else _redact_value(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_value(item) for item in value]
    return value


@dataclass
class RunContext:
    mode: str
    target_url: str
    target_key: str
    run_id: str
    users: list[str]
    passwords: list[str]
    delay: int
    jitter: int
    continue_on_hit: bool
    binding: dict[str, Any]
    shape: dict[str, Any]
    run_dir: Path
    private_dir: Path
    attempts_path: Path
    summary_path: Path
    dry_run: bool = False
    preflight_path: Path | None = None
    completed_attempts: set[str] | None = None
    existing_counts: dict[str, int] | None = None
    valid_users: set[str] | None = None
    lock_fd: int | None = None

    def attempt_key(self, user: str, password: str) -> str:
        return f"{user}\0{password_hash_prefix(password)}"


def _common_input(mode: str, config_binding: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    target_url = os.environ.get("SPRAY_TARGET_URL", "").strip()
    parsed = urlparse(target_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("SPRAY_TARGET_URL must be a valid http/https URL")
    if parsed.username or parsed.password:
        raise ValueError("SPRAY_TARGET_URL must not contain embedded credentials")
    if any(SECRET_KEY_RE.search(key) for key, _ in parse_qsl(parsed.query, keep_blank_values=True)):
        raise ValueError("SPRAY_TARGET_URL must not contain secret-like query parameters")
    if os.environ.get("SPRAY_MODE", "").strip().lower() != mode:
        raise ValueError(f"SPRAY_MODE must be {mode}")

    users_path = os.environ.get("SPRAY_USERS_FILE", "")
    passes_path = os.environ.get("SPRAY_PASSES_FILE", "")
    passes_source = Path(passes_path)
    pass_name = passes_source.name.lower()
    if pass_name in {"candidate-pool.txt", "ranked.txt"} or pass_name.endswith("-ranked.txt"):
        raise ValueError("candidate-pool/ranked artifacts cannot be used as Spray input; use spray-shortlist.txt")
    if passes_source.is_file() and stat.S_IMODE(passes_source.stat().st_mode) & 0o077:
        raise ValueError(f"passwords file must be owner-only (chmod 600): {passes_source}")
    users = read_unique_lines(users_path, label="users")
    passwords = read_unique_lines(passes_path, label="passwords")
    shortlist_meta_sha256 = _shortlist_metadata_digest(passes_source, passwords)
    delay = parse_non_negative_int(os.environ.get("SPRAY_DELAY", "1800"), label="SPRAY_DELAY")
    jitter = parse_non_negative_int(os.environ.get("SPRAY_JITTER", "60"), label="SPRAY_JITTER")
    continue_raw = os.environ.get("SPRAY_CONTINUE_ON_HIT", "false").lower()
    if continue_raw not in {"true", "false"}:
        raise ValueError("SPRAY_CONTINUE_ON_HIT must be true or false")
    continue_on_hit = continue_raw == "true"

    binding = {
        "target_url": target_url,
        "mode": mode,
        "users_sha256": _lines_digest(users),
        "passwords_sha256": _lines_digest(passwords),
        "shortlist_meta_sha256": shortlist_meta_sha256,
        "config_sha256": _canonical_digest(config_binding),
        "user_count": len(users),
        "password_count": len(passwords),
        "delay": delay,
        "jitter": jitter,
        "continue_on_hit": continue_on_hit,
    }
    values = {
        "target_url": target_url,
        "users": users,
        "passwords": passwords,
        "delay": delay,
        "jitter": jitter,
        "continue_on_hit": continue_on_hit,
    }
    return values, binding


def _validate_preflight(path: Path, binding: dict[str, Any]) -> dict[str, Any]:
    payload = _load_json_object(path, label="preflight")
    if payload.get("schema_version") != SCHEMA_VERSION or payload.get("kind") != "spray_preflight":
        raise ValueError(f"unsupported preflight schema: {path}")
    if payload.get("binding") != binding:
        raise ValueError("preflight binding mismatch: URL, mode, input, config, or timing changed")
    try:
        expires_at = _parse_utc(str(payload["expires_at"]))
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"invalid preflight expiry: {path}") from exc
    if datetime.now(timezone.utc) > expires_at:
        raise ValueError(f"preflight expired: {path}")
    return payload


def _load_attempt_state(path: Path, run_id: str) -> tuple[set[str], dict[str, int], set[str]]:
    completed: set[str] = set()
    counts: dict[str, int] = {}
    valid_users: set[str] = set()
    if not path.exists():
        return completed, counts, valid_users
    with path.open(encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid attempts JSONL at {path}:{line_no}") from exc
            if not isinstance(event, dict) or event.get("schema_version") != SCHEMA_VERSION:
                raise ValueError(f"invalid attempts schema at {path}:{line_no}")
            if event.get("run_id") != run_id:
                raise ValueError(f"attempt run_id mismatch at {path}:{line_no}")
            key = event.get("attempt_key")
            if event.get("event") == "attempt_result" and isinstance(key, str) and key:
                completed.add(key)
            classification = event.get("classification")
            if event.get("event") == "attempt_result" and isinstance(classification, str):
                counts[classification] = counts.get(classification, 0) + 1
            user = event.get("user")
            if event.get("credential_valid") is True and isinstance(user, str) and user:
                valid_users.add(user)
    return completed, counts, valid_users


def _validate_resume_summary(run_dir: Path) -> None:
    """只允许恢复崩溃、人工中断或工具错误的 run。"""
    path = run_dir / "summary.json"
    if not path.exists():
        return
    payload = _load_json_object(path, label="run summary")
    if payload.get("schema_version") != SCHEMA_VERSION or payload.get("kind") != "spray_summary":
        raise ValueError(f"unsupported run summary schema: {path}")
    status = payload.get("status")
    if status not in {"interrupted", "error"}:
        raise ValueError(
            f"run is terminal ({status}/{payload.get('stop_reason')}); create a new preflight instead of resuming"
        )


def _acquire_run_lock(run_dir: Path) -> int:
    path = run_dir / ".run.lock"
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        os.close(fd)
        raise ValueError(f"spray run is already active: {run_dir}") from exc
    os.fchmod(fd, 0o600)
    return fd


def _release_run_lock(context: RunContext) -> None:
    if context.lock_fd is None:
        return
    try:
        fcntl.flock(context.lock_fd, fcntl.LOCK_UN)
    finally:
        os.close(context.lock_fd)
        context.lock_fd = None


def prepare_run(
    mode: str,
    *,
    config_binding: dict[str, Any],
    request_shape: dict[str, Any],
) -> RunContext:
    """Validate common inputs and create either a preflight or live run context."""
    values, binding = _common_input(mode, config_binding)
    repo_root = Path(os.environ.get("SPRAY_REPO_ROOT") or Path.cwd()).resolve()
    key = target_storage_key(values["target_url"])
    spray_root = repo_root / "recon" / key / "spray"
    private_root = repo_root / ".private" / "spray" / key
    dry_run = os.environ.get("SPRAY_DRY_RUN", "false").lower() == "true"
    preflight_arg = os.environ.get("SPRAY_PREFLIGHT", "").strip()
    resume_arg = os.environ.get("SPRAY_RESUME", "").strip()
    interactive_confirmed = os.environ.get("SPRAY_INTERACTIVE_CONFIRMED", "false").lower() == "true"

    if dry_run and (preflight_arg or resume_arg):
        raise ValueError("dry-run cannot be combined with preflight or resume")

    if dry_run:
        run_id = _new_run_id()
        preflight_path = Path(
            os.environ.get("SPRAY_PREFLIGHT_OUTPUT")
            or spray_root / f"preflight-{run_id}.json"
        )
        created = datetime.now(timezone.utc)
        payload = {
            "schema_version": SCHEMA_VERSION,
            "kind": "spray_preflight",
            "created_at": created.isoformat().replace("+00:00", "Z"),
            "expires_at": (created + PREFLIGHT_TTL).isoformat().replace("+00:00", "Z"),
            "run_id": run_id,
            "binding": binding,
            "request_shape": _redact_value(request_shape),
            "estimated_duration_seconds": max(
                0,
                (binding["password_count"] - 1) * (binding["delay"] + binding["jitter"] // 2),
            ),
        }
        _write_json_atomic(preflight_path, payload)
        return RunContext(
            mode=mode,
            target_url=values["target_url"],
            target_key=key,
            run_id=run_id,
            users=values["users"],
            passwords=values["passwords"],
            delay=values["delay"],
            jitter=values["jitter"],
            continue_on_hit=values["continue_on_hit"],
            binding=binding,
            shape=request_shape,
            run_dir=spray_root / run_id,
            private_dir=private_root / run_id,
            attempts_path=spray_root / run_id / "attempts.jsonl",
            summary_path=spray_root / run_id / "summary.json",
            dry_run=True,
            preflight_path=preflight_path,
            completed_attempts=set(),
            existing_counts={},
            valid_users=set(),
        )

    preflight_payload: dict[str, Any] | None = None
    if preflight_arg:
        preflight_payload = _validate_preflight(Path(preflight_arg), binding)
    elif not resume_arg and not interactive_confirmed:
        raise ValueError("live run requires --preflight unless the orchestrator completed interactive confirmation")

    if resume_arg:
        run_dir = Path(resume_arg).resolve()
        if run_dir.parent != spray_root.resolve():
            raise ValueError(f"resume run is outside target spray directory: {run_dir}")
        manifest = _load_json_object(run_dir / "run.json", label="run manifest")
        if manifest.get("schema_version") != SCHEMA_VERSION or manifest.get("kind") != "spray_run":
            raise ValueError(f"unsupported run manifest schema: {run_dir / 'run.json'}")
        if manifest.get("binding") != binding:
            raise ValueError("resume binding mismatch: URL, mode, input, config, or timing changed")
        run_id = str(manifest.get("run_id") or "")
        if not run_id or run_dir.name != run_id:
            raise ValueError(f"invalid run_id in manifest: {run_dir / 'run.json'}")
        _validate_resume_summary(run_dir)
    else:
        run_id = str((preflight_payload or {}).get("run_id") or _new_run_id())
        run_dir = spray_root / run_id
        if run_dir.exists():
            raise ValueError(f"run already exists; use --resume: {run_dir}")

    private_dir = private_root / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    lock_fd = _acquire_run_lock(run_dir)
    try:
        private_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(run_dir, 0o700)
        os.chmod(private_dir, 0o700)
        attempts_path = run_dir / "attempts.jsonl"
        attempts_path.parent.mkdir(parents=True, exist_ok=True)
        attempts_path.touch(mode=0o600, exist_ok=True)
        os.chmod(attempts_path, 0o600)
        manifest = {
            "schema_version": SCHEMA_VERSION,
            "kind": "spray_run",
            "run_id": run_id,
            "created_at": utc_now(),
            "binding": binding,
            "request_shape": _redact_value(request_shape),
            "preflight": str(Path(preflight_arg).resolve()) if preflight_arg else None,
        }
        manifest_path = run_dir / "run.json"
        if not resume_arg:
            _write_json_atomic(manifest_path, manifest)

        completed_attempts, existing_counts, valid_users = _load_attempt_state(attempts_path, run_id)
    except Exception:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)
        raise
    return RunContext(
        mode=mode,
        target_url=values["target_url"],
        target_key=key,
        run_id=run_id,
        users=values["users"],
        passwords=values["passwords"],
        delay=values["delay"],
        jitter=values["jitter"],
        continue_on_hit=values["continue_on_hit"],
        binding=binding,
        shape=request_shape,
        run_dir=run_dir,
        private_dir=private_dir,
        attempts_path=attempts_path,
        summary_path=run_dir / "summary.json",
        preflight_path=Path(preflight_arg).resolve() if preflight_arg else None,
        completed_attempts=completed_attempts,
        existing_counts=existing_counts,
        valid_users=valid_users,
        lock_fd=lock_fd,
    )


def append_attempt(context: RunContext, event: dict[str, Any]) -> dict[str, Any]:
    payload = {
        "schema_version": SCHEMA_VERSION,
        "ts": utc_now(),
        "run_id": context.run_id,
        "event": "attempt_result",
        "mode": context.mode,
        **event,
    }
    if any(AUDIT_SECRET_KEY_RE.fullmatch(str(key)) for key in payload):
        raise ValueError("attempt audit contains a secret-like field name")
    raw = (json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
    fd = os.open(context.attempts_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        if os.write(fd, raw) != len(raw):
            raise OSError(f"partial write: {context.attempts_path}")
        os.fsync(fd)
    finally:
        os.close(fd)
    if context.completed_attempts is not None and isinstance(payload.get("attempt_key"), str):
        context.completed_attempts.add(payload["attempt_key"])
    return payload


def write_private_json(context: RunContext, name: str, payload: dict[str, Any]) -> Path:
    if Path(name).name != name:
        raise ValueError("private evidence name must be a basename")
    path = context.private_dir / name
    _write_json_atomic(path, payload)
    return path


def finish_run(
    context: RunContext,
    *,
    status: str,
    stop_reason: str,
    counters: dict[str, int],
    exit_code: int,
) -> dict[str, Any]:
    payload = {
        "schema_version": SCHEMA_VERSION,
        "kind": "spray_summary",
        "run_id": context.run_id,
        "finished_at": utc_now(),
        "status": status,
        "stop_reason": stop_reason,
        "exit_code": exit_code,
        "counts": dict(sorted(counters.items())),
        "attempts_file": str(context.attempts_path),
    }
    try:
        _write_json_atomic(context.summary_path, payload)
        return payload
    finally:
        _release_run_lock(context)


def assert_private_permissions(path: Path) -> None:
    """Small runtime assertion used by focused tests and adapters."""
    if stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise ValueError(f"sensitive path is accessible by group/other: {path}")
