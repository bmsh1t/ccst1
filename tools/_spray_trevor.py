#!/usr/bin/env python3
"""将 TREVORspray 文本流转换为脱敏、逐事件可解析的 JSONL。"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


SCHEMA_VERSION = 1
AADSTS_RE = re.compile(r"\bAADSTS(?P<code>\d{5,6})\b", re.IGNORECASE)
EMAIL_RE = re.compile(r"(?<![\w.+-])([A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,})(?![\w.-])", re.IGNORECASE)
HTTP_429_RE = re.compile(r"(?:\bHTTP(?:/[0-9.]+)?\s+)?\b429\b", re.IGNORECASE)
SECRET_FIELD_RE = re.compile(
    r'(?P<prefix>"(?:access_token|refresh_token|id_token|sessionToken|client_secret|authorization)"\s*:\s*)'
    r'"(?:\\.|[^"\\])*"',
    re.IGNORECASE,
)
SECRET_SINGLE_FIELD_RE = re.compile(
    r"(?P<prefix>'(?:access_token|refresh_token|id_token|sessionToken|client_secret|authorization)'\s*:\s*)"
    r"'(?:\\.|[^'\\])*'",
    re.IGNORECASE,
)
BEARER_RE = re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]+", re.IGNORECASE)

AADSTS_CLASSIFICATIONS: dict[str, tuple[str, bool | None]] = {
    "50034": ("invalid_user", False),
    "50126": ("invalid_password", False),
    "50053": ("locked", None),
    "53003": ("valid_password_conditional_access", True),
    "50076": ("valid_password_mfa", True),
    "50079": ("valid_password_mfa", True),
    "50158": ("valid_password_external_auth", True),
    "530003": ("valid_password_device_required", True),
    "65001": ("consent_required", True),
    "700016": ("app_not_in_tenant", None),
    "90002": ("tenant_not_found", None),
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_json_object(line: str) -> dict[str, Any] | None:
    """解析整行或带日志前缀的首个 JSON object。"""
    decoder = json.JSONDecoder()
    stripped = line.strip()
    try:
        payload = json.loads(stripped)
    except (json.JSONDecodeError, TypeError):
        payload = None
    if isinstance(payload, dict):
        return payload

    for index, char in enumerate(line):
        if char != "{":
            continue
        try:
            candidate, _ = decoder.raw_decode(line[index:])
        except json.JSONDecodeError:
            continue
        if isinstance(candidate, dict):
            return candidate
    return None


def _parse_response_json_object(line: str) -> dict[str, Any] | None:
    """只接受整行响应对象或明确日志前缀后的响应对象。

    `claims={...}` 之类片段不是响应顶层；即使其对象内出现 access_token，
    也不能标记 token issued。
    """
    stripped = line.strip()
    try:
        payload = json.loads(stripped)
    except (json.JSONDecodeError, TypeError):
        payload = None
    if isinstance(payload, dict):
        return payload

    decoder = json.JSONDecoder()
    for index, char in enumerate(line):
        if char != "{":
            continue
        prefix = line[:index].rstrip()
        if re.search(r"\bclaims?\s*[:=]\s*$", prefix, re.IGNORECASE):
            continue
        if prefix and not (
            prefix.endswith("]")
            or re.search(r"\b(?:response|body|result)\s*:\s*$", prefix, re.IGNORECASE)
        ):
            continue
        try:
            candidate, _ = decoder.raw_decode(line[index:])
        except json.JSONDecodeError:
            continue
        if isinstance(candidate, dict):
            return candidate
    return None


def _walk_items(value: Any) -> Iterable[tuple[str, Any]]:
    if isinstance(value, dict):
        for key, item in value.items():
            yield str(key), item
            yield from _walk_items(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk_items(item)


def _first_value(payload: dict[str, Any] | None, keys: set[str]) -> Any:
    if not payload:
        return None
    lowered = {key.lower() for key in keys}
    for key, value in _walk_items(payload):
        if key.lower() in lowered:
            return value
    return None


def _extract_user(payload: dict[str, Any] | None, line: str) -> str:
    value = _first_value(payload, {"user", "username", "email", "login", "account"})
    if isinstance(value, str) and value.strip():
        return value.strip()
    match = EMAIL_RE.search(line)
    return match.group(1) if match else ""


def classify_emitted_line(line: str, *, mode: str) -> dict[str, Any]:
    """按结构化身份结果优先级分类单条 TREVOR 输出。"""
    payload = _parse_json_object(line)
    aadsts_match = AADSTS_RE.search(line)
    aadsts_code = aadsts_match.group("code") if aadsts_match else ""
    if aadsts_code:
        classification, credential_valid = AADSTS_CLASSIFICATIONS.get(
            aadsts_code,
            ("aadsts_unknown", None),
        )
        return {
            "classification": classification,
            "credential_valid": credential_valid,
            "token_issued": False,
            "aadsts_code": aadsts_code,
        }

    response_payload = _parse_response_json_object(line)
    top_level_token = bool(
        isinstance(response_payload, dict)
        and "access_token" in response_payload
        and response_payload.get("access_token")
    )
    if top_level_token:
        return {
            "classification": "valid_token",
            "credential_valid": True,
            "token_issued": True,
            "aadsts_code": "",
        }

    # Okta 的 errorCode/status 可能嵌在工具包装对象中，因此允许递归读取；
    # access_token 则刻意只认顶层，避免 claims 文本造成成功误判。
    error_code = str(_first_value(payload, {"errorCode"}) or "").upper()
    status = str(_first_value(payload, {"status", "factorResult"}) or "").upper()
    session_token = _first_value(payload, {"sessionToken"})
    upper_line = line.upper()

    if error_code == "E0000047" or HTTP_429_RE.search(line):
        classification, credential_valid = "rate_limited", None
    elif error_code == "E0000119" or status == "LOCKED_OUT" or "LOCKED_OUT" in upper_line:
        classification, credential_valid = "locked", None
    elif status == "MFA_REQUIRED" or "MFA_REQUIRED" in upper_line:
        classification, credential_valid = "valid_password_mfa", True
    elif status == "PASSWORD_EXPIRED" or "PASSWORD_EXPIRED" in upper_line:
        classification, credential_valid = "valid_password_expired", True
    elif status == "SUCCESS" and bool(session_token):
        classification, credential_valid = "valid_session", True
    elif error_code == "E0000004":
        classification, credential_valid = "invalid_credentials", False
    else:
        classification, credential_valid = "unknown", None

    return {
        "classification": classification,
        "credential_valid": credential_valid,
        "token_issued": False,
        "aadsts_code": "",
    }


def _load_passwords(path: Path) -> tuple[str, ...]:
    values = {
        line.rstrip("\r\n")
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
        if line.rstrip("\r\n")
    }
    return tuple(sorted(values, key=lambda value: (-len(value), value)))


def _password_variants(password: str) -> tuple[str, ...]:
    escaped = json.dumps(password, ensure_ascii=False)[1:-1]
    return (password,) if escaped == password else (password, escaped)


def _password_hash_for_line(line: str, passwords: tuple[str, ...]) -> str:
    for password in passwords:
        if any(variant in line for variant in _password_variants(password)):
            return hashlib.sha256(password.encode("utf-8")).hexdigest()[:12]
    return ""


def redact_passwords(line: str, passwords: tuple[str, ...]) -> str:
    redacted = line
    for password in passwords:
        for variant in _password_variants(password):
            redacted = redacted.replace(variant, "[REDACTED_PASSWORD]")
    redacted = SECRET_FIELD_RE.sub(r'\g<prefix>"[REDACTED_SECRET]"', redacted)
    redacted = SECRET_SINGLE_FIELD_RE.sub(r"\g<prefix>'[REDACTED_SECRET]'", redacted)
    return BEARER_RE.sub("Bearer [REDACTED_SECRET]", redacted)


def build_attempt_event(line: str, *, mode: str, passwords: tuple[str, ...]) -> dict[str, Any]:
    parsed = _parse_json_object(line)
    classification = classify_emitted_line(line, mode=mode)
    return {
        "schema_version": SCHEMA_VERSION,
        "ts": _utc_now(),
        "mode": mode,
        "tool": "trevorspray",
        "event": "attempt_result",
        "user": _extract_user(parsed, line),
        **classification,
        "pwd_sha256_prefix": _password_hash_for_line(line, passwords),
        "raw": redact_passwords(line.rstrip("\r\n"), passwords),
    }


def _append_event(handle: Any, event: dict[str, Any]) -> None:
    handle.write(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n")
    handle.flush()


def _required_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise ValueError(f"missing required environment variable: {name}")
    return value


def _parse_bool(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _build_command() -> list[str]:
    delay_seconds = int(_required_env("SPRAY_DELAY"))
    jitter_seconds = int(_required_env("SPRAY_JITTER"))
    command = [
        _required_env("SPRAY_TREVOR_BIN"),
        "--users",
        _required_env("SPRAY_USERS_FILE"),
        "--passlist",
        _required_env("SPRAY_PASSES_FILE"),
        "--url",
        _required_env("SPRAY_TARGET_URL"),
        "--delay",
        str(delay_seconds // 60),
        "--jitter",
        str(jitter_seconds),
    ]
    if not _parse_bool(os.environ.get("SPRAY_CONTINUE_ON_HIT", "false")):
        command.append("--no-loot")
    return command


def run() -> int:
    mode = _required_env("SPRAY_MODE").lower()
    if mode not in {"o365", "okta"}:
        raise ValueError(f"unsupported TREVOR mode: {mode}")

    audit_path = Path(_required_env("AUDIT_LOG"))
    pass_path = Path(_required_env("SPRAY_PASSES_FILE"))
    passwords = _load_passwords(pass_path)
    audit_path.parent.mkdir(parents=True, exist_ok=True)

    with audit_path.open("a", encoding="utf-8") as audit:
        try:
            process = subprocess.Popen(
                _build_command(),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
            )
        except OSError as exc:
            message = redact_passwords(str(exc), passwords)
            _append_event(
                audit,
                {
                    "schema_version": SCHEMA_VERSION,
                    "ts": _utc_now(),
                    "mode": mode,
                    "tool": "trevorspray",
                    "event": "tool_error",
                    "user": "",
                    "classification": "tool_error",
                    "credential_valid": None,
                    "token_issued": False,
                    "aadsts_code": "",
                    "pwd_sha256_prefix": "",
                    "raw": message,
                },
            )
            print(message, file=sys.stderr, flush=True)
            return 127

        assert process.stdout is not None
        try:
            for line in process.stdout:
                event = build_attempt_event(line, mode=mode, passwords=passwords)
                print(event["raw"], flush=True)
                _append_event(audit, event)
        except KeyboardInterrupt:
            process.terminate()
            process.wait()
            return 130

        exit_code = process.wait()
        if exit_code != 0:
            _append_event(
                audit,
                {
                    "schema_version": SCHEMA_VERSION,
                    "ts": _utc_now(),
                    "mode": mode,
                    "tool": "trevorspray",
                    "event": "process_exit",
                    "user": "",
                    "classification": "tool_error",
                    "credential_valid": None,
                    "token_issued": False,
                    "aadsts_code": "",
                    "pwd_sha256_prefix": "",
                    "raw": f"trevorspray exited with code {exit_code}",
                    "exit_code": exit_code,
                },
            )
        return exit_code


def main() -> int:
    try:
        return run()
    except (OSError, ValueError) as exc:
        print(f"trevorspray adapter error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
