#!/usr/bin/env python3
"""将 TREVORspray 文本流转换为脱敏、逐事件可解析的 JSONL。"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

try:
    from tools.spray_contract import append_attempt, finish_run, prepare_run
except ImportError:  # pragma: no cover - 支持直接运行 tools 脚本
    from spray_contract import append_attempt, finish_run, prepare_run


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
KEY_VALUE_SECRET_RE = re.compile(
    r"\b(?P<key>password|access_token|refresh_token|id_token|sessionToken|client_secret|authorization)"
    r"(?P<sep>\s*[=:]\s*)(?P<value>[^\s,;]+)",
    re.IGNORECASE,
)

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

    if re.search(r"\balready\s+tried\b", line, re.IGNORECASE):
        return {
            "classification": "already_tried",
            "credential_valid": None,
            "token_issued": False,
            "aadsts_code": "",
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
    redacted = KEY_VALUE_SECRET_RE.sub(
        lambda match: f"{match.group('key')}{match.group('sep')}[REDACTED_SECRET]",
        redacted,
    )
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


def _required_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise ValueError(f"missing required environment variable: {name}")
    return value


def _parse_bool(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _build_command(
    mode: str,
    *,
    users_file: Path | None = None,
    passes_file: Path | None = None,
    user_count: int | None = None,
) -> list[str]:
    delay_seconds = int(_required_env("SPRAY_DELAY"))
    jitter_seconds = int(_required_env("SPRAY_JITTER"))
    users_file = users_file or Path(_required_env("SPRAY_USERS_FILE"))
    user_count = user_count if user_count is not None else len(
        dict.fromkeys(
            line.strip()
            for line in users_file.read_text(encoding="utf-8", errors="replace").splitlines()
            if line.strip()
        )
    )
    if user_count < 1:
        raise ValueError("SPRAY_USERS_FILE contains no usernames")
    passes_file = passes_file or Path(_required_env("SPRAY_PASSES_FILE"))

    # 项目入口的 delay/jitter 表示每轮间隔；TREVORspray 接收的是每次请求间隔。
    # 单线程按 password -> users 执行，按用户名数均摊后才能保持相同的每账号轮次节奏。
    request_delay = delay_seconds / user_count
    request_jitter = jitter_seconds / user_count
    module = {"o365": "msol", "okta": "okta"}[mode]
    command = [
        _required_env("SPRAY_TREVOR_BIN"),
        "--module",
        module,
        "--users",
        str(users_file),
        "--passwords",
        str(passes_file),
        "--url",
        _required_env("SPRAY_TARGET_URL"),
        "--delay",
        f"{request_delay:g}",
        "--jitter",
        f"{request_jitter:g}",
        "--no-loot",
    ]
    if not _parse_bool(os.environ.get("SPRAY_CONTINUE_ON_HIT", "false")):
        command.append("--exit-on-success")
    return command


def _write_normalized_inputs(context) -> tuple[Path, Path]:
    """让 TREVOR 实际消费与 preflight digest 完全相同的去重输入。"""
    inputs_dir = context.private_dir / "trevor-inputs"
    inputs_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(inputs_dir, 0o700)
    users_file = inputs_dir / "users.txt"
    passes_file = inputs_dir / "passwords.txt"
    users_file.write_text("".join(f"{value}\n" for value in context.users), encoding="utf-8")
    passes_file.write_text("".join(f"{value}\n" for value in context.passwords), encoding="utf-8")
    os.chmod(users_file, 0o600)
    os.chmod(passes_file, 0o600)
    return users_file, passes_file


def run() -> int:
    mode = _required_env("SPRAY_MODE").lower()
    if mode not in {"o365", "okta"}:
        raise ValueError(f"unsupported TREVOR mode: {mode}")

    binary = Path(_required_env("SPRAY_TREVOR_BIN"))
    config_binding = {
        "module": {"o365": "msol", "okta": "okta"}[mode],
        "binary": str(binary),
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest() if binary.is_file() else "",
        "no_loot": True,
        "exit_on_success": not _parse_bool(os.environ.get("SPRAY_CONTINUE_ON_HIT", "false")),
    }
    context = prepare_run(
        mode,
        config_binding=config_binding,
        request_shape={
            "provider": mode,
            "module": config_binding["module"],
            "no_loot": True,
            "exit_on_success": config_binding["exit_on_success"],
        },
    )
    passwords = tuple(sorted(context.passwords, key=lambda value: (-len(value), value)))
    if context.dry_run:
        command = _build_command(
            mode,
            users_file=Path("<private>/trevor-inputs/users.txt"),
            passes_file=Path("<private>/trevor-inputs/passwords.txt"),
            user_count=len(context.users),
        )
        print(f"[+] Preflight: {context.preflight_path}")
        print(f"[+] TREVOR command: {shlex.join(command)}")
        print("[+] network attempts=0")
        return 0

    counters: Counter[str] = Counter(context.existing_counts or {})
    process: subprocess.Popen[str] | None = None
    stop_reason = "completed"
    status = "completed"
    try:
        normalized_users, normalized_passwords = _write_normalized_inputs(context)
        command = _build_command(
            mode,
            users_file=normalized_users,
            passes_file=normalized_passwords,
            user_count=len(context.users),
        )
        trevor_home = context.private_dir / "trevor-home"
        trevor_home.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(trevor_home, 0o700)
        child_env = os.environ.copy()
        child_env["HOME"] = str(trevor_home)
        child_env["XDG_CONFIG_HOME"] = str(trevor_home / ".config")
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            env=child_env,
        )
        assert process.stdout is not None
        for line in process.stdout:
            event = build_attempt_event(line, mode=mode, passwords=passwords)
            print(event["raw"], flush=True)
            classification = event["classification"]
            counters[classification] += 1
            password_prefix = event["pwd_sha256_prefix"]
            attempt_key = (
                f"{event['user']}\0{password_prefix}"
                if event["user"] and password_prefix
                else ""
            )
            append_attempt(
                context,
                {
                    "tool": "trevorspray",
                    "round": None,
                    "user": event["user"],
                    "pwd_sha256_prefix": password_prefix,
                    "attempt_key": attempt_key,
                    "classification": classification,
                    "credential_valid": event["credential_valid"],
                    "token_issued": event["token_issued"],
                    "status_code": None,
                    "duration_ms": None,
                    "aadsts_code": event["aadsts_code"],
                    "raw": event["raw"],
                },
            )
            if classification in {"rate_limited", "locked"}:
                stop_reason, status = classification, "stopped"
                process.terminate()
                break
            if event["credential_valid"] is True and not context.continue_on_hit:
                stop_reason, status = "credential_valid", "stopped"
                process.terminate()
                break

        exit_code = process.wait()
        if status == "completed" and exit_code != 0:
            stop_reason, status = "tool_error", "error"
        finish_run(
            context,
            status=status,
            stop_reason=stop_reason,
            counters=dict(counters),
            exit_code=exit_code if status != "stopped" else 0,
        )
        print(f"[+] Summary: {context.summary_path}")
        return exit_code if status == "error" else 0
    except KeyboardInterrupt:
        if process is not None and process.poll() is None:
            process.terminate()
            process.wait()
        finish_run(
            context,
            status="interrupted",
            stop_reason="sigint",
            counters=dict(counters),
            exit_code=130,
        )
        return 130
    except (OSError, ValueError) as exc:
        message = redact_passwords(str(exc), passwords)
        finish_run(
            context,
            status="error",
            stop_reason="tool_error",
            counters=dict(counters),
            exit_code=127,
        )
        print(message, file=sys.stderr, flush=True)
        return 127


def main() -> int:
    try:
        return run()
    except (OSError, ValueError) as exc:
        print(f"trevorspray adapter error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
