#!/usr/bin/env python3
"""Validate and normalize AI-generated 401/403 probe plans.

This module owns only the input contract. Network execution remains in
``bypass_403.sh`` and durable state remains in the existing queue/checkpoint
owners.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

try:
    from tools.auth_session import AuthSession
    from tools.target_paths import canonical_target_value, url_belongs_to_target
except ImportError:  # pragma: no cover - direct tools/ execution
    from auth_session import AuthSession  # type: ignore
    from target_paths import canonical_target_value, url_belongs_to_target  # type: ignore


SCHEMA_VERSION = 1
MAX_PROBES = 256
MAX_MARKERS = 8
MAX_TEXT = 600
MAX_ROUNDS = 2
ALLOWED_KINDS = {"path", "header", "encoding", "method", "sibling", "custom"}
# Keep the input contract finite, but do not treat a verb as proof of mutation.
ALLOWED_METHODS = {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE", "TRACE"}
# Advisory hints retained for compatibility; execution gates use explicit flags.
UNSAFE_METHODS = {"PUT", "PATCH", "DELETE", "TRACE"}
AUTH_HEADER_NAMES = {"authorization", "cookie", "proxy-authorization", "set-cookie"}
HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")


def _text(value: Any, field: str, *, required: bool = True) -> str:
    if not isinstance(value, str):
        if required:
            raise ValueError(f"{field} must be a string")
        return ""
    value = value.strip()
    if required and not value:
        raise ValueError(f"{field} is required")
    if any(ord(char) < 0x20 for char in value):
        raise ValueError(f"{field} contains control characters")
    if len(value) > MAX_TEXT:
        raise ValueError(f"{field} exceeds {MAX_TEXT} characters")
    return value


def _url(value: Any, *, target: str, field: str) -> str:
    value = _text(value, field)
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"{field} must be an absolute http(s) URL")
    if parsed.username or parsed.password:
        raise ValueError(f"{field} must not contain URL credentials")
    if any(ord(char) < 0x20 for char in value):
        raise ValueError(f"{field} contains control characters")
    if not url_belongs_to_target(value, target):
        raise ValueError(f"{field} is outside target scope")
    return value


def _headers(value: Any) -> dict[str, str]:
    if value is None:
        return {}
    if isinstance(value, list):
        pairs: dict[str, str] = {}
        for raw in value:
            if not isinstance(raw, str) or ":" not in raw:
                raise ValueError("mutation.headers entries must be 'Name: value'")
            name, header_value = raw.split(":", 1)
            pairs[name.strip()] = header_value.strip()
        value = pairs
    if not isinstance(value, dict):
        raise ValueError("mutation.headers must be an object or list")
    result: dict[str, str] = {}
    for name, header_value in value.items():
        if not isinstance(name, str) or not HEADER_NAME_RE.fullmatch(name.strip()):
            raise ValueError("mutation.headers contains an invalid header name")
        if name.strip().lower() in AUTH_HEADER_NAMES:
            raise ValueError("mutation.headers cannot carry authentication material; use AuthSession")
        if not isinstance(header_value, str) or "\r" in header_value or "\n" in header_value:
            raise ValueError("mutation.headers contains an invalid header value")
        result[name.strip()] = header_value.strip()
    return result


def _markers(value: Any) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > MAX_MARKERS:
        raise ValueError("protected_markers must be a short list")
    result = []
    for index, marker in enumerate(value):
        marker = _text(marker, f"protected_markers[{index}]")
        if len(marker) < 3:
            raise ValueError("protected markers must contain at least 3 characters")
        result.append(marker)
    return result


def _explicit_action_flag(item: dict[str, Any], mutation: dict[str, Any], field: str) -> bool:
    """Read an explicit side-effect declaration; method names remain advisory."""
    value = item.get(field, mutation.get(field, False))
    if not isinstance(value, bool):
        raise ValueError(f"probes[].{field} must be a boolean")
    return value


def validate_plan(
    payload: dict[str, Any],
    *,
    target: str,
    auth_file: str = "",
    max_requests: int | None = None,
) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        raise ValueError("plan must contain one object")
    if payload.get("schema_version", SCHEMA_VERSION) != SCHEMA_VERSION:
        raise ValueError(f"plan schema_version must be {SCHEMA_VERSION}")
    resolved_target = canonical_target_value(target)
    if not resolved_target:
        raise ValueError("target is required")
    declared_target = payload.get("target")
    if declared_target not in (None, "") and canonical_target_value(str(declared_target)) != resolved_target:
        raise ValueError("plan.target does not match the execution target")
    probes = payload.get("probes")
    if not isinstance(probes, list) or not probes:
        raise ValueError("plan.probes must be a non-empty list")
    if len(probes) > MAX_PROBES:
        raise ValueError(f"plan contains more than {MAX_PROBES} probes")
    budget = payload.get("budget") if isinstance(payload.get("budget"), dict) else {}
    declared_rounds = budget.get("max_rounds", 1)
    try:
        declared_rounds = int(declared_rounds)
    except (TypeError, ValueError) as exc:
        raise ValueError("budget.max_rounds must be an integer") from exc
    if declared_rounds < 1 or declared_rounds > MAX_ROUNDS:
        raise ValueError(f"budget.max_rounds must be between 1 and {MAX_ROUNDS}")
    plan_round = payload.get("round", 1)
    try:
        plan_round = int(plan_round)
    except (TypeError, ValueError) as exc:
        raise ValueError("round must be an integer") from exc
    if plan_round < 1 or plan_round > declared_rounds:
        raise ValueError("round must be within budget.max_rounds")
    declared_budget = budget.get("max_requests", len(probes))
    try:
        declared_budget = int(declared_budget)
    except (TypeError, ValueError) as exc:
        raise ValueError("budget.max_requests must be an integer") from exc
    if declared_budget < 1 or declared_budget > MAX_PROBES:
        raise ValueError(f"budget.max_requests must be between 1 and {MAX_PROBES}")
    # A CLI cap may narrow the plan, never widen the budget declared by the
    # caller. This keeps the plan's own request contract authoritative.
    request_budget = min(
        declared_budget,
        int(max_requests) if max_requests is not None else declared_budget,
    )
    if request_budget < 1 or request_budget > MAX_PROBES:
        raise ValueError(f"max_requests must be between 1 and {MAX_PROBES}")

    session = AuthSession.from_file(auth_file) if auth_file else AuthSession()
    if auth_file:
        session = session.bind_target(target)

    plan_markers = _markers(payload.get("protected_markers"))
    normalized: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for index, item in enumerate(probes):
        if not isinstance(item, dict):
            raise ValueError(f"probes[{index}] must be an object")
        probe_id = _text(item.get("id", f"probe-{index + 1}"), f"probes[{index}].id")
        if probe_id in seen_ids:
            raise ValueError(f"probes[{index}].id is duplicated")
        seen_ids.add(probe_id)
        kind = _text(item.get("kind"), f"probes[{index}].kind")
        if kind not in ALLOWED_KINDS:
            raise ValueError(f"probes[{index}].kind is unsupported")
        mutation = item.get("mutation")
        if not isinstance(mutation, dict):
            raise ValueError(f"probes[{index}].mutation must be an object")
        probe_url = _url(mutation.get("url"), target=target, field=f"probes[{index}].mutation.url")
        method = _text(mutation.get("method", "GET"), f"probes[{index}].mutation.method").upper()
        if method not in ALLOWED_METHODS:
            raise ValueError(f"probes[{index}].mutation.method is unsupported")
        headers = _headers(mutation.get("headers"))
        markers = _markers(item.get("protected_markers", plan_markers))
        action_flags = [
            _explicit_action_flag(item, mutation, field)
            for field in ("state_changing", "destructive", "action_requires_opt_in")
        ]
        state_changing = any(action_flags)
        if auth_file and not session.allows_url(probe_url):
            raise ValueError(f"probes[{index}] auth session is outside its target scope")
        normalized.append(
            {
                "id": probe_id,
                "kind": kind,
                "url": probe_url,
                "method": method,
                "headers": headers,
                "protected_markers": markers,
                "reason": _text(item.get("reason"), f"probes[{index}].reason"),
                "expected_signal": _text(item.get("expected_signal"), f"probes[{index}].expected_signal"),
                "stop_condition": _text(item.get("stop_condition"), f"probes[{index}].stop_condition"),
                "state_changing": state_changing,
                "unsafe": method in UNSAFE_METHODS,
            }
        )
    return normalized[:request_budget]


def build_plan_metadata(
    payload: dict[str, Any],
    normalized: list[dict[str, Any]],
    *,
    target: str,
    request_budget: int,
    plan_path: str = "",
) -> dict[str, Any]:
    """Describe truncation and round identity without becoming a second state owner."""
    probes = payload.get("probes") if isinstance(payload.get("probes"), list) else []
    declared_ids = [
        str(item.get("id", f"probe-{index + 1}"))
        for index, item in enumerate(probes)
        if isinstance(item, dict)
    ]
    executed_ids = [str(item.get("id") or "") for item in normalized]
    executed_set = set(executed_ids)
    skipped_ids = [probe_id for probe_id in declared_ids if probe_id not in executed_set]
    plan_sha256 = ""
    if plan_path:
        try:
            plan_sha256 = hashlib.sha256(Path(plan_path).read_bytes()).hexdigest()
        except OSError:
            plan_sha256 = ""
    budget = payload.get("budget") if isinstance(payload.get("budget"), dict) else {}
    return {
        "schema_version": SCHEMA_VERSION,
        "target": canonical_target_value(target),
        "plan_ref": str(plan_path or ""),
        "plan_sha256": plan_sha256,
        "declared_probe_count": len(declared_ids),
        "executed_probe_count": len(executed_ids),
        "executed_probe_ids": executed_ids,
        "skipped_probe_ids": skipped_ids,
        "request_budget": request_budget,
        "budget_exhausted": bool(skipped_ids),
        "round": int(payload.get("round", 1) or 1),
        "max_rounds": int(budget.get("max_rounds", 1) or 1),
        "baseline_ref": str(payload.get("baseline_ref") or ""),
    }


def _write_json_atomic(path: str | Path, payload: dict[str, Any]) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    temp = output.with_name(f".{output.name}.tmp")
    temp.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temp.replace(output)


def load_and_validate(path: str | Path, **kwargs: Any) -> list[dict[str, Any]]:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"unable to read plan: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid plan JSON: {exc.msg}") from exc
    return validate_plan(payload, **kwargs)


def _shell_lines(probes: list[dict[str, Any]]) -> str:
    """Encode fields so the shell executor never parses untrusted delimiters."""
    fields = (
        "id",
        "kind",
        "method",
        "url",
        "headers",
        "protected_markers",
        "reason",
        "expected_signal",
        "stop_condition",
        "state_changing",
        "unsafe",
    )
    lines = []
    for probe in probes:
        values = dict(probe)
        values["headers"] = json.dumps(probe["headers"], ensure_ascii=False)
        values["protected_markers"] = json.dumps(probe["protected_markers"], ensure_ascii=False)
        lines.append(
            "\t".join(
                base64.b64encode(str(values.get(field, "")).encode("utf-8")).decode("ascii")
                for field in fields
            )
        )
    return "\n".join(lines)


def summarize_results(
    results_path: str | Path,
    *,
    target: str,
    plan_path: str = "",
    plan_metadata_path: str = "",
) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    malformed = 0
    path = Path(results_path)
    if path.exists():
        for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if not raw.strip():
                continue
            try:
                item = json.loads(raw)
            except json.JSONDecodeError:
                malformed += 1
                continue
            if isinstance(item, dict):
                results.append(item)
            else:
                malformed += 1
    counts: dict[str, int] = {}
    for item in results:
        status = str(item.get("status") or "partial")
        counts[status] = counts.get(status, 0) + 1
    unresolved = sum(counts.get(status, 0) for status in ("candidate", "edge_passed", "needs_review", "partial"))
    waf_contexts = sorted(
        {
            str(item.get("waf_context"))
            for item in results
            if item.get("waf_context")
        }
    )
    analyzer_verdicts = sorted(
        {
            str((item.get("analyzer") or {}).get("verdict"))
            for item in results
            if isinstance(item.get("analyzer"), dict)
            and (item.get("analyzer") or {}).get("verdict")
        }
    )
    metadata: dict[str, Any] = {}
    if plan_metadata_path:
        try:
            loaded = json.loads(Path(plan_metadata_path).read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                metadata = loaded
        except (OSError, json.JSONDecodeError):
            metadata = {}
    budget_exhausted = bool(metadata.get("budget_exhausted"))
    if malformed or counts.get("partial") or budget_exhausted:
        status = "partial"
    elif unresolved:
        status = "candidate_pending"
    elif results and counts.get("blocked", 0) == len(results):
        status = "complete_no_hit"
    else:
        status = "invalid_input"
    plan_sha256 = ""
    if plan_path:
        try:
            plan_sha256 = hashlib.sha256(Path(plan_path).read_bytes()).hexdigest()
        except OSError:
            plan_sha256 = ""
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "bypass_403_summary",
        "target": canonical_target_value(target),
        "status": status,
        "counts": counts,
        "request_count": len(results),
        "declared_probe_count": int(metadata.get("declared_probe_count", len(results)) or 0),
        "executed_probe_count": int(metadata.get("executed_probe_count", len(results)) or 0),
        "executed_probe_ids": list(metadata.get("executed_probe_ids") or []),
        "skipped_probe_ids": list(metadata.get("skipped_probe_ids") or []),
        "request_budget": int(metadata.get("request_budget", 0) or 0),
        "budget_exhausted": budget_exhausted,
        "round": int(metadata.get("round", 1) or 1),
        "max_rounds": int(metadata.get("max_rounds", 1) or 1),
        "baseline_ref": str(metadata.get("baseline_ref") or ""),
        "malformed_result_count": malformed,
        "waf_contexts": waf_contexts,
        "analyzer_verdicts": analyzer_verdicts,
        "plan_ref": str(plan_path or ""),
        "plan_sha256": plan_sha256,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "next_action": (
            "resume unexecuted plan probes before closing the access-limit lane"
            if budget_exhausted
            else "validate protected content or permission differential"
            if unresolved
            else "record bounded access-limit lane as tested or blocked"
        ),
        "results": results[:MAX_PROBES],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate an AI 401/403 bypass probe plan")
    parser.add_argument("--plan", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--auth-file", default="")
    parser.add_argument("--max-requests", type=int, default=None)
    parser.add_argument("--shell-lines", action="store_true")
    parser.add_argument("--summarize-results", default="")
    parser.add_argument("--summary-output", default="")
    parser.add_argument("--plan-ref", default="")
    parser.add_argument("--plan-meta", default="")
    parser.add_argument("--meta-output", default="")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        probes = load_and_validate(args.plan, target=args.target, auth_file=args.auth_file, max_requests=args.max_requests)
    except (OSError, ValueError) as exc:
        print(f"bypass_403_plan: {exc}", file=sys.stderr)
        return 2
    if args.summarize_results:
        summary = summarize_results(
            args.summarize_results,
            target=args.target,
            plan_path=args.plan_ref,
            plan_metadata_path=args.plan_meta,
        )
        if not args.summary_output:
            print(json.dumps(summary, ensure_ascii=False, indent=2))
        else:
            output = Path(args.summary_output)
            output.parent.mkdir(parents=True, exist_ok=True)
            _write_json_atomic(output, summary)
        return 0
    if args.meta_output:
        payload = json.loads(Path(args.plan).read_text(encoding="utf-8"))
        budget = payload.get("budget") if isinstance(payload.get("budget"), dict) else {}
        declared_budget = int(budget.get("max_requests", len(payload.get("probes") or [])))
        request_budget = min(
            declared_budget,
            int(args.max_requests) if args.max_requests is not None else declared_budget,
        )
        _write_json_atomic(
            args.meta_output,
            build_plan_metadata(
                payload,
                probes,
                target=args.target,
                request_budget=request_budget,
                plan_path=args.plan,
            ),
        )
    if args.shell_lines:
        print(_shell_lines(probes))
    elif args.json:
        print(json.dumps(probes, ensure_ascii=False))
    else:
        for probe in probes:
            print(json.dumps(probe, ensure_ascii=False))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
