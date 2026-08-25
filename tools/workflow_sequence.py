#!/usr/bin/env python3
"""Evidence-gated business workflow record/replay/perturb lane."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shlex
import sys
import urllib.parse
from http.cookies import CookieError, SimpleCookie
from pathlib import Path
from typing import Any

try:
    from tools.action_queue import add_manual_action, resolve_action
    from tools.auth_session import add_cli_args, session_from_args, AuthSession
    from tools.browser_surface import public_url_shape
    from tools.json_inject_probe import _write_json_atomic
    from tools.private_artifacts import private_artifact_dir, write_private_json
    from tools.response_diff import diff_responses, snapshot_response
    from tools.target_paths import canonical_target_value, target_storage_key, url_belongs_to_target
    from tools.validation_runner import request_once
except ImportError:  # pragma: no cover
    from action_queue import add_manual_action, resolve_action  # type: ignore
    from auth_session import add_cli_args, session_from_args, AuthSession  # type: ignore
    from browser_surface import public_url_shape  # type: ignore
    from json_inject_probe import _write_json_atomic  # type: ignore
    from private_artifacts import private_artifact_dir, write_private_json  # type: ignore
    from response_diff import diff_responses, snapshot_response  # type: ignore
    from target_paths import canonical_target_value, target_storage_key, url_belongs_to_target  # type: ignore
    from validation_runner import request_once  # type: ignore

BASE_DIR = Path(__file__).resolve().parents[1]
MAX_STEPS = 8
DEFAULT_REQUEST_CAP = 16
TOKEN_SOURCES = ("regex", "response_header", "cookie", "json_path")
MAX_TOKEN_LENGTH = 8192


def _rel(path: Path, repo_root: Path) -> str:
    try:
        return str(path.relative_to(repo_root))
    except ValueError:
        return str(path)


def _safe_input(repo_root: Path, evidence_ref: str) -> Path:
    path = Path(evidence_ref).expanduser()
    if not path.is_absolute():
        path = repo_root / path
    path = path.resolve()
    try:
        path.relative_to(repo_root.resolve())
    except ValueError as exc:
        raise ValueError("evidence_ref must remain inside repo_root") from exc
    if not path.is_file():
        raise ValueError(f"workflow evidence file not found: {path}")
    return path


def _header_map(value: Any) -> dict[str, str]:
    if isinstance(value, dict):
        return {
            str(key): str(item)
            for key, item in value.items()
            if str(key).lower() not in {"host", "content-length"}
        }
    if isinstance(value, list):
        return _header_map({item.get("name"): item.get("value", "") for item in value if isinstance(item, dict)})
    return {}


def _extract_steps(payload: dict[str, Any], *, target: str, max_steps: int) -> list[dict[str, Any]]:
    declared_target = str(payload.get("target") or "").strip()
    if declared_target and canonical_target_value(declared_target) != canonical_target_value(target):
        raise ValueError("workflow evidence target does not match requested target")
    raw_steps = payload.get("steps")
    if raw_steps is None and isinstance(payload.get("log"), dict):
        raw_steps = payload["log"].get("entries")
    if not isinstance(raw_steps, list):
        raise ValueError("workflow evidence must contain steps or HAR log.entries")
    steps: list[dict[str, Any]] = []
    for index, raw in enumerate(raw_steps[:max_steps]):
        if not isinstance(raw, dict):
            continue
        request = raw.get("request") if isinstance(raw.get("request"), dict) else raw
        url = str(request.get("url") or "").strip()
        parsed_url = urllib.parse.urlsplit(url)
        if parsed_url.scheme.lower() not in {"http", "https"} or not parsed_url.netloc:
            raise ValueError(f"workflow step {index + 1} URL must be an absolute HTTP(S) URL")
        if not url_belongs_to_target(url, target):
            raise ValueError(f"workflow step {index + 1} is outside target scope")
        method = str(request.get("method") or "GET").upper()
        if method not in {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}:
            raise ValueError(f"workflow step {index + 1} has unsupported method {method}")
        post_data = request.get("postData") if isinstance(request.get("postData"), dict) else {}
        body = str(raw.get("body") if "body" in raw else post_data.get("text") or "")
        steps.append({
            "id": str(raw.get("id") or f"step-{index + 1}"),
            "url": url,
            "method": method,
            "headers": _header_map(raw.get("headers") if "headers" in raw else request.get("headers")),
            "body": body,
            "token": raw.get("token") if isinstance(raw.get("token"), dict) else {},
        })
    if len(steps) < 2:
        raise ValueError("workflow sequence needs at least two ordered steps")
    if not any(
        "/api/" in urllib.parse.urlparse(step["url"]).path.lower()
        or step["method"] != "GET"
        or step["body"]
        for step in steps
    ):
        raise ValueError("workflow evidence lacks a concrete business-flow signal")
    return steps


def _refresh_token(
    step: dict[str, Any],
    *,
    target: str,
    session: AuthSession,
    timeout: int,
) -> tuple[str, int]:
    spec = step.get("token") if isinstance(step.get("token"), dict) else {}
    if not spec:
        return "", 0
    url = str(spec.get("url") or step["url"])
    if not url_belongs_to_target(url, target):
        raise ValueError("workflow token source leaves target scope")
    sources = [name for name in TOKEN_SOURCES if str(spec.get(name) or "").strip()]
    if len(sources) != 1:
        raise ValueError("workflow token requires exactly one extraction source")
    response = request_once(
        target=target,
        url=url,
        method=str(spec.get("method") or "GET").upper(),
        headers=session.headers_for_url(url),
        timeout=timeout,
    )
    source = sources[0]
    token = ""
    if source == "regex":
        try:
            regex = re.compile(str(spec["regex"]))
        except re.error as exc:
            raise ValueError(f"invalid workflow token regex: {exc}") from exc
        if regex.groups < 1:
            raise ValueError("workflow token regex requires a capture group")
        match = regex.search(str(response.get("body") or ""))
        token = str(match.group(1)) if match else ""
    elif source == "response_header":
        wanted = str(spec["response_header"]).strip().lower()
        token = next(
            (str(value).strip() for name, value in (response.get("headers") or {}).items() if str(name).lower() == wanted),
            "",
        )
    elif source == "cookie":
        raw_cookie = next(
            (str(value) for name, value in (response.get("headers") or {}).items() if str(name).lower() == "set-cookie"),
            "",
        )
        jar = SimpleCookie()
        try:
            jar.load(raw_cookie)
        except CookieError as exc:
            raise ValueError("workflow token source returned an invalid Set-Cookie header") from exc
        morsel = jar.get(str(spec["cookie"]).strip())
        token = morsel.value if morsel else ""
    else:
        path = str(spec["json_path"]).strip()
        # ponytail: dotted keys and numeric indexes only; add JSONPath when target evidence requires it.
        parts = path.split(".")
        if parts and parts[0] == "$":
            parts.pop(0)
        if not parts or len(parts) > 8 or len(path) > 200 or any(not part for part in parts):
            raise ValueError("workflow token json_path must contain 1-8 bounded segments")
        try:
            value: Any = json.loads(str(response.get("body") or ""))
        except json.JSONDecodeError as exc:
            raise ValueError("workflow token source did not return valid JSON") from exc
        for part in parts:
            if isinstance(value, dict) and part in value:
                value = value[part]
            elif isinstance(value, list) and part.isdigit() and int(part) < len(value):
                value = value[int(part)]
            else:
                raise ValueError("workflow token json_path did not resolve")
        if value is not None and not isinstance(value, (dict, list, bool)):
            token = str(value).strip()
    if not token:
        raise ValueError("workflow token source did not yield a token")
    if len(token) > MAX_TOKEN_LENGTH:
        raise ValueError("workflow token exceeds the bounded length")
    return token, 1


def _step_request(step: dict[str, Any], *, target: str, session: AuthSession, timeout: int) -> tuple[dict[str, Any], int]:
    token, refreshed = _refresh_token(step, target=target, session=session, timeout=timeout)
    headers = {**step["headers"], **session.headers_for_url(step["url"])}
    body = step["body"]
    spec = step.get("token") if isinstance(step.get("token"), dict) else {}
    if token:
        header = str(spec.get("header") or "").strip()
        placeholder = str(spec.get("placeholder") or "{TOKEN}")
        if header:
            if "\r" in token or "\n" in token:
                raise ValueError("workflow token header value contains CR/LF")
            headers[header] = token
        else:
            if placeholder not in body:
                raise ValueError("workflow token has no header or body placeholder destination")
            body = body.replace(placeholder, token)
    return request_once(
        target=target,
        url=step["url"],
        method=step["method"],
        headers=headers,
        body=body,
        timeout=timeout,
    ), refreshed


def _material_diff(baseline: dict[str, Any], variant: dict[str, Any]) -> bool:
    diff = diff_responses(
        baseline_status=int(baseline.get("status") or 0),
        baseline_headers=baseline.get("headers") or {},
        baseline_body=str(baseline.get("body") or ""),
        variant_status=int(variant.get("status") or 0),
        variant_headers=variant.get("headers") or {},
        variant_body=str(variant.get("body") or ""),
    )
    diff = diff.get("diff") if isinstance(diff.get("diff"), dict) else diff
    changed = diff.get("changed") or {}
    return bool(
        changed.get("status")
        or changed.get("json_count")
        or changed.get("json_fields")
        or abs(int((diff.get("body_length") or {}).get("delta", 0) or 0)) > 20
    )


def _summary_snapshot(response: dict[str, Any]) -> dict[str, Any]:
    return snapshot_response(
        int(response.get("status") or 0),
        response.get("headers") or {},
        str(response.get("body") or ""),
        truncated=bool(response.get("body_truncated")),
        observed_bytes=int(response.get("body_observed_bytes", 0) or 0),
    )


def _queue_sequence_action(
    repo_root: Path,
    target: str,
    evidence_ref: str,
    summary_path: str,
    run_id: str,
    status: str,
) -> dict[str, Any]:
    source_id = hashlib.sha256(f"{evidence_ref}:{run_id}".encode("utf-8")).hexdigest()[:20]
    try:
        result = add_manual_action(
            repo_root,
            target=target,
            action_type="workflow-sequence",
            evidence=f"Workflow sequence evidence: {summary_path}",
            next_question="Did the bounded perturbation produce a stable business-state difference?",
            action=f"Review workflow sequence result and classify the recorded diff: {summary_path}",
            priority=86,
            command_hint=(
                "python3 tools/workflow_sequence.py --target "
                f"{shlex.quote(target)} --evidence-ref {shlex.quote(evidence_ref)}"
            ),
            source="workflow-sequence",
            source_id=source_id,
            generation=run_id,
            stop_condition="record tested_clean, candidate, or blocked before closing the sequence",
        )
        queue = result.get("queue") if isinstance(result, dict) else {}
        action = next(
            (item for item in (queue.get("actions") or [])
             if isinstance(item, dict) and str(item.get("source_id") or "") == source_id),
            {},
        )
        action_id = str(action.get("id") or "")
        current_status = str(action.get("status") or "queued")
        final_status = {"tested_clean": "tested", "candidate_pending": "candidate"}.get(status)
        if action_id and final_status and current_status not in {"tested", "candidate", "dead-end", "blocked", "validated", "reported", "n/a"}:
            resolved = resolve_action(
                repo_root,
                target=target,
                action_id=action_id,
                status=final_status,
                result=f"workflow-sequence-result={status}",
                notes=f"summary={summary_path}",
            )
            current_status = str(resolved.get("status") or final_status)
        return {"status": "ok", "action_id": action_id, "action_status": current_status}
    except (OSError, KeyError, ValueError) as exc:
        return {"status": "error", "error": str(exc)[:240]}


def run_sequence(
    *,
    repo_root: Path,
    target: str,
    evidence_ref: str,
    session: AuthSession | None = None,
    perturb: str = "remove",
    step_index: int = -1,
    max_steps: int = MAX_STEPS,
    max_requests: int = DEFAULT_REQUEST_CAP,
    timeout: int = 15,
    allow_mutation: bool | None = None,
) -> dict[str, Any]:
    # Compatibility-only flag; request safety is not inferred or gated here.
    del allow_mutation
    if max_steps < 2 or max_steps > MAX_STEPS:
        raise ValueError(f"max_steps must be between 2 and {MAX_STEPS}")
    if max_requests < 2:
        raise ValueError("max_requests must be at least 2")
    if perturb not in {"remove", "repeat"}:
        raise ValueError("perturb must be remove or repeat")
    evidence = _safe_input(repo_root, evidence_ref)
    payload = json.loads(evidence.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("workflow evidence must be a JSON object")
    resolved_target = canonical_target_value(target)
    steps = _extract_steps(payload, target=resolved_target, max_steps=max_steps)
    if step_index < 0:
        step_index = len(steps) - 1
    if step_index >= len(steps):
        raise ValueError("step_index is outside the recorded sequence")
    evidence_stat = evidence.stat()
    transition = f"{evidence}:{evidence_stat.st_size}:{evidence_stat.st_mtime_ns}:{perturb}:{step_index}"
    run_id = hashlib.sha256(transition.encode()).hexdigest()[:16]
    target_key = target_storage_key(resolved_target)
    summary_path = repo_root / "findings" / target_key / "workflow_sequence" / run_id / "summary.json"
    private_dir = private_artifact_dir(repo_root, "workflow-sequence", target_key, run_id)
    summary: dict[str, Any] = {
        "schema_version": 1,
        "kind": "workflow_sequence_summary",
        "target": resolved_target,
        "status": "partial",
        "evidence_ref": _rel(evidence, repo_root),
        "summary_path": _rel(summary_path, repo_root),
        "step_count": len(steps),
        "perturbation": {"kind": perturb, "step_index": step_index},
        "request_budget": max_requests,
        "request_count": 0,
        "token_refresh_count": 0,
        "errors": [],
        "diffs": [],
    }
    active_session = (session or AuthSession()).bind_target(resolved_target)
    baseline_steps = list(steps)
    variant_steps = list(steps)
    selected = variant_steps[step_index]
    if perturb == "remove":
        variant_steps.pop(step_index)
    else:
        variant_steps.insert(step_index + 1, {**selected, "id": f"{selected['id']}-repeat"})
    required_requests = len(baseline_steps) + len(variant_steps) + sum(
        bool(step.get("token")) for step in baseline_steps + variant_steps
    )
    if required_requests > max_requests:
        summary["errors"].append("request budget is smaller than baseline plus perturbation sequence")
        summary["status"] = "partial"
        summary["queue"] = _queue_sequence_action(
            repo_root,
            resolved_target,
            _rel(evidence, repo_root),
            _rel(summary_path, repo_root),
            run_id,
            summary["status"],
        )
        _write_json_atomic(summary_path, summary)
        return summary

    raw: dict[str, Any] = {"baseline": [], "variant": []}

    def execute(label: str, plan: list[dict[str, Any]]) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for step in plan:
            needed = 2 if step.get("token") else 1
            if summary["request_count"] + needed > max_requests:
                summary["errors"].append("request budget exhausted before workflow step")
                break
            try:
                response, refreshed = _step_request(step, target=resolved_target, session=active_session, timeout=timeout)
                summary["request_count"] += 1 + refreshed
                summary["token_refresh_count"] += refreshed
                results.append({"id": step["id"], "response": response})
                raw[label].append({
                    "id": step["id"],
                    "request": response.get("request_text", ""),
                    "response": response.get("response_text", ""),
                    "requested_url": response.get("requested_url") or response.get("url", ""),
                    "final_url": response.get("final_url") or response.get("url", ""),
                    "redirect_chain": response.get("redirect_chain") or [],
                })
            except Exception as exc:
                summary["errors"].append({"step": step["id"], "type": type(exc).__name__, "reason": str(exc)[:240]})
                break
        return results

    baseline_results = execute("baseline", baseline_steps)
    variant_results = execute("variant", variant_steps) if not summary["errors"] else []
    write_private_json(private_dir / "sequence.json", raw)
    base_by_id = {item["id"]: item["response"] for item in baseline_results}
    variant_by_id = {item["id"]: item["response"] for item in variant_results}
    for step_id in [item["id"] for item in baseline_steps if item["id"] in variant_by_id]:
        if step_id not in base_by_id:
            continue
        baseline = base_by_id[step_id]
        variant = variant_by_id[step_id]
        summary["diffs"].append({
            "step": step_id,
            "changed": _material_diff(baseline, variant),
            "baseline": _summary_snapshot(baseline),
            "variant": _summary_snapshot(variant),
        })
    summary["evidence_artifact"] = _rel(private_dir / "sequence.json", repo_root)
    if summary["errors"] or summary["request_count"] >= max_requests:
        summary["status"] = "partial"
    elif any(item.get("changed") for item in summary["diffs"]):
        summary["status"] = "candidate_pending"
    else:
        summary["status"] = "tested_clean"
    summary["queue"] = _queue_sequence_action(
        repo_root,
        resolved_target,
        _rel(evidence, repo_root),
        _rel(summary_path, repo_root),
        run_id,
        summary["status"],
    )
    if summary["queue"].get("status") == "error" and summary["status"] == "tested_clean":
        summary["status"] = "partial"
    _write_json_atomic(summary_path, summary)
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Replay and perturb an evidence-backed workflow sequence")
    parser.add_argument("--target", required=True)
    parser.add_argument("--evidence-ref", required=True)
    parser.add_argument("--repo-root", default=str(BASE_DIR))
    parser.add_argument("--perturb", choices=("remove", "repeat"), default="remove")
    parser.add_argument("--step-index", type=int, default=-1)
    parser.add_argument("--max-steps", type=int, default=MAX_STEPS)
    parser.add_argument("--max-requests", type=int, default=DEFAULT_REQUEST_CAP)
    parser.add_argument("--timeout", type=int, default=15)
    parser.add_argument("--allow-mutation", action="store_true", help=argparse.SUPPRESS)
    add_cli_args(parser)
    args = parser.parse_args(argv)
    try:
        summary = run_sequence(
            repo_root=Path(args.repo_root),
            target=args.target,
            evidence_ref=args.evidence_ref,
            session=session_from_args(args),
            perturb=args.perturb,
            step_index=args.step_index,
            max_steps=args.max_steps,
            max_requests=args.max_requests,
            timeout=args.timeout,
            allow_mutation=args.allow_mutation,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "invalid_input", "error": str(exc)[:300]}), file=sys.stderr)
        return 2
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if summary.get("status") not in {"partial", "invalid_input"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
