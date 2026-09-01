#!/usr/bin/env python3
"""Bounded, interleaved timing validation for SQL-shaped candidates."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import statistics
import sys
import tempfile
import time
import urllib.parse
from pathlib import Path
from typing import Any

try:
    from tools.action_queue import add_manual_action, claim_next_action, resolve_action
    from tools.auth_session import add_cli_args, session_from_args, AuthSession
    from tools.browser_surface import public_url_shape
    from tools.private_artifacts import private_artifact_dir, write_private_json
    from tools.target_paths import canonical_target_value, target_storage_key, url_belongs_to_target
    from tools.validation_runner import request_once
except ImportError:  # pragma: no cover
    from action_queue import add_manual_action, claim_next_action, resolve_action  # type: ignore
    from auth_session import add_cli_args, session_from_args, AuthSession  # type: ignore
    from browser_surface import public_url_shape  # type: ignore
    from private_artifacts import private_artifact_dir, write_private_json  # type: ignore
    from target_paths import canonical_target_value, target_storage_key, url_belongs_to_target  # type: ignore
    from validation_runner import request_once  # type: ignore

BASE_DIR = Path(__file__).resolve().parents[1]
DEFAULT_REPEAT = 5
DEFAULT_CAP = 20
DEFAULT_DELTA_MS = 1000.0
USER_AGENT = "ccst/timing-sql-runner"
_WAF_MARKERS = (
    "access denied",
    "request blocked",
    "web application firewall",
    "captcha required",
    "challenge required",
)


def _rel(path: Path, repo_root: Path) -> str:
    try:
        return str(path.relative_to(repo_root))
    except ValueError:
        return str(path)


def _mutated_request(url: str, method: str, body: str, param: str, value: str) -> tuple[str, bytes | None, str]:
    if not param:
        raise ValueError("param is required")
    if method == "GET":
        parts = urllib.parse.urlsplit(url)
        pairs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
        if not any(name == param for name, _ in pairs):
            raise ValueError(f"query parameter not found: {param}")
        index = next(i for i, (name, _) in enumerate(pairs) if name == param)
        mutated = list(pairs)
        mutated[index] = (mutated[index][0], value)
        encoded = urllib.parse.urlencode(mutated, doseq=True)
        parts = urllib.parse.urlsplit(url)
        mutated_url = urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, encoded, parts.fragment))
        return mutated_url, None, ""
    pairs = urllib.parse.parse_qsl(body, keep_blank_values=True)
    if not any(name == param for name, _ in pairs):
        raise ValueError(f"form parameter not found: {param}")
    mutated = list(pairs)
    index = next(i for i, (name, _) in enumerate(mutated) if name == param)
    mutated[index] = (mutated[index][0], value)
    return url, urllib.parse.urlencode(mutated, doseq=True).encode("utf-8"), "application/x-www-form-urlencoded"


def _http_request(
    url: str,
    *,
    method: str,
    body: bytes | None = None,
    content_type: str = "",
    timeout: float,
    target: str,
    session: AuthSession | None,
) -> dict[str, Any]:
    """Adapt the shared HTTP replay boundary to the timing sampler shape."""
    started = time.time()
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json,text/html;q=0.9,*/*;q=0.1"}
    if content_type:
        headers["Content-Type"] = content_type
    body_text = body.decode("utf-8", errors="replace") if isinstance(body, bytes) else (body or "")
    try:
        response = request_once(
            target=target,
            url=url,
            method=method,
            headers=headers,
            body=body_text,
            timeout=timeout,
            max_body_bytes=64 * 1024,
            session=session,
        )
    except Exception as exc:
        return {
            "status": 0,
            "body_text": "",
            "body_size": 0,
            "headers": "",
            "latency": time.time() - started,
            "error": f"{type(exc).__name__}:{exc}",
        }
    response_headers = response.get("headers") or {}
    if isinstance(response_headers, dict):
        response_headers = "\n".join(f"{key}: {value}" for key, value in response_headers.items())
    response_body = str(response.get("body") or "")
    return {
        "status": int(response.get("status") or 0),
        "body_text": response_body,
        "body_size": int(response.get("body_retained_bytes") or len(response_body.encode("utf-8"))),
        "headers": str(response_headers),
        "latency": time.time() - started,
        "error": None,
    }


def _waf_observation(baseline: dict[str, Any], response: dict[str, Any]) -> dict[str, Any]:
    """Classify only a new block signal relative to the baseline response."""
    baseline_status = int(baseline.get("status") or 0)
    response_status = int(response.get("status") or 0)
    if baseline.get("error") or baseline_status <= 0:
        return {"blocked": False, "signals": [], "status": response_status, "outcome": "baseline_unavailable"}
    if response.get("error") or response_status <= 0:
        return {"blocked": False, "signals": [], "status": response_status, "outcome": "transport_error"}
    baseline_body = str(baseline.get("body_text") or "").lower()
    response_body = str(response.get("body_text") or "").lower()
    signals = []
    if response_status in {403, 406} and baseline_status not in {403, 406}:
        signals.append("block_status_delta")
    if any(marker in response_body and marker not in baseline_body for marker in _WAF_MARKERS):
        signals.append("block_body")
    outcome = "waf_blocked" if signals else ("rate_limited" if response_status == 429 else "application_response")
    return {"blocked": bool(signals), "signals": signals, "status": response_status, "outcome": outcome}


def _write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    """Persist a summary without exposing a partially written JSON file."""
    path.parent.mkdir(parents=True, exist_ok=True)
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
            handle.write(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
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


def _median(values: list[float]) -> float:
    return float(statistics.median(values)) if values else 0.0


def _mad(values: list[float], center: float) -> float:
    return _median([abs(value - center) for value in values])


def _public_body_shape(body: str) -> str:
    pairs = urllib.parse.parse_qsl(str(body or ""), keep_blank_values=True)
    return urllib.parse.urlencode([(name, "") for name, _ in pairs], doseq=True)


def _queue_action(
    repo_root: Path,
    target: str,
    summary_path: str,
    url: str,
    param: str,
    generation: str,
    status: str,
    *,
    method: str = "GET",
    body: str = "",
    resolve: bool = False,
) -> dict[str, Any]:
    source_id = hashlib.sha256(
        f"{url}|{param}|{method}|{generation}".encode("utf-8")
    ).hexdigest()[:20]
    safe_url = public_url_shape(url)
    try:
        safe_body = _public_body_shape(body)
        recovery_hint = (
            "python3 tools/timing_sql_runner.py --target "
            f"{shlex.quote(target)} --url {shlex.quote(safe_url)}"
            f" --param {shlex.quote(param)} --variant-value PAYLOAD --baseline-value BASELINE"
        )
        if str(method).upper() == "POST":
            recovery_hint += f" --method POST --body {shlex.quote(safe_body)}"
        result = add_manual_action(
            repo_root,
            target=target,
            action_type="sql-timing-validation",
            evidence=f"Timing SQL evidence: {summary_path}",
            next_question="Is the interleaved timing trend stable after excluding WAF, 429, and transport noise?",
            action=f"Review bounded timing SQL evidence for {safe_url} parameter {param}: {summary_path}",
            priority=90,
            command_hint=recovery_hint,
            source="sql-timing",
            source_id=source_id,
            generation=generation,
            stop_condition="record stable candidate, complete_no_hit, blocked, or transport-limited partial result",
        )
        queue = result.get("queue") if isinstance(result, dict) else {}
        stats = result.get("stats") if isinstance(result, dict) else {}
        action = next(
            (item for item in (queue.get("actions") or [])
             if isinstance(item, dict) and str(item.get("source_id") or "") == source_id),
            {},
        )
        action_id = str(action.get("id") or "")
        current = str(action.get("status") or "queued")
        if int((stats or {}).get("skipped_final", 0) or 0) > 0:
            return {
                "status": "already_final",
                "action_id": action_id,
                "action_status": current,
            }
        final = {"complete_no_hit": "tested", "candidate_pending": "candidate", "manual_required": "blocked"}.get(status)
        if action_id and current == "queued":
            claimed = claim_next_action(repo_root, target=target, action_id=action_id)
            current = str(claimed.get("status") or "running")
        if resolve and action_id and final and current not in {"tested", "candidate", "dead-end", "blocked", "validated", "reported", "n/a"}:
            current = str(resolve_action(
                repo_root,
                target=target,
                action_id=action_id,
                status=final,
                result=summary_path,
                notes=f"timing SQL status={status}; summary={summary_path}",
            ).get("status") or final)
        return {"status": "ok", "action_id": action_id, "action_status": current}
    except (OSError, KeyError, ValueError) as exc:
        return {"status": "error", "error": str(exc)[:240]}


def run_timing_sql(
    *,
    repo_root: Path,
    target: str,
    url: str,
    param: str,
    variant_value: str,
    baseline_value: str = "",
    method: str = "GET",
    body: str = "",
    repeat: int = DEFAULT_REPEAT,
    max_requests: int = DEFAULT_CAP,
    timeout: float = 12.0,
    min_delta_ms: float = DEFAULT_DELTA_MS,
    session: AuthSession | None = None,
) -> dict[str, Any]:
    method = str(method or "GET").upper()
    if method not in {"GET", "POST"}:
        raise ValueError("timing SQL supports GET or POST only")
    if repeat < 3:
        raise ValueError("repeat must be at least 3 to reject a single slow sample")
    if max_requests < 2:
        raise ValueError("max_requests must be at least 2")
    if min_delta_ms <= 0:
        raise ValueError("min_delta_ms must be positive")
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    target = canonical_target_value(target)
    if not url_belongs_to_target(url, target):
        raise ValueError("timing SQL URL is outside target scope")
    probe_url, probe_body, content_type = _mutated_request(url, method, body, param, variant_value)
    if not baseline_value:
        if method == "GET":
            baseline_value = next(
                (value for name, value in urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query, keep_blank_values=True) if name == param),
                "",
            )
        else:
            baseline_value = next((value for name, value in urllib.parse.parse_qsl(body, keep_blank_values=True) if name == param), "")
    if baseline_value == "":
        raise ValueError("baseline_value is required or must be present in the input")
    baseline_url, baseline_body, _ = _mutated_request(url, method, body, param, baseline_value)
    generation = hashlib.sha256(json.dumps({"url": url, "method": method, "body": body, "param": param, "variant": variant_value, "baseline": baseline_value}, sort_keys=True).encode()).hexdigest()[:16]
    run_id = generation
    target_key = target_storage_key(target)
    private_dir = private_artifact_dir(repo_root, "sql-timing", target_key, run_id)
    summary_path = repo_root / "findings" / target_key / "poc" / "sql_timing" / run_id / "summary.json"
    summary: dict[str, Any] = {
        "schema_version": 1,
        "kind": "sql_timing_summary",
        "target": target,
        "url": public_url_shape(url),
        "method": method,
        "param": param,
        "variant_value_sha256": hashlib.sha256(variant_value.encode()).hexdigest(),
        "baseline_value_sha256": hashlib.sha256(baseline_value.encode()).hexdigest(),
        "status": "partial",
        "request_budget": max_requests,
        "request_count": 0,
        "transport_error_count": 0,
        "waf_observation_count": 0,
        "repeat": repeat,
        "min_delta_ms": min_delta_ms,
        "samples": [],
        "errors": [],
    }
    active_session = (session or AuthSession()).bind_target(target)
    # Claim before requests so an interrupted run leaves a recoverable action.
    summary["queue"] = _queue_action(
        repo_root, target, _rel(summary_path, repo_root), url, param, generation, summary["status"],
        method=method, body=body,
    )
    if summary["queue"].get("status") == "error":
        summary["errors"].append({"queue": summary["queue"].get("error", "queue claim failed")})
        _write_json_atomic(summary_path, summary)
        return summary
    if summary["queue"].get("status") == "already_final":
        try:
            existing = json.loads(summary_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            summary["status"] = "partial"
            summary["errors"].append("terminal queue action has no readable summary")
            _write_json_atomic(summary_path, summary)
            return summary
        if isinstance(existing, dict):
            existing["queue"] = summary["queue"]
            return existing
        summary["status"] = "partial"
        summary["errors"].append("terminal queue action summary is not an object")
        _write_json_atomic(summary_path, summary)
        return summary
    while len(summary["samples"]) < repeat and summary["request_count"] + 2 <= max_requests:
        iteration = len(summary["samples"]) + 1
        sample: dict[str, Any] = {"iteration": iteration}
        try:
            base = _http_request(
                baseline_url,
                method=method,
                body=baseline_body,
                content_type=content_type,
                timeout=timeout,
                target=target,
                session=active_session,
            )
            summary["request_count"] += 1
            variant = _http_request(
                probe_url,
                method=method,
                body=probe_body,
                content_type=content_type,
                timeout=timeout,
                target=target,
                session=active_session,
            )
            summary["request_count"] += 1
        except Exception as exc:
            summary["errors"].append({"iteration": iteration, "type": type(exc).__name__, "reason": str(exc)[:240]})
            break
        for response in (base, variant):
            if response.get("error") or int(response.get("status") or 0) <= 0:
                summary["transport_error_count"] += 1
        try:
            waf = _waf_observation(base, variant)
        except Exception as exc:
            summary["errors"].append({"iteration": iteration, "type": type(exc).__name__, "reason": str(exc)[:240]})
            break
        baseline_status = int(base.get("status") or 0)
        variant_status = int(variant.get("status") or 0)
        baseline_rate_limited = baseline_status == 429
        rate_limited = baseline_rate_limited or variant_status == 429
        baseline_waf_blocked = baseline_status in {403, 406}
        waf_blocked = bool(waf.get("blocked") or baseline_waf_blocked)
        if waf_blocked or rate_limited:
            summary["waf_observation_count"] += 1
        sample.update({
            "baseline_ms": round(float(base.get("latency") or 0.0) * 1000, 3),
            "variant_ms": round(float(variant.get("latency") or 0.0) * 1000, 3),
            "baseline_status": baseline_status,
            "variant_status": variant_status,
            "variant_body_sha256": hashlib.sha256(str(variant.get("body_text") or "").encode()).hexdigest(),
            "variant_body_size": int(variant.get("body_size") or 0),
            "waf_blocked": waf_blocked,
            "rate_limited": rate_limited,
            "baseline_waf_blocked": baseline_waf_blocked,
            "baseline_rate_limited": baseline_rate_limited,
        })
        summary["samples"].append(sample)
        if sample["rate_limited"] or sample["waf_blocked"]:
            summary["errors"].append("waf_or_rate_limit")
    valid_samples = [
        item for item in summary["samples"]
        if item["baseline_status"] > 0
        and item["variant_status"] > 0
        and not item.get("rate_limited")
        and not item.get("waf_blocked")
    ]
    baseline_times = [float(item["baseline_ms"]) for item in valid_samples]
    variant_times = [float(item["variant_ms"]) for item in valid_samples]
    baseline_median = _median(baseline_times)
    variant_median = _median(variant_times)
    deltas = [float(item["variant_ms"]) - float(item["baseline_ms"]) for item in valid_samples]
    stable_hits = sum(delta >= min_delta_ms for delta in deltas)
    stable = bool(
        len(deltas) >= 3
        and stable_hits >= (len(deltas) + 1) // 2 + 1
        and variant_median - baseline_median >= min_delta_ms
        and _mad(deltas, _median(deltas)) <= max(min_delta_ms, abs(_median(deltas)) * 0.5)
    )
    summary["statistics"] = {
        "baseline_median_ms": round(baseline_median, 3),
        "variant_median_ms": round(variant_median, 3),
        "delta_median_ms": round(variant_median - baseline_median, 3),
        "delta_mad_ms": round(_mad(deltas, _median(deltas)), 3) if deltas else 0.0,
        "stable_hits": stable_hits,
        "sample_count": len(deltas),
    }
    try:
        write_private_json(private_dir / "samples.json", summary["samples"])
        summary["evidence_artifact"] = _rel(private_dir / "samples.json", repo_root)
    except Exception as exc:
        summary["errors"].append({"artifact": type(exc).__name__, "reason": str(exc)[:240]})
    if summary["errors"] or summary["transport_error_count"]:
        summary["status"] = "partial"
    elif stable:
        summary["status"] = "candidate_pending"
    elif len(summary["samples"]) < repeat:
        summary["status"] = "partial"
    else:
        summary["status"] = "complete_no_hit"
    # Queue terminal evidence must exist before resolve_action is called.
    _write_json_atomic(summary_path, summary)
    if summary["status"] in {"complete_no_hit", "candidate_pending", "manual_required"}:
        summary["queue"] = _queue_action(
            repo_root, target, _rel(summary_path, repo_root), url, param, generation, summary["status"],
            method=method, body=body, resolve=True
        )
    if summary["queue"].get("status") == "error" and summary["status"] in {"complete_no_hit", "candidate_pending"}:
        summary["status"] = "partial"
    if summary["queue"].get("status") == "error" and summary["status"] == "manual_required":
        summary["status"] = "partial"
    _write_json_atomic(summary_path, summary)
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Bounded interleaved timing SQL validation")
    parser.add_argument("--target", required=True)
    parser.add_argument("--url", required=True)
    parser.add_argument("--param", required=True)
    parser.add_argument("--variant-value", required=True)
    parser.add_argument("--baseline-value", default="")
    parser.add_argument("--method", default="GET")
    parser.add_argument("--body", default="")
    parser.add_argument("--repeat", type=int, default=DEFAULT_REPEAT)
    parser.add_argument("--max-requests", type=int, default=DEFAULT_CAP)
    parser.add_argument("--timeout", type=float, default=12.0)
    parser.add_argument("--min-delta-ms", type=float, default=DEFAULT_DELTA_MS)
    parser.add_argument("--repo-root", default=str(BASE_DIR))
    add_cli_args(parser)
    args = parser.parse_args(argv)
    try:
        summary = run_timing_sql(
            repo_root=Path(args.repo_root), target=args.target, url=args.url,
            param=args.param, variant_value=args.variant_value,
            baseline_value=args.baseline_value, method=args.method, body=args.body,
            repeat=args.repeat, max_requests=args.max_requests, timeout=args.timeout,
            min_delta_ms=args.min_delta_ms, session=session_from_args(args),
        )
    except (OSError, ValueError) as exc:
        print(json.dumps({"status": "invalid_input", "error": str(exc)[:300]}), file=sys.stderr)
        return 2
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if summary.get("status") in {"complete_no_hit", "candidate_pending"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
