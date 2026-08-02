#!/usr/bin/env python3
"""Bounded, interleaved timing validation for SQL-shaped candidates."""

from __future__ import annotations

import argparse
import hashlib
import json
import shlex
import statistics
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Any

try:
    from tools import sql_parameter_probe as core
    from tools.action_queue import add_manual_action, resolve_action
    from tools.auth_session import add_cli_args, session_from_args, AuthSession
    from tools.json_inject_probe import _write_json_atomic
    from tools.private_artifacts import private_artifact_dir, write_private_json
    from tools.target_paths import canonical_target_value, target_storage_key, url_belongs_to_target
except ImportError:  # pragma: no cover
    import sql_parameter_probe as core  # type: ignore
    from action_queue import add_manual_action, resolve_action  # type: ignore
    from auth_session import add_cli_args, session_from_args, AuthSession  # type: ignore
    from json_inject_probe import _write_json_atomic  # type: ignore
    from private_artifacts import private_artifact_dir, write_private_json  # type: ignore
    from target_paths import canonical_target_value, target_storage_key, url_belongs_to_target  # type: ignore

BASE_DIR = Path(__file__).resolve().parents[1]
DEFAULT_REPEAT = 5
DEFAULT_CAP = 20
DEFAULT_DELTA_MS = 1000.0


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
        mutated_url, _ = core._mutate_parameter(url, pairs, index, value, "query")
        return mutated_url, None, ""
    pairs = urllib.parse.parse_qsl(body, keep_blank_values=True)
    if not any(name == param for name, _ in pairs):
        raise ValueError(f"form parameter not found: {param}")
    index = next(i for i, (name, _) in enumerate(pairs) if name == param)
    mutated_url, mutated_body = core._mutate_parameter(url, pairs, index, value, "form")
    return mutated_url, mutated_body, "application/x-www-form-urlencoded"


def _median(values: list[float]) -> float:
    return float(statistics.median(values)) if values else 0.0


def _mad(values: list[float], center: float) -> float:
    return _median([abs(value - center) for value in values])


def _queue_action(
    repo_root: Path,
    target: str,
    summary_path: str,
    url: str,
    param: str,
    generation: str,
    status: str,
) -> dict[str, Any]:
    source_id = hashlib.sha256(f"{url}|{param}".encode("utf-8")).hexdigest()[:20]
    try:
        result = add_manual_action(
            repo_root,
            target=target,
            action_type="sql-timing-validation",
            evidence=f"Timing SQL evidence: {summary_path}",
            next_question="Is the interleaved timing trend stable after excluding WAF, 429, and transport noise?",
            action=f"Review bounded timing SQL evidence for {url} parameter {param}: {summary_path}",
            priority=90,
            command_hint=(
                "python3 tools/timing_sql_runner.py --target "
                f"{shlex.quote(target)} --url {shlex.quote(url)} --param {shlex.quote(param)}"
            ),
            source="sql-timing",
            source_id=source_id,
            generation=generation,
            stop_condition="record stable candidate, complete_no_hit, blocked, or transport-limited partial result",
        )
        queue = result.get("queue") if isinstance(result, dict) else {}
        action = next(
            (item for item in (queue.get("actions") or [])
             if isinstance(item, dict) and str(item.get("source_id") or "") == source_id),
            {},
        )
        action_id = str(action.get("id") or "")
        current = str(action.get("status") or "queued")
        final = {"complete_no_hit": "tested", "candidate_pending": "candidate", "manual_required": "blocked"}.get(status)
        if action_id and final and current not in {"tested", "candidate", "dead-end", "blocked", "validated", "reported", "n/a"}:
            current = str(resolve_action(
                repo_root,
                target=target,
                action_id=action_id,
                status=final,
                result=f"timing-sql-result={status}",
                notes=f"summary={summary_path}",
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
        "url": core.public_url_shape(url),
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
    while len(summary["samples"]) < repeat and summary["request_count"] + 2 <= max_requests:
        iteration = len(summary["samples"]) + 1
        sample: dict[str, Any] = {"iteration": iteration}
        base = core._http_request(
            baseline_url,
            method=method,
            body=baseline_body,
            content_type=content_type,
            timeout=timeout,
            target=target,
            session=active_session,
        )
        variant = core._http_request(
            probe_url,
            method=method,
            body=probe_body,
            content_type=content_type,
            timeout=timeout,
            target=target,
            session=active_session,
        )
        summary["request_count"] += 2
        for response in (base, variant):
            if response.get("error") or int(response.get("status") or 0) <= 0:
                summary["transport_error_count"] += 1
        waf = core.core._waf_observation(base, variant)
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
    baseline_times = [float(item["baseline_ms"]) for item in summary["samples"] if item["baseline_status"] > 0]
    variant_times = [float(item["variant_ms"]) for item in summary["samples"] if item["variant_status"] > 0]
    baseline_median = _median(baseline_times)
    variant_median = _median(variant_times)
    deltas = [float(item["variant_ms"]) - float(item["baseline_ms"]) for item in summary["samples"]]
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
    write_private_json(private_dir / "samples.json", summary["samples"])
    summary["evidence_artifact"] = _rel(private_dir / "samples.json", repo_root)
    if summary["errors"] or summary["transport_error_count"]:
        summary["status"] = "partial"
    elif stable:
        summary["status"] = "candidate_pending"
    elif len(summary["samples"]) < repeat:
        summary["status"] = "partial"
    else:
        summary["status"] = "complete_no_hit"
    summary["queue"] = _queue_action(repo_root, target, _rel(summary_path, repo_root), url, param, generation, summary["status"])
    if summary["queue"].get("status") == "error" and summary["status"] == "complete_no_hit":
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
