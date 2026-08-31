#!/usr/bin/env python3
"""Run the shared SQL matrix against query-string or form parameters.

JSON POST callers stay on ``json_inject_probe``; this adapter reuses its
baseline-relative detection, WAF handling, request budget, and the shared
``SQL_PAYLOADS`` catalog for non-JSON parameter surfaces.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

try:
    from tools import json_inject_probe as core
    from tools.auth_session import add_cli_args, session_from_args, AuthSession
    from tools.browser_surface import public_url_shape
    from tools.sql_payloads import SQL_PAYLOADS
    from tools.target_paths import canonical_target_value, target_storage_key, url_belongs_to_target
except ImportError:  # pragma: no cover
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import json_inject_probe as core  # type: ignore
    from auth_session import add_cli_args, session_from_args, AuthSession  # type: ignore
    from browser_surface import public_url_shape  # type: ignore
    from sql_payloads import SQL_PAYLOADS  # type: ignore
    from target_paths import canonical_target_value, target_storage_key, url_belongs_to_target  # type: ignore

BASE_DIR = Path(__file__).resolve().parent.parent
USER_AGENT = "claude-bug-bounty/sql_parameter_probe"
SUMMARY_ITEM_LIMIT = 100


def _source_binding(
    path_value: str,
    *,
    repo_root: str | Path | None = None,
) -> dict:
    """Return a redacted, replay-freshness binding for an input artifact."""
    if not path_value:
        return {}
    path = Path(path_value).expanduser().resolve()
    if not path.is_file():
        return {}
    root = Path(repo_root) if repo_root is not None else BASE_DIR
    try:
        display = str(path.relative_to(root))
    except ValueError:
        display = str(path)
    data = path.read_bytes()
    return {"path": display, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}


def _input_fingerprint(endpoints: list[dict], source_bindings: list[dict]) -> str:
    canonical = {
        "endpoints": [
            {
                "method": str(item.get("method") or "GET"),
                "url": str(item.get("url") or ""),
                "body": str(item.get("body") or ""),
            }
            for item in endpoints
        ],
        "sources": source_bindings,
    }
    encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _http_request(
    url: str,
    *,
    method: str,
    body: bytes | None = None,
    content_type: str = "",
    timeout: float,
    target: str,
    session: AuthSession | None,
) -> dict:
    if target and not url_belongs_to_target(url, target):
        return {
            "status": 0,
            "body_text": "",
            "body_size": 0,
            "headers": "",
            "latency": 0.0,
            "error": f"OutOfScopeURL:{public_url_shape(url)}",
        }
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json,text/html;q=0.9,*/*;q=0.1",
    }
    if content_type:
        headers["Content-Type"] = content_type
    if session is not None:
        headers.update(session.headers_for_url(url))
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    started = time.time()
    try:
        opener = urllib.request.build_opener(core._ScopedRedirectHandler(target or url, session))
        with opener.open(request, timeout=timeout) as response:
            raw = response.read(64 * 1024)
            return {
                "status": response.status,
                "body_text": raw.decode("utf-8", errors="replace"),
                "body_size": len(raw),
                "headers": "\n".join(f"{key}: {value}" for key, value in response.headers.items()),
                "latency": time.time() - started,
                "error": None,
            }
    except urllib.error.HTTPError as exc:
        try:
            raw = exc.read(64 * 1024)
        except Exception:
            raw = b""
        return {
            "status": exc.code,
            "body_text": raw.decode("utf-8", errors="replace"),
            "body_size": len(raw),
            "headers": "\n".join(f"{key}: {value}" for key, value in (exc.headers or {}).items()),
            "latency": time.time() - started,
            "error": None,
        }
    except Exception as exc:  # transport errors are recorded, never findings
        return {
            "status": 0,
            "body_text": "",
            "body_size": 0,
            "headers": "",
            "latency": time.time() - started,
            "error": f"{type(exc).__name__}:{exc}",
        }


def _parameter_source(endpoint: dict, mode: str) -> tuple[str, str, list[tuple[str, str]], str] | None:
    url = str(endpoint.get("url") or "").strip()
    if mode == "query":
        if str(endpoint.get("method") or "GET").strip().upper() != "GET":
            return None
        parts = urllib.parse.urlsplit(url)
        pairs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
        return url, "GET", pairs, ""
    if str(endpoint.get("method") or "POST").strip().upper() != "POST":
        return None
    body = endpoint.get("body")
    if not isinstance(body, str):
        return None
    pairs = urllib.parse.parse_qsl(body, keep_blank_values=True)
    return url, str(endpoint.get("method") or "POST").upper(), pairs, "application/x-www-form-urlencoded"


def _mutate_parameter(url: str, pairs: list[tuple[str, str]], index: int, value: str, mode: str) -> tuple[str, bytes | None]:
    mutated = list(pairs)
    mutated[index] = (mutated[index][0], value)
    encoded = urllib.parse.urlencode(mutated, doseq=True)
    if mode == "query":
        parts = urllib.parse.urlsplit(url)
        return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, encoded, parts.fragment)), None
    return url, encoded.encode("utf-8")


def _hit_record(url: str, method: str, field: str, payload: dict, value: str, response: dict, detection: dict, *, body: bytes | None = None) -> dict:
    record = {
        "url": url,
        "method": method,
        "field": field,
        "payload_class": payload["class"],
        "payload_value": value,
        "payload_family": payload.get("family", payload["class"]),
        "signal": detection["signal"],
        "evidence": detection["evidence"],
        "response_status": response["status"],
        "response_size": response["body_size"],
        "response_excerpt": response["body_text"][:280],
    }
    if payload.get("dbms"):
        record["dbms"] = payload["dbms"]
    if body is None:
        record["reproducer"] = f"curl -sk '{url}'"
    else:
        record["reproducer"] = f"curl -sk -X {method} '{url}' --data '{body.decode('utf-8', errors='replace')}'"
    return record


def probe_parameter_endpoint(
    endpoint: dict,
    *,
    mode: str,
    max_requests: int,
    target: str,
    session: AuthSession | None,
    waf_plan: dict | None = None,
    stats: dict | None = None,
) -> tuple[list[dict], list[dict]]:
    source = _parameter_source(endpoint, mode)
    if source is None:
        return [], []
    if waf_plan and waf_plan.get("max_requests") is not None:
        max_requests = min(max_requests, int(waf_plan["max_requests"]))
    url, method, pairs, content_type = source
    if not pairs:
        return [], []
    baseline_body = urllib.parse.urlencode(pairs, doseq=True).encode("utf-8") if mode == "form" else None
    baseline = _http_request(
        url,
        method=method,
        body=baseline_body,
        content_type=content_type,
        timeout=10.0,
        target=target,
        session=session,
    )
    core._record_request(stats, baseline)
    request_count = 1
    if baseline.get("error") or int(baseline.get("status") or 0) <= 0:
        return [], []

    fields: dict[str, str] = {}
    field_indexes: dict[str, int] = {}
    for index, (name, value) in enumerate(pairs):
        if name not in fields:
            fields[name] = value
            field_indexes[name] = index
    plan = core._payload_field_plan(fields, SQL_PAYLOADS)
    hits: list[dict] = []
    waf_events: list[dict] = []
    pair_responses: dict[tuple[str, str], dict[str, dict]] = {}
    reported_pairs: set[tuple[str, str]] = set()

    for payload, field in plan:
        if request_count >= max_requests:
            break
        index = field_indexes[field]
        probe_url, probe_body = _mutate_parameter(url, pairs, index, str(payload["value"]), mode)
        timeout = 12.0 if payload["class"].startswith("sqli_time") else 8.0
        response = _http_request(
            probe_url,
            method=method,
            body=probe_body,
            content_type=content_type,
            timeout=timeout,
            target=target,
            session=session,
        )
        core._record_request(stats, response)
        request_count += 1
        waf = core._waf_observation(baseline, response)
        if waf["outcome"] == "application_response":
            pair_id = str(payload.get("pair_id") or "")
            pair_side = str(payload.get("pair_side") or "")
            pair_key = (field, pair_id)
            pair_detection = {"hit": False, "signal": "", "evidence": ""}
            if pair_id and pair_side in {"true", "false"}:
                pair_responses.setdefault(pair_key, {})[pair_side] = response
                pair = pair_responses[pair_key]
                if pair_key not in reported_pairs and {"true", "false"}.issubset(pair):
                    pair_detection = core._boolean_pair_detection(pair["true"], pair["false"])
                    if pair_detection["hit"]:
                        reported_pairs.add(pair_key)
            detection = pair_detection if pair_detection["hit"] else core._detect_hit(
                payload["class"],
                baseline,
                response,
                str(payload["value"]),
                min_delay=float(payload.get("min_delay", 4.0) or 4.0),
            )
            if detection["hit"]:
                record = _hit_record(
                    probe_url,
                    method,
                    field,
                    payload,
                    str(payload["value"]),
                    response,
                    detection,
                    body=probe_body,
                )
                if pair_detection["hit"]:
                    record["payload_class"] = "sqli_boolean_pair"
                    record["pair_id"] = pair_id
                hits.append(record)
            continue
        if not waf["blocked"]:
            continue
        waf_events.append({
            "url": probe_url,
            "method": method,
            "field": field,
            "payload_class": payload["class"],
            "payload_family": payload.get("family", payload["class"]),
            "technique": "canonical",
            **waf,
        })
        for candidate in core._waf_retry_variants(
            waf_plan,
            url=url,
            field=field,
            payload=payload,
        ):
            if request_count >= max_requests:
                break
            technique = str(candidate.get("technique") or candidate.get("id") or "ai-variant")
            variant = str(candidate.get("value") or "")
            retry_url, retry_body = _mutate_parameter(url, pairs, index, variant, mode)
            retry = _http_request(
                retry_url,
                method=method,
                body=retry_body,
                content_type=content_type,
                timeout=timeout,
                target=target,
                session=session,
            )
            core._record_request(stats, retry)
            request_count += 1
            retry_waf = core._waf_observation(baseline, retry)
            event = {
                "url": retry_url,
                "method": method,
                "field": field,
                "payload_class": payload["class"],
                "payload_family": payload.get("family", payload["class"]),
                "technique": technique,
                "variant_source": candidate.get("source", "fallback"),
                **retry_waf,
            }
            if candidate.get("source") == "ai":
                event.update({
                    "variant_id": candidate.get("id", ""),
                    "ai_reason": candidate.get("reason", ""),
                    "expected_signal": candidate.get("expected_signal", ""),
                    "stop_condition": candidate.get("stop_condition", ""),
                    "evidence_refs": candidate.get("evidence_refs", []),
                })
            waf_events.append(event)
            if retry_waf["outcome"] in {"transport_error", "rate_limited"}:
                break
            if retry_waf["blocked"]:
                continue
            detection = core._detect_hit(
                payload["class"],
                baseline,
                retry,
                variant,
                min_delay=float(payload.get("min_delay", 4.0) or 4.0),
            )
            if detection["hit"]:
                record = _hit_record(retry_url, method, field, payload, variant, retry, detection, body=retry_body)
                record["waf_variant"] = technique
                record["variant_source"] = candidate.get("source", "fallback")
                if candidate.get("source") == "ai":
                    record.update({
                        "waf_variant_id": candidate.get("id", ""),
                        "ai_reason": candidate.get("reason", ""),
                        "expected_signal": candidate.get("expected_signal", ""),
                        "stop_condition": candidate.get("stop_condition", ""),
                        "evidence_refs": candidate.get("evidence_refs", []),
                    })
                hits.append(record)
            break
    return hits, waf_events


def _write_results(
    target: str,
    lane: str,
    hits: list[dict],
    waf_events: list[dict],
    execution: dict,
    *,
    repo_root: str | Path | None = None,
) -> dict:
    root = Path(repo_root) if repo_root is not None else BASE_DIR
    out_dir = root / "findings" / target_storage_key(target) / "poc" / "sql_matrix" / lane
    out_dir.mkdir(parents=True, exist_ok=True)
    summary_path = out_dir / "summary.json"
    details = dict(execution)
    resumed = bool(details.get("resumed"))
    previous: dict = {}
    if resumed and summary_path.is_file():
        try:
            loaded = json.loads(summary_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict) and loaded.get("input_fingerprint") == details.get("input_fingerprint"):
                previous = loaded
        except (OSError, json.JSONDecodeError):
            previous = {}
    if not previous:
        for stale in out_dir.glob("*.json"):
            if stale.name != "summary.json":
                stale.unlink()
    files: list[str] = []
    for hit in hits:
        slug = re.sub(r"[^A-Za-z0-9._-]+", "_", urllib.parse.urlparse(hit["url"]).path).strip("_") or "root"
        path = out_dir / f"{hit['payload_class']}_{slug}_{hit['field']}.json"
        path.write_text(json.dumps(hit, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        files.append(str(path))
    skipped = details.get("skipped") or {}
    prior_hits = previous.get("hits") if isinstance(previous.get("hits"), list) else []
    prior_waf = previous.get("waf_observations") if isinstance(previous.get("waf_observations"), list) else []
    prior_hit_count = int(previous.get("hit_count", 0) or 0) if previous else 0
    prior_waf_count = int(previous.get("waf_observation_count", 0) or 0) if previous else 0
    if not int(execution.get("endpoint_count") or 0) and any(int(value or 0) for value in skipped.values()):
        status = "invalid_input"
    elif hits or prior_hit_count:
        status = "candidate_pending"
    elif details.get("transport_error_count") or details.get("budget_exhausted") or any(int(value or 0) for value in skipped.values()):
        status = "partial"
    else:
        status = "complete_no_hit"
    current_hit_summaries = [
        {"url": item["url"], "field": item["field"], "class": item["payload_class"], "signal": item["signal"]}
        for item in hits
    ]
    merged_hits = core._merge_summary_items(prior_hits, current_hit_summaries)
    merged_waf = core._merge_summary_items(prior_waf, waf_events)
    payload = {
        "schema_version": 1,
        "kind": "sql_matrix_summary",
        "lane": lane,
        "target": canonical_target_value(target),
        "status": status,
        **details,
        "hit_count": prior_hit_count + core._new_summary_item_count(prior_hits, current_hit_summaries),
        "waf_observation_count": prior_waf_count + core._new_summary_item_count(prior_waf, waf_events),
        "generated_at": int(time.time()),
        "hits": merged_hits[:SUMMARY_ITEM_LIMIT],
        "waf_observations": merged_waf[:SUMMARY_ITEM_LIMIT],
    }
    core._write_json_atomic(summary_path, payload)
    return {"summary": str(summary_path), "files": files}


def _read_inputs(path: str, mode: str) -> list[dict]:
    items: list[dict] = []
    with Path(path).expanduser().open(encoding="utf-8", errors="replace") as handle:
        for raw in handle:
            raw = raw.strip()
            if not raw:
                continue
            if raw.startswith("{"):
                try:
                    item = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if isinstance(item, dict):
                    items.append(item)
            elif mode == "query":
                items.append({"url": raw, "method": "GET"})
    return items


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Shared SQL matrix for query-string and form parameters")
    parser.add_argument("--target", required=True)
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--urls-file", help="newline-delimited query URLs or JSONL")
    inputs.add_argument("--form-file", help="JSONL of POST form requests: {url, method, body}")
    parser.add_argument("--max-requests", type=int, default=60)
    parser.add_argument("--repo-root", default="", help="Repository root for plans and findings artifacts")
    parser.add_argument(
        "--waf-plan",
        default="",
        help="Optional target-owned AI WAF-pass plan JSON; only used after a new baseline-relative SQLi block",
    )
    add_cli_args(parser)
    args = parser.parse_args(argv)
    repo_root = Path(args.repo_root) if args.repo_root else BASE_DIR
    if args.max_requests < 1:
        parser.error("--max-requests must be a positive integer")
    target = canonical_target_value(args.target)
    mode = "query" if args.urls_file else "form"
    source = args.urls_file or args.form_file
    session = session_from_args(args).bind_target(target)
    try:
        waf_plan = (
            core.load_plan(args.waf_plan, target=target, repo_root=repo_root)
            if args.waf_plan
            else None
        )
    except ValueError as exc:
        parser.error(str(exc))
    endpoints = _read_inputs(source, mode)
    source_bindings = [
        binding
        for binding in (
            _source_binding(source, repo_root=repo_root),
            _source_binding(args.waf_plan, repo_root=repo_root),
        )
        if binding
    ]
    input_fingerprint = _input_fingerprint(endpoints, source_bindings)
    hits: list[dict] = []
    waf_events: list[dict] = []
    stats = {
        "input_fingerprint": input_fingerprint,
        "source_bindings": source_bindings,
        "request_count": 0,
        "transport_error_count": 0,
        "endpoint_count": 0,
        "probed_endpoint_count": 0,
        "skipped": {"out_of_scope": 0, "invalid": 0},
    }
    request_budget = int(args.max_requests)
    if waf_plan and waf_plan.get("max_requests") is not None:
        request_budget = min(request_budget, int(waf_plan["max_requests"]))
    eligible: list[dict] = []
    for endpoint in endpoints:
        url = str(endpoint.get("url") or "").strip()
        if not url or not url_belongs_to_target(url, target):
            stats["skipped"]["out_of_scope"] += 1
            continue
        source_shape = _parameter_source(endpoint, mode)
        if source_shape is None or not source_shape[2]:
            stats["skipped"]["invalid"] += 1
            continue
        stats["endpoint_count"] += 1
        eligible.append(endpoint)
    summary_path = repo_root / "findings" / target_storage_key(target) / "poc" / "sql_matrix" / mode / "summary.json"
    cursor_state = core._probe_cursor(
        summary_path,
        target=target,
        input_fingerprint=input_fingerprint,
        endpoint_count=len(eligible),
        kind="sql_matrix_summary",
        lane=mode,
    )
    start_index = int(cursor_state["start_index"])
    deferred_indices = list(cursor_state["deferred_indices"])
    worklist: list[int] = []
    for index in [*deferred_indices, *range(start_index, len(eligible))]:
        if index not in worklist:
            worklist.append(index)
    next_index = start_index
    deferred_next: list[int] = []
    processed_work_items = 0
    for position, index in enumerate(worklist):
        endpoint = eligible[index]
        remaining_budget = request_budget - stats["request_count"]
        if remaining_budget <= 0:
            break
        remaining_endpoints = len(worklist) - position
        before_errors = stats["transport_error_count"]
        found, events = probe_parameter_endpoint(
            endpoint,
            mode=mode,
            max_requests=max(1, remaining_budget // remaining_endpoints),
            target=target,
            session=session,
            waf_plan=waf_plan,
            stats=stats,
        )
        stats["probed_endpoint_count"] += 1
        processed_work_items += 1
        hits.extend(found)
        waf_events.extend(events)
        if index >= start_index:
            next_index = max(next_index, index + 1)
        if stats["transport_error_count"] > before_errors:
            deferred_next.append(index)
    deferred_next.extend(
        index
        for index in worklist[processed_work_items:]
        if index < start_index
    )
    cursor = core._build_probe_cursor(
        input_fingerprint,
        endpoint_count=len(eligible),
        next_endpoint_index=next_index,
        deferred_endpoint_indices=deferred_next,
    )
    stats["request_budget"] = request_budget
    stats["waf_plan_ref"] = str(waf_plan.get("plan_ref") or "") if waf_plan else ""
    stats["waf_plan_sha256"] = str(waf_plan.get("plan_sha256") or "") if waf_plan else ""
    stats["waf_plan_variant_count"] = len(waf_plan.get("variants") or []) if waf_plan else 0
    stats["waf_ai_variants_executed"] = sum(
        1 for event in waf_events if event.get("variant_source") == "ai"
    )
    stats["budget_exhausted"] = bool(
        stats["request_count"] >= request_budget
        or not cursor["coverage_complete"]
    )
    stats["batch_start_endpoint_index"] = start_index
    stats["batch_tested_endpoint_count"] = processed_work_items
    stats["resumed"] = bool(cursor_state["resumed"])
    stats["cursor"] = cursor
    result = _write_results(
        target,
        mode,
        hits,
        waf_events,
        stats,
        repo_root=repo_root,
    )
    print(json.dumps({"status": "ok", "hit_count": len(hits), **result}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
