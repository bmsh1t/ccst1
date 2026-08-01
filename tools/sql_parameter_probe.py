#!/usr/bin/env python3
"""Run the shared SQL matrix against query-string or form parameters.

JSON POST callers stay on ``json_inject_probe``; this adapter reuses its
baseline-relative detection, WAF handling, request budget, and the shared
``SQL_PAYLOADS`` catalog for non-JSON parameter surfaces.
"""

from __future__ import annotations

import argparse
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
    stats: dict | None = None,
) -> tuple[list[dict], list[dict]]:
    source = _parameter_source(endpoint, mode)
    if source is None:
        return [], []
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
        for technique, variant in core._waf_variants(payload["class"], payload["value"]):
            if request_count >= max_requests:
                break
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
            waf_events.append({
                "url": retry_url,
                "method": method,
                "field": field,
                "payload_class": payload["class"],
                "payload_family": payload.get("family", payload["class"]),
                "technique": technique,
                **retry_waf,
            })
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
                hits.append(record)
            break
    return hits, waf_events


def _write_results(target: str, lane: str, hits: list[dict], waf_events: list[dict], execution: dict) -> dict:
    out_dir = BASE_DIR / "findings" / target_storage_key(target) / "poc" / "sql_matrix" / lane
    out_dir.mkdir(parents=True, exist_ok=True)
    for stale in out_dir.glob("*.json"):
        if stale.name != "summary.json":
            stale.unlink()
    files: list[str] = []
    for hit in hits:
        slug = re.sub(r"[^A-Za-z0-9._-]+", "_", urllib.parse.urlparse(hit["url"]).path).strip("_") or "root"
        path = out_dir / f"{hit['payload_class']}_{slug}_{hit['field']}.json"
        path.write_text(json.dumps(hit, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        files.append(str(path))
    skipped = execution.get("skipped") or {}
    if not int(execution.get("endpoint_count") or 0) and any(int(value or 0) for value in skipped.values()):
        status = "invalid_input"
    elif hits:
        status = "candidate_pending"
    elif execution.get("transport_error_count") or any(int(value or 0) for value in skipped.values()):
        status = "partial"
    else:
        status = "complete_no_hit"
    payload = {
        "schema_version": 1,
        "kind": "sql_matrix_summary",
        "lane": lane,
        "target": canonical_target_value(target),
        "status": status,
        **execution,
        "hit_count": len(hits),
        "waf_observation_count": len(waf_events),
        "generated_at": int(time.time()),
        "hits": [
            {"url": item["url"], "field": item["field"], "class": item["payload_class"], "signal": item["signal"]}
            for item in hits[:SUMMARY_ITEM_LIMIT]
        ],
        "waf_observations": waf_events[:SUMMARY_ITEM_LIMIT],
    }
    path = out_dir / "summary.json"
    core._write_json_atomic(path, payload)
    return {"summary": str(path), "files": files}


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


def main() -> int:
    parser = argparse.ArgumentParser(description="Shared SQL matrix for query-string and form parameters")
    parser.add_argument("--target", required=True)
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--urls-file", help="newline-delimited query URLs or JSONL")
    inputs.add_argument("--form-file", help="JSONL of POST form requests: {url, method, body}")
    parser.add_argument("--max-requests", type=int, default=60)
    add_cli_args(parser)
    args = parser.parse_args()
    target = canonical_target_value(args.target)
    mode = "query" if args.urls_file else "form"
    source = args.urls_file or args.form_file
    session = session_from_args(args).bind_target(target)
    endpoints = _read_inputs(source, mode)
    hits: list[dict] = []
    waf_events: list[dict] = []
    stats = {"request_count": 0, "transport_error_count": 0, "endpoint_count": 0, "probed_endpoint_count": 0, "skipped": {"out_of_scope": 0, "invalid": 0}}
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
        found, events = probe_parameter_endpoint(
            endpoint,
            mode=mode,
            max_requests=max(1, int(args.max_requests)),
            target=target,
            session=session,
            stats=stats,
        )
        stats["probed_endpoint_count"] += 1
        hits.extend(found)
        waf_events.extend(events)
    result = _write_results(target, mode, hits, waf_events, stats)
    print(json.dumps({"status": "ok", "hit_count": len(hits), **result}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
