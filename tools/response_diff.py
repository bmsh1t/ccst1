#!/usr/bin/env python3
"""Small response-diff helpers for validation evidence bundles.

这里不是漏洞判断器，只把 baseline / variant 响应转成 Claude 可以继续推理的
结构化差异：状态码、长度、JSON 数量、字段集合和简短摘要。漏洞类型的证据门槛
仍由 evidence_rubric / validation_runner 决定。
"""

from __future__ import annotations

import json
import hashlib
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ResponseSnapshot:
    """Compact representation of one HTTP response."""

    status: int
    headers: dict[str, str]
    body: str


def _parse_json(body: str) -> Any:
    try:
        return json.loads(body)
    except (TypeError, json.JSONDecodeError):
        return None


def _json_data_node(parsed: Any) -> Any:
    if isinstance(parsed, dict) and "data" in parsed:
        return parsed.get("data")
    return parsed


def _json_count(parsed: Any) -> int | None:
    node = _json_data_node(parsed)
    if isinstance(node, list):
        return len(node)
    if isinstance(node, dict):
        return len(node)
    return None


def _json_field_set(parsed: Any) -> list[str]:
    node = _json_data_node(parsed)
    keys: set[str] = set()
    if isinstance(node, dict):
        keys.update(str(key) for key in node.keys())
    elif isinstance(node, list):
        for item in node[:20]:
            if isinstance(item, dict):
                keys.update(str(key) for key in item.keys())
    return sorted(keys)


def snapshot_response(
    status: int,
    headers: dict[str, str] | None,
    body: str,
    *,
    truncated: bool = False,
    observed_bytes: int | None = None,
) -> dict[str, Any]:
    """Return a JSON-safe response snapshot."""
    parsed = _parse_json(body)
    content_type = ""
    if headers:
        content_type = headers.get("content-type") or headers.get("Content-Type") or ""
    encoded = (body or "").encode("utf-8", errors="replace")
    retained_bytes = len(encoded)
    return {
        "status": int(status or 0),
        "content_type": content_type,
        "body_length": retained_bytes,
        "body_retained_bytes": retained_bytes,
        "body_observed_bytes": max(retained_bytes, int(observed_bytes or 0)),
        "body_truncated": bool(truncated),
        "body_sha256": hashlib.sha256(encoded).hexdigest(),
        "body_sha256_scope": "retained",
        "json_valid": parsed is not None,
        "json_count": _json_count(parsed),
        "json_fields": _json_field_set(parsed),
    }


def diff_snapshots(baseline: dict[str, Any], variant: dict[str, Any]) -> dict[str, Any]:
    """Compare two response snapshots and return high-signal differences."""
    base_len = int(baseline.get("body_length", 0) or 0)
    var_len = int(variant.get("body_length", 0) or 0)
    base_fields = set(str(item) for item in baseline.get("json_fields", []) or [])
    var_fields = set(str(item) for item in variant.get("json_fields", []) or [])
    base_count = baseline.get("json_count")
    var_count = variant.get("json_count")
    changed = {
        "status": baseline.get("status") != variant.get("status"),
        "body_length": base_len != var_len,
        "json_count": base_count != var_count,
        "json_fields": base_fields != var_fields,
    }
    return {
        "changed": changed,
        "changed_any": any(changed.values()),
        "status": {
            "baseline": baseline.get("status"),
            "variant": variant.get("status"),
        },
        "body_length": {
            "baseline": base_len,
            "variant": var_len,
            "delta": var_len - base_len,
        },
        "json_count": {
            "baseline": base_count,
            "variant": var_count,
            "delta": (
                int(var_count) - int(base_count)
                if isinstance(base_count, int) and isinstance(var_count, int)
                else None
            ),
        },
        "json_fields": {
            "added": sorted(var_fields - base_fields),
            "removed": sorted(base_fields - var_fields),
        },
        "summary": summarize_diff(baseline, variant),
    }


def summarize_diff(baseline: dict[str, Any], variant: dict[str, Any]) -> str:
    """Human-readable one-line summary for checkpoint / Claude reasoning."""
    parts: list[str] = []
    if baseline.get("status") != variant.get("status"):
        parts.append(f"status {baseline.get('status')} -> {variant.get('status')}")
    if baseline.get("json_count") != variant.get("json_count"):
        parts.append(f"json_count {baseline.get('json_count')} -> {variant.get('json_count')}")
    base_len = int(baseline.get("body_length", 0) or 0)
    var_len = int(variant.get("body_length", 0) or 0)
    if base_len != var_len:
        parts.append(f"body_length {base_len} -> {var_len}")
    base_fields = set(str(item) for item in baseline.get("json_fields", []) or [])
    var_fields = set(str(item) for item in variant.get("json_fields", []) or [])
    if base_fields != var_fields:
        added = ",".join(sorted(var_fields - base_fields)[:6]) or "-"
        removed = ",".join(sorted(base_fields - var_fields)[:6]) or "-"
        parts.append(f"fields +[{added}] -[{removed}]")
    return "; ".join(parts) if parts else "no material response difference"


def diff_responses(
    *,
    baseline_status: int,
    baseline_headers: dict[str, str] | None,
    baseline_body: str,
    variant_status: int,
    variant_headers: dict[str, str] | None,
    variant_body: str,
) -> dict[str, Any]:
    """Convenience wrapper for raw response values."""
    baseline = snapshot_response(baseline_status, baseline_headers, baseline_body)
    variant = snapshot_response(variant_status, variant_headers, variant_body)
    return {
        "baseline": baseline,
        "variant": variant,
        "diff": diff_snapshots(baseline, variant),
    }
