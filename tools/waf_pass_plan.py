#!/usr/bin/env python3
"""Validate and select bounded, evidence-linked AI WAF-pass variants.

The probe tools remain the only network executors.  This module accepts the
small decision artifact produced by the model and keeps scope, evidence, and
variant-count checks in one place for JSON, query, and form transports.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

try:
    from tools.target_paths import canonical_target_value, target_storage_key, url_belongs_to_target
except ImportError:  # pragma: no cover - direct tools/ execution
    from target_paths import canonical_target_value, target_storage_key, url_belongs_to_target  # type: ignore


BASE_DIR = Path(__file__).resolve().parent.parent
SCHEMA_VERSION = 1
DEFAULT_AI_VARIANTS = 4
MAX_AI_VARIANTS = 8
MAX_EVIDENCE_REFS = 4
MAX_TEXT = 600
# Query/form field names commonly use brackets, dollar-prefixed operators, or
# Unicode. Matching is exact and never interpolated into a command, so keep
# only the bounded printable-text guard here.
_FIELD_RE = re.compile(r"^[^\x00-\x1f\x7f]{1,120}$")
_ALLOWED_ARTIFACT_ROOTS = {"findings", "recon", "state", "evidence"}


def _text(value: Any, field: str, *, required: bool = True) -> str:
    if not isinstance(value, str):
        if required:
            raise ValueError(f"{field} must be a string")
        return ""
    value = value.strip()
    if required and not value:
        raise ValueError(f"{field} is required")
    if len(value) > MAX_TEXT or any(ord(char) < 0x20 for char in value):
        raise ValueError(f"{field} is invalid or too long")
    return value


def _artifact_ref(
    value: Any,
    *,
    target: str,
    field: str,
    repo_root: str | Path | None = None,
) -> str:
    raw = _text(value, field)
    if raw.startswith("artifact://"):
        raw = raw[len("artifact://") :]
    root = Path(repo_root) if repo_root is not None else BASE_DIR
    candidate = Path(raw).expanduser()
    path = (candidate if candidate.is_absolute() else root / candidate).resolve()
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"{field} must stay inside the repository") from exc
    if not path.is_file() or not relative.parts or relative.parts[0] not in _ALLOWED_ARTIFACT_ROOTS:
        raise ValueError(f"{field} must reference an existing target artifact")
    target_key = target_storage_key(target)
    if target_key not in relative.parts:
        raise ValueError(f"{field} must reference an artifact for the execution target")
    return str(relative)


def _refs(
    value: Any,
    *,
    target: str,
    field: str,
    repo_root: str | Path | None = None,
) -> list[str]:
    if not isinstance(value, list) or not value or len(value) > MAX_EVIDENCE_REFS:
        raise ValueError(f"{field} must contain 1-{MAX_EVIDENCE_REFS} artifact refs")
    refs: list[str] = []
    for index, item in enumerate(value):
        ref = _artifact_ref(
            item,
            target=target,
            field=f"{field}[{index}]",
            repo_root=repo_root,
        )
        if ref not in refs:
            refs.append(ref)
    return refs


def _integer(value: Any, field: str) -> int:
    """Require a JSON integer; coercion would make malformed plans ambiguous."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field} must be an integer")
    return value


_MISSING = object()


def _optional_text(value: Any, field: str) -> str:
    if value is _MISSING or value == "":
        return ""
    return _text(value, field)


def _variant_value(item: dict[str, Any], index: int) -> str:
    value = item.get("value")
    mutation = item.get("mutation")
    if value is None and isinstance(mutation, dict):
        value = mutation.get("value")
    value = _text(value, f"variants[{index}].value")
    if not value:
        raise ValueError(f"variants[{index}].value is required")
    return value


def validate_plan(
    payload: dict[str, Any],
    *,
    target: str,
    plan_path: str = "",
    repo_root: str | Path | None = None,
) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("WAF plan must contain an object")
    if payload.get("schema_version", SCHEMA_VERSION) != SCHEMA_VERSION:
        raise ValueError(f"WAF plan schema_version must be {SCHEMA_VERSION}")
    resolved_target = canonical_target_value(target)
    if not resolved_target:
        raise ValueError("WAF plan target is required")
    declared = payload.get("target")
    if not isinstance(declared, str) or not declared.strip():
        raise ValueError("WAF plan target is required")
    if canonical_target_value(declared) != resolved_target:
        raise ValueError("WAF plan target does not match the execution target")

    if "budget" in payload and not isinstance(payload["budget"], dict):
        raise ValueError("WAF plan budget must be an object")
    budget = payload.get("budget") or {}
    raw_max_requests = (
        payload["max_requests"]
        if "max_requests" in payload
        else budget.get("max_requests")
    )
    max_requests = None
    if "max_requests" in payload or "max_requests" in budget:
        max_requests = _integer(raw_max_requests, "WAF plan max_requests")
        if max_requests < 1 or max_requests > 256:
            raise ValueError("WAF plan max_requests must be between 1 and 256")

    raw_max_variants = payload.get("max_variants", DEFAULT_AI_VARIANTS)
    max_variants = _integer(raw_max_variants, "WAF plan max_variants")
    if max_variants < 1 or max_variants > MAX_AI_VARIANTS:
        raise ValueError(f"WAF plan max_variants must be between 1 and {MAX_AI_VARIANTS}")

    top_refs = _refs(
        payload.get("evidence_refs"),
        target=resolved_target,
        field="evidence_refs",
        repo_root=repo_root,
    )
    variants = payload.get("variants")
    if not isinstance(variants, list) or not variants or len(variants) > max_variants:
        raise ValueError("WAF plan variants must be a non-empty bounded list")

    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    seen_variants: set[tuple[str, str, str, str]] = set()
    for index, raw in enumerate(variants):
        if not isinstance(raw, dict):
            raise ValueError(f"variants[{index}] must be an object")
        variant_id = _text(raw.get("id", f"ai-variant-{index + 1}"), f"variants[{index}].id")
        if variant_id in seen:
            raise ValueError(f"variants[{index}].id is duplicated")
        seen.add(variant_id)
        payload_class = _text(
            raw.get("payload_class", raw.get("class")),
            f"variants[{index}].payload_class",
        )
        if not (payload_class == "xss" or payload_class.startswith("sqli_")):
            raise ValueError(f"variants[{index}].payload_class must be SQLi or XSS")
        field = _optional_text(raw.get("field", _MISSING), f"variants[{index}].field")
        if field and not _FIELD_RE.fullmatch(field):
            raise ValueError(f"variants[{index}].field is invalid")
        endpoint_value = raw["endpoint"] if "endpoint" in raw else raw.get("url", _MISSING)
        endpoint = _optional_text(endpoint_value, f"variants[{index}].endpoint")
        if endpoint:
            parsed = urlparse(endpoint)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                raise ValueError(f"variants[{index}].endpoint must be an absolute http(s) URL")
            if not url_belongs_to_target(endpoint, resolved_target):
                raise ValueError(f"variants[{index}].endpoint is outside target scope")
        item_refs = raw.get("evidence_refs", top_refs)
        refs = _refs(
            item_refs,
            target=resolved_target,
            field=f"variants[{index}].evidence_refs",
            repo_root=repo_root,
        )
        value = _variant_value(raw, index)
        signature = (payload_class, field, str(endpoint), value)
        if signature in seen_variants:
            raise ValueError(f"variants[{index}] duplicates an earlier variant")
        seen_variants.add(signature)
        normalized.append({
            "id": variant_id,
            "payload_class": payload_class,
            "field": field,
            "endpoint": endpoint,
            "value": value,
            "technique": _text(raw.get("technique", "ai-semantic-variant"), f"variants[{index}].technique"),
            "reason": _text(raw.get("reason"), f"variants[{index}].reason"),
            "expected_signal": _text(raw.get("expected_signal"), f"variants[{index}].expected_signal"),
            "stop_condition": _text(raw.get("stop_condition"), f"variants[{index}].stop_condition"),
            "evidence_refs": refs,
        })
    return {
        "schema_version": SCHEMA_VERSION,
        "target": resolved_target,
        "max_requests": max_requests,
        "max_variants": max_variants,
        "evidence_refs": top_refs,
        "variants": normalized,
        "plan_ref": str(plan_path or ""),
    }


def load_plan(
    path: str | Path,
    *,
    target: str,
    repo_root: str | Path | None = None,
) -> dict[str, Any]:
    plan_file = Path(path).expanduser().resolve()
    try:
        raw = plan_file.read_bytes()
        payload = json.loads(raw.decode("utf-8"))
    except OSError as exc:
        raise ValueError(f"unable to read WAF plan: {exc}") from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid WAF plan JSON: {exc}") from exc
    root = Path(repo_root) if repo_root is not None else BASE_DIR
    plan = validate_plan(
        payload,
        target=target,
        plan_path=str(plan_file),
        repo_root=root,
    )
    try:
        plan["plan_ref"] = str(plan_file.relative_to(root))
    except ValueError:
        plan["plan_ref"] = str(plan_file)
    plan["plan_sha256"] = hashlib.sha256(raw).hexdigest()
    return plan


def select_variants(
    plan: dict[str, Any] | None,
    *,
    url: str,
    payload_class: str,
    field: str,
    canonical_value: object,
    limit: int = DEFAULT_AI_VARIANTS,
) -> list[dict[str, Any]]:
    """Return matching AI decisions; WAF block detection remains tool-owned."""
    if not isinstance(plan, dict) or not isinstance(canonical_value, str):
        return []
    selected: list[dict[str, Any]] = []
    for variant in plan.get("variants") or []:
        if not isinstance(variant, dict) or variant.get("payload_class") != payload_class:
            continue
        if variant.get("field") and variant.get("field") != field:
            continue
        if variant.get("endpoint") and variant.get("endpoint") != url:
            continue
        if variant.get("value") == canonical_value:
            continue
        selected.append(variant)
        if len(selected) >= min(limit, int(plan.get("max_variants", DEFAULT_AI_VARIANTS))):
            break
    return selected
