#!/usr/bin/env python3
"""Intel v2 artifact 的原子发布、校验和兼容读取。"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

try:
    from tools.target_paths import canonical_target_value, target_storage_key
except ImportError:  # pragma: no cover - direct tools/ execution
    from target_paths import canonical_target_value, target_storage_key  # type: ignore


INTEL_SCHEMA_VERSION = 2
SOURCE_STATUSES = {"ok", "partial", "unavailable", "error"}
COVERAGE_STATUSES = {"ready", "partial", "unavailable", "error"}
REVIEW_ITEM_LIMIT = 16


class IntelArtifactError(RuntimeError):
    """Intel artifact 存在但无法安全消费。"""


def validate_intel_artifact(payload: object) -> dict:
    if not isinstance(payload, dict):
        raise IntelArtifactError("intel artifact must be a JSON object")
    schema_version = payload.get("schema_version")
    if schema_version != INTEL_SCHEMA_VERSION:
        raise IntelArtifactError(f"unsupported intel artifact schema: {schema_version!r}")
    for field in ("sources", "advisories", "critical", "high", "info"):
        if not isinstance(payload.get(field), list):
            raise IntelArtifactError(f"intel artifact field {field!r} must be an array")
    for field in ("advisories", "critical", "high", "info"):
        if any(not isinstance(item, dict) for item in payload.get(field) or []):
            raise IntelArtifactError(f"intel artifact field {field!r} must contain objects")
    if not isinstance(payload.get("inventory"), dict):
        raise IntelArtifactError("intel artifact inventory must be an object")
    if not str(payload.get("target") or "").strip():
        raise IntelArtifactError("intel artifact target is missing")
    if payload.get("coverage_status") not in COVERAGE_STATUSES:
        raise IntelArtifactError(
            f"invalid intel coverage_status: {payload.get('coverage_status')!r}"
        )
    for source in payload.get("sources") or []:
        if not isinstance(source, dict):
            raise IntelArtifactError("intel source status entries must be objects")
        if source.get("status") not in SOURCE_STATUSES:
            raise IntelArtifactError(
                f"invalid intel source status: {source.get('status')!r}"
            )
        if not str(source.get("source") or "").strip():
            raise IntelArtifactError("intel source name is missing")
    return payload


def _write_json_atomic(path: Path, payload: dict) -> None:
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


def intel_artifact_path(repo_root: str | Path, target: str) -> Path:
    resolved_target = canonical_target_value(target)
    return Path(repo_root) / "recon" / target_storage_key(resolved_target) / "intel.json"


def write_intel_artifact(repo_root: str | Path, target: str, payload: dict) -> Path:
    validated = validate_intel_artifact(payload)
    resolved_target = canonical_target_value(target)
    if canonical_target_value(str(validated.get("target") or "")) != resolved_target:
        raise IntelArtifactError(
            f"intel artifact target mismatch: expected {resolved_target}, got {validated.get('target')!r}"
        )
    path = intel_artifact_path(repo_root, resolved_target)
    _write_json_atomic(path, validated)
    return path


def read_intel_artifact(path: str | Path) -> dict:
    artifact_path = Path(path)
    try:
        payload = json.loads(artifact_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise IntelArtifactError(f"invalid intel artifact {artifact_path}: {exc}") from exc
    return validate_intel_artifact(payload)


def _score_hint(item: dict) -> int:
    try:
        return int(float(item.get("score_hint") or 0))
    except (TypeError, ValueError):
        return 0


def _bounded_list(value: object, limit: int) -> list:
    return list(value)[:limit] if isinstance(value, list) else []


def project_intel_review_items(items: list[dict], *, limit: int = REVIEW_ITEM_LIMIT) -> list[dict]:
    """生成有界、可追溯的 advisory review 投影，不携带无界原始响应。"""
    candidates = [
        item
        for item in items
        if isinstance(item, dict) and item.get("applicability") != "not_affected"
    ]
    candidates.sort(key=lambda item: (-_score_hint(item), str(item.get("id") or "")))
    projected = []
    for item in candidates[:max(0, limit)]:
        component = item.get("component") if isinstance(item.get("component"), dict) else {}
        source_refs = [
            {
                "source": ref.get("source", ""),
                "id": ref.get("id", ""),
                "url": ref.get("url", ""),
                "fetched_at": ref.get("fetched_at", ""),
            }
            for ref in item.get("source_refs") or []
            if isinstance(ref, dict)
        ]
        projected.append({
            "id": item.get("id", ""),
            "aliases": _bounded_list(item.get("aliases"), 8),
            "component": {
                "name": component.get("name", ""),
                "display_name": component.get("display_name", ""),
                "version": component.get("version", ""),
                "hosts": _bounded_list(component.get("hosts"), 5),
                "ports": _bounded_list(component.get("ports"), 8),
                "protocols": _bounded_list(component.get("protocols"), 8),
                "cpes": _bounded_list(component.get("cpes"), 5),
            },
            "applicability": item.get("applicability", "unknown"),
            "severity": item.get("severity", "UNKNOWN"),
            "summary": str(item.get("summary") or "")[:500],
            "score_hint": _score_hint(item),
            "score_reasons": _bounded_list(item.get("score_reasons"), 12),
            "kev": bool(item.get("kev")),
            "epss": item.get("epss"),
            "source_names": _bounded_list(item.get("source_names"), 8),
            "source_refs": source_refs[:8],
            "already_tested": bool(item.get("already_tested")),
        })
    return projected


def load_intel_projection(recon_dir: str | Path) -> dict:
    """返回显式 missing/ready/legacy/invalid 状态，避免 invalid 被投影为空。"""
    recon_path = Path(recon_dir)
    json_path = recon_path / "intel.json"
    markdown_path = recon_path / "intel.md"
    if json_path.is_file():
        try:
            raw = json.loads(json_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return {
                "status": "invalid",
                "path": str(json_path),
                "error": str(exc),
                "items": [],
                "sources": [],
                "coverage_status": "error",
            }
        if isinstance(raw, dict) and raw.get("schema_version") == INTEL_SCHEMA_VERSION:
            try:
                payload = validate_intel_artifact(raw)
            except IntelArtifactError as exc:
                return {
                    "status": "invalid",
                    "path": str(json_path),
                    "error": str(exc),
                    "items": [],
                    "sources": [],
                    "coverage_status": "error",
                }
            return {
                "status": "ready",
                "path": str(json_path),
                "error": "",
                "payload": payload,
                "items": list(payload.get("advisories") or []),
                "review_items": project_intel_review_items(payload.get("advisories") or []),
                "sources": list(payload.get("sources") or []),
                "coverage_status": payload.get("coverage_status", "error"),
            }
        if isinstance(raw, dict):
            schema_version = raw.get("schema_version")
            if schema_version not in (None, 1):
                return {
                    "status": "invalid",
                    "path": str(json_path),
                    "error": f"unsupported intel artifact schema: {schema_version!r}",
                    "items": [],
                    "sources": [],
                    "coverage_status": "error",
                }
            legacy_items = []
            for bucket in ("critical", "high", "info"):
                values = raw.get(bucket) or []
                if isinstance(values, list):
                    legacy_items.extend(item for item in values if isinstance(item, dict))
            return {
                "status": "legacy",
                "path": str(json_path),
                "error": "",
                "payload": raw,
                "items": legacy_items,
                "review_items": project_intel_review_items(legacy_items),
                "sources": [],
                "coverage_status": "legacy",
            }
        return {
            "status": "invalid",
            "path": str(json_path),
            "error": "legacy intel artifact must be a JSON object",
            "items": [],
            "sources": [],
            "coverage_status": "error",
        }
    if markdown_path.is_file():
        try:
            text = markdown_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return {
                "status": "invalid",
                "path": str(markdown_path),
                "error": str(exc),
                "items": [],
                "sources": [],
                "coverage_status": "error",
            }
        items = [
            {"summary": line, "severity": "INFO", "source": "intel.md"}
            for line in text.splitlines()
            if "|" in line or line.startswith(("[", "-", "  "))
        ]
        return {
            "status": "legacy_markdown",
            "path": str(markdown_path),
            "error": "",
            "items": items,
            "sources": [],
            "coverage_status": "legacy",
        }
    return {
        "status": "missing",
        "path": str(json_path),
        "error": "",
        "items": [],
        "sources": [],
        "coverage_status": "missing",
    }
