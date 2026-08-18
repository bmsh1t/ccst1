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
INTEL_REVIEW_SCHEMA_VERSION = 1
SOURCE_STATUSES = {"ok", "partial", "unavailable", "error"}
COVERAGE_STATUSES = {"ready", "partial", "unavailable", "error"}
REVIEW_ITEM_LIMIT = 16
REVIEW_GROUP_LIMIT = 32
NOT_APPLICABLE_VALUES = {
    "not_affected",
    "not-affected",
    "not affected",
    "not_applicable",
    "not-applicable",
    "not applicable",
    "n/a",
    "na",
}
STALE_ADVISORY_STATUSES = {"stale", "partial", "invalid", "error", "unavailable"}


class IntelArtifactError(RuntimeError):
    """Intel artifact 存在但无法安全消费。"""


def normalize_advisory_applicability(value: object) -> str:
    """Normalize legacy advisory disposition spellings before routing."""
    normalized = str(value or "unknown").strip().lower().replace("_", " ").replace("-", " ")
    normalized = " ".join(normalized.split())
    if normalized in {item.replace("_", " ").replace("-", " ") for item in NOT_APPLICABLE_VALUES}:
        return "not_affected"
    return normalized.replace(" ", "_")


def advisory_is_stale(item: dict) -> bool:
    """Return true only for an explicit stale/degraded advisory marker."""
    if bool(item.get("stale")):
        return True
    status = str(item.get("status") or item.get("source_status") or "").strip().lower()
    return status in STALE_ADVISORY_STATUSES


def advisory_is_actionable(item: dict) -> bool:
    """Gate advisory consumers on applicability and explicit freshness."""
    return (
        normalize_advisory_applicability(item.get("applicability")) != "not_affected"
        and not advisory_is_stale(item)
    )


def _with_advisory_source_freshness(payload: dict) -> dict:
    """Mark advisories backed only by degraded sources as stale."""
    sources = {
        str(source.get("source") or "").strip(): source
        for source in payload.get("sources") or []
        if isinstance(source, dict) and str(source.get("source") or "").strip()
    }
    degraded = {
        name
        for name, source in sources.items()
        if str(source.get("status") or "").strip().lower() in STALE_ADVISORY_STATUSES
        or bool(source.get("stale"))
    }
    if not degraded:
        return payload
    result = dict(payload)
    advisories = []
    for item in payload.get("advisories") or []:
        if not isinstance(item, dict):
            continue
        names = {
            str(name).strip()
            for name in item.get("source_names") or []
            if str(name).strip()
        }
        if str(item.get("source") or "").strip():
            names.add(str(item.get("source")).strip())
        names.update(
            str(ref.get("source") or "").strip()
            for ref in item.get("source_refs") or []
            if isinstance(ref, dict) and str(ref.get("source") or "").strip()
        )
        copy = dict(item)
        if names and names.issubset(degraded):
            copy["stale"] = True
            copy["source_status"] = "partial"
        advisories.append(copy)
    result["advisories"] = advisories
    return result


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


def intel_review_path(repo_root: str | Path, target: str) -> Path:
    """Return the bounded AI-facing projection beside the lossless artifact."""
    resolved_target = canonical_target_value(target)
    return Path(repo_root) / "recon" / target_storage_key(resolved_target) / "intel-review.json"


def write_intel_artifact(repo_root: str | Path, target: str, payload: dict) -> Path:
    validated = validate_intel_artifact(payload)
    resolved_target = canonical_target_value(target)
    if canonical_target_value(str(validated.get("target") or "")) != resolved_target:
        raise IntelArtifactError(
            f"intel artifact target mismatch: expected {resolved_target}, got {validated.get('target')!r}"
        )
    path = intel_artifact_path(repo_root, resolved_target)
    _write_json_atomic(path, validated)
    _write_json_atomic(
        intel_review_path(repo_root, resolved_target),
        build_intel_review_projection(
            _with_advisory_source_freshness(validated),
            owner_path=path,
        ),
    )
    return path


def read_intel_artifact(path: str | Path) -> dict:
    artifact_path = Path(path)
    try:
        payload = json.loads(artifact_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise IntelArtifactError(f"invalid intel artifact {artifact_path}: {exc}") from exc
    return _with_advisory_source_freshness(validate_intel_artifact(payload))


def _score_hint(item: dict) -> int:
    try:
        return int(float(item.get("score_hint") or 0))
    except (TypeError, ValueError):
        return 0


def _bounded_list(value: object, limit: int) -> list:
    return list(value)[:limit] if isinstance(value, list) else []


def _bounded_texts(value: object, limit: int = 64) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item or "")[:240] for item in value if str(item or "").strip()][:limit]


def _bounded_gap_items(value: object, limit: int = 8) -> list[dict]:
    if not isinstance(value, list):
        return []
    fields = ("subject", "intent", "query", "component", "version", "reason")
    return [
        {key: str(item.get(key) or "")[:240] for key in fields if item.get(key)}
        for item in value[:limit]
        if isinstance(item, dict)
    ]


def _is_review_candidate(item: object, *, include_stale: bool = False) -> bool:
    return bool(
        isinstance(item, dict)
        and (
            advisory_is_actionable(item)
            or (
                include_stale
                and normalize_advisory_applicability(item.get("applicability"))
                != "not_affected"
            )
        )
    )


def project_intel_review_items(
    items: list[dict],
    *,
    limit: int = REVIEW_ITEM_LIMIT,
    include_stale: bool = False,
) -> list[dict]:
    """生成有界、可追溯的 advisory review 投影，不携带无界原始响应。"""
    candidates = [
        item for item in items
        if _is_review_candidate(item, include_stale=include_stale)
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
            "stale": bool(item.get("stale")),
            "source_status": str(item.get("source_status") or ""),
        })
    return projected


def build_intel_review_projection(
    payload: dict,
    *,
    owner_path: Path,
    limit: int = REVIEW_GROUP_LIMIT,
) -> dict:
    """Build a bounded, component/version-grouped packet for AI steering.

    ``intel.json`` remains the complete raw/normalized owner.  This sidecar is
    deliberately small: one representative per observed component/version
    group, with counts and reactivation hints instead of one queue row per CVE.
    """
    grouped: dict[tuple[str, str], list[dict]] = {}
    for item in payload.get("advisories") or []:
        if not _is_review_candidate(item, include_stale=True):
            continue
        component = item.get("component") if isinstance(item.get("component"), dict) else {}
        key = (
            str(component.get("name") or "").strip().lower(),
            str(component.get("version") or "").strip(),
        )
        if not key[0]:
            continue
        grouped.setdefault(key, []).append(item)
    groups = []
    for key, raw_items in grouped.items():
        representatives = project_intel_review_items(
            raw_items,
            limit=3,
            include_stale=True,
        )
        groups.append(
            {
                "group_key": f"{key[0]}@{key[1]}" if key[1] else key[0],
                "component": {
                    "name": key[0],
                    "version": key[1],
                },
                "advisory_count": len(raw_items),
                "representative_count": len(representatives),
                "omitted_count": max(0, len(raw_items) - len(representatives)),
                "representatives": representatives,
                "reactivate_when": "new route/browser/source evidence binds the dependency to reachable target behavior",
            }
        )
    ordered = sorted(
        groups,
        key=lambda group: (
            -max((_score_hint(item) for item in group["representatives"]), default=0),
            group["group_key"],
        ),
    )
    selected = ordered[:max(0, limit)]
    stat = owner_path.stat()
    inventory = payload.get("inventory") if isinstance(payload.get("inventory"), dict) else {}
    gaps = payload.get("intel_gaps") if isinstance(payload.get("intel_gaps"), dict) else {}
    web_intel = payload.get("web_intel") if isinstance(payload.get("web_intel"), dict) else {}
    stats = payload.get("stats") if isinstance(payload.get("stats"), dict) else {}
    return {
        "schema_version": INTEL_REVIEW_SCHEMA_VERSION,
        "target": str(payload.get("target") or ""),
        "generated_at": str(payload.get("generated_at") or ""),
        "advisory_count": len(list(payload.get("advisories") or [])),
        "review_candidate_count": sum(len(items) for items in grouped.values()),
        "group_count": len(selected),
        "total_group_count": len(ordered),
        "truncated_group_count": max(0, len(ordered) - len(selected)),
        "groups": selected,
        "items": [
            item
            for group in selected
            for item in group.get("representatives") or []
        ],
        "coverage_status": str(payload.get("coverage_status") or "error"),
        "inventory": {
            "status": str(inventory.get("status") or ""),
            "fingerprint": str(inventory.get("fingerprint") or ""),
        },
        "intel_gaps": {
            "web_search_recommended": bool(gaps.get("web_search_recommended")),
            "recommended": _bounded_gap_items(gaps.get("recommended")),
            "blocked": _bounded_gap_items(gaps.get("blocked")),
        },
        "web_intel": {
            "status": str(web_intel.get("status") or "")[:80],
            "fingerprint": str(web_intel.get("fingerprint") or "")[:128],
            "covered_subjects": _bounded_texts(web_intel.get("covered_subjects")),
            "blocked_subjects": _bounded_texts(web_intel.get("blocked_subjects")),
        },
        "stats": {"component_count": int(stats.get("component_count", 0) or 0)},
        "owner_binding": {
            "size": stat.st_size,
            "mtime_ns": stat.st_mtime_ns,
            "ctime_ns": stat.st_ctime_ns,
            "st_dev": stat.st_dev,
            "st_ino": stat.st_ino,
        },
    }


def load_intel_review_projection(recon_dir: str | Path, target: str) -> dict | None:
    """Read the bounded sidecar, returning ``None`` for legacy artifacts."""
    path = Path(recon_dir) / "intel-review.json"
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict) or payload.get("schema_version") != INTEL_REVIEW_SCHEMA_VERSION:
        return None
    if canonical_target_value(str(payload.get("target") or "")) != canonical_target_value(target):
        return None
    groups = payload.get("groups")
    items = payload.get("items")
    if not isinstance(groups, list) or not isinstance(items, list):
        return None
    binding = payload.get("owner_binding") if isinstance(payload.get("owner_binding"), dict) else {}
    owner_path = Path(recon_dir) / "intel.json"
    try:
        stat = owner_path.stat()
        matches = all(
            int(binding.get(key, -1)) == int(getattr(stat, attribute))
            for key, attribute in (
                ("size", "st_size"),
                ("mtime_ns", "st_mtime_ns"),
                ("ctime_ns", "st_ctime_ns"),
                ("st_dev", "st_dev"),
                ("st_ino", "st_ino"),
            )
        )
    except (OSError, TypeError, ValueError):
        matches = False
    if not matches:
        return None
    return payload


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
            payload = _with_advisory_source_freshness(payload)
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
