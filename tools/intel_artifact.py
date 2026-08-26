#!/usr/bin/env python3
"""Intel v2 artifact 的原子发布、校验和兼容读取。"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import tempfile
import urllib.parse
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
INTEL_QUERY_PAGE_LIMIT = 8
INTEL_QUERY_MAX_PAGE_LIMIT = 32
OMITTED_GROUP_INDEX_LIMIT = 128
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
    degraded = set()
    for name, source in sources.items():
        status = str(source.get("status") or "").strip().lower()
        if (
            bool(source.get("stale"))
            or status in {"stale", "invalid", "error", "unavailable"}
            or (status == "partial" and not bool(source.get("items_fresh")))
        ):
            degraded.add(name)
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


def _owner_binding(path: Path) -> dict[str, int]:
    stat = path.stat()
    return {
        "size": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
        "ctime_ns": stat.st_ctime_ns,
        "st_dev": stat.st_dev,
        "st_ino": stat.st_ino,
    }


def _query_filters(
    *,
    component: str = "",
    version: str = "",
    host: str = "",
    severity: str = "",
    applicability: str = "",
    kev: bool = False,
    include_stale: bool = False,
) -> dict[str, object]:
    normalized_severity = str(severity or "").strip().upper()
    if normalized_severity == "MODERATE":
        normalized_severity = "MEDIUM"
    normalized_applicability = normalize_advisory_applicability(applicability) if applicability else ""
    return {
        "component": str(component or "").strip().lower(),
        "version": str(version or "").strip().lower(),
        "host": str(host or "").strip().lower(),
        "severity": normalized_severity,
        "applicability": normalized_applicability,
        "kev": bool(kev),
        "include_stale": bool(include_stale),
    }


def _query_fingerprint(filters: dict[str, object]) -> str:
    material = json.dumps(filters, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def _cursor_token(*, owner_binding: dict[str, int], filters: dict[str, object], offset: int) -> str:
    payload = {
        "owner_binding": owner_binding,
        "filters": _query_fingerprint(filters),
        "offset": offset,
    }
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return base64.urlsafe_b64encode(encoded.encode("utf-8")).decode("ascii").rstrip("=")


def _decode_cursor(
    cursor: object,
    *,
    owner_binding: dict[str, int],
    filters: dict[str, object],
) -> int:
    if cursor in (None, "", 0):
        return 0
    try:
        raw = str(cursor)
        padding = "=" * (-len(raw) % 4)
        payload = json.loads(base64.urlsafe_b64decode((raw + padding).encode("ascii")))
    except (ValueError, TypeError, json.JSONDecodeError, UnicodeError) as exc:
        raise IntelArtifactError("invalid Intel query cursor") from exc
    if not isinstance(payload, dict):
        raise IntelArtifactError("invalid Intel query cursor")
    if payload.get("owner_binding") != owner_binding or payload.get("filters") != _query_fingerprint(filters):
        raise IntelArtifactError("Intel query cursor is stale for this owner or filter")
    try:
        offset = int(payload.get("offset"))
    except (TypeError, ValueError) as exc:
        raise IntelArtifactError("invalid Intel query cursor offset") from exc
    if offset < 0:
        raise IntelArtifactError("invalid Intel query cursor offset")
    return offset


def _query_sort_key(item: dict) -> tuple:
    severity = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    applicability = {"unknown": 0, "likely": 1, "affected": 2}
    component = item.get("component") if isinstance(item.get("component"), dict) else {}
    return (
        -severity.get(str(item.get("severity") or "UNKNOWN").upper(), 0),
        -applicability.get(normalize_advisory_applicability(item.get("applicability")), 0),
        -_score_hint(item),
        str(component.get("name") or "").lower(),
        str(component.get("version") or "").lower(),
        str(item.get("id") or ""),
    )


def _query_matches(item: dict, filters: dict[str, object]) -> bool:
    component = item.get("component") if isinstance(item.get("component"), dict) else {}
    component_name = str(component.get("name") or "").strip().lower()
    display_name = str(component.get("display_name") or "").strip().lower()
    if filters["component"] and filters["component"] not in {component_name, display_name}:
        return False
    if filters["version"] and str(component.get("version") or "").strip().lower() != filters["version"]:
        return False
    if filters["host"]:
        values = [
            *(component.get("hosts") or []),
            *(component.get("urls") or []),
        ]
        normalized_hosts = set()
        for value in values:
            text = str(value or "").strip().lower()
            if not text:
                continue
            parsed = urllib.parse.urlparse(text if "://" in text else f"//{text}")
            normalized_hosts.add(text)
            if parsed.hostname:
                normalized_hosts.add(parsed.hostname.lower())
            if parsed.netloc:
                normalized_hosts.add(parsed.netloc.lower())
        if filters["host"] not in normalized_hosts:
            return False
    if filters["severity"] and str(item.get("severity") or "UNKNOWN").upper() != filters["severity"]:
        return False
    if filters["applicability"] and normalize_advisory_applicability(item.get("applicability")) != filters["applicability"]:
        return False
    if filters["kev"] and not bool(item.get("kev")):
        return False
    return True


def _project_query_item(item: dict) -> dict:
    projected = project_intel_review_items([item], limit=1, include_stale=True)
    if not projected:
        return {}
    result = projected[0]
    result.update({
        "fixed_versions": _bounded_list(item.get("fixed_versions"), 8),
        "affected_ranges": _bounded_list(item.get("affected_ranges"), 8),
        "poc_available": bool(item.get("poc_available")),
        "nuclei_templates": _bounded_list(item.get("nuclei_templates"), 8),
        "local_evidence_refs": _bounded_list(item.get("local_evidence_refs"), 8),
    })
    return result


def query_intel_advisories(
    path: str | Path,
    *,
    component: str = "",
    version: str = "",
    host: str = "",
    severity: str = "",
    applicability: str = "",
    kev: bool = False,
    cursor: object = "",
    limit: int = INTEL_QUERY_PAGE_LIMIT,
    include_stale: bool = False,
) -> dict:
    """Read a bounded, deterministic page from the complete Intel owner."""
    owner_path = Path(path)
    before = _owner_binding(owner_path)
    payload = read_intel_artifact(owner_path)
    after = _owner_binding(owner_path)
    if before != after:
        raise IntelArtifactError("intel.json changed during query")
    filters = _query_filters(
        component=component,
        version=version,
        host=host,
        severity=severity,
        applicability=applicability,
        kev=kev,
        include_stale=include_stale,
    )
    try:
        page_limit = int(limit)
    except (TypeError, ValueError) as exc:
        raise IntelArtifactError("invalid Intel query page limit") from exc
    page_limit = max(1, min(page_limit, INTEL_QUERY_MAX_PAGE_LIMIT))
    offset = _decode_cursor(cursor, owner_binding=after, filters=filters)
    candidates = [
        item
        for item in payload.get("advisories") or []
        if isinstance(item, dict)
        and _is_review_candidate(item, include_stale=include_stale)
        and _query_matches(item, filters)
    ]
    candidates.sort(key=_query_sort_key)
    page = candidates[offset:offset + page_limit]
    next_offset = offset + len(page)
    next_cursor = (
        _cursor_token(owner_binding=after, filters=filters, offset=next_offset)
        if next_offset < len(candidates)
        else None
    )
    return {
        "status": "ok",
        "owner_path": str(owner_path),
        "owner_binding": after,
        "query": filters,
        "total_matches": len(candidates),
        "offset": offset,
        "limit": page_limit,
        "items": [_project_query_item(item) for item in page],
        "next_cursor": next_cursor,
        "has_more": next_cursor is not None,
    }


def _bounded_texts(value: object, limit: int = 64) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item or "")[:240] for item in value if str(item or "").strip()][:limit]


def project_intel_gap_items(value: object, limit: int = 8) -> list[dict]:
    if not isinstance(value, list):
        return []
    fields = ("subject", "intent", "query", "component", "version", "reason")
    return [
        {key: str(item.get(key) or "")[:240] for key in fields if item.get(key)}
        for item in value[:limit]
        if isinstance(item, dict)
    ]


def project_intel_source_coverage_gaps(sources: object, limit: int = 8) -> list[dict]:
    result = []
    for source in sources if isinstance(sources, list) else []:
        if not isinstance(source, dict):
            continue
        source_name = str(source.get("source") or "")[:40]
        for gap in source.get("coverage_gaps") or []:
            if not isinstance(gap, dict):
                continue
            component = gap.get("component") if isinstance(gap.get("component"), dict) else {}
            query = gap.get("query") if isinstance(gap.get("query"), dict) else {}
            binding = gap.get("owner_binding") if isinstance(gap.get("owner_binding"), dict) else {}
            result.append({
                "source": source_name,
                "gap_key": str(gap.get("gap_key") or "")[:160],
                "query_mode": str(gap.get("query_mode") or "")[:40],
                "component": {
                    "name": str(component.get("name") or "")[:160],
                    "version": str(component.get("version") or "")[:80],
                },
                "query": {
                    str(key)[:40]: str(value)[:500]
                    for key, value in list(query.items())[:4]
                },
                "total_results": int(gap.get("total_results", 0) or 0),
                "fetched_results": int(gap.get("fetched_results", 0) or 0),
                "next_start_index": int(gap.get("next_start_index", 0) or 0),
                "next_cursor": str(gap.get("next_cursor") or "")[:2000],
                "next_page": int(gap.get("next_page", 0) or 0),
                "initial_query_pending": bool(gap.get("initial_query_pending")),
                "reason": str(gap.get("reason") or "")[:240],
                "owner_binding": binding,
            })
            if len(result) >= limit:
                return result
    return result


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
    omitted = ordered[max(0, limit):]
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
        "omitted_groups": [
            {
                "group_key": group.get("group_key", ""),
                "component": group.get("component", {}),
                "advisory_count": int(group.get("advisory_count", 0) or 0),
                "representative_count": int(group.get("representative_count", 0) or 0),
                "omitted_count": int(group.get("omitted_count", 0) or 0),
                "max_score_hint": max(
                    (_score_hint(item) for item in group.get("representatives") or []),
                    default=0,
                ),
                "reactivate_when": str(group.get("reactivate_when") or "")[:240],
            }
            for group in omitted[:OMITTED_GROUP_INDEX_LIMIT]
        ],
        "omitted_group_count": len(omitted),
        "groups": selected,
        "items": [
            item
            for group in selected
            for item in group.get("representatives") or []
        ],
        "coverage_status": str(payload.get("coverage_status") or "error"),
        "source_coverage": [
            {
                "source": str(source.get("source") or "")[:40],
                "status": str(source.get("status") or "")[:40],
                "network_unavailable": bool(source.get("network_unavailable")),
                "eligible_queries": int((source.get("stats") or {}).get("eligible_queries", 0) or 0),
                "error_count": int((source.get("stats") or {}).get("error_count", 0) or 0),
            }
            for source in payload.get("sources") or []
            if isinstance(source, dict)
            and source.get("source") in {"osv", "github_advisory", "nvd"}
        ],
        "inventory": {
            "status": str(inventory.get("status") or ""),
            "fingerprint": str(inventory.get("fingerprint") or ""),
        },
        "intel_gaps": {
            "web_search_recommended": bool(gaps.get("web_search_recommended")),
            "recommended": project_intel_gap_items(gaps.get("recommended")),
            "blocked": project_intel_gap_items(gaps.get("blocked")),
        },
        "source_coverage_gaps": project_intel_source_coverage_gaps(payload.get("sources")),
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
    omitted_groups = payload.get("omitted_groups")
    source_gaps = payload.get("source_coverage_gaps", [])
    if (
        not isinstance(groups, list)
        or not isinstance(items, list)
        or not isinstance(omitted_groups, list)
        or not isinstance(source_gaps, list)
    ):
        return None
    binding = payload.get("owner_binding") if isinstance(payload.get("owner_binding"), dict) else {}
    owner_path = Path(recon_dir) / "intel.json"
    try:
        matches = binding == _owner_binding(owner_path)
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


def _query_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Read bounded pages from a target Intel artifact")
    sub = parser.add_subparsers(dest="command", required=True)
    query = sub.add_parser("query", help="Query advisory facts without modifying artifacts")
    query.add_argument("--target", required=True)
    query.add_argument("--repo-root", default=str(Path(__file__).resolve().parents[1]))
    query.add_argument("--component", default="")
    query.add_argument("--version", default="")
    query.add_argument("--host", default="")
    query.add_argument("--severity", default="")
    query.add_argument("--applicability", default="")
    query.add_argument("--kev", action="store_true")
    query.add_argument("--include-stale", action="store_true")
    query.add_argument("--cursor", default="")
    query.add_argument("--limit", type=int, default=INTEL_QUERY_PAGE_LIMIT)
    return parser


def _query_cli(argv: list[str] | None = None) -> int:
    args = _query_parser().parse_args(argv)
    try:
        result = query_intel_advisories(
            intel_artifact_path(args.repo_root, args.target),
            component=args.component,
            version=args.version,
            host=args.host,
            severity=args.severity,
            applicability=args.applicability,
            kev=args.kev,
            cursor=args.cursor,
            limit=args.limit,
            include_stale=args.include_stale,
        )
    except (IntelArtifactError, OSError, ValueError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, ensure_ascii=False))
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(_query_cli())
