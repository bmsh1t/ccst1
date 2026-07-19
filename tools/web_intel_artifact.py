#!/usr/bin/env python3
"""Provider-neutral Web Intel 查询记录、校验和 bounded 投影。"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

try:
    from tools.target_paths import canonical_target_value, target_storage_key
except ImportError:  # pragma: no cover - direct tools/ execution
    from target_paths import canonical_target_value, target_storage_key  # type: ignore


WEB_INTEL_SCHEMA_VERSION = 1
WEB_INTEL_INDEX_SCHEMA_VERSION = 1
WEB_INTEL_STATUSES = {"ok", "partial", "error", "blocked"}
SOURCE_TIERS = {"A", "B", "C"}
APPLICABILITY = {"affected", "likely", "unknown", "not_affected"}
DEFAULT_TTL_HOURS = {
    "alias_resolution": 24,
    "cve_verification": 24,
    "poc_lookup": 24,
    "component_advisory": 7 * 24,
    "target_osint": 30 * 24,
}
MAX_RESULTS = 20
MAX_INDEX_ENTRIES = 128
MAX_VERIFIED_CLAIMS = 32
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_GHSA_RE = re.compile(r"^GHSA-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$", re.IGNORECASE)


class WebIntelArtifactError(RuntimeError):
    """Web Intel artifact 存在但不满足可消费契约。"""


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _iso_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_utc(value: object) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


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


def _canonical_url(value: object) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        parsed = urlsplit(text)
    except ValueError:
        return text
    if not parsed.scheme or not parsed.netloc:
        return text
    path = parsed.path.rstrip("/") or "/"
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), path, parsed.query, ""))


def _identifier(value: object) -> str:
    text = str(value or "").strip().upper()
    return text if _CVE_RE.fullmatch(text) or _GHSA_RE.fullmatch(text) else ""


def _normalize_claim(raw: object) -> dict | None:
    if not isinstance(raw, dict):
        return None
    raw_identifiers = raw.get("identifiers", [])
    if not isinstance(raw_identifiers, list):
        raise WebIntelArtifactError("web intel claim identifiers must be an array")
    identifiers = list(dict.fromkeys(
        value
        for value in (_identifier(item) for item in raw_identifiers)
        if value
    ))
    component_raw = raw.get("component") if isinstance(raw.get("component"), dict) else {}
    component_name = str(component_raw.get("name") or "").strip().lower()
    if not identifiers or not component_name:
        return None
    aliases = [
        str(item).strip().lower()
        for item in component_raw.get("aliases") or []
        if str(item).strip()
    ]
    applicability = str(raw.get("applicability") or "unknown").strip().lower()
    if applicability not in APPLICABILITY:
        applicability = "unknown"
    severity = str(raw.get("severity") or "UNKNOWN").strip().upper()
    if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}:
        severity = "UNKNOWN"
    return {
        "identifiers": identifiers,
        "component": {
            "name": component_name,
            "display_name": str(component_raw.get("display_name") or component_name).strip(),
            "version": str(component_raw.get("version") or "").strip(),
            "aliases": list(dict.fromkeys(aliases))[:8],
        },
        "applicability": applicability,
        "severity": severity,
        "summary": str(raw.get("summary") or "").strip()[:1000],
        "published": str(raw.get("published") or "").strip(),
        "modified": str(raw.get("modified") or "").strip(),
        "fixed_versions": [
            str(item).strip() for item in raw.get("fixed_versions") or [] if str(item).strip()
        ][:16],
    }


def _normalize_result(raw: object) -> dict | None:
    if not isinstance(raw, dict):
        return None
    url = _canonical_url(raw.get("url"))
    if not url:
        return None
    tier = str(raw.get("source_tier") or "C").strip().upper()
    if tier not in SOURCE_TIERS:
        tier = "C"
    verified = bool(raw.get("body_verified"))
    origin_url = _canonical_url(raw.get("origin_url"))
    group = str(raw.get("independent_source_group") or origin_url or url).strip()
    raw_claims = raw.get("claims", [])
    if not isinstance(raw_claims, list):
        raise WebIntelArtifactError("web intel result claims must be an array")
    claims = [
        claim
        for item in raw_claims
        if (claim := _normalize_claim(item)) is not None
    ]
    return {
        "url": url,
        "origin_url": origin_url,
        "title": str(raw.get("title") or "").strip()[:500],
        "excerpt": str(raw.get("excerpt") or "").strip()[:1000],
        "source_tier": tier,
        "independent_source_group": group,
        "body_verified": verified,
        # 未核对正文的 claim 只保留在 query artifact；index 不会提升它。
        "claims": claims[:16],
    }


def normalize_web_intel_payload(
    payload: object,
    *,
    target: str,
    now: datetime | None = None,
) -> dict:
    if not isinstance(payload, dict):
        raise WebIntelArtifactError("web intel input must be a JSON object")
    resolved_target = canonical_target_value(target)
    raw_target = str(payload.get("target") or resolved_target).strip()
    if canonical_target_value(raw_target) != resolved_target:
        raise WebIntelArtifactError(
            f"web intel target mismatch: expected {resolved_target}, got {raw_target!r}"
        )
    intent = str(payload.get("intent") or "").strip().lower()
    query = str(payload.get("query") or "").strip()
    subject = str(payload.get("subject") or "").strip()
    provider = str(payload.get("provider") or "").strip()
    status = str(payload.get("status") or "ok").strip().lower()
    if not intent or not query or not subject or not provider:
        raise WebIntelArtifactError("intent, query, subject and provider are required")
    if status not in WEB_INTEL_STATUSES:
        raise WebIntelArtifactError(f"invalid web intel status: {status!r}")
    current = now or _now_utc()
    ttl_hours = payload.get("ttl_hours", DEFAULT_TTL_HOURS.get(intent, 24))
    try:
        ttl_hours = int(ttl_hours)
    except (TypeError, ValueError) as exc:
        raise WebIntelArtifactError("ttl_hours must be an integer") from exc
    if ttl_hours < 1 or ttl_hours > 30 * 24:
        raise WebIntelArtifactError("ttl_hours must be between 1 and 720")
    raw_results = payload.get("results", [])
    if not isinstance(raw_results, list):
        raise WebIntelArtifactError("web intel results must be an array")
    results = [
        result
        for item in raw_results
        if (result := _normalize_result(item)) is not None
    ][:MAX_RESULTS]
    fetched_at = _parse_utc(payload.get("fetched_at")) or current
    normalized = {
        "schema_version": WEB_INTEL_SCHEMA_VERSION,
        "target": resolved_target,
        "subject": subject,
        "intent": intent,
        "query": query,
        "provider": provider,
        "fetched_at": _iso_utc(fetched_at),
        "expires_at": _iso_utc(fetched_at + timedelta(hours=ttl_hours)),
        "ttl_hours": ttl_hours,
        "status": status,
        "error": str(payload.get("error") or "").strip()[:1000],
        "results": results,
        "conclusion": payload.get("conclusion") if isinstance(payload.get("conclusion"), dict) else {},
    }
    return normalized


def validate_web_intel_payload(payload: object) -> dict:
    if not isinstance(payload, dict) or payload.get("schema_version") != WEB_INTEL_SCHEMA_VERSION:
        raise WebIntelArtifactError("unsupported web intel query artifact")
    for field in ("target", "subject", "intent", "query", "provider", "fetched_at", "expires_at"):
        if not str(payload.get(field) or "").strip():
            raise WebIntelArtifactError(f"web intel field {field!r} is missing")
    if payload.get("status") not in WEB_INTEL_STATUSES:
        raise WebIntelArtifactError("web intel status is invalid")
    if not isinstance(payload.get("results"), list):
        raise WebIntelArtifactError("web intel results must be an array")
    if _parse_utc(payload.get("fetched_at")) is None or _parse_utc(payload.get("expires_at")) is None:
        raise WebIntelArtifactError("web intel timestamps are invalid")
    return payload


def _query_hash(payload: dict) -> str:
    material = {
        "target": payload["target"],
        "intent": payload["intent"],
        "subject": payload["subject"].strip().lower(),
        "query": payload["query"].strip(),
        "provider": payload["provider"].strip().lower(),
    }
    return hashlib.sha256(
        json.dumps(material, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def web_intel_root(repo_root: str | Path, target: str) -> Path:
    return Path(repo_root) / "evidence" / target_storage_key(target) / "web-intel"


def _verified_claim_projection(query_hash: str, payload: dict) -> list[dict]:
    projected = []
    seen = set()
    for result in payload.get("results") or []:
        if not isinstance(result, dict) or not result.get("body_verified"):
            continue
        group = str(result.get("independent_source_group") or result.get("url") or "").strip()
        for claim in result.get("claims") or []:
            if not isinstance(claim, dict):
                continue
            key = (
                group,
                tuple(claim.get("identifiers") or []),
                str((claim.get("component") or {}).get("name") or ""),
            )
            if key in seen:
                continue
            seen.add(key)
            projected.append({
                **claim,
                "query_hash": query_hash,
                "subject": payload.get("subject", ""),
                "intent": payload.get("intent", ""),
                "provider": payload.get("provider", ""),
                "fetched_at": payload.get("fetched_at", ""),
                "source": {
                    "url": result.get("url", ""),
                    "origin_url": result.get("origin_url", ""),
                    "title": result.get("title", ""),
                    "source_tier": result.get("source_tier", "C"),
                    "independent_source_group": group,
                    "body_verified": True,
                },
            })
    return projected


def rebuild_web_intel_index(repo_root: str | Path, target: str) -> dict:
    resolved_target = canonical_target_value(target)
    root = web_intel_root(repo_root, resolved_target)
    entries = []
    verified_claims = []
    errors = []
    for path in sorted((root / "queries").glob("*.json")) if (root / "queries").is_dir() else []:
        try:
            payload = validate_web_intel_payload(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError, WebIntelArtifactError) as exc:
            errors.append(f"{path.name}: {exc}")
            continue
        if canonical_target_value(str(payload.get("target") or "")) != resolved_target:
            errors.append(f"{path.name}: target mismatch")
            continue
        query_hash = path.stem
        claims = _verified_claim_projection(query_hash, payload)
        verified_claims.extend(claims)
        entries.append({
            "query_hash": query_hash,
            "path": str(path),
            "subject": payload.get("subject", ""),
            "intent": payload.get("intent", ""),
            "provider": payload.get("provider", ""),
            "fetched_at": payload.get("fetched_at", ""),
            "expires_at": payload.get("expires_at", ""),
            "status": payload.get("status", "error"),
            "error": str(payload.get("error") or "")[:500],
            "result_count": len(payload.get("results") or []),
            "verified_claim_count": len(claims),
        })
    entries.sort(
        key=lambda item: (
            str(item.get("fetched_at") or ""),
            str(item.get("query_hash") or ""),
        ),
        reverse=True,
    )
    total_entries = len(entries)
    entries = entries[:MAX_INDEX_ENTRIES]
    indexed_hashes = {str(item.get("query_hash") or "") for item in entries}
    verified_claims = [
        item
        for item in verified_claims
        if str(item.get("query_hash") or "") in indexed_hashes
    ]
    verified_claims.sort(
        key=lambda item: (
            str(item.get("fetched_at") or ""),
            str((item.get("component") or {}).get("name") or ""),
            str((item.get("identifiers") or [""])[0]),
        ),
        reverse=True,
    )
    unique_claims = []
    seen_claims = set()
    for claim in verified_claims:
        source = claim.get("source") if isinstance(claim.get("source"), dict) else {}
        component = claim.get("component") if isinstance(claim.get("component"), dict) else {}
        key = (
            str(source.get("independent_source_group") or source.get("url") or ""),
            tuple(str(item) for item in claim.get("identifiers") or []),
            str(component.get("name") or ""),
            str(component.get("version") or ""),
        )
        if key in seen_claims:
            continue
        seen_claims.add(key)
        unique_claims.append(claim)
    verified_claims = unique_claims
    index = {
        "schema_version": WEB_INTEL_INDEX_SCHEMA_VERSION,
        "target": resolved_target,
        "generated_at": _iso_utc(_now_utc()),
        "entries": entries,
        "verified_claims": verified_claims[:MAX_VERIFIED_CLAIMS],
        "errors": errors[:20],
        "stats": {
            "query_count": total_entries,
            "indexed_query_count": len(entries),
            "verified_claim_count": len(verified_claims),
            "invalid_count": len(errors),
        },
    }
    _write_json_atomic(root / "index.json", index)
    return index


def record_web_intel(
    repo_root: str | Path,
    target: str,
    payload: object,
    *,
    now: datetime | None = None,
) -> tuple[Path, dict]:
    normalized = normalize_web_intel_payload(payload, target=target, now=now)
    query_hash = _query_hash(normalized)
    path = web_intel_root(repo_root, target) / "queries" / f"{query_hash}.json"
    _write_json_atomic(path, normalized)
    return path, rebuild_web_intel_index(repo_root, target)


def load_web_intel_projection(
    repo_root: str | Path,
    target: str,
    *,
    now: datetime | None = None,
) -> dict:
    resolved_target = canonical_target_value(target)
    path = web_intel_root(repo_root, resolved_target) / "index.json"
    if not path.is_file():
        return {
            "status": "missing",
            "path": str(path),
            "fingerprint": "",
            "entries": [],
            "verified_claims": [],
            "covered_subjects": [],
            "blocked_subjects": [],
            "error": "",
        }
    try:
        raw = path.read_bytes()
        fingerprint = hashlib.sha256(raw).hexdigest()
        payload = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return {
            "status": "invalid",
            "path": str(path),
            "fingerprint": locals().get("fingerprint", ""),
            "entries": [],
            "verified_claims": [],
            "covered_subjects": [],
            "blocked_subjects": [],
            "error": str(exc),
        }
    if (
        not isinstance(payload, dict)
        or payload.get("schema_version") != WEB_INTEL_INDEX_SCHEMA_VERSION
        or canonical_target_value(str(payload.get("target") or "")) != resolved_target
        or not isinstance(payload.get("entries"), list)
        or not isinstance(payload.get("verified_claims"), list)
    ):
        return {
            "status": "invalid",
            "path": str(path),
            "fingerprint": fingerprint,
            "entries": [],
            "verified_claims": [],
            "covered_subjects": [],
            "blocked_subjects": [],
            "error": "invalid web intel index schema or target",
        }
    current = now or _now_utc()
    active_entries = [
        item
        for item in payload.get("entries") or []
        if isinstance(item, dict)
        and (_parse_utc(item.get("expires_at")) or datetime.min.replace(tzinfo=timezone.utc)) > current
    ]
    successful_entries = [
        item for item in active_entries if item.get("status") in {"ok", "partial"}
    ]
    blocked_entries = [
        item for item in active_entries if item.get("status") in {"blocked", "error"}
    ]
    successful_hashes = {str(item.get("query_hash") or "") for item in successful_entries}
    claims = [
        item
        for item in payload.get("verified_claims") or []
        if isinstance(item, dict) and str(item.get("query_hash") or "") in successful_hashes
    ]
    if successful_entries:
        status = "partial" if blocked_entries else "ready"
    elif any(item.get("status") == "blocked" for item in blocked_entries):
        status = "blocked"
    elif blocked_entries:
        status = "error"
    else:
        status = "stale"
    if payload.get("errors"):
        status = "partial" if active_entries else "invalid"
    active_errors = [
        str(item.get("error") or "").strip()
        for item in blocked_entries
        if str(item.get("error") or "").strip()
    ]
    active_errors.extend(str(item) for item in payload.get("errors") or [] if str(item).strip())
    return {
        "status": status,
        "path": str(path),
        "fingerprint": fingerprint,
        "entries": active_entries[:20],
        "verified_claims": claims[:MAX_VERIFIED_CLAIMS],
        "covered_subjects": list(dict.fromkeys(
            str(item.get("subject") or "").strip().lower()
            for item in successful_entries
            if str(item.get("subject") or "").strip()
        )),
        "blocked_subjects": list(dict.fromkeys(
            str(item.get("subject") or "").strip().lower()
            for item in blocked_entries
            if str(item.get("subject") or "").strip()
        )),
        "stats": payload.get("stats") if isinstance(payload.get("stats"), dict) else {},
        "error": "; ".join(active_errors)[:1000],
    }


def _component_projection(observations: list[dict], name: str, version: str) -> dict:
    matching = [
        item for item in observations
        if isinstance(item, dict)
        and str(item.get("name") or "").strip().lower() == name
        and str(item.get("version") or "").strip() == version
    ]

    def unique(field: str) -> list:
        values = []
        seen = set()
        for item in matching:
            value = item.get(field)
            if value in (None, "", 0) or value in seen:
                continue
            seen.add(value)
            values.append(value)
        return values

    first = matching[0]
    return {
        "name": name,
        "display_name": str(first.get("display_name") or name),
        "version": version,
        "hosts": unique("host"),
        "urls": unique("url"),
        "ports": unique("port"),
        "protocols": unique("protocol"),
        "cpes": unique("cpe"),
    }


def build_web_intel_source(projection: dict, components: list[dict]) -> dict:
    """把已核对 Web claim 转换成 Intel source envelope；未匹配资产只保留在线索层。"""
    if projection.get("status") == "missing":
        return {
            "source": "web_intel",
            "status": "unavailable",
            "fetched_at": "",
            "cached": False,
            "stale": False,
            "error": "web intel has not been collected",
            "eligible": 0,
            "attempted": 0,
            "items": [],
        }
    if projection.get("status") in {"invalid", "stale"}:
        return {
            "source": "web_intel",
            "status": "error" if projection.get("status") == "invalid" else "partial",
            "fetched_at": "",
            "cached": False,
            "stale": projection.get("status") == "stale",
            "error": str(projection.get("error") or projection.get("status")),
            "eligible": 0,
            "attempted": 0,
            "items": [],
        }
    if projection.get("status") in {"blocked", "error"}:
        return {
            "source": "web_intel",
            "status": "unavailable" if projection.get("status") == "blocked" else "error",
            "fetched_at": "",
            "cached": True,
            "stale": False,
            "error": str(projection.get("error") or f"web intel {projection.get('status')}"),
            "eligible": 0,
            "attempted": len(projection.get("entries") or []),
            "items": [],
        }

    component_names: dict[str, list[dict]] = {}
    for component in components:
        if not isinstance(component, dict) or component.get("kind") == "unknown_service":
            continue
        name = str(component.get("name") or "").strip().lower()
        if name:
            component_names.setdefault(name, []).append(component)

    items = []
    seen = set()
    unmatched = 0
    for claim in projection.get("verified_claims") or []:
        if not isinstance(claim, dict):
            continue
        claim_component = claim.get("component") if isinstance(claim.get("component"), dict) else {}
        names = [str(claim_component.get("name") or "").strip().lower()]
        names.extend(str(item).strip().lower() for item in claim_component.get("aliases") or [])
        matched_name = next((name for name in names if name in component_names), "")
        if not matched_name:
            unmatched += 1
            continue
        observed_versions = list(dict.fromkeys(
            str(item.get("version") or "").strip()
            for item in component_names[matched_name]
        ))
        for observed_version in observed_versions:
            identifiers = [str(item).strip().upper() for item in claim.get("identifiers") or [] if str(item).strip()]
            if not identifiers:
                continue
            source = claim.get("source") if isinstance(claim.get("source"), dict) else {}
            group = str(source.get("independent_source_group") or source.get("url") or "")
            dedupe_key = (tuple(identifiers), matched_name, observed_version, group)
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            declared_version = str(claim_component.get("version") or "").strip()
            applicability = str(claim.get("applicability") or "unknown")
            if applicability in {"affected", "not_affected"} and (
                not declared_version or declared_version != observed_version
            ):
                applicability = "unknown"
            items.append({
                "id": identifiers[0],
                "aliases": identifiers,
                "source": "web_intel",
                "component": _component_projection(
                    component_names[matched_name], matched_name, observed_version
                ),
                "applicability": applicability if applicability in APPLICABILITY else "unknown",
                "severity": claim.get("severity", "UNKNOWN"),
                "cvss": None,
                "summary": str(claim.get("summary") or "")[:500],
                "published": claim.get("published", ""),
                "modified": claim.get("modified", ""),
                "fixed_versions": list(claim.get("fixed_versions") or []),
                "affected_ranges": [],
                "poc_available": claim.get("intent") == "poc_lookup",
                "source_refs": [{
                    "source": "web_intel",
                    "id": identifiers[0],
                    "url": source.get("url", ""),
                    "origin_url": source.get("origin_url", ""),
                    "source_tier": source.get("source_tier", "C"),
                    "independent_source_group": group,
                    "body_verified": True,
                    "query_hash": claim.get("query_hash", ""),
                    "fetched_at": claim.get("fetched_at", ""),
                }],
            })
    entries = projection.get("entries") or []
    fetched_at = max(
        (str(item.get("fetched_at") or "") for item in entries if isinstance(item, dict)),
        default="",
    )
    status = "partial" if projection.get("status") == "partial" else "ok"
    return {
        "source": "web_intel",
        "status": status,
        "fetched_at": fetched_at,
        "cached": True,
        "stale": False,
        "error": str(projection.get("error") or ""),
        "eligible": len(projection.get("verified_claims") or []),
        "attempted": len(entries),
        "unmatched": unmatched,
        "items": items,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Record or inspect provider-neutral Web Intel")
    subparsers = parser.add_subparsers(dest="command", required=True)
    record = subparsers.add_parser("record", help="Validate and atomically record one query JSON")
    record.add_argument("--target", required=True)
    record.add_argument("--input", required=True, help="JSON file produced after search/source review")
    record.add_argument("--repo-root", default=str(Path(__file__).resolve().parent.parent))
    status = subparsers.add_parser("status", help="Print the bounded Web Intel projection")
    status.add_argument("--target", required=True)
    status.add_argument("--repo-root", default=str(Path(__file__).resolve().parent.parent))
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "status":
        print(json.dumps(
            load_web_intel_projection(args.repo_root, args.target),
            ensure_ascii=False,
            indent=2,
        ))
        return 0
    try:
        raw = json.loads(Path(args.input).read_text(encoding="utf-8"))
        path, index = record_web_intel(args.repo_root, args.target, raw)
    except (OSError, json.JSONDecodeError, ValueError, WebIntelArtifactError) as exc:
        print(f"web intel error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({
        "status": "recorded",
        "path": str(path),
        "index": str(web_intel_root(args.repo_root, args.target) / "index.json"),
        "verified_claims": int((index.get("stats") or {}).get("verified_claim_count", 0)),
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
