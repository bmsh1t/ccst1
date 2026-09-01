#!/usr/bin/env python3
"""
surface.py — build an AI-first review pack from cached recon and hunt memory.
"""

import argparse
import heapq
import hashlib
import json
import os
import re
import shlex
import sys
import tempfile
from pathlib import Path
from typing import Iterator
from urllib.parse import urlparse

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from memory.pattern_db import PatternDB  # noqa: E402
from memory.target_profile import default_memory_dir, load_target_profile  # noqa: E402
from tools.target_memory import load_goal_memory  # noqa: E402
try:
    from tools.closure_resolver import ClosureResolver, canonical_endpoint_path
    from tools.coverage_matrix import load_matrix
    from tools.evidence_ledger import (
        build_current_cell_projection,
        load_entries as load_evidence_ledger_entries,
    )
    from tools.action_queue import FINAL_STATUSES as ACTION_QUEUE_FINAL_STATUSES
    from tools.action_queue import load_queue as load_action_queue
    from tools.attack_probe_filter import (
        filter_attack_probes,
        is_attack_probe,
        sanitize_attack_probe_url,
    )
    from tools.finding_index import (
        load_finding_index,
        verify_finalized_finding_owner_provenance,
    )
    from tools.intel_artifact import load_intel_projection
    from tools.observation_inventory import (
        InventoryError,
        inventory_path,
        sync_inventory_summary,
    )
    from tools.recon_adapter import ReconAdapter
    from tools.runtime_state import (
        derive_owner_projection,
        inspect_recon_artifacts,
        load_runtime_state,
    )
    from tools.surface_index import (
        SurfaceIndexError,
        build_surface_index,
        iter_surface_index,
        load_surface_index_status,
        page_surface_index,
        surface_shape,
        surface_request_shape,
        surface_safe_preview,
        surface_value_summary,
    )
    from tools.surface_projection import (
        build_surface_input_manifest,
        write_surface_projection,
    )
    from tools.target_paths import (
        compact_url,
        canonical_target_value,
        resolve_target_url,
        target_storage_key,
        url_belongs_to_target,
    )
except ImportError:  # pragma: no cover - top-level tools/ import
    from closure_resolver import ClosureResolver, canonical_endpoint_path  # type: ignore
    from coverage_matrix import load_matrix  # type: ignore
    from evidence_ledger import (  # type: ignore
        build_current_cell_projection,
        load_entries as load_evidence_ledger_entries,
    )
    from action_queue import FINAL_STATUSES as ACTION_QUEUE_FINAL_STATUSES  # type: ignore
    from action_queue import load_queue as load_action_queue  # type: ignore
    from attack_probe_filter import filter_attack_probes, is_attack_probe, sanitize_attack_probe_url
    from finding_index import load_finding_index, verify_finalized_finding_owner_provenance
    from intel_artifact import load_intel_projection
    from observation_inventory import (  # type: ignore
        InventoryError,
        inventory_path,
        sync_inventory_summary,
    )
    from recon_adapter import ReconAdapter
    from runtime_state import derive_owner_projection, inspect_recon_artifacts, load_runtime_state
    from surface_index import SurfaceIndexError, build_surface_index, iter_surface_index, load_surface_index_status, page_surface_index, surface_shape, surface_request_shape, surface_safe_preview, surface_value_summary
    from surface_projection import build_surface_input_manifest, write_surface_projection
    from target_paths import (  # type: ignore
        compact_url,
        canonical_target_value,
        resolve_target_url,
        target_storage_key,
        url_belongs_to_target,
    )
try:
    from tools.browser_surface import public_url_shape
    from tools.high_value_signals import classify_high_value_signal, summarize_high_value_signal
    from tools.intel_artifact import advisory_is_actionable, normalize_advisory_applicability
    from tools.surface_js_intel import (
        build_js_lead_hints,
        build_js_intel_urls,
        js_intel_counts,
        load_js_intel_hypotheses,
    )
    from tools.surface_source_intel import (
        build_source_lead_hints,
        build_source_intel_urls,
        load_source_intel_hypotheses,
        source_intel_counts,
    )
except ImportError:  # pragma: no cover - top-level tools/ import
    from browser_surface import public_url_shape  # type: ignore
    from high_value_signals import classify_high_value_signal, summarize_high_value_signal
    from intel_artifact import advisory_is_actionable, normalize_advisory_applicability  # type: ignore
    from surface_js_intel import (
        build_js_lead_hints,
        build_js_intel_urls,
        js_intel_counts,
        load_js_intel_hypotheses,
    )
    from surface_source_intel import (
        build_source_lead_hints,
        build_source_intel_urls,
        load_source_intel_hypotheses,
        source_intel_counts,
    )


def _dedupe_keep_order(items):
    seen = set()
    out = []
    for item in items:
        if not item or item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def _read_lines(path: Path) -> list[str]:
    if not path.is_file():
        return []
    with open(path, encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


def _read_json_object(path: Path) -> dict:
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _load_browser_request_shapes(recon_dir: Path) -> dict[str, list[dict]]:
    """Load the public, value-free request metadata projection when present."""
    path = recon_dir / "browser" / "request_shapes.json"
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(payload, list):
        return {}
    result: dict[str, list[dict]] = {}
    for item in payload:
        if not isinstance(item, dict):
            continue
        key = str(item.get("url") or "").strip()
        if not key:
            continue
        result.setdefault(key, []).append(
            {
                "method": str(item.get("method") or "GET").upper(),
                "resource_type": str(item.get("resourceType") or "").lower(),
                "status": item.get("status", ""),
                "body": item.get("postData") if isinstance(item.get("postData"), dict) else {},
            }
        )
    return result


def unsafe_skipped_id(line: str) -> str:
    """Return a stable compact id for one unsafe-skipped scanner line."""
    return hashlib.sha256(str(line or "").strip().encode("utf-8")).hexdigest()[:16]


def _load_resolved_unsafe_skipped(repo_root: Path, storage_key: str) -> set[str]:
    review_path = repo_root / "state" / storage_key / "unsafe_skipped_reviews.json"
    payload = _read_json_object(review_path)
    resolved = payload.get("resolved") or {}
    if not isinstance(resolved, dict):
        return set()
    return {str(key) for key in resolved if str(key).strip()}


def _load_scanner_manual_review(findings_dir: Path, target: str) -> dict:
    """Load the scanner's complete target-owned manual-review index."""
    storage_key = target_storage_key(target)
    summary_path = findings_dir / "summary.json"
    display_summary = f"findings/{storage_key}/summary.json"
    payload = _read_json_object(summary_path)
    if not payload:
        return {"summary_path": display_summary, "items": []}

    summary_target = str(payload.get("target") or "").strip()
    try:
        if summary_target and canonical_target_value(summary_target) != canonical_target_value(target):
            return {"summary_path": display_summary, "items": []}
    except ValueError:
        return {"summary_path": display_summary, "items": []}

    raw_items = payload.get("manual_review")
    if not isinstance(raw_items, list):
        return {"summary_path": display_summary, "items": []}

    findings_root = findings_dir.resolve()
    seen: set[str] = set()
    items: list[dict] = []
    for item in raw_items:
        if not isinstance(item, dict):
            continue
        raw_path = str(item.get("path") or "").strip()
        if not raw_path or Path(raw_path).is_absolute():
            continue
        try:
            path = (findings_root / raw_path).resolve()
            relative_path = path.relative_to(findings_root).as_posix()
        except (OSError, RuntimeError, ValueError):
            continue
        if relative_path in seen or not path.is_file():
            continue
        try:
            lines = _read_lines(path)
        except (OSError, UnicodeError):
            continue
        if not lines:
            continue
        seen.add(relative_path)
        items.append({
            "path": f"findings/{storage_key}/{relative_path}",
            "relative_path": relative_path,
            "count": len(lines),
            "preview": [surface_safe_preview(line) for line in lines[:3]],
        })
    return {"summary_path": display_summary, "items": items}


def _count_recon_artifact(recon_artifacts: dict, key: str) -> int:
    """Safely read one integer count from runtime_state recon metadata."""
    counts = recon_artifacts.get("counts") or {}
    try:
        return int(counts.get(key, 0) or 0)
    except (TypeError, ValueError):
        return 0


def _sync_observation_inventory(repo_root: Path, target: str) -> dict:
    """同步中性 observation 状态，并把故障保留为显式 surface warning。"""
    try:
        return sync_inventory_summary(repo_root, target)
    except (InventoryError, OSError) as exc:
        return {
            "available": False,
            "path": str(inventory_path(repo_root, target)),
            "error": str(exc),
            "total": 0,
            "present": 0,
            "untouched": 0,
            "reviewing": 0,
            "reviewed": 0,
            "parked": 0,
            "stale": 0,
            "sample": [],
        }


def _build_exposure_lead_hints(recon_artifacts: dict, target: str) -> list[dict]:
    """Convert recon exposure counts into soft workflow leads.

    These are attention hints only: they do not alter advisory scoring, do not set
    next_action, and do not call any follow-up tools automatically.
    """
    if not recon_artifacts.get("available"):
        return []

    storage_key = target_storage_key(target)
    leads: list[dict] = []

    api_docs = _count_recon_artifact(recon_artifacts, "api_doc_candidates")
    api_leaks = _count_recon_artifact(recon_artifacts, "api_leak_candidates")
    verified = _count_recon_artifact(recon_artifacts, "verified_secrets")
    postman = _count_recon_artifact(recon_artifacts, "postman_leaks")
    postleaks = _count_recon_artifact(recon_artifacts, "postleaks_urls")
    swagger = _count_recon_artifact(recon_artifacts, "swagger_leaks")
    openapi_specs = _count_recon_artifact(recon_artifacts, "openapi_specs")
    openapi_operations = _count_recon_artifact(recon_artifacts, "openapi_operations")
    openapi_public = _count_recon_artifact(recon_artifacts, "openapi_public_operations")
    openapi_auth = _count_recon_artifact(recon_artifacts, "openapi_auth_boundary_candidates")
    platform_metadata = _count_recon_artifact(recon_artifacts, "platform_metadata")
    config = _count_recon_artifact(recon_artifacts, "config_exposures")
    cloud = _count_recon_artifact(recon_artifacts, "cloud_storage_candidates")
    s3 = _count_recon_artifact(recon_artifacts, "s3_bucket_candidates")
    external_hosts = _count_recon_artifact(recon_artifacts, "external_service_hosts")
    host_pivots = _count_recon_artifact(recon_artifacts, "host_pivot_candidates")
    host_collision_observations = _count_recon_artifact(
        recon_artifacts, "host_collision_observations"
    )
    ai_assets = _count_recon_artifact(recon_artifacts, "ai_asset_candidates")
    asset_relations = _count_recon_artifact(recon_artifacts, "asset_relation_candidates")
    asset_relation_state = (
        recon_artifacts.get("asset_relations")
        if isinstance(recon_artifacts.get("asset_relations"), dict)
        else {}
    )
    try:
        asset_scope_reviews = min(
            asset_relations,
            max(0, int(asset_relation_state.get("scope_review_pending", 0) or 0)),
        )
    except (TypeError, ValueError):
        asset_scope_reviews = 0
    asset_next_cursor = str(asset_relation_state.get("next_cursor") or "").strip()[:512]
    asset_continuation = (
        " Continue the bounded candidate page with `python3 tools/recon_candidates.py "
        f"--target {target} --asset-cursor {asset_next_cursor}`."
        if asset_next_cursor
        else ""
    )
    emails = _count_recon_artifact(recon_artifacts, "identity_emails")
    leaksearch = _count_recon_artifact(recon_artifacts, "leaksearch_hits")
    cloud_enum = _count_recon_artifact(recon_artifacts, "cloud_enum_hits")

    if verified > 0:
        leads.append({
            "source": "recon_exposure",
            "title": "Verified secret material found in API leak artifacts",
            "category": "verified-secret",
            "priority": "critical",
            "artifact": f"recon/{storage_key}/exposure/api_leak_trufflehog_verified.jsonl",
            "next_action": (
                f"inspect recon/{storage_key}/exposure/api_leak_trufflehog_verified.jsonl "
                "and perform minimal-impact credential usability validation only"
            ),
            "rationale": (
                "Verified secret artifacts are high-signal, but they still need scoped, "
                "minimal-impact validation before becoming a finding."
            ),
            "evidence": f"{verified} verified line(s)",
        })

    if openapi_operations > 0 or openapi_auth > 0 or platform_metadata > 0:
        semantic_artifact = (
            "auth_boundary_candidates.jsonl" if openapi_auth > 0
            else "operations.jsonl" if openapi_operations > 0
            else "platform_metadata.jsonl"
        )
        if openapi_operations > 0 or openapi_auth > 0:
            semantic_next_action = (
                f"review recon/{storage_key}/api_specs/{semantic_artifact} and select high-value "
                "operations for anonymous baseline plus controlled authentication, role, and "
                "object differential evidence"
            )
        else:
            semantic_next_action = (
                f"review recon/{storage_key}/api_specs/platform_metadata.jsonl and use advertised "
                "authorization servers or endpoints to form scoped authentication hypotheses"
            )
        leads.append({
            "source": "recon_exposure",
            "title": (
                "OpenAPI operations and authentication declarations extracted"
                if openapi_operations > 0 or openapi_auth > 0
                else "Platform authentication metadata extracted"
            ),
            "category": "openapi-semantics",
            "priority": "high" if openapi_auth > 0 else "medium",
            "artifact": f"recon/{storage_key}/api_specs/{semantic_artifact}",
            "next_action": semantic_next_action,
            "rationale": (
                f"specs={openapi_specs}, operations={openapi_operations}, public_or_optional={openapi_public}, "
                f"auth_boundaries={openapi_auth}, platform_metadata={platform_metadata}; "
                "schema declarations are discovery facts, not proof of authorization behavior."
            ),
            "evidence": f"{openapi_operations + platform_metadata} structured discovery fact(s)",
        })

    if api_leaks > 0 or postman > 0 or postleaks > 0 or swagger > 0:
        leads.append({
            "source": "recon_exposure",
            "title": "API leak candidates from Postman/OpenAPI discovery",
            "category": "api-leak",
            "priority": "high",
            "next_action": (
                f"review recon/{storage_key}/exposure/api_leak_candidates.txt; "
                "identify imported specs/collections, high-impact verbs, and auth boundaries"
            ),
            "rationale": (
                f"candidate={api_leaks}, swagger={swagger}, postman={postman}, "
                f"postleaks={postleaks}; leaked collections/specs often expose hidden workflows."
            ),
            "evidence": f"{api_leaks + postman + postleaks + swagger} exposure line(s)",
        })

    if api_docs > 0 and openapi_operations == 0:
        leads.append({
            "source": "recon_exposure",
            "title": "OpenAPI/Swagger/API documentation candidates discovered",
            "category": "api-docs",
            "priority": "high",
            "next_action": (
                f"review recon/{storage_key}/exposure/api_doc_candidates.txt for auth model, "
                "hidden endpoints, admin paths, and GraphQL mutations"
            ),
            "rationale": "API documentation often reveals routes and auth assumptions before broad scanning.",
            "evidence": f"{api_docs} candidate line(s)",
        })

    if config > 0 or cloud > 0 or s3 > 0 or external_hosts > 0:
        leads.append({
            "source": "recon_exposure",
            "title": "Config/cloud exposure candidates discovered",
            "category": "config-cloud",
            "priority": "medium",
            "next_action": (
                f"review recon/{storage_key}/exposure/config_files.txt and cloud candidate files; "
                "verify ownership and permissions before deeper cloud testing"
            ),
            "rationale": (
                f"config={config}, cloud={cloud}, s3={s3}, external_hosts={external_hosts}; "
                "these are ownership and access-control hypotheses, not conclusions."
            ),
            "evidence": f"{config + cloud + s3 + external_hosts} candidate line(s)",
        })

    if emails > 0 or leaksearch > 0 or cloud_enum > 0:
        leads.append({
            "source": "recon_exposure",
            "title": "Identity/cloud intel signals discovered",
            "category": "identity-cloud",
            "priority": "medium",
            "next_action": (
                f"review recon/{storage_key}/exposure/identity_intel/summary.md before "
                "SSO, reset-flow, invite, tenant, or cloud ownership hypotheses"
            ),
            "rationale": (
                f"emails={emails}, LeakSearch={leaksearch}, cloud_enum={cloud_enum}; "
                "use these to focus hypotheses rather than to force a live exploit path."
            ),
            "evidence": f"{emails + leaksearch + cloud_enum} signal line(s)",
        })

    if host_pivots > 0:
        leads.append({
            "source": "recon_routing_candidate",
            "title": "Host/SNI/VirtualHost pivot evidence is available",
            "category": "host-pivot",
            "priority": "high",
            "artifact": f"recon/{storage_key}/exposure/host_pivot_candidates.jsonl",
            "next_action": (
                f"review recon/{storage_key}/exposure/host_pivot_candidates.jsonl; select only "
                "evidence-backed Host Header, SNI, or VirtualHost differentials and keep a "
                "default-vhost/CDN/error-page control"
            ),
            "rationale": (
                f"{host_pivots} low-cost candidate(s) were derived from existing origin, shared-IP, "
                "CNAME, or certificate facts; no active pivot has been validated yet."
            ),
            "evidence": f"{host_pivots} candidate row(s)",
        })

    if host_collision_observations > 0:
        leads.append({
            "source": "recon_routing_observation",
            "title": "Host collision response observations are available",
            "category": "host-collision-observation",
            "priority": "high",
            "artifact": f"recon/{storage_key}/exposure/host_collision_observations.jsonl",
            "next_action": (
                f"review recon/{storage_key}/exposure/host_collision_observations.jsonl; "
                "replay only target-owned host/SNI/default-vhost controls and keep response "
                "differences as candidates until independently validated"
            ),
            "rationale": (
                f"{host_collision_observations} bounded read-only response observation(s) were "
                "recorded from existing Host pivot candidates; no observation is a finding or "
                "scope expansion."
            ),
            "evidence": f"{host_collision_observations} observation row(s)",
        })

    if ai_assets > 0:
        leads.append({
            "source": "recon_routing_candidate",
            "title": "AI/LLM application or service candidates are available",
            "category": "ai-asset",
            "priority": "high",
            "artifact": f"recon/{storage_key}/exposure/ai_asset_candidates.jsonl",
            "next_action": (
                f"review recon/{storage_key}/exposure/ai_asset_candidates.jsonl and route selected "
                "Chat/RAG/model/API/upload/tool-use evidence through web-llm-tool-chains"
            ),
            "rationale": (
                f"{ai_assets} title/tech/path/schema/browser/source candidate(s) were observed; "
                "product strings and status codes are discovery facts, not vulnerability proof."
            ),
            "evidence": f"{ai_assets} candidate row(s)",
        })

    if asset_scope_reviews > 0:
        leads.append({
            "source": "recon_routing_candidate",
            "title": "High-confidence target-linked assets require Scope review",
            "category": "asset-scope-review",
            "priority": "high",
            "artifact": f"recon/{storage_key}/exposure/asset_relation_candidates.jsonl",
            "next_action": (
                f"review recon/{storage_key}/exposure/asset_relation_candidates.jsonl and classify "
                "each scope-review row as explicitly in scope, external context, or excluded; do not "
                "issue active requests until the explicit target set proves Scope."
                f"{asset_continuation}"
            ),
            "rationale": (
                f"{asset_scope_reviews} high-confidence target-linked candidate(s) have ownership or "
                "multi-source evidence, but relationship evidence cannot expand active Scope."
            ),
            "evidence": f"{asset_scope_reviews} pending Scope review row(s)",
        })

    if asset_relations > asset_scope_reviews:
        leads.append({
            "source": "recon_routing_candidate",
            "title": "External asset relationship candidates are available",
            "category": "asset-relation",
            "priority": "medium",
            "artifact": f"recon/{storage_key}/exposure/asset_relation_candidates.jsonl",
            "next_action": (
                f"review recon/{storage_key}/exposure/asset_relation_candidates.jsonl; prioritize "
                "multi-source or high-confidence relationships, then promote only target-owned or "
                "explicitly supplied assets into active Recon/Surface work."
                f"{asset_continuation}"
            ),
            "rationale": (
                f"{asset_relations - asset_scope_reviews} contextual relationship candidate(s) were derived from external "
                "registries, RDAP/WHOIS, certificate transparency, passive DNS, ASN/BGP, fingerprints, "
                "or public supplier records; association is context, not scope or vulnerability proof."
            ),
            "evidence": f"{asset_relations - asset_scope_reviews} contextual candidate row(s)",
        })

    return leads


def _build_manual_review_lead_hints(findings_dir: Path, storage_key: str) -> list[dict]:
    """Convert scanner manual-review artifacts into soft workflow leads."""
    leads: list[dict] = []

    unsafe_path = findings_dir / "manual_review" / "unsafe_skipped.txt"
    lines = _read_lines(unsafe_path)
    if lines:
        repo_root = findings_dir.parent.parent
        resolved_ids = _load_resolved_unsafe_skipped(repo_root, storage_key)
        unresolved = [line for line in lines if unsafe_skipped_id(line) not in resolved_ids]
        if unresolved:
            unsafe_display_path = f"findings/{storage_key}/manual_review/unsafe_skipped.txt"
            first_id = unsafe_skipped_id(unresolved[0])
            leads.append({
                "source": "scanner_manual_review",
                "title": "Side-effect-capable scanner probes were skipped",
                "category": "action-gated",
                "priority": "high",
                "unsafe_skipped_id": first_id,
                "unsafe_skipped_ids": [unsafe_skipped_id(line) for line in unresolved[:20]],
                "artifact": unsafe_display_path,
                "next_action": (
                    f"review {unsafe_display_path} before rerunning the upload canary"
                ),
                "rationale": (
                    "The upload canary was deferred. Treat it as a Lead, not a tested-clean result."
                ),
                "evidence": f"{len(unresolved)} unresolved skipped probe line(s)",
            })

    open_200_path = findings_dir / "manual_review" / "open_200_api.txt"
    open_200 = _read_lines(open_200_path)
    if open_200:
        display_path = f"findings/{storage_key}/manual_review/open_200_api.txt"
        leads.append({
            "source": "scanner_manual_review",
            "title": "Anonymous API endpoints returned substantial 200 responses",
            "category": "open-200-api-review",
            "priority": "medium",
            "artifact": display_path,
            "next_action": (
                f"review {display_path}; sample the highest-value response bodies, identify structured data, "
                "and promote only body-backed authz/config/secret/business-impact evidence to validation"
            ),
            "rationale": (
                "The scanner kept non-obvious anonymous 200 responses as discovery leads instead of dropping them "
                "or auto-promoting them as auth bypass findings."
            ),
            "evidence": f"{len(open_200)} anonymous substantial 200 response(s)",
        })

    public_metadata_path = findings_dir / "manual_review" / "standard_public_metadata.txt"
    public_metadata = _read_lines(public_metadata_path)
    if public_metadata:
        display_path = f"findings/{storage_key}/manual_review/standard_public_metadata.txt"
        leads.append({
            "source": "scanner_manual_review",
            "title": "Standard public metadata endpoints were demoted from exposure findings",
            "category": "public-metadata",
            "priority": "low",
            "artifact": display_path,
            "next_action": (
                f"review {display_path} only when you suspect unusual field content or a chain pivot; "
                "default posture is informative, not reportable"
            ),
            "rationale": (
                "These endpoints matched known public metadata schemas (for example OIDC discovery, JWKS, CSAF, security.txt) "
                "without separate high-value body evidence."
            ),
            "evidence": f"{len(public_metadata)} demoted metadata line(s)",
        })

    return leads


def _load_target_goal_memory(repo_root: Path, target: str) -> dict:
    """Load Claude CLI target memory without depending on the writer module globals."""
    return load_goal_memory(repo_root, target)


def _target_memory_entries(target_goal_memory: dict, field: str) -> list[dict]:
    target_memory = target_goal_memory.get("target") or {}
    entries = target_memory.get(field) or []
    if not isinstance(entries, list):
        return []
    return [
        item for item in entries
        if isinstance(item, dict) and str(item.get("text", "") or "").strip()
    ]


def _target_memory_summary(target_goal_memory: dict) -> dict:
    active = target_goal_memory.get("active") or {}
    target_memory = target_goal_memory.get("target") or {}
    if not target_memory and not active:
        return {}

    summary = {
        "active_matches": bool(target_goal_memory.get("active_matches")),
        "goal": str(active.get("active_goal") or target_memory.get("active_goal") or "").strip(),
        "hypothesis": str(
            active.get("current_hypothesis")
            or target_memory.get("current_hypothesis")
            or ""
        ).strip(),
        "active_leads": _target_memory_entries(target_goal_memory, "active_leads"),
        "next_actions": _target_memory_entries(target_goal_memory, "next_actions"),
        "dead_ends": _target_memory_entries(target_goal_memory, "dead_ends"),
    }
    handoffs = target_memory.get("session_handoffs") or []
    if isinstance(handoffs, list):
        summary["session_handoffs"] = [
            item for item in handoffs
            if isinstance(item, dict) and (item.get("summary") or item.get("path"))
        ]
    else:
        summary["session_handoffs"] = []
    return summary


def _target_memory_text(item: dict) -> str:
    return str(item.get("text", "") or "").strip()


def _memory_token_matches(token: str, haystack: str) -> bool:
    token = token.strip(" \t\r\n,.;:()[]'\"")
    if not token:
        return False
    lowered = token.lower()
    if lowered in haystack:
        return True
    # 支持 /api/org/{id}/users 这类目标记忆模板匹配真实路径。
    escaped = re.escape(lowered)
    templated = re.sub(r"\\\{[^}]+\\\}", r"[^/?&#]+", escaped)
    return bool(re.search(templated, haystack))


def _target_memory_entry_matches(item: dict, raw_url: str, path: str) -> bool:
    text = _target_memory_text(item).lower()
    if not text:
        return False
    haystack = f"{raw_url} {path}".lower()
    if text in haystack:
        return True

    path_tokens = re.findall(r"https?://[^\s)]+|/[A-Za-z0-9._~:/?#[\]@!$&'()*+,;=%{}-]+", text)
    if any(_memory_token_matches(token, haystack) for token in path_tokens):
        return True

    stopwords = {
        "about", "accounts", "after", "already", "before", "continue", "owned",
        "target", "tested", "validated", "with", "without",
    }
    keywords = [
        word for word in re.findall(r"[a-z0-9_]{4,}", text)
        if word not in stopwords
    ]
    return bool(keywords and any(word in haystack for word in keywords[:8]))


def _matching_target_memory_entries(
    target_goal_memory: dict,
    field: str,
    raw_url: str,
    path: str,
) -> list[dict]:
    return [
        item for item in _target_memory_entries(target_goal_memory, field)
        if _target_memory_entry_matches(item, raw_url, path)
    ]


def _build_target_memory_lead_hints(target_goal_memory: dict) -> list[dict]:
    """Convert remembered operator intent into soft workflow leads."""
    leads: list[dict] = []
    for item in _target_memory_entries(target_goal_memory, "active_leads")[-5:]:
        text = _target_memory_text(item)
        leads.append({
            "source": "target_memory",
            "title": text[:140],
            "category": "active-lead",
            "priority": "high",
            "next_action": f"continue validating remembered lead: {text}",
            "rationale": "Target memory marks this as an active lead from prior Claude CLI work.",
            "evidence": item.get("ts", ""),
        })

    for item in _target_memory_entries(target_goal_memory, "next_actions")[-5:]:
        text = _target_memory_text(item)
        leads.append({
            "source": "target_memory",
            "title": text[:140],
            "category": "next-action",
            "priority": "medium",
            "next_action": text,
            "rationale": "Target memory recorded this as a concrete next action.",
            "evidence": item.get("ts", ""),
        })

    return leads


def _build_cf_bypass_refresh_leads(context: dict) -> list[dict]:
    """把 CF 绕过态下的 403-only host 转成刷新提示，而不是丢进 kill。

    cf_solver 产出的 cf_clearance 与 User-Agent 绑定且会过期。只要
    recon/<target>/cf_cookies.txt 存在，就说明本轮曾尝试带绕过态访问；此时
    httpx 的 403-only 更像是 cookie 过期/UA 不匹配，而不是目标无价值。
    """
    if not context.get("cf_bypass_active"):
        return []

    recon_dir = Path(str(context.get("recon_dir") or ""))
    storage_key = target_storage_key(context.get("target", ""))
    leads: list[dict] = []
    for host in sorted(context.get("status403_hosts") or []):
        host_meta = (context.get("hosts") or {}).get(host) or {}
        url = str(host_meta.get("url") or host)
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"
        artifact = f"recon/{storage_key}/cf_cookies.txt"
        if recon_dir:
            cookie_path = recon_dir / "cf_cookies.txt"
            if cookie_path.is_file():
                artifact = str(cookie_path.relative_to(recon_dir.parent.parent))
        leads.append({
            "source": "cf_solver",
            "title": f"403-only host may need refreshed Cloudflare clearance: {host}",
            "category": "cf-bypass-refresh",
            "priority": "high",
            "artifact": artifact,
            "next_action": f"python3 tools/cf_solver.py --target {url} --check --auto-resolve",
            "rationale": (
                "cf_cookies.txt exists, so a 403-only recon result may indicate an expired "
                "cf_clearance or User-Agent mismatch; refresh before treating the host as dead."
            ),
            "evidence": host,
        })
    return leads


def _build_external_url_context_leads(
    context: dict,
    urls: list[str],
    *,
    total_count: int | None = None,
) -> list[dict]:
    """把第三方 URL 保留为链路上下文，不作为当前目标直接验证面。"""
    clean_urls = _dedupe_keep_order([str(url or "").strip() for url in urls if str(url or "").strip()])
    count = max(len(clean_urls), int(total_count or 0))
    if not count:
        return []
    storage_key = target_storage_key(context.get("target", ""))
    return [{
        "source": "external_url_context",
        "title": f"{count} third-party/integration URL(s) preserved as chain context",
        "category": "external-chain-context",
        "priority": "medium",
        "artifact": f"recon/{storage_key}/urls/all.txt",
        "next_action": (
            f"review recon/{storage_key}/urls/all.txt and browser/JS artifacts for target-owned "
            "integrations, hardcoded keys, OAuth/JWKS/webhook/CDN dependencies, or report-writing "
            "context; do not run direct vulnerability validation against third-party hosts unless "
            "ownership/scope is established"
        ),
        "rationale": (
            "External URLs can be useful chain intel, but ranking them as direct surface creates "
            "off-target false positives and unsafe validation suggestions."
        ),
        "evidence": ", ".join(clean_urls[:5]),
    }]


_WORKFLOW_LEAD_PRIORITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _sort_workflow_leads(leads: list[dict]) -> list[dict]:
    """Sort soft leads by priority without changing their semantics."""
    return [
        item
        for _, item in sorted(
            enumerate(leads),
            key=lambda pair: (
                _WORKFLOW_LEAD_PRIORITY_ORDER.get(
                    str(pair[1].get("priority", "medium") or "medium").lower(),
                    4,
                ),
                pair[0],
            ),
        )
    ]


def _build_evidence_convergence_leads(
    *,
    browser_urls: set[str],
    js_intel_urls: dict[str, list[dict]],
    source_intel_urls: dict[str, list[dict]],
) -> list[dict]:
    """把 browser / JS / source 的交叉命中转成可执行 workflow lead。"""
    leads: list[dict] = []
    all_urls = _dedupe_keep_order(
        list(browser_urls) + list(js_intel_urls.keys()) + list(source_intel_urls.keys())
    )
    for url in all_urls:
        sources = []
        if url in browser_urls:
            sources.append("browser")
        if js_intel_urls.get(url):
            sources.append("js")
        if source_intel_urls.get(url):
            sources.append("source")
        if len(sources) < 2:
            continue

        source_types = _dedupe_keep_order([
            str(item.get("type", "")).lower()
            for item in source_intel_urls.get(url, [])[:3]
            if item.get("type")
        ])
        js_methods = _dedupe_keep_order([
            str(item.get("method", "")).upper()
            for item in js_intel_urls.get(url, [])[:3]
            if item.get("method")
        ])
        action_bits = []
        if source_types:
            action_bits.append("source hypotheses: " + ", ".join(source_types[:3]))
        if js_methods:
            action_bits.append("JS methods: " + ", ".join(js_methods[:3]))
        leads.append({
            "source": "evidence_convergence",
            "title": url,
            "category": "+".join(sources),
            "priority": "critical" if len(sources) >= 3 else "high",
            "next_action": (
                "replay the browser-observed endpoint with JS/source-informed "
                "parameters and compare authz, object, role, and workflow behavior"
            ),
            "rationale": (
                " / ".join(sources)
                + " evidence converges on the same endpoint; this is stronger than any single source."
            ),
            "evidence": "; ".join(action_bits) or ", ".join(sources),
        })
    return leads[:5]


def _read_httpx_hosts(recon_dir: Path, target: str = "") -> tuple[dict[str, dict], set[str]]:
    """从共享组件清单读取 host metadata 与 403-only hosts。"""
    hosts = {}
    status403 = set()
    try:
        from tools.technology_inventory import load_or_build_inventory_for_recon_dir
    except ImportError:  # pragma: no cover - direct tools/ execution
        from technology_inventory import load_or_build_inventory_for_recon_dir

    inventory = load_or_build_inventory_for_recon_dir(recon_dir, target=target)
    if inventory.get("status") != "ready":
        return hosts, status403
    for item in inventory.get("hosts") or []:
        host = str(item.get("host") or "").strip()
        if not host:
            continue
        techs = []
        seen = set()
        for component in item.get("components") or []:
            name = str(component.get("name") or "").strip()
            if name and name not in seen:
                seen.add(name)
                techs.append(name)
        status = str(item.get("status") or "").strip()
        hosts[host] = {
            "url": str(item.get("url") or "").strip(),
            "host": host,
            "status": status,
            "title": str(item.get("title") or "").strip(),
            "tech_stack": techs,
        }
        if status == "403":
            status403.add(host)
    return hosts, status403


CONTEXTUAL_NUMERIC_ID_RE = re.compile(
    r"/(?:users?|accounts?|profiles?|members?|customers?|orgs?|organizations?|tenants?|workspaces?|"
    r"orders?|invoices?|tickets?|messages?|comments?|files?|addresses?|carts?|products?|items?)/"
    r"\d{1,8}(?:/|$)",
    re.I,
)

WEBSOCKET_ENDPOINT_RE = re.compile(r"(?:^|/)(?:ws|websocket)(?:/|$)", re.I)


def _has_contextual_numeric_id(path: str) -> bool:
    """Return true for numeric IDs with resource context, not bare `/<number>` pages."""
    return bool(CONTEXTUAL_NUMERIC_ID_RE.search(str(path or "")))


def _is_websocket_endpoint(path: str) -> bool:
    """Return true for an explicit WebSocket path segment, not a substring."""
    raw = str(path or "").strip()
    if not raw:
        return False
    parsed = urlparse(raw)
    candidate = parsed.path or raw.split("?", 1)[0].split("#", 1)[0]
    return bool(WEBSOCKET_ENDPOINT_RE.search(candidate))


def _candidate_reason(path: str, query_keys: list[str]) -> tuple[str, str]:
    lower = path.lower()
    if "graphql" in lower:
        return "GraphQL surface", "field-level auth checks and mutation abuse"
    if _is_websocket_endpoint(path):
        return "WebSocket candidate", "authorization checks on subscribe/send actions"
    if any(key in {"id", "user_id", "account_id", "order_id"} or key.endswith("_id") for key in query_keys):
        return "ID-bearing parameter", "ID swap and sibling endpoint access control checks"
    if _has_contextual_numeric_id(path):
        return "Sequential object reference", "numeric ID swap on GET/PUT/DELETE"
    if query_keys:
        return "Parameterized endpoint", "input tampering and auth boundary checks"
    return "API endpoint", "baseline authz and business-logic checks"


INTEL_KEYWORDS = {
    "graphql": ("graphql", "introspection", "mutation"),
    "idor": ("idor", "insecure direct object", "object reference", "account id", "user id"),
    "ssrf": ("ssrf", "server-side request forgery", "webhook", "callback"),
    "oauth": ("oauth", "oidc", "redirect_uri", "pkce", "state"),
    "redirect": ("open redirect", "return_to", "next="),
    "upload": ("upload", "file upload", "unrestricted file"),
    "sqli": ("sqli", "sql injection", "injection"),
    "xss": ("xss", "cross-site scripting"),
    "saml": ("saml", "sso", "assertion"),
    "mfa": ("mfa", "2fa", "otp", "totp"),
}


SCORE_SOURCE_LABELS = {
    "attack_value": "attack",
    "browser": "browser",
    "evidence_convergence": "converged",
    "recon": "recon",
    "memory": "memory",
    "scanner": "scanner",
    "intel": "intel",
    "js_intel": "js",
}

BROWSER_VALUE_KEYWORDS = (
    "graphql",
    "mutation",
    "export",
    "download",
    "account",
    "order",
    "user",
    "admin",
    "approve",
    "submit",
    "update",
    "delete",
    "invite",
)

REVIEW_POOL_LIMIT = 16
REVIEW_SIGNAL_GROUPS = (
    ("client-side", frozenset({"xss"})),
    ("auth", frozenset({"auth", "oauth", "saml", "secret"})),
    ("admin", frozenset({"admin", "internal"})),
    ("payment", frozenset({"billing", "payment"})),
    ("upload", frozenset({"upload"})),
    ("api", frozenset({"api"})),
    ("graphql", frozenset({"graphql", "websocket"})),
    ("file", frozenset({"file", "export", "download"})),
    ("server-side", frozenset({"server-side", "callback", "webhook"})),
    ("object", frozenset({"id-ref", "sequential", "tenant", "workspace", "account", "order"})),
)


def _add_score_breakdown(
    score_breakdown: list[dict],
    source: str,
    label: str,
    points: int,
    evidence: str = "",
) -> int:
    """Record one deterministic surface-ranking score contribution."""
    if points == 0:
        return 0

    item = {
        "source": source,
        "label": label,
        "score": points,
    }
    if evidence:
        item["evidence"] = evidence
    score_breakdown.append(item)
    return points


def _format_score_breakdown(item: dict) -> str:
    """Return a compact, grouped score explanation for terminal output."""
    total = item.get("score", 0)
    breakdown = item.get("score_breakdown") or []
    if not breakdown:
        return str(total)

    source_totals = {}
    source_order = []
    for part in breakdown:
        source = str(part.get("source", "other"))
        if source not in source_totals:
            source_totals[source] = 0
            source_order.append(source)
        source_totals[source] += int(part.get("score", 0) or 0)

    segments = []
    for source in source_order:
        points = source_totals[source]
        if points == 0:
            continue
        label = SCORE_SOURCE_LABELS.get(source, source)
        segments.append(f"{label} {points:+d}")

    if not segments:
        return str(total)
    return f"{total} = " + ", ".join(segments[:6])


def _add_review_item(
    pool: list[dict],
    seen: set[str],
    item: dict,
    reason: str,
    shape_counts: dict[str, int] | None = None,
) -> bool:
    """Add one surface item to the bounded AI review pool."""
    url = str(item.get("url") or "").strip()
    if not url or url in seen or len(pool) >= REVIEW_POOL_LIMIT:
        return False
    shape_id = str(_candidate_semantic_shape(item).get("id") or url)
    if shape_counts is not None and shape_counts.get(shape_id, 0) >= 2:
        return False
    seen.add(url)
    if shape_counts is not None:
        shape_counts[shape_id] = shape_counts.get(shape_id, 0) + 1
    cloned = dict(item)
    cloned["review_reason"] = reason
    pool.append(cloned)
    return True


def _is_final_surface_item(item: dict) -> bool:
    """Return True only for an explicitly finalized surface identity.

    Raw URL surface is not lane-specific. Authz/SQLi/SSRF 等任一 cell 关闭都
    不能隐藏整个 endpoint；精确 action 去重由 checkpoint/action_queue 负责。
    """
    return bool(item.get("surface_identity_final"))


ACTIONABLE_REVIEW_SOURCES = {
    "attack_value",
    "browser",
    "evidence_convergence",
    "intel",
    "js_intel",
    "scanner",
    "target_memory",
}


def _has_actionable_review_evidence(item: dict) -> bool:
    """Return true when a candidate has enough evidence to lead Claude's review.

    Recon-wide facts such as "non-standard port", "tech stack overlap", or
    "untested in memory" are useful tie-breakers, but they are not concrete
    next-action evidence by themselves. Keep those candidates in p1/p2
    compatibility output, yet avoid letting them crowd the AI review pool when
    browser/source/JS/scanner/parameter/intel evidence exists.
    """
    if any(
        item.get(key)
        for key in (
            "evidence_convergence",
            "browser_observed",
            "js_intel_observed",
            "source_intel_observed",
            "scanner_findings",
            "target_memory_hits",
            "intel_signals",
        )
    ):
        return True
    for part in item.get("score_breakdown") or []:
        source = str(part.get("source", ""))
        if source in ACTIONABLE_REVIEW_SOURCES and int(part.get("score", 0) or 0) > 0:
            return True
    return False


def _review_signal_groups(item: dict) -> tuple[str, ...]:
    """返回候选覆盖的高价值业务类别，不改变原始 URL identity。"""
    raw_url = str(item.get("url") or "").strip()
    parsed = urlparse(raw_url)
    path = parsed.path or "/"
    query_keys = [key.lower() for key in re.findall(r"[?&]([^=&]+)=", raw_url)]
    evidence = " ".join(
        str(value or "")
        for value in (item.get("suggested"), *(item.get("reasons") or []))
    )
    classes = set(
        classify_high_value_signal(
            path=path,
            query_keys=query_keys,
            evidence=evidence,
        ).classes
    )
    return tuple(
        group
        for group, members in REVIEW_SIGNAL_GROUPS
        if classes.intersection(members)
    )


def _category_review_reason(item: dict, groups: tuple[str, ...]) -> str:
    if item.get("evidence_convergence"):
        return "cross-evidence convergence"
    if item.get("browser_observed"):
        return "browser-observed API/workflow"
    if item.get("js_intel_observed") or item.get("source_intel_observed"):
        return "JS/source-inferred surface"
    if item.get("scanner_findings"):
        return "scanner lead requiring AI triage"
    if item.get("target_memory_hits"):
        return "target-memory continuation"
    return "high-value category: " + "/".join(groups[:4])


def _candidate_semantic_shape(item: dict) -> dict:
    """Build a semantic identity from URL plus optional observed request metadata."""
    observed = item.get("request_shapes") if isinstance(item.get("request_shapes"), list) else []
    if not observed:
        return surface_shape(str(item.get("url") or ""))
    methods = sorted({str(entry.get("method") or "GET").upper() for entry in observed if isinstance(entry, dict)})
    content_types = set()
    body_parameter_names = set()
    graphql_operations = set()
    for entry in observed:
        if not isinstance(entry, dict):
            continue
        body = entry.get("body") if isinstance(entry.get("body"), dict) else {}
        if body.get("content_type_hint"):
            content_types.add(str(body["content_type_hint"]).lower())
        body_parameter_names.update(str(name) for name in body.get("parameter_names") or [] if str(name))
        graphql_operations.update(str(name) for name in body.get("graphql_operations") or [] if str(name))
    return surface_request_shape(
        str(item.get("url") or ""),
        method="|".join(methods) or "GET",
        content_type="|".join(sorted(content_types)),
        body_parameter_names=body_parameter_names,
        graphql_operations=graphql_operations,
    )


def _build_review_pool(
    candidates: list[dict],
    ffuf_candidates: list[dict] | None = None,
) -> list[dict]:
    """Build an AI-first review pool without treating score as a verdict.

    `p1` / `p2` remain for backward-compatible callers. This pool is the
    preferred Claude-facing surface, so it starts with evidence-rich sources
    that are hard for regex scoring to judge correctly. Score-only candidates
    stay visible in p1/p2, but only become a fallback pool when no actionable
    evidence exists. That keeps tools from steering Claude toward generic
    recon/memory-only paths before real browser/source/scanner evidence.
    """
    pool: list[dict] = []
    seen: set[str] = set()
    shape_counts: dict[str, int] = {}
    unresolved = [item for item in candidates if not _is_final_surface_item(item)]

    # New observations are neutral facts, not a score source.  Keep two exact
    # matches visible before the ordinary evidence-led review seats fill up.
    for item in unresolved:
        if item.get("new_observation"):
            reason = (
                "browser-observed API/workflow" if item.get("browser_observed")
                else "JS/source-inferred surface" if item.get("js_intel_observed") or item.get("source_intel_observed")
                else "top advisory score" if _has_actionable_review_evidence(item)
                else "top advisory score (low-evidence fallback)"
            )
            _add_review_item(pool, seen, item, reason, shape_counts)
            if len(pool) == 2:
                break

    # 先保留各业务类别的最高分代表，避免大量同源 search/facet 路径占满 16 条。
    represented_groups: set[str] = set()
    for item in unresolved:
        groups = _review_signal_groups(item)
        if not groups or represented_groups.issuperset(groups):
            continue
        if _add_review_item(pool, seen, item, _category_review_reason(item, groups), shape_counts):
            represented_groups.update(groups)

    for item in unresolved:
        if item.get("evidence_convergence"):
            _add_review_item(pool, seen, item, "cross-evidence convergence", shape_counts)
    for item in unresolved:
        if item.get("browser_observed"):
            _add_review_item(pool, seen, item, "browser-observed API/workflow", shape_counts)
    for item in unresolved:
        if item.get("js_intel_observed") or item.get("source_intel_observed"):
            _add_review_item(pool, seen, item, "JS/source-inferred surface", shape_counts)
    for item in unresolved:
        if item.get("scanner_findings"):
            _add_review_item(pool, seen, item, "scanner lead requiring AI triage", shape_counts)
    for item in unresolved:
        if item.get("target_memory_hits"):
            _add_review_item(pool, seen, item, "target-memory continuation", shape_counts)
    for item in unresolved:
        if _has_actionable_review_evidence(item):
            _add_review_item(pool, seen, item, "top advisory score", shape_counts)
    for item in ffuf_candidates or []:
        _add_review_item(pool, seen, item, "ffuf-observed route; AI triage required", shape_counts)
    if not pool:
        for item in unresolved:
            _add_review_item(pool, seen, item, "top advisory score (low-evidence fallback)", shape_counts)
        for item in unresolved:
            _add_review_item(pool, seen, item, "top advisory score (low-evidence fallback)")
    else:
        eligible = [
            item
            for item in unresolved
            if not (item.get("new_observation") and not _has_actionable_review_evidence(item))
            and (_review_signal_groups(item) or _has_actionable_review_evidence(item))
        ]
        for item in eligible:
            _add_review_item(pool, seen, item, "top advisory score", shape_counts)
        for item in eligible:
            _add_review_item(pool, seen, item, "top advisory score")
    return pool


def _build_ffuf_review_candidates(
    ffuf_summary: dict,
    target: str,
    candidates: list[dict],
) -> list[dict]:
    """构建中性 FFUF sample，不让其进入价值打分。"""
    if not ffuf_summary.get("available"):
        return []
    by_url = {
        str(item.get("url") or "").strip(): item
        for item in candidates
        if str(item.get("url") or "").strip()
    }
    result = []
    for observation in (ffuf_summary.get("review_sample") or [])[:4]:
        if not isinstance(observation, dict):
            continue
        url = str(observation.get("url") or "").strip()
        if not url or not url_belongs_to_target(url, target):
            continue
        response_meta = {
            key: observation.get(key)
            for key in (
                "status",
                "length",
                "words",
                "lines",
                "content_type",
                "redirect_location",
                "input",
            )
        }
        existing = by_url.get(url)
        if existing is not None:
            existing["ffuf_observed"] = True
            existing["ffuf_observation"] = response_meta
            result.append(existing)
            continue

        parsed = urlparse(url)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        result.append({
            "url": url,
            "host": parsed.netloc,
            "path": path,
            "score": 0,
            "score_breakdown": [],
            "reasons": ["FFUF observation"],
            "suggested": (
                "inspect cached response metadata and current business/browser/source context, "
                "then let AI choose whether a focused replay is warranted"
            ),
            "tech_stack": [],
            "ffuf_observed": True,
            "ffuf_observation": response_meta,
        })
    return result


def _load_intel_context(recon_dir: Path) -> dict:
    """通过 artifact owner 读取 Intel，并投影为 Surface 信号与覆盖状态。"""
    projection = load_intel_projection(recon_dir)
    review_items = [
        item for item in projection.get("review_items") or [] if isinstance(item, dict)
    ]
    signals = []
    seen = set()
    for item in review_items:
        if not isinstance(item, dict) or not advisory_is_actionable(item):
            continue
        component = item.get("component") if isinstance(item.get("component"), dict) else {}
        haystack = " ".join(
            str(item.get(key, ""))
            for key in (
                "id",
                "source",
                "source_names",
                "tech",
                "severity",
                "summary",
                "note",
                "applicability",
            )
        ).lower()
        haystack += " " + " ".join(
            str(component.get(key, "")) for key in ("name", "display_name", "version")
        ).lower()
        for vuln_class, keywords in INTEL_KEYWORDS.items():
            if any(keyword in haystack for keyword in keywords):
                severity = str(item.get("severity", "INFO")).upper()
                key = (vuln_class, str(item.get("id", "")), str(item.get("summary", ""))[:120])
                if key in seen:
                    continue
                seen.add(key)
                source_names = item.get("source_names") if isinstance(item.get("source_names"), list) else []
                signals.append({
                    "class": vuln_class,
                    "severity": severity,
                    "source": ",".join(str(value) for value in source_names if value)
                    or item.get("source", "intel"),
                    "id": item.get("id", ""),
                    "summary": item.get("summary", ""),
                    "applicability": normalize_advisory_applicability(item.get("applicability")),
                    "score_hint": item.get("score_hint", 0),
                    "kev": bool(item.get("kev")),
                    "epss": item.get("epss"),
                })
    sources = [item for item in projection.get("sources") or [] if isinstance(item, dict)]
    degraded_sources = [
        {
            "source": item.get("source", ""),
            "status": item.get("status", "unknown"),
            "error": item.get("error", ""),
            "stale": bool(item.get("stale")),
        }
        for item in sources
        if item.get("status") != "ok"
    ]
    return {
        "status": projection.get("status", "invalid"),
        "coverage_status": projection.get("coverage_status", "error"),
        "path": projection.get("path", ""),
        "error": projection.get("error", ""),
        "sources": sources,
        "degraded_sources": degraded_sources,
        "review_items": review_items,
        "review_item_count": len(review_items),
        "signals": signals,
        "signal_count": len(signals),
    }


def _intel_signal_matches(signal: dict, raw_url: str, path: str, query_keys: list[str], tech_stack: list[str]) -> bool:
    """Return whether an intel signal is relevant to a surface candidate."""
    klass = signal.get("class", "")
    lower_url = raw_url.lower()
    lower_path = path.lower()
    keys = set(query_keys)
    tech = {item.lower() for item in tech_stack}

    if klass == "graphql":
        return "graphql" in lower_url or "graphql" in tech
    if klass == "idor":
        return (
            bool(keys & {"id", "user_id", "account_id", "order_id"})
            or any(key.endswith("_id") for key in keys)
            or _has_contextual_numeric_id(lower_path)
        )
    if klass == "ssrf":
        return bool(keys & {"url", "uri", "dest", "destination", "callback", "webhook", "target", "next", "return"})
    if klass == "oauth":
        return "oauth" in lower_url or "oidc" in lower_url or bool(keys & {"redirect_uri", "state", "code", "client_id"})
    if klass == "redirect":
        return bool(keys & {"redirect", "redirect_uri", "return", "return_to", "next", "url", "continue", "callback"})
    if klass == "upload":
        return "upload" in lower_url or "file" in lower_url or "avatar" in lower_url or "media" in lower_url
    if klass == "sqli":
        return bool(query_keys)
    if klass == "xss":
        return bool(query_keys) or "search" in lower_url
    if klass == "saml":
        return "saml" in lower_url or "sso" in lower_url
    if klass == "mfa":
        return any(token in lower_url for token in ("mfa", "2fa", "otp", "totp", "verify"))
    return False


def _intel_signal_bonus(signal: dict) -> int:
    severity = str(signal.get("severity", "INFO")).upper()
    if severity == "CRITICAL":
        return 6
    if severity == "HIGH":
        return 5
    if severity in {"MEDIUM", "MODERATE"}:
        return 3
    return 1


def _intel_candidate_bonus(signal: dict, query_keys: list[str]) -> int:
    """Boost stronger URL-level matches for an intel signal."""
    klass = signal.get("class", "")
    keys = set(query_keys)
    if klass == "oauth" and keys & {"redirect_uri", "state", "code", "client_id"}:
        return 4
    if klass == "redirect" and keys & {"redirect", "redirect_uri", "return", "return_to", "next", "url", "continue", "callback"}:
        return 3
    if klass == "ssrf" and keys & {"url", "uri", "dest", "destination", "callback", "webhook", "target"}:
        return 3
    if klass in {"idor", "sqli", "xss"} and query_keys:
        return 2
    return 0


def _finding_score_bonus(finding: dict) -> int:
    """Return deterministic score boost from scanner finding confidence."""
    severity = (finding.get("severity") or "").lower()
    confidence = (finding.get("confidence") or "").lower()
    vuln_type = (finding.get("type") or finding.get("category") or "").lower()
    validation_status = (finding.get("validation_status") or "").lower()
    report_status = (finding.get("report_status") or "").lower()

    if report_status == "generated":
        return -20

    score = 0
    if severity == "critical":
        score += 9
    elif severity == "high":
        score += 7
    elif severity == "medium":
        score += 4
    elif severity == "low":
        score += 1

    if confidence == "confirmed":
        score += 6
    elif confidence == "high":
        score += 4
    elif confidence == "medium":
        score += 2

    if vuln_type in {"sqli", "ssti", "upload", "saml", "auth_bypass"}:
        score += 2
    elif vuln_type in {"mfa", "ssrf", "idor"}:
        score += 1

    if validation_status == "validated":
        score += 3

    if score < 1:
        return 1
    return score


def _project_untrusted_finality_as_candidate(
    finding: dict,
    *,
    findings_dir: Path,
    target: str,
) -> dict:
    """Keep an edited finality claim visible without letting it close surface work.

    ``surface`` is a reader, not a second finding owner.  When a row declares
    a final lifecycle state without a matching owner event, preserve its URL as
    a candidate but remove the untrusted validation/report bonus and closure
    signal from this read-only projection.
    """
    if str(finding.get("validation_status") or "").strip().lower() == "needs_owner_revalidation":
        projected = dict(finding)
        projected["claimed_validation_status"] = str(
            finding.get("claimed_validation_status") or "needs_owner_revalidation"
        )
        projected["claimed_report_status"] = str(
            finding.get("claimed_report_status") or finding.get("report_status") or ""
        )
        projected["validation_status"] = "candidate"
        projected["report_status"] = "not_generated"
        projected["lifecycle_status"] = "needs_owner_revalidation"
        projected["provenance_reason"] = str(
            finding.get("owner_revalidation_reason") or "owner-provenance-invalid"
        )
        return projected

    provenance = verify_finalized_finding_owner_provenance(
        findings_dir,
        finding,
        target=target,
    )
    if not provenance.get("required") or provenance.get("valid"):
        return finding
    projected = dict(finding)
    projected["claimed_validation_status"] = str(finding.get("validation_status") or "")
    projected["claimed_report_status"] = str(finding.get("report_status") or "")
    projected["validation_status"] = "candidate"
    projected["report_status"] = "not_generated"
    projected["lifecycle_status"] = "needs_owner_revalidation"
    projected["provenance_reason"] = str(provenance.get("reason") or "owner-provenance-invalid")
    return projected


def _source_intel_score_bonus(hypothesis: dict) -> int:
    """Return deterministic score boost from source_intel hypothesis type."""
    hypothesis_type = str(hypothesis.get("type", "")).lower()
    if hypothesis_type == "idor":
        return 5
    if hypothesis_type == "auth-bypass":
        return 4
    if hypothesis_type == "business-logic":
        return 4
    if hypothesis_type in {"websocket", "oauth", "ssrf"}:
        return 4
    if hypothesis_type in {"upload", "webhook"}:
        return 3
    if hypothesis_type in {"framework-intel", "csrf"}:
        return 2
    return 2


def _source_intel_suggestion(hypotheses: list[dict], fallback: str) -> str:
    """Suggest next action for a source-intel-backed surface candidate."""
    types = {
        str(item.get("type", "")).lower()
        for item in hypotheses
        if item.get("type")
    }
    if "idor" in types:
        return "prioritize ID swap, sibling object access, and role-diff checks from source_intel"
    if "auth-bypass" in types:
        return "probe auth/role/tenant boundary checks from source_intel before broad fuzzing"
    if "business-logic" in types:
        return "replay the workflow or GraphQL mutation sequence from source_intel with authz/state diffs"
    if "websocket" in types:
        return "capture WS handshake/frames, then compare Origin and frame-level authz across owned roles"
    if "oauth" in types:
        return "review OAuth/OIDC redirect/state/session binding and email-normalization before generic auth tests"
    if "ssrf" in types:
        return "prove server-side fetch with a controlled callback before internal/metadata follow-up"
    if "upload" in types:
        return "inspect upload/import parser and authorization boundaries with minimal benign samples"
    if "webhook" in types:
        return "review webhook signature, replay, ownership, and SSRF-adjacent URL handling"
    if "csrf" in types:
        return "analyze CSRF token/SameSite binding; do not perform state-changing proof by default"
    return fallback


def _scanner_suggestion(finding: dict, fallback: str) -> str:
    """Suggest next action for a scanner-backed surface candidate."""
    vuln_type = (finding.get("type") or finding.get("category") or "").lower()
    confidence = (finding.get("confidence") or "").lower()
    source = finding.get("source_file") or "findings.json"
    report_status = (finding.get("report_status") or "").lower()
    if report_status == "generated":
        return "already reported/generated; avoid repeating unless new evidence changes impact or scope"
    if confidence in {"confirmed", "high"}:
        return f"validate {vuln_type or 'scanner'} evidence from {source}, then prepare report"
    return f"review scanner candidate from {source}; {fallback}"


def _action_queue_final_endpoints(actions: list[dict]) -> dict[str, str]:
    """Return endpoint-level queue history for advisory display only.

    Queue rows often lack a precise vulnerability class and evidence timestamp.
    Therefore this map must never become a closure filter: a final Authz action on
    one endpoint cannot hide SQLi/GraphQL/new browser evidence on the same path.
    """
    endpoints: dict[str, str] = {}
    for action in actions:
        if not isinstance(action, dict):
            continue
        status = str(action.get("status") or "").strip().lower()
        if status not in ACTION_QUEUE_FINAL_STATUSES:
            continue
        metadata = action.get("metadata") if isinstance(action.get("metadata"), dict) else {}
        endpoint = canonical_endpoint_path(str(metadata.get("endpoint") or ""))
        if not endpoint:
            endpoint = canonical_endpoint_path(str(metadata.get("url") or ""))
        if endpoint:
            endpoints[endpoint] = status
    return endpoints


def _surface_vuln_hint(path: str, suggested: str, query_keys: list[str]) -> str:
    """Best-effort vuln class for matching a surface candidate to ledger facts."""
    text = f"{path} {suggested}".lower()
    if "sqli" in text or "sql injection" in text:
        return "SQLi"
    if "ssrf" in text or any(
        key in {"url", "uri", "dest", "destination", "callback", "webhook", "target"}
        for key in query_keys
    ):
        return "SSRF"
    if "id swap" in text or "idor" in text or any(key.endswith("_id") for key in query_keys):
        return "IDOR"
    if "authz" in text or "authorization" in text or "auth boundary" in text or "access control" in text:
        return "Authz"
    if any(token in text for token in ("admin", "account", "order", "payment", "tenant", "user")):
        return "Authz"
    return ""


def load_surface_context(
    repo_root: str | Path,
    target: str,
    memory_dir: str | Path | None = None,
    *,
    write_probe_log: bool = True,
) -> dict:
    """Load recon + memory data for the surface review pack."""
    repo_root = Path(repo_root)
    storage_key = target_storage_key(target)
    recon_dir = repo_root / "recon" / storage_key
    findings_dir = repo_root / "findings" / storage_key
    runtime_state = load_runtime_state(repo_root, target)
    recon_artifacts = inspect_recon_artifacts(repo_root, target)
    owner_projection = derive_owner_projection(repo_root, target)
    target_goal_memory = _load_target_goal_memory(repo_root, target)
    if not recon_dir.is_dir():
        return {
            "target": target,
            "available": False,
            "runtime_state": runtime_state,
            "recon_artifacts": recon_artifacts,
            "owner_projection": owner_projection,
            "target_goal_memory": target_goal_memory,
        }

    hosts, status403_hosts = _read_httpx_hosts(recon_dir, target)
    browser_request_shapes = _load_browser_request_shapes(recon_dir)
    surface_index_status = load_surface_index_status(repo_root, target)
    use_surface_index = surface_index_status.get("status") == "valid"
    # Payload-marker handling: never lose the endpoint/parameter surface during
    # discovery. Raw historical probes are logged for review, while inert
    # probe-derived shapes stay in ranking so a noisy archive cannot hide a
    # real attack surface.
    _probe_log = recon_dir / "urls" / "_filtered_attack_probes.txt"
    probe_log_path = None
    if write_probe_log:
        _probe_log.parent.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(
            prefix=f".{_probe_log.name}.",
            dir=_probe_log.parent,
        )
        os.close(fd)
        probe_log_path = Path(temp_name)
    try:
        if use_surface_index:
            # 完整 URL 正文由 index iterator 流式消费；这里不再把 30 万行物化成 list。
            api_urls = []
            param_urls = []
            js_endpoints = []
            browser_xhr_urls = []
            browser_api_urls = []
        else:
            api_urls = filter_attack_probes(
                _read_lines(recon_dir / "urls" / "api_endpoints.txt"),
                log_path=probe_log_path,
                preserve_surfaces=True,
            )
            param_urls = filter_attack_probes(
                _read_lines(recon_dir / "urls" / "with_params.txt"),
                log_path=probe_log_path,
                preserve_surfaces=True,
            )
            js_endpoints = filter_attack_probes(
                _read_lines(recon_dir / "js" / "endpoints.txt"),
                log_path=probe_log_path,
                preserve_surfaces=True,
            )
            browser_xhr_urls = filter_attack_probes(
                _read_lines(recon_dir / "browser" / "xhr_endpoints.txt"),
                log_path=probe_log_path,
                preserve_surfaces=True,
            )
            browser_api_urls = filter_attack_probes(
                _read_lines(recon_dir / "browser" / "api_endpoints.txt"),
                log_path=probe_log_path,
                preserve_surfaces=True,
            )
        if probe_log_path is not None:
            if probe_log_path.stat().st_size:
                os.replace(probe_log_path, _probe_log)
            else:
                probe_log_path.unlink()
                _probe_log.unlink(missing_ok=True)
    except Exception:
        if probe_log_path is not None:
            probe_log_path.unlink(missing_ok=True)
        raise
    finding_index = load_finding_index(
        findings_dir,
        target=target,
        allow_legacy=True,
    )
    scanner_findings = [
        _project_untrusted_finality_as_candidate(
            item,
            findings_dir=findings_dir,
            target=target,
        )
        for item in finding_index.get("findings", [])
        if isinstance(item, dict) and item.get("url")
        and url_belongs_to_target(str(item.get("url") or ""), target)
    ]
    ledger_entries = load_evidence_ledger_entries(repo_root, target)
    coverage_matrix = load_matrix(target, repo_root=repo_root)
    action_queue_entries = load_action_queue(repo_root, target).get("actions", [])
    intel_context = _load_intel_context(recon_dir)
    intel_signals = intel_context["signals"]
    ffuf_summary = ReconAdapter(recon_dir).get_ffuf_summary()
    js_intel = load_js_intel_hypotheses(findings_dir)
    source_intel = load_source_intel_hypotheses(findings_dir)
    scanner_manual_review = _load_scanner_manual_review(findings_dir, target)
    manual_review_leads = _build_manual_review_lead_hints(findings_dir, storage_key)
    observation_inventory = _sync_observation_inventory(repo_root, target)

    profile = None
    pattern_matches = []
    if memory_dir:
        profile = load_target_profile(memory_dir, target)
        tech_stack = profile.get("tech_stack", []) if profile else []
        if tech_stack:
            pattern_db = PatternDB(Path(memory_dir) / "patterns.jsonl")
            # B12d R5 — /surface ranking auto-deprioritises low-precision
            # patterns by passing calibrated=True; PatternDB.match() consults
            # hunt-memory/pattern_calibration.jsonl and excludes patterns
            # with samples>=5 AND precision<0.2.
            for pattern in pattern_db.match(
                tech_stack=tech_stack,
                calibrated=True,
                calibration_path=Path(memory_dir) / "pattern_calibration.jsonl",
            ):
                if pattern.get("target") == target:
                    continue
                pattern_matches.append({
                    "target": pattern.get("target", ""),
                    "technique": pattern.get("technique", ""),
                    "vuln_class": pattern.get("vuln_class", ""),
                    "payout": pattern.get("payout", 0),
                })

    # Per-page JS loading map (PR-19). Empty when no browser captures yet.
    # We build closures over the loaded map so callers can answer
    # "which page loads this JS file?" without juggling raw dicts.
    try:
        from tools.browser_surface import load_page_js_map
    except ImportError:  # pragma: no cover - top-level import path
        from browser_surface import load_page_js_map
    _page_js_map = load_page_js_map(repo_root / "recon", storage_key)
    _pages_lookup = _page_js_map.get("pages", {}) if isinstance(_page_js_map, dict) else {}
    _js_index = _page_js_map.get("js_index", {}) if isinstance(_page_js_map, dict) else {}

    def pages_for_js(js_url: str) -> list[str]:
        return list(_js_index.get(js_url, []))

    def js_for_page(page_url: str) -> list[str]:
        entry = _pages_lookup.get(page_url, {})
        if not isinstance(entry, dict):
            return []
        return list(entry.get("js_files", []))

    return {
        "target": target,
        "available": True,
        "repo_root": str(repo_root),
        "recon_dir": str(recon_dir),
        "cf_bypass_active": (recon_dir / "cf_cookies.txt").is_file(),
        "hosts": hosts,
        "status403_hosts": status403_hosts,
        "api_urls": api_urls,
        "param_urls": param_urls,
        "js_endpoints": js_endpoints,
        "browser_xhr_urls": browser_xhr_urls,
        "browser_api_urls": browser_api_urls,
        "browser_request_shapes": browser_request_shapes,
        "surface_index": surface_index_status,
        "scanner_findings": scanner_findings,
        "ledger_entries": ledger_entries,
        "ledger_summary": build_current_cell_projection(ledger_entries),
        "coverage_matrix": coverage_matrix,
        "action_queue_entries": action_queue_entries if isinstance(action_queue_entries, list) else [],
        "intel_signals": intel_signals,
        "intel": intel_context,
        "ffuf_summary": ffuf_summary,
        "js_intel": js_intel,
        "source_intel": source_intel,
        "scanner_manual_review": scanner_manual_review,
        "manual_review_leads": manual_review_leads,
        "observation_inventory": observation_inventory,
        "target_goal_memory": target_goal_memory,
        "profile": profile,
        "owner_projection": owner_projection,
        "runtime_state": runtime_state,
        "recon_artifacts": recon_artifacts,
        "pattern_matches": _dedupe_keep_order(
            [json.dumps(item, sort_keys=True) for item in pattern_matches]
        ),
        "page_js_map": _page_js_map,
        "pages_for_js": pages_for_js,
        "js_for_page": js_for_page,
    }


class _BoundedCandidateFrontier:
    """按 legacy ``score desc, first-seen asc`` 保留固定数量候选。"""

    def __init__(self, limit: int):
        self.limit = limit
        self._heap: list[tuple[int, int, str, dict]] = []

    def add(self, item: dict, sequence: int) -> None:
        quality = (int(item.get("score", 0) or 0), -int(sequence), str(item.get("url") or ""), item)
        if len(self._heap) < self.limit:
            heapq.heappush(self._heap, quality)
            return
        if quality[:3] > self._heap[0][:3]:
            heapq.heapreplace(self._heap, quality)

    def values(self) -> list[tuple[int, dict]]:
        return [
            (-negative_sequence, item)
            for _score, negative_sequence, _url, item in sorted(
                self._heap,
                key=lambda value: (-value[0], -value[1], value[2]),
            )
        ]


class _DiverseBoundedCandidateFrontier:
    """Keep top exact candidates plus bounded top representatives per route shape."""

    def __init__(self, limit: int):
        self.limit = limit
        self._overall = _BoundedCandidateFrontier(limit)
        self._shapes: dict[str, tuple[int, dict]] = {}

    @staticmethod
    def _better_representative(
        left_sequence: int,
        left: dict,
        right_sequence: int,
        right: dict,
    ) -> bool:
        """Prefer score, then legacy first-seen order, then stable URL."""
        left_score = int(left.get("score", 0) or 0)
        right_score = int(right.get("score", 0) or 0)
        if left_score != right_score:
            return left_score > right_score
        if left_sequence != right_sequence:
            return left_sequence < right_sequence
        return str(left.get("url") or "") < str(right.get("url") or "")

    def _worst_shape(self) -> tuple[str, tuple[int, dict]]:
        iterator = iter(self._shapes.items())
        worst_shape, worst = next(iterator)
        for shape_id, candidate in iterator:
            if self._better_representative(
                worst[0], worst[1], candidate[0], candidate[1]
            ):
                worst_shape, worst = shape_id, candidate
        return worst_shape, worst

    def add(self, item: dict, sequence: int) -> None:
        self._overall.add(item, sequence)
        url = str(item.get("url") or "")
        shape_id = str(_candidate_semantic_shape(item).get("id") or url)
        current = self._shapes.get(shape_id)
        if current is not None:
            if self._better_representative(sequence, item, current[0], current[1]):
                self._shapes[shape_id] = (sequence, item)
            return
        if len(self._shapes) < self.limit:
            self._shapes[shape_id] = (sequence, item)
            return
        worst_shape, worst = self._worst_shape()
        if self._better_representative(sequence, item, worst[0], worst[1]):
            del self._shapes[worst_shape]
            self._shapes[shape_id] = (sequence, item)

    def values(self) -> list[tuple[int, dict]]:
        selected = sorted(
            self._shapes.values(),
            key=lambda value: (-int(value[1].get("score", 0) or 0), value[0], str(value[1].get("url") or "")),
        )
        seen = {str(item.get("url") or "") for _sequence, item in selected}
        for sequence, item in self._overall.values():
            url = str(item.get("url") or "")
            if url not in seen:
                selected.append((sequence, item))
                seen.add(url)
            if len(selected) >= self.limit:
                break
        return sorted(
            selected[: self.limit],
            key=lambda value: (-int(value[1].get("score", 0) or 0), value[0], str(value[1].get("url") or "")),
        )


class _SurfaceCandidateFrontiers:
    """生成兼容 P1/P2/review pool 所需的 bounded deterministic 子集。"""

    def __init__(self, ffuf_urls: set[str]):
        self.total = 0
        self.p1 = _DiverseBoundedCandidateFrontier(8)
        self.p2 = _DiverseBoundedCandidateFrontier(8)
        self.overall = _DiverseBoundedCandidateFrontier(REVIEW_POOL_LIMIT)
        self.review = {
            name: _DiverseBoundedCandidateFrontier(REVIEW_POOL_LIMIT)
            for name in (
                "convergence",
                "browser",
                "intel",
                "scanner",
                "target_memory",
                "actionable",
            )
        }
        self.categories = {
            name: _BoundedCandidateFrontier(1)
            for name, _members in REVIEW_SIGNAL_GROUPS
        }
        self.ffuf_urls = ffuf_urls
        self.ffuf_matches: dict[str, tuple[int, dict]] = {}
        self.new_observations: list[tuple[int, dict]] = []

    def add(self, item: dict, sequence: int) -> None:
        self.total += 1
        score = int(item.get("score", 0) or 0)
        if score >= 8:
            self.p1.add(item, sequence)
        elif 3 <= score < 8:
            self.p2.add(item, sequence)
        self.overall.add(item, sequence)
        if item.get("evidence_convergence"):
            self.review["convergence"].add(item, sequence)
        if item.get("browser_observed"):
            self.review["browser"].add(item, sequence)
        if item.get("js_intel_observed") or item.get("source_intel_observed"):
            self.review["intel"].add(item, sequence)
        if item.get("scanner_findings"):
            self.review["scanner"].add(item, sequence)
        if item.get("target_memory_hits"):
            self.review["target_memory"].add(item, sequence)
        if _has_actionable_review_evidence(item):
            self.review["actionable"].add(item, sequence)
        for category in _review_signal_groups(item):
            self.categories[category].add(item, sequence)
        url = str(item.get("url") or "")
        if url in self.ffuf_urls:
            self.ffuf_matches[url] = (sequence, item)
        if item.get("new_observation"):
            self.new_observations.append((sequence, item))
            self.new_observations.sort(key=lambda value: value[0])
            del self.new_observations[2:]

    def review_candidates(self) -> list[dict]:
        by_url: dict[str, tuple[int, dict]] = {}
        frontiers = [*self.review.values(), *self.categories.values(), self.overall]
        for frontier in frontiers:
            for sequence, item in frontier.values():
                url = str(item.get("url") or "")
                current = by_url.get(url)
                if url and (current is None or sequence < current[0]):
                    by_url[url] = (sequence, item)
        for url, value in self.ffuf_matches.items():
            by_url.setdefault(url, value)
        for sequence, item in self.new_observations:
            by_url.setdefault(str(item.get("url") or ""), (sequence, item))
        return [
            item
            for sequence, item in sorted(
                by_url.values(),
                key=lambda value: (-int(value[1].get("score", 0) or 0), value[0]),
            )
        ]


def _enrich_bounded_candidates(candidates: list[dict]) -> None:
    """Attach bounded value metadata only after the streaming frontier is selected."""
    seen: set[str] = set()
    for item in candidates:
        if not isinstance(item, dict):
            continue
        url = str(item.get("url") or "")
        if not url or url in seen:
            continue
        seen.add(url)
        item.setdefault("semantic_shape", _candidate_semantic_shape(item))
        summary = surface_value_summary(url)
        if summary.get("signal_count"):
            item["value_summary"] = summary


def _build_semantic_surface(context: dict, candidates: list[dict]) -> list[dict]:
    """Summarize selected shapes without creating lifecycle state."""
    groups: dict[str, dict] = {}
    base_ids: set[str] = set()
    for item in candidates:
        if not isinstance(item, dict) or not str(item.get("url") or ""):
            continue
        semantic = item.get("semantic_shape") or _candidate_semantic_shape(item)
        shape_id = str(semantic.get("id") or "")
        if not shape_id:
            continue
        base_id = str(semantic.get("url_shape_id") or shape_id)
        base_ids.add(base_id)
        entry = groups.setdefault(
            shape_id,
            {
                "shape_id": shape_id,
                "url_shape_id": base_id,
                "path_template": semantic.get("path_template", ""),
                "parameter_names": [name for name, _count in semantic.get("parameter_multiset", [])],
                "methods": [method for method in str(semantic.get("method") or "").split("|") if method],
                "content_types": [value for value in str(semantic.get("content_type") or "").split("|") if value],
                "candidate_count": 0,
                "active_variant_count": 0,
                "sources": set(),
                "representatives": [],
                "value_classes": set(),
            },
        )
        entry["candidate_count"] += 1
        entry["representatives"].append((int(item.get("score", 0) or 0), str(item.get("url") or "")))
        for signal in (item.get("value_summary") or {}).get("signals", []):
            entry["value_classes"].update(str(value) for value in signal.get("classes", []) if str(value))
        for source in ("browser" if item.get("browser_observed") else "", "js" if item.get("js_intel_observed") else "", "source" if item.get("source_intel_observed") else "", "scanner" if item.get("scanner_findings") else ""):
            if source:
                entry["sources"].add(source)

    index_status = context.get("surface_index") or {}
    if index_status.get("status") == "valid" and base_ids:
        index_repo = context.get("repo_root") or Path(BASE_DIR)
        entries_by_base: dict[str, list[dict]] = {}
        for entry in groups.values():
            base_id = str(entry.get("url_shape_id") or "")
            if base_id:
                entries_by_base.setdefault(base_id, []).append(entry)
        for row in iter_surface_index(index_repo, context["target"]):
            base_id = str(row.get("shape_id") or "")
            entries = entries_by_base.get(base_id)
            if not entries:
                continue
            row_sources = {str(value) for value in row.get("sources", []) if str(value)}
            for entry in entries:
                entry["active_variant_count"] += 1
                entry["sources"].update(row_sources)
    else:
        for entry in groups.values():
            entry["active_variant_count"] = entry["candidate_count"]

    storage_key = target_storage_key(context["target"])
    raw_reference = ""
    for suffix in ("all.txt", "all.txt.gz"):
        candidate = Path(context.get("recon_dir") or "") / "urls" / "raw" / suffix
        if candidate.is_file():
            raw_reference = f"recon/{storage_key}/urls/raw/{suffix}"
            break
    result = []
    for entry in groups.values():
        representatives = sorted(entry.pop("representatives"), key=lambda value: (-value[0], value[1]))
        entry["representative_url"] = compact_url(representatives[0][1]) if representatives else ""
        entry["candidate_urls"] = [compact_url(url) for _score, url in representatives[:2]]
        entry["sources"] = sorted(entry["sources"])
        entry["value_classes"] = sorted(entry["value_classes"])
        if raw_reference:
            entry["raw_reference"] = raw_reference
        result.append(entry)
    return sorted(result, key=lambda item: (-int(item.get("candidate_count", 0)), item.get("shape_id", "")))[:REVIEW_POOL_LIMIT]


def _iter_rankable_surface_rows(
    context: dict,
    js_intel_urls: dict[str, list[dict]],
    source_intel_urls: dict[str, list[dict]],
) -> Iterator[tuple[str, set[str], int, bool | None]]:
    """统一 legacy list 与 exact index，保持 URL first-seen tie-breaker。"""
    index_status = context.get("surface_index") or {}
    extra_sources: dict[str, set[str]] = {}
    for url in js_intel_urls:
        extra_sources.setdefault(url, set()).add("js_intel")
    for url in source_intel_urls:
        extra_sources.setdefault(url, set()).add("source_intel")

    if index_status.get("status") == "valid":
        # 先只收集 probe-derived inert identity。若直接边读边 yield，文件后段
        # 的 probe 可能 sanitize 成前段已经输出过的正常 URL，导致 P1/P2 重复
        # 和 total_candidates 虚增。两次流式遍历仍为 O(N)，且只为 probe 子集
        # 保留内存。
        index_repo = context.get("repo_root") or Path(BASE_DIR)
        max_sequence = -1
        probe_rows: dict[str, tuple[int, set[str], bool | None]] = {}
        for row in iter_surface_index(index_repo, context["target"]):
            raw_url = str(row.get("url") or "")
            sequence = int(row.get("sequence", 0) or 0)
            max_sequence = max(max_sequence, sequence)
            if not is_attack_probe(raw_url):
                continue
            safe_url = sanitize_attack_probe_url(raw_url)
            if not safe_url or safe_url == raw_url:
                continue
            sources = {str(value) for value in (row.get("sources") or []) if str(value)}
            target_owned = row.get("target_owned") if isinstance(row.get("target_owned"), bool) else None
            previous = probe_rows.get(safe_url)
            if previous is None:
                probe_rows[safe_url] = (sequence, sources, target_owned)
            else:
                previous[1].update(sources)
                previous_target_owned = previous[2]
                if previous_target_owned is None:
                    previous_target_owned = target_owned
                probe_rows[safe_url] = (min(sequence, previous[0]), previous[1], previous_target_owned)

        for row in iter_surface_index(index_repo, context["target"]):
            raw_url = str(row.get("url") or "")
            if is_attack_probe(raw_url):
                continue
            sequence = int(row.get("sequence", 0) or 0)
            sources = {str(value) for value in (row.get("sources") or []) if str(value)}
            probe_match = probe_rows.pop(raw_url, None)
            if probe_match is not None:
                sequence = min(sequence, probe_match[0])
                sources.update(probe_match[1])
            if raw_url in extra_sources:
                sources.update(extra_sources.pop(raw_url))
            target_owned = row.get("target_owned") if isinstance(row.get("target_owned"), bool) else None
            if probe_match is not None and target_owned is None:
                target_owned = probe_match[2]
            yield raw_url, sources, sequence, target_owned

        # Probe-shaped rows 数量通常很小；只对该子集做 safe URL 合并，避免
        # 为全部 30 万正常 URL 维护 Python seen set。
        for safe_url, (sequence, sources, target_owned) in sorted(probe_rows.items(), key=lambda item: item[1][0]):
            if safe_url in extra_sources:
                sources.update(extra_sources.pop(safe_url))
            yield safe_url, sources, sequence, target_owned
        for offset, (url, sources) in enumerate(extra_sources.items(), 1):
            yield url, set(sources), max_sequence + offset, None
        return

    api_urls = list(context.get("api_urls") or [])
    param_urls = list(context.get("param_urls") or [])
    browser_xhr_urls = list(context.get("browser_xhr_urls") or [])
    browser_api_urls = list(context.get("browser_api_urls") or [])
    scanner_urls = [
        str(item.get("url") or "")
        for item in context.get("scanner_findings", [])
        if str(item.get("url") or "")
    ]
    default_host = next(
        (
            str(item.get("url") or "")
            for item in (context.get("hosts") or {}).values()
            if str(item.get("url") or "")
        ),
        "",
    )
    js_urls = []
    for endpoint in context.get("js_endpoints") or []:
        js_urls.append(resolve_target_url(str(endpoint), default_host))

    sources_by_url: dict[str, set[str]] = {}
    ordered: list[str] = []
    for source, values in (
        ("api", api_urls),
        ("param", param_urls),
        ("browser_xhr", browser_xhr_urls),
        ("browser_api", browser_api_urls),
        ("scanner", scanner_urls),
        ("js", js_urls),
        ("js_intel", list(js_intel_urls)),
        ("source_intel", list(source_intel_urls)),
    ):
        for url in values:
            if not url:
                continue
            if url not in sources_by_url:
                ordered.append(url)
                sources_by_url[url] = set()
            sources_by_url[url].add(source)
    for sequence, url in enumerate(ordered):
        yield url, sources_by_url[url], sequence, None


def rank_surface(context: dict) -> dict:
    """Build an AI-first surface review pack with compatibility P1/P2 hints."""
    if not context.get("available"):
        return {
            "available": False,
            "target": context.get("target", ""),
            "runtime_state": context.get("runtime_state", {}),
            "recon_artifacts": context.get("recon_artifacts", {}),
        }

    profile = context.get("profile") or {}
    owner_projection = context.get("owner_projection") or {}
    target_goal_memory = context.get("target_goal_memory") or {}
    target_memory_summary = _target_memory_summary(target_goal_memory)
    tested_endpoints = set(
        owner_projection.get("tested_endpoints", [])
        if owner_projection.get("tested_authoritative")
        else profile.get("tested_endpoints", [])
    )
    untested_endpoints = set(
        owner_projection.get("untested_endpoints", [])
        if owner_projection.get("untested_authoritative")
        else profile.get("untested_endpoints", [])
    )
    # Surface candidates are path-shaped; retain exact query variants for
    # compatibility while also matching their canonical path.
    tested_endpoints |= {item.split("?", 1)[0] for item in tested_endpoints if "?" in item}
    untested_endpoints |= {item.split("?", 1)[0] for item in untested_endpoints if "?" in item}
    profile_tech = {tech.lower() for tech in profile.get("tech_stack", [])}

    pattern_matches = [
        json.loads(item) if isinstance(item, str) else item
        for item in context.get("pattern_matches", [])
    ]
    pattern_techniques = []
    for item in pattern_matches:
        technique = item.get("technique", "")
        vuln_class = item.get("vuln_class", "")
        payout = item.get("payout", 0)
        suffix = f" (${payout:.0f})" if payout else ""
        pattern_techniques.append(f"{item.get('target', '')}: {technique} [{vuln_class}]{suffix}")

    browser_urls = set(context.get("browser_xhr_urls", []) + context.get("browser_api_urls", []))
    browser_request_shapes = context.get("browser_request_shapes") or {}
    api_urls = set(context.get("api_urls") or [])
    new_observations = {
        str(item.get("value") or "").strip(): item
        for item in (context.get("observation_inventory") or {}).get("new_sample") or []
        if isinstance(item, dict)
        and str(item.get("kind") or "") == "url"
        and url_belongs_to_target(str(item.get("value") or "").strip(), context["target"])
    }
    js_intel = context.get("js_intel") or {}
    scanner_findings_by_url = {}
    for finding in context.get("scanner_findings", []):
        url = finding.get("url")
        if not url:
            continue
        scanner_findings_by_url.setdefault(url, []).append(finding)
    closure_resolver = ClosureResolver(
        context.get("ledger_summary") or {},
        context.get("coverage_matrix") or {},
    )
    action_queue_final_endpoints = _action_queue_final_endpoints(
        context.get("action_queue_entries") or []
    )

    default_host = ""
    if context["hosts"]:
        default_host = next(iter(context["hosts"].values())).get("url", "")

    js_intel_urls = build_js_intel_urls(js_intel, default_host)
    source_intel_urls = build_source_intel_urls(
        context.get("source_intel") or {},
        default_host,
        list(js_intel_urls.keys()),
    )
    business_logic_hypotheses = [
        item
        for item in (context.get("source_intel") or {}).get("hypotheses", [])
        if isinstance(item, dict) and item.get("type") == "business-logic"
    ]
    ffuf_summary = context.get("ffuf_summary") or {}
    ffuf_urls = {
        str(item.get("url") or "")
        for item in (ffuf_summary.get("review_sample") or [])[:4]
        if isinstance(item, dict) and str(item.get("url") or "")
    }
    frontiers = _SurfaceCandidateFrontiers(ffuf_urls)
    external_context_count = 0
    external_context_sample: list[tuple[int, str]] = []
    convergence_browser_urls: set[str] = set()
    convergence_source_intel_urls = {
        url: list(items)
        for url, items in source_intel_urls.items()
    }

    for raw_url, source_tags, sequence, indexed_target_owned in _iter_rankable_surface_rows(
        context,
        js_intel_urls,
        source_intel_urls,
    ):
        target_owned = indexed_target_owned
        if target_owned is False or (target_owned is None and not url_belongs_to_target(raw_url, context["target"])):
            external_context_count += 1
            external_context_sample.append((sequence, raw_url))
            external_context_sample.sort(key=lambda item: item[0])
            del external_context_sample[5:]
            continue
        browser_observed = bool(
            raw_url in browser_urls
            or source_tags.intersection({"browser_xhr", "browser_api"})
        )
        api_observed = bool(raw_url in api_urls or "api" in source_tags)
        parsed = urlparse(raw_url)
        host = parsed.netloc
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        query_keys = [key.lower() for key in re.findall(r"[?&]([^=&]+)=", raw_url)]
        score = 0
        score_breakdown = []
        reasons = []
        reason_label, suggested = _candidate_reason(path, query_keys)
        reasons.append(reason_label)
        high_value_signal = classify_high_value_signal(
            path=path,
            query_keys=query_keys,
            # Hostname 只是归属信息，不能因为其中偶然含 rce/ci/cd 等短串
            # 就成为漏洞价值证据；path/query 已通过结构化参数传入。
            evidence=path,
        )
        if high_value_signal.score:
            score += _add_score_breakdown(
                score_breakdown,
                "attack_value",
                summarize_high_value_signal(high_value_signal),
                high_value_signal.score,
                ", ".join(high_value_signal.reasons[:3]),
            )
            reasons.append("high-value signal: " + "+".join(high_value_signal.classes[:3]))

        if browser_observed:
            score += _add_score_breakdown(
                score_breakdown,
                "browser",
                "Browser-observed XHR/API",
                5,
                path,
            )
            reasons.append("browser-observed surface")
            suggested = "prioritize authenticated/browser-observed authz and workflow checks"
            if any(token in path.lower() for token in BROWSER_VALUE_KEYWORDS):
                score += _add_score_breakdown(
                    score_breakdown,
                    "browser",
                    "High-value browser workflow",
                    4,
                    path,
                )
        if "graphql" in path.lower() or _is_websocket_endpoint(path):
            score += _add_score_breakdown(
                score_breakdown,
                "attack_value",
                "GraphQL/WebSocket surface",
                8,
                path,
            )
        if _has_contextual_numeric_id(path) or any(
            key in {"id", "user_id", "account_id", "order_id"} or key.endswith("_id")
            for key in query_keys
        ):
            score += _add_score_breakdown(
                score_breakdown,
                "attack_value",
                "ID-bearing or sequential object reference",
                5,
                ", ".join(query_keys) or path,
            )
        matching_js_intel_endpoints = js_intel_urls.get(raw_url, [])
        if matching_js_intel_endpoints:
            methods = _dedupe_keep_order([
                str(item.get("method", "")).upper()
                for item in matching_js_intel_endpoints
                if item.get("method")
            ])
            evidence = ", ".join(methods[:3]) or path
            score += _add_score_breakdown(
                score_breakdown,
                "js_intel",
                "JS-reader endpoint hypothesis",
                5,
                evidence,
            )
            reasons.append("js-reader endpoint hypothesis")
            suggested = "probe JS-reader endpoint hypothesis with authz and workflow checks"
            if any(token in path.lower() for token in BROWSER_VALUE_KEYWORDS):
                score += _add_score_breakdown(
                    score_breakdown,
                    "js_intel",
                    "JS-reader high-value workflow",
                    3,
                    path,
                )
        matching_source_intel_hypotheses = list(source_intel_urls.get(raw_url, []))
        if "graphql" in raw_url.lower() and business_logic_hypotheses:
            for hypothesis in business_logic_hypotheses:
                if hypothesis not in matching_source_intel_hypotheses:
                    matching_source_intel_hypotheses.append(hypothesis)
        if matching_source_intel_hypotheses:
            convergence_source_intel_urls[raw_url] = list(
                matching_source_intel_hypotheses
            )
            source_types = _dedupe_keep_order([
                str(item.get("type", "")).lower()
                for item in matching_source_intel_hypotheses
                if item.get("type")
            ])
            source_bonus = sum(
                _source_intel_score_bonus(item)
                for item in matching_source_intel_hypotheses[:5]
            )
            evidence = ", ".join(source_types[:3]) or path
            score += _add_score_breakdown(
                score_breakdown,
                "intel",
                "Source-intel hypothesis: " + ", ".join(source_types[:3] or ["candidate"]),
                source_bonus,
                evidence,
            )
            reasons.append("source-intel hypothesis: " + ", ".join(source_types[:3]) + f" (+{source_bonus})")
            suggested = _source_intel_suggestion(matching_source_intel_hypotheses, suggested)

        convergence_sources = []
        if browser_observed:
            convergence_sources.append("browser")
        if matching_js_intel_endpoints:
            convergence_sources.append("js")
        if matching_source_intel_hypotheses:
            convergence_sources.append("source")
        if len(convergence_sources) >= 2:
            convergence_bonus = 10 if len(convergence_sources) >= 3 else 6
            score += _add_score_breakdown(
                score_breakdown,
                "evidence_convergence",
                "Cross-evidence endpoint convergence",
                convergence_bonus,
                "+".join(convergence_sources),
            )
            reasons.append("cross-evidence convergence: " + "+".join(convergence_sources))
            suggested = (
                "replay browser-observed flow with JS/source-informed parameters, "
                "then compare authz, object, role, and workflow behavior"
            )
            if browser_observed:
                convergence_browser_urls.add(raw_url)
        if api_observed or "/api/" in path.lower():
            score += _add_score_breakdown(
                score_breakdown,
                "recon",
                "API endpoint",
                4,
                "api_endpoints.txt" if api_observed else path,
            )
        if query_keys:
            score += _add_score_breakdown(
                score_breakdown,
                "attack_value",
                "Parameterized endpoint",
                2,
                ", ".join(query_keys),
            )
        if host and ":" in host:
            port = host.rsplit(":", 1)[-1]
            if port not in {"80", "443"}:
                score += _add_score_breakdown(
                    score_breakdown,
                    "recon",
                    "Non-standard port",
                    2,
                    port,
                )
                reasons.append("non-standard port")

        host_tech = set(context["hosts"].get(host, {}).get("tech_stack", []))
        if profile_tech and host_tech & profile_tech:
            score += _add_score_breakdown(
                score_breakdown,
                "memory",
                "Tech stack overlap",
                2,
                ", ".join(sorted(host_tech & profile_tech)),
            )
            reasons.append("tech stack overlap")

        if path in untested_endpoints:
            score += _add_score_breakdown(
                score_breakdown,
                "memory",
                "Untested in hunt memory",
                3,
                path,
            )
            reasons.append("untested in memory")
        if path in tested_endpoints:
            score += _add_score_breakdown(
                score_breakdown,
                "memory",
                "Tested before",
                -3,
                path,
            )
            reasons.append("tested before")

        active_memory_hits = _matching_target_memory_entries(
            target_goal_memory, "active_leads", raw_url, path
        )
        next_memory_hits = _matching_target_memory_entries(
            target_goal_memory, "next_actions", raw_url, path
        )
        dead_end_hits = _matching_target_memory_entries(
            target_goal_memory, "dead_ends", raw_url, path
        )
        if active_memory_hits:
            first = _target_memory_text(active_memory_hits[-1])
            score += _add_score_breakdown(
                score_breakdown,
                "target_memory",
                "Active target-memory lead",
                4,
                first[:120],
            )
            reasons.append("target-memory active lead")
            suggested = f"continue remembered lead: {first[:140]}"
        if next_memory_hits:
            first = _target_memory_text(next_memory_hits[-1])
            score += _add_score_breakdown(
                score_breakdown,
                "target_memory",
                "Remembered next action",
                2,
                first[:120],
            )
            reasons.append("target-memory next action")
            suggested = first[:180]
        if dead_end_hits:
            first = _target_memory_text(dead_end_hits[-1])
            score += _add_score_breakdown(
                score_breakdown,
                "target_memory",
                "Remembered dead end",
                -4,
                first[:120],
            )
            reasons.append("target-memory dead end")
            suggested = f"avoid repeating remembered dead end unless new evidence changed: {first[:120]}"

        for item in pattern_matches:
            if item.get("technique") and profile_tech:
                score += _add_score_breakdown(
                    score_breakdown,
                    "memory",
                    "Historical pattern match",
                    1,
                    item.get("technique", ""),
                )
                break

        scanner_findings = scanner_findings_by_url.get(raw_url, [])
        top_scanner_finding = None
        if scanner_findings:
            top_scanner_finding = max(scanner_findings, key=_finding_score_bonus)
            scanner_bonus = sum(_finding_score_bonus(item) for item in scanner_findings)
            scanner_types = _dedupe_keep_order([
                item.get("type") or item.get("category") or "scanner"
                for item in scanner_findings
            ])
            scanner_statuses = _dedupe_keep_order([
                (item.get("report_status") or item.get("validation_status") or "untracked")
                for item in scanner_findings
            ])
            scanner_ids = _dedupe_keep_order([
                item.get("id", "")
                for item in scanner_findings
                if item.get("id")
            ])
            score += _add_score_breakdown(
                score_breakdown,
                "scanner",
                "Scanner finding: " + ", ".join(scanner_types[:3]),
                scanner_bonus,
                ", ".join(scanner_ids[:3]),
            )
            reasons.append(
                "scanner finding: "
                + ", ".join(scanner_types[:3])
                + f" status={','.join(scanner_statuses[:3])}"
                + f" (+{scanner_bonus})"
            )
            suggested = _scanner_suggestion(top_scanner_finding, suggested)

        observed_request_shapes = list(
            browser_request_shapes.get(public_url_shape(raw_url), [])
            if isinstance(browser_request_shapes, dict)
            else []
        )
        for endpoint in matching_js_intel_endpoints:
            method = str(endpoint.get("method") or "").upper()
            if method:
                observed_request_shapes.append({
                    "method": method,
                    "resource_type": "js",
                    "body": endpoint.get("body_shape") if isinstance(endpoint.get("body_shape"), dict) else {},
                })
        for hypothesis in matching_source_intel_hypotheses:
            method = str(hypothesis.get("method") or "").upper()
            if method:
                observed_request_shapes.append({
                    "method": method,
                    "resource_type": "source",
                    "body": hypothesis.get("body_shape") if isinstance(hypothesis.get("body_shape"), dict) else {},
                })
        deduped_request_shapes = []
        seen_request_shapes = set()
        for request_shape in observed_request_shapes:
            if not isinstance(request_shape, dict):
                continue
            key = json.dumps(request_shape, ensure_ascii=False, sort_keys=True)
            if key in seen_request_shapes:
                continue
            seen_request_shapes.add(key)
            deduped_request_shapes.append(request_shape)

        entry = {
            "url": raw_url,
            "host": host,
            "path": path,
            "source_names": sorted(source_tags),
            "raw_evidence": "raw" in source_tags,
            "score": score,
            "score_breakdown": score_breakdown,
            "reasons": reasons,
            "suggested": suggested,
            "tech_stack": context["hosts"].get(host, {}).get("tech_stack", []),
            "tested": path in tested_endpoints,
        }
        if deduped_request_shapes:
            entry["request_shapes"] = deduped_request_shapes[:8]
            entry["semantic_shape"] = _candidate_semantic_shape(entry)
        else:
            entry["semantic_shape"] = _candidate_semantic_shape(entry)
        evidence_refs: list[str] = []
        if browser_observed:
            evidence_refs.extend([
                f"recon/{target_storage_key(context['target'])}/browser/xhr_endpoints.txt",
                f"recon/{target_storage_key(context['target'])}/browser/api_endpoints.txt",
            ])
            page_js_map = Path(context.get("recon_dir") or "") / "browser" / "page_js_map.json"
            if page_js_map.is_file():
                evidence_refs.append(
                    f"recon/{target_storage_key(context['target'])}/browser/page_js_map.json"
                )
        if matching_js_intel_endpoints:
            evidence_refs.extend([
                f"findings/{target_storage_key(context['target'])}/js_intel/hypotheses.json",
                f"findings/{target_storage_key(context['target'])}/js_intel/materials.json",
            ])
        if evidence_refs:
            entry["evidence_refs"] = _dedupe_keep_order(evidence_refs)
        new_observation = new_observations.get(raw_url)
        if new_observation is not None:
            entry["new_observation"] = True
            entry["new_observation_id"] = str(new_observation.get("id") or "")
        if active_memory_hits or next_memory_hits:
            entry["target_memory_hits"] = [
                {"type": "active_lead", "text": _target_memory_text(item)}
                for item in active_memory_hits[-3:]
            ] + [
                {"type": "next_action", "text": _target_memory_text(item)}
                for item in next_memory_hits[-3:]
            ]
        if dead_end_hits:
            entry["target_memory_dead_ends"] = [
                {"text": _target_memory_text(item)}
                for item in dead_end_hits[-3:]
            ]
        if browser_observed:
            entry["browser_observed"] = True
        if matching_js_intel_endpoints:
            entry["js_intel_observed"] = True
            entry["js_intel_endpoints"] = [
                {
                    "method": item.get("method", ""),
                    "source_file": item.get("source_file", ""),
                    "auth_required": item.get("auth_required", ""),
                }
                for item in matching_js_intel_endpoints[:5]
            ]
        if matching_source_intel_hypotheses:
            entry["source_intel_observed"] = True
            entry["source_intel_hypotheses"] = [
                {
                    "type": item.get("type", ""),
                    "candidate": item.get("candidate", ""),
                    "reason": item.get("reason", ""),
                    "source": item.get("source", ""),
                }
                for item in matching_source_intel_hypotheses[:5]
            ]
        if len(convergence_sources) >= 2:
            entry["evidence_convergence"] = convergence_sources
        if scanner_findings:
            entry["scanner_findings"] = [
                {
                    "id": item.get("id", ""),
                    "type": item.get("type", ""),
                    "severity": item.get("severity", ""),
                    "confidence": item.get("confidence", ""),
                    "validation_status": item.get("validation_status", ""),
                    "report_status": item.get("report_status", ""),
                    "source_file": item.get("source_file", ""),
                }
                for item in scanner_findings[:5]
            ]

        matching_intel = [
            signal for signal in context.get("intel_signals", [])
            if _intel_signal_matches(signal, raw_url, path, query_keys, entry["tech_stack"])
        ]
        if matching_intel:
            intel_bonus = sum(_intel_signal_bonus(signal) + _intel_candidate_bonus(signal, query_keys) for signal in matching_intel[:5])
            intel_classes = _dedupe_keep_order([signal.get("class", "intel") for signal in matching_intel])
            intel_evidence = _dedupe_keep_order([
                str(signal.get("id") or signal.get("summary") or signal.get("source") or "")
                for signal in matching_intel[:5]
            ])
            score += _add_score_breakdown(
                score_breakdown,
                "intel",
                "Intel signal: " + ", ".join(intel_classes[:3]),
                intel_bonus,
                ", ".join(item for item in intel_evidence[:3] if item),
            )
            entry["score"] = score
            reasons.append("intel signal: " + ", ".join(intel_classes[:3]) + f" (+{intel_bonus})")
            entry["reasons"] = reasons
            entry["score_breakdown"] = score_breakdown
            entry["intel_signals"] = [
                {
                    "class": signal.get("class", ""),
                    "severity": signal.get("severity", ""),
                    "source": signal.get("source", ""),
                    "id": signal.get("id", ""),
                    "summary": signal.get("summary", ""),
                    "applicability": signal.get("applicability", "unknown"),
                    "score_hint": signal.get("score_hint", 0),
                    "kev": bool(signal.get("kev")),
                    "epss": signal.get("epss"),
                }
                for signal in matching_intel[:5]
            ]

        endpoint_path = canonical_endpoint_path(raw_url) or "/"
        ledger_vuln_hint = _surface_vuln_hint(path, suggested, query_keys)
        if ledger_vuln_hint:
            # Keep the best-effort lane hint with the bounded candidate so
            # closure can distinguish Authz/IDOR/SQLi outcomes on one path.
            entry["vuln_class"] = ledger_vuln_hint
        ledger_result = closure_resolver.closed_result(endpoint_path, ledger_vuln_hint)
        if ledger_result:
            # 终态只说明这个精确 lane 已处理，不代表 endpoint 无其他攻击面。
            # 保留轻量历史提示，不把 raw surface 从 AI Review Pool 移除。
            penalty = -3
            score += _add_score_breakdown(
                score_breakdown,
                "memory",
                f"Evidence ledger final: {ledger_vuln_hint} {ledger_result}",
                penalty,
                endpoint_path,
            )
            entry["score"] = score
            entry["score_breakdown"] = score_breakdown
            reasons.append(f"evidence-ledger {ledger_vuln_hint} {ledger_result}")
            entry["reasons"] = reasons
            entry["ledger_history"] = {
                "endpoint": endpoint_path,
                "vuln_class": ledger_vuln_hint,
                "result": ledger_result,
            }
            suggested = (
                f"ledger shows {ledger_vuln_hint}={ledger_result}; avoid repeating that exact lane, "
                "but keep the endpoint open for a different class or fresh browser/source evidence"
            )
            entry["suggested"] = suggested
        queue_status = action_queue_final_endpoints.get(endpoint_path)
        if queue_status:
            reasons.append(f"action-queue history {queue_status}")
            entry["reasons"] = reasons
            entry["action_queue_history"] = {
                "endpoint": endpoint_path,
                "status": queue_status,
            }
            if not _has_actionable_review_evidence(entry):
                entry["suggested"] = (
                    f"review prior action-queue outcome ({queue_status}) before repeating the same lane; "
                    "fresh browser/source/role/object evidence may justify a different test"
                )
        frontiers.add(entry, sequence)

    bounded_candidates = frontiers.review_candidates()
    ffuf_review_candidates = _build_ffuf_review_candidates(
        ffuf_summary,
        context["target"],
        bounded_candidates,
    )

    lead_items = _sort_workflow_leads(
        _build_exposure_lead_hints(context.get("recon_artifacts") or {}, context["target"])
        + _build_target_memory_lead_hints(target_goal_memory)
        + _build_evidence_convergence_leads(
            browser_urls=convergence_browser_urls,
            js_intel_urls=js_intel_urls,
            source_intel_urls=convergence_source_intel_urls,
        )
        + _build_cf_bypass_refresh_leads(context)
        + _build_external_url_context_leads(
            context,
            [url for _sequence, url in external_context_sample],
            total_count=external_context_count,
        )
        + build_js_lead_hints(js_intel)
        + build_source_lead_hints(
            context.get("source_intel") or {},
            target=context["target"],
            default_host=default_host,
        )
        + list(context.get("manual_review_leads") or [])
    )
    workflow_leads = _dedupe_keep_order([
        json.dumps(item, sort_keys=True)
        for item in lead_items
    ])

    kill = []
    for host, item in context["hosts"].items():
        lower_host = host.lower()
        title = item.get("title", "").lower()
        if host in context["status403_hosts"] and context.get("cf_bypass_active"):
            continue
        if any(token in lower_host for token in ("docs.", "status.", "blog.", "static.", "cdn.")):
            kill.append({"host": host, "reason": "possible docs/static/support host"})
            continue
        if host in context["status403_hosts"]:
            kill.append({"host": host, "reason": "403-only host from recon; revisit if auth/CF/session context changes"})
            continue
        if any(token in title for token in ("documentation", "status page", "help center")):
            kill.append({"host": host, "reason": f"title suggests lower-priority surface: {item.get('title', '')}"})

    p1 = [item for _sequence, item in frontiers.p1.values()]
    p2 = [item for _sequence, item in frontiers.p2.values()]
    _enrich_bounded_candidates([*bounded_candidates, *p1, *p2])
    review_pool = _build_review_pool(bounded_candidates, ffuf_review_candidates)
    semantic_surface = _build_semantic_surface(context, [*bounded_candidates, *p1, *p2])
    observation_inventory = context.get("observation_inventory") or {}
    index_status = context.get("surface_index") or {}
    index_summary = index_status.get("summary") or {}
    index_manifest = index_status.get("manifest") if isinstance(index_status.get("manifest"), dict) else {}
    index_binding = index_manifest.get("index_binding") if isinstance(index_manifest.get("index_binding"), dict) else {}
    continuation = {"available": False, "next_cursor": "", "command": ""}
    if str(index_status.get("status") or "") == "valid":
        try:
            first_page = page_surface_index(
                context["repo_root"],
                context["target"],
                limit=50,
                target_owned=True,
            )
            next_cursor = str(first_page.get("next_cursor") or "")
            continuation = {
                "available": bool(next_cursor),
                "next_cursor": next_cursor,
                "command": (
                    "python3 tools/surface_index.py page "
                    f"--target {shlex.quote(context['target'])} --limit 50 "
                    f"--target-owned --cursor {shlex.quote(next_cursor)}"
                ),
            }
        except (OSError, SurfaceIndexError, ValueError):
            # Ranking remains usable; stale index status is already a refresh gate.
            pass
    browser_source_counts = index_summary.get("source_counts") or {}
    filter_summary = _read_json_object(Path(context.get("recon_dir") or "") / "urls" / "filter_summary.json")
    raw_url_count = int((index_summary.get("source_counts") or {}).get("raw", 0) or 0)
    active_url_count = int(filter_summary.get("kept", 0) or (index_summary.get("source_counts") or {}).get("active", 0) or 0)
    reactivated_count = sum(
        1
        for item in bounded_candidates
        if item.get("raw_evidence") and _has_actionable_review_evidence(item)
    )

    return {
        "available": True,
        "target": context["target"],
        "runtime_state": context.get("runtime_state", {}),
        "recon_artifacts": context.get("recon_artifacts", {}),
        "p1": p1,
        "p2": p2,
        "review_pool": review_pool,
        "semantic_surface": semantic_surface,
        "surface_index": {
            "status": str(index_status.get("status") or "missing"),
            "row_count": int(index_status.get("row_count", 0) or 0),
            "index_revision": str(index_binding.get("sha256") or ""),
            "continuation": {
                **continuation,
            },
        },
        "observation_inventory": observation_inventory,
        "kill": _dedupe_keep_order([json.dumps(item, sort_keys=True) for item in kill]),
        "memory": {
            "tested_count": len(tested_endpoints),
            "untested_count": len(untested_endpoints),
            "pattern_suggestions": pattern_techniques[:3],
        },
        "target_memory": target_memory_summary,
        "scanner": {
            "finding_count": len(context.get("scanner_findings", [])),
            "manual_review": list((context.get("scanner_manual_review") or {}).get("items") or []),
            "manual_review_total": len((context.get("scanner_manual_review") or {}).get("items") or []),
            "manual_review_summary_path": str(
                (context.get("scanner_manual_review") or {}).get("summary_path") or ""
            ),
        },
        "intel": {
            **(context.get("intel") or {}),
            "signal_count": len(context.get("intel_signals", [])),
        },
        "ffuf": ffuf_summary,
        "js_intel": js_intel_counts(js_intel),
        "source_intel": source_intel_counts(context.get("source_intel") or {}),
        "workflow_leads": workflow_leads,
        "browser": {
            "xhr_count": int(
                browser_source_counts.get("browser_xhr", len(context.get("browser_xhr_urls", []))) or 0
            ),
            "api_count": int(
                browser_source_counts.get("browser_api", len(context.get("browser_api_urls", []))) or 0
            ),
        },
        "evidence_refs": {
            "browser": [
                path
                for path in (
                    f"recon/{target_storage_key(context['target'])}/browser/xhr_endpoints.txt",
                    f"recon/{target_storage_key(context['target'])}/browser/api_endpoints.txt",
                    f"recon/{target_storage_key(context['target'])}/browser/page_js_map.json",
                )
                if (context.get("repo_root") and (Path(context["repo_root"]) / path).is_file())
            ],
            "js": [
                path
                for path in (
                    f"findings/{target_storage_key(context['target'])}/js_intel/hypotheses.json",
                    f"findings/{target_storage_key(context['target'])}/js_intel/materials.json",
                )
                if (context.get("repo_root") and (Path(context["repo_root"]) / path).is_file())
            ],
        },
        "stats": {
            "total_candidates": frontiers.total,
            "p1": len(p1),
            "p2": len(p2),
            "review_pool": len(review_pool),
            "semantic_shape_count": len(semantic_surface),
            "semantic_variant_count": sum(
                int(item.get("active_variant_count", 0) or 0)
                for item in semantic_surface
            ),
            "raw_urls": raw_url_count,
            "exact_unique": int(index_summary.get("unique_urls", 0) or 0),
            "semantic_shapes": int(index_summary.get("shape_count", 0) or 0),
            "active_candidates": active_url_count,
            "dormant_noise": max(0, raw_url_count - active_url_count),
            "reactivated_by_evidence": reactivated_count,
            "kill": len(kill),
            "observation_total": int(observation_inventory.get("total", 0) or 0),
            "observation_untouched": int(observation_inventory.get("untouched", 0) or 0),
            "observation_stale": int(observation_inventory.get("stale", 0) or 0),
        },
    }


def _format_ffuf_evidence_lines(ffuf: dict, target: str) -> list[str]:
    """渲染有界 FFUF 事实，不判断 route 价值。"""
    if not ffuf:
        return []
    if not ffuf.get("available"):
        if not ffuf.get("needs_summary"):
            return []
        artifact = str(ffuf.get("artifact") or "dirs/ffuf_*.json*")
        if not artifact.startswith("recon/"):
            artifact = f"recon/{target_storage_key(target)}/{artifact}"
        legacy_count = int(ffuf.get("legacy_raw_files", 0) or 0)
        return [
            "FFUF Evidence (unranked):",
            f"- Cached artifact requires a compact summary: {artifact} (legacy files: {legacy_count})",
        ]

    lines = [
        "FFUF Evidence (unranked; AI decides route value):",
        (
            f"- Observations: {int(ffuf.get('observations', 0) or 0)}, "
            f"sample: {int(ffuf.get('sample_count', 0) or 0)}, "
            f"overflow: {int(ffuf.get('overflow', 0) or 0)}, "
            f"control failures: {int(ffuf.get('control_failed', 0) or 0)}, "
            f"status: {json.dumps(ffuf.get('status_counts') or {}, sort_keys=True)}"
        ),
    ]
    controls = ffuf.get("controls") or []
    if controls:
        rendered = [
            f"{item.get('status', 0)}/{item.get('length', 0)}/{item.get('content_type', '') or '-'}"
            for item in controls[:6]
            if isinstance(item, dict)
        ]
        suffix = f" (+{len(controls) - len(rendered)} more)" if len(controls) > len(rendered) else ""
        lines.append("- Random-miss controls: " + ", ".join(rendered) + suffix)
    heavy = ffuf.get("heavy_signatures") or []
    if heavy:
        rendered = [
            (
                f"{item.get('signature_id', '-')}:status={item.get('status', 0)}"
                f"/len={item.get('length', 0)}/count={item.get('count', 0)}"
                f"/ratio={item.get('ratio', 0)}"
                f"/control_match={str(bool(item.get('matches_random_miss_control'))).lower()}"
            )
            for item in heavy[:4]
            if isinstance(item, dict)
        ]
        lines.append("- Heavy response signatures: " + ", ".join(rendered))
    artifacts = ffuf.get("artifacts") or []
    artifact_paths = [
        (
            str(item.get("path") or "")
            if str(item.get("path") or "").startswith("recon/")
            else f"recon/{target_storage_key(target)}/{item.get('path', '')}"
        )
        for item in artifacts[:2]
        if isinstance(item, dict) and item.get("path")
    ]
    if artifact_paths:
        lines.append("- Full evidence: " + ", ".join(artifact_paths))
    return lines


def format_surface_output(ranked: dict, target: str) -> str:
    """Format the surface review pack for terminal display."""
    runtime_state = ranked.get("runtime_state") or {}
    recon_artifacts = ranked.get("recon_artifacts") or {}
    # v2 schema uses last_executed_workflow. v1 callers wrote current_stage;
    # we fall back to it so old session.json files still render something.
    runtime_workflow = str(
        runtime_state.get("last_executed_workflow")
        or runtime_state.get("current_stage")
        or ""
    ).strip()
    runtime_mode = str(runtime_state.get("mode", "") or "").strip()
    if not ranked.get("available"):
        lines = [f"No recon data found for {target}."]
        # Show recon-cache observation first (the evidence) then runtime hint.
        if recon_artifacts.get("available"):
            missing = recon_artifacts.get("missing") or []
            warnings = recon_artifacts.get("warnings") or []
            if missing:
                lines.append(f"Cached recon issue: {', '.join(missing[:2])}")
            elif warnings:
                lines.append(f"Cached recon warning: {warnings[0]}")
        if runtime_workflow:
            lines.append(
                f"Last workflow: {runtime_workflow}"
                + (f" (mode: {runtime_mode})" if runtime_mode else "")
            )
        # Options instead of a single prescriptive next step.
        lines.append("Options:")
        lines.append(f"- run /recon {target} (if target may have undiscovered surface)")
        lines.append("- switch to source-intel if a public repo URL is relevant to the target")
        lines.append(f"- abandon {target} (if confirmed unproductive)")
        return "\n".join(lines)

    kill_items = [
        json.loads(item) if isinstance(item, str) else item
        for item in ranked.get("kill", [])
    ]
    workflow_leads = [
        json.loads(item) if isinstance(item, str) else item
        for item in ranked.get("workflow_leads", [])
    ]
    target_memory = ranked.get("target_memory") or {}

    lines = [
        f"ATTACK SURFACE: {target}",
        "═══════════════════════════════════════",
        "",
    ]
    # Evidence first, last-workflow second — encourages reasoning from data
    # rather than locking the agent into a pipeline stage.
    if recon_artifacts.get("available"):
        counts = recon_artifacts.get("counts") or {}
        lines.append("Recon Cache:")
        lines.append(
            f"- Hosts: {counts.get('hosts', 0)}, "
            f"surface inputs: {counts.get('api_urls', 0) + counts.get('param_urls', 0) + counts.get('js_files', 0) + counts.get('js_endpoints', 0) + counts.get('browser_xhr_urls', 0) + counts.get('browser_api_urls', 0) + counts.get('ffuf_observations', 0)}, "
            f"structured findings: {counts.get('structured_findings', 0)}, "
            f"ports: {counts.get('open_ports', 0)}, "
            f"waf: {counts.get('waf_hits', 0)}, "
            f"origin: {counts.get('origin_candidates', 0)}"
        )
        infra_paths = recon_artifacts.get("infra_paths") or {}
        if infra_paths:
            lines.append("- Infra artifacts: " + ", ".join(infra_paths.values()))
        warnings = recon_artifacts.get("warnings") or []
        missing = recon_artifacts.get("missing") or []
        if missing:
            lines.append(f"- Issue: {', '.join(missing[:2])}")
        elif warnings:
            lines.append(f"- Warning: {warnings[0]}")
    if runtime_workflow:
        lines.append("Last Workflow:")
        lines.append(
            f"- {runtime_workflow}"
            + (f" (mode: {runtime_mode})" if runtime_mode else "")
        )
    if runtime_workflow or recon_artifacts.get("available"):
        lines.append("")
    host_ranking_count = _count_recon_artifact(recon_artifacts, "host_ranking")
    if host_ranking_count:
        lines.append(
            f"- Host ranking: {host_ranking_count} all-host soft priority rows "
            "(advisory; raw recon remains authoritative)"
        )
    observation_inventory = ranked.get("observation_inventory") or {}
    inventory_error = str(observation_inventory.get("error") or "").strip()
    if inventory_error:
        lines.extend([
            "Observation Inventory:",
            f"- Warning: {inventory_error}",
            f"- State: {observation_inventory.get('path', '')}",
            "",
        ])
    elif observation_inventory.get("available"):
        lines.extend([
            "Observation Inventory (neutral; no route ranking):",
            (
                f"- Total: {observation_inventory.get('total', 0)}, "
                f"present: {observation_inventory.get('present', 0)}, "
                f"untouched: {observation_inventory.get('untouched', 0)}, "
                f"stale: {observation_inventory.get('stale', 0)}, "
                f"reviewing: {observation_inventory.get('reviewing', 0)}"
            ),
            f"- State: {observation_inventory.get('path', '')}",
            "",
        ])
    ffuf_lines = _format_ffuf_evidence_lines(ranked.get("ffuf") or {}, target)
    if ffuf_lines:
        lines.extend(ffuf_lines)
        lines.append("")
    review_pool = ranked.get("review_pool") or []
    lines.extend([
        "AI Review Pool (advisory; Claude chooses final priority):",
    ])
    if review_pool:
        for idx, item in enumerate(review_pool[:10], 1):
            reason = ", ".join(item.get("reasons", [])[:2])
            review_reason = str(item.get("review_reason") or "surface evidence").strip()
            lines.append(f"{idx}. {surface_safe_preview(item['url'])} — {review_reason}; {reason}")
            lines.append(f"   Score hint: {_format_score_breakdown(item)}")
            lines.append(f"   Suggested evidence path: {item['suggested']}")
    else:
        lines.append("1. No review candidates from cached recon.")

    lines.extend([
        "",
        "Advisory first-review score hints (legacy P1, not verdicts):",
    ])
    if ranked["p1"]:
        for idx, item in enumerate(ranked["p1"], 1):
            reason = ", ".join(item["reasons"][:2])
            lines.append(f"{idx}. {surface_safe_preview(item['url'])} — {reason}")
            if item["tech_stack"]:
                lines.append(f"   Tech: {', '.join(item['tech_stack'])}")
            if item.get("browser_observed"):
                lines.append("   Source: browser-observed XHR/API")
            if item.get("js_intel_observed"):
                lines.append("   Source: js-reader hypotheses")
            if item.get("source_intel_observed"):
                lines.append("   Source: source-intel hypotheses")
            if item.get("evidence_convergence"):
                lines.append("   Source: cross-evidence convergence (" + "+".join(item["evidence_convergence"]) + ")")
            if item.get("target_memory_hits"):
                lines.append("   Source: target memory")
            if item.get("target_memory_dead_ends"):
                lines.append("   Caution: matches remembered dead end")
            lines.append(f"   Score: {_format_score_breakdown(item)}")
            lines.append(f"   Suggested: {item['suggested']}")
    else:
        lines.append("1. No clear first-review score hints from cached recon.")

    lines.extend(["", "Advisory follow-up score hints (legacy P2, not verdicts):"])
    if ranked["p2"]:
        for idx, item in enumerate(ranked["p2"], 1):
            reason = ", ".join(item["reasons"][:2])
            lines.append(f"{idx}. {surface_safe_preview(item['url'])} — {reason}")
            if item.get("browser_observed"):
                lines.append("   Source: browser-observed XHR/API")
            if item.get("js_intel_observed"):
                lines.append("   Source: js-reader hypotheses")
            if item.get("source_intel_observed"):
                lines.append("   Source: source-intel hypotheses")
            if item.get("evidence_convergence"):
                lines.append("   Source: cross-evidence convergence (" + "+".join(item["evidence_convergence"]) + ")")
            if item.get("target_memory_hits"):
                lines.append("   Source: target memory")
            if item.get("target_memory_dead_ends"):
                lines.append("   Caution: matches remembered dead end")
            lines.append(f"   Score: {_format_score_breakdown(item)}")
            lines.append(f"   Suggested: {item['suggested']}")
    else:
        lines.append("1. No follow-up score hints. Consider re-running recon.")

    lines.extend(["", "Low-priority host hints (not exclusion):"])
    if kill_items:
        for item in kill_items[:5]:
            lines.append(f"- {item['host']} — {item['reason']}")
    else:
        lines.append("- No obvious low-value hosts from cached recon.")

    lines.extend(["", "Memory:"])
    for item in ranked["memory"]["pattern_suggestions"]:
        lines.append(f"- Pattern: {item}")
    lines.append(
        f"- Tested endpoints: {ranked['memory']['tested_count']}, untested remain: {ranked['memory']['untested_count']}"
    )

    lines.extend(["", "Target Memory:"])
    if target_memory:
        if target_memory.get("goal"):
            lines.append(f"- Goal: {target_memory['goal']}")
        if target_memory.get("hypothesis"):
            lines.append(f"- Hypothesis: {target_memory['hypothesis']}")
        for label, field in (
            ("Active leads", "active_leads"),
            ("Next actions", "next_actions"),
            ("Dead ends", "dead_ends"),
        ):
            entries = target_memory.get(field) or []
            lines.append(f"- {label}: {len(entries)}")
            for entry in entries[-2:]:
                text = str(entry.get("text", "") or "").strip()
                if text:
                    lines.append(f"  - {text}")
        handoffs = target_memory.get("session_handoffs") or []
        if handoffs:
            latest = handoffs[-1]
            summary = str(latest.get("summary", "") or "").strip()
            path = str(latest.get("path", "") or "").strip()
            if summary:
                lines.append(f"- Latest handoff: {summary}")
            if path:
                lines.append(f"- Handoff path: {path}")
    else:
        lines.append("- No target memory saved yet.")

    lines.extend(["", "Scanner Findings:"])
    scanner_count = ranked.get("scanner", {}).get("finding_count", 0)
    if scanner_count:
        lines.append(f"- Structured scanner candidates: {scanner_count}")
        shown = 0
        for item in ranked.get("p1", []) + ranked.get("p2", []):
            for finding in item.get("scanner_findings", []):
                lines.append(
                    f"- {finding.get('id', '-')} "
                    f"[{finding.get('severity', '-')}/{finding.get('confidence', '-')}] "
                    f"{finding.get('type', '-')} "
                    f"status={finding.get('validation_status', '-')}/{finding.get('report_status', '-')} "
                    f"→ {surface_safe_preview(item['url'])}"
                )
                shown += 1
                if shown >= 5:
                    break
            if shown >= 5:
                break
    else:
        lines.append("- No structured scanner candidates yet.")
    scanner_manual_review = ranked.get("scanner", {}).get("manual_review") or []
    if scanner_manual_review:
        manual_total = int(
            ranked.get("scanner", {}).get("manual_review_total", len(scanner_manual_review))
            or len(scanner_manual_review)
        )
        lines.append(
            f"- Manual-review artifacts: {manual_total} (neutral evidence index; no route implied)"
        )
        summary_path = str(
            ranked.get("scanner", {}).get("manual_review_summary_path") or ""
        ).strip()
        if summary_path:
            lines.append(f"- Canonical summary: {summary_path}")
        for item in scanner_manual_review[:8]:
            lines.append(
                f"- Review artifact: {item.get('path', '-')} "
                f"({int(item.get('count', 0) or 0)} non-empty line(s))"
            )
            for preview in (item.get("preview") or [])[:3]:
                lines.append(f"  - {preview}")
        if manual_total > 8:
            lines.append(f"- Manual-review preview overflow: {manual_total - 8}")

    lines.extend(["", "Intel Signals:"])
    intel_meta = ranked.get("intel", {})
    intel_status = intel_meta.get("status", "missing")
    intel_coverage = intel_meta.get("coverage_status", "missing")
    lines.append(f"- Artifact status: {intel_status}; coverage: {intel_coverage}")
    if intel_meta.get("error"):
        lines.append(f"- Intel artifact error: {str(intel_meta['error'])[:240]}")
    for source in intel_meta.get("degraded_sources", [])[:5]:
        detail = f" — {str(source.get('error') or '')[:180]}" if source.get("error") else ""
        lines.append(
            f"- Degraded source: {source.get('source', '-')} "
            f"[{source.get('status', 'unknown')}]{detail}"
        )
    review_items = intel_meta.get("review_items", [])
    if review_items:
        lines.append(f"- Advisory review items: {len(review_items)}")
        for advisory in review_items[:5]:
            component = (
                advisory.get("component")
                if isinstance(advisory.get("component"), dict)
                else {}
            )
            component_name = str(
                component.get("display_name") or component.get("name") or "unknown"
            )
            version = str(component.get("version") or "unknown")
            lines.append(
                f"- Advisory review: {advisory.get('id', '-')} "
                f"[{advisory.get('severity', '-')}/{advisory.get('applicability', 'unknown')}] "
                f"score={advisory.get('score_hint', 0)} component={component_name}@{version}"
            )
    intel_count = intel_meta.get("signal_count", 0)
    if intel_count:
        lines.append(f"- Local intel signals: {intel_count}")
        shown = 0
        for item in ranked.get("p1", []) + ranked.get("p2", []):
            for signal in item.get("intel_signals", []):
                label = signal.get("id") or signal.get("summary") or signal.get("source", "intel")
                lines.append(
                    f"- {signal.get('class', '-')} "
                    f"[{signal.get('severity', '-')}] → {surface_safe_preview(item['url'])} :: {str(label)[:90]}"
                )
                shown += 1
                if shown >= 5:
                    break
            if shown >= 5:
                break
    else:
        lines.append("- No local intel signals yet.")

    lines.extend(["", "Source Intel:"])
    source_counts = ranked.get("source_intel", {})
    if source_counts.get("hypothesis_count") or source_counts.get("route_count") or source_counts.get("graphql_count"):
        lines.append(
            f"- Source-intel hypotheses: {source_counts.get('hypothesis_count', 0)}, "
            f"routes: {source_counts.get('route_count', 0)}, "
            f"GraphQL operations: {source_counts.get('graphql_count', 0)}"
        )
    else:
        lines.append("- No source-intel hypotheses yet.")

    lines.extend(["", "JS Reader Intel:"])
    js_counts = ranked.get("js_intel", {})
    if js_counts.get("endpoint_count") or js_counts.get("lead_count") or js_counts.get("graphql_count"):
        lines.append(
            f"- JS-reader hypotheses: {js_counts.get('endpoint_count', 0)} endpoints, "
            f"{js_counts.get('lead_count', 0)} leads, "
            f"{js_counts.get('graphql_count', 0)} GraphQL operations"
        )
    else:
        lines.append("- No js-reader hypotheses yet.")

    lines.extend(["", "Browser Surface:"])
    browser_counts = ranked.get("browser", {})
    if browser_counts.get("xhr_count") or browser_counts.get("api_count"):
        lines.append(
            f"- Browser-observed XHR/API: {browser_counts.get('xhr_count', 0)} xhr, "
            f"{browser_counts.get('api_count', 0)} api"
        )
    else:
        lines.append("- No browser-observed surface yet.")

    lines.extend(["", "Workflow Leads:"])
    if workflow_leads:
        for item in workflow_leads[:5]:
            title = item.get("title", "-")
            category = item.get("category", "other")
            priority = item.get("priority", "medium")
            lines.append(f"- [{priority}] {category}: {title}")
            lines.append(f"  Next: {item.get('next_action', '')}")
            rationale = str(item.get("rationale", "") or "").strip()
            if rationale:
                lines.append(f"  Why: {rationale[:160]}")
    else:
        lines.append("- No actionable JS/source workflow leads yet.")

    lines.extend([
        "",
        "Stats:",
        f"- Total candidates: {ranked['stats']['total_candidates']}",
        f"- Advisory first-review hints: {ranked['stats']['p1']}",
        f"- Advisory follow-up hints: {ranked['stats']['p2']}",
        f"- Low-priority host hints: {ranked['stats']['kill']}",
    ])

    # Options surface multiple candidate next moves rather than a single
    # prescriptive directive. The agent picks based on which option best
    # matches the evidence shape — preserving non-linear hunting flexibility.
    options = _surface_options(ranked, target)
    if options:
        lines.extend(["", "Options:"])
        for opt in options:
            lines.append(f"- {opt}")
    return "\n".join(lines)


def _surface_options(ranked: dict, target: str) -> list[str]:
    """Return ≥2 candidate next moves derived from current evidence."""
    stats = ranked.get("stats") or {}
    recon_artifacts = ranked.get("recon_artifacts") or {}
    recon_counts = recon_artifacts.get("counts") or {}

    options: list[str] = []
    review_count = stats.get("review_pool", 0)
    if review_count > 0:
        options.append(f"review the AI surface pool ({review_count} candidates) and choose the next evidence step")
        options.append("spawn chain-builder after Claude chooses a candidate from the evidence")
    if recon_counts.get("js_endpoints", 0) > 0:
        options.append("spawn js-reader on cached JS bundles for endpoint hypotheses")
    if recon_counts.get("browser_xhr_urls", 0) > 0 or recon_counts.get("browser_api_urls", 0) > 0:
        options.append("inspect browser-observed XHR/API endpoints before broad fuzz")
    if recon_counts.get("structured_findings", 0) > 0:
        options.append("review structured findings via tools/finding_index.py and validate the next pending one")
    if recon_counts.get("open_ports", 0) > 0 or recon_counts.get("waf_hits", 0) > 0 or recon_counts.get("origin_candidates", 0) > 0:
        options.append("review cached infra artifacts (ports/WAF/origin) before choosing the next lane")
    missing = recon_artifacts.get("missing") or []
    if missing and recon_artifacts.get("available"):
        options.append(f"rerun /recon {target} to refresh stale artifacts ({', '.join(missing[:2])})")
    # Always offer at least one orthogonal exit so the agent isn't locked in.
    if len(options) < 2:
        options.append(f"switch to source-intel if {target} has a relevant public repo URL")
    return options


def build_surface_review(
    repo_root: str | Path,
    target: str,
    *,
    memory_dir: str | Path | None = None,
    refresh: bool = False,
    publish_projection: bool = True,
) -> dict:
    """显式构建完整 index/ranking，并原子发布 bounded projection。"""
    repo = Path(repo_root).resolve()
    resolved_memory = str(memory_dir or default_memory_dir(repo))
    index_status = load_surface_index_status(repo, target)
    if refresh or index_status.get("status") != "valid":
        build_surface_index(repo, target)

    # inventory sidecar 的显式同步发生在 context load；之后再冻结 ranking
    # manifest，确保 projection 不绑定到一次构建前的旧摘要。
    context = load_surface_context(repo, target, memory_dir=resolved_memory)
    initial_manifest = build_surface_input_manifest(
        repo,
        target,
        memory_dir=resolved_memory,
    )
    ranked = rank_surface(context)
    final_manifest = build_surface_input_manifest(
        repo,
        target,
        memory_dir=resolved_memory,
    )
    if final_manifest.get("fingerprint") != initial_manifest.get("fingerprint"):
        raise SurfaceIndexError("surface inputs changed during ranking; projection not published")
    if publish_projection and ranked.get("available"):
        projection_path = write_surface_projection(
            repo,
            target,
            ranked,
            manifest=initial_manifest,
            memory_dir=resolved_memory,
        )
        ranked["surface_projection"] = {
            "status": "valid",
            "path": str(projection_path),
            "input_fingerprint": initial_manifest.get("fingerprint", ""),
        }
    return ranked


def main() -> None:
    parser = argparse.ArgumentParser(description="Build an AI-first surface review pack from cached recon")
    parser.add_argument("--target", required=True, help="Target domain")
    parser.add_argument("--memory-dir", default="", help="Optional hunt-memory directory")
    parser.add_argument("--json", action="store_true", help="Output JSON summary")
    parser.add_argument("--refresh", action="store_true", help="Force a complete index/ranking rebuild")
    args = parser.parse_args()

    memory_dir = args.memory_dir or str(default_memory_dir(BASE_DIR))
    try:
        ranked = build_surface_review(
            BASE_DIR,
            args.target,
            memory_dir=memory_dir,
            refresh=args.refresh,
        )
    except (SurfaceIndexError, OSError, ValueError) as exc:
        print(f"surface: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
    if args.json:
        print(json.dumps(ranked, indent=2))
        return
    print(format_surface_output(ranked, args.target))


if __name__ == "__main__":
    main()
