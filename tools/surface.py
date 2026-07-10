#!/usr/bin/env python3
"""
surface.py — build an AI-first review pack from cached recon and hunt memory.
"""

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from memory.pattern_db import PatternDB
from memory.target_profile import default_memory_dir, load_target_profile
try:
    from tools.closure_resolver import ClosureResolver
    from tools.evidence_ledger import load_entries as load_evidence_ledger_entries
    from tools.action_queue import FINAL_STATUSES as ACTION_QUEUE_FINAL_STATUSES
    from tools.action_queue import load_queue as load_action_queue
    from tools.attack_probe_filter import filter_attack_probes, is_attack_probe
    from tools.finding_index import load_finding_index
    from tools.recon_adapter import ReconAdapter
    from tools.runtime_state import inspect_recon_artifacts, load_runtime_state
    from tools.target_paths import canonical_target_value, target_storage_key, url_belongs_to_target
except ImportError:  # pragma: no cover - top-level tools/ import
    from closure_resolver import ClosureResolver  # type: ignore
    from evidence_ledger import load_entries as load_evidence_ledger_entries
    from action_queue import FINAL_STATUSES as ACTION_QUEUE_FINAL_STATUSES  # type: ignore
    from action_queue import load_queue as load_action_queue  # type: ignore
    from attack_probe_filter import filter_attack_probes, is_attack_probe
    from finding_index import load_finding_index
    from recon_adapter import ReconAdapter
    from runtime_state import inspect_recon_artifacts, load_runtime_state
    from target_paths import canonical_target_value, target_storage_key, url_belongs_to_target
try:
    from tools.high_value_signals import classify_high_value_signal, summarize_high_value_signal
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
    from high_value_signals import classify_high_value_signal, summarize_high_value_signal
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


def _count_recon_artifact(recon_artifacts: dict, key: str) -> int:
    """Safely read one integer count from runtime_state recon metadata."""
    counts = recon_artifacts.get("counts") or {}
    try:
        return int(counts.get(key, 0) or 0)
    except (TypeError, ValueError):
        return 0


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
    config = _count_recon_artifact(recon_artifacts, "config_exposures")
    cloud = _count_recon_artifact(recon_artifacts, "cloud_storage_candidates")
    s3 = _count_recon_artifact(recon_artifacts, "s3_bucket_candidates")
    external_hosts = _count_recon_artifact(recon_artifacts, "external_service_hosts")
    emails = _count_recon_artifact(recon_artifacts, "identity_emails")
    leaksearch = _count_recon_artifact(recon_artifacts, "leaksearch_hits")
    cloud_enum = _count_recon_artifact(recon_artifacts, "cloud_enum_hits")

    if verified > 0:
        leads.append({
            "source": "recon_exposure",
            "title": "Verified secret material found in API leak artifacts",
            "category": "verified-secret",
            "priority": "critical",
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

    if api_docs > 0:
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
                    f"review {unsafe_display_path} and only rerun with ALLOW_UNSAFE_HTTP_TESTS=1 "
                    "when the operator explicitly opts in for those broad scanner probes; "
                    "do not treat this as a ban on safe observed-method replay"
                ),
                "rationale": (
                    "Skipped lanes may include PUT/DELETE/PATCH method tampering, upload canary POST, "
                    "MFA/OTP POST, or forged SAML POST. Treat them as Leads, not tested-clean results."
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
    resolved_target = canonical_target_value(target)
    goals_dir = repo_root / "memory" / "goals"
    active = _read_json_object(goals_dir / "active.json")
    target_memory = _read_json_object(
        goals_dir / "targets" / f"{target_storage_key(resolved_target)}.json"
    )
    active_target = canonical_target_value(str(active.get("target", "") or ""))
    active_matches = bool(active_target and active_target == resolved_target)
    return {
        "active": active if active_matches else {},
        "target": target_memory,
        "active_matches": active_matches,
    }


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


def _build_external_url_context_leads(context: dict, urls: list[str]) -> list[dict]:
    """把第三方 URL 保留为链路上下文，不作为当前目标直接验证面。"""
    clean_urls = _dedupe_keep_order([str(url or "").strip() for url in urls if str(url or "").strip()])
    if not clean_urls:
        return []
    storage_key = target_storage_key(context.get("target", ""))
    return [{
        "source": "external_url_context",
        "title": f"{len(clean_urls)} third-party/integration URL(s) preserved as chain context",
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


def _read_httpx_hosts(recon_dir: Path) -> tuple[dict[str, dict], set[str]]:
    """Parse live/httpx_full.txt into host metadata and 403-only hosts."""
    httpx_path = recon_dir / "live" / "httpx_full.txt"
    hosts = {}
    status403 = set()
    if not httpx_path.is_file():
        return hosts, status403

    with open(httpx_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if not parts:
                continue
            url = parts[0]
            parsed = urlparse(url)
            host = parsed.netloc or parsed.path
            matches = re.findall(r"\[([^\]]+)\]", line)
            status = matches[0] if len(matches) >= 1 else ""
            title = matches[1] if len(matches) >= 2 else ""
            techs = []
            if len(matches) >= 3:
                techs = [item.strip().lower() for item in matches[2].split(",") if item.strip()]
            hosts[host] = {
                "url": url,
                "host": host,
                "status": status,
                "title": title,
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


def _has_contextual_numeric_id(path: str) -> bool:
    """Return true for numeric IDs with resource context, not bare `/<number>` pages."""
    return bool(CONTEXTUAL_NUMERIC_ID_RE.search(str(path or "")))


def _candidate_reason(path: str, query_keys: list[str]) -> tuple[str, str]:
    lower = path.lower()
    if "graphql" in lower:
        return "GraphQL surface", "field-level auth checks and mutation abuse"
    if lower.startswith("/ws") or "websocket" in lower or lower.endswith("/ws"):
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


def _add_review_item(pool: list[dict], seen: set[str], item: dict, reason: str) -> None:
    """Add one surface item to the bounded AI review pool."""
    url = str(item.get("url") or "").strip()
    if not url or url in seen or len(pool) >= REVIEW_POOL_LIMIT:
        return
    seen.add(url)
    cloned = dict(item)
    cloned["review_reason"] = reason
    pool.append(cloned)


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
    unresolved = [item for item in candidates if not _is_final_surface_item(item)]

    for item in unresolved:
        if item.get("evidence_convergence"):
            _add_review_item(pool, seen, item, "cross-evidence convergence")
    for item in unresolved:
        if item.get("browser_observed"):
            _add_review_item(pool, seen, item, "browser-observed API/workflow")
    for item in unresolved:
        if item.get("js_intel_observed") or item.get("source_intel_observed"):
            _add_review_item(pool, seen, item, "JS/source-inferred surface")
    for item in unresolved:
        if item.get("scanner_findings"):
            _add_review_item(pool, seen, item, "scanner lead requiring AI triage")
    for item in unresolved:
        if item.get("target_memory_hits"):
            _add_review_item(pool, seen, item, "target-memory continuation")
    for item in unresolved:
        if _has_actionable_review_evidence(item):
            _add_review_item(pool, seen, item, "top advisory score")
    for item in ffuf_candidates or []:
        _add_review_item(pool, seen, item, "ffuf-observed route; AI triage required")
    if not pool:
        for item in unresolved:
            _add_review_item(pool, seen, item, "top advisory score (low-evidence fallback)")
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


def _load_intel_signals(recon_dir: Path) -> list[dict]:
    """Load local /intel output and reduce it to deterministic keyword signals."""
    intel_items = []
    intel_json = recon_dir / "intel.json"
    if intel_json.is_file():
        try:
            payload = json.loads(intel_json.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            payload = {}

        for bucket in ("critical", "high", "info"):
            for item in payload.get(bucket, []) if isinstance(payload, dict) else []:
                if isinstance(item, dict):
                    intel_items.append(item)

    intel_md = recon_dir / "intel.md"
    if intel_md.is_file():
        text = intel_md.read_text(encoding="utf-8", errors="replace")
        for line in text.splitlines():
            if "|" in line or line.startswith(("[", "-", "  ")):
                intel_items.append({"summary": line, "severity": "INFO", "source": "intel.md"})

    signals = []
    seen = set()
    for item in intel_items:
        haystack = " ".join(
            str(item.get(key, ""))
            for key in ("id", "source", "tech", "severity", "summary", "note")
        ).lower()
        for vuln_class, keywords in INTEL_KEYWORDS.items():
            if any(keyword in haystack for keyword in keywords):
                severity = str(item.get("severity", "INFO")).upper()
                key = (vuln_class, str(item.get("id", "")), str(item.get("summary", ""))[:120])
                if key in seen:
                    continue
                seen.add(key)
                signals.append({
                    "class": vuln_class,
                    "severity": severity,
                    "source": item.get("source", "intel"),
                    "id": item.get("id", ""),
                    "summary": item.get("summary", ""),
                })

    return signals


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
        endpoint = str(metadata.get("endpoint") or "").split("?", 1)[0].strip()
        if not endpoint:
            url = str(metadata.get("url") or "").strip()
            if url:
                endpoint = (urlparse(url).path or "/").split("?", 1)[0].strip()
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
    target_goal_memory = _load_target_goal_memory(repo_root, target)
    if not recon_dir.is_dir():
        return {
            "target": target,
            "available": False,
            "runtime_state": runtime_state,
            "recon_artifacts": recon_artifacts,
            "target_goal_memory": target_goal_memory,
        }

    hosts, status403_hosts = _read_httpx_hosts(recon_dir)
    # Payload-marker handling: never lose the endpoint/parameter surface during
    # discovery. Raw historical probes are logged for review, while inert
    # probe-derived shapes stay in ranking so a noisy archive cannot hide a
    # real attack surface.
    _probe_log = recon_dir / "urls" / "_filtered_attack_probes.txt"
    if write_probe_log and _probe_log.is_file():
        # Reset on each context load so the log reflects only the
        # current pass — otherwise it grows unboundedly across re-runs.
        _probe_log.unlink()
    probe_log_path = _probe_log if write_probe_log else None
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
    finding_index = load_finding_index(findings_dir)
    scanner_findings = [
        item for item in finding_index.get("findings", [])
        if isinstance(item, dict) and item.get("url")
        and url_belongs_to_target(str(item.get("url") or ""), target)
    ]
    ledger_entries = load_evidence_ledger_entries(repo_root, target)
    action_queue_entries = load_action_queue(repo_root, target).get("actions", [])
    intel_signals = _load_intel_signals(recon_dir)
    ffuf_summary = ReconAdapter(recon_dir).get_ffuf_summary()
    js_intel = load_js_intel_hypotheses(findings_dir)
    source_intel = load_source_intel_hypotheses(findings_dir)
    manual_review_leads = _build_manual_review_lead_hints(findings_dir, storage_key)

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
            for pattern in pattern_db.match(tech_stack=tech_stack, calibrated=True):
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
        "recon_dir": str(recon_dir),
        "cf_bypass_active": (recon_dir / "cf_cookies.txt").is_file(),
        "hosts": hosts,
        "status403_hosts": status403_hosts,
        "api_urls": api_urls,
        "param_urls": param_urls,
        "js_endpoints": js_endpoints,
        "browser_xhr_urls": browser_xhr_urls,
        "browser_api_urls": browser_api_urls,
        "scanner_findings": scanner_findings,
        "ledger_entries": ledger_entries,
        "action_queue_entries": action_queue_entries if isinstance(action_queue_entries, list) else [],
        "intel_signals": intel_signals,
        "ffuf_summary": ffuf_summary,
        "js_intel": js_intel,
        "source_intel": source_intel,
        "manual_review_leads": manual_review_leads,
        "target_goal_memory": target_goal_memory,
        "profile": profile,
        "runtime_state": runtime_state,
        "recon_artifacts": recon_artifacts,
        "pattern_matches": _dedupe_keep_order(
            [json.dumps(item, sort_keys=True) for item in pattern_matches]
        ),
        "page_js_map": _page_js_map,
        "pages_for_js": pages_for_js,
        "js_for_page": js_for_page,
    }


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
    target_goal_memory = context.get("target_goal_memory") or {}
    target_memory_summary = _target_memory_summary(target_goal_memory)
    tested_endpoints = set(profile.get("tested_endpoints", []))
    untested_endpoints = set(profile.get("untested_endpoints", []))
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

    candidates = []
    browser_urls = set(context.get("browser_xhr_urls", []) + context.get("browser_api_urls", []))
    js_intel = context.get("js_intel") or {}
    scanner_findings_by_url = {}
    for finding in context.get("scanner_findings", []):
        url = finding.get("url")
        if not url:
            continue
        scanner_findings_by_url.setdefault(url, []).append(finding)
    closure_resolver = ClosureResolver({
        "recent_entries": context.get("ledger_entries") or [],
    })
    action_queue_final_endpoints = _action_queue_final_endpoints(
        context.get("action_queue_entries") or []
    )

    raw_urls = _dedupe_keep_order(
        context["api_urls"]
        + context["param_urls"]
        + context.get("browser_xhr_urls", [])
        + context.get("browser_api_urls", [])
        + [finding.get("url", "") for finding in context.get("scanner_findings", [])]
    )
    js_full_urls = []
    default_host = ""
    if context["hosts"]:
        default_host = next(iter(context["hosts"].values())).get("url", "")
    for endpoint in context["js_endpoints"]:
        if endpoint.startswith("http://") or endpoint.startswith("https://"):
            js_full_urls.append(endpoint)
        elif default_host:
            js_full_urls.append(default_host.rstrip("/") + endpoint)
        else:
            js_full_urls.append(endpoint)

    js_intel_urls = build_js_intel_urls(js_intel, default_host)
    source_intel_urls = build_source_intel_urls(
        context.get("source_intel") or {},
        default_host,
        raw_urls + js_full_urls + list(js_intel_urls.keys()),
    )
    raw_urls = _dedupe_keep_order(
        raw_urls + js_full_urls + list(js_intel_urls.keys()) + list(source_intel_urls.keys())
    )
    external_context_urls = [
        url for url in raw_urls
        if not url_belongs_to_target(url, context["target"])
    ]
    raw_urls = [
        url for url in raw_urls
        if url_belongs_to_target(url, context["target"])
    ]

    lead_items = _sort_workflow_leads(
        _build_exposure_lead_hints(context.get("recon_artifacts") or {}, context["target"])
        + _build_target_memory_lead_hints(target_goal_memory)
        + _build_evidence_convergence_leads(
            browser_urls=browser_urls,
            js_intel_urls=js_intel_urls,
            source_intel_urls=source_intel_urls,
        )
        + _build_cf_bypass_refresh_leads(context)
        + _build_external_url_context_leads(context, external_context_urls)
        + build_js_lead_hints(js_intel)
        + build_source_lead_hints(context.get("source_intel") or {})
        + list(context.get("manual_review_leads") or [])
    )
    workflow_leads = _dedupe_keep_order([
        json.dumps(item, sort_keys=True)
        for item in lead_items
    ])

    for raw_url in raw_urls:
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
            evidence=raw_url,
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

        if raw_url in browser_urls:
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
        if "graphql" in path.lower() or "ws" in path.lower():
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
        matching_source_intel_hypotheses = source_intel_urls.get(raw_url, [])
        if matching_source_intel_hypotheses:
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
        if raw_url in browser_urls:
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
        if raw_url in context["api_urls"] or "/api/" in path.lower():
            score += _add_score_breakdown(
                score_breakdown,
                "recon",
                "API endpoint",
                4,
                "api_endpoints.txt" if raw_url in context["api_urls"] else path,
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

        entry = {
            "url": raw_url,
            "host": host,
            "path": path,
            "score": score,
            "score_breakdown": score_breakdown,
            "reasons": reasons,
            "suggested": suggested,
            "tech_stack": context["hosts"].get(host, {}).get("tech_stack", []),
            "tested": path in tested_endpoints,
        }
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
        if raw_url in browser_urls:
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
                }
                for signal in matching_intel[:5]
            ]

        endpoint_path = parsed.path or "/"
        ledger_vuln_hint = _surface_vuln_hint(path, suggested, query_keys)
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
        candidates.append(entry)

    ffuf_summary = context.get("ffuf_summary") or {}
    ffuf_review_candidates = _build_ffuf_review_candidates(
        ffuf_summary,
        context["target"],
        candidates,
    )

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

    candidates.sort(key=lambda item: item["score"], reverse=True)
    p1 = [item for item in candidates if item["score"] >= 8][:8]
    p2 = [item for item in candidates if 3 <= item["score"] < 8][:8]
    review_pool = _build_review_pool(candidates, ffuf_review_candidates)

    return {
        "available": True,
        "target": context["target"],
        "runtime_state": context.get("runtime_state", {}),
        "recon_artifacts": context.get("recon_artifacts", {}),
        "p1": p1,
        "p2": p2,
        "review_pool": review_pool,
        "kill": _dedupe_keep_order([json.dumps(item, sort_keys=True) for item in kill]),
        "memory": {
            "tested_count": len(tested_endpoints),
            "untested_count": len(untested_endpoints),
            "pattern_suggestions": pattern_techniques[:3],
        },
        "target_memory": target_memory_summary,
        "scanner": {
            "finding_count": len(context.get("scanner_findings", [])),
        },
        "intel": {
            "signal_count": len(context.get("intel_signals", [])),
        },
        "ffuf": ffuf_summary,
        "js_intel": js_intel_counts(js_intel),
        "source_intel": source_intel_counts(context.get("source_intel") or {}),
        "workflow_leads": workflow_leads,
        "browser": {
            "xhr_count": len(context.get("browser_xhr_urls", [])),
            "api_count": len(context.get("browser_api_urls", [])),
        },
        "stats": {
            "total_candidates": len(candidates),
            "p1": len(p1),
            "p2": len(p2),
            "review_pool": len(review_pool),
            "kill": len(kill),
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
            f"surface inputs: {counts.get('api_urls', 0) + counts.get('param_urls', 0) + counts.get('js_endpoints', 0) + counts.get('browser_xhr_urls', 0) + counts.get('browser_api_urls', 0) + counts.get('ffuf_observations', 0)}, "
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
            lines.append(f"{idx}. {item['url']} — {review_reason}; {reason}")
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
            lines.append(f"{idx}. {item['url']} — {reason}")
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
            lines.append(f"{idx}. {item['url']} — {reason}")
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
                    f"→ {item['url']}"
                )
                shown += 1
                if shown >= 5:
                    break
            if shown >= 5:
                break
    else:
        lines.append("- No structured scanner candidates yet.")

    lines.extend(["", "Intel Signals:"])
    intel_count = ranked.get("intel", {}).get("signal_count", 0)
    if intel_count:
        lines.append(f"- Local intel signals: {intel_count}")
        shown = 0
        for item in ranked.get("p1", []) + ranked.get("p2", []):
            for signal in item.get("intel_signals", []):
                label = signal.get("id") or signal.get("summary") or signal.get("source", "intel")
                lines.append(
                    f"- {signal.get('class', '-')} "
                    f"[{signal.get('severity', '-')}] → {item['url']} :: {str(label)[:90]}"
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


def main() -> None:
    parser = argparse.ArgumentParser(description="Build an AI-first surface review pack from cached recon")
    parser.add_argument("--target", required=True, help="Target domain")
    parser.add_argument("--memory-dir", default="", help="Optional hunt-memory directory")
    parser.add_argument("--json", action="store_true", help="Output JSON summary")
    args = parser.parse_args()

    memory_dir = args.memory_dir or str(default_memory_dir(BASE_DIR))
    context = load_surface_context(BASE_DIR, args.target, memory_dir=memory_dir)
    ranked = rank_surface(context)
    if args.json:
        print(json.dumps(ranked, indent=2))
        return
    print(format_surface_output(ranked, args.target))


if __name__ == "__main__":
    main()
