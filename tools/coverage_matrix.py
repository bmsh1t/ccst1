#!/usr/bin/env python3
"""
coverage_matrix.py — (endpoint x vuln_class) coverage state for the hunt.

Purpose:
    A senior hunter does NOT finish a run while obvious high-value
    test combinations remain unexplained. The coverage matrix captures
    this as an evidence hint ledger: for each endpoint × vuln class pair,
    the cell is either tested-clean, tested-with-finding, untested, or N/A.
    It is not a fixed execution checklist and must not override Claude's
    attack-surface judgment. Raw gaps are hints; Claude must review them
    against browser/source/JS evidence, Evidence Ledger, case state, raw
    responses, and business context before treating them as actionable.

    This tool is NOT auto-invoked. Claude consults it via the
    Question -> Tool Reference table when its working_hypothesis
    asks "which coverage hints still need explanation?".

Design notes:
    - Schema per design.md Contract 4 (Phase 3): endpoints array
      with nested cells per vuln class.
    - Every observed route stays discoverable; bounded projections limit context, not coverage.
    - primary rebuild recovers authored reviews from Store, including with
      --force-clean; legacy incremental rebuild retains matrix annotations.
    - All cell values are typed enums INTERNALLY (4 statuses) but
      the cell shape is data, NOT a Claude-facing options[] menu.
      `find-gaps` exposes all unresolved cells; --limit only bounds output.
      The grid is not a prescribed test sequence.

VULN_CLASSES taxonomy (ordering is stable and append-only
on extension; positional consumers may rely on the prefix):

    NOTE: the three groups below are CONCEPTUAL organisation for human
    comprehension — they do NOT reflect tuple order. The actual enum
    order is preserved as: original 10 first (IDOR..JWT), 5 new
    appended (SQLi..CSRF). See `VULN_CLASSES = (...)` for the
    canonical positional layout.

    Group 1 — Authn/Authz/identity surface (5):
      IDOR     — direct object reference horizontal/vertical
      Authz    — broader access control (admin endpoints, role bypass)
      OAuth    — OAuth/OIDC flows (state, redirect_uri, scope confusion)
      JWT      — token-level (alg=none, kid injection, weak secret)
      CSRF     — session-riding; standalone is often rejected — submit
                 chained (CSRF -> state-change -> account compromise)

    Group 2 — Input injection family (5):
      XSS      — reflected/stored/DOM execution contexts
      SQLi     — error-based / boolean-blind / time-based / OOB;
                 covers all DBMS variants
      XXE      — classic + blind/OOB; both general & parameter entities
      RCE      — umbrella: OS command injection, deserialisation,
                 SSTI -> RCE escalation, file upload -> exec, etc.
      Path     — Path Traversal / LFI / RFI variants. Single-token
                 name kept for symmetry with JWT/RCE/XXE; if you find
                 LFI or RFI, mark as Path. Burp/Nuclei may tag
                 differently — normalise here.

    Group 3 — Server-side & API (5):
      SSRF     — outbound request forge, includes blind SSRF + OOB
      Race     — TOCTOU, double-spend, parallel state mutation
      GraphQL  — introspection, deep-nested queries, alias DoS, batch
                 abuse, mutation IDOR (overlaps with IDOR but tagged
                 separately because the discovery surface is distinct)
      Upload   — file upload bypass (extension/MIME/content), often
                 chains to RCE via webshell
      Webhook  — incoming webhook abuse (HMAC bypass, replay, spoof)

    Appended semantic classes retain independent cells for NoSQLi,
    PrototypePollution, OpenRedirect, and BusinessLogic. They must not be
    closed by a related SQLi, XSS, or Authz result.
"""

from __future__ import annotations

import argparse
import bisect
import fcntl
import hashlib
import html
import json
import re
import shlex
import sys
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote, urlsplit

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

try:
    from tools.artifact_io import write_json_atomic
except ImportError:  # pragma: no cover - direct tools/ execution
    from artifact_io import write_json_atomic


try:
    from tools.attack_probe_filter import is_attack_probe, sanitize_attack_probe_url
    from tools.closure_resolver import ClosureResolver, STRUCTURAL_NA_MARKERS, is_structural_na
    from tools.evidence_identity import CANONICAL_VULN_CLASSES, VULN_CLASS_ALIASES as CLOSURE_VULN_CLASS_ALIASES, collapse_dynamic_path_segments, extract_endpoint_path, normalize_vuln_class, path_with_query, query_param_names
    from tools.recon_filters import (
        has_html_unicode_encoding,
        has_malformed_path,
        has_url_encoding_error,
    )
    from tools.route_kinds import load_observations as load_route_kind_observations
    from tools.surface_index import build_surface_index_input_manifest, iter_surface_index, load_surface_index_status, recon_source_iterators
    from tools.target_paths import canonical_target_value, target_https_url, target_storage_key
    from tools.scope_context import url_belongs_to_target
    from tools.target_store import COVERAGE_REVIEW_STATUSES, ENDPOINT_KIND_VALUES, FINAL_ENDPOINT_KIND_SOURCES, StoreError, runtime_store, target_switch_lock
except ImportError:  # pragma: no cover - top-level tools/ import
    from attack_probe_filter import is_attack_probe, sanitize_attack_probe_url  # type: ignore
    from closure_resolver import ClosureResolver, STRUCTURAL_NA_MARKERS, is_structural_na  # type: ignore
    from evidence_identity import (  # type: ignore
        CANONICAL_VULN_CLASSES,
        VULN_CLASS_ALIASES as CLOSURE_VULN_CLASS_ALIASES,
        collapse_dynamic_path_segments,
        extract_endpoint_path,
        normalize_vuln_class,
        path_with_query,
        query_param_names,
    )
    from recon_filters import (  # type: ignore
        has_html_unicode_encoding,
        has_malformed_path,
        has_url_encoding_error,
    )
    from route_kinds import load_observations as load_route_kind_observations  # type: ignore
    from surface_index import build_surface_index_input_manifest, iter_surface_index, load_surface_index_status, recon_source_iterators  # type: ignore
    from target_paths import canonical_target_value, target_https_url, target_storage_key  # type: ignore
    from scope_context import url_belongs_to_target  # type: ignore
    from target_store import (  # type: ignore
        COVERAGE_REVIEW_STATUSES, ENDPOINT_KIND_VALUES, FINAL_ENDPOINT_KIND_SOURCES,
        StoreError, runtime_store, target_switch_lock,
    )


class CoverageEvidenceChangedError(StoreError):
    """Coverage and a later evidence acquisition no longer describe the same inputs."""


VULN_CLASSES = CANONICAL_VULN_CLASSES
VULN_CLASS_ALIASES = {
    alias: canonical
    for alias, canonical in CLOSURE_VULN_CLASS_ALIASES.items()
    if canonical in VULN_CLASSES
}
HIGH_RISK_LANE_TECHNIQUES = {
    "RCE": ("SSTI", "CommandInjection", "Deserialization"),
    "Path": ("LFI", "RFI"),
}
COVERAGE_BUILD_VERSION = 8


STATUS_VALUES = COVERAGE_REVIEW_STATUSES

STATIC_ASSET_EXTENSIONS = {
    ".js", ".mjs", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".ico", ".webp", ".woff", ".woff2", ".ttf", ".eot", ".map", ".txt",
    ".pdf", ".mp4", ".webm", ".wasm",
}
STATIC_ASSET_ROOT_SEGMENTS = {
    "assets", "asset", "static", "public", "images", "img", "css", "js",
    "fonts", "i18n", "locales", "favicon",
}
PUBLIC_METADATA_EXACT_PATHS = {
    "/__/firebase/init.json",
    "/.well-known/security.txt",
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/.well-known/oauth-protected-resource",
    "/.well-known/jwks",
    "/.well-known/jwks.json",
    "/.well-known/csaf/provider-metadata.json",
}
PUBLIC_METADATA_PREFIXES = (
    "/.well-known/csaf/",
)

ROUTE_PREFIX_CANDIDATE_SEGMENTS = {
    "admin",
    "api",
    "rest",
    "graphql",
    "internal",
    "staff",
    "console",
    "backoffice",
    "manage",
    "management",
}

AUTO_APPLICABILITY_NA_MARKERS = (
    "static asset;",
    "standard/public metadata;",
    "route prefix/container;",
    "minified JS property-chain artifact;",
)

STRUCTURAL_NOISE_HINTS = {
    "static_asset_shape",
    "public_metadata_path",
    "minified_js_pseudo",
    "route_prefix_candidate",
}

# Route-kind observation labels (tools/route_kinds.py) attached as endpoint
# hints. These are GET-probe/brower/scanner facts, never an endpoint-kind
# decision: a client_route label does not close any cell and does not block
# an AI-chosen test; it only feeds queue qualification so an unobserved
# server-backed surface is not crowded out by SPA shell routes.
SERVER_BACKED_ROUTE_KINDS = {"json_api", "auth_gate", "http_error", "http_redirect"}
OBSERVED_ROUTE_KIND_HINT_PREFIX = "route_kind:"


def _storage_key(target: str) -> str:
    """Return the canonical directory key shared with recon/findings/memory.

    URL targets contain `/` in their raw form. Writing coverage artifacts under
    the raw target creates split paths such as `evidence/http:/127...`, while
    recon/findings use `target_storage_key()` (`http:_127...`). Keep every
    coverage read/write on the shared storage key so `/autopilot` sees one
    coherent target state.
    """
    return target_storage_key(canonical_target_value(target))


def _matrix_path(repo_root: Path, target: str) -> Path:
    return repo_root / "evidence" / _storage_key(target) / "coverage_matrix.json"


@contextmanager
def coverage_matrix_mutation_lock(repo_root: Path | str, target: str):
    """Serialize one target's complete coverage read-modify-write transaction."""
    path = _matrix_path(Path(repo_root), target)
    lock_path = path.parent / "locks" / "coverage_matrix.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with target_switch_lock(repo_root, target):
        with lock_path.open("a+", encoding="utf-8") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _empty_matrix(target: str) -> dict:
    return {
        "target": target,
        "vuln_classes": list(VULN_CLASSES),
        "endpoints": [],
        "summary": {
            "total_cells": 0,
            "tested_clean": 0,
            "tested_finding": 0,
            "untested": 0,
            "n_a": 0,
            "high_value_gaps_count": 0,
        },
        "last_updated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "policy_skips": {},
    }


def load_matrix(target: str, repo_root: Path | str | None = None) -> dict:
    """Load the matrix for a target. Returns an empty shell when absent."""
    repo = Path(repo_root) if repo_root else BASE_DIR
    path = _matrix_path(repo, target)
    if not path.is_file():
        return _empty_matrix(target)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"unable to read coverage matrix {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid coverage matrix JSON {path}: {exc.msg}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"coverage matrix {path} must contain one object")
    if not isinstance(data.get("endpoints"), list):
        raise ValueError(f"coverage matrix {path} endpoints must be a list")
    data["high_risk_lanes"] = high_risk_lane_summary(data)
    return data


def coverage_source_fingerprint(
    target: str,
    repo_root: Path | str | None = None,
) -> str:
    """Bind a rebuilt matrix to its inputs without reading large bodies."""
    repo = Path(repo_root) if repo_root else BASE_DIR
    key = _storage_key(target)
    store = runtime_store(repo, target)
    paths = (
        repo / "recon" / key / "urls" / "all_filtered.txt",
        repo / "recon" / key / "urls" / "all.txt",
        repo / "recon" / key / "urls" / "filter.log",
        repo / "recon" / key / "route_kinds.json",
        repo / "findings" / key / "scanner_pass.json",
        repo / "findings" / key / "summary.json",
    )
    paths += (
        repo / "recon" / key / "urls" / "raw",
        repo / "recon" / key / "browser" / "xhr_endpoints.txt",
        repo / "recon" / key / "browser" / "api_endpoints.txt",
        repo / "findings" / key / "js_intel" / "hypotheses.json",
    )
    items = []
    for path in paths:
        try:
            stat = path.stat()
        except FileNotFoundError:
            items.append({"path": str(path.relative_to(repo)), "exists": False})
            continue
        items.append({
            "path": str(path.relative_to(repo)),
            "exists": True,
            "size": stat.st_size,
            "mtime_ns": stat.st_mtime_ns,
            "ctime_ns": stat.st_ctime_ns,
            "st_dev": stat.st_dev,
            "st_ino": stat.st_ino,
        })
    surface_status = load_surface_index_status(repo, target)
    surface_binding = {
        "status": str(surface_status.get("status") or "invalid"),
        "reason": str(surface_status.get("reason") or ""),
    }
    if surface_binding["status"] == "valid":
        manifest = surface_status.get("manifest") or {}
        surface_binding.update({
            "input_fingerprint": str(manifest.get("input_fingerprint") or ""),
            "index_binding": manifest.get("index_binding") or {},
            "row_count": int(manifest.get("row_count", 0) or 0),
        })
    store_binding = store.binding()
    payload = {
        "build_version": COVERAGE_BUILD_VERSION,
        "inputs": items,
        "surface_index": surface_binding,
        "store": store_binding,
        "surface_inputs": build_surface_index_input_manifest(repo, target)["fingerprint"],
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def matrix_is_fresh(
    target: str,
    matrix: dict,
    repo_root: Path | str | None = None,
) -> bool:
    snapshot = matrix.get("source_snapshot") or {}
    if matrix.get("backend") == "primary" and "as_of" in snapshot:
        current = read_matrix(target, repo_root, as_of=snapshot["as_of"])
        return matrix.get("source_fingerprint") == current["source_fingerprint"]
    expected = coverage_source_fingerprint(
        target,
        repo_root,
    )
    return bool(matrix.get("source_fingerprint")) and matrix.get("source_fingerprint") == expected


def _write_json_atomic(path: Path, payload: dict) -> None:
    write_json_atomic(path, payload, ensure_ascii=True)


def load_matrix_projection(target: str, repo_root: Path | str | None = None) -> dict:
    """Read the current Store projection without publishing a cache."""
    return read_matrix(target, repo_root)


def _save_matrix_unlocked(target: str, matrix: dict, repo_root: Path | str | None = None) -> Path:
    """Persist matrix; recompute summary at save time.

    Mutates the input dict in place so the caller sees the freshly
    computed `summary` and updated `last_updated` immediately after
    return — required by the CLI `rebuild` stdout path which reads
    `matrix["summary"]` to print cell counts. A prior shallow-copy
    implementation caused stdout to report a stale summary while the
    on-disk file was correct.
    """
    repo = Path(repo_root) if repo_root else BASE_DIR
    matrix["last_updated"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    matrix["summary"] = _compute_summary(matrix)
    matrix["high_risk_lanes"] = high_risk_lane_summary(matrix)
    path = _matrix_path(repo, target)
    _write_json_atomic(path, matrix)
    return path


def save_matrix(target: str, matrix: dict, repo_root: Path | str | None = None) -> Path:
    """Persist a matrix under the target-local mutation lock."""
    repo = Path(repo_root) if repo_root else BASE_DIR
    with coverage_matrix_mutation_lock(repo, target):
        return _save_matrix_unlocked(target, matrix, repo)


def _compute_summary(matrix: dict) -> dict:
    counts = {status: 0 for status in STATUS_VALUES}
    total = 0
    high_gaps = 0
    for ep in matrix.get("endpoints", []):
        for cell in ep.get("cells", {}).values():
            total += 1
            status = cell.get("status", "untested")
            if status in counts:
                counts[status] += 1
            if status == "untested":
                high_gaps += 1
    if matrix.get("backend") == "primary":
        high_gaps = sum(1 for _ in _iter_high_value_gaps(matrix))
    actionable_gaps = high_gaps
    return {
        "total_cells": total,
        **counts,
        "high_value_gaps_count": high_gaps,
        "actionable_high_value_gaps_count": actionable_gaps,
    }


def _canonicalize_endpoint(url: str) -> str:
    """Project a raw URL to a canonical endpoint key (no query string)."""
    return extract_endpoint_path(url)


_EMBEDDED_URL_IN_PATH_PATTERN = re.compile(r"https?://", re.IGNORECASE)
_PATH_CONTROL_PATTERN = re.compile(r"[\x00-\x1f\x7f]|\\[nrtfv]", re.IGNORECASE)
_HTML_ENTITY_PATTERN = re.compile(
    r"&(?:#[0-9]+|#x[0-9a-f]+|[a-z][a-z0-9]+);",
    re.IGNORECASE,
)


def _raw_path_text(raw_url: str) -> str:
    """Keep entity-like `#` text visible while excluding the query string."""
    value = str(raw_url or "").strip()
    value = re.sub(r"^[a-z][a-z0-9+.-]*://[^/]*", "", value, count=1, flags=re.I)
    return value.split("?", 1)[0]


def _is_malformed_coverage_path(raw_url: str, endpoint: str) -> bool:
    """Keep crawler fragments out of coverage without changing raw recon."""
    try:
        parsed_path = urlsplit(str(raw_url or "").strip()).path
    except ValueError:
        return True
    raw_path = _raw_path_text(raw_url) or parsed_path or str(endpoint or "")
    decoded_paths = [raw_path]
    for _ in range(3):
        decoded = unquote(decoded_paths[-1])
        if decoded == decoded_paths[-1]:
            break
        decoded_paths.append(decoded)
    normalized_paths = [html.unescape(value) for value in decoded_paths]
    return (
        has_malformed_path(raw_path)
        or any(
            has_url_encoding_error(value) or has_html_unicode_encoding(value)
            for value in (*decoded_paths, *normalized_paths)
        )
        or any(_HTML_ENTITY_PATTERN.search(value) for value in decoded_paths)
        or any(_PATH_CONTROL_PATTERN.search(value) for value in normalized_paths)
        or any(_EMBEDDED_URL_IN_PATH_PATTERN.search(value) for value in normalized_paths)
    )


def _route_template(endpoint: str) -> str:
    """Collapse obvious dynamic path tokens for coverage admission only.

    The segment collapsing itself lives with the endpoint identity contract
    (``collapse_dynamic_path_segments``); only the admission policy stays here.
    """
    path = _canonicalize_endpoint(endpoint)
    if not path or _is_static_asset_endpoint(path) or _is_public_metadata_endpoint(path):
        return path
    return collapse_dynamic_path_segments(path)


def _has_persisted_coverage_state(endpoint: dict | None) -> bool:
    if not isinstance(endpoint, dict):
        return False
    return bool(endpoint.get("kind_review") or endpoint.get("reviews")) or any(
        isinstance(cell, dict) and cell.get("status", "untested") != "untested"
        for cell in (endpoint.get("cells") or {}).values()
    )


def _path_segments(endpoint: str) -> list[str]:
    path = _canonicalize_endpoint(endpoint)
    return [part for part in path.strip("/").split("/") if part]


def _is_identifier_token(token: str) -> bool:
    if not token:
        return False
    first = token[0]
    if not (first.isalpha() or first in {"_", "$"}):
        return False
    return all(ch.isalnum() or ch in {"_", "$"} for ch in token[1:])


def _is_dotted_identifier_chain(segment: str) -> bool:
    parts = segment.split(".")
    return len(parts) >= 2 and all(_is_identifier_token(part) for part in parts)


def _is_static_asset_endpoint(endpoint: str) -> bool:
    """Return true only for structural static-file / asset paths.

    这里不用漏洞语义词表判断，只看“首段是否是静态资源目录”或“后缀是否
    是明确静态文件类型”。`/api/file.json` 这类 API 形态不会因为有点号
    被降级。
    """
    path = _canonicalize_endpoint(endpoint)
    segments = _path_segments(path)
    if not segments:
        return False
    first = segments[0].lower()
    if first in STATIC_ASSET_ROOT_SEGMENTS:
        return True
    suffix = Path(segments[-1]).suffix.lower()
    return suffix in STATIC_ASSET_EXTENSIONS


def _is_public_metadata_endpoint(endpoint: str) -> bool:
    path = _canonicalize_endpoint(endpoint).lower().rstrip("/")
    return path in PUBLIC_METADATA_EXACT_PATHS or any(
        path.startswith(prefix) for prefix in PUBLIC_METADATA_PREFIXES
    )


def _looks_like_minified_js_pseudo_endpoint(endpoint: str) -> bool:
    """Detect DOM/property chains accidentally emitted as URL paths.

    Keep this deliberately narrow so real dotted paths such as
    `/.well-known/openid-configuration` or `/api/file.json` survive.
    """
    path = str(endpoint or "").strip()
    if not path:
        return False
    parts = _path_segments(path)
    if len(parts) < 2:
        return False
    dotted = [
        part for part in parts
        if _is_dotted_identifier_chain(part)
    ]
    if len(dotted) < 2:
        return False
    joined = ".".join(dotted).lower()
    browser_tokens = (
        "document",
        "window",
        "viewport",
        "visualviewport",
        "prototype",
        "addeventlistener",
        "queryselector",
        "getelement",
    )
    return any(token in joined for token in browser_tokens)


def _endpoint_kind(endpoint: str) -> str:
    """Return only a final structural kind when the evidence is deterministic.

    Endpoint semantics are deliberately AI-first. Regex/path heuristics may
    produce `auto_hints`, but they must not become final `endpoint_kind` until
    Claude/operator writes them back with `mark-endpoint-kind`.
    """
    return "untriaged"


def _is_route_prefix_candidate(endpoint: str, all_endpoints: set[str]) -> bool:
    """Return a non-authoritative hint for bare container-like paths.

    `/rest/admin` can be a real handler or just a prefix for
    `/rest/admin/application-configuration`; the tool only exposes this as a
    hint so Claude can judge from response/body/browser evidence.
    """
    path = str(endpoint or "").rstrip("/")
    if not path or path == "/":
        return False
    segments = _path_segments(path)
    if not segments:
        return False
    if segments[-1].lower() not in ROUTE_PREFIX_CANDIDATE_SEGMENTS:
        return False
    prefix = f"{path}/"
    return any(other != path and str(other).startswith(prefix) for other in all_endpoints)


def _endpoint_auto_hints(
    endpoint: str,
    observed_params: object | None = None,
    all_endpoints: set[str] | None = None,
) -> list[str]:
    """Return non-authoritative hints for Claude triage.

    These hints are facts/features for ordering and explanation. They are not
    endpoint-kind decisions and must not be used as N/A proof.
    """
    hints: list[str] = []
    path = _canonicalize_endpoint(endpoint)
    if _looks_like_minified_js_pseudo_endpoint(path):
        hints.append("minified_js_pseudo")
    if _is_public_metadata_endpoint(path):
        hints.append("public_metadata_path")
    if _is_static_asset_endpoint(path):
        hints.append("static_asset_shape")
    if re.search(r"^/(?:api|rest|graphql|wp-json)(?:/|$)", path, re.I):
        hints.append("api_like_path")
    if all_endpoints is not None and _is_route_prefix_candidate(path, all_endpoints):
        hints.append("route_prefix_candidate")
    params: list[str] = []
    if isinstance(observed_params, (list, tuple, set)):
        params = [str(item) for item in observed_params if str(item or "").strip()]
    if params:
        hints.append("has_query_params")
    return list(dict.fromkeys(hints))


def _has_final_endpoint_kind(ep: dict | None) -> bool:
    if not isinstance(ep, dict):
        return False
    return (
        str(ep.get("kind_source") or "") in FINAL_ENDPOINT_KIND_SOURCES
        and str(ep.get("endpoint_kind") or "") in ENDPOINT_KIND_VALUES
        and ep.get("endpoint_kind") != "untriaged"
    )


def _effective_endpoint_kind(existing_ep: dict | None, endpoint: str) -> str:
    if _has_final_endpoint_kind(existing_ep):
        return str(existing_ep.get("endpoint_kind") or "untriaged")
    return _endpoint_kind(endpoint)


def _na_cell(reason: str, *, code: str) -> dict[str, str]:
    return {"status": "n_a", "reason": reason, "structural_code": code,
            "structural_marker": STRUCTURAL_NA_MARKERS[code],
            "structural_source": "coverage:endpoint_kind"}


def _empty_cells(
    endpoint: str = "",
    *,
    endpoint_kind: str | None = None,
    auto_hints: list[str] | None = None,
) -> dict[str, dict]:
    kind = endpoint_kind or _endpoint_kind(endpoint)
    hints = set(auto_hints or [])
    reason = ""
    # 不把 endpoint kind 当成漏洞适用性的最终裁判。static asset /
    # public metadata 只影响优先级，不自动写 n_a；是否值得继续看由 AI
    # 结合 JS/source/exposure 证据判断，避免工具层把攻击面“判死”。
    # 只有结构性垃圾（dotted minified-JS 链）是 strong enough 的 floor。
    # 例外：route_prefix 不是工具正则裁判，而是 Claude/operator 已经写回的
    # final endpoint kind。此时应把它从“直接 replay 目标”里移出，避免
    # `/rest/admin × 15 类` 这种虚假 coverage gap 干扰专家循环；真实子端点
    # 仍保留为独立行继续验证。
    if kind == "minified_js_pseudo" or "minified_js_pseudo" in hints:
        code = "minified_js_property_chain"
        reason = "minified JS property-chain artifact; not an HTTP handler endpoint"
    elif kind == "route_prefix":
        code = "route_prefix"
        reason = "route prefix/container; AI-triaged as not a direct replay endpoint"

    if reason:
        return {vc: _na_cell(reason, code=code) for vc in VULN_CLASSES}
    return {vc: {"status": "untested"} for vc in VULN_CLASSES}


def _is_auto_applicability_na(cell: dict) -> bool:
    return is_structural_na(cell)


def _apply_endpoint_applicability(ep: dict, endpoint_kind: str) -> None:
    """Apply conservative N/A defaults without overwriting evidence."""
    defaults = _empty_cells(
        str(ep.get("endpoint") or ""),
        endpoint_kind=endpoint_kind,
        auto_hints=list(ep.get("auto_hints") or []),
    )
    cells = ep.get("cells") or {}
    for vc in VULN_CLASSES:
        default = defaults.get(vc, {"status": "untested"})
        current = cells.get(vc)
        if not isinstance(current, dict):
            cells[vc] = dict(default)
            continue
        if default.get("status") != "n_a" and _is_auto_applicability_na(current):
            cells[vc] = dict(default)
            continue
        if default.get("status") == "n_a" and current.get("status", "untested") == "untested":
            cells[vc] = dict(default)
    ep["cells"] = cells


def _load_js_path_artifact_urls(urls_dir: Path) -> set[str]:
    """Load recon-filtered JS member-expression pseudo URLs.

    These entries are not merely low-priority attack surface. They are crawler
    artifacts where JavaScript property chains were mistaken for paths, so raw
    URL fallback must not resurrect them as coverage endpoints.
    """
    log_path = urls_dir / "filter.log"
    if not log_path.is_file():
        return set()
    artifacts: set[str] = set()
    try:
        lines = log_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return artifacts
    prefix = "[JS_PATH_ARTIFACT] "
    for line in lines:
        if not line.startswith(prefix):
            continue
        artifact = line[len(prefix):].strip()
        if artifact:
            artifacts.add(artifact)
    return artifacts


def _gap_sort_key(gap: dict) -> tuple:
    """Stable identity order; recorded route facts do not choose the work."""
    return (str(gap.get("endpoint") or ""), str(gap.get("vuln_class") or ""))


def high_value_gaps_from_matrix(matrix: dict) -> list[dict]:
    """Return sorted untested cells from an in-memory matrix."""
    gaps = list(_iter_high_value_gaps(matrix))
    gaps.sort(key=_gap_sort_key)
    return gaps


def coverage_gaps_with_observed_evidence(gaps: list[dict], matrix: dict | None = None) -> list[dict]:
    """Gaps that at least one OBSERVED fact points at.

    Shared Closure/queue visibility criterion: evidence-backed gaps are open
    work (unassessed != clean); gaps with no parameter, no source, and no
    route-kind observation are enumeration artifacts of the endpoint x class
    grid, advisory only, and AI may dispose of them implicitly. Word-list
    relevance never decides this — only observations do.

    An endpoint row in a full rebuild matrix was itself observed by recon
    (source_count defaults positive there), so gaps on such rows are
    evidence-backed unless the row explicitly records zero sources.
    """
    endpoint_sources: dict[str, int] = {}
    if isinstance(matrix, dict):
        for item in matrix.get("endpoints") or []:
            if isinstance(item, dict):
                try:
                    endpoint_sources[str(item.get("endpoint") or "")] = int(
                        item.get("source_count", 1) or 0
                    )
                except (TypeError, ValueError):
                    endpoint_sources[str(item.get("endpoint") or "")] = 1
    evidence_gaps: list[dict] = []
    for gap in gaps:
        if not isinstance(gap, dict):
            continue
        endpoint = str(gap.get("endpoint") or "")
        source_count = int(gap.get("source_count", 0) or 0)
        if not source_count and matrix is not None:
            source_count = endpoint_sources.get(endpoint, 0)
        has_evidence = bool(
            gap.get("observed_params")
            or gap.get("sources")
            or source_count > 0
            or int(gap.get("observation_count", 0) or 0) > 1
            or str(gap.get("route_kind") or "").strip()
        )
        if has_evidence:
            evidence_gaps.append(gap)
    return evidence_gaps


def _iter_high_value_gaps(matrix: dict):
    """Yield untested cells without materializing the full result."""
    resolver = (ClosureResolver(matrix.get("closure_projection"))
                if matrix.get("backend") == "primary" else None)
    for ep in matrix.get("endpoints", []):
        if not isinstance(ep, dict):
            continue
        endpoint = str(ep.get("endpoint") or "")
        observed_params = ep.get("observed_params") or []
        for vc, cell in (ep.get("cells") or {}).items():
            if not isinstance(cell, dict) or cell.get("status") != "untested":
                continue
            if resolver is not None and resolver.is_cell_closed(
                endpoint, vc, identity_v2=cell.get("identity_v2"),
            ):
                continue
            gap = {
                "endpoint": endpoint,
                "vuln_class": vc,
                # 只存参数名和来源/观察计数，不存参数值。checkpoint 需要这些
                # 轻量信号来区分“真实可重放输入面”和“仅路径命中的语义 gap”。
                "observed_params": list(observed_params),
                "source_count": int(ep.get("source_count", 0) or 0),
                "sources": sorted(str(s) for s in (ep.get("sources") or []) if str(s)),
                "observation_count": int(ep.get("observation_count", 0) or 0),
            }
            route_kind_label = str(ep.get("route_kind") or "").strip()
            if route_kind_label:
                gap["route_kind"] = route_kind_label
            representative = str(ep.get("representative_endpoint") or "").strip()
            if representative and representative != endpoint:
                gap["representative_endpoint"] = representative
            if isinstance(cell.get("identity_v2"), dict):
                gap["identity_v2"] = cell["identity_v2"]
            if ep.get("kind_review"):
                gap["endpoint_kind"] = ep["endpoint_kind"]
                gap["kind_review"] = ep["kind_review"]
            if cell.get("review"):
                gap["review"] = cell["review"]
            yield gap


def high_value_gap_window_from_matrix(
    matrix: dict,
    *,
    limit: int,
) -> tuple[list[dict], int]:
    """Return a ranked gap window and exact count for the selected view."""
    if limit < 0:
        raise ValueError("limit must be >= 0")
    total = 0
    selected: list[tuple[tuple, int, dict]] = []
    for index, gap in enumerate(_iter_high_value_gaps(matrix)):
        total += 1
        if limit:
            key = _gap_sort_key(gap)
            entry = (key, index, gap)
            if len(selected) < limit or entry[:2] < selected[-1][:2]:
                bisect.insort(selected, entry)
                if len(selected) > limit:
                    selected.pop()
    items = [entry[2] for entry in selected]
    return items, total


def high_risk_lane_summary(
    matrix: dict,
) -> dict[str, dict]:
    """Project an explicit disposition for every canonical high-risk family.

    This is a reporting/queue hint, not a scanner verdict.  In particular,
    ``unassessed`` means the endpoint has no family-specific evidence yet; it
    must never be treated as clean or N/A by closure.
    """
    endpoints = [item for item in matrix.get("endpoints", []) if isinstance(item, dict)]
    result: dict[str, dict] = {}
    for vuln_class in VULN_CLASSES:
        cells = [
            ep.get("cells", {}).get(vuln_class)
            for ep in endpoints
            if isinstance(ep.get("cells"), dict)
            and isinstance(ep.get("cells", {}).get(vuln_class), dict)
        ]
        counts = {
            "tested_clean": sum(cell.get("status") == "tested_clean" for cell in cells),
            "tested_finding": sum(cell.get("status") == "tested_finding" for cell in cells),
            "untested": sum(cell.get("status", "untested") == "untested" for cell in cells),
            "n_a": sum(cell.get("status") == "n_a" for cell in cells),
            "blocked": sum(cell.get("status") == "blocked" for cell in cells),
            "scanner_swept": sum(bool(cell.get("scanner_swept")) for cell in cells),
        }
        total = len(cells)
        if not total:
            disposition = "not_observed"
            reason = "no target-owned endpoint entered the coverage matrix"
        elif counts["tested_finding"]:
            disposition = "candidate"
            reason = "finding-grade evidence requires validation"
        elif counts["blocked"]:
            disposition = "blocked"
            reason = "one or more family checks are explicitly blocked"
        elif counts["n_a"] == total:
            disposition = "not_applicable"
            reason = "all endpoint cells have an explicit N/A reason"
        elif counts["untested"] == 0:
            disposition = "tested"
            reason = "every endpoint cell has an evidence-grade terminal state"
        else:
            disposition = "unassessed"
            reason = "untested cells remain; AI chooses applicability and the next experiment"
        result[vuln_class] = {
            "disposition": disposition,
            "reason": reason,
            "endpoint_count": total,
            **counts,
        }
        techniques = HIGH_RISK_LANE_TECHNIQUES.get(vuln_class)
        if techniques:
            result[vuln_class]["techniques"] = list(techniques)
    return result


def _ensure_endpoint(endpoints: dict[str, dict], endpoint: str) -> dict:
    """Reuse one read's endpoint entry without rescanning the growing matrix."""
    if endpoint in endpoints:
        return endpoints[endpoint]
    kind = _endpoint_kind(endpoint)
    auto_hints = _endpoint_auto_hints(endpoint)
    new_ep = {
        "endpoint": endpoint,
        "endpoint_kind": kind,
        "auto_hints": auto_hints,
        "observed_params": [],
        "source_count": 0,
        "observation_count": 0,
        "cells": _empty_cells(endpoint, endpoint_kind=kind),
    }
    endpoints[endpoint] = new_ep
    return new_ep


def rebuild_matrix(
    target: str,
    repo_root: Path | str | None = None,
    *,
    force_clean: bool = False,
) -> dict:
    """Rebuild and publish Coverage atomically for one target.

    The returned dict remains available to callers that need the in-memory
    projection, while the target-local lock also covers the persisted write so
    a concurrent mark cannot be overwritten by a stale rebuild snapshot.
    """
    repo = Path(repo_root) if repo_root else BASE_DIR
    with coverage_matrix_mutation_lock(repo, target):
        matrix = _rebuild_matrix_unlocked(
            target,
            repo_root=repo,
            force_clean=force_clean,
        )
        _save_matrix_unlocked(target, matrix, repo)
        return matrix


def read_matrix(
    target: str, repo_root: Path | str | None = None, *, as_of: str | None = None,
    current_only: bool = False,
) -> dict:
    """Read without publishing; primary always uses Store-authored reviews.

    as_of labels this read, not a historical query. Primary inputs are checked
    for drift; current truth verifies raw evidence bytes.
    """
    repo = Path(repo_root) if repo_root else BASE_DIR
    runtime_store(repo, target)
    reference_time = as_of if as_of is not None else datetime.now(timezone.utc).isoformat(timespec="seconds")
    if not isinstance(reference_time, str) or not reference_time.strip():
        raise ValueError("as_of must be a non-empty timestamp")
    inputs = coverage_source_fingerprint(target, repo)
    matrix = _rebuild_matrix_unlocked(target, repo, force_clean=current_only)
    if inputs != coverage_source_fingerprint(target, repo):
        raise StoreError("primary coverage inputs changed during assembly")
    matrix["as_of"] = matrix["last_updated"] = reference_time
    matrix["source_snapshot"].update({
        "as_of": reference_time,
        "discovery_fingerprint": inputs,
    })
    matrix["source_fingerprint"] = hashlib.sha256(json.dumps(
        matrix["source_snapshot"], sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")).hexdigest()
    matrix["summary"] = _compute_summary(matrix)
    matrix["high_risk_lanes"] = high_risk_lane_summary(matrix)
    return matrix


def require_matching_truth(matrix: dict, truth: dict) -> None:
    """Reject reused Coverage if a later evidence acquisition saw different inputs."""
    if (matrix.get("evidence_source") != truth["source"]
            or matrix.get("evidence_health") != truth["health"]
            or matrix.get("closure_projection") != truth["projection"]):
        raise CoverageEvidenceChangedError("primary coverage evidence changed during assembly; rebuild the view")


def _rebuild_matrix_unlocked(
    target: str,
    repo_root: Path | str | None = None,
    *,
    force_clean: bool = False,
) -> dict:
    """Project Recon, Store findings, observations and authored reviews.

    Reviews survive cache deletion and narrower Recon runs. force_clean is
    retained for call compatibility; cached cells never become current facts.
    """
    repo = Path(repo_root) if repo_root else BASE_DIR
    store = runtime_store(repo, target)
    store_binding = store.binding()
    matrix = _empty_matrix(target)
    if "endpoints" not in matrix:
        matrix["endpoints"] = []
    matrix["vuln_classes"] = list(VULN_CLASSES)
    existing: dict[str, dict] = {}
    page = store.coverage_review_page(limit=1000)
    while True:
        if page["store_id"] != store_binding["store_id"] or page["revision"] != store_binding["revision"]:
            raise StoreError("primary coverage inputs changed during assembly")
        for review in page["items"]:
            ep = _ensure_endpoint(existing, review["endpoint"])
            if review["kind"] == "endpoint_kind":
                ep.update({"endpoint_kind": review["value"], "kind_source": review["source"],
                           "kind_reason": review["reason"], "kind_triaged_at": review["reviewed_at"],
                           "kind_review": review})
            else:
                ep.setdefault("reviews", {})[review["family"]] = review
        if not page["has_more"]:
            break
        page = store.coverage_review_page(limit=1000, cursor=page["next_cursor"])

    # Collect URLs from recon
    target_key = _storage_key(target)
    urls_dir = repo / "recon" / target_key / "urls"
    surface_status = load_surface_index_status(repo, target)
    if surface_status.get("status") == "valid":
        source_rows = (
            (str(item.get("url") or ""), item.get("sources") or ("surface",))
            for item in iter_surface_index(repo, target)
            if item.get("target_owned") and str(item.get("url") or "")
        )
    else:
        source_rows = (
            (raw, (label,))
            for label, values in recon_source_iterators(repo, target)
            for raw in values
            if url_belongs_to_target(raw, target)
        )

    # Keep observed routes, parameter names and source provenance.
    js_path_artifacts = _load_js_path_artifact_urls(urls_dir)
    # Route-kind observations are keyed by full URL (query stripped); index
    # them by path so both full URLs and bare paths can pick the fact up.
    route_kind_by_path: dict[str, str] = {}
    route_kind_observations = load_route_kind_observations(repo, target).get("endpoints") or {}
    for observed_url, item in route_kind_observations.items():
        if not isinstance(item, dict):
            continue
        kind_label = str(item.get("route_kind") or "").strip()
        if not kind_label:
            continue
        observed_path = _canonicalize_endpoint(str(observed_url))
        if observed_path:
            route_kind_by_path.setdefault(observed_path, kind_label)
    seen: dict[str, dict] = {}
    for raw, raw_sources in source_rows:
        sources = {
            str(source).strip()
            for source in raw_sources
            if str(source).strip()
        }
        if raw in js_path_artifacts:
            continue
        if is_attack_probe(raw):
            raw = sanitize_attack_probe_url(raw)
        path = _canonicalize_endpoint(raw)
        if not path or _is_malformed_coverage_path(raw, path):
            continue
        if _looks_like_minified_js_pseudo_endpoint(path):
            continue
        params = query_param_names(raw)
        path_query = path_with_query(raw) or path
        meta = seen.setdefault(path, {
            "params": set(),
            "sources": set(),
            "observation_count": 0,
        })
        meta["params"].update(params)
        meta["sources"].update(sources)
        meta["observation_count"] = int(meta.get("observation_count", 0) or 0) + 1
        route_kind_label = route_kind_by_path.get(path)
        if route_kind_label:
            meta["route_kind"] = route_kind_label

    route_template_counts: dict[str, int] = {}
    for endpoint in seen:
        template = _route_template(endpoint)
        route_template_counts[template] = route_template_counts.get(template, 0) + 1

    # Only fold a route template when multiple distinct paths prove the pattern
    # is repeated. Query variants of one `/orders/123` stay addressable for
    # backwards compatibility and precise operator review.
    compacted_seen: dict[str, dict] = {}
    for endpoint, meta in seen.items():
        template = _route_template(endpoint)
        key = (
            template
            if template != endpoint
            and route_template_counts.get(template, 0) > 1
            and not _has_persisted_coverage_state(existing.get(endpoint))
            else endpoint
        )
        current = compacted_seen.setdefault(key, {
            "params": set(),
            "sources": set(),
            "observation_count": 0,
        })
        current["params"].update(meta.get("params") or [])
        current["sources"].update(meta.get("sources") or [])
        current["observation_count"] += int(meta.get("observation_count", 0) or 0)
        merged_kind = str(current.get("route_kind") or "")
        incoming_kind = str(meta.get("route_kind") or "")
        if incoming_kind and (
            not merged_kind
            or (
                incoming_kind in SERVER_BACKED_ROUTE_KINDS
                and merged_kind not in SERVER_BACKED_ROUTE_KINDS
            )
        ):
            current["route_kind"] = incoming_kind
        if key != endpoint:
            representative = str(current.get("representative_endpoint") or "")
            current["representative_endpoint"] = min(
                value for value in (representative, endpoint) if value
            )
    seen = compacted_seen

    # Merge request facts without suppressing unfamiliar or static-looking routes.
    all_seen_endpoints = set(seen)
    filtered_seen: dict[str, dict] = {}
    for endpoint, meta in seen.items():
        params = sorted(meta.get("params") or [])
        auto_hints = _endpoint_auto_hints(endpoint, params, all_endpoints=all_seen_endpoints)
        filtered_seen[endpoint] = {
            "params": params,
            "source_count": len(meta.get("sources") or []),
            "sources": sorted(meta.get("sources") or []),
            "observation_count": int(meta.get("observation_count", 0) or 0),
            "auto_hints": auto_hints,
        }
        route_kind_label = str(meta.get("route_kind") or "").strip()
        if route_kind_label:
            filtered_seen[endpoint]["route_kind"] = route_kind_label
            # Observation hint, sibling of auto_hints: never an endpoint-kind
            # decision, never N/A proof, visible to AI triage.
            filtered_seen[endpoint]["auto_hints"] = auto_hints + [
                OBSERVED_ROUTE_KIND_HINT_PREFIX + route_kind_label
            ]
        representative = str(meta.get("representative_endpoint") or "").strip()
        if representative and representative != endpoint:
            filtered_seen[endpoint]["representative_endpoint"] = representative

    # Merge: keep existing cells, add new endpoints with untested cells
    new_endpoints: list[dict] = []
    for endpoint, meta in filtered_seen.items():
        existing_ep = existing.get(endpoint)
        kind = _effective_endpoint_kind(existing_ep, endpoint)
        auto_hints = list(meta.get("auto_hints") or _endpoint_auto_hints(
            endpoint,
            meta.get("params") or [],
            all_endpoints=all_seen_endpoints,
        ))
        if endpoint in existing:
            ep = existing_ep or existing[endpoint]
            ep["endpoint_kind"] = kind
            ep["auto_hints"] = auto_hints
            ep["observed_params"] = sorted(set(ep.get("observed_params") or []) | set(meta.get("params") or []))
            ep["source_count"] = int(meta.get("source_count", 0) or 0)
            ep["observation_count"] = int(meta.get("observation_count", 0) or 0)
            merged_sources = sorted(set(ep.get("sources") or []) | set(meta.get("sources") or []))
            if merged_sources:
                ep["sources"] = merged_sources
            route_kind_label = str(meta.get("route_kind") or "").strip()
            if route_kind_label:
                ep["route_kind"] = route_kind_label
            else:
                ep.pop("route_kind", None)
            representative = str(meta.get("representative_endpoint") or "").strip()
            if representative and representative != endpoint:
                ep["representative_endpoint"] = representative
            else:
                ep.pop("representative_endpoint", None)
            cells = ep.get("cells") or {}
            ep["cells"] = cells
            _apply_endpoint_applicability(ep, kind)
            new_endpoints.append(ep)
        else:
            new_endpoint = {
                "endpoint": endpoint,
                "endpoint_kind": kind,
                "auto_hints": auto_hints,
                "observed_params": list(meta.get("params") or []),
                "source_count": int(meta.get("source_count", 0) or 0),
                "sources": list(meta.get("sources") or []),
                "observation_count": int(meta.get("observation_count", 0) or 0),
                "cells": _empty_cells(endpoint, endpoint_kind=kind, auto_hints=auto_hints),
            }
            route_kind_label = str(meta.get("route_kind") or "").strip()
            if route_kind_label:
                new_endpoint["route_kind"] = route_kind_label
            representative = str(meta.get("representative_endpoint") or "").strip()
            if representative and representative != endpoint:
                new_endpoint["representative_endpoint"] = representative
            new_endpoints.append(new_endpoint)

    # Store-authored reviews remain visible after narrower Recon runs.
    current_endpoints = {str(item.get("endpoint") or "") for item in new_endpoints}
    for endpoint, historical_ep in existing.items():
        endpoint = str(endpoint or "")
        if not endpoint or endpoint in current_endpoints:
            continue
        if not isinstance(historical_ep, dict):
            continue
        kind = _effective_endpoint_kind(historical_ep, endpoint)
        historical_ep["endpoint"] = endpoint
        historical_ep.setdefault("endpoint_kind", kind)
        historical_ep.setdefault("auto_hints", _endpoint_auto_hints(
            endpoint,
            historical_ep.get("observed_params") or [],
            all_endpoints=current_endpoints,
        ))
        historical_ep.setdefault("observed_params", [])
        historical_ep.setdefault("source_count", 0)
        historical_ep.setdefault("observation_count", 0)
        historical_ep.setdefault("cells", {})
        _apply_endpoint_applicability(historical_ep, kind)
        new_endpoints.append(historical_ep)

    # Apply finding claims from the active owner. Primary targets never read
    # the retired JSON index; the matrix remains a rebuildable projection.
    matrix["backend"] = "primary"
    matrix["target"] = store_binding["target"]
    matrix["store_id"] = store_binding["store_id"]
    matrix["store_revision"] = store_binding["revision"]
    endpoints = {ep["endpoint"]: ep for ep in new_endpoints}
    page = store.page("findings", limit=1000)
    while True:
        for finding in page["items"]:
            raw_endpoint = str(finding.get("endpoint") or finding.get("url") or "")
            ep_path = _canonicalize_endpoint(raw_endpoint)
            params = sorted(query_param_names(raw_endpoint))
            if not ep_path:
                continue
            coverage_path = ep_path
            if ep_path not in endpoints:
                template = _route_template(ep_path)
                if template != ep_path and (
                    template in endpoints or template in existing
                ):
                    coverage_path = template
            # ensure endpoint exists in matrix even if recon missed it
            if coverage_path in endpoints:
                ep = endpoints[coverage_path]
                ep["observed_params"] = sorted(set(ep.get("observed_params") or []) | set(params))
                existing_ep = existing.get(coverage_path)
                kind = _effective_endpoint_kind(existing_ep, coverage_path)
                ep["auto_hints"] = _endpoint_auto_hints(
                    coverage_path,
                    ep.get("observed_params") or [],
                    all_endpoints=all_seen_endpoints,
                )
                ep["endpoint_kind"] = kind
                _apply_endpoint_applicability(ep, kind)
            else:
                existing_ep = existing.get(coverage_path)
                kind = _effective_endpoint_kind(existing_ep, coverage_path)
                if isinstance(existing_ep, dict):
                    ep = dict(existing_ep)
                    ep["cells"] = dict(existing_ep.get("cells") or {})
                    ep["observed_params"] = sorted(set(ep.get("observed_params") or []) | set(params))
                else:
                    ep = {
                        "endpoint": coverage_path,
                        "observed_params": params,
                        "source_count": 0,
                        "observation_count": 0,
                        "cells": _empty_cells(coverage_path, endpoint_kind=kind),
                    }
                auto_hints = _endpoint_auto_hints(
                    coverage_path,
                    ep.get("observed_params") or [],
                    all_endpoints=all_seen_endpoints,
                )
                ep["endpoint"] = coverage_path
                ep["endpoint_kind"] = kind
                ep["auto_hints"] = auto_hints
                ep["source_count"] = int(ep.get("source_count", 0) or 0)
                ep["observation_count"] = int(ep.get("observation_count", 0) or 0)
                _apply_endpoint_applicability(ep, kind)
                endpoints[coverage_path] = ep
        if not page["has_more"]:
            break
        page = store.page("findings", limit=1000, cursor=page["next_cursor"])
    new_endpoints = list(endpoints.values())

    # Apply scanner_pass.json as advisory scanner-swept metadata. Broad scanner
    # negatives are not proof of absence, so they must not close coverage cells
    # as `tested_clean`; only deterministic validation runners or explicit
    # operator marks may do that.
    _apply_scanner_pass(target_key, repo, new_endpoints)
    endpoints = {ep["endpoint"]: ep for ep in new_endpoints}

    for endpoint in new_endpoints:
        endpoint.pop("weight", None)
    try:
        from tools.current_truth import current_cell_projection
    except ImportError:  # pragma: no cover - direct tools/ execution
        from current_truth import current_cell_projection
    truth = current_cell_projection(repo, target, _store=store)
    source = truth["source"]
    if (source.get("kind") != "store"
            or source.get("store_id") != store_binding["store_id"]
            or source.get("revision") != store_binding["revision"]):
        raise StoreError("primary coverage inputs changed during assembly")
    matrix["evidence_source"] = source
    matrix["evidence_health"] = truth["health"]
    matrix["closure_projection"] = truth["projection"]
    observation_ids = sorted(str(row["event_id"]) for row in truth["records"])
    matrix["source_snapshot"] = {
        "store": store_binding,
        "review_ids": sorted(
            review["id"] for ep in new_endpoints
            for review in ([ep["kind_review"]] if ep.get("kind_review") else [])
            + list((ep.get("reviews") or {}).values())
        ),
        "observation_ids": observation_ids,
        # Immutable operations bind the registered artifact digest identities.
        "operation_ids": sorted({event_id.rsplit(":", 1)[0] for event_id in observation_ids}),
        "evidence_health": truth["health"],
        "authorization_fingerprint": hashlib.sha256(json.dumps(
            truth["projection"], sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")).hexdigest(),
    }
    for record in truth["records"]:
        endpoint = _canonicalize_endpoint(str(record.get("endpoint") or ""))
        if endpoint:
            entry = _ensure_endpoint(endpoints, endpoint)
            entry["sources"] = sorted(set(entry.get("sources") or []) | {"store-observation"})
            entry["source_count"] = len(entry["sources"])
            entry["observation_count"] = int(entry.get("observation_count", 0)) + 1
            entry["observed_params"] = sorted(set(entry.get("observed_params") or []) | query_param_names(
                str(record.get("raw_endpoint") or record.get("endpoint") or "")))
    for endpoint in endpoints.values():
        # Endpoint-kind N/A defaults remain historical advice. Keep current
        # scanner metadata on open cells without promoting it to closure.
        cells = endpoint["cells"]
        for family, cell in cells.items():
            if cell.get("status") != "untested" and not is_structural_na(cell):
                endpoint.setdefault("historical_cells", {}).setdefault(family, dict(cell))
        endpoint["cells"] = {
            family: dict(cells[family])
            if cells.get(family, {}).get("status") == "untested" or is_structural_na(cells.get(family, {}))
            else {"status": "untested"}
            for family in VULN_CLASSES
        }
    # Identity-scoped v2 and exact query/hash closure stay scoped in
    # closure_projection; never widen them to the path/family grid.
    new_endpoints = list(endpoints.values())
    matrix["endpoints"] = new_endpoints
    for ep in new_endpoints:
        for family, review in ep.pop("reviews", {}).items():
            ep["cells"][family]["review"] = review
    matrix["policy_skips"] = _xss_policy_skip(repo, target_key, new_endpoints)
    matrix["source_fingerprint"] = coverage_source_fingerprint(
        target,
        repo,
    )
    if store.binding() != store_binding:
        raise StoreError("primary coverage inputs changed during assembly")
    return matrix


def _apply_scanner_pass(
    target: str,
    repo: Path,
    endpoints: list[dict],
) -> None:
    """Attach scanner-swept metadata without changing coverage status.

    Scanner output is a lead source, not a validation verdict. Keeping the cell
    `untested` prevents broad negative scans from hiding attack surface while
    still giving Claude context that a scanner lane touched the pair.
    """
    sp_path = repo / "findings" / target / "scanner_pass.json"
    if not sp_path.is_file():
        return
    try:
        payload = json.loads(sp_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    if not isinstance(payload, dict):
        return
    rows = payload.get("endpoints", [])
    if not isinstance(rows, list):
        return

    # Build {endpoint: ep_dict} index for quick lookup
    ep_index = {ep.get("endpoint"): ep for ep in endpoints}

    # Endpoint universe for route_prefix_candidate detection. Include both the
    # rebuilt matrix endpoints and scanner-only endpoints so recomputing
    # auto_hints here does not drop route-prefix hints produced during rebuild.
    all_endpoints = {str(ep.get("endpoint") or "") for ep in endpoints}
    for row in rows:
        if not isinstance(row, dict):
            continue
        canon = _canonicalize_endpoint(str(row.get("endpoint") or ""))
        if canon:
            all_endpoints.add(canon)

    scanned_at = str(payload.get("scanned_at") or "")
    scanner_version = str(payload.get("scanner_version") or "")

    for row in rows:
        if not isinstance(row, dict):
            continue
        endpoint_raw = str(row.get("endpoint") or "")
        endpoint = _canonicalize_endpoint(endpoint_raw)
        vc_raw = str(row.get("vuln_class") or "").strip()
        if not endpoint or not vc_raw:
            continue
        try:
            vc = normalize_vuln_class(vc_raw)
        except ValueError:
            # Per AC: unknown vuln_class → log warning, do not crash, leave cell untested
            print(
                f"[coverage_matrix] scanner_pass: unknown vuln_class={vc_raw!r} "
                f"(endpoint={endpoint!r}) — leaving cell untested",
                file=sys.stderr,
            )
            continue
        module = str(row.get("module") or "")
        evidence_ref = (
            f"findings/{target}/scanner_pass.json#{module}"
            if module else f"findings/{target}/scanner_pass.json"
        )

        if endpoint not in ep_index:
            # Endpoint not in matrix yet — add it so scanner-swept context is visible.
            kind = _endpoint_kind(endpoint)
            auto_hints = _endpoint_auto_hints(endpoint, all_endpoints=all_endpoints)
            new_ep = {
                "endpoint": endpoint,
                "endpoint_kind": kind,
                "auto_hints": auto_hints,
                "observed_params": [],
                "source_count": 0,
                "observation_count": 0,
                "cells": _empty_cells(endpoint, endpoint_kind=kind, auto_hints=auto_hints),
            }
            endpoints.append(new_ep)
            ep_index[endpoint] = new_ep

        ep = ep_index[endpoint]
        kind = _effective_endpoint_kind(ep, endpoint)
        ep["endpoint_kind"] = kind
        ep["auto_hints"] = _endpoint_auto_hints(
            endpoint,
            ep.get("observed_params") or [],
            all_endpoints=all_endpoints,
        )
        _apply_endpoint_applicability(ep, kind)
        cells = ep.setdefault("cells", _empty_cells(endpoint, endpoint_kind=kind))
        current = cells.get(vc, {"status": "untested"})
        cur_status = current.get("status", "untested")
        if cur_status != "untested":
            continue
        current = dict(current)
        current.setdefault("status", "untested")
        current["scanner_swept"] = True
        current["scanner_evidence_ref"] = evidence_ref
        if module:
            current["scanner_module"] = module
        current["scanner_pass"] = {
            "evidence_ref": evidence_ref,
            "scanned_at": scanned_at,
            "scanner_version": scanner_version,
        }
        cells[vc] = current


def _xss_policy_skip(repo: Path, target_key: str, endpoints: list[dict]) -> dict:
    """Expose default XSS delegation without closing its coverage cells."""
    summary_path = repo / "findings" / target_key / "summary.json"
    try:
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}
    skipped = summary.get("skipped_checks") if isinstance(summary, dict) else None
    if not isinstance(skipped, list) or not any(
        str(item).strip().lower() in {"xss", "all"} for item in skipped
    ):
        return {}
    if any(
        isinstance(endpoint, dict)
        and isinstance(endpoint.get("cells"), dict)
        and str((endpoint["cells"].get("XSS") or {}).get("status") or "untested") != "untested"
        for endpoint in endpoints
    ):
        return {}

    evidence_paths = (
        repo / "recon" / target_key / "browser" / "xhr_endpoints.txt",
        repo / "recon" / target_key / "browser" / "api_endpoints.txt",
        repo / "findings" / target_key / "js_intel" / "hypotheses.json",
    )
    evidence_markers = re.compile(
        r"\b(?:xss|dom[-_ ]?xss|reflected|innerhtml|outerhtml|insertadjacenthtml|document\.write)\b",
        re.I,
    )
    for path in evidence_paths:
        try:
            if path.is_file() and evidence_markers.search(
                path.read_text(encoding="utf-8", errors="replace")[:2_000_000]
            ):
                return {}
        except OSError:
            continue
    return {
        "XSS": {
            "status": "skipped",
            "coverage_status": "untested",
            "reason": "scanner_default_skip",
            "reactivate_when": "browser, JS, or reflection evidence appears; use full scanner or focused validation",
        }
    }


def find_high_value_gaps(
    target: str,
    repo_root: Path | str | None = None,
) -> list[dict]:
    """Return untested cells, without a path or class-value filter."""
    matrix = read_matrix(target, repo_root, current_only=True)
    gaps = high_value_gaps_from_matrix(matrix)
    return gaps


def needs_endpoint_triage(
    target: str,
    repo_root: Path | str | None = None,
    *,
    limit: int | None = None,
) -> list[dict]:
    """Return endpoints whose semantic kind still needs Claude/operator triage."""
    matrix = read_matrix(target, repo_root, current_only=True)
    items: list[dict] = []
    for ep in matrix.get("endpoints", []):
        if not isinstance(ep, dict):
            continue
        if _has_final_endpoint_kind(ep):
            continue
        endpoint = str(ep.get("endpoint") or "")
        if not endpoint:
            continue
        cells = ep.get("cells") or {}
        status_counts = {
            status: sum(1 for cell in cells.values() if isinstance(cell, dict) and cell.get("status") == status)
            for status in STATUS_VALUES
        }
        observed_params = list(ep.get("observed_params") or [])
        auto_hints = list(ep.get("auto_hints") or _endpoint_auto_hints(endpoint, observed_params))
        items.append({
            "endpoint": endpoint,
            "endpoint_kind": str(ep.get("endpoint_kind") or "untriaged"),
            "auto_hints": auto_hints,
            "observed_params": observed_params,
            "source_count": int(ep.get("source_count", 0) or 0),
            "observation_count": int(ep.get("observation_count", 0) or 0),
            "status_counts": status_counts,
        })

    items.sort(key=lambda item: str(item.get("endpoint") or ""))
    if limit is not None and limit >= 0:
        return items[:limit]
    return items


def mark_endpoint_kind(
    target: str,
    endpoint: str,
    kind: str,
    *,
    reason: str = "",
    source: str = "ai_triage",
    repo_root: Path | str | None = None,
    command_id: str | None = None,
    actor: str = "coverage-matrix",
) -> dict:
    """Persist an authored classification through the active domain owner."""
    if kind not in ENDPOINT_KIND_VALUES:
        raise ValueError(
            f"unknown endpoint kind: {kind!r}. "
            f"Valid kinds: {', '.join(ENDPOINT_KIND_VALUES)}"
        )
    if source not in FINAL_ENDPOINT_KIND_SOURCES:
        raise ValueError(
            f"unknown endpoint kind source: {source!r}. "
            f"Valid sources: {', '.join(sorted(FINAL_ENDPOINT_KIND_SOURCES))}"
        )
    repo = Path(repo_root) if repo_root else BASE_DIR
    store = runtime_store(repo, target)
    receipt = store.record_coverage_review(
        command_id=command_id if command_id is not None else f"coverage-review:{uuid.uuid4().hex}",
        endpoint=endpoint, kind="endpoint_kind", value=kind,
        reason=reason, source=source, actor=actor,
    )
    review = store.coverage_review(receipt["entity_id"])
    return {"endpoint": review["endpoint"], "endpoint_kind": review["value"],
            "kind_source": review["source"], "kind_reason": review["reason"],
            "kind_triaged_at": review["reviewed_at"], "kind_review": review, "receipt": receipt}


def mark_cell(
    target: str,
    endpoint: str,
    vuln_class: str,
    status: str,
    *,
    reason: str = "",
    repo_root: Path | str | None = None,
    write_finding: bool = False,
    command_id: str | None = None,
    actor: str = "coverage-matrix",
    source: str = "manual",
) -> dict:
    """Mark a cell. Raises ValueError on invalid vuln_class/status.

    `vuln_class` is normalised through `normalize_vuln_class()` so
    operators may pass aliases (`lfi`, `ssti`, `sql-injection`) or
    any case variant (`sqli`, `SQLI`) — the canonical name is what
    gets stored on disk.

    Primary records are advisory reviews, recovered from Store after rebuild.
    `write_finding` also saves an unassessed claim in the same transaction for
    `tested_finding`. It never creates execution evidence or closes a cell.
    """
    vuln_class = normalize_vuln_class(vuln_class)
    if status not in STATUS_VALUES:
        raise ValueError(f"unknown status: {status}")
    repo = Path(repo_root) if repo_root else BASE_DIR
    store = runtime_store(repo, target)
    path = store.coverage_endpoint(endpoint)
    candidate = None
    if write_finding and status == "tested_finding":
        finding_id = "coverage_" + hashlib.sha256(
            f"{store.target}|{path}|{vuln_class}".encode("utf-8")
        ).hexdigest()[:16]
        candidate = {
            "id": finding_id, "endpoint": target_https_url(store.target).rstrip("/") + path,
            "method": "GET", "family": vuln_class,
            "title": f"{vuln_class} finding on {path}",
            "claim": reason or f"Coverage review reports a possible {vuln_class} finding on {path}",
        }
    receipt = store.record_coverage_review(
        command_id=command_id if command_id is not None else f"coverage-review:{uuid.uuid4().hex}",
        endpoint=path, kind="cell_status", family=vuln_class, value=status,
        reason=reason, source=source, actor=actor, candidate=candidate,
    )
    return {"advisory": True, "review": store.coverage_review(receipt["entity_id"]), "receipt": receipt}


def _run_command(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Coverage matrix for (endpoint x vuln_class) state."
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_rebuild = sub.add_parser("rebuild", help="rebuild matrix from recon + findings")
    p_rebuild.add_argument("--target", required=True)
    p_rebuild.add_argument("--repo-root", default=str(BASE_DIR))
    p_rebuild.add_argument("--force-clean", action="store_true")

    p_gaps = sub.add_parser("find-gaps", help="list unresolved cells in endpoint/class order")
    p_gaps.add_argument("--target", required=True)
    p_gaps.add_argument("--repo-root", default=str(BASE_DIR))
    p_gaps.add_argument(
        "--limit",
        type=int,
        default=None,
        help="presentation limit; output includes total/truncated metadata",
    )
    p_needs_triage = sub.add_parser(
        "needs-triage",
        help="list endpoints whose kind should be decided by Claude/operator",
    )
    p_needs_triage.add_argument("--target", required=True)
    p_needs_triage.add_argument("--repo-root", default=str(BASE_DIR))
    triage_window = p_needs_triage.add_mutually_exclusive_group()
    triage_window.add_argument("--limit", type=int, default=50)
    triage_window.add_argument("--all", action="store_true", help="return every untriaged endpoint")

    p_mark_kind = sub.add_parser("mark-endpoint-kind", help="persist Claude/operator endpoint-kind triage")
    p_mark_kind.add_argument("--target", required=True)
    p_mark_kind.add_argument("--endpoint", required=True)
    p_mark_kind.add_argument("--kind", required=True, choices=list(ENDPOINT_KIND_VALUES))
    p_mark_kind.add_argument("--reason", default="")
    p_mark_kind.add_argument("--source", default="ai_triage", choices=sorted(FINAL_ENDPOINT_KIND_SOURCES))
    p_mark_kind.add_argument("--repo-root", default=str(BASE_DIR))
    p_mark_kind.add_argument("--command-id", default=None, help="stable ID for retrying one review")
    p_mark_kind.add_argument("--actor", default="coverage-matrix")

    p_mark = sub.add_parser("mark", help="mark a specific cell")
    p_mark.add_argument("--target", required=True)
    p_mark.add_argument("--endpoint", required=True)
    p_mark.add_argument("--vuln-class", required=True)
    p_mark.add_argument("--status", required=True, choices=list(STATUS_VALUES))
    p_mark.add_argument("--reason", default="")
    p_mark.add_argument("--repo-root", default=str(BASE_DIR))
    p_mark.add_argument("--command-id", default=None, help="stable ID for retrying one review")
    p_mark.add_argument("--actor", default="coverage-matrix")
    p_mark.add_argument("--source", default="manual", choices=sorted(FINAL_ENDPOINT_KIND_SOURCES))
    p_mark.add_argument(
        "--write-finding",
        action="store_true",
        help=(
            "Also record an unassessed Finding claim (only for tested_finding); "
            "review and claim commit together in Store."
        ),
    )
    p_reviews = sub.add_parser("reviews", help="read Store-authored reviews without rebuilding Coverage")
    p_reviews.add_argument("--target", required=True)
    p_reviews.add_argument("--repo-root", default=str(BASE_DIR))
    p_reviews.add_argument("--endpoint", default=None)
    p_reviews.add_argument("--history", action="store_true", help="include replaced reviews and imported history")
    selection = p_reviews.add_mutually_exclusive_group()
    selection.add_argument("--id", default=None)
    selection.add_argument("--cursor", default=None)
    p_reviews.add_argument("--limit", type=int, default=50)

    args = parser.parse_args(argv)

    if args.cmd == "reviews":
        store = runtime_store(Path(args.repo_root), args.target)
        if args.id is not None:
            result = store.coverage_review(args.id)
        else:
            result = store.coverage_review_page(endpoint=args.endpoint, latest=not args.history,
                                                limit=args.limit, cursor=args.cursor)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    if args.cmd == "rebuild":
        repo = Path(args.repo_root)
        out = _matrix_path(repo, args.target)
        reused = False
        if not args.force_clean:
            existing = load_matrix(args.target, repo)
            if matrix_is_fresh(
                args.target,
                existing,
                repo_root=repo,
            ):
                matrix = existing
                reused = True
        if not reused:
            matrix = rebuild_matrix(
                args.target,
                repo_root=repo,
                force_clean=args.force_clean,
            )
            out = save_matrix(args.target, matrix, repo)
        summary = matrix.get("summary") or _compute_summary(matrix)
        print(f"coverage_matrix {'reused' if reused else 'written'}: {out}")
        print(
            f"  endpoints={len(matrix['endpoints'])}  cells={summary['total_cells']}  "
            f"untested={summary['untested']}  "
            f"high_value_gaps={summary['high_value_gaps_count']}  "
            f"actionable_high_value_gaps={summary.get('actionable_high_value_gaps_count', 0)}"
        )
        return 0

    if args.cmd == "find-gaps":
        if args.limit is None:
            payload = find_high_value_gaps(
                args.target,
                args.repo_root,
            )
        else:
            if args.limit < 0:
                raise ValueError("--limit must be >= 0")
            matrix = read_matrix(args.target, args.repo_root, current_only=True)
            items, total = high_value_gap_window_from_matrix(
                matrix,
                limit=args.limit,
            )
            payload = {
                "target": args.target,
                "items": items,
                "total": total,
                "returned": len(items),
                "remaining": total - len(items),
                "truncated": len(items) < total,
                "limit": args.limit,
                "scope": "all",
                "order": "endpoint,vuln_class",
                "expand_command": shlex.join([
                    "python3", "tools/coverage_matrix.py", "find-gaps", "--repo-root",
                    str(Path(args.repo_root).resolve()), "--target", args.target,
                ]),
            }
        print(json.dumps(payload, indent=2))
        return 0

    if args.cmd == "needs-triage":
        if args.limit < 0:
            raise ValueError("--limit must be >= 0")
        items = needs_endpoint_triage(args.target, args.repo_root)
        total = len(items)
        if not args.all:
            items = items[:args.limit]
        print(json.dumps({
            "target": args.target,
            "total": total,
            "total_returned": len(items),
            "returned": len(items),
            "remaining": total - len(items),
            "truncated": len(items) < total,
            "order": "endpoint",
            "expand_command": shlex.join([
                "python3", "tools/coverage_matrix.py", "needs-triage", "--repo-root",
                str(Path(args.repo_root).resolve()), "--target", args.target, "--all",
            ]),
            "items": items,
        }, ensure_ascii=False, indent=2))
        return 0

    if args.cmd == "mark-endpoint-kind":
        ep = mark_endpoint_kind(
            args.target,
            args.endpoint,
            args.kind,
            reason=args.reason,
            source=args.source,
            repo_root=args.repo_root,
            command_id=args.command_id,
            actor=args.actor,
        )
        print(json.dumps(ep, ensure_ascii=False, indent=2))
        return 0

    if args.cmd == "mark":
        cell = mark_cell(
            args.target,
            args.endpoint,
            args.vuln_class,
            args.status,
            reason=args.reason,
            repo_root=args.repo_root,
            write_finding=args.write_finding,
            command_id=args.command_id,
            actor=args.actor,
            source=args.source,
        )
        print(json.dumps(cell, indent=2))
        return 0

    return 1


def main(argv: list[str] | None = None) -> int:
    try:
        return _run_command(argv)
    except (OSError, ValueError, KeyError) as exc:
        print(f"coverage matrix command failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
