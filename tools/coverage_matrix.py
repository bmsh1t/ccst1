#!/usr/bin/env python3
"""
coverage_matrix.py — (endpoint x vuln_class) coverage state for the hunt.

Purpose:
    A senior hunter does NOT finish a run while obvious high-value
    test combinations remain untouched. The coverage matrix captures
    this as state: for each endpoint × vuln class pair, the cell is
    either tested-clean, tested-with-finding, untested, or N/A. The
    Finish Condition F3 invariant (commands/autopilot.md) blocks
    `finish` while any high-weight cell remains untested without an
    N/A reason.

    This tool is NOT auto-invoked. Claude consults it via the
    Question -> Tool Reference table when its working_hypothesis
    asks "which high-value cells remain untested?".

Design notes:
    - Schema per design.md Contract 4 (Phase 3): endpoints array
      with nested cells per vuln class.
    - Only endpoints with value_weight >= 1.0 enter the matrix
      (Risk R-E: avoid bloat on huge recon outputs).
    - rebuild operates incrementally — re-runs preserve operator
      annotations (n_a reasons, etc.) unless --force-clean is set.
    - All cell values are typed enums INTERNALLY (4 statuses) but
      the cell shape is data, NOT a Claude-facing options[] menu.
      Claude reads `find-gaps` output which is just (endpoint,
      vuln_class) tuples — no "pick one of these statuses" prompt.

VULN_CLASSES taxonomy (15 entries, ordering is stable — append-only
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
      XSS      — reflected/stored/DOM; includes prototype-pollution
                 -> XSS chains where impact is JS execution
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

    Intentionally NOT in this enum (out of scope for this PR; obvious
    next candidates if the matrix grows): SSTI as its own class
    (currently subsumed under RCE), NoSQLi, OpenRedirect, Prototype
    Pollution as a primary class (currently rolled into XSS when the
    impact path is JS exec), Deserialisation (under RCE), CRLF
    injection, HTTP smuggling.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlparse

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

try:
    from tools.surface_weights import value_weight
    from tools.target_paths import canonical_target_value, target_storage_key
except ImportError:  # pragma: no cover - top-level tools/ import
    from surface_weights import value_weight  # type: ignore
    from target_paths import canonical_target_value, target_storage_key  # type: ignore

VULN_CLASSES = (
    "IDOR", "SSRF", "XSS", "Race", "Authz",
    "GraphQL", "OAuth", "Upload", "Webhook", "JWT",
    "SQLi", "XXE", "RCE", "Path", "CSRF",
)

# Operator-side aliases. The KEY is the lowercased form of an alias
# the operator might type; the VALUE is the canonical name from
# VULN_CLASSES that gets stored on disk. This is intentionally
# curated (not Levenshtein-fuzzy) so behaviour is predictable.
#
# Aliases also include the canonical names lowercased so case-folding
# alone resolves correctly without a separate code path.
VULN_CLASS_ALIASES = {
    # Case-insensitive matches for the canonical names
    **{vc.lower(): vc for vc in VULN_CLASSES},
    # Path traversal family
    "lfi": "Path",
    "rfi": "Path",
    "pathtraversal": "Path",
    "path-traversal": "Path",
    "path_traversal": "Path",
    "directory-traversal": "Path",
    "directorytraversal": "Path",
    # RCE umbrella
    "oscommand": "RCE",
    "os-command": "RCE",
    "cmdinjection": "RCE",
    "cmd-injection": "RCE",
    "commandinjection": "RCE",
    "command-injection": "RCE",
    "deser": "RCE",
    "deserialization": "RCE",
    "unserialize": "RCE",
    "ssti": "RCE",
    "template-injection": "RCE",
    "templateinjection": "RCE",
    # XSS variants
    "xss-dom": "XSS",
    "dom-xss": "XSS",
    "domxss": "XSS",
    "prototype-pollution": "XSS",
    "prototypepollution": "XSS",
    "pp": "XSS",
    # SQLi variants
    "sql-injection": "SQLi",
    "sqlinjection": "SQLi",
    "sqlblind": "SQLi",
    "sqli-blind": "SQLi",
    "sqli-time": "SQLi",
    "blindsqli": "SQLi",
    # CSRF variants
    "csrf-token": "CSRF",
    "xsrf": "CSRF",
    # XXE variants
    "xxe-blind": "XXE",
    "xml-injection": "XXE",
    "xmlinjection": "XXE",
    "xinclude": "XXE",
}


def normalize_vuln_class(name: str) -> str:
    """Resolve operator-typed vuln_class to its canonical form.

    Accepts canonical names case-insensitively and a curated alias
    set (LFI/RFI -> Path, OSCommand -> RCE, etc. — see
    `VULN_CLASS_ALIASES`). Returns the canonical name (the form
    stored on disk).

    Raises `ValueError` on unrecognised input with a message that
    lists the canonical names so the operator can pick the right one.
    """
    if name in VULN_CLASSES:
        return name
    key = name.strip().lower()
    if key in VULN_CLASS_ALIASES:
        return VULN_CLASS_ALIASES[key]
    raise ValueError(
        f"unknown vuln_class: {name!r}. "
        f"Canonical names: {', '.join(VULN_CLASSES)}. "
        f"Aliases like 'lfi'->'Path', 'ssti'->'RCE', 'sql-injection'->'SQLi' "
        f"are also accepted (case-insensitive)."
    )

STATUS_VALUES = ("tested_clean", "tested_finding", "untested", "n_a")

DEFAULT_MIN_WEIGHT = 3.0

# 用于 gaps 排序的漏洞类型基础优先级。它不是覆盖范围过滤器，只在
# endpoint/参数没有明显语义命中时做轻量 tie-break，避免默认永远从
# VULN_CLASSES 的第一个 IDOR 开始。
CLASS_IMPACT_PRIORITY = {
    "RCE": 90,
    "SQLi": 82,
    "SSRF": 80,
    "Authz": 76,
    "IDOR": 72,
    "Path": 70,
    "XXE": 68,
    "Upload": 64,
    "GraphQL": 62,
    "OAuth": 60,
    "JWT": 58,
    "Webhook": 55,
    "Race": 52,
    "XSS": 45,
    "CSRF": 40,
}


# endpoint/参数语义到漏洞类型的软关联。这里的职责是“排序和提示更准”，
# 不是把某类漏洞排除掉；未命中的 cell 仍然保留在矩阵里。
#
# 规则保持短而通用：只使用路径段和参数名，不沉淀特定目标 payload。
_RELEVANCE_RULES: tuple[tuple[str, int, re.Pattern, str], ...] = (
    ("Authz", 8, re.compile(r"\b(isadmin|is_admin|isstaff|is_staff|issuperuser|is_superuser|role|roles|permission|permissions|privilege|privileges|scope|scopes|acl|policy|owner|superadmin)\b", re.I), "privilege/role parameter"),
    ("Authz", 5, re.compile(r"/(?:admin|staff|internal|backoffice|console|manage|management)(?:/|$|\b)", re.I), "admin/internal path"),
    ("IDOR", 6, re.compile(r"\b(userid|user_id|accountid|account_id|orgid|org_id|organizationid|organization_id|tenantid|tenant_id|workspaceid|workspace_id|customerid|customer_id|memberid|member_id|orderid|order_id|invoiceid|invoice_id|objectid|object_id|ownerid|owner_id)\b", re.I), "object/tenant identifier parameter"),
    ("IDOR", 3, re.compile(r"\b(id|uid|uuid|guid|account|accounts|tenant|tenants|org|organization|workspace|customer|customers|order|orders|invoice|invoices|user|users|member|members|profile|profiles)\b", re.I), "object reference path/parameter"),
    ("SSRF", 8, re.compile(r"\b(url|uri|callback|callbackurl|callback_url|webhook|fetch|proxy|target|host|hostname|domain|remote|endpoint|imageurl|image_url|avatarurl|avatar_url|feed|oembed|importurl|import_url|sourceurl|source_url)\b", re.I), "server-side fetch candidate parameter"),
    ("SSRF", 5, re.compile(r"/(?:fetch|proxy|webhook|callback|oembed|import|integrations?)(?:/|$|\b)", re.I), "server-side fetch/webhook path"),
    ("Path", 8, re.compile(r"\b(file|filepath|file_path|filename|file_name|path|dir|directory|download|export|include|include_path|template|theme|locale|doc|document|attachment|archive)\b", re.I), "file/path selector"),
    ("Path", 6, re.compile(r"/(?:download|export|file|files|attachment|attachments|include|static|assets|preview)(?:/|$|\b)", re.I), "file download/read path"),
    ("RCE", 9, re.compile(r"\b(cmd|command|exec|execute|shell|process|template|render|ssti|deserialize|deserialise|unserialize|pickle|yaml|script|workflow|job)\b", re.I), "code/template/deserialization execution candidate"),
    ("RCE", 6, re.compile(r"/(?:render|template|preview|execute|exec|job|jobs|worker|debug)(?:/|$|\b)", re.I), "render/execution path"),
    ("XXE", 8, re.compile(r"\b(xml|soap|wsdl|saml|xinclude|xxe|doctype|docx|xlsx|svg|rss|feed)\b", re.I), "XML/parser surface"),
    ("Upload", 8, re.compile(r"\b(upload|import|file|filename|attachment|avatar|media|document|csv|xlsx|zip|archive)\b", re.I), "upload/import file surface"),
    ("GraphQL", 9, re.compile(r"\b(graphql|gql|query|mutation|operationname|operation_name|variables)\b|/graphql(?:/|$|\b)", re.I), "GraphQL operation surface"),
    ("OAuth", 8, re.compile(r"\b(oauth|oidc|saml|sso|redirecturi|redirect_uri|clientid|client_id|state|nonce|pkce|scope|callback)\b", re.I), "OAuth/OIDC/SAML flow surface"),
    ("JWT", 7, re.compile(r"\b(jwt|token|access_token|refresh_token|id_token|kid|jwks|jwk|jws|bearer|authorization)\b", re.I), "token/JWT surface"),
    ("Webhook", 8, re.compile(r"\b(webhook|hook|callback|signature|hmac|event|secret)\b|/(?:webhook|hook|callback)(?:/|$|\b)", re.I), "webhook/signature surface"),
    ("XSS", 5, re.compile(r"\b(html|content|message|comment|title|name|callback|redirect|return|next|search|q)\b", re.I), "reflection/DOM input surface"),
    ("CSRF", 5, re.compile(r"\b(csrf|xsrf|state|token|update|change|invite|delete|remove|submit)\b", re.I), "session state-change surface"),
)

# SQLi 需要把“路径段语义”和“参数名语义”分开：
# - `/address/select`、`/rest/order-history` 里的 select/order 是资源命名，
#   不是天然的查询入口，不应仅凭路径就被抬进高价值 SQLi 队列。
# - `/search?q=`、`?filter=`、`?order=` 这类参数名仍是高信号，应保持高优先级。
_SQLI_PATH_PATTERN = re.compile(
    r"/(?:search|query|filter|filters|lookup|report|reports)(?:/|$|\b)",
    re.I,
)
_SQLI_PARAM_PATTERN = re.compile(
    r"\b(q|query|search|filter|filters|sort|order|orderby|order_by|where|select|keyword|term|report|lookup|condition)\b",
    re.I,
)
_SQLI_LOOKUP_PARAM_PATTERN = re.compile(
    r"\b(id|uid|uuid|name|email|username)\b",
    re.I,
)
_RACE_ACTION_PATH_PATTERN = re.compile(
    r"/(?:checkout|payment|payments|pay|refund|refunds|redeem|transfer|transfers|withdraw|withdrawals|payout|payouts|confirm|approve|capture|charge|charges|subscribe|subscription|subscriptions)(?:/|$|\b)",
    re.I,
)
_RACE_STATE_PARAM_PATTERN = re.compile(
    r"\b(coupon|coupon_code|promo|promo_code|voucher|quantity|qty|amount|credits|credit|points|reward|rewards|balance|wallet|seat|seats|quota|limit|otp|totp|token|idempotency|idempotency_key)\b",
    re.I,
)


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
    }


def load_matrix(target: str, repo_root: Path | str | None = None) -> dict:
    """Load the matrix for a target. Returns an empty shell when absent."""
    repo = Path(repo_root) if repo_root else BASE_DIR
    path = _matrix_path(repo, target)
    if not path.is_file():
        return _empty_matrix(target)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return _empty_matrix(target)
    if not isinstance(data, dict) or "endpoints" not in data:
        return _empty_matrix(target)
    return data


def save_matrix(target: str, matrix: dict, repo_root: Path | str | None = None) -> Path:
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
    path = _matrix_path(repo, target)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(matrix, indent=2), encoding="utf-8")
    return path


def _compute_summary(matrix: dict) -> dict:
    counts = {status: 0 for status in STATUS_VALUES}
    total = 0
    high_gaps = 0
    for ep in matrix.get("endpoints", []):
        weight = float(ep.get("weight", 1.0) or 1.0)
        for cell in ep.get("cells", {}).values():
            total += 1
            status = cell.get("status", "untested")
            if status in counts:
                counts[status] += 1
            if status == "untested" and weight >= DEFAULT_MIN_WEIGHT:
                high_gaps += 1
    return {
        "total_cells": total,
        **counts,
        "high_value_gaps_count": high_gaps,
    }


def _canonicalize_endpoint(url: str) -> str:
    """Project a raw URL to a canonical endpoint key (no query string)."""
    if not url:
        return ""
    if "://" in url:
        try:
            parsed = urlparse(url)
            path = parsed.path or "/"
        except ValueError:
            return ""
    else:
        path = url
    return path.split("?", 1)[0].split("#", 1)[0]


def _split_path_query(url: str) -> tuple[str, str]:
    """Return (path, query) for full or relative URLs.

    `_canonicalize_endpoint` intentionally drops query strings so rows
    dedupe correctly. For ranking, however, parameter names are valuable
    signals (e.g. `isAdmin`, `url`, `file`, `template`), so rebuild keeps
    a small param-name summary per canonical endpoint.
    """
    if not url:
        return "", ""
    raw = url.strip()
    if "://" in raw:
        try:
            parsed = urlparse(raw)
        except ValueError:
            return "", ""
        return parsed.path or "/", parsed.query or ""
    raw = raw.split("#", 1)[0]
    if "?" not in raw:
        return raw, ""
    path, query = raw.split("?", 1)
    return path or "/", query


def _path_with_query(url: str) -> str:
    """Return relative path plus query, suitable for value/semantic scoring."""
    path, query = _split_path_query(url)
    if not path:
        return ""
    return f"{path}?{query}" if query else path


def _param_names_from_url(url: str) -> set[str]:
    """Extract query parameter names without storing parameter values."""
    _path, query = _split_path_query(url)
    if not query:
        return set()
    out: set[str] = set()
    try:
        pairs = parse_qsl(query, keep_blank_values=True)
    except ValueError:
        pairs = []
    for key, _value in pairs:
        key = str(key or "").strip()
        if key:
            out.add(key[:80])
    # parse_qsl may ignore malformed fragments; keep a conservative fallback.
    for chunk in query.split("&"):
        key = chunk.split("=", 1)[0].strip()
        if key:
            out.add(key[:80])
    return out


def _normalise_signal(value: str) -> str:
    return re.sub(r"[^a-z0-9_/-]+", " ", str(value or "").lower())


def _sqli_relevance(endpoint: str, params: list[str]) -> dict:
    """单独处理 SQLi 语义，避免路径词误伤。

    目标是保留真正的 query/search/filter surface，同时避免 `/select`
    `/order-history` 这类资源路径因为单词撞名被错误升权。
    """
    score = 0
    reasons: list[str] = []
    params_blob = _normalise_signal(" ".join(params))

    if _SQLI_PATH_PATTERN.search(str(endpoint or "")):
        score += 7
        reasons.append("query/filter/search path")
    if _SQLI_PARAM_PATTERN.search(params_blob):
        score += 7
        reasons.append("query/filter/search parameter")
    if _SQLI_LOOKUP_PARAM_PATTERN.search(params_blob):
        score += 3
        reasons.append("database-backed lookup parameter")

    return {
        "relevance_score": min(score, 20),
        "relevance_reason": "; ".join(reasons[:3]),
    }


def _race_relevance(endpoint: str, params: list[str]) -> dict:
    """单独处理 Race 语义，避免状态对象名被当成状态变更动作。

    `order-history`、`track-order`、`wallet/balance` 更像读取/查询资源；
    竞态优先级应由 checkout/refund/redeem/transfer/confirm 等动作路径，
    或 coupon/quantity/amount/quota 等状态变更参数驱动。
    """
    score = 0
    reasons: list[str] = []
    params_blob = _normalise_signal(" ".join(params))

    if _RACE_ACTION_PATH_PATTERN.search(str(endpoint or "")):
        score += 7
        reasons.append("state-transition action path")
    if _RACE_STATE_PARAM_PATTERN.search(params_blob):
        score += 5
        reasons.append("state/value-changing parameter")

    return {
        "relevance_score": min(score, 20),
        "relevance_reason": "; ".join(reasons[:3]),
    }


def class_relevance(endpoint: str, vuln_class: str, observed_params: object | None = None) -> dict:
    """Score how naturally a vuln class fits an endpoint.

    This is a soft prioritisation helper for `find-gaps` and checkpoint
    queues. A score of 0 does NOT mean N/A; it only means “no obvious
    semantic hint, still untested”.
    """
    params: list[str] = []
    if isinstance(observed_params, list):
        params = [str(item) for item in observed_params if str(item or "").strip()]
    elif isinstance(observed_params, (set, tuple)):
        params = [str(item) for item in observed_params if str(item or "").strip()]

    if vuln_class == "SQLi":
        return _sqli_relevance(endpoint, params)
    if vuln_class == "Race":
        return _race_relevance(endpoint, params)

    blob = _normalise_signal(" ".join([endpoint, *params]))
    score = 0
    reasons: list[str] = []
    for klass, points, pattern, reason in _RELEVANCE_RULES:
        if klass != vuln_class:
            continue
        if pattern.search(blob):
            score += points
            if reason not in reasons:
                reasons.append(reason)

    return {
        "relevance_score": min(score, 20),
        "relevance_reason": "; ".join(reasons[:3]),
    }


def _semantic_weight_floor(endpoint: str, observed_params: object | None = None) -> float:
    """Promote obviously high-risk semantic surfaces into high-value gaps.

    Without this, `/api/fetch?url=...` or `/search?q=...` may sit at a
    generic path weight and never reach the default high-value threshold.
    The floor is intentionally modest and only affects prioritisation.
    """
    max_relevance = 0
    for vuln_class in VULN_CLASSES:
        rel = class_relevance(endpoint, vuln_class, observed_params)
        max_relevance = max(max_relevance, int(rel.get("relevance_score", 0) or 0))
    if max_relevance >= 7:
        return DEFAULT_MIN_WEIGHT
    if max_relevance >= 5:
        return 2.0
    return 0.0


def _gap_sort_key(gap: dict) -> tuple:
    """Sort high-value gaps by semantic fit, endpoint value, and impact."""
    vuln_class = str(gap.get("vuln_class") or "")
    try:
        weight = float(gap.get("weight", 1.0) or 1.0)
    except (TypeError, ValueError):
        weight = 1.0
    try:
        relevance = int(gap.get("relevance_score", 0) or 0)
    except (TypeError, ValueError):
        relevance = 0
    impact = int(CLASS_IMPACT_PRIORITY.get(vuln_class, 0) or 0)
    class_index = VULN_CLASSES.index(vuln_class) if vuln_class in VULN_CLASSES else len(VULN_CLASSES)

    # 先把“路径/参数明显暗示的漏洞类型”排到泛化 cell 前面；同为语义命中时，
    # 再结合 endpoint 价值、命中强度和漏洞影响排序。
    semantic_bucket = 1 if relevance > 0 else 0
    effective = (weight * 5.0) + (relevance * 3.0) + (impact / 10.0)
    return (
        -semantic_bucket,
        -effective,
        -relevance,
        -weight,
        -impact,
        str(gap.get("endpoint") or ""),
        class_index,
    )


def high_value_gaps_from_matrix(matrix: dict, min_weight: float = DEFAULT_MIN_WEIGHT) -> list[dict]:
    """Return sorted untested high-value cells from an in-memory matrix."""
    gaps: list[dict] = []
    for ep in matrix.get("endpoints", []):
        if not isinstance(ep, dict):
            continue
        try:
            weight = float(ep.get("weight", 1.0) or 1.0)
        except (TypeError, ValueError):
            weight = 1.0
        if weight < min_weight:
            continue
        endpoint = str(ep.get("endpoint") or "")
        observed_params = ep.get("observed_params") or []
        for vc, cell in (ep.get("cells") or {}).items():
            if not isinstance(cell, dict) or cell.get("status") != "untested":
                continue
            gap = {
                "endpoint": endpoint,
                "vuln_class": vc,
                "weight": weight,
            }
            gap.update(class_relevance(endpoint, vc, observed_params))
            gaps.append(gap)
    gaps.sort(key=_gap_sort_key)
    return gaps


def _empty_cells() -> dict[str, dict]:
    return {vc: {"status": "untested"} for vc in VULN_CLASSES}


def _ensure_endpoint(matrix: dict, endpoint: str, weight: float) -> dict:
    """Return the endpoint entry dict; create if missing."""
    for ep in matrix.get("endpoints", []):
        if ep.get("endpoint") == endpoint:
            return ep
    new_ep = {
        "endpoint": endpoint,
        "weight": weight,
        "observed_params": [],
        "source_count": 0,
        "cells": _empty_cells(),
    }
    matrix.setdefault("endpoints", []).append(new_ep)
    return new_ep


def rebuild_matrix(
    target: str,
    repo_root: Path | str | None = None,
    *,
    force_clean: bool = False,
    min_weight_to_include: float = 1.0,
) -> dict:
    """Populate the matrix from cached recon URLs + findings.

    Two endpoint sources are scanned:
      1. recon/<target>/urls/all.txt — bulk discovery surface, gated
         by `min_weight_to_include` (default 1.0) to avoid bloat from
         marketing/CDN URLs.
      2. findings/<target>/findings.json — endpoints discovered
         through working_hypothesis exploration that may not have
         appeared in bulk recon (e.g. WordPress REST API paths,
         /wp-json/* endpoints surfaced via JS inspection). These
         endpoints are added to the matrix REGARDLESS of recon
         presence; their value_weight is computed at insertion time
         and they bypass the min_weight_to_include filter (because a
         finding by definition makes the endpoint relevant).

    For an endpoint discovered through Claude's hypothesis-driven
    workflow to land in the matrix on rebuild, it must either:
      (a) be in recon/<target>/urls/all.txt (auto-collected), OR
      (b) be referenced from findings/<target>/findings.json with
          {"endpoint": "/path", "vuln_class": "..."}.
    Operators using `mark_cell` for ad-hoc cells should ALSO append a
    matching entry to findings.json so the cell survives a rebuild.

    Operator annotations (n_a reasons) are preserved unless
    force_clean=True. Recon URLs below min_weight_to_include are
    skipped to avoid bloat (Risk R-E).
    """
    repo = Path(repo_root) if repo_root else BASE_DIR
    matrix = _empty_matrix(target) if force_clean else load_matrix(target, repo)
    if "endpoints" not in matrix:
        matrix["endpoints"] = []
    matrix["vuln_classes"] = list(VULN_CLASSES)

    # Index existing cells by endpoint for preservation
    existing = {ep.get("endpoint"): ep for ep in matrix.get("endpoints", [])}

    # Collect URLs from recon
    target_key = _storage_key(target)
    urls_dir = repo / "recon" / target_key / "urls"
    # Prefer the denoised URL set when recon produced it. Raw all.txt keeps
    # external embeds and historical third-party URLs for audit, but coverage
    # should rank the current target surface instead of converting
    # `https://third-party/player/?url=...` into a fake local `/player/` gap.
    urls_path = urls_dir / "all_filtered.txt"
    if not urls_path.is_file():
        urls_path = urls_dir / "all.txt"
    urls: list[str] = []
    if urls_path.is_file():
        try:
            urls = [
                line.strip()
                for line in urls_path.read_text(encoding="utf-8", errors="ignore").splitlines()
                if line.strip()
            ]
        except OSError:
            urls = []

    # Build endpoint set with weights and lightweight param-name signals.
    # The canonical matrix key remains path-only, but the sorting layer can
    # now distinguish `/api/admin/users?isAdmin=true` from a generic users
    # endpoint and avoid always proposing IDOR first.
    seen: dict[str, dict] = {}
    for raw in urls:
        path = _canonicalize_endpoint(raw)
        if not path:
            continue
        params = _param_names_from_url(raw)
        path_query = _path_with_query(raw) or path
        weight = max(value_weight(path), value_weight(path_query))
        meta = seen.setdefault(path, {
            "weight": 0.0,
            "params": set(),
            "source_count": 0,
        })
        meta["weight"] = max(float(meta.get("weight", 0.0) or 0.0), weight)
        meta["params"].update(params)
        meta["source_count"] = int(meta.get("source_count", 0) or 0) + 1

    # Apply a small semantic weight floor after all params for an endpoint
    # have been merged. This lets high-risk query surfaces participate in
    # the high-value queue even when their path alone is generic.
    filtered_seen: dict[str, dict] = {}
    for endpoint, meta in seen.items():
        params = sorted(meta.get("params") or [])
        weight = max(
            float(meta.get("weight", 1.0) or 1.0),
            _semantic_weight_floor(endpoint, params),
        )
        if weight < min_weight_to_include:
            continue
        filtered_seen[endpoint] = {
            "weight": weight,
            "params": params,
            "source_count": int(meta.get("source_count", 0) or 0),
        }

    # Merge: keep existing cells, add new endpoints with untested cells
    new_endpoints: list[dict] = []
    for endpoint, meta in filtered_seen.items():
        weight = float(meta.get("weight", 1.0) or 1.0)
        if endpoint in existing:
            ep = existing[endpoint]
            ep["weight"] = max(float(ep.get("weight", weight) or weight), weight)
            ep["observed_params"] = sorted(set(ep.get("observed_params") or []) | set(meta.get("params") or []))
            ep["source_count"] = max(int(ep.get("source_count", 0) or 0), int(meta.get("source_count", 0) or 0))
            cells = ep.get("cells") or {}
            for vc in VULN_CLASSES:
                cells.setdefault(vc, {"status": "untested"})
            ep["cells"] = cells
            new_endpoints.append(ep)
        else:
            new_endpoints.append({
                "endpoint": endpoint,
                "weight": weight,
                "observed_params": list(meta.get("params") or []),
                "source_count": int(meta.get("source_count", 0) or 0),
                "cells": _empty_cells(),
            })

    # Apply findings: mark cells as tested_finding
    findings_path = repo / "findings" / target_key / "findings.json"
    if findings_path.is_file():
        try:
            findings = json.loads(findings_path.read_text(encoding="utf-8"))
            if isinstance(findings, dict):
                findings = findings.get("findings", [])
            for finding in findings or []:
                raw_endpoint = str(finding.get("endpoint") or finding.get("url") or "")
                ep_path = _canonicalize_endpoint(raw_endpoint)
                params = sorted(_param_names_from_url(raw_endpoint))
                vc = str(finding.get("vuln_class") or finding.get("class") or "").strip()
                if not ep_path or vc not in VULN_CLASSES:
                    continue
                # ensure endpoint exists in matrix even if recon missed it
                for ep in new_endpoints:
                    if ep["endpoint"] == ep_path:
                        ep["observed_params"] = sorted(set(ep.get("observed_params") or []) | set(params))
                        ep["weight"] = max(
                            float(ep.get("weight", value_weight(ep_path)) or value_weight(ep_path)),
                            _semantic_weight_floor(ep_path, ep.get("observed_params") or []),
                        )
                        ep["cells"][vc] = {
                            "status": "tested_finding",
                            "evidence_ref": f"findings/{target_key}/findings.json#{finding.get('id', '')}",
                        }
                        break
                else:
                    ep = {
                        "endpoint": ep_path,
                        "weight": max(value_weight(ep_path), _semantic_weight_floor(ep_path, params)),
                        "observed_params": params,
                        "source_count": 0,
                        "cells": _empty_cells(),
                    }
                    ep["cells"][vc] = {
                        "status": "tested_finding",
                        "evidence_ref": f"findings/{target_key}/findings.json#{finding.get('id', '')}",
                    }
                    new_endpoints.append(ep)
        except (OSError, json.JSONDecodeError):
            pass

    # Apply scanner_pass.json: mark cells `tested_clean` only when scanner
    # exercised them and no higher-precedence status (tested_finding > n_a)
    # already applies. Per task 05-16-b4-scanner-matrix-feedback (R2/R3).
    _apply_scanner_pass(target_key, repo, new_endpoints)

    matrix["endpoints"] = new_endpoints
    return matrix


def _apply_scanner_pass(
    target: str,
    repo: Path,
    endpoints: list[dict],
) -> None:
    """Mark cells tested_clean when scanner_pass.json says the scanner
    exercised (endpoint, vuln_class) but the cell is still untested.

    Cell-state precedence (highest to lowest):
        tested_finding > tested_clean > n_a > untested
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

        if endpoint not in ep_index:
            # Endpoint not in matrix yet — add it so the tested_clean mark survives
            new_ep = {
                "endpoint": endpoint,
                "weight": value_weight(endpoint),
                "observed_params": [],
                "source_count": 0,
                "cells": _empty_cells(),
            }
            endpoints.append(new_ep)
            ep_index[endpoint] = new_ep

        ep = ep_index[endpoint]
        cells = ep.setdefault("cells", _empty_cells())
        current = cells.get(vc, {"status": "untested"})
        cur_status = current.get("status", "untested")
        # Precedence: tested_finding and n_a stay; otherwise upgrade to tested_clean
        if cur_status in ("tested_finding", "n_a"):
            continue
        cells[vc] = {
            "status": "tested_clean",
            "evidence_ref": (
                f"findings/{target}/scanner_pass.json#{module}"
                if module else f"findings/{target}/scanner_pass.json"
            ),
            "scanned_at": scanned_at,
            "scanner_version": scanner_version,
        }


def find_high_value_gaps(
    target: str,
    repo_root: Path | str | None = None,
    min_weight: float = DEFAULT_MIN_WEIGHT,
) -> list[dict]:
    """Return (endpoint, vuln_class) cells with status=untested AND weight >= min_weight."""
    matrix = load_matrix(target, repo_root)
    return high_value_gaps_from_matrix(matrix, min_weight=min_weight)


def mark_cell(
    target: str,
    endpoint: str,
    vuln_class: str,
    status: str,
    *,
    reason: str = "",
    repo_root: Path | str | None = None,
    write_finding: bool = False,
) -> dict:
    """Mark a cell. Raises ValueError on invalid vuln_class/status.

    `vuln_class` is normalised through `normalize_vuln_class()` so
    operators may pass aliases (`lfi`, `ssti`, `sql-injection`) or
    any case variant (`sqli`, `SQLI`) — the canonical name is what
    gets stored on disk.

    When `write_finding=True` AND status indicates a finding
    (`tested_finding`), append a matching entry to
    `findings/<target>/findings.json`. This keeps the cell durable
    across `rebuild_matrix` re-runs: without the findings.json entry,
    a `force_clean` rebuild that the endpoint is not in recon would
    drop the cell.
    """
    vuln_class = normalize_vuln_class(vuln_class)
    if status not in STATUS_VALUES:
        raise ValueError(f"unknown status: {status}")
    matrix = load_matrix(target, repo_root)
    endpoint = _canonicalize_endpoint(endpoint)
    weight = value_weight(endpoint)
    ep = _ensure_endpoint(matrix, endpoint, weight)
    cell = {"status": status}
    if reason:
        cell["reason"] = reason
    ep["cells"][vuln_class] = cell
    save_matrix(target, matrix, repo_root)

    if write_finding and status == "tested_finding":
        _append_finding(target, endpoint, vuln_class, reason, repo_root)

    return cell


def _append_finding(
    target: str,
    endpoint: str,
    vuln_class: str,
    reason: str,
    repo_root: Path | str | None = None,
) -> None:
    """Append an entry to findings/<target>/findings.json so the cell
    survives a future `rebuild_matrix` call. Generates a stable id
    from (endpoint, vuln_class). Idempotent — duplicate entries are
    skipped on the (endpoint, vuln_class) key.
    """
    repo = Path(repo_root) if repo_root else BASE_DIR
    target_key = _storage_key(target)
    findings_dir = repo / "findings" / target_key
    findings_dir.mkdir(parents=True, exist_ok=True)
    findings_path = findings_dir / "findings.json"

    existing: list[dict] = []
    if findings_path.is_file():
        try:
            data = json.loads(findings_path.read_text(encoding="utf-8"))
            if isinstance(data, list):
                existing = data
            elif isinstance(data, dict):
                existing = list(data.get("findings", []))
        except (OSError, json.JSONDecodeError):
            existing = []

    finding_id = f"M-{vuln_class}-{abs(hash(endpoint)) % 10_000_000}"
    for item in existing:
        if (item.get("endpoint") == endpoint
                and item.get("vuln_class") == vuln_class):
            return  # idempotent

    existing.append({
        "id": finding_id,
        "endpoint": endpoint,
        "vuln_class": vuln_class,
        "reason": reason,
        "source": "mark_cell",
    })
    findings_path.write_text(json.dumps(existing, indent=2), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Coverage matrix for (endpoint x vuln_class) state."
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_rebuild = sub.add_parser("rebuild", help="rebuild matrix from recon + findings")
    p_rebuild.add_argument("--target", required=True)
    p_rebuild.add_argument("--repo-root", default=str(BASE_DIR))
    p_rebuild.add_argument("--force-clean", action="store_true")
    p_rebuild.add_argument("--min-weight-to-include", type=float, default=1.0)

    p_gaps = sub.add_parser("find-gaps", help="list high-value untested cells")
    p_gaps.add_argument("--target", required=True)
    p_gaps.add_argument("--repo-root", default=str(BASE_DIR))
    p_gaps.add_argument("--min-weight", type=float, default=DEFAULT_MIN_WEIGHT)

    p_mark = sub.add_parser("mark", help="mark a specific cell")
    p_mark.add_argument("--target", required=True)
    p_mark.add_argument("--endpoint", required=True)
    p_mark.add_argument("--vuln-class", required=True)
    p_mark.add_argument("--status", required=True, choices=list(STATUS_VALUES))
    p_mark.add_argument("--reason", default="")
    p_mark.add_argument("--repo-root", default=str(BASE_DIR))
    p_mark.add_argument(
        "--write-finding",
        action="store_true",
        help=(
            "Also append an entry to findings/<target>/findings.json so "
            "the cell survives `rebuild` (only takes effect when "
            "--status tested_finding)."
        ),
    )

    args = parser.parse_args(argv)

    if args.cmd == "rebuild":
        matrix = rebuild_matrix(
            args.target,
            repo_root=args.repo_root,
            force_clean=args.force_clean,
            min_weight_to_include=args.min_weight_to_include,
        )
        out = save_matrix(args.target, matrix, args.repo_root)
        summary = matrix["summary"]
        print(f"coverage_matrix written: {out}")
        print(
            f"  endpoints={len(matrix['endpoints'])}  cells={summary['total_cells']}  "
            f"untested={summary['untested']}  high_value_gaps={summary['high_value_gaps_count']}"
        )
        return 0

    if args.cmd == "find-gaps":
        gaps = find_high_value_gaps(args.target, args.repo_root, args.min_weight)
        print(json.dumps(gaps, indent=2))
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
        )
        print(json.dumps(cell, indent=2))
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
