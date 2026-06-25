#!/usr/bin/env python3
"""为 Claude CLI 装配当前目标的最小高信号上下文包。

Context Pack 是只读导航层：它收敛 Claude 本轮应该加载的目标、Skill、
知识卡和检查规则，同时给出发散假设与相邻角度。它不扫描目标、不写目标
记忆、不自动修改知识库或 Skill。
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

BASE_DIR = Path(__file__).resolve().parents[1]
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

try:
    from memory.target_profile import default_memory_dir
    from tools.coverage_matrix import find_high_value_gaps, load_matrix
    from tools.evidence_ledger import build_summary as build_evidence_summary
    from tools.surface import load_surface_context, rank_surface
    from tools.target_paths import canonical_target_value, target_storage_key
except ImportError:  # pragma: no cover - direct tools/ execution
    from memory.target_profile import default_memory_dir
    from coverage_matrix import find_high_value_gaps, load_matrix  # type: ignore
    from evidence_ledger import build_summary as build_evidence_summary  # type: ignore
    from surface import load_surface_context, rank_surface  # type: ignore
    from target_paths import canonical_target_value, target_storage_key  # type: ignore


SKILL_PATHS = {
    "bb-methodology": "skills/bb-methodology/SKILL.md",
    "bug-bounty": "skills/bug-bounty/SKILL.md",
    "triage-validation": "skills/triage-validation/SKILL.md",
    "web2-recon": "skills/web2-recon/SKILL.md",
    "web2-vuln-classes": "skills/web2-vuln-classes/SKILL.md",
}

KNOWN_SKILL_OR_FOCUS = {
    *SKILL_PATHS.keys(),
    "api",
    "idor",
    "api-idor",
    "auth",
    "auth-hidden",
    "authz",
    "hidden-login",
    "login-bypass",
    "ato",
    "missing-param",
    "parameter-null",
    "param-discovery",
    "api-docs",
    "path-pattern",
    "management-exposure",
    "admin-panel",
    "monitoring-console",
    "druid",
    "actuator",
    "secret-leak",
    "graphql",
    "sqli",
    "sql-injection",
    "hidden-param",
    "ssrf",
    "url-fetch",
    "webhook",
    "upload",
    "import",
    "parser",
    "race",
    "candidate",
    "validate",
    "validation",
    "coverage",
    "dead-end",
}

CARD_PATHS = {
    "api-idor": "knowledge/cards/api-idor.md",
    "auth-access": "knowledge/cards/auth-access.md",
    "auth-hidden-switches": "knowledge/cards/auth-hidden-switches.md",
    "missing-parameter-discovery": "knowledge/cards/missing-parameter-discovery.md",
    "path-pattern-management-exposure": "knowledge/cards/path-pattern-management-exposure.md",
    "ssrf-url-fetch": "knowledge/cards/ssrf-url-fetch.md",
    "graphql": "knowledge/cards/graphql.md",
    "sqli-hidden-surfaces": "knowledge/cards/sqli-hidden-surfaces.md",
    "upload-parser": "knowledge/cards/upload-parser.md",
    "race-conditions": "knowledge/cards/race-conditions.md",
    "coverage-prompts": "knowledge/cards/coverage-prompts.md",
    "dead-ends": "knowledge/cards/dead-ends.md",
}

TOKEN_TO_CARDS = (
    (
        re.compile(
            r"\b(missing[-_ ]?param(?:eter)?|parameter[-_ ]?null|parameter is null|required[-_ ]?param(?:eter)?|param[-_ ]?discovery|arjun|api[-_ ]?docs|v3/api-docs|swagger|openapi)\b",
            re.I,
        ),
        ("missing-parameter-discovery",),
    ),
    (
        re.compile(
            r"\b(path[-_ ]?pattern|directory[-_ ]?fuzz(?:ing)?|dirsearch|admin[-_ ]?panel|management[-_ ]?exposure|management[-_ ]?console|monitoring[-_ ]?console|druid|weburi|actuator|spring[-_ ]?boot[-_ ]?admin|grafana|kibana|nacos|consul|jenkins|accesskey|secretkey|secret[-_ ]?leak)\b",
            re.I,
        ),
        ("path-pattern-management-exposure",),
    ),
    (
        re.compile(r"\b(graphql|gql|mutation|subscription|introspection|global[_-]?id)\b", re.I),
        ("graphql",),
    ),
    (
        re.compile(
            r"\b(sqli|sql[-_ ]?injection|hidden[-_ ]?param|x[-_ ]?forwarded[-_ ]?for|x[-_ ]?real[-_ ]?ip|path[-_ ]?segment)\b",
            re.I,
        ),
        ("sqli-hidden-surfaces",),
    ),
    (
        re.compile(r"\b(upload|import|parser|parse|preview|convert|csv|pdf|xlsx|avatar|attachment)\b", re.I),
        ("upload-parser",),
    ),
    (
        re.compile(r"\b(ssrf|url[-_ ]?fetch|webhook|callback|oembed|fetch_url|remote_url)\b", re.I),
        ("ssrf-url-fetch",),
    ),
    (
        re.compile(r"\b(race|concurrent|parallel|quota|otp|totp|payment|billing|refund|coupon|wallet|cart|checkout)\b", re.I),
        ("race-conditions",),
    ),
    (
        re.compile(r"\b(auth|authz|rbac|role|session|sso|oauth|oidc|admin|member|workspace)\b", re.I),
        ("auth-access", "api-idor"),
    ),
    (
        re.compile(
            r"\b(auth[-_ ]?hidden|hidden[-_ ]?login|login[-_ ]?bypass|account[-_ ]?takeover|ato|username[-_ ]?enum|soap|ldap)\b",
            re.I,
        ),
        ("auth-hidden-switches", "auth-access"),
    ),
    (
        re.compile(r"\b(idor|tenant|org|organization|account|user_id|account_id|org_id|tenant_id|order_id|invoice|export|download|report|object)\b", re.I),
        ("api-idor", "auth-access"),
    ),
)


def _read_json_object(path: Path) -> dict:
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _read_json_any(path: Path) -> object:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _read_lines(path: Path, limit: int = 50) -> list[str]:
    if not path.is_file():
        return []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    return _dedupe([line.strip() for line in lines if line.strip()])[:limit]


def _read_jsonl_objects(path: Path, limit: int = 50) -> list[dict]:
    if not path.is_file():
        return []
    items: list[dict] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    for line in lines:
        value = line.strip()
        if not value:
            continue
        try:
            item = json.loads(value)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            items.append(item)
        if len(items) >= limit:
            break
    return items


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        value = str(item or "").strip()
        if not value or value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def _display(path: Path, repo_root: Path) -> str:
    try:
        return str(path.relative_to(repo_root))
    except ValueError:
        return str(path)


def _entry_text(item: object) -> str:
    if isinstance(item, dict):
        return str(item.get("text") or item.get("summary") or item.get("title") or "").strip()
    return str(item or "").strip()


def _json_list(items: object) -> list[dict]:
    out: list[dict] = []
    if not isinstance(items, list):
        return out
    for item in items:
        if isinstance(item, str):
            try:
                item = json.loads(item)
            except json.JSONDecodeError:
                item = {"title": item}
        if isinstance(item, dict):
            out.append(item)
    return out


def _looks_like_target(value: str) -> bool:
    value = value.strip()
    if not value:
        return False
    if value in KNOWN_SKILL_OR_FOCUS:
        return False
    if "://" in value:
        return True
    if "/" in value and not value.startswith("/"):
        return True
    if ":" in value and not value.startswith("http"):
        return True
    return "." in value


def _resolve_cli_args(args: argparse.Namespace, repo_root: Path) -> tuple[str, str]:
    positional = list(args.args or [])
    target = args.target or ""
    focus_parts: list[str] = []

    if target:
        focus_parts.extend(positional)
    elif positional and _looks_like_target(positional[0]):
        target = positional[0]
        focus_parts.extend(positional[1:])
    else:
        focus_parts.extend(positional)

    if args.focus:
        focus_parts.append(args.focus)

    if not target:
        active = _read_json_object(repo_root / "memory" / "goals" / "active.json")
        target = str(active.get("target") or "").strip()
    if not target:
        raise SystemExit(
            "No target resolved. Use --target target.com or set active target with "
            "`python3 tools/target_memory.py set <target>`."
        )

    return canonical_target_value(target), " ".join(focus_parts).strip()


def _load_goal_memory(repo_root: Path, target: str) -> dict:
    target_key = target_storage_key(target)
    active_path = repo_root / "memory" / "goals" / "active.json"
    target_path = repo_root / "memory" / "goals" / "targets" / f"{target_key}.json"
    active = _read_json_object(active_path)
    target_memory = _read_json_object(target_path)
    active_target = canonical_target_value(str(active.get("target") or ""))
    return {
        "active": active if active_target == target else {},
        "raw_active": active,
        "target": target_memory,
        "active_matches": bool(active_target and active_target == target),
        "active_path": _display(active_path, repo_root),
        "target_path": _display(target_path, repo_root),
    }


def _load_findings(repo_root: Path, target_key: str) -> list[dict]:
    payload = _read_json_any(repo_root / "findings" / target_key / "findings.json")
    if isinstance(payload, dict):
        payload = payload.get("findings", [])
    if not isinstance(payload, list):
        return []
    return [item for item in payload if isinstance(item, dict)]


def _artifact_path(path: Path, repo_root: Path) -> str:
    return _display(path, repo_root) if path.is_file() else ""


def _load_local_intel(repo_root: Path, target_key: str) -> dict:
    """读取小型浏览器/JS/source 证据索引；不触发扫描或浏览器动作。"""
    browser_dir = repo_root / "recon" / target_key / "browser"
    js_dir = repo_root / "findings" / target_key / "js_intel"
    source_dir = repo_root / "findings" / target_key / "source_intel"

    forms_payload = _read_json_any(browser_dir / "forms.json")
    forms = []
    if isinstance(forms_payload, dict) and isinstance(forms_payload.get("forms"), list):
        forms = [item for item in forms_payload["forms"] if isinstance(item, dict)]

    page_js_map = _read_json_object(browser_dir / "page_js_map.json")
    pages = page_js_map.get("pages") if isinstance(page_js_map.get("pages"), dict) else {}
    js_index = page_js_map.get("js_index") if isinstance(page_js_map.get("js_index"), dict) else {}

    js_payload = _read_json_object(js_dir / "hypotheses.json")
    js_endpoints = [
        item for item in js_payload.get("endpoints", [])
        if isinstance(item, dict) and item.get("path")
    ]
    js_leads = js_payload.get("attack_surface_leads", js_payload.get("ranked_leads", []))
    js_leads = [item for item in js_leads if isinstance(item, dict)]
    js_graphql = [
        item for item in js_payload.get("graphql_operations", [])
        if isinstance(item, dict)
    ]

    source_routes_payload = _read_json_object(source_dir / "routes.json")
    source_routes = [
        item for item in source_routes_payload.get("routes", [])
        if isinstance(item, dict) and item.get("route")
    ]
    source_graphql = [
        item for item in source_routes_payload.get("graphql_operations", [])
        if isinstance(item, dict)
    ]
    source_hypotheses = _read_jsonl_objects(source_dir / "hypotheses.jsonl", limit=50)

    return {
        "browser": {
            "summary": _read_json_object(browser_dir / "summary.json"),
            "xhr_endpoints": _read_lines(browser_dir / "xhr_endpoints.txt"),
            "api_endpoints": _read_lines(browser_dir / "api_endpoints.txt"),
            "params": _read_lines(browser_dir / "browser_params.txt"),
            "forms": forms,
            "page_count": len(pages),
            "js_file_count": len(js_index),
            "paths": _dedupe([
                _artifact_path(browser_dir / "xhr_endpoints.txt", repo_root),
                _artifact_path(browser_dir / "api_endpoints.txt", repo_root),
                _artifact_path(browser_dir / "browser_params.txt", repo_root),
                _artifact_path(browser_dir / "page_js_map.json", repo_root),
                _artifact_path(browser_dir / "summary.json", repo_root),
            ]),
        },
        "js_intel": {
            "endpoints": js_endpoints,
            "leads": js_leads,
            "graphql_operations": js_graphql,
            "paths": _dedupe([
                _artifact_path(js_dir / "hypotheses.json", repo_root),
                _artifact_path(js_dir / "materials_summary.md", repo_root),
            ]),
        },
        "source_intel": {
            "hypotheses": source_hypotheses,
            "routes": source_routes,
            "graphql_operations": source_graphql,
            "paths": _dedupe([
                _artifact_path(source_dir / "hypotheses.jsonl", repo_root),
                _artifact_path(source_dir / "routes.json", repo_root),
                _artifact_path(source_dir / "summary.md", repo_root),
            ]),
        },
    }


def _finding_is_candidate(finding: dict) -> bool:
    status_blob = " ".join(
        str(finding.get(key) or "")
        for key in ("status", "validation_status", "report_status", "state")
    ).lower()
    if any(token in status_blob for token in ("candidate", "pending", "unvalidated", "needs_validation")):
        return True
    if any(token in status_blob for token in ("validated", "submitted", "rejected", "false_positive")):
        return False
    return bool(finding.get("id") or finding.get("type") or finding.get("endpoint") or finding.get("url"))


def _finding_anchor(finding: dict) -> str:
    label = str(finding.get("id") or finding.get("type") or finding.get("title") or "finding").strip()
    vuln = str(finding.get("vuln_class") or finding.get("class") or finding.get("category") or "").strip()
    endpoint = str(finding.get("endpoint") or finding.get("url") or "").strip()
    status = str(finding.get("validation_status") or finding.get("report_status") or finding.get("status") or "").strip()
    parts = [label]
    if vuln:
        parts.append(f"[{vuln}]")
    if endpoint:
        parts.append(f"-> {endpoint}")
    if status:
        parts.append(f"status={status}")
    return " ".join(parts)


def _safe_find_gaps(target: str, target_key: str, repo_root: Path) -> tuple[list[dict], dict]:
    gaps = find_high_value_gaps(target, repo_root=repo_root)
    matrix = load_matrix(target, repo_root=repo_root)
    if not gaps and target_key != target:
        key_gaps = find_high_value_gaps(target_key, repo_root=repo_root)
        key_matrix = load_matrix(target_key, repo_root=repo_root)
        if key_gaps or key_matrix.get("summary", {}).get("total_cells", 0):
            return key_gaps, key_matrix
    return gaps, matrix


def _surface_state(repo_root: Path, target: str, memory_dir: str | None) -> dict:
    resolved_memory_dir = memory_dir or str(default_memory_dir(repo_root))
    context = load_surface_context(
        repo_root,
        target,
        memory_dir=resolved_memory_dir,
        write_probe_log=False,
    )
    return rank_surface(context)


def _local_intel_blob(local_intel: dict) -> list[str]:
    pieces: list[str] = []
    browser = local_intel.get("browser") or {}
    pieces.extend(browser.get("xhr_endpoints") or [])
    pieces.extend(browser.get("api_endpoints") or [])
    pieces.extend(browser.get("params") or [])
    for form in (browser.get("forms") or [])[:5]:
        pieces.append(f"{form.get('method', '')} {form.get('action', '')}")

    js_intel = local_intel.get("js_intel") or {}
    for endpoint in (js_intel.get("endpoints") or [])[:10]:
        pieces.extend([
            str(endpoint.get("method") or ""),
            str(endpoint.get("path") or ""),
            str(endpoint.get("evidence") or ""),
            str(endpoint.get("auth_required") or ""),
        ])
    for lead in (js_intel.get("leads") or [])[:5]:
        pieces.extend([
            str(lead.get("title") or ""),
            str(lead.get("category") or ""),
            str(lead.get("next_action") or ""),
        ])
    for operation in (js_intel.get("graphql_operations") or [])[:5]:
        pieces.extend([
            str(operation.get("name") or ""),
            str(operation.get("type") or operation.get("operation") or ""),
        ])

    source_intel = local_intel.get("source_intel") or {}
    for hypothesis in (source_intel.get("hypotheses") or [])[:10]:
        pieces.extend([
            str(hypothesis.get("type") or ""),
            str(hypothesis.get("candidate") or ""),
            str(hypothesis.get("reason") or ""),
        ])
    for route in (source_intel.get("routes") or [])[:10]:
        pieces.extend([
            str(route.get("method") or ""),
            str(route.get("route") or ""),
        ])
    for operation in (source_intel.get("graphql_operations") or [])[:5]:
        pieces.extend([
            str(operation.get("name") or ""),
            str(operation.get("operation") or ""),
        ])
    return [piece for piece in pieces if str(piece).strip()]


def _text_blob(
    focus: str,
    goal_memory: dict,
    ranked: dict,
    gaps: list[dict],
    findings: list[dict],
    local_intel: dict,
) -> str:
    pieces: list[str] = [focus]
    active = goal_memory.get("active") or {}
    target_memory = goal_memory.get("target") or {}
    for key in ("active_goal", "current_hypothesis", "phase", "mode"):
        pieces.append(str(active.get(key) or target_memory.get(key) or ""))
    for field in ("active_leads", "next_actions", "dead_ends", "useful_patterns"):
        for item in (target_memory.get(field) or [])[-5:]:
            pieces.append(_entry_text(item))
    for item in ranked.get("p1", [])[:5] + ranked.get("p2", [])[:3]:
        pieces.extend([
            str(item.get("url") or ""),
            str(item.get("path") or ""),
            " ".join(str(reason) for reason in item.get("reasons", [])[:3]),
            str(item.get("suggested") or ""),
        ])
    for lead in _json_list(ranked.get("workflow_leads"))[:5]:
        pieces.extend([
            str(lead.get("title") or ""),
            str(lead.get("category") or ""),
            str(lead.get("next_action") or ""),
            str(lead.get("rationale") or ""),
        ])
    for gap in gaps[:8]:
        pieces.append(f"{gap.get('endpoint')} {gap.get('vuln_class')}")
    for finding in findings[:5]:
        pieces.append(_finding_anchor(finding))
    pieces.extend(_local_intel_blob(local_intel))
    return "\n".join(piece for piece in pieces if piece)


def _select_skill(focus: str, blob: str, ranked: dict, findings: list[dict], goal_memory: dict) -> tuple[str, str]:
    focus_l = focus.lower()
    blob_l = blob.lower()
    target_memory = goal_memory.get("target") or {}
    selected = [
        str(item).strip()
        for item in (
            (goal_memory.get("active") or {}).get("selected_skills")
            or target_memory.get("selected_skills")
            or []
        )
        if str(item).strip()
    ]
    has_candidate = any(_finding_is_candidate(item) for item in findings)

    if "triage-validation" in focus_l or re.search(r"\b(validate|validation|candidate)\b", blob_l) or has_candidate:
        return "triage-validation", "已有 candidate / validation 信号，本轮优先把候选证据过验证门。"
    if "web2-recon" in focus_l or "recon" == focus_l.strip():
        return "web2-recon", "用户 focus 指向 recon，需要先补攻击面输入再进入漏洞验证。"
    if "web2-vuln-classes" in focus_l:
        return "web2-vuln-classes", "用户 focus 指向 Web2 漏洞类别验证。"
    if not ranked.get("available"):
        return "web2-recon", "本地 recon/surface 缓存不足，先补最小攻击面上下文。"
    if selected:
        for item in selected:
            if item in SKILL_PATHS:
                return item, "目标记忆层已记录该 Skill，沿用当前目标上下文。"
    if re.search(r"\b(dead[-_ ]?end|stuck|no progress|plateau)\b", blob_l):
        return "bb-methodology", "目标记忆显示方向可能卡住，先用方法论 Skill 重定向。"
    if ranked.get("p1") or ranked.get("p2") or re.search(
        r"\b(idor|auth|graphql|sqli|sql[-_ ]?injection|ssrf|upload|race|webhook|api|tenant|org|admin|missing[-_ ]?param(?:eter)?|parameter[-_ ]?null|param[-_ ]?discovery|arjun|api[-_ ]?docs|swagger|openapi|path[-_ ]?pattern|directory[-_ ]?fuzz(?:ing)?|dirsearch|admin[-_ ]?panel|management[-_ ]?exposure|management[-_ ]?console|monitoring[-_ ]?console|druid|weburi|actuator|accesskey|secretkey|secret[-_ ]?leak)\b",
        blob_l,
    ):
        return "web2-vuln-classes", "已有可测试的 Web/API surface 或漏洞类别信号。"
    return "bb-methodology", "缺少明确类别信号，先做阶段判断和路线收敛。"


def _cards_from_focus(focus: str) -> list[str]:
    focus_l = focus.lower()
    cards: list[str] = []
    if "graphql" in focus_l:
        cards.append("graphql")
    if (
        "missing-param" in focus_l
        or "parameter-null" in focus_l
        or "param-discovery" in focus_l
        or "api-docs" in focus_l
        or "arjun" in focus_l
    ):
        cards.append("missing-parameter-discovery")
    if (
        "path-pattern" in focus_l
        or "management-exposure" in focus_l
        or "admin-panel" in focus_l
        or "monitoring-console" in focus_l
        or "druid" in focus_l
        or "actuator" in focus_l
        or "secret-leak" in focus_l
    ):
        cards.append("path-pattern-management-exposure")
    if "sqli" in focus_l or "sql-injection" in focus_l or "hidden-param" in focus_l:
        cards.append("sqli-hidden-surfaces")
    if "api-idor" in focus_l or "idor" in focus_l:
        cards.extend(["api-idor", "auth-access"])
    if (
        "auth-hidden" in focus_l
        or "hidden-login" in focus_l
        or "login-bypass" in focus_l
        or "ato" in focus_l
    ):
        cards.extend(["auth-hidden-switches", "auth-access"])
    if "auth" in focus_l:
        cards.extend(["auth-access", "api-idor"])
    if "ssrf" in focus_l or "url-fetch" in focus_l or "webhook" in focus_l:
        cards.append("ssrf-url-fetch")
    if "upload" in focus_l or "import" in focus_l or "parser" in focus_l:
        cards.append("upload-parser")
    if "race" in focus_l:
        cards.append("race-conditions")
    return _dedupe(cards)


def _select_cards(
    blob: str,
    skill: str,
    ranked: dict,
    gaps: list[dict],
    goal_memory: dict,
    focus: str,
) -> list[str]:
    cards: list[str] = _cards_from_focus(focus)
    for pattern, names in TOKEN_TO_CARDS:
        if pattern.search(blob):
            cards.extend(names)
    target_memory = goal_memory.get("target") or {}
    if len(target_memory.get("dead_ends") or []) >= 2:
        cards.append("dead-ends")
    if gaps or skill in {"web2-recon", "bb-methodology"}:
        cards.append("coverage-prompts")
    if not ranked.get("available"):
        cards = (cards[:1] + ["coverage-prompts"]) if cards else ["coverage-prompts"]
    if skill == "triage-validation" and not cards:
        cards.extend(["api-idor", "auth-access"])
    if not cards:
        cards.append("coverage-prompts")
    focus_l = focus.lower()
    priority: list[str] = []
    if (
        "missing-param" in focus_l
        or "parameter-null" in focus_l
        or "param-discovery" in focus_l
        or "api-docs" in focus_l
        or "arjun" in focus_l
        or re.search(
            r"\b(missing[-_ ]?param(?:eter)?|parameter[-_ ]?null|parameter is null|required[-_ ]?param(?:eter)?|param[-_ ]?discovery|arjun|api[-_ ]?docs|v3/api-docs|swagger|openapi)\b",
            blob,
            re.I,
        )
    ):
        priority.append("missing-parameter-discovery")
    if (
        "path-pattern" in focus_l
        or "management-exposure" in focus_l
        or "admin-panel" in focus_l
        or "monitoring-console" in focus_l
        or "druid" in focus_l
        or "actuator" in focus_l
        or "secret-leak" in focus_l
        or re.search(
            r"\b(path[-_ ]?pattern|directory[-_ ]?fuzz(?:ing)?|dirsearch|admin[-_ ]?panel|management[-_ ]?exposure|management[-_ ]?console|monitoring[-_ ]?console|druid|weburi|actuator|spring[-_ ]?boot[-_ ]?admin|grafana|kibana|nacos|consul|jenkins|accesskey|secretkey|secret[-_ ]?leak)\b",
            blob,
            re.I,
        )
    ):
        priority.append("path-pattern-management-exposure")
    if "graphql" in focus_l:
        priority.append("graphql")
    if (
        "api-idor" in focus_l
        or "idor" in focus_l
        or re.search(r"\b(idor|tenant|org|account|user_id|account_id|org_id|tenant_id|order_id|invoice_id|object_id)\b", blob, re.I)
    ):
        priority.append("api-idor")
    if (
        "auth-hidden" in focus_l
        or "hidden-login" in focus_l
        or "login-bypass" in focus_l
        or "ato" in focus_l
        or re.search(r"\b(hidden[-_ ]?login|login[-_ ]?bypass|account[-_ ]?takeover|username[-_ ]?enum|soap|ldap)\b", blob, re.I)
    ):
        priority.append("auth-hidden-switches")
        priority.append("auth-access")
    if "auth" in focus_l:
        priority.append("auth-access")
    if (
        "sqli" in focus_l
        or "sql-injection" in focus_l
        or re.search(r"\b(sqli|sql[-_ ]?injection|x[-_ ]?forwarded[-_ ]?for|x[-_ ]?real[-_ ]?ip|hidden[-_ ]?param|path[-_ ]?segment)\b", blob, re.I)
    ):
        priority.append("sqli-hidden-surfaces")
    if not priority and re.search(r"\b(graphql|gql|mutation|subscription|introspection|global[_-]?id)\b", blob, re.I):
        priority.append("graphql")
    cards = _dedupe(priority + cards)
    return [CARD_PATHS[name] for name in _dedupe(cards)[:2]]


def _required_checks(skill: str, blob: str) -> list[str]:
    checks = [
        "rules/context-loading.md",
        "rules/red-lines.md",
        "rules/coverage-gate.md",
    ]
    if skill == "triage-validation":
        checks.append("rules/reporting.md")
    if re.search(r"\b(jwt|oauth|graphql|ssrf|upload|url[-_ ]?fetch|webhook)\b", blob, re.I):
        checks.append("rules/playbook-router.md")
    return _dedupe(checks)


def _phase(goal_memory: dict) -> str:
    active = goal_memory.get("active") or {}
    target_memory = goal_memory.get("target") or {}
    return str(active.get("phase") or target_memory.get("phase") or "unknown").strip() or "unknown"


def _active_goal(goal_memory: dict) -> str:
    active = goal_memory.get("active") or {}
    target_memory = goal_memory.get("target") or {}
    return str(active.get("active_goal") or target_memory.get("active_goal") or "").strip()


def _hypothesis(goal_memory: dict) -> str:
    active = goal_memory.get("active") or {}
    target_memory = goal_memory.get("target") or {}
    return str(active.get("current_hypothesis") or target_memory.get("current_hypothesis") or "").strip()


def _surface_anchor(item: dict) -> str:
    url = str(item.get("url") or "").strip()
    reasons = ", ".join(str(reason) for reason in (item.get("reasons") or [])[:2])
    score = item.get("score")
    return f"P1/P2 {url} score={score} reasons={reasons}".strip()


def _gap_anchor(gap: dict) -> str:
    return f"Coverage gap: {gap.get('endpoint', '')} x {gap.get('vuln_class', '')} weight={gap.get('weight', '')}"


def _local_intel_anchors(local_intel: dict) -> list[str]:
    anchors: list[str] = []
    browser = local_intel.get("browser") or {}
    for url in (browser.get("xhr_endpoints") or [])[:3]:
        anchors.append(f"Browser XHR/API: {url}")
    for line in (browser.get("params") or [])[:3]:
        anchors.append(f"Browser param: {line}")
    for form in (browser.get("forms") or [])[:2]:
        method = str(form.get("method") or "").strip() or "GET"
        action = str(form.get("action") or "").strip() or "(current page)"
        anchors.append(f"Browser form: {method} {action}")

    js_intel = local_intel.get("js_intel") or {}
    for endpoint in (js_intel.get("endpoints") or [])[:3]:
        method = str(endpoint.get("method") or "").strip()
        path = str(endpoint.get("path") or "").strip()
        source = str(endpoint.get("source_file") or "").strip()
        auth_required = str(endpoint.get("auth_required") or "").strip()
        parts = ["JS-reader endpoint:"]
        if method:
            parts.append(method)
        if path:
            parts.append(path)
        if source:
            parts.append(f"source={source}")
        if auth_required:
            parts.append(f"auth={auth_required}")
        anchors.append(" ".join(parts))
    for lead in (js_intel.get("leads") or [])[:2]:
        title = str(lead.get("title") or "").strip()
        category = str(lead.get("category") or "js").strip()
        if title:
            anchors.append(f"JS-reader lead [{category}]: {title}")

    source_intel = local_intel.get("source_intel") or {}
    for hypothesis in (source_intel.get("hypotheses") or [])[:3]:
        vuln_type = str(hypothesis.get("type") or "source").strip()
        candidate = str(hypothesis.get("candidate") or "").strip()
        reason = str(hypothesis.get("reason") or "").strip()
        if candidate:
            suffix = f" -> {reason[:120]}" if reason else ""
            anchors.append(f"Source-intel hypothesis [{vuln_type}]: {candidate}{suffix}")
    for route in (source_intel.get("routes") or [])[:2]:
        route_value = str(route.get("route") or "").strip()
        method = str(route.get("method") or "").strip()
        if route_value:
            anchors.append(f"Source route: {method} {route_value}".strip())
    return _dedupe(anchors)


def _build_evidence_anchors(
    ranked: dict,
    goal_memory: dict,
    gaps: list[dict],
    findings: list[dict],
    local_intel: dict,
) -> list[str]:
    anchors: list[str] = []
    for item in ranked.get("p1", [])[:3]:
        anchors.append(_surface_anchor(item))
    anchors.extend(_local_intel_anchors(local_intel)[:6])
    for lead in _json_list(ranked.get("workflow_leads"))[:3]:
        title = str(lead.get("title") or "").strip()
        category = str(lead.get("category") or "workflow").strip()
        priority = str(lead.get("priority") or "medium").strip()
        anchors.append(f"Workflow lead [{priority}/{category}]: {title}")
    target_memory = goal_memory.get("target") or {}
    for label, field in (
        ("Target lead", "active_leads"),
        ("Next action", "next_actions"),
        ("Dead end", "dead_ends"),
    ):
        for item in (target_memory.get(field) or [])[-2:]:
            text = _entry_text(item)
            if text:
                anchors.append(f"{label}: {text}")
    for gap in gaps[:5]:
        anchors.append(_gap_anchor(gap))
    for finding in findings[:3]:
        anchors.append(f"Finding: {_finding_anchor(finding)}")
    return _dedupe(anchors)[:12] or ["No strong local evidence anchor yet; start from target memory and recon freshness."]


def _has_browser_intel(local_intel: dict) -> bool:
    browser = local_intel.get("browser") or {}
    return bool(
        browser.get("xhr_endpoints")
        or browser.get("api_endpoints")
        or browser.get("params")
        or browser.get("forms")
    )


def _local_intel_hypothesis_seeds(local_intel: dict) -> list[str]:
    seeds: list[str] = []
    browser = local_intel.get("browser") or {}
    browser_blob = "\n".join(
        list(browser.get("xhr_endpoints") or [])
        + list(browser.get("api_endpoints") or [])
        + list(browser.get("params") or [])
    )
    if _has_browser_intel(local_intel):
        seeds.append(
            "浏览器观察到的 XHR/API 优先做登录态、角色、租户差异对比；遇到状态改变动作先按红线降级到只读或可回滚验证。"
        )
    if re.search(r"\b(user|account|tenant|org|order|invoice|object|profile|workspace)[_-]?id\b|[?&]id=", browser_blob, re.I):
        seeds.append(
            "browser_params / XHR 中的对象 ID 适合做 attacker/victim、同组织/跨组织、角色差异验证。"
        )
    if re.search(r"\b(graphql|mutation|subscription)\b", browser_blob, re.I):
        seeds.append(
            "浏览器态 GraphQL 先提取 operation、变量和对象 ID，再做低频 authz 差异，不做深层递归或 alias 加压。"
        )
    if browser.get("forms"):
        seeds.append(
            "表单 action / method 可作为 CSRF、SameSite、服务端权限绑定线索；默认不提交真实状态改变动作。"
        )

    js_intel = local_intel.get("js_intel") or {}
    if js_intel.get("endpoints") or js_intel.get("leads"):
        seeds.append(
            "JS-reader 暴露的 endpoint / lead 要和浏览器 Network 或实际 replay 交叉验证，优先找前端可见但服务端未绑定的权限边界。"
        )

    source_intel = local_intel.get("source_intel") or {}
    source_types = {
        str(item.get("type") or "").lower()
        for item in (source_intel.get("hypotheses") or [])
        if item.get("type")
    }
    if source_types:
        seeds.append(
            "source-intel hypothesis 是路线种子，不是结论；先用浏览器态或最小请求验证真实可达性和权限影响。"
        )
    if {"csrf", "auth-bypass"} & source_types:
        seeds.append(
            "source-intel 命中 CSRF/auth-bypass 时先检查 token、SameSite、Origin/Referer 和角色绑定，避免直接执行破坏性 workflow。"
        )
    return _dedupe(seeds)


def _hypothesis_seeds(cards: list[str], blob: str, local_intel: dict) -> list[str]:
    seeds: list[str] = []
    seeds.extend(_local_intel_hypothesis_seeds(local_intel))
    if CARD_PATHS["api-idor"] in cards or re.search(r"\b(idor|tenant|org|account|user_id|order_id)\b", blob, re.I):
        seeds.extend([
            "对象/组织/租户 ID 是否只在前端约束，服务端是否重新绑定当前身份。",
            "export/download/report 类接口是否可通过 ID 或筛选条件读取其他主体数据。",
        ])
    if CARD_PATHS["auth-access"] in cards:
        seeds.extend([
            "同一 endpoint 在匿名、普通用户、低权限成员、管理员之间是否只有 UI 差异而缺少服务端差异。",
        ])
    if CARD_PATHS["auth-hidden-switches"] in cards:
        seeds.extend([
            "登录接口是否存在 UI 未传但后端读取的隐藏认证参数，能切换 SSO/LDAP/SOAP/test/mock/skip 等认证分支。",
            "本 lane 只做自有/测试账号 baseline 与单变量隐藏参数差异；若转入口令爆破/密码喷洒，记录为 next action 并切到手动 /spray 或 credential-attack 受控流程。",
        ])
    if CARD_PATHS["missing-parameter-discovery"] in cards:
        seeds.extend([
            "`parameter is null` / `missing parameter` 只是入口信号；先从 JS/source/API docs/浏览器 XHR 构造目标特定参数词表，再低频验证响应形态差异。",
            "隐藏参数命中后只做最小影响验证：状态码、长度、字段集合、空/非空结构和自有/测试对象差异；不批量枚举真实 PII、密码、地址或 token。",
        ])
    if CARD_PATHS["path-pattern-management-exposure"] in cards:
        seeds.extend([
            "发现类 fuzz 先从目标已有路径、文件名、API 前缀、参数名、子域、静态资源等命名规律生成有界词表，再验证兄弟 surface；不要直接扩大到无边界通用字典。",
            "管理/监控/日志/统计/配置/记录类 surface 优先做只读识别和结构化记录提取；疑似 access key/secret 只记录最小证据与验证计划，不接管云资源或读取真实数据。",
        ])
    if CARD_PATHS["graphql"] in cards:
        seeds.extend([
            "GraphQL mutation / global ID / node 查询是否复用 REST 的对象权限缺口。",
        ])
    if CARD_PATHS["sqli-hidden-surfaces"] in cards:
        seeds.extend([
            "SQLi 不只看显式 query/body 参数；检查 header、path segment、跨接口隐藏参数是否进入查询、日志或风控链路。",
            "从 A 接口提取参数集喂给同业务 B 接口，每次只扰动一个参数，比较稳定的状态码、长度、错误、排序或布尔差异。",
        ])
    if CARD_PATHS["ssrf-url-fetch"] in cards:
        seeds.extend([
            "URL fetch、webhook、import callback 是否存在 server-side fetch，可先用 allowlisted harmless URL 建模。",
        ])
    if CARD_PATHS["upload-parser"] in cards:
        seeds.extend([
            "上传、导入、预览、转换是否形成解析器链路，优先验证元数据/预览差异而非破坏性 payload。",
        ])
    if CARD_PATHS["race-conditions"] in cards:
        seeds.extend([
            "并发风险先做低频状态模型和幂等性推理，不做高并发或真实资金/库存状态改变。",
        ])
    if CARD_PATHS["coverage-prompts"] in cards:
        seeds.append("把 P1/P2 surface 映射到 authz、IDOR、SSRF、Upload、GraphQL、Race 等高价值 lane，找未测组合。")
    if CARD_PATHS["dead-ends"] in cards:
        seeds.append("复查 dead end 的停止条件：只有出现新证据时才重开旧方向。")
    return _dedupe(seeds)[:6]


def _alternative_angles(cards: list[str], ranked: dict, local_intel: dict) -> list[str]:
    angles = [
        "如果主路径证据不足，转到相邻高信号 P1/P2，而不是扩大读取全量日志。",
        "对浏览器态 XHR/API、JS-reader、source-intel 的新证据保持开放，必要时改选 Skill。",
    ]
    browser = local_intel.get("browser") or {}
    if _has_browser_intel(local_intel):
        angles.extend([
            "用 Playwright/浏览器复用登录态重放关键页面，只看 Network/Console 差异和只读响应变化。",
            "用 Chrome DevTools Network/Console 对照真实前端请求，再决定是否转成 curl/local helper 精确 replay。",
            "对同一 browser-observed endpoint 做匿名、低权限、高权限账号差异，而不是只测单账号成功路径。",
        ])
    if browser.get("page_count") or browser.get("js_file_count"):
        angles.append("从 page_js_map 反查哪个页面加载目标 JS，再回到对应 workflow 捕获 XHR。")
    js_intel = local_intel.get("js_intel") or {}
    source_intel = local_intel.get("source_intel") or {}
    if js_intel.get("endpoints") and source_intel.get("hypotheses"):
        angles.append("把 JS-reader endpoint 与 source-intel route/hypothesis 交叉，优先验证两者重合的权限边界。")
    if CARD_PATHS["api-idor"] in cards:
        angles.append("从 REST IDOR 横向扩展到导出、报表、批量查询、成员管理和 invite 流程。")
    if CARD_PATHS["auth-hidden-switches"] in cards:
        angles.append("登录绕过无信号时，回到 JS/source/browser 找 sibling 登录端点、旧认证源和隐藏模式参数。")
    if CARD_PATHS["missing-parameter-discovery"] in cards:
        angles.append("缺参信号无结果时，回到 JS 词表、API docs schema、sibling endpoint 参数和浏览器 XHR，而不是扩大通用字典喷洒。")
    if CARD_PATHS["path-pattern-management-exposure"] in cards:
        angles.append("命名规律没有直接结果时，提取只读结构化记录、访问记录、统计接口、配置字段和 raw log 反哺二次 recon，并把 secret 候选降级为最小验证线索。")
    if CARD_PATHS["graphql"] in cards:
        angles.append("GraphQL 无结果时检查同业务的 REST sibling endpoint、global ID 解码和前端缓存。")
    if CARD_PATHS["sqli-hidden-surfaces"] in cards:
        angles.append("常规参数无 SQLi 信号时，转向 Header、路径段和 JS/source-derived sibling endpoint 的隐藏参数验证。")
    if CARD_PATHS["upload-parser"] in cards:
        angles.append("上传链路无结果时转向 import URL、预览 worker、异步转换状态和权限绑定。")
    if CARD_PATHS["race-conditions"] in cards:
        angles.append("Race 不直接加压；先寻找可回滚测试资源、幂等 key、状态机边界和重复提交证据。")
    if not ranked.get("available"):
        angles.append("如果 recon 缺失，先只补最小可用 surface，再回到漏洞类别验证。")
    return _dedupe(angles)[:6]


def _unknowns(
    ranked: dict,
    goal_memory: dict,
    matrix: dict,
    findings: list[dict],
    local_intel: dict,
) -> list[str]:
    items: list[str] = []
    if not ranked.get("available"):
        items.append("No ranked surface available from local recon cache.")
    stats = ranked.get("stats") or {}
    if ranked.get("available") and not stats.get("p1") and not stats.get("p2"):
        items.append("Surface rank has no P1/P2 candidates; recon may be thin or low-signal.")
    browser = ranked.get("browser") or {}
    local_browser = local_intel.get("browser") or {}
    if (
        not browser.get("xhr_count")
        and not browser.get("api_count")
        and not local_browser.get("xhr_endpoints")
        and not local_browser.get("api_endpoints")
    ):
        items.append("No browser-observed XHR/API context loaded.")
    summary = matrix.get("summary") or {}
    if not summary.get("total_cells"):
        items.append("Coverage matrix is empty or not rebuilt for this target.")
    if not findings:
        items.append("No structured findings.json entries found for this target.")
    if not (goal_memory.get("active") or goal_memory.get("target")):
        items.append("No target memory found; write back the first concrete lead/handoff after work.")
    return items or ["No major local unknowns surfaced by context_pack."]


def _token_overlap(a: str, b: str) -> bool:
    tokens = {
        token
        for token in re.findall(r"[a-z0-9_./:-]{4,}", a.lower())
        if token not in {"https", "http", "target", "tested", "without", "with"}
    }
    haystack = b.lower()
    return any(token in haystack for token in list(tokens)[:12])


def _contradictions(
    target: str,
    goal_memory: dict,
    ranked: dict,
    gaps: list[dict],
    local_intel: dict,
) -> list[str]:
    items: list[str] = []
    raw_active = goal_memory.get("raw_active") or {}
    raw_active_target = canonical_target_value(str(raw_active.get("target") or ""))
    if raw_active_target and raw_active_target != target:
        items.append(
            f"Active target memory points to {raw_active_target}, but context_pack target is {target}."
        )
    dead_ends = [
        _entry_text(item)
        for item in ((goal_memory.get("target") or {}).get("dead_ends") or [])[-5:]
        if _entry_text(item)
    ]
    new_evidence = "\n".join(
        [_surface_anchor(item) for item in ranked.get("p1", [])[:5]]
        + [
            f"{lead.get('title', '')} {lead.get('next_action', '')}"
            for lead in _json_list(ranked.get("workflow_leads"))[:5]
        ]
        + [_gap_anchor(gap) for gap in gaps[:5]]
        + _local_intel_blob(local_intel)[:20]
    )
    for dead in dead_ends:
        if _token_overlap(dead, new_evidence):
            items.append(
                f"Remembered dead end may have new evidence now: {dead[:140]}"
            )
    workflow_leads = _json_list(ranked.get("workflow_leads"))
    if not gaps and workflow_leads:
        items.append(
            "Coverage gaps are empty, but workflow leads still exist; do not treat empty matrix gaps as full exhaustion."
        )
    if not ranked.get("available") and ((goal_memory.get("target") or {}).get("active_leads")):
        items.append(
            "Target memory has active leads, but local surface is unavailable; use memory as hypothesis, not proof."
        )
    return _dedupe(items) or ["None detected."]


def _write_back_commands(target: str) -> list[str]:
    return [
        f'python3 tools/target_memory.py lead "Evidence: ... Why it matters: ... Next action: ... Stop condition: ..." --target {target}',
        f'python3 tools/target_memory.py next "..." --target {target}',
        f'python3 tools/target_memory.py dead-end "..." --target {target}',
        f'python3 tools/target_memory.py handoff "..." --target {target}',
        "/retrospect <target>  # 可复用经验只建议晋升到知识库 / Skill / Rules，默认不自动改文件",
    ]


def _local_intel_paths(local_intel: dict) -> list[str]:
    paths: list[str] = []
    for section in ("browser", "js_intel", "source_intel"):
        paths.extend(((local_intel.get(section) or {}).get("paths") or [])[:3])
    return _dedupe(paths)


def _local_intel_source_summary(local_intel: dict) -> dict:
    browser = local_intel.get("browser") or {}
    js_intel = local_intel.get("js_intel") or {}
    source_intel = local_intel.get("source_intel") or {}
    return {
        "browser_xhr": len(browser.get("xhr_endpoints") or []),
        "browser_api": len(browser.get("api_endpoints") or []),
        "browser_params": len(browser.get("params") or []),
        "browser_forms": len(browser.get("forms") or []),
        "browser_pages_with_js": int(browser.get("page_count") or 0),
        "js_intel_endpoints": len(js_intel.get("endpoints") or []),
        "js_intel_leads": len(js_intel.get("leads") or []),
        "js_intel_graphql": len(js_intel.get("graphql_operations") or []),
        "source_intel_hypotheses": len(source_intel.get("hypotheses") or []),
        "source_intel_routes": len(source_intel.get("routes") or []),
        "source_intel_graphql": len(source_intel.get("graphql_operations") or []),
    }


def _focus_endpoints_for_ledger(ranked: dict, gaps: list[dict], local_intel: dict) -> list[str]:
    endpoints: list[str] = []
    for item in ranked.get("p1", [])[:4] + ranked.get("p2", [])[:2]:
        endpoints.append(str(item.get("url") or item.get("path") or ""))
    for gap in gaps[:4]:
        endpoints.append(str(gap.get("endpoint") or ""))
    browser = local_intel.get("browser") or {}
    endpoints.extend((browser.get("xhr_endpoints") or [])[:4])
    js_intel = local_intel.get("js_intel") or {}
    for endpoint in (js_intel.get("endpoints") or [])[:3]:
        endpoints.append(str(endpoint.get("path") or ""))
    source_intel = local_intel.get("source_intel") or {}
    for hypothesis in (source_intel.get("hypotheses") or [])[:3]:
        endpoints.append(str(hypothesis.get("candidate") or ""))
    return _dedupe(endpoints)[:8]


def _ledger_vuln_classes(cards: list[str], blob: str) -> list[str]:
    classes: list[str] = []
    if CARD_PATHS["api-idor"] in cards or re.search(r"\b(idor|account_id|tenant_id|org_id|user_id|order_id)\b", blob, re.I):
        classes.append("IDOR")
    if CARD_PATHS["auth-access"] in cards or re.search(r"\b(authz|rbac|role|admin|permission)\b", blob, re.I):
        classes.append("Authz")
    if CARD_PATHS["auth-hidden-switches"] in cards or re.search(r"\b(login[-_ ]?bypass|account[-_ ]?takeover|ato|hidden[-_ ]?login)\b", blob, re.I):
        classes.append("Authz")
    if CARD_PATHS["missing-parameter-discovery"] in cards or re.search(r"\b(missing[-_ ]?param(?:eter)?|parameter[-_ ]?null|parameter is null|param[-_ ]?discovery|arjun)\b", blob, re.I):
        classes.extend(["IDOR", "Authz"])
    if CARD_PATHS["path-pattern-management-exposure"] in cards or re.search(r"\b(druid|actuator|admin[-_ ]?panel|management[-_ ]?console|monitoring[-_ ]?console|accesskey|secretkey|secret[-_ ]?leak)\b", blob, re.I):
        classes.extend(["Authz", "Path"])
    if CARD_PATHS["graphql"] in cards or re.search(r"\b(graphql|mutation|subscription)\b", blob, re.I):
        classes.append("GraphQL")
    if CARD_PATHS["sqli-hidden-surfaces"] in cards or re.search(r"\b(sqli|sql[-_ ]?injection|hidden[-_ ]?param)\b", blob, re.I):
        classes.append("SQLi")
    if re.search(r"\b(csrf|xsrf|same[-_ ]?site|origin|referer)\b", blob, re.I):
        classes.append("CSRF")
    return _dedupe(classes)[:3] or ["IDOR", "Authz"]


def _ledger_relative_path(summary: dict, repo_root: Path) -> str:
    path = str(summary.get("path") or "").strip()
    if not path or not summary.get("path_exists"):
        return ""
    try:
        return str(Path(path).relative_to(repo_root))
    except ValueError:
        return path


def _ledger_anchors(summary: dict) -> list[str]:
    anchors: list[str] = []
    for entry in (summary.get("recent_entries") or [])[-3:]:
        anchors.append(
            "Ledger: {method} {endpoint} x {vuln} {actor}/{scope}/{variant} -> {result}".format(
                method=entry.get("method", ""),
                endpoint=entry.get("endpoint", ""),
                vuln=entry.get("vuln_class", ""),
                actor=entry.get("actor", ""),
                scope=entry.get("object_scope", ""),
                variant=entry.get("variant", ""),
                result=entry.get("result", ""),
            )
        )
    matrix = summary.get("actor_matrix") or {}
    for gap in (matrix.get("gaps") or [])[:3]:
        anchors.append(
            "Actor gap: {endpoint} x {vuln} {actor}/{scope}/{variant} expected={expected} status={status}".format(
                endpoint=gap.get("endpoint", ""),
                vuln=gap.get("vuln_class", ""),
                actor=gap.get("actor", ""),
                scope=gap.get("object_scope", ""),
                variant=gap.get("variant", ""),
                expected=gap.get("expected", ""),
                status=gap.get("status", ""),
            )
        )
    return _dedupe(anchors)


def _ledger_unknowns(summary: dict) -> list[str]:
    items: list[str] = []
    if not summary.get("entry_count"):
        items.append("No evidence ledger entries found; exact actor/object/replay coverage is not recorded yet.")
    matrix = summary.get("actor_matrix") or {}
    if matrix.get("gap_count"):
        items.append(
            f"Actor matrix has {matrix.get('gap_count')} missing/pending/blocked role-object checks."
        )
    if summary.get("redline_unchecked_count"):
        items.append(
            f"Evidence ledger has {summary.get('redline_unchecked_count')} state-changing record(s) without red-line check."
        )
    return items


def _ledger_source_summary(summary: dict) -> dict:
    matrix = summary.get("actor_matrix") or {}
    result_counts = summary.get("result_counts") or {}
    return {
        "evidence_ledger_entries": int(summary.get("entry_count") or 0),
        "actor_matrix_gaps": int(matrix.get("gap_count") or 0),
        "actor_matrix_covered": int(matrix.get("covered_count") or 0),
        "evidence_candidates": int(result_counts.get("candidate", 0) or 0),
        "evidence_redline_unchecked": int(summary.get("redline_unchecked_count") or 0),
    }


def build_context_pack(
    repo_root: Path | str = BASE_DIR,
    *,
    target: str,
    focus: str = "",
    memory_dir: str | None = None,
) -> dict:
    repo = Path(repo_root)
    resolved_target = canonical_target_value(target)
    target_key = target_storage_key(resolved_target)
    goal_memory = _load_goal_memory(repo, resolved_target)
    ranked = _surface_state(repo, resolved_target, memory_dir)
    gaps, matrix = _safe_find_gaps(resolved_target, target_key, repo)
    findings = _load_findings(repo, target_key)
    local_intel = _load_local_intel(repo, target_key)
    blob = _text_blob(focus, goal_memory, ranked, gaps, findings, local_intel)
    skill, why_skill = _select_skill(focus, blob, ranked, findings, goal_memory)
    cards = _select_cards(blob, skill, ranked, gaps, goal_memory, focus)
    checks = _required_checks(skill, blob)
    evidence_summary = build_evidence_summary(
        repo,
        target=resolved_target,
        focus_endpoints=_focus_endpoints_for_ledger(ranked, gaps, local_intel),
        vuln_classes=_ledger_vuln_classes(cards, blob),
    )
    ledger_path = _ledger_relative_path(evidence_summary, repo)

    must_read = _dedupe([
        goal_memory["active_path"],
        goal_memory["target_path"],
        "skills/runtime-protocol.md",
        SKILL_PATHS[skill],
        "knowledge/index.md",
        ledger_path,
    ] + _local_intel_paths(local_intel))

    pack = {
        "target": resolved_target,
        "target_storage_key": target_key,
        "phase": _phase(goal_memory),
        "active_goal": _active_goal(goal_memory),
        "current_hypothesis": _hypothesis(goal_memory),
        "focus": focus,
        "selected_skill": SKILL_PATHS[skill],
        "selected_skill_id": skill,
        "why_this_skill": why_skill,
        "must_read": must_read,
        "knowledge_cards": cards,
        "required_checks": checks,
        "evidence_anchors": _build_evidence_anchors(ranked, goal_memory, gaps, findings, local_intel)
        + _ledger_anchors(evidence_summary),
        "hypothesis_seeds": _hypothesis_seeds(cards, blob, local_intel),
        "alternative_angles": _alternative_angles(cards, ranked, local_intel),
        "unknowns": _unknowns(ranked, goal_memory, matrix, findings, local_intel)
        + _ledger_unknowns(evidence_summary),
        "contradictions": _contradictions(resolved_target, goal_memory, ranked, gaps, local_intel),
        "actor_matrix_gaps": (evidence_summary.get("actor_matrix") or {}).get("gaps", [])[:8],
        "do_not_load": [
            "full skills/* tree",
            "full knowledge/cards/* tree",
            "full skills/security-arsenal/REFERENCES.md unless playbook-router requires it",
            "raw large recon logs, full JSONL, full HTML responses, or unrelated historical sessions",
            "raw browser capture requests/console/storage unless validating one exact replay path",
            "all findings evidence bodies; start from findings/<target>/findings.json index only",
        ],
        "write_back": _write_back_commands(resolved_target) + (evidence_summary.get("record_commands") or [])[:3],
        "ai_override": (
            "Claude may choose another skill, knowledge card, or path if the evidence supports it; "
            "state the reason, keep red-lines/coverage checks loaded, and write the decision back "
            "to target memory or /retrospect."
        ),
        "source_summary": {
            "surface_available": bool(ranked.get("available")),
            "p1": (ranked.get("stats") or {}).get("p1", 0),
            "p2": (ranked.get("stats") or {}).get("p2", 0),
            "workflow_leads": len(_json_list(ranked.get("workflow_leads"))),
            "coverage_gaps": len(gaps),
            "findings": len(findings),
            **_local_intel_source_summary(local_intel),
            **_ledger_source_summary(evidence_summary),
        },
    }
    return pack


def _format_list(lines: list[str]) -> list[str]:
    if not lines:
        return ["  - None"]
    return [f"  - {line}" for line in lines]


def format_context_pack(pack: dict) -> str:
    lines = [
        "CONTEXT PACK",
        f"- Target: {pack['target']}",
        f"- Phase: {pack['phase']}",
        f"- Active goal: {pack.get('active_goal') or '-'}",
        f"- Current hypothesis: {pack.get('current_hypothesis') or '-'}",
        f"- Selected skill: {pack['selected_skill']}",
        f"- Why this skill: {pack['why_this_skill']}",
        "- Must read:",
        *_format_list(pack["must_read"]),
        "- Knowledge cards:",
        *_format_list(pack["knowledge_cards"]),
        "- Required checks:",
        *_format_list(pack["required_checks"]),
        "- Evidence anchors:",
        *_format_list(pack["evidence_anchors"]),
        "- Hypothesis seeds:",
        *_format_list(pack["hypothesis_seeds"]),
        "- Alternative angles:",
        *_format_list(pack["alternative_angles"]),
        "- Unknowns:",
        *_format_list(pack["unknowns"]),
        "- Actor matrix gaps:",
        *_format_list([
            "{endpoint} x {vuln}: {actor}/{scope}/{variant} expected={expected} status={status}".format(
                endpoint=item.get("endpoint", ""),
                vuln=item.get("vuln_class", ""),
                actor=item.get("actor", ""),
                scope=item.get("object_scope", ""),
                variant=item.get("variant", ""),
                expected=item.get("expected", ""),
                status=item.get("status", ""),
            )
            for item in pack.get("actor_matrix_gaps", [])
        ]),
        "- Contradictions:",
        *_format_list(pack["contradictions"]),
        "- Do not load:",
        *_format_list(pack["do_not_load"]),
        "- Write-back:",
        *_format_list(pack["write_back"]),
        f"- AI override: {pack['ai_override']}",
    ]
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build a read-only Claude CLI context pack for one target."
    )
    parser.add_argument("args", nargs="*", help="optional target and/or focus words")
    parser.add_argument("--target", default="", help="target; defaults to active target memory")
    parser.add_argument("--focus", default="", help="focus such as api-idor, graphql, upload, race")
    parser.add_argument("--repo-root", default=str(BASE_DIR))
    parser.add_argument("--memory-dir", default="")
    parser.add_argument("--json", action="store_true", help="output JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    repo_root = Path(args.repo_root)
    target, focus = _resolve_cli_args(args, repo_root)
    pack = build_context_pack(
        repo_root,
        target=target,
        focus=focus,
        memory_dir=args.memory_dir or None,
    )
    if args.json:
        print(json.dumps(pack, ensure_ascii=False, indent=2))
    else:
        print(format_context_pack(pack))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
