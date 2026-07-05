#!/usr/bin/env python3
"""记录 endpoint 级测试账本，并生成角色/对象差异矩阵。

Evidence Ledger 补 coverage_matrix 没覆盖到的一层：同一个 endpoint 是否
真的做过匿名、owner、peer、低权限、跨租户等差异验证。默认 summary 只读；
只有 record 子命令会追加写入 `memory/evidence/<target>/ledger.jsonl`。
"""

from __future__ import annotations

import argparse
import json
import re
import shlex
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

BASE_DIR = Path(__file__).resolve().parents[1]
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

try:
    from tools.coverage_matrix import normalize_vuln_class
    from tools.target_paths import canonical_target_value, target_storage_key
except ImportError:  # pragma: no cover - direct tools/ execution
    from coverage_matrix import normalize_vuln_class  # type: ignore
    from target_paths import canonical_target_value, target_storage_key  # type: ignore


SCHEMA_VERSION = 1
SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "POST"}
RESULTS = (
    "lead",
    "signal",
    "candidate",
    "tested_clean",
    "tested_finding",
    "dead_end",
    "blocked_redline",
    "not_applicable",
)
COVERING_RESULTS = {"signal", "candidate", "tested_clean", "tested_finding", "dead_end"}
CLOSED_CELL_RESULTS = {"tested_clean", "tested_finding", "dead_end", "not_applicable"}

ACTOR_ALIASES = {
    "anonymous": "anonymous",
    "anon": "anonymous",
    "unauth": "anonymous",
    "unauthenticated": "anonymous",
    "owner": "owner",
    "self": "owner",
    "user_a": "owner",
    "peer": "peer",
    "other": "peer",
    "victim": "peer",
    "user_b": "peer",
    "low_role": "low_role",
    "low-role": "low_role",
    "lowpriv": "low_role",
    "member": "low_role",
    "admin": "admin",
    "cross_tenant": "cross_tenant",
    "cross-tenant": "cross_tenant",
    "tenant_b": "cross_tenant",
}

OBJECT_ALIASES = {
    "none": "none",
    "na": "none",
    "own": "own_object",
    "own_object": "own_object",
    "self": "own_object",
    "other": "other_object_same_org",
    "peer": "other_object_same_org",
    "same_org_other": "other_object_same_org",
    "cross_tenant": "cross_tenant_object",
    "cross-tenant": "cross_tenant_object",
    "tenant_b": "cross_tenant_object",
    "admin": "admin_object",
    "admin_object": "admin_object",
    "unknown": "unknown",
}

VARIANT_ALIASES = {
    "baseline": "baseline",
    "allow": "baseline",
    "unauth": "unauth_denied",
    "unauth_denied": "unauth_denied",
    "anonymous_denied": "unauth_denied",
    "id_swap": "id_swap",
    "idswap": "id_swap",
    "object_swap": "id_swap",
    "role_diff": "role_diff",
    "role": "role_diff",
    "tenant_diff": "tenant_diff",
    "tenant": "tenant_diff",
    "method_diff": "method_diff",
    "method": "method_diff",
    "version_diff": "version_diff",
    "version": "version_diff",
    "token_missing": "token_missing",
    "csrf_missing": "token_missing",
    "origin_diff": "origin_diff",
    "referer_diff": "origin_diff",
    "replay": "replay",
    "browser_observed": "browser_observed",
}


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def ledger_path(repo_root: Path | str, target: str) -> Path:
    repo = Path(repo_root)
    key = target_storage_key(canonical_target_value(target))
    return repo / "memory" / "evidence" / key / "ledger.jsonl"


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


def _canonicalize_endpoint(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""

    def _hash_route(path: str, fragment: str) -> str:
        fragment = str(fragment or "")
        if not fragment.startswith("/"):
            return ""
        route = fragment.split("?", 1)[0].split("#", 1)[0] or "/"
        prefix = (path or "/").split("?", 1)[0].rstrip("/") or "/"
        return f"{prefix}#{route}"

    if "://" in raw:
        try:
            parsed = urlparse(raw)
        except ValueError:
            return raw.split("?", 1)[0].split("#", 1)[0]
        hash_route = _hash_route(parsed.path or "/", parsed.fragment)
        if hash_route:
            return hash_route
        return (parsed.path or "/").split("?", 1)[0].split("#", 1)[0]
    if "#/" in raw:
        path, fragment = raw.split("#", 1)
        hash_route = _hash_route(path or "/", fragment)
        if hash_route:
            return hash_route
    return raw.split("?", 1)[0].split("#", 1)[0]


def _quote(value: str) -> str:
    return shlex.quote(str(value))


def _normalize(value: str, aliases: dict[str, str], field: str) -> str:
    key = str(value or "").strip().lower().replace(" ", "_")
    if key in aliases:
        return aliases[key]
    by_canonical: dict[str, list[str]] = {}
    for input_key, canonical in aliases.items():
        by_canonical.setdefault(canonical, []).append(input_key)

    groups = []
    for canonical in sorted(by_canonical):
        accepted_inputs = sorted(by_canonical[canonical])
        if accepted_inputs == [canonical]:
            groups.append(canonical)
        else:
            groups.append(f"{canonical} (input: {', '.join(accepted_inputs)})")
    raise ValueError(f"unknown {field}: {value!r}. Accepted inputs: {'; '.join(groups)}")


def normalize_actor(value: str) -> str:
    return _normalize(value or "owner", ACTOR_ALIASES, "actor")


def normalize_object_scope(value: str) -> str:
    return _normalize(value or "unknown", OBJECT_ALIASES, "object_scope")


def normalize_variant(value: str) -> str:
    return _normalize(value or "baseline", VARIANT_ALIASES, "variant")


def normalize_result(value: str) -> str:
    result = str(value or "").strip().lower().replace("-", "_")
    if result not in RESULTS:
        raise ValueError(f"unknown result: {value!r}. Allowed: {', '.join(RESULTS)}")
    return result


def load_entries(repo_root: Path | str, target: str) -> list[dict]:
    path = ledger_path(repo_root, target)
    if not path.is_file():
        return []
    entries: list[dict] = []
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
            entries.append(item)
    return entries


def record_entry(
    repo_root: Path | str,
    *,
    target: str,
    endpoint: str,
    method: str = "GET",
    vuln_class: str = "IDOR",
    workflow: str = "",
    actor: str = "owner",
    object_scope: str = "unknown",
    variant: str = "baseline",
    source: str = "manual",
    result: str = "lead",
    browser_observed: bool = False,
    replayed: bool = False,
    state_changing: bool = False,
    redline_checked: bool = False,
    evidence_ref: str = "",
    notes: str = "",
) -> dict:
    resolved_target = canonical_target_value(target)
    canonical_endpoint = _canonicalize_endpoint(endpoint)
    if not canonical_endpoint:
        raise ValueError("endpoint is required")

    method_u = str(method or "GET").strip().upper()
    normalized_vuln = normalize_vuln_class(vuln_class)
    normalized_result = normalize_result(result)
    entry = {
        "schema_version": SCHEMA_VERSION,
        "ts": now_utc(),
        "target": resolved_target,
        "target_key": target_storage_key(resolved_target),
        "endpoint": canonical_endpoint,
        "raw_endpoint": endpoint,
        "method": method_u,
        "vuln_class": normalized_vuln,
        "workflow": str(workflow or "").strip(),
        "actor": normalize_actor(actor),
        "object_scope": normalize_object_scope(object_scope),
        "variant": normalize_variant(variant),
        "source": str(source or "manual").strip(),
        "result": normalized_result,
        "browser_observed": bool(browser_observed),
        "replayed": bool(replayed),
        "state_changing": bool(state_changing or method_u not in SAFE_METHODS),
        "redline_checked": bool(redline_checked),
        "evidence_ref": str(evidence_ref or "").strip(),
        "notes": str(notes or "").strip(),
        "warnings": [],
    }
    if entry["state_changing"] and not entry["redline_checked"] and normalized_result in COVERING_RESULTS:
        entry["warnings"].append("redline_check_missing_for_state_changing_test")

    path = ledger_path(repo_root, resolved_target)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n")
    return entry


_OBJECT_RESOURCE_SEGMENTS = {
    "account", "accounts", "customer", "customers", "invoice", "invoices",
    "member", "members", "order", "orders", "org", "orgs", "organization",
    "organizations", "profile", "profiles", "project", "projects", "team",
    "teams", "tenant", "tenants", "user", "users", "workspace", "workspaces",
}
_NON_OBJECT_SELECTOR_SEGMENTS = {
    "add", "admin", "all", "apply", "auth", "authentication", "callback",
    "change-password", "config", "configuration", "create", "current",
    "delete", "edit", "export", "history", "import", "internal", "invite",
    "list", "login", "logout", "manage", "management", "metadata",
    "new", "preview", "reset-password", "search", "select", "settings",
    "signup", "track-order", "update", "version", "whoami",
}


def _object_reference_endpoint(endpoint: str) -> bool:
    value = str(endpoint or "").strip().lower()
    if not value:
        return False
    if re.search(r"/\d{1,10}(?:/|$)", value):
        return True
    if re.search(r"[?&][a-z0-9_]*(?:id|uuid)=", value):
        return True

    path = _canonicalize_endpoint(value)
    segments = [segment for segment in path.split("/") if segment]
    if not segments:
        return False

    uuid_like = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.I)
    for idx, segment in enumerate(segments[:-1]):
        if segment not in _OBJECT_RESOURCE_SEGMENTS:
            continue
        candidate = segments[idx + 1]
        if (
            candidate
            and candidate not in _OBJECT_RESOURCE_SEGMENTS
            and candidate not in _NON_OBJECT_SELECTOR_SEGMENTS
            and not candidate.endswith((".json", ".xml", ".txt", ".csv"))
        ):
            return True
        if uuid_like.fullmatch(candidate or ""):
            return True
    return False


def actor_requirements(endpoint: str, vuln_class: str = "IDOR", method: str = "GET") -> list[dict]:
    """返回高级 authz/IDOR 测试应覆盖的角色/对象差异项。"""
    canonical_endpoint = _canonicalize_endpoint(endpoint)
    vc = normalize_vuln_class(vuln_class)
    method_u = str(method or "GET").strip().upper()
    state_changing = method_u not in SAFE_METHODS

    # actor matrix 只服务“角色/对象边界”类验证。像 Upload/SSRF/SQLi 即使落在
    # admin path 上，也不应自动生成 anonymous/owner/peer 这类 actor-gap，
    # 否则 checkpoint 会不断推送无意义待办。
    if vc not in {"IDOR", "Authz", "GraphQL", "CSRF"}:
        return []
    if vc != "CSRF" and not _object_reference_endpoint(canonical_endpoint):
        return []

    requirements = [
        {
            "id": "unauth-deny",
            "endpoint": canonical_endpoint,
            "method": method_u,
            "vuln_class": vc,
            "actor": "anonymous",
            "object_scope": "none",
            "variant": "unauth_denied",
            "expected": "deny",
            "redline_required": False,
        },
        {
            "id": "owner-baseline",
            "endpoint": canonical_endpoint,
            "method": method_u,
            "vuln_class": vc,
            "actor": "owner",
            "object_scope": "own_object",
            "variant": "baseline",
            "expected": "allow",
            "redline_required": state_changing,
        },
    ]

    if vc in {"IDOR", "Authz", "GraphQL"}:
        requirements.extend([
            {
                "id": "peer-id-swap",
                "endpoint": canonical_endpoint,
                "method": method_u,
                "vuln_class": vc,
                "actor": "peer",
                "object_scope": "other_object_same_org",
                "variant": "id_swap",
                "expected": "deny_or_no_data",
                "redline_required": state_changing,
            },
            {
                "id": "low-role-diff",
                "endpoint": canonical_endpoint,
                "method": method_u,
                "vuln_class": vc,
                "actor": "low_role",
                "object_scope": "own_object",
                "variant": "role_diff",
                "expected": "deny_or_limited",
                "redline_required": state_changing,
            },
            {
                "id": "cross-tenant-diff",
                "endpoint": canonical_endpoint,
                "method": method_u,
                "vuln_class": vc,
                "actor": "cross_tenant",
                "object_scope": "cross_tenant_object",
                "variant": "tenant_diff",
                "expected": "deny_or_no_data",
                "redline_required": state_changing,
            },
        ])

    if vc == "CSRF":
        requirements.extend([
            {
                "id": "csrf-token-missing",
                "endpoint": canonical_endpoint,
                "method": method_u,
                "vuln_class": vc,
                "actor": "owner",
                "object_scope": "own_object",
                "variant": "token_missing",
                "expected": "deny",
                "redline_required": True,
            },
            {
                "id": "csrf-origin-diff",
                "endpoint": canonical_endpoint,
                "method": method_u,
                "vuln_class": vc,
                "actor": "owner",
                "object_scope": "own_object",
                "variant": "origin_diff",
                "expected": "deny",
                "redline_required": True,
            },
        ])
    return requirements


def _entry_matches_requirement(entry: dict, requirement: dict) -> bool:
    return (
        _canonicalize_endpoint(str(entry.get("endpoint") or "")) == requirement["endpoint"]
        and str(entry.get("vuln_class") or "") == requirement["vuln_class"]
        and str(entry.get("actor") or "") == requirement["actor"]
        and str(entry.get("object_scope") or "") == requirement["object_scope"]
        and str(entry.get("variant") or "") == requirement["variant"]
    )


def actor_matrix_status(entries: list[dict], requirements: list[dict]) -> list[dict]:
    rows: list[dict] = []
    for requirement in requirements:
        matches = [entry for entry in entries if _entry_matches_requirement(entry, requirement)]
        status = "missing"
        latest: dict = {}
        if matches:
            latest = matches[-1]
            result = str(latest.get("result") or "")
            if result in COVERING_RESULTS:
                status = "covered"
            elif result == "blocked_redline":
                status = "blocked"
            elif result == "not_applicable":
                status = "not_applicable"
            else:
                status = "pending"
        row = dict(requirement)
        row.update({
            "status": status,
            "latest_result": latest.get("result", "") if latest else "",
            "latest_ts": latest.get("ts", "") if latest else "",
            "evidence_ref": latest.get("evidence_ref", "") if latest else "",
        })
        rows.append(row)
    return rows


def _focus_endpoint_values(focus_endpoints: list[str | dict] | None, entries: list[dict]) -> list[str]:
    values: list[str] = []
    for item in focus_endpoints or []:
        if isinstance(item, dict):
            values.append(str(item.get("endpoint") or item.get("url") or item.get("path") or ""))
        else:
            values.append(str(item or ""))
    for entry in entries[-20:]:
        values.append(str(entry.get("endpoint") or ""))
    return _dedupe([_canonicalize_endpoint(value) for value in values])[:8]


def build_summary(
    repo_root: Path | str,
    *,
    target: str,
    focus_endpoints: list[str | dict] | None = None,
    vuln_classes: list[str] | None = None,
    method: str = "GET",
) -> dict:
    resolved_target = canonical_target_value(target)
    entries = load_entries(repo_root, resolved_target)
    path = ledger_path(repo_root, resolved_target)
    endpoints = _focus_endpoint_values(focus_endpoints, entries)
    selected_vulns = vuln_classes or ["IDOR", "Authz"]
    selected_vulns = _dedupe([normalize_vuln_class(vuln) for vuln in selected_vulns])

    actor_rows: list[dict] = []
    for endpoint in endpoints:
        for vuln in selected_vulns[:3]:
            actor_rows.extend(actor_matrix_status(entries, actor_requirements(endpoint, vuln, method)))
    actor_gaps = [
        row for row in actor_rows
        if row.get("status") in {"missing", "pending", "blocked"}
    ]

    counts = {result: 0 for result in RESULTS}
    redline_unchecked = 0
    for entry in entries:
        result = str(entry.get("result") or "")
        if result in counts:
            counts[result] += 1
        if entry.get("state_changing") and not entry.get("redline_checked"):
            redline_unchecked += 1

    closed_by_key: dict[tuple[str, str], dict] = {}
    for entry in entries:
        result = str(entry.get("result") or "")
        if result not in CLOSED_CELL_RESULTS:
            continue
        endpoint = _canonicalize_endpoint(str(entry.get("endpoint") or entry.get("raw_endpoint") or ""))
        vuln_class = str(entry.get("vuln_class") or "").strip()
        if not endpoint or not vuln_class:
            continue
        closed_by_key[(endpoint, vuln_class)] = {
            "endpoint": endpoint,
            "vuln_class": vuln_class,
            "result": result,
            "ts": str(entry.get("ts") or ""),
            "evidence_ref": str(entry.get("evidence_ref") or ""),
        }

    return {
        "target": resolved_target,
        "path": str(path),
        "path_exists": path.is_file(),
        "entry_count": len(entries),
        "result_counts": counts,
        "redline_unchecked_count": redline_unchecked,
        "closed_cells": list(closed_by_key.values()),
        "recent_entries": entries[-5:],
        "actor_matrix": {
            "endpoint_count": len(endpoints),
            "vuln_classes": selected_vulns,
            "rows": actor_rows[:60],
            "gaps": actor_gaps[:20],
            "gap_count": len(actor_gaps),
            "covered_count": len([row for row in actor_rows if row.get("status") == "covered"]),
        },
        "record_commands": [
            record_command(resolved_target, row)
            for row in actor_gaps[:5]
        ],
    }


def record_command(target: str, row: dict) -> str:
    parts = [
        "python3",
        "tools/evidence_ledger.py",
        "record",
        "--target",
        target,
        "--endpoint",
        str(row.get("endpoint") or ""),
        "--method",
        str(row.get("method") or "GET"),
        "--vuln-class",
        str(row.get("vuln_class") or "IDOR"),
        "--actor",
        str(row.get("actor") or "owner"),
        "--object-scope",
        str(row.get("object_scope") or "unknown"),
        "--variant",
        str(row.get("variant") or "baseline"),
        "--result",
        "tested_clean",
        "--notes",
        "observed expected authz/object-boundary behavior",
    ]
    if row.get("redline_required"):
        parts.append("--redline-checked")
    return " ".join(_quote(part) for part in parts)


def format_summary(summary: dict) -> str:
    matrix = summary.get("actor_matrix") or {}
    counts = summary.get("result_counts") or {}
    lines = [
        "EVIDENCE LEDGER",
        f"- Target: {summary.get('target', '')}",
        f"- Entries: {summary.get('entry_count', 0)}",
        f"- Ledger path: {summary.get('path', '')}",
        f"- Red-line unchecked state-changing records: {summary.get('redline_unchecked_count', 0)}",
        "- Results:",
    ]
    for result in RESULTS:
        lines.append(f"  - {result}: {counts.get(result, 0)}")

    lines.extend([
        "- Recent entries:",
    ])
    recent = summary.get("recent_entries") or []
    if recent:
        for entry in recent[-5:]:
            lines.append(
                "  - {method} {endpoint} x {vuln} {actor}/{scope}/{variant} -> {result}".format(
                    method=entry.get("method", ""),
                    endpoint=entry.get("endpoint", ""),
                    vuln=entry.get("vuln_class", ""),
                    actor=entry.get("actor", ""),
                    scope=entry.get("object_scope", ""),
                    variant=entry.get("variant", ""),
                    result=entry.get("result", ""),
                )
            )
    else:
        lines.append("  - none")

    lines.extend([
        "- Actor matrix gaps:",
    ])
    gaps = matrix.get("gaps") or []
    if gaps:
        for row in gaps[:8]:
            redline = " redline-required" if row.get("redline_required") else ""
            lines.append(
                "  - {endpoint} x {vuln}: {actor}/{scope}/{variant} expected={expected} status={status}{redline}".format(
                    endpoint=row.get("endpoint", ""),
                    vuln=row.get("vuln_class", ""),
                    actor=row.get("actor", ""),
                    scope=row.get("object_scope", ""),
                    variant=row.get("variant", ""),
                    expected=row.get("expected", ""),
                    status=row.get("status", ""),
                    redline=redline,
                )
            )
    else:
        lines.append("  - none")

    lines.extend(["- Record commands:"])
    commands = summary.get("record_commands") or []
    if commands:
        for command in commands[:5]:
            lines.append(f"  - {command}")
    else:
        lines.append("  - none")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evidence ledger and actor matrix for one target.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_record = sub.add_parser("record", help="append one explicit evidence ledger entry")
    p_record.add_argument("--target", required=True)
    p_record.add_argument("--endpoint", required=True)
    p_record.add_argument("--method", default="GET")
    p_record.add_argument("--vuln-class", default="IDOR")
    p_record.add_argument("--workflow", default="")
    p_record.add_argument("--actor", default="owner")
    p_record.add_argument("--object-scope", default="unknown")
    p_record.add_argument("--variant", default="baseline")
    p_record.add_argument("--source", default="manual")
    p_record.add_argument("--result", default="lead", choices=list(RESULTS))
    p_record.add_argument("--browser-observed", action="store_true")
    p_record.add_argument("--replayed", action="store_true")
    p_record.add_argument("--state-changing", action="store_true")
    p_record.add_argument("--redline-checked", action="store_true")
    p_record.add_argument("--evidence-ref", default="")
    p_record.add_argument("--notes", default="")
    p_record.add_argument("--repo-root", default=str(BASE_DIR))
    p_record.add_argument("--json", action="store_true")

    p_summary = sub.add_parser("summary", help="read ledger summary and actor matrix gaps")
    p_summary.add_argument("--target", required=True)
    p_summary.add_argument("--endpoint", action="append", default=[])
    p_summary.add_argument("--vuln-class", action="append", default=[])
    p_summary.add_argument("--method", default="GET")
    p_summary.add_argument("--repo-root", default=str(BASE_DIR))
    p_summary.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.cmd == "record":
        entry = record_entry(
            args.repo_root,
            target=args.target,
            endpoint=args.endpoint,
            method=args.method,
            vuln_class=args.vuln_class,
            workflow=args.workflow,
            actor=args.actor,
            object_scope=args.object_scope,
            variant=args.variant,
            source=args.source,
            result=args.result,
            browser_observed=args.browser_observed,
            replayed=args.replayed,
            state_changing=args.state_changing,
            redline_checked=args.redline_checked,
            evidence_ref=args.evidence_ref,
            notes=args.notes,
        )
        if args.json:
            print(json.dumps(entry, ensure_ascii=False, indent=2))
        else:
            print(f"evidence ledger recorded: {entry['method']} {entry['endpoint']} x {entry['vuln_class']} -> {entry['result']}")
        return 0

    if args.cmd == "summary":
        summary = build_summary(
            args.repo_root,
            target=args.target,
            focus_endpoints=args.endpoint,
            vuln_classes=args.vuln_class or None,
            method=args.method,
        )
        if args.json:
            print(json.dumps(summary, ensure_ascii=False, indent=2))
        else:
            print(format_summary(summary))
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
