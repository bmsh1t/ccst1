#!/usr/bin/env python3
"""记录 endpoint 级测试账本，并生成角色/对象差异矩阵。

Evidence Ledger 补 coverage_matrix 没覆盖到的一层：同一个 endpoint 是否
真的做过匿名、owner、peer、低权限、跨租户等差异验证。默认 summary 只读；
当前查询使用 Store；旧 JSONL 仅供显式历史检查和迁移。
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

try:
    from tools.evidence_identity import (
        ACTOR_ALIASES,
        OBJECT_ALIASES,
        VARIANT_ALIASES,
        normalize_actor,
        normalize_object_scope,
        normalize_variant,
        CLOSED_LEDGER_RESULTS,
        COVERING_RESULTS,
        LEDGER_RESULTS,
        canonical_endpoint_identity,
        normalize_family,
        observation_supports_coverage,
    )
    from tools.target_paths import canonical_target_value, target_storage_key
except ImportError:  # pragma: no cover - direct tools/ execution
    from evidence_identity import (  # type: ignore
        ACTOR_ALIASES,
        OBJECT_ALIASES,
        VARIANT_ALIASES,
        normalize_actor,
        normalize_object_scope,
        normalize_variant,
        CLOSED_LEDGER_RESULTS,
        COVERING_RESULTS,
        LEDGER_RESULTS,
        canonical_endpoint_identity,
        normalize_family,
        observation_supports_coverage,
    )
    from target_paths import canonical_target_value, target_storage_key  # type: ignore


SCHEMA_VERSION = 1
# Terminal vocabulary is defined once in evidence_identity and shared with
# Closure; the Ledger owns which of these are observed terminal results.
RESULTS = LEDGER_RESULTS
ACTOR_MATRIX_VULN_CLASSES = frozenset({"IDOR", "Authz", "GraphQL", "CSRF"})
CLOSED_CELL_RESULTS = set(CLOSED_LEDGER_RESULTS)

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
    return canonical_endpoint_identity(value)


def normalize_result(value: str) -> str:
    result = str(value or "").strip().lower().replace("-", "_")
    if result not in RESULTS:
        raise ValueError(f"unknown result: {value!r}. Allowed: {', '.join(RESULTS)}")
    return result


def normalize_ledger_vuln_class(value: str) -> str:
    """Admit open evidence families without widening canonical Coverage."""
    return normalize_family(value)


def load_entries_diagnostic(repo_root: Path | str, target: str) -> dict:
    path = ledger_path(repo_root, target)
    if not path.is_file():
        return {
            "status": "missing",
            "path": str(path),
            "entries": [],
            "invalid_rows": [],
            "invalid_count": 0,
            "last_valid_offset": 0,
        }
    entries: list[dict] = []
    invalid_rows: list[dict] = []
    offset = 0
    last_valid_offset = 0
    valid_prefix = True
    try:
        with path.open("rb") as handle:
            for line_number, raw_line in enumerate(handle, 1):
                offset += len(raw_line)
                if not raw_line.strip():
                    if valid_prefix:
                        last_valid_offset = offset
                    continue
                try:
                    value = raw_line.decode("utf-8").strip()
                    item = json.loads(value)
                except UnicodeDecodeError:
                    invalid_rows.append({"line": line_number, "reason": "invalid UTF-8"})
                    valid_prefix = False
                    continue
                except json.JSONDecodeError as exc:
                    invalid_rows.append({"line": line_number, "reason": exc.msg[:160]})
                    valid_prefix = False
                    continue
                if not isinstance(item, dict):
                    invalid_rows.append({"line": line_number, "reason": "row is not a JSON object"})
                    valid_prefix = False
                    continue
                if not valid_prefix:
                    continue
                entries.append(item)
                last_valid_offset = offset
    except OSError as exc:
        return {
            "status": "unreadable",
            "path": str(path),
            "entries": [],
            "invalid_rows": [],
            "invalid_count": 0,
            "last_valid_offset": 0,
            "read_error": str(exc)[:300],
        }
    return {
        "status": "partial" if invalid_rows else "valid",
        "path": str(path),
        "entries": entries,
        "invalid_rows": invalid_rows[:20],
        "invalid_count": len(invalid_rows),
        "last_valid_offset": last_valid_offset,
    }


def load_entries(repo_root: Path | str, target: str) -> list[dict]:
    diagnostic = load_entries_diagnostic(repo_root, target)
    if diagnostic.get("read_error"):
        print(
            f"warning: evidence ledger unreadable: {diagnostic['path']}: {diagnostic['read_error']}",
            file=sys.stderr,
        )
    for item in (diagnostic.get("invalid_rows") or [])[:5]:
        print(
            f"warning: evidence ledger invalid row: {diagnostic['path']}:{item['line']}: {item['reason']}",
            file=sys.stderr,
        )
    return list(diagnostic.get("entries") or [])


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
    "image", "list", "login", "logout", "manage", "management", "metadata",
    "new", "photo", "picture", "preview", "reset-password", "search", "select",
    "settings", "signup", "track-order", "update", "url", "version", "whoami",
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


def actor_requirements(
    endpoint: str,
    vuln_class: str = "IDOR",
    method: str = "GET",
) -> list[dict]:
    """返回高级 authz/IDOR 测试应覆盖的角色/对象差异项。"""
    canonical_endpoint = _canonicalize_endpoint(endpoint)
    vc = normalize_ledger_vuln_class(vuln_class)
    method_u = str(method or "GET").strip().upper()
    # actor matrix 只服务“角色/对象边界”类验证。像 Upload/SSRF/SQLi 即使落在
    # admin path 上，也不应自动生成 anonymous/owner/peer 这类 actor-gap，
    # 否则 checkpoint 会不断推送无意义待办。
    if vc not in ACTOR_MATRIX_VULN_CLASSES:
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
            },
        ])
    return requirements


def _entry_requirement_key(entry: dict) -> tuple[str, str, str, str, str, str]:
    """One requirement-matching key per entry (single canonicalize per entry)."""
    return (
        _canonicalize_endpoint(str(entry.get("endpoint") or "")),
        str(entry.get("method") or "GET").upper(),
        str(entry.get("vuln_class") or ""),
        str(entry.get("actor") or ""),
        str(entry.get("object_scope") or ""),
        str(entry.get("variant") or ""),
    )


def actor_matrix_status(
    entries: list[dict], requirements: list[dict], *,
    invalid_event_ids: frozenset[str] | None = frozenset(),
) -> list[dict]:
    # 单次调用内建索引：每个 entry 只 canonicalize 一次，requirement 查 dict。
    # 语义与逐对 _entry_matches_requirement 完全一致（latest-wins：同 key 的
    # 后写条目覆盖先写），owner 写入后随调用结束失效，无持久缓存。
    indexed: dict[tuple[str, str, str, str, str, str], dict] = {}
    for entry in entries:
        if entry.get("superseded"):
            continue
        indexed[_entry_requirement_key(entry)] = entry
    rows: list[dict] = []
    for requirement in requirements:
        latest = indexed.get((
            requirement["endpoint"],
            requirement["method"],
            requirement["vuln_class"],
            requirement["actor"],
            requirement["object_scope"],
            requirement["variant"],
        ))
        status = "missing"
        if latest:
            result = str(latest.get("result") or "")
            # Check the selected result; filtering damaged history would revive older evidence.
            if (invalid_event_ids is None or latest.get("event_id") in invalid_event_ids
                    or not observation_supports_coverage(latest)):
                status = "pending"
            elif result in COVERING_RESULTS:
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
    _truth: dict | None = None,
) -> dict:
    resolved_target = canonical_target_value(target)
    # 调用方若已持有「当前真源」seam 结果（checkpoint → context_pack → 此处 →
    # 自身 aggregate），直接复用同一次读取与同一份闭合投影：不再自行读盘、
    # 也不再重新推导闭合单元，否则同一轮会出现两份可分歧的闭合答案。
    # 快照只在单次构建内有效；owner 写入后由下次调用自然失效。
    truth = _truth if isinstance(_truth, dict) and _truth.get("records") is not None else None
    if truth is None:
        # 没有现成快照时也走同一读口，直接调用者不会拿到第二份闭合答案。
        # 函数级 import：current_truth 在模块级导入本模块。
        try:
            from tools.current_truth import current_cell_projection
        except ImportError:  # pragma: no cover - direct tools/ execution
            from current_truth import current_cell_projection  # type: ignore
        truth = current_cell_projection(repo_root, resolved_target)
    diagnostics = {**dict(truth.get("health") or {}), "entries": list(truth["records"])}
    entries = list(diagnostics.get("entries") or [])
    invalid_event_ids = truth["invalid_event_ids"]
    invalid_event_ids = frozenset(invalid_event_ids) if invalid_event_ids is not None else None
    endpoints = _focus_endpoint_values(focus_endpoints, entries)
    # ``None`` keeps the legacy caller default; an explicit empty list means
    # no owner-backed actor-matrix classes for this projection.
    selected_vulns = ["IDOR", "Authz"] if vuln_classes is None else list(vuln_classes)
    selected_vulns = _dedupe([normalize_ledger_vuln_class(vuln) for vuln in selected_vulns])

    actor_rows: list[dict] = []
    for endpoint in endpoints:
        for vuln in selected_vulns[:3]:
            actor_rows.extend(actor_matrix_status(
                entries, actor_requirements(endpoint, vuln, method), invalid_event_ids=invalid_event_ids,
            ))
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

    # 闭合单元直接取真源投影：损伤抑制（closed_cells 清空 + 两个 suppressed 计数）
    # 由 `closure_projection.suppress_unauthorized_closures` 唯一定义，此处不重述。
    current_cells = dict(truth.get("projection") or {})
    source = dict(truth.get("source") or {})
    label = str(source.get("path_label") or "").strip()
    if label:
        path = Path(repo_root) / label
        path_exists = str(source.get("status") or "").strip().lower() != "missing"
    else:  # pragma: no cover - the seam always labels its source
        path = ledger_path(repo_root, resolved_target)
        path_exists = path.is_file()

    summary = {
        "target": resolved_target,
        "path": str(path),
        "path_exists": path_exists,
        "entry_count": len(entries),
        "evidence_source": source,
        "ledger_status": diagnostics.get("status", "missing"),
        "ledger_diagnostics": {
            key: diagnostics[key]
            for key in ("status", "source_kind", "invalid_count", "invalid_rows", "last_valid_offset", "read_error")
            if key in diagnostics
        },
        "result_counts": counts,
        "redline_unchecked_count": redline_unchecked,
        "closed_cells": current_cells["closed_cells"],
        "closed_cells_v2": current_cells.get("closed_cells_v2", []),
        "open_candidates": current_cells["open_candidates"],
        "open_candidates_v2": current_cells.get("open_candidates_v2", []),
        "identity_v2_follow_up_actions": current_cells.get("identity_v2_follow_up_actions", []),
        "identity_v2_diagnostics": current_cells.get("identity_v2_diagnostics", {}),
        "identity_v2_shadow": current_cells.get("identity_v2_shadow", {}),
        "recent_entries": entries[-5:],
        "actor_matrix": {
            "endpoint_count": len(endpoints),
            "vuln_classes": selected_vulns,
            "rows": actor_rows[:60],
            "gaps": actor_gaps[:20],
            "gap_count": len(actor_gaps),
            "covered_count": len([row for row in actor_rows if row.get("status") == "covered"]),
        },
        "record_commands": [],
    }
    return summary


def format_summary(summary: dict) -> str:
    matrix = summary.get("actor_matrix") or {}
    counts = summary.get("result_counts") or {}
    lines = [
        "EVIDENCE LEDGER",
        f"- Target: {summary.get('target', '')}",
        f"- Entries: {summary.get('entry_count', 0)}",
        f"- Ledger path: {summary.get('path', '')}",
        f"- Ledger status: {summary.get('ledger_status', 'missing')}",
        f"- Invalid rows: {(summary.get('ledger_diagnostics') or {}).get('invalid_count', 0)}",
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
            lines.append(
                "  - {endpoint} x {vuln}: {actor}/{scope}/{variant} expected={expected} status={status}".format(
                    endpoint=row.get("endpoint", ""),
                    vuln=row.get("vuln_class", ""),
                    actor=row.get("actor", ""),
                    scope=row.get("object_scope", ""),
                    variant=row.get("variant", ""),
                    expected=row.get("expected", ""),
                    status=row.get("status", ""),
                )
            )
    else:
        lines.append("  - none")

    lines.append("- Register existing observations: python3 tools/validation_runner.py record-evidence --help")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evidence ledger and actor matrix for one target.")
    sub = parser.add_subparsers(dest="cmd", required=True)

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
    if args.cmd == "summary":
        try:
            summary = build_summary(
                args.repo_root,
                target=args.target,
                focus_endpoints=args.endpoint,
                vuln_classes=args.vuln_class or None,
                method=args.method,
            )
        except (OSError, ValueError) as exc:
            print(f"evidence-ledger: {exc}", file=sys.stderr)
            return 2
        if args.json:
            print(json.dumps(summary, ensure_ascii=False, indent=2))
        else:
            print(format_summary(summary))
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
