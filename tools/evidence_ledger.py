#!/usr/bin/env python3
"""记录 endpoint 级测试账本，并生成角色/对象差异矩阵。

Evidence Ledger 补 coverage_matrix 没覆盖到的一层：同一个 endpoint 是否
真的做过匿名、owner、peer、低权限、跨租户等差异验证。默认 summary 只读；
只有 record 子命令会追加写入 `memory/evidence/<target>/ledger.jsonl`。
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import shlex
import sys
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

BASE_DIR = Path(__file__).resolve().parents[1]
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

try:
    from tools.closure_resolver import canonical_endpoint_identity
    from tools.coverage_matrix import normalize_vuln_class
    from tools.identity_contract import (
        ClosureCellKey,
        build_closure_cell,
        validate_identity_candidate,
    )
    from tools.target_paths import canonical_target_value, target_storage_key
except ImportError:  # pragma: no cover - direct tools/ execution
    from closure_resolver import canonical_endpoint_identity  # type: ignore
    from coverage_matrix import normalize_vuln_class  # type: ignore
    from identity_contract import (  # type: ignore
        ClosureCellKey,
        build_closure_cell,
        validate_identity_candidate,
    )
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
CLOSED_CELL_RESULTS = {"tested_clean", "tested_finding", "dead_end", "blocked_redline", "not_applicable"}

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


@contextmanager
def ledger_mutation_lock(repo_root: Path | str, target: str):
    """Serialize one target's append without creating a second state owner."""
    path = ledger_path(repo_root, target)
    lock_path = path.parent / ".locks" / "ledger.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


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


def normalize_ledger_vuln_class(value: str) -> str:
    """Normalize Ledger families without widening Coverage Matrix's enum."""
    if str(value or "").strip().lower() == "workflow":
        return "Workflow"
    return normalize_vuln_class(value)


def _identity_fact_conflicts(key: ClosureCellKey, entry: Mapping[str, Any]) -> tuple[str, ...]:
    """Reject a planned key that disagrees with durable Ledger facts."""
    conflicts: list[str] = []
    if key.endpoint != str(entry.get("endpoint") or ""):
        conflicts.append("endpoint_mismatch")
    if key.family != str(entry.get("vuln_class") or ""):
        conflicts.append("family_mismatch")
    dimensions = key.dimension_map
    method = str(entry.get("method") or "").upper()
    if "method" in dimensions and dimensions["method"] != method:
        conflicts.append("method_mismatch")
    return tuple(sorted(set(conflicts)))


def _identity_follow_up_action(
    entry: Mapping[str, Any],
    *,
    missing_fields: tuple[str, ...] | list[str] = (),
    conflicts: tuple[str, ...] | list[str] = (),
    evidence_refs: tuple[str, ...] | list[str] = (),
) -> dict[str, Any]:
    refs = _dedupe([
        *(str(item) for item in evidence_refs),
        str(entry.get("evidence_ref") or ""),
    ])
    return {
        "kind": "identity_follow_up",
        "family": str(entry.get("vuln_class") or ""),
        "endpoint": str(entry.get("endpoint") or ""),
        "missing_fields": sorted(set(missing_fields)),
        "conflicts": sorted(set(conflicts)),
        "evidence_refs": refs,
    }


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
    state_changing: bool | None = False,
    redline_checked: bool = False,
    evidence_ref: str = "",
    notes: str = "",
    operation_id: str = "",
    event_id: str = "",
    identity_v2: Mapping[str, Any] | ClosureCellKey | None = None,
    identity_dimensions: Mapping[str, Any] | None = None,
    identity_candidate: Mapping[str, Any] | None = None,
    identity_replaces_event_id: str = "",
) -> dict:
    resolved_target = canonical_target_value(target)
    canonical_endpoint = _canonicalize_endpoint(endpoint)
    if not canonical_endpoint:
        raise ValueError("endpoint is required")

    method_u = str(method or "GET").strip().upper()
    normalized_vuln = normalize_ledger_vuln_class(vuln_class)
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
        "state_changing": (
            None
            if state_changing is None
            else bool(state_changing)
        ),
        "redline_checked": bool(redline_checked),
        "evidence_ref": str(evidence_ref or "").strip(),
        "notes": str(notes or "").strip(),
        "operation_id": str(operation_id or "").strip(),
        "event_id": str(event_id or "").strip(),
        "warnings": [],
    }
    if sum(value is not None for value in (identity_v2, identity_candidate, identity_dimensions)) > 1:
        raise ValueError("provide only one of identity_v2, identity_candidate, or identity_dimensions")
    if (
        identity_v2 is not None
        and not isinstance(identity_v2, Mapping)
        and not callable(getattr(identity_v2, "to_dict", None))
    ):
        raise ValueError("identity_v2 must be a closure identity object")
    if identity_candidate is not None and not isinstance(identity_candidate, Mapping):
        raise ValueError("identity_candidate must be an object")
    if identity_dimensions is not None and not isinstance(identity_dimensions, Mapping):
        raise ValueError("identity_dimensions must be an object")
    if identity_v2 is not None:
        identity_payload = (
            identity_v2.to_dict()
            if callable(getattr(identity_v2, "to_dict", None))
            else identity_v2
        )
        identity_key = ClosureCellKey.from_dict(identity_payload)
        conflicts = _identity_fact_conflicts(identity_key, entry)
        entry["identity_status"] = "conflict" if conflicts else "complete"
        entry["identity_missing_fields"] = []
        entry["identity_conflicts"] = list(conflicts)
        if conflicts:
            entry["identity_follow_up_action"] = _identity_follow_up_action(
                entry,
                conflicts=conflicts,
            )
        else:
            entry["identity_v2"] = identity_key.to_dict()
    elif identity_candidate is not None:
        candidate_validation = validate_identity_candidate(identity_candidate)
        candidate = candidate_validation.candidate
        entry["identity_candidate"] = candidate.to_dict()
        fact_conflicts = (
            _identity_fact_conflicts(candidate_validation.identity, entry)
            if candidate_validation.identity is not None
            else ()
        )
        if candidate.endpoint and candidate.endpoint != canonical_endpoint:
            fact_conflicts = (*fact_conflicts, "endpoint_mismatch")
        if candidate.family and candidate.family != normalized_vuln:
            fact_conflicts = (*fact_conflicts, "family_mismatch")
        candidate_method = str(candidate.dimensions.get("method") or "").upper()
        if candidate_method and candidate_method != method_u:
            fact_conflicts = (*fact_conflicts, "method_mismatch")
        fact_conflicts = tuple(sorted(set(fact_conflicts)))
        conflicts = tuple(sorted(set((*candidate.conflicts, *fact_conflicts))))
        if candidate_validation.closeable and not conflicts:
            entry["identity_v2"] = candidate_validation.identity.to_dict()
            entry["identity_status"] = "complete"
        else:
            entry["identity_status"] = "conflict" if fact_conflicts else "follow_up_required"
            entry["identity_missing_fields"] = list(candidate.missing_fields)
            entry["identity_conflicts"] = list(conflicts)
            entry["identity_follow_up_action"] = _identity_follow_up_action(
                entry,
                missing_fields=candidate.missing_fields,
                conflicts=conflicts,
                evidence_refs=candidate.evidence_refs,
            )
    elif identity_dimensions is not None:
        identity_result = build_closure_cell(
            canonical_endpoint,
            normalized_vuln,
            identity_dimensions,
        )
        fact_conflicts = (
            _identity_fact_conflicts(identity_result.key, entry)
            if identity_result.key is not None
            else ()
        )
        conflicts = tuple(sorted(set((*identity_result.conflicts, *fact_conflicts))))
        entry["identity_status"] = (
            "complete"
            if identity_result.complete and not conflicts
            else "conflict"
            if conflicts
            else "incomplete"
        )
        entry["identity_missing_fields"] = list(identity_result.missing_fields)
        entry["identity_conflicts"] = list(conflicts)
        if identity_result.key is not None and not conflicts:
            entry["identity_v2"] = identity_result.key.to_dict()
        if conflicts:
            entry["identity_follow_up_action"] = _identity_follow_up_action(
                entry,
                missing_fields=identity_result.missing_fields,
                conflicts=conflicts,
            )
    requires_redline = method_u == "PATCH" and bool(entry["state_changing"])
    if requires_redline and not entry["redline_checked"] and normalized_result in COVERING_RESULTS:
        entry["requested_result"] = normalized_result
        entry["result"] = "blocked_redline"
        entry["redline_decision"] = "blocked"
        entry["warnings"].append("redline_check_missing_for_state_changing_test")
    elif entry["redline_checked"]:
        entry["redline_decision"] = "allowed"
    elif entry["result"] == "blocked_redline":
        entry["redline_decision"] = "blocked"

    path = ledger_path(repo_root, resolved_target)
    with ledger_mutation_lock(repo_root, resolved_target):
        replacement_event_id = str(identity_replaces_event_id or "").strip()
        existing_entries: list[dict] = []
        if entry["event_id"] or replacement_event_id:
            diagnostic = load_entries_diagnostic(repo_root, resolved_target)
            existing_entries = list(diagnostic.get("entries") or [])
        if entry["event_id"]:
            existing = next(
                (
                    item
                    for item in existing_entries
                    if str(item.get("event_id") or "") == entry["event_id"]
                ),
                None,
            )
            if existing is not None:
                return {**existing, "write_status": "deduplicated"}
        if replacement_event_id:
            if str(entry.get("identity_status") or "") != "complete":
                raise ValueError("identity replacement requires a complete new identity")
            replaced = next(
                (
                    item
                    for item in existing_entries
                    if str(item.get("event_id") or "") == replacement_event_id
                ),
                None,
            )
            if replaced is None or "identity_status" not in replaced:
                raise ValueError(f"identity replacement event not found: {replacement_event_id}")
            if (
                str(replaced.get("endpoint") or "") != entry["endpoint"]
                or str(replaced.get("vuln_class") or "") != entry["vuln_class"]
            ):
                raise ValueError("identity replacement must keep the same endpoint and vulnerability family")
            entry["identity_replacement"] = {
                "event_id": replacement_event_id,
                "evidence_ref": str(replaced.get("evidence_ref") or ""),
                "identity_v2": replaced.get("identity_v2") if isinstance(replaced.get("identity_v2"), dict) else None,
            }
        path.parent.mkdir(parents=True, exist_ok=True)
        encoded = (json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
        with path.open("ab", buffering=0) as fh:
            if fh.write(encoded) != len(encoded):
                raise OSError(f"partial evidence ledger append: {path}")
            os.fsync(fh.fileno())
    return {**entry, "write_status": "updated"}


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


def actor_requirements(endpoint: str, vuln_class: str = "IDOR", method: str = "GET") -> list[dict]:
    """返回高级 authz/IDOR 测试应覆盖的角色/对象差异项。"""
    canonical_endpoint = _canonicalize_endpoint(endpoint)
    vc = normalize_ledger_vuln_class(vuln_class)
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
        and str(entry.get("method") or "GET").upper() == requirement["method"]
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


def _entry_closure_identity(entry: Mapping[str, Any]) -> ClosureCellKey | None:
    if str(entry.get("identity_status") or "") != "complete":
        return None
    payload = entry.get("identity_v2")
    if not isinstance(payload, Mapping):
        return None
    try:
        return ClosureCellKey.from_dict(payload)
    except (TypeError, ValueError, KeyError):
        return None


def _replaced_identity_event_ids(entries: list[dict]) -> set[str]:
    return {
        str(replacement.get("event_id") or "")
        for entry in entries
        for replacement in [entry.get("identity_replacement")]
        if str(entry.get("identity_status") or "") == "complete"
        and isinstance(replacement, Mapping)
        and str(replacement.get("event_id") or "")
    }


def _project_v2_cells(entries: list[dict]) -> tuple[list[dict], list[dict]]:
    """Project only complete v2 identities; legacy rows never enter this view."""
    replaced_event_ids = _replaced_identity_event_ids(entries)
    current: dict[str, tuple[int, ClosureCellKey, dict]] = {}
    for sequence, entry in enumerate(entries):
        if str(entry.get("event_id") or "") in replaced_event_ids:
            continue
        key = _entry_closure_identity(entry)
        if key is None or str(entry.get("result") or "") not in RESULTS:
            continue
        current[key.identity_key] = (sequence, key, entry)

    closed: list[dict] = []
    open_candidates: list[dict] = []
    for _identity_key, (_sequence, key, entry) in current.items():
        result = str(entry.get("result") or "")
        if result == "candidate":
            open_candidates.append(entry)
        if result in {"lead", "signal", "candidate"}:
            continue
        if result not in CLOSED_CELL_RESULTS:
            continue
        closed.append({
            "identity_v2": key.to_dict(),
            "endpoint": key.endpoint,
            "vuln_class": key.family,
            "dimensions": key.dimension_map,
            "result": result,
            "ts": str(entry.get("ts") or ""),
            "evidence_ref": str(entry.get("evidence_ref") or ""),
        })
    return closed, sorted(
        open_candidates,
        key=lambda item: str(item.get("ts") or ""),
        reverse=True,
    )[:10]


def _project_identity_follow_ups(entries: list[dict], replaced_event_ids: set[str]) -> list[dict]:
    rows = [
        entry
        for entry in entries
        if str(entry.get("identity_status") or "") in {"conflict", "follow_up_required"}
        and isinstance(entry.get("identity_follow_up_action"), Mapping)
        and str(entry.get("event_id") or "") not in replaced_event_ids
    ]
    return [
        {
            **dict(entry["identity_follow_up_action"]),
            "ts": str(entry.get("ts") or ""),
            "event_id": str(entry.get("event_id") or ""),
        }
        for entry in sorted(rows, key=lambda item: str(item.get("ts") or ""), reverse=True)[:10]
    ]


def _identity_shadow_diff(closed_cells: list[dict], closed_cells_v2: list[dict]) -> dict[str, Any]:
    legacy_keys = {
        (str(cell.get("endpoint") or ""), str(cell.get("vuln_class") or ""))
        for cell in closed_cells
    }
    v2_keys = {
        (str(cell.get("endpoint") or ""), str(cell.get("vuln_class") or ""))
        for cell in closed_cells_v2
    }
    legacy_only = [
        {"endpoint": endpoint, "vuln_class": family}
        for endpoint, family in sorted(legacy_keys - v2_keys)
    ]
    v2_only = [
        cell
        for cell in closed_cells_v2
        if (str(cell.get("endpoint") or ""), str(cell.get("vuln_class") or ""))
        in v2_keys - legacy_keys
    ]
    scope_mismatches = [
        {
            "endpoint": endpoint,
            "vuln_class": family,
            "legacy_scope": "endpoint_family",
            "v2_cells": [
                cell["identity_v2"]
                for cell in closed_cells_v2
                if str(cell.get("endpoint") or "") == endpoint
                and str(cell.get("vuln_class") or "") == family
            ],
        }
        for endpoint, family in sorted(legacy_keys & v2_keys)
    ]
    return {
        "status": "compared",
        "different": bool(legacy_only or v2_only or scope_mismatches),
        "legacy_closed_count": len(closed_cells),
        "v2_closed_count": len(closed_cells_v2),
        "legacy_only": legacy_only,
        "v2_only": v2_only,
        "scope_mismatches": scope_mismatches,
    }


def _project_legacy_cells(
    entries: list[dict],
    *,
    include_identity_rows: bool,
) -> tuple[list[dict], list[dict]]:
    current_by_evidence_key: dict[tuple[str, str, str, str, str, str], tuple[int, dict]] = {}
    for sequence, entry in enumerate(entries):
        if not include_identity_rows and "identity_status" in entry:
            continue
        result = str(entry.get("result") or "")
        if result not in RESULTS:
            continue
        endpoint = _canonicalize_endpoint(
            str(entry.get("raw_endpoint") or entry.get("endpoint") or "")
        )
        vuln_class = str(entry.get("vuln_class") or "").strip()
        if not endpoint or not vuln_class:
            continue
        evidence_key = (
            endpoint,
            vuln_class,
            str(entry.get("method") or "GET").strip().upper(),
            str(entry.get("actor") or "owner").strip(),
            str(entry.get("object_scope") or "unknown").strip(),
            str(entry.get("variant") or "baseline").strip(),
        )
        current_by_evidence_key[evidence_key] = (sequence, entry)

    current_by_closure_key: dict[tuple[str, str], list[tuple[int, dict]]] = {}
    for evidence_key, current in current_by_evidence_key.items():
        current_by_closure_key.setdefault(evidence_key[:2], []).append(current)

    closed_cells: list[dict] = []
    open_candidates: list[dict] = []
    for (endpoint, vuln_class), current_rows in current_by_closure_key.items():
        open_rows = [
            item for item in current_rows
            if str(item[1].get("result") or "") in {"lead", "signal", "candidate"}
        ]
        open_candidates.extend(
            entry for _sequence, entry in open_rows
            if str(entry.get("result") or "") == "candidate"
        )
        if open_rows:
            continue
        terminal_rows = [
            item for item in current_rows
            if str(item[1].get("result") or "") in CLOSED_CELL_RESULTS
        ]
        if not terminal_rows:
            continue
        _sequence, latest = max(terminal_rows, key=lambda item: item[0])
        closed_cells.append({
            "endpoint": endpoint,
            "vuln_class": vuln_class,
            "result": str(latest.get("result") or ""),
            "ts": str(latest.get("ts") or ""),
            "evidence_ref": str(latest.get("evidence_ref") or ""),
        })
    return closed_cells, open_candidates


def build_current_cell_projection(entries: list[dict]) -> dict:
    """Project current evidence identities and retain a v2 closure projection.

    ``closed_cells`` remains the legacy endpoint projection for old readers.
    ``closed_cells_v2`` is the only projection allowed to close a complete
    family-aware identity.
    """
    closed_cells, open_candidates = _project_legacy_cells(
        entries,
        include_identity_rows=False,
    )
    shadow_legacy_cells, _shadow_candidates = _project_legacy_cells(
        entries,
        include_identity_rows=True,
    )
    closed_cells_v2, open_candidates_v2 = _project_v2_cells(entries)
    replaced_event_ids = _replaced_identity_event_ids(entries)
    identity_v2_incomplete = sum(
        1
        for entry in entries
        if str(entry.get("identity_status") or "") in {"incomplete", "follow_up_required", "conflict"}
        and str(entry.get("event_id") or "") not in replaced_event_ids
    )
    identity_v2_follow_ups = _project_identity_follow_ups(entries, replaced_event_ids)
    return {
        "closed_cells": closed_cells,
        "closed_cells_v2": closed_cells_v2,
        "open_candidates": sorted(
            open_candidates,
            key=lambda item: str(item.get("ts") or ""),
            reverse=True,
        )[:10],
        "open_candidates_v2": open_candidates_v2,
        "identity_v2_follow_up_actions": identity_v2_follow_ups,
        "identity_v2_diagnostics": {
            "incomplete_count": identity_v2_incomplete,
            "closed_count": len(closed_cells_v2),
            "follow_up_count": len(identity_v2_follow_ups),
            "replacement_count": len(replaced_event_ids),
        },
        "identity_v2_shadow": _identity_shadow_diff(shadow_legacy_cells, closed_cells_v2),
    }


def build_summary(
    repo_root: Path | str,
    *,
    target: str,
    focus_endpoints: list[str | dict] | None = None,
    vuln_classes: list[str] | None = None,
    method: str = "GET",
) -> dict:
    resolved_target = canonical_target_value(target)
    diagnostics = load_entries_diagnostic(repo_root, resolved_target)
    entries = list(diagnostics.get("entries") or [])
    path = ledger_path(repo_root, resolved_target)
    endpoints = _focus_endpoint_values(focus_endpoints, entries)
    selected_vulns = vuln_classes or ["IDOR", "Authz"]
    selected_vulns = _dedupe([normalize_ledger_vuln_class(vuln) for vuln in selected_vulns])

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

    current_cells = build_current_cell_projection(entries)
    if diagnostics.get("status") in {"partial", "unreadable"}:
        current_cells["closed_cells"] = []
        current_cells["closed_cells_v2"] = []
        identity_diagnostics = dict(current_cells.get("identity_v2_diagnostics") or {})
        identity_diagnostics["suppressed_closed_count"] = int(identity_diagnostics.get("closed_count", 0) or 0)
        identity_diagnostics["closed_count"] = 0
        current_cells["identity_v2_diagnostics"] = identity_diagnostics
        current_cells["identity_v2_shadow"] = {
            "status": "unavailable",
            "reason": f"ledger_{diagnostics.get('status')}",
        }

    return {
        "target": resolved_target,
        "path": str(path),
        "path_exists": path.is_file(),
        "entry_count": len(entries),
        "ledger_status": diagnostics.get("status", "missing"),
        "ledger_diagnostics": {
            key: diagnostics[key]
            for key in ("status", "invalid_count", "invalid_rows", "last_valid_offset", "read_error")
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
    identity_group = p_record.add_mutually_exclusive_group()
    identity_group.add_argument(
        "--identity-v2-json",
        default="",
        help="prebuilt ClosureCellKey v2 JSON carried unchanged from the planned test",
    )
    identity_group.add_argument(
        "--identity-dimensions-json",
        default="",
        help="JSON object with deterministic family-specific closure dimensions",
    )
    identity_group.add_argument(
        "--identity-candidate-json",
        default="",
        help="JSON object containing an AI identity candidate",
    )
    p_record.add_argument(
        "--identity-replaces-event-id",
        default="",
        help="event_id of an immutable identity row replaced by this complete cell",
    )
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
        try:
            identity_v2 = json.loads(args.identity_v2_json) if args.identity_v2_json else None
            identity_dimensions = json.loads(args.identity_dimensions_json) if args.identity_dimensions_json else None
            identity_candidate = json.loads(args.identity_candidate_json) if args.identity_candidate_json else None
        except json.JSONDecodeError as exc:
            parser.error(f"identity JSON must be valid JSON: {exc.msg}")
        if identity_v2 is not None and not isinstance(identity_v2, dict):
            parser.error("--identity-v2-json must contain a JSON object")
        if identity_dimensions is not None and not isinstance(identity_dimensions, dict):
            parser.error("--identity-dimensions-json must contain a JSON object")
        if identity_candidate is not None and not isinstance(identity_candidate, dict):
            parser.error("--identity-candidate-json must contain a JSON object")
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
            identity_v2=identity_v2,
            identity_dimensions=identity_dimensions,
            identity_candidate=identity_candidate,
            identity_replaces_event_id=args.identity_replaces_event_id,
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
