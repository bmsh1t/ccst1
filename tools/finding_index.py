#!/usr/bin/env python3
"""Build a structured finding index from scanner artifacts.

The scanner still writes human-readable ``.txt`` files.  This module adds a
small stable JSON contract so Claude Code agents, validation, and report
workflows can consume candidate findings without reparsing every directory in
slightly different ways.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sqlite3
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from tools.closure_resolver import canonical_endpoint_identity
    from tools.target_paths import canonical_target_value, target_storage_key, url_belongs_to_target
    from tools.target_store import StoreError, target_switch_lock
except ImportError:  # pragma: no cover - top-level tools/ import
    from closure_resolver import canonical_endpoint_identity
    from target_paths import canonical_target_value, target_storage_key, url_belongs_to_target
    from target_store import StoreError, target_switch_lock  # type: ignore

SCHEMA_VERSION = 1
MUTATION_EVENT_SCHEMA_VERSION = 1
MUTATION_EVENTS_FILENAME = "mutation-events.jsonl"
OWNER_PROVENANCE_FIELD = "owner_provenance"
FINDING_OWNER = "tools.finding_index"
FINALIZED_VALIDATION_STATUSES = frozenset({"validated", "rejected"})
FINALIZED_REPORT_STATUSES = frozenset({"generated", "reported"})
OWNER_REVALIDATION_STATUS = "needs_owner_revalidation"


def _finding_backend_context(findings_dir: str | Path, target: str | None = None) -> tuple[Path, str]:
    """Resolve the same target for backend admission and the cutover lock."""
    root = Path(os.path.abspath(findings_dir))
    if root != root.resolve():
        raise StoreError(f"finding directory must not traverse symlinks: {root}")
    root = next((path for path in (root, *root.parents) if path.parent.name == "findings"), root)
    repo_root = root.parent.parent if root.parent.name == "findings" else root.parent
    key = root.name
    store_path = repo_root / "state" / key / "metadata.sqlite3"
    fence_path = repo_root / "state" / key / "legacy-frozen.json"
    stored_target = None
    if store_path.is_file():
        try:
            with sqlite3.connect(f"file:{store_path}?mode=ro", uri=True) as conn:
                stored_target = conn.execute("SELECT target FROM store WHERE singleton=1").fetchone()[0]
        except (OSError, sqlite3.DatabaseError, TypeError, IndexError) as exc:
            raise StoreError(f"cannot determine finding backend for {root}") from exc
    elif fence_path.exists() or fence_path.is_symlink():
        raise StoreError(f"fenced target store is unavailable for legacy finding writer: {root}")
    resolved_target = canonical_target_value(str(stored_target or target or key))
    if target_storage_key(resolved_target) != key or (
        target and canonical_target_value(target) != resolved_target
    ):
        raise StoreError(f"finding target mismatch with directory owner: {root}")
    _finding_output_path(root, root / "findings.json")
    return repo_root, resolved_target


def _finding_output_path(findings_dir: str | Path, output: str | Path) -> Path:
    """Keep custom index names inside the same non-symlinked owner directory."""
    root = Path(findings_dir).resolve()
    path = Path(os.path.abspath(output))
    if path != path.resolve() or not path.is_relative_to(root):
        raise StoreError(f"finding output escapes directory owner: {path}")
    return path


ROOT_CLAIM_KIND = "finding_claim"
ROOT_CLAIM_SCHEMA_VERSION = 1
URL_RE = re.compile(r"https?://[^\s|`>'\")]+")
BRACKET_RE = re.compile(r"\[([^\]]+)\]")

CATEGORY_TYPE_MAP = {
    "upload": "upload",
    "sqli": "sqli",
    "xss": "xss",
    "ssti": "ssti",
    "takeover": "takeover",
    "misconfig": "misconfig",
    "exposure": "exposure",
    "ssrf": "ssrf",
    "cves": "cve",
    "redirects": "redirect",
    "idor": "idor",
    "auth_bypass": "auth_bypass",
    "mfa": "mfa",
    "saml": "saml",
}

DEFAULT_SEVERITY = {
    "upload": "high",
    "sqli": "high",
    "xss": "medium",
    "ssti": "critical",
    "takeover": "high",
    "misconfig": "medium",
    "exposure": "medium",
    "ssrf": "high",
    "cve": "high",
    "redirect": "low",
    "idor": "medium",
    "auth_bypass": "high",
    "mfa": "medium",
    "saml": "high",
}

CONFIRMED_MARKERS = (
    "RCE-POC",
    "SQLI-POC-VERIFIED",
    "SSTI-CONFIRMED",
    "SAML-SIG-STRIP",
)

HIGH_CONFIDENCE_MARKERS = CONFIRMED_MARKERS + (
    "UNAUTH",
)

REPORTABLE_TYPES = {
    "upload",
    "sqli",
    "xss",
    "ssti",
    "takeover",
    "misconfig",
    "exposure",
    "ssrf",
    "cve",
    "redirect",
    "idor",
    "auth_bypass",
    "mfa",
    "saml",
}


# 根目录 JSON 是 Claude/人工常见的临时落点，但它不是 canonical finding
# lifecycle。以下文件是已有工具的摘要/索引，不能被误判为一个 claim。
ROOT_CLAIM_EXCLUDED_FILES = {
    "findings.json",
    "scanner_candidates.json",
    "validation-summary.json",
    "last-validate.json",
    "autopilot_run.json",
    "run.json",
    # Machine decision/output witnesses are validation inputs or derived
    # pointers, not independent finding claims.
    "machine-decision.json",
    "validate-output.json",
    "checkpoint_latest.json",
    "last_checkpoint.json",
    "autopilot_state.json",
    "runtime_state.json",
    "session.json",
    "case_state.json",
    "coverage_matrix.json",
    "action_queue.json",
}

# 每个 finding 的 validation summary 按 ``<artifact-key>.validation-summary.json``
# 命名。它们是 /validate 生成的 lifecycle artifact，不是待归档的人工/AI claim。
ROOT_CLAIM_EXCLUDED_SUFFIXES = (
    ".validation-summary.json",
)


def _is_root_claim_excluded_file(path: Path) -> bool:
    """判断根目录 JSON 是否为生成的非 claim artifact。"""
    return path.name in ROOT_CLAIM_EXCLUDED_FILES or path.name.endswith(ROOT_CLAIM_EXCLUDED_SUFFIXES)


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def mutation_events_path(findings_dir: str | Path) -> Path:
    """Return the append-only owner-provenance path for one target index."""
    return Path(findings_dir) / MUTATION_EVENTS_FILENAME


def _canonical_target_or_raw(value: str | None) -> str:
    """Normalize target identity where possible without hiding malformed legacy rows."""
    raw = str(value or "").strip()
    if not raw:
        return ""
    try:
        return canonical_target_value(raw)
    except (TypeError, ValueError):
        return raw


def _finding_without_owner_provenance(finding: dict[str, Any]) -> dict[str, Any]:
    """Return the canonical row shape used by provenance fingerprinting.

    Caller-supplied provenance is deliberately not part of the canonical row
    contract. Only this module can attach it after a successful owner mutation.
    """
    normalized = dict(finding)
    normalized.pop(OWNER_PROVENANCE_FIELD, None)
    return normalized


def finding_row_fingerprint(finding: dict[str, Any]) -> str:
    """Return a stable digest of a canonical row excluding owner metadata."""
    serialized = json.dumps(
        _finding_without_owner_provenance(finding),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def finding_evidence_summary(finding: dict[str, Any]) -> dict[str, str]:
    """Project the bounded evidence pointers that make one mutation reviewable."""
    fields = (
        "source_file",
        "claim_source_file",
        "validation_summary",
        "validation_summary_sha256",
        "validation_report_path",
        "report_file",
        "report_id",
        "evidence_ref",
        "raw_request_path",
        "raw_response_path",
    )
    summary = {
        field: str(finding.get(field) or "").strip()
        for field in fields
        if str(finding.get(field) or "").strip()
    }
    if not summary:
        # Scanner/owner rows can legitimately have no linked artifact yet.
        # Keep the event structurally reviewable without copying arbitrary PoC
        # prose into the audit log.
        summary["source"] = "canonical-finding-row"
    return summary


def _resolve_finding_artifact_path(findings_dir: str | Path, value: str) -> Path | None:
    """Resolve an owner-recorded artifact across target- and repo-relative styles."""
    raw = str(value or "").strip()
    if not raw:
        return None
    path = Path(raw).expanduser()
    candidates = [path] if path.is_absolute() else [Path(findings_dir) / path]
    if not path.is_absolute():
        root = Path(findings_dir)
        if len(root.parents) >= 2:
            candidates.append(root.parents[1] / path)
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return candidates[0] if candidates else None


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_mutation_events(findings_dir: str | Path) -> tuple[list[dict[str, Any]], list[str]]:
    """Read provenance events for verification; retain malformed-line diagnostics."""
    path = mutation_events_path(findings_dir)
    if not path.is_file():
        return [], []
    events: list[dict[str, Any]] = []
    errors: list[str] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        return [], [str(exc)]
    for line_number, raw in enumerate(lines, 1):
        if not raw.strip():
            continue
        try:
            event = json.loads(raw)
        except json.JSONDecodeError as exc:
            errors.append(f"line {line_number}: {exc.msg}")
            continue
        if not isinstance(event, dict):
            errors.append(f"line {line_number}: event is not an object")
            continue
        events.append(event)
    return events, errors


def verify_finding_owner_provenance(
    findings_dir: str | Path,
    finding: dict[str, Any],
    *,
    target: str | None = None,
) -> dict[str, Any]:
    """Verify that one canonical row still matches a finding-index mutation event."""
    if not isinstance(finding, dict):
        return {"valid": False, "reason": "finding-not-object"}
    provenance = finding.get(OWNER_PROVENANCE_FIELD)
    if not isinstance(provenance, dict):
        return {"valid": False, "reason": "missing-owner-provenance"}
    event_id = str(provenance.get("event_id") or "").strip()
    finding_id = str(finding.get("id") or "").strip()
    if not event_id or not finding_id:
        return {"valid": False, "reason": "missing-event-or-finding-id"}

    events, parse_errors = _load_mutation_events(findings_dir)
    event = next(
        (item for item in events if str(item.get("event_id") or "") == event_id),
        None,
    )
    if not event:
        result = {"valid": False, "reason": "missing-mutation-event", "event_id": event_id}
        if parse_errors:
            result["event_log_errors"] = parse_errors[:3]
        return result

    expected_target = _canonical_target_or_raw(target or "")
    event_target = _canonical_target_or_raw(str(event.get("target") or ""))
    fingerprint = finding_row_fingerprint(finding)
    evidence_summary = finding_evidence_summary(finding)
    if str(provenance.get("owner") or "") != FINDING_OWNER or str(event.get("owner") or "") != FINDING_OWNER:
        return {"valid": False, "reason": "unexpected-owner", "event_id": event_id}
    if event.get("schema_version") != MUTATION_EVENT_SCHEMA_VERSION:
        return {"valid": False, "reason": "unexpected-event-schema", "event_id": event_id}
    if str(event.get("finding_id") or "") != finding_id:
        return {"valid": False, "reason": "finding-id-mismatch", "event_id": event_id}
    if expected_target and event_target != expected_target:
        return {"valid": False, "reason": "target-mismatch", "event_id": event_id}
    if str(provenance.get("operation") or "") != str(event.get("operation") or ""):
        return {"valid": False, "reason": "operation-mismatch", "event_id": event_id}
    if str(provenance.get("recorded_at") or "") != str(event.get("recorded_at") or ""):
        return {"valid": False, "reason": "recorded-at-mismatch", "event_id": event_id}
    if str(provenance.get("fingerprint") or "") != fingerprint:
        return {"valid": False, "reason": "row-fingerprint-mismatch", "event_id": event_id}
    if str(event.get("finding_fingerprint") or "") != fingerprint:
        return {"valid": False, "reason": "event-fingerprint-mismatch", "event_id": event_id}
    if event.get("evidence_summary") != evidence_summary:
        return {"valid": False, "reason": "evidence-summary-mismatch", "event_id": event_id}
    expected_summary_digest = str(finding.get("validation_summary_sha256") or "").strip()
    if expected_summary_digest:
        summary_path = _resolve_finding_artifact_path(
            findings_dir,
            str(finding.get("validation_summary") or ""),
        )
        if summary_path is None or not summary_path.is_file():
            return {
                "valid": False,
                "reason": "validation-summary-missing",
                "event_id": event_id,
            }
        if _sha256_file(summary_path) != expected_summary_digest:
            return {
                "valid": False,
                "reason": "validation-summary-content-mismatch",
                "event_id": event_id,
            }
    return {
        "valid": True,
        "event_id": event_id,
        "operation": str(event.get("operation") or ""),
        "evidence_summary": evidence_summary,
    }


def finding_requires_owner_provenance(finding: dict[str, Any]) -> bool:
    """Return whether a row claims a lifecycle state that must be owner-backed.

    Candidate and scanner rows can exist before the canonical owner has written
    a lifecycle transition.  A row that claims validation/rejection or a
    generated/reported report is different: consumers must be able to replay
    the matching ``finding_index`` mutation before treating that claim as a
    closure, report input, or suppression signal.
    """
    if not isinstance(finding, dict):
        return False
    validation_status = str(finding.get("validation_status") or "").strip().lower()
    report_status = str(finding.get("report_status") or "").strip().lower()
    return (
        validation_status in FINALIZED_VALIDATION_STATUSES
        or report_status in FINALIZED_REPORT_STATUSES
    )


def verify_finalized_finding_owner_provenance(
    findings_dir: str | Path,
    finding: dict[str, Any],
    *,
    target: str | None = None,
) -> dict[str, Any]:
    """Verify a lifecycle-final row, or mark non-final rows as not requiring it.

    This is the shared consumer gate.  It lets state, report, and surface
    readers use exactly the same definition instead of independently checking
    the mutable status strings in ``findings.json``.
    """
    required = finding_requires_owner_provenance(finding)
    if not required:
        return {"required": False, "valid": True, "reason": "not-finalized"}
    result = verify_finding_owner_provenance(findings_dir, finding, target=target)
    return {"required": True, **result}


def _quarantine_finality_claim(
    finding: dict[str, Any],
    *,
    reason: str,
) -> dict[str, Any]:
    """把未验证的终态声明降级为可审计的 owner revalidation 行。

    rebuild、legacy migration 和通用 upsert 都会重新签名其输出。如果直接保留旧的
    ``validated/generated`` 字段，这些正常 owner 操作反而会把无 event 的终态洗白。
    降级后仍保留证据/report 指针和原声明，供显式 ``/validate`` 重放，但任何 consumer
    都不能把它当作已完成生命周期。
    """
    quarantined = dict(finding)
    validation_status = str(quarantined.get("validation_status") or "unvalidated").strip().lower()
    report_status = str(quarantined.get("report_status") or "not_generated").strip().lower()
    quarantined["claimed_validation_status"] = str(
        quarantined.get("claimed_validation_status") or validation_status
    )
    quarantined["claimed_report_status"] = str(
        quarantined.get("claimed_report_status") or report_status
    )
    quarantined["validation_status"] = OWNER_REVALIDATION_STATUS
    quarantined["report_status"] = "not_generated"
    quarantined["owner_revalidation_reason"] = reason or "owner-provenance-invalid"
    quarantined.pop(OWNER_PROVENANCE_FIELD, None)
    _sync_legacy_lifecycle_fields(quarantined)
    return quarantined


def _extract_url(raw: str) -> str:
    match = URL_RE.search(raw)
    return match.group(0) if match else ""


def _extract_template_id(raw: str) -> str:
    brackets = BRACKET_RE.findall(raw)
    if len(brackets) >= 3 and brackets[1].lower() in {"http", "dns", "ssl", "tcp", "file"}:
        return brackets[0]
    if brackets and not brackets[0].isupper():
        return brackets[0]
    return ""


def _extract_nuclei_severity(raw: str) -> str:
    brackets = [item.lower() for item in BRACKET_RE.findall(raw)]
    for value in brackets:
        if value in {"critical", "high", "medium", "low", "info"}:
            return value
    return ""


def _severity_for(raw: str, vuln_type: str) -> str:
    explicit = _extract_nuclei_severity(raw)
    if explicit:
        return explicit

    if "RCE-POC" in raw or "SSTI-CONFIRMED" in raw or "SAML-SIG-STRIP" in raw:
        return "critical"
    if "SQLI-POC-VERIFIED" in raw or "DEFAULT" in raw.upper():
        return "high"
    return DEFAULT_SEVERITY.get(vuln_type, "medium")


def _confidence_for(raw: str, source_file: str) -> str:
    if any(marker in raw for marker in CONFIRMED_MARKERS):
        return "confirmed"
    if any(marker in raw for marker in HIGH_CONFIDENCE_MARKERS):
        return "high"
    if "manual" in source_file.lower() or "candidate" in raw.lower():
        return "needs_review"
    return "medium"


def _title_for(vuln_type: str, raw: str, url: str) -> str:
    marker = ""
    brackets = BRACKET_RE.findall(raw)
    if brackets:
        marker = brackets[0]
    elif raw.startswith("[") and "]" in raw:
        marker = raw.split("]", 1)[0].lstrip("[")

    label = marker or vuln_type.upper()
    if url:
        return f"{label} on {url}"
    return label


def _stable_id(category: str, rel_path: str, line_number: int, raw: str) -> str:
    digest = hashlib.sha1(f"{rel_path}:{line_number}:{raw}".encode("utf-8")).hexdigest()[:10]
    return f"{category}_{digest}"


def _finding_from_line(findings_dir: Path, path: Path, line_number: int, raw: str) -> dict[str, Any] | None:
    raw = raw.strip()
    if not raw:
        return None

    rel_path = str(path.relative_to(findings_dir))
    category = rel_path.split("/", 1)[0]
    vuln_type = CATEGORY_TYPE_MAP.get(category, category)
    if vuln_type not in REPORTABLE_TYPES:
        return None

    url = _extract_url(raw)
    template_id = _extract_template_id(raw)
    severity = _severity_for(raw, vuln_type)
    confidence = _confidence_for(raw, rel_path)

    return {
        "id": _stable_id(category, rel_path, line_number, raw),
        "type": vuln_type,
        "category": category,
        "title": _title_for(vuln_type, raw, url),
        "summary": raw[:240],
        "url": url,
        "severity": severity,
        "confidence": confidence,
        "source_file": rel_path,
        "line_number": line_number,
        "template_id": template_id,
        "raw": raw,
        "validation_status": "unvalidated",
        "report_status": "not_generated",
    }


def _is_target_owned_finding(finding: dict[str, Any], target: str) -> bool:
    """Return whether a structured finding is safe to promote as direct target surface."""
    url = str(finding.get("url") or "").strip()
    if not target or not url:
        return True
    return url_belongs_to_target(url, target)


def _root_claim_id(relative_path: str) -> str:
    """Return the stable canonical identity for one root-level claim artifact."""
    digest = hashlib.sha1(f"root-finding-claim:{relative_path}".encode("utf-8")).hexdigest()[:12]
    return f"claim_{digest}"


def _claim_value(payload: dict[str, Any], *keys: str) -> str:
    """Read the first scalar claim field without copying arbitrary payload data."""
    for key in keys:
        value = payload.get(key)
        if isinstance(value, (str, int, float)) and str(value).strip():
            return str(value).strip()
    return ""


def _claim_detail_present(payload: dict[str, Any]) -> bool:
    """Return whether a JSON object contains a finding-shaped detail field."""
    detail_keys = (
        "poc",
        "evidence",
        "impact",
        "reproduction",
        "steps_to_reproduce",
        "description",
        "summary",
        "proof",
        "observed",
        "exploit_steps",
        "finding_summary",
    )
    return any(payload.get(key) not in (None, "", [], {}) for key in detail_keys)


def _claim_type(value: str) -> str:
    """Normalize a claim class while retaining unknown classes for review."""
    return str(value or "unknown").strip().lower().replace("-", "_").replace(" ", "_") or "unknown"


def _claim_incomplete_fields(title: str, endpoint: str, vuln_type: str, detail: bool) -> list[str]:
    missing: list[str] = []
    if not title:
        missing.append("title")
    if not endpoint:
        missing.append("endpoint")
    if not vuln_type:
        missing.append("vuln_class")
    if not detail:
        missing.append("claim_detail")
    return missing


def _root_claim_revision(payload: dict[str, Any]) -> str:
    serialized = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _root_claim_from_json(
    findings_dir: Path,
    path: Path,
    payload: dict[str, Any],
    *,
    target: str,
) -> dict[str, Any] | None:
    """Normalize one direct root JSON claim without trusting its lifecycle labels.

    Scanner projections live in typed subdirectories and are built by
    :func:`build_finding_index`.  A standalone root JSON with a title, endpoint,
    vulnerability class and reproduction/impact field instead represents a
    human/AI claim that must first become a canonical ``candidate``.
    """
    if _is_root_claim_excluded_file(path):
        return None
    if "findings" in payload or payload.get("kind") == "autopilot_checkpoint_witness":
        return None

    raw_kind = str(payload.get("kind") or "").strip().lower().replace("-", "_")
    if raw_kind and raw_kind != ROOT_CLAIM_KIND:
        return None
    if raw_kind == ROOT_CLAIM_KIND and payload.get("schema_version") not in {
        None,
        ROOT_CLAIM_SCHEMA_VERSION,
    }:
        return None

    title = _claim_value(payload, "title", "name", "finding_title")
    endpoint = _claim_value(payload, "url", "endpoint", "path", "route", "resource")
    vuln_type = _claim_value(
        payload,
        "type",
        "vuln_type",
        "vuln_class",
        "vulnerability_class",
        "finding_type",
        "category",
    )
    declared_vuln_class = _claim_value(
        payload,
        "vuln_class",
        "vulnerability_class",
        "vuln_type",
        "type",
        "finding_type",
        "category",
    )
    has_claim_detail = _claim_detail_present(payload)
    incomplete_fields = _claim_incomplete_fields(title, endpoint, vuln_type, has_claim_detail)

    # A malformed/partial claim is still a useful recovery object when it has
    # at least one identity field plus evidence-shaped detail.  Do not accept
    # arbitrary metadata JSON, and never substitute the target root for a
    # missing endpoint.
    identity_count = sum(bool(value) for value in (title, endpoint, vuln_type))
    explicit_claim = raw_kind == ROOT_CLAIM_KIND
    legacy_evidence_claim = identity_count >= 2 and has_claim_detail
    if identity_count == 0 or (not explicit_claim and not legacy_evidence_claim):
        return None
    if endpoint and target and not url_belongs_to_target(endpoint, target):
        return None

    relative_path = str(path.relative_to(findings_dir))
    normalized_type = _claim_type(vuln_type)
    declared_severity = str(payload.get("severity") or "medium").strip().lower() or "medium"
    claim_id = _root_claim_id(relative_path)
    claim_status = "incomplete" if incomplete_fields else "complete"
    claimed_validation_status = _claim_value(payload, "validation_status", "state", "status")
    claimed_report_status = _claim_value(payload, "report_status", "report_state")
    claim_target = _claim_value(payload, "target", "host")
    if claim_target and target and not url_belongs_to_target(claim_target, target):
        return None
    claim_revision = _root_claim_revision(payload)
    claim_source = {
        "claim_id": claim_id,
        "source_file": relative_path,
        "revision": claim_revision,
    }
    return {
        "id": claim_id,
        "claim_id": claim_id,
        "claim_source_file": relative_path,
        "claim_revision": claim_revision,
        "claim_sources": [claim_source],
        # Keep an absolute artifact pointer for Claude's next evidence step;
        # `claim_source_file` remains the stable, portable identity.
        "source_file": str(path),
        "type": normalized_type,
        "category": normalized_type,
        "vuln_class": declared_vuln_class or vuln_type or normalized_type,
        "title": title,
        "summary": (
            f"Unvalidated root JSON finding claim from {relative_path}. "
            + (
                "Missing: " + ", ".join(incomplete_fields) + ". "
                if incomplete_fields
                else ""
            )
            + "Its prose/PoC is not linked raw evidence or a /validate result."
        ),
        "url": endpoint,
        "claim_target": claim_target,
        "claim_status": claim_status,
        "incomplete_fields": incomplete_fields,
        "claimed_validation_status": claimed_validation_status,
        "claimed_report_status": claimed_report_status,
        "severity": declared_severity,
        "claimed_severity": declared_severity,
        "confidence": "needs_review",
        "raw": f"root-finding-claim:{relative_path}",
        "claim_payload": payload,
        "validation_status": "candidate",
        "report_status": "not_generated",
    }


def list_root_finding_claims(
    findings_dir: str | Path,
    *,
    target: str | None = None,
) -> list[dict[str, Any]]:
    """Read raw manual/interrupted claims in path order, without lifecycle authority."""
    root = Path(findings_dir)
    if not root.is_dir():
        return []
    resolved_target = str(target or root.name)
    claims: list[dict[str, Any]] = []
    for path in sorted(root.glob("*.json")):
        if _is_root_claim_excluded_file(path) or ".review-" in path.name:
            continue
        payload = _load_json_value(path)
        if not isinstance(payload, dict):
            continue
        claim = _root_claim_from_json(root, path, payload, target=resolved_target)
        if not claim:
            continue
        claims.append(claim)
    return claims


def build_finding_index(findings_dir: str | Path, *, target: str | None = None) -> dict[str, Any]:
    """Build a structured index from category ``.txt`` artifacts."""
    root = Path(findings_dir)
    resolved_target = target or root.name
    findings: list[dict[str, Any]] = []

    for category in sorted(CATEGORY_TYPE_MAP):
        category_dir = root / category
        if not category_dir.is_dir():
            continue

        for path in sorted(category_dir.glob("*.txt")):
            with path.open(encoding="utf-8", errors="replace") as handle:
                for line_number, line in enumerate(handle, 1):
                    finding = _finding_from_line(root, path, line_number, line)
                    if finding and _is_target_owned_finding(finding, resolved_target):
                        findings.append(finding)

    severity_counts: dict[str, int] = {}
    type_counts: dict[str, int] = {}
    confidence_counts: dict[str, int] = {}
    for finding in findings:
        severity_counts[finding["severity"]] = severity_counts.get(finding["severity"], 0) + 1
        type_counts[finding["type"]] = type_counts.get(finding["type"], 0) + 1
        confidence_counts[finding["confidence"]] = confidence_counts.get(finding["confidence"], 0) + 1

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": _now_utc(),
        "target": resolved_target,
        "findings_dir": str(root),
        "total": len(findings),
        "counts": {
            "severity": dict(sorted(severity_counts.items())),
            "type": dict(sorted(type_counts.items())),
            "confidence": dict(sorted(confidence_counts.items())),
        },
        "artifacts": {
            "summary_json": "summary.json" if (root / "summary.json").is_file() else "",
            "summary_txt": "summary.txt" if (root / "summary.txt").is_file() else "",
        },
        "findings": findings,
    }


def _load_json_value(path: Path) -> Any:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _validate_finding_payload(
    payload: dict[str, Any],
    *,
    path: Path,
    target: str | None = None,
) -> dict[str, Any]:
    """Fail closed on a non-canonical or cross-target findings index."""
    schema_version = payload.get("schema_version")
    if schema_version is not None and (
        isinstance(schema_version, bool) or schema_version != SCHEMA_VERSION
    ):
        raise ValueError(
            f"invalid finding index schema_version at {path}: expected {SCHEMA_VERSION}"
        )
    raw_target = payload.get("target")
    if not isinstance(raw_target, str) or not raw_target.strip():
        raise ValueError(f"invalid finding index target at {path}")
    expected_target = _canonical_target_or_raw(target)
    actual_target = _canonical_target_or_raw(raw_target)
    if expected_target and actual_target != expected_target:
        raise ValueError(
            f"finding index target mismatch at {path}: expected {expected_target}, got {actual_target}"
        )
    findings = payload.get("findings")
    if not isinstance(findings, list):
        raise ValueError(f"invalid finding index findings at {path}: expected a list")
    for index, finding in enumerate(findings):
        if not isinstance(finding, dict) or not str(finding.get("id") or "").strip():
            raise ValueError(f"invalid finding index row at {path}: findings[{index}]")
    return payload


def _legacy_object_to_index(
    findings_dir: Path,
    payload: dict[str, Any],
    *,
    target: str | None = None,
) -> dict[str, Any]:
    """Project the historical object envelope without trusting finality.

    Early writers emitted ``{"findings": [...]}`` objects before the target
    envelope and row IDs became mandatory.  Projection readers may still need
    to inspect those artifacts, but the conversion must follow the same
    quarantine rules as legacy list migration and must never hide a target or
    schema mismatch.
    """
    schema_version = payload.get("schema_version")
    if schema_version is not None and (
        isinstance(schema_version, bool) or schema_version != SCHEMA_VERSION
    ):
        raise ValueError(
            f"invalid finding index schema_version at {findings_dir / 'findings.json'}: "
            f"expected {SCHEMA_VERSION}"
        )

    raw_target = payload.get("target")
    if raw_target is not None:
        if not isinstance(raw_target, str) or not raw_target.strip():
            raise ValueError(f"invalid finding index target at {findings_dir / 'findings.json'}")
        expected_target = _canonical_target_or_raw(target)
        actual_target = _canonical_target_or_raw(raw_target)
        if expected_target and actual_target != expected_target:
            raise ValueError(
                f"finding index target mismatch at {findings_dir / 'findings.json'}: "
                f"expected {expected_target}, got {actual_target}"
            )
        target = raw_target

    rows = payload.get("findings")
    if not isinstance(rows, list):
        raise ValueError(
            f"invalid finding index findings at {findings_dir / 'findings.json'}: expected a list"
        )
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ValueError(
                f"invalid finding index row at {findings_dir / 'findings.json'}: findings[{index}]"
            )
    return _legacy_list_to_index(findings_dir, rows, target=target)


def _empty_finding_index(findings_dir: Path, *, target: str | None = None) -> dict[str, Any]:
    resolved_target = str(target or findings_dir.name)
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": _now_utc(),
        "target": resolved_target,
        "findings_dir": str(findings_dir),
        "total": 0,
        "counts": {"severity": {}, "type": {}, "confidence": {}},
        "artifacts": {
            "summary_json": "summary.json" if (findings_dir / "summary.json").is_file() else "",
            "summary_txt": "summary.txt" if (findings_dir / "summary.txt").is_file() else "",
        },
        "findings": [],
    }


def _finding_semantic_key(finding: dict[str, Any]) -> tuple[str, str, str, str, str, str]:
    endpoint = canonical_endpoint_identity(
        str(finding.get("url") or finding.get("endpoint") or "")
    )
    vuln_class = str(
        finding.get("vuln_class")
        or finding.get("type")
        or finding.get("category")
        or "finding"
    ).strip().lower().replace("-", "_")
    return (
        endpoint,
        vuln_class,
        str(finding.get("method") or "").strip().upper(),
        str(finding.get("actor") or "").strip().lower(),
        str(finding.get("object_scope") or finding.get("object") or "").strip().lower(),
        str(finding.get("variant") or "").strip().lower(),
    )


def _generated_finding_id(finding: dict[str, Any]) -> str:
    semantic_key = _finding_semantic_key(finding)
    endpoint, vuln_class = semantic_key[:2]
    source = str(finding.get("source_file") or finding.get("source") or "")
    raw = str(finding.get("raw") or finding.get("reason") or "")
    identity = "|".join(semantic_key) if endpoint else f"{vuln_class}|{source}|{raw}"
    digest = hashlib.sha1(identity.encode("utf-8")).hexdigest()[:12]
    prefix = re.sub(r"[^a-z0-9_-]+", "_", vuln_class) or "finding"
    return f"{prefix}_{digest}"


def _legacy_lifecycle_status(validation_status: str) -> str:
    """Map canonical validation state to the historical ``state/status`` value."""
    value = str(validation_status or "").strip().lower()
    if value == "validated":
        return "validated"
    if value == "rejected":
        return "rejected"
    if value in {"candidate", "partial", "needs_validation", "needs_owner_revalidation"}:
        return "candidate"
    return "unvalidated"


def _sync_legacy_lifecycle_fields(finding: dict[str, Any]) -> dict[str, Any]:
    """Keep legacy lifecycle aliases aligned when an owner mutation touches a row.

    ``validation_status`` is the canonical field.  Some older runtime writers
    also emit top-level ``state``/``status``; preserving those keys is useful for
    compatibility, but leaving them stale creates contradictory operator views.
    Only existing alias keys are projected so new rows do not silently acquire a
    second lifecycle schema.
    """
    if "state" not in finding and "status" not in finding:
        return finding
    value = _legacy_lifecycle_status(str(finding.get("validation_status") or ""))
    if "state" in finding:
        finding["state"] = value
    if "status" in finding:
        finding["status"] = value
    return finding


def _normalized_claim_source_entries(finding: dict[str, Any]) -> list[dict[str, str]]:
    """Normalize scalar/collection claim trace into a stable revision set."""
    entries: list[dict[str, str]] = []
    raw_entries = finding.get("claim_sources")
    if isinstance(raw_entries, list):
        for raw in raw_entries:
            if not isinstance(raw, dict):
                continue
            source_file = str(raw.get("source_file") or "").strip()
            if not source_file:
                continue
            entries.append(
                {
                    "claim_id": str(raw.get("claim_id") or "").strip(),
                    "source_file": source_file,
                    "revision": str(raw.get("revision") or "").strip(),
                }
            )
    scalar_source = str(finding.get("claim_source_file") or "").strip()
    if scalar_source:
        entries.append(
            {
                "claim_id": str(finding.get("claim_id") or finding.get("id") or "").strip(),
                "source_file": scalar_source,
                "revision": str(finding.get("claim_revision") or "").strip(),
            }
        )

    unique: dict[tuple[str, str], dict[str, str]] = {}
    for item in entries:
        key = (item["source_file"], item["revision"])
        existing = unique.get(key)
        if existing is None or (not existing.get("claim_id") and item.get("claim_id")):
            unique[key] = item
    return [unique[key] for key in sorted(unique)]


def _merge_claim_sources(
    existing: dict[str, Any],
    candidate: dict[str, Any],
) -> list[dict[str, str]]:
    return _normalized_claim_source_entries(
        {
            "claim_sources": [
                *_normalized_claim_source_entries(existing),
                *_normalized_claim_source_entries(candidate),
            ]
        }
    )


def _normalize_finding(finding: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(finding)
    endpoint = str(normalized.get("url") or normalized.get("endpoint") or "").strip()
    vuln_type = str(
        normalized.get("type")
        or normalized.get("category")
        or normalized.get("vuln_class")
        or "finding"
    ).strip().lower().replace("-", "_")
    if endpoint:
        normalized["url"] = str(normalized.get("url") or endpoint)
    if vuln_type:
        normalized["type"] = str(normalized.get("type") or vuln_type)
        normalized["category"] = str(normalized.get("category") or vuln_type)
    normalized["id"] = str(normalized.get("id") or _generated_finding_id(normalized))
    normalized.setdefault("validation_status", "unvalidated")
    normalized.setdefault("report_status", "not_generated")
    claim_sources = _normalized_claim_source_entries(normalized)
    if claim_sources:
        normalized["claim_sources"] = claim_sources
    _sync_legacy_lifecycle_fields(normalized)
    return normalized


def _merge_finding_rows(
    existing: dict[str, Any],
    candidate: dict[str, Any],
) -> dict[str, Any]:
    """Merge evidence fields without resetting advanced lifecycle state."""
    merged = dict(existing)
    for key, value in candidate.items():
        if value in (None, ""):
            continue
        if key == "claim_sources":
            merged[key] = _merge_claim_sources(existing, candidate)
            continue
        if (
            key == "validation_status"
            and str(existing.get(key) or "").strip().lower()
            in FINALIZED_VALIDATION_STATUSES | {OWNER_REVALIDATION_STATUS}
            and str(value or "").strip().lower()
            != str(existing.get(key) or "").strip().lower()
        ):
            continue
        if (
            key == "report_status"
            and str(existing.get(key) or "").strip().lower() in FINALIZED_REPORT_STATUSES
            and str(value or "").strip().lower()
            not in FINALIZED_REPORT_STATUSES
        ):
            continue
        if (
            key == "report_status"
            and str(existing.get(key) or "").strip().lower() == "reported"
            and str(value or "").strip().lower() == "generated"
        ):
            continue
        merged[key] = value
    if _finding_semantic_key(existing) == _finding_semantic_key(candidate):
        merged["id"] = existing.get("id") or candidate.get("id")
    return _normalize_finding(merged)


def _legacy_list_to_index(
    findings_dir: Path,
    rows: list[Any],
    *,
    target: str | None = None,
) -> dict[str, Any]:
    """Convert the historical target-level list payload into canonical schema."""
    payload = _empty_finding_index(findings_dir, target=target)
    findings: list[dict[str, Any]] = []
    index_by_id: dict[str, int] = {}
    for raw in rows:
        if not isinstance(raw, dict):
            continue
        finding = _normalize_finding(raw)
        # Historical list payloads never had owner provenance. Ignore any
        # ad-hoc field and quarantine lifecycle finality before the migration
        # owner signs the safe recovery row.
        finding.pop(OWNER_PROVENANCE_FIELD, None)
        if finding_requires_owner_provenance(finding):
            finding = _quarantine_finality_claim(
                finding,
                reason="legacy-finality-without-owner-event",
            )
        finding_id = str(finding["id"])
        existing_index = index_by_id.get(finding_id)
        if existing_index is None:
            index_by_id[finding_id] = len(findings)
            findings.append(finding)
            continue
        findings[existing_index] = _merge_finding_rows(findings[existing_index], finding)
    payload["findings"] = findings
    _refresh_finding_counts(payload)
    return payload


def _write_finding_payload(path: Path, payload: dict[str, Any]) -> None:
    """Atomically persist the canonical target-level finding payload."""
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


def _load_finding_payload(
    path: Path,
    findings_dir: Path,
    *,
    target: str | None = None,
    allow_legacy: bool = False,
) -> dict[str, Any]:
    raw = _load_json_value(path)
    if isinstance(raw, dict):
        try:
            return _validate_finding_payload(raw, path=path, target=target)
        except ValueError:
            if not allow_legacy:
                raise
            return _legacy_object_to_index(findings_dir, raw, target=target)
    if not isinstance(raw, list):
        return {}
    payload = _legacy_list_to_index(findings_dir, raw, target=target)
    return payload


def load_legacy_finding_index(
    findings_dir: str | Path, *, target: str | None = None, allow_legacy: bool = False,
) -> dict[str, Any]:
    """Inspect historical Finding metadata without modifying any legacy files."""
    root = Path(findings_dir)
    return _load_finding_payload(root / "findings.json", root, target=target, allow_legacy=allow_legacy)


def _refresh_finding_counts(payload: dict[str, Any]) -> None:
    """Recalculate totals after scanner rows and preserved runtime rows merge."""
    findings = [item for item in payload.get("findings", []) if isinstance(item, dict)]
    payload["total"] = len(findings)

    severity_counts: dict[str, int] = {}
    type_counts: dict[str, int] = {}
    confidence_counts: dict[str, int] = {}
    for finding in findings:
        severity = str(finding.get("severity") or "medium")
        vuln_type = str(finding.get("type") or "exposure")
        confidence = str(finding.get("confidence") or "medium")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        type_counts[vuln_type] = type_counts.get(vuln_type, 0) + 1
        confidence_counts[confidence] = confidence_counts.get(confidence, 0) + 1

    payload["counts"] = {
        "severity": dict(sorted(severity_counts.items())),
        "type": dict(sorted(type_counts.items())),
        "confidence": dict(sorted(confidence_counts.items())),
    }


def format_finding_index(payload: dict[str, Any], *, limit: int = 8) -> str:
    """Return a compact text summary for Claude Code context."""
    if not payload:
        return ""

    lines = [
        "=== finding_index ===",
        f"total={payload.get('total', 0)} target={payload.get('target', '-')}",
    ]

    counts = payload.get("counts") if isinstance(payload.get("counts"), dict) else {}
    for key in ("severity", "type", "confidence"):
        values = counts.get(key) if isinstance(counts.get(key), dict) else {}
        if values:
            rendered = ", ".join(f"{name}={count}" for name, count in sorted(values.items()))
            lines.append(f"{key}: {rendered}")

    for finding in payload.get("findings", [])[:limit]:
        if not isinstance(finding, dict):
            continue
        lines.append(
            "- {id} [{severity}/{confidence}] {type} {url} status={validation}/{report} :: {summary}".format(
                id=finding.get("id", "-"),
                severity=finding.get("severity", "medium"),
                confidence=finding.get("confidence", "medium"),
                type=finding.get("type", "unknown"),
                url=finding.get("url") or "no-url",
                validation=finding.get("validation_status", "unvalidated"),
                report=finding.get("report_status", "not_generated"),
                summary=(finding.get("summary") or "")[:120],
            )
        )

    return "\n".join(lines)


def index_scanner_material(findings_dir: str | Path, *, target: str | None = None,
                           output: str | Path | None = None) -> dict[str, Any]:
    """Register raw candidate material as review work without inventing execution facts."""
    try:
        from tools.action_queue import add_material_review
        from tools.target_store import runtime_store
    except ImportError:  # pragma: no cover - direct tools/ execution
        from action_queue import add_material_review
        from target_store import runtime_store
    repo, owner = _finding_backend_context(findings_dir, target)
    root = Path(findings_dir).resolve()
    destination = _finding_output_path(root, output or root / "scanner_candidates.json")
    if destination.name != "scanner_candidates.json":
        raise StoreError("scanner material index must be scanner_candidates.json; legacy findings are immutable")
    with target_switch_lock(repo, owner):
        store = runtime_store(repo, owner)
        payload = build_finding_index(root, target=owner)
        payload["root_claims"] = list_root_finding_claims(root, target=owner)
        groups: dict[str, list[dict]] = {}
        for finding in payload["findings"]:
            groups.setdefault(finding["source_file"], []).append(finding)
        for claim in payload["root_claims"]:
            groups.setdefault(claim["claim_source_file"], []).append(claim)
        actions = []
        for source_file, findings in sorted(groups.items()):
            source_path = root / source_file
            if source_path.is_symlink() or not source_path.resolve().is_relative_to(root):
                raise StoreError("scanner material escapes the target directory")
            action = add_material_review(
                repo, target=owner, source="scanner", source_id=source_path.relative_to(repo).as_posix(),
                action_type="scanner-review", summary_path=source_path,
                material={"kind": "scanner_candidates", "findings": findings},
            )
            actions.append(action["action"]["id"])
        payload.update(kind="scanner_material_index", review_action_ids=actions,
                       source_binding=store.binding())
        _write_finding_payload(destination, payload)
        return payload


def main() -> None:
    parser = argparse.ArgumentParser(description="Index scanner material and register Store review work")
    parser.add_argument("findings_dir", help="Directory containing scanner findings")
    parser.add_argument("--target", default="", help="Target owner")
    parser.add_argument("--output", default="", help="Output path for scanner_candidates.json")
    args = parser.parse_args()
    try:
        payload = index_scanner_material(args.findings_dir, target=args.target or None,
                                         output=args.output or None)
    except (OSError, ValueError) as exc:
        parser.exit(2, f"scanner material registration failed: {exc}\n")
    print(f"indexed {payload['total']} raw candidate(s); review actions={len(payload['review_action_ids'])}")


if __name__ == "__main__":
    main()
