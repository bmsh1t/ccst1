#!/usr/bin/env python3
"""Build a structured finding index from scanner artifacts.

The scanner still writes human-readable ``.txt`` files.  This module adds a
small stable JSON contract so Claude Code agents, validation, and report
workflows can consume candidate findings without reparsing every directory in
slightly different ways.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from tools.evidence_rubric import rubric_for
    from tools.target_paths import canonical_target_value, url_belongs_to_target
except ImportError:  # pragma: no cover - top-level tools/ import
    from evidence_rubric import rubric_for
    from target_paths import canonical_target_value, url_belongs_to_target

SCHEMA_VERSION = 1
MUTATION_EVENT_SCHEMA_VERSION = 1
MUTATION_EVENTS_FILENAME = "mutation-events.jsonl"
OWNER_PROVENANCE_FIELD = "owner_provenance"
FINDING_OWNER = "tools.finding_index"
FINALIZED_VALIDATION_STATUSES = frozenset({"validated", "rejected"})
FINALIZED_REPORT_STATUSES = frozenset({"generated", "reported"})
OWNER_REVALIDATION_STATUS = "needs_owner_revalidation"
ROOT_CLAIM_KIND = "finding_claim"
ROOT_CLAIM_SCHEMA_VERSION = 1
URL_RE = re.compile(r"https?://[^\s|`>'\")]+")
BRACKET_RE = re.compile(r"\[([^\]]+)\]")
SOURCE_CODE_SUFFIXES = frozenset({
    ".c", ".cc", ".cpp", ".cs", ".go", ".h", ".hpp", ".java", ".js",
    ".jsx", ".kt", ".kts", ".php", ".py", ".rb", ".rs", ".scala",
    ".swift", ".ts", ".tsx", ".vue",
})
SOURCE_GUARD_SHAPE_RE = re.compile(
    r"(?:\b(?:if|unless|assert|raise|throw|return|continue|break|deny|forbid|"
    r"authorize|permission|require|ensure|guard|abort|panic)\b|"
    r"\b(?:contains|includes|has_permission|can_[a-z0-9_]*|is_allowed)\s*\()",
    re.IGNORECASE,
)
SOURCE_COMMENT_PREFIXES = ("#", "//", "/*", "*", "<!--")

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
    "MFA-NO-RATE-LIMIT",
    "MFA-WORKFLOW-SKIP",
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

PRESERVED_FINDING_FIELDS = {
    "validation_status",
    "report_status",
    "validation_summary",
    "validation_summary_sha256",
    "validation_report_path",
    "validated_at",
    "vuln_class",
    "updated_at",
    "report_file",
    "report_id",
    "queue_sync",
    # 根目录的人工/AI finding claim 仍由本 owner 投影到 canonical index；重建
    # scanner index 时不能丢失其可追溯来源和稳定 identity。
    "claim_id",
    "claim_source_file",
    "claim_revision",
    "claim_sources",
    "claimed_severity",
    "claim_target",
    "claim_status",
    "incomplete_fields",
    "claimed_validation_status",
    "claimed_report_status",
    "owner_revalidation_reason",
}

# 根目录 JSON 是 Claude/人工常见的临时落点，但它不是 canonical finding
# lifecycle。以下文件是已有工具的摘要/索引，不能被误判为一个 claim。
ROOT_CLAIM_EXCLUDED_FILES = {
    "findings.json",
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


@contextmanager
def finding_mutation_lock(findings_dir: str | Path):
    """串行化单 target canonical findings 的完整 read-modify-write。"""
    root = Path(findings_dir)
    lock_path = root / ".locks" / "findings.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


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


def _is_source_backed_finding(finding: dict[str, Any]) -> bool:
    """判断 finding 的原始来源是否为可执行源码，而不是证据 artifact。"""
    raw = str(finding.get("source_file") or "").strip()
    if not raw:
        return False
    normalized = raw.removeprefix("repo:").split("#", 1)[0]
    return Path(normalized).suffix.lower() in SOURCE_CODE_SUFFIXES


def _resolve_source_guard_path(findings_dir: str | Path, value: Any) -> Path:
    """解析 validation summary 中的源码引用，不依赖调用方当前目录。"""
    raw = str(value or "").strip()
    if not raw:
        raise ValueError("source rejection requires source_guard.source_file")
    normalized = raw.removeprefix("repo:")
    path = Path(normalized).expanduser()
    if path.is_absolute():
        candidates = [path]
    else:
        target_dir = Path(findings_dir).resolve()
        repo_root = target_dir.parent.parent if target_dir.parent.name == "findings" else target_dir
        candidates = [repo_root / path, target_dir / path]
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    raise ValueError(f"source rejection guard file is not readable: {raw}")


def _verify_source_rejection_summary(
    findings_dir: str | Path,
    finding: dict[str, Any],
    updates: dict[str, Any],
) -> None:
    """在源码 finding 进入 rejected 前确定性验证 guard 引用。

    这里只验证引用真实性，不推断 guard 是否支配危险路径；后者仍由验证流程负责。
    """
    if not _is_source_backed_finding(finding):
        return

    summary_value = str(updates.get("validation_summary") or "").strip()
    if not summary_value:
        raise ValueError("source rejection requires a new validation_summary")
    summary_path = _resolve_finding_artifact_path(findings_dir, summary_value)
    if summary_path is None or not summary_path.is_file():
        raise ValueError(f"source rejection validation summary is not readable: {summary_value}")
    try:
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"unable to read source rejection summary: {summary_path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid source rejection summary: {summary_path}: {exc.msg}") from exc
    if not isinstance(summary, dict) or str(summary.get("result") or "").strip().lower() != "rejected":
        raise ValueError("source rejection validation summary must set result=rejected")

    guard = summary.get("source_guard")
    if not isinstance(guard, dict):
        raise ValueError("source rejection validation summary requires source_guard")
    source_path = _resolve_source_guard_path(
        findings_dir,
        guard.get("source_file") or guard.get("file"),
    )
    if source_path.suffix.lower() not in SOURCE_CODE_SUFFIXES:
        raise ValueError("source rejection guard must cite a supported source-code file")

    line_number = guard.get("line_number")
    if isinstance(line_number, bool) or not isinstance(line_number, int) or line_number < 1:
        raise ValueError("source rejection source_guard.line_number must be a positive integer")
    quote = str(guard.get("quote") or "").strip()
    if not quote:
        raise ValueError("source rejection source_guard.quote must be non-empty")
    if not SOURCE_GUARD_SHAPE_RE.search(quote):
        raise ValueError("source rejection quote does not have guard shape")

    try:
        lines = source_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        raise ValueError(f"unable to read source rejection guard file: {source_path}: {exc}") from exc
    if line_number > len(lines):
        raise ValueError("source rejection source_guard.line_number is outside the source file")
    source_line = lines[line_number - 1]
    if source_line.lstrip().startswith(SOURCE_COMMENT_PREFIXES):
        raise ValueError("source rejection guard points to a comment, not executable source")
    normalized_quote = re.sub(r"\s+", "", quote).lower()
    normalized_line = re.sub(r"\s+", "", source_line).lower()
    if not normalized_line.startswith(normalized_quote):
        raise ValueError("source rejection guard quote does not match the cited source line")


def _attach_validation_summary_digest(
    findings_dir: str | Path,
    finding: dict[str, Any],
) -> None:
    """Bind a locatable validation summary to the row/event snapshot."""
    path = _resolve_finding_artifact_path(
        findings_dir,
        str(finding.get("validation_summary") or ""),
    )
    if path is None or not path.is_file():
        return
    finding["validation_summary_sha256"] = _sha256_file(path)


def _new_mutation_event_id(
    *,
    target: str,
    finding_id: str,
    operation: str,
    fingerprint: str,
    recorded_at: str,
    ordinal: int,
) -> str:
    seed = "|".join((target, finding_id, operation, fingerprint, recorded_at, str(ordinal), str(os.getpid())))
    return "fmut_" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:20]


def _prepare_owner_provenance(
    findings: list[dict[str, Any]],
    *,
    target: str,
    operation: str,
) -> list[dict[str, Any]]:
    """Attach owner metadata to mutated rows and return their audit events.

    The row mutation and event are intentionally built from the same stripped
    snapshot. Consumers can therefore detect a later direct JSON edit without
    inventing a second finding lifecycle or parsing caller-specific payloads.
    """
    resolved_target = _canonical_target_or_raw(target)
    recorded_at = _now_utc()
    events: list[dict[str, Any]] = []
    for ordinal, finding in enumerate(findings, 1):
        if not isinstance(finding, dict):
            continue
        finding.pop(OWNER_PROVENANCE_FIELD, None)
        finding_id = str(finding.get("id") or "").strip()
        if not finding_id:
            continue
        fingerprint = finding_row_fingerprint(finding)
        evidence_summary = finding_evidence_summary(finding)
        event_id = _new_mutation_event_id(
            target=resolved_target,
            finding_id=finding_id,
            operation=operation,
            fingerprint=fingerprint,
            recorded_at=recorded_at,
            ordinal=ordinal,
        )
        provenance = {
            "event_id": event_id,
            "owner": FINDING_OWNER,
            "operation": operation,
            "recorded_at": recorded_at,
            "fingerprint": fingerprint,
        }
        finding[OWNER_PROVENANCE_FIELD] = provenance
        events.append(
            {
                "schema_version": MUTATION_EVENT_SCHEMA_VERSION,
                "event_id": event_id,
                "recorded_at": recorded_at,
                "owner": FINDING_OWNER,
                "operation": operation,
                "target": resolved_target,
                "finding_id": finding_id,
                "endpoint": str(finding.get("url") or finding.get("endpoint") or "").strip(),
                "vuln_class": str(
                    finding.get("vuln_class")
                    or finding.get("type")
                    or finding.get("category")
                    or ""
                ).strip(),
                "validation_status": str(finding.get("validation_status") or "").strip(),
                "report_status": str(finding.get("report_status") or "").strip(),
                "evidence_summary": evidence_summary,
                "finding_fingerprint": fingerprint,
            }
        )
    return events


def _append_mutation_events(path: Path, events: list[dict[str, Any]]) -> None:
    """Append complete owner events with one locked, fsynced write sequence."""
    if not events:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = "".join(
        json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
        for event in events
    ).encode("utf-8")
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            written = os.write(fd, encoded)
            if written != len(encoded):
                raise OSError(f"partial finding provenance write: {written}/{len(encoded)} bytes")
            os.fsync(fd)
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def _write_payload_with_owner_provenance(
    path: Path,
    payload: dict[str, Any],
    *,
    findings_dir: Path,
    target: str,
    operation: str,
    mutated_findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Persist canonical JSON then append matching owner mutation events.

    There is no cross-file transaction in this repository. The canonical index
    remains the source of truth, while a provenance append failure is surfaced
    to the caller and intentionally leaves a detectable runtime-invalid row.
    Retrying the owner mutation repairs that state without an unsafe rollback.
    """
    for finding in mutated_findings:
        if isinstance(finding, dict):
            _attach_validation_summary_digest(findings_dir, finding)
    events = _prepare_owner_provenance(
        mutated_findings,
        target=target,
        operation=operation,
    )
    _write_finding_payload(path, payload)
    _append_mutation_events(mutation_events_path(findings_dir), events)
    return events


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


def _normalize_existing_row_for_owner_mutation(
    findings_dir: str | Path,
    finding: dict[str, Any],
    *,
    target: str,
) -> dict[str, Any]:
    """Normalize an existing row without re-authorizing untrusted finality."""
    normalized = _normalize_finding(finding)
    provenance = verify_finalized_finding_owner_provenance(
        findings_dir,
        normalized,
        target=target,
    )
    if not provenance.get("required") or provenance.get("valid"):
        return normalized
    return _quarantine_finality_claim(
        normalized,
        reason=str(provenance.get("reason") or "owner-provenance-invalid"),
    )


def _line_count(path: Path) -> int:
    if not path.is_file():
        return 0
    with path.open(encoding="utf-8", errors="replace") as handle:
        return sum(1 for line in handle if line.rstrip("\n"))


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


def _claim_rubric(vuln_type: str) -> dict[str, Any]:
    """Build an explicitly incomplete rubric for an unindexed claim.

    A root JSON may contain a natural-language PoC or copied response snippets,
    but it is not a linked raw request/response or `/validate` result.  Do not
    feed those prose fields to the keyword rubric, otherwise self-described
    evidence could accidentally become candidate-ready.
    """
    rubric = rubric_for(vuln_type)
    missing = [
        {"id": requirement.id, "label": requirement.label}
        for requirement in rubric.requirements
    ]
    return {
        "rubric_id": rubric.id,
        "title": rubric.title,
        "status": "needs-evidence",
        "ready": False,
        "score": 0,
        "satisfied_count": 0,
        "total": len(rubric.requirements),
        "satisfied": [],
        "missing": missing,
        "missing_labels": [item["label"] for item in missing],
        "next_actions": [requirement.next_action for requirement in rubric.requirements],
        "strong_evidence": False,
        "summary": (
            f"{rubric.id}:needs-evidence score=0 satisfied=0/{len(rubric.requirements)} "
            "(root JSON claim is not linked validation evidence)"
        ),
    }


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
        "validation_status": "candidate",
        "report_status": "not_generated",
        "evidence_rubric": _claim_rubric(normalized_type),
    }


def list_root_finding_claims(
    findings_dir: str | Path,
    *,
    target: str | None = None,
    include_reconciled: bool = False,
) -> list[dict[str, Any]]:
    """Return direct root JSON claims not yet owned by ``findings.json``.

    This is intentionally read-only so ``autopilot_state`` can surface an
    interrupted/manual claim before any checkpoint is run.  The CLI checkpoint
    calls :func:`reconcile_root_finding_claims` to persist the same projection.
    """
    root = Path(findings_dir)
    if not root.is_dir():
        return []
    resolved_target = str(target or root.name)
    canonical = _load_finding_payload(
        root / "findings.json",
        root,
        target=resolved_target,
        migrate_legacy=False,
    )
    reconciled_revisions: set[tuple[str, str]] = set()
    for item in canonical.get("findings", []):
        if not isinstance(item, dict):
            continue
        for source in _normalized_claim_source_entries(item):
            source_file = str(source.get("source_file") or "")
            revision = str(source.get("revision") or "")
            if source_file and revision:
                reconciled_revisions.add((source_file, revision))

    claims: list[dict[str, Any]] = []
    for path in sorted(root.glob("*.json")):
        payload = _load_json_value(path)
        if not isinstance(payload, dict):
            continue
        claim = _root_claim_from_json(root, path, payload, target=resolved_target)
        if not claim:
            continue
        if not include_reconciled and (
            str(claim.get("claim_source_file") or ""),
            str(claim.get("claim_revision") or ""),
        ) in reconciled_revisions:
            continue
        claims.append(claim)

    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    claims.sort(
        key=lambda item: (
            -severity_rank.get(str(item.get("severity") or "").lower(), 0),
            str(item.get("claim_source_file") or ""),
        )
    )
    return claims


def reconcile_root_finding_claims(
    findings_dir: str | Path,
    *,
    target: str | None = None,
) -> dict[str, Any]:
    """Persist direct root JSON claims through the canonical finding owner.

    The operation is idempotent.  It intentionally creates only an
    ``candidate`` with an explicitly incomplete evidence rubric; it never
    upgrades a prose claim to ``validated`` or report-ready.
    """
    root = Path(findings_dir)
    resolved_target = str(target or root.name)
    claims = list_root_finding_claims(root, target=resolved_target)
    if not claims:
        return {
            "status": "noop",
            "claims": [],
            "created": 0,
            "updated": 0,
            "path": str(root / "findings.json"),
        }

    result = upsert_findings(root, claims, target=resolved_target)
    return {
        "status": "updated",
        "claims": [
            {
                "id": str(item.get("id") or ""),
                "source_file": str(item.get("claim_source_file") or ""),
            }
            for item in result.get("findings", [])
            if isinstance(item, dict)
        ],
        "created": int(result.get("created", 0) or 0),
        "updated": int(result.get("updated", 0) or 0),
        "path": str(result.get("path") or root / "findings.json"),
    }


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


def _finding_semantic_key(finding: dict[str, Any]) -> tuple[str, str]:
    endpoint = str(finding.get("url") or finding.get("endpoint") or "").strip().rstrip("/")
    vuln_class = str(
        finding.get("vuln_class")
        or finding.get("type")
        or finding.get("category")
        or "finding"
    ).strip().lower().replace("-", "_")
    return endpoint, vuln_class


def _generated_finding_id(finding: dict[str, Any]) -> str:
    endpoint, vuln_class = _finding_semantic_key(finding)
    source = str(finding.get("source_file") or finding.get("source") or "")
    raw = str(finding.get("raw") or finding.get("reason") or "")
    identity = f"{endpoint}|{vuln_class}" if endpoint else f"{vuln_class}|{source}|{raw}"
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
    migrate_legacy: bool = False,
) -> dict[str, Any]:
    raw = _load_json_value(path)
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, list):
        return {}
    payload = _legacy_list_to_index(findings_dir, raw, target=target)
    if migrate_legacy:
        _write_payload_with_owner_provenance(
            path,
            payload,
            findings_dir=findings_dir,
            target=str(payload.get("target") or target or findings_dir.name),
            operation="legacy_migration",
            mutated_findings=[
                item for item in payload.get("findings", []) if isinstance(item, dict)
            ],
        )
    return payload


def _preserve_existing_finding_state(
    payload: dict[str, Any],
    existing: dict[str, Any],
    *,
    findings_dir: Path,
) -> None:
    """Carry validation/report state across deterministic index rebuilds.

    `findings.json` is not fed only by scanner text files. Evidence runners and
    `/validate` can append replay-backed candidates whose `source_file` points
    at `evidence/.../summary.json`. A rebuild must not silently drop those
    out-of-band rows, otherwise the AI loses validated/candidate state even
    though the raw evidence still exists.
    """
    target = str(payload.get("target") or findings_dir.name)
    existing_by_id = {
        str(item.get("id")): _normalize_existing_row_for_owner_mutation(
            findings_dir,
            item,
            target=target,
        )
        for item in existing.get("findings", [])
        if isinstance(item, dict) and item.get("id")
    }
    rebuilt_ids: set[str] = set()
    for finding in payload.get("findings", []):
        if not isinstance(finding, dict):
            continue
        finding_id = str(finding.get("id") or "")
        if finding_id:
            rebuilt_ids.add(finding_id)
        old = existing_by_id.get(finding_id)
        if not old:
            continue
        for field in PRESERVED_FINDING_FIELDS:
            if field in old:
                finding[field] = old[field]

    preserved_orphans = []
    for finding_id, old in existing_by_id.items():
        if finding_id in rebuilt_ids:
            continue
        if not _should_preserve_orphan_finding(old, target=target):
            continue
        preserved_orphans.append(dict(old))

    if preserved_orphans:
        findings = payload.setdefault("findings", [])
        if isinstance(findings, list):
            findings.extend(preserved_orphans)


def _should_preserve_orphan_finding(finding: dict[str, Any], *, target: str) -> bool:
    """Return whether a finding absent from scanner text output must survive.

    Default, unreviewed scanner rows are deterministic projections of current
    `*.txt` artifacts and can disappear when their source line disappears.
    Replay-backed, validated, rejected, partial, or reported rows are runtime
    state and must be kept unless they are clearly off-target.
    """
    url = str(finding.get("url") or "").strip()
    if url and target and not url_belongs_to_target(url, target):
        return False

    validation_status = str(finding.get("validation_status") or "unvalidated")
    report_status = str(finding.get("report_status") or "not_generated")
    if validation_status not in {"", "unvalidated"}:
        return True
    if report_status not in {"", "not_generated"}:
        return True

    source_file = str(finding.get("source_file") or "")
    raw = str(finding.get("raw") or "")
    if source_file.startswith("evidence/") or "/evidence/" in source_file:
        return True
    if raw.startswith("validation_runner:"):
        return True
    return False


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


def _write_finding_index_unlocked(findings_dir: str | Path, *, target: str | None = None, output: str | Path | None = None) -> dict[str, Any]:
    root = Path(findings_dir)
    payload = build_finding_index(root, target=target)
    output_path = Path(output) if output else root / "findings.json"
    existing = _load_finding_payload(
        output_path,
        root,
        target=target,
        migrate_legacy=False,
    )
    _preserve_existing_finding_state(payload, existing, findings_dir=root)
    _refresh_finding_counts(payload)
    updated_at = _now_utc()
    payload["updated_at"] = updated_at
    mutated_findings = [
        item for item in payload.get("findings", []) if isinstance(item, dict)
    ]
    for finding in mutated_findings:
        finding["updated_at"] = updated_at
    _write_payload_with_owner_provenance(
        output_path,
        payload,
        findings_dir=root,
        target=str(payload.get("target") or target or root.name),
        operation="rebuild_index",
        mutated_findings=mutated_findings,
    )
    return payload


def write_finding_index(findings_dir: str | Path, *, target: str | None = None, output: str | Path | None = None) -> dict[str, Any]:
    with finding_mutation_lock(findings_dir):
        return _write_finding_index_unlocked(findings_dir, target=target, output=output)


def load_finding_index(
    findings_dir: str | Path,
    *,
    migrate_legacy: bool = True,
) -> dict[str, Any]:
    root = Path(findings_dir)
    path = root / "findings.json"
    if not migrate_legacy:
        return _load_finding_payload(path, root, migrate_legacy=False)
    with finding_mutation_lock(root):
        return _load_finding_payload(path, root, migrate_legacy=True)


def _upsert_findings_unlocked(
    findings_dir: str | Path,
    findings: list[dict[str, Any]],
    *,
    target: str | None = None,
) -> dict[str, Any]:
    """Create or merge target findings through the canonical mutation boundary."""
    root = Path(findings_dir)
    path = root / "findings.json"
    payload = load_finding_index(root, migrate_legacy=False) or _empty_finding_index(root, target=target)
    if target:
        payload["target"] = target
    payload.setdefault("schema_version", SCHEMA_VERSION)
    payload.setdefault("findings_dir", str(root))

    resolved_target = str(payload.get("target") or target or root.name)
    existing_rows = [
        _normalize_existing_row_for_owner_mutation(
            root,
            item,
            target=resolved_target,
        )
        for item in payload.get("findings", [])
        if isinstance(item, dict)
    ]
    payload["findings"] = existing_rows
    id_to_index = {str(item.get("id")): idx for idx, item in enumerate(existing_rows)}
    semantic_to_index = {
        _finding_semantic_key(item): idx
        for idx, item in enumerate(existing_rows)
        if _finding_semantic_key(item)[0]
    }

    created = 0
    updated = 0
    mutated: list[dict[str, Any]] = []
    for raw in findings:
        if not isinstance(raw, dict):
            continue
        candidate = _normalize_finding(raw)
        # A caller must not be able to forge owner provenance through an input
        # row. Existing metadata is replaced below by this mutation's event.
        candidate.pop(OWNER_PROVENANCE_FIELD, None)
        index = id_to_index.get(str(candidate.get("id") or ""))
        semantic_key = _finding_semantic_key(candidate)
        if index is None and semantic_key[0]:
            index = semantic_to_index.get(semantic_key)

        if index is None:
            existing_rows.append(candidate)
            index = len(existing_rows) - 1
            created += 1
        else:
            existing = existing_rows[index]
            candidate = _merge_finding_rows(existing, candidate)
            existing_rows[index] = candidate
            updated += 1

        candidate["updated_at"] = _now_utc()
        existing_rows[index] = candidate
        id_to_index[str(candidate.get("id") or "")] = index
        persisted_semantic_key = _finding_semantic_key(candidate)
        if persisted_semantic_key[0]:
            semantic_to_index[persisted_semantic_key] = index
        mutated.append(candidate)

    payload["updated_at"] = _now_utc()
    _refresh_finding_counts(payload)
    _write_payload_with_owner_provenance(
        path,
        payload,
        findings_dir=root,
        target=str(payload.get("target") or target or root.name),
        operation="upsert",
        mutated_findings=mutated,
    )
    return {
        "created": created,
        "updated": updated,
        "findings": mutated,
        "payload": payload,
        "path": str(path),
    }


def upsert_findings(
    findings_dir: str | Path,
    findings: list[dict[str, Any]],
    *,
    target: str | None = None,
) -> dict[str, Any]:
    with finding_mutation_lock(findings_dir):
        return _upsert_findings_unlocked(findings_dir, findings, target=target)


def upsert_finding(
    findings_dir: str | Path,
    finding: dict[str, Any],
    *,
    target: str | None = None,
) -> dict[str, Any]:
    """Single-row convenience wrapper around :func:`upsert_findings`."""
    result = upsert_findings(findings_dir, [finding], target=target)
    return {
        "created": bool(result["created"]),
        "finding": result["findings"][0] if result["findings"] else {},
        "payload": result["payload"],
        "path": result["path"],
    }


def find_finding(
    findings_dir: str | Path,
    finding_id: str,
    *,
    migrate_legacy: bool = True,
) -> dict[str, Any] | None:
    payload = load_finding_index(findings_dir, migrate_legacy=migrate_legacy)
    for finding in payload.get("findings", []):
        if isinstance(finding, dict) and finding.get("id") == finding_id:
            return finding
    return None


def _update_finding_status_unlocked(findings_dir: str | Path, finding_id: str, **updates: Any) -> dict[str, Any] | None:
    """Update one finding in findings.json and return the updated finding."""
    path = Path(findings_dir) / "findings.json"
    payload = load_finding_index(findings_dir, migrate_legacy=False)
    if not payload:
        return None

    updated_finding = None
    for finding in payload.get("findings", []):
        if not isinstance(finding, dict) or finding.get("id") != finding_id:
            continue
        requested_validation = str(updates.get("validation_status") or "").strip().lower()
        if requested_validation == "rejected":
            _verify_source_rejection_summary(findings_dir, finding, updates)
        for key, value in updates.items():
            if key == OWNER_PROVENANCE_FIELD:
                continue
            if value in (None, ""):
                continue
            finding[key] = value
        requested_report = str(updates.get("report_status") or "").strip().lower()
        if requested_validation in FINALIZED_VALIDATION_STATUSES:
            finding.pop("claimed_validation_status", None)
            finding.pop("owner_revalidation_reason", None)
        if requested_report in FINALIZED_REPORT_STATUSES:
            finding.pop("claimed_report_status", None)
            finding.pop("owner_revalidation_reason", None)
        _sync_legacy_lifecycle_fields(finding)
        finding["updated_at"] = _now_utc()
        updated_finding = finding
        break

    if updated_finding is None:
        return None

    _refresh_finding_counts(payload)
    _write_payload_with_owner_provenance(
        path,
        payload,
        findings_dir=Path(findings_dir),
        target=str(payload.get("target") or Path(findings_dir).name),
        operation="status_update",
        mutated_findings=[updated_finding],
    )
    return updated_finding


def update_finding_status(findings_dir: str | Path, finding_id: str, **updates: Any) -> dict[str, Any] | None:
    with finding_mutation_lock(findings_dir):
        return _update_finding_status_unlocked(findings_dir, finding_id, **updates)


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


def main() -> None:
    parser = argparse.ArgumentParser(description="Build findings.json from scanner artifacts")
    parser.add_argument("findings_dir", help="Directory containing scanner findings")
    parser.add_argument("--target", default="", help="Target name override")
    parser.add_argument("--output", default="", help="Output JSON path; defaults to <findings_dir>/findings.json")
    args = parser.parse_args()

    payload = write_finding_index(
        args.findings_dir,
        target=args.target or None,
        output=args.output or None,
    )
    print(f"wrote {payload['total']} finding(s) to {args.output or str(Path(args.findings_dir) / 'findings.json')}")


if __name__ == "__main__":
    main()
