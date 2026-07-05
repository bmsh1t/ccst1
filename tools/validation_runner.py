#!/usr/bin/env python3
"""Deterministic validation runner for Claude-driven security findings.

Validation Runner v1 intentionally stays small:

- authz-public-exposure: one anonymous/read-only request, sensitive exposure check.
- authz-role-replay: anonymous/owner/peer replay on the same surface from case_state.
- sqli-result-diff: baseline vs single-variable perturbation, structural diff.
- marker-replay: exact request replay plus inert marker evidence check.
- idor-actor-pair: owner vs peer exact replay plus response diff and evidence gate.
- idor-skeleton: create a two-actor evidence bundle skeleton without guessing sessions.

AI 仍负责选择 hypothesis、解释业务影响、决定是否升级/降级；本工具只负责稳定
执行 replay / diff / evidence bundle / ledger 写入。
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parents[1]
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

try:
    from tools.action_queue import (
        ACTIVE_STATUSES,
        load_queue,
        resolve_action,
        save_queue,
        select_next_action,
        summarize_queue,
    )
    from tools.evidence_ledger import record_entry
    from tools.evidence_rubric import compact_evidence_rubric, evaluate_candidate_evidence
    from tools.finding_index import update_finding_status
    from tools.public_exposure_signals import (
        public_exposure_candidate_ready as shared_public_exposure_candidate_ready,
        public_exposure_marker_sources as shared_public_exposure_marker_sources,
        public_exposure_markers as shared_public_exposure_markers,
    )
    from tools.response_diff import diff_responses, snapshot_response
    from tools.target_case_state import complete_backlog, load_case_state
    from tools.target_paths import canonical_target_value, target_storage_key
except ImportError:  # pragma: no cover - direct tools/ execution
    from action_queue import (  # type: ignore
        ACTIVE_STATUSES,
        load_queue,
        resolve_action,
        save_queue,
        select_next_action,
        summarize_queue,
    )
    from evidence_ledger import record_entry  # type: ignore
    from evidence_rubric import compact_evidence_rubric, evaluate_candidate_evidence  # type: ignore
    from finding_index import update_finding_status  # type: ignore
    from public_exposure_signals import (  # type: ignore
        public_exposure_candidate_ready as shared_public_exposure_candidate_ready,
        public_exposure_marker_sources as shared_public_exposure_marker_sources,
        public_exposure_markers as shared_public_exposure_markers,
    )
    from response_diff import diff_responses, snapshot_response  # type: ignore
    from target_case_state import complete_backlog, load_case_state  # type: ignore
    from target_paths import canonical_target_value, target_storage_key  # type: ignore


SCHEMA_VERSION = 1
SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "POST"}
SQLI_PROBE_RE = re.compile(
    r"('|--|/\*|\*/|;|\)\)|\b(?:or|and|union|select|where|from|sleep|benchmark|"
    r"waitfor|pg_sleep|information_schema|null|true|false)\b|\$(?:ne|gt|regex|where)\b|\{\s*\"?\$)",
    re.I,
)
SQLI_ERROR_RE = re.compile(
    r"SQL syntax|sqlite|mysql|mariadb|postgres|postgresql|psql|oracle|ORA-\d+|"
    r"mssql|SQL Server|ODBC|JDBC|PDOException|SequelizeDatabaseError|"
    r"near ['\"][^'\"]+['\"]: syntax error|unterminated quoted string|"
    r"MongoError|CastError|BSON|NoSQL",
    re.I,
)

RUNNER_RESULT_TO_FINDING_STATUS = {
    "tested_finding": "validated",
    "candidate": "partial",
    "tested_clean": "rejected",
    "dead_end": "rejected",
}
RUNNER_RESULT_TO_QUEUE_STATUS = {
    "tested_finding": "validated",
    "candidate": "candidate",
    "tested_clean": "tested",
    "dead_end": "dead-end",
}
QUEUE_UPGRADE_TARGET_STATUSES = {"candidate", "validated"}
QUEUE_UPGRADABLE_FINAL_STATUSES = {"tested", "dead-end", "blocked"}
LANE_TO_VULN_CLASS = {
    "authz_public_exposure": "Authz",
    "authz_role_replay": "Authz",
    "sqli_result_diff": "SQLi",
    "marker_replay": "RCE",
    "idor_actor_pair": "IDOR",
}


def _dedupe_keep_order(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        text = str(item or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _safe_id(value: str, default: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._:-]+", "_", str(value or "").strip()).strip("._-")
    return cleaned[:120] or default


def _default_finding_id(lane: str, url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    path = parsed.path or "root"
    suffix = _safe_id(path.replace("/", "_"), "endpoint")
    return f"{lane}-{suffix}"


def _bundle_dir(repo_root: Path, target: str, finding_id: str) -> Path:
    target_key = target_storage_key(canonical_target_value(target))
    return repo_root / "evidence" / target_key / "validation" / _safe_id(finding_id, "finding")


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _read_json_object(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _rel(path: Path, repo_root: Path) -> str:
    try:
        return str(path.relative_to(repo_root))
    except ValueError:
        return str(path)


def _summary_path(summary: dict[str, Any], repo_root: Path) -> Path | None:
    raw = str(summary.get("summary_path") or "").strip()
    if not raw:
        return None
    path = Path(raw)
    if not path.is_absolute():
        path = repo_root / path
    return path


def _findings_dir(repo_root: Path, target: str) -> Path:
    key = target_storage_key(canonical_target_value(target))
    return repo_root / "findings" / key


def _normalized_url_for_match(url: str) -> str:
    parsed = urllib.parse.urlparse(str(url or "").strip())
    if not parsed.scheme or not parsed.netloc:
        return str(url or "").strip().rstrip("/")
    path = parsed.path or "/"
    query = f"?{parsed.query}" if parsed.query else ""
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{path}{query}".rstrip("/")


def _find_existing_finding_id_by_url(
    findings_dir: Path,
    *,
    url: str,
    finding_type: str,
    vuln_class: str,
) -> str:
    payload = _read_json_object(findings_dir / "findings.json")
    needle = _normalized_url_for_match(url)
    if not needle:
        return ""
    compatible_types = {str(finding_type or "").lower()}
    if str(vuln_class or "").lower() == "authz":
        compatible_types.update({"auth_bypass", "exposure"})

    for item in payload.get("findings", []):
        if not isinstance(item, dict):
            continue
        if _normalized_url_for_match(str(item.get("url") or "")) != needle:
            continue
        item_type = str(item.get("type") or item.get("category") or "").lower()
        item_class = str(item.get("vuln_class") or "").lower()
        if item_type in compatible_types or item_class == str(vuln_class or "").lower():
            return str(item.get("id") or "")
    return ""


def _runner_finding_type(vuln_class: str, lane: str) -> str:
    value = str(vuln_class or "").strip().lower()
    lane_value = str(lane or "").strip().lower()
    if value == "idor" or lane_value == "idor_actor_pair":
        return "idor"
    if value == "authz" or lane_value == "authz_public_exposure":
        return "auth_bypass"
    if value == "sqli" or lane_value == "sqli_result_diff":
        return "sqli"
    if value == "rce":
        return "ssti" if lane_value == "marker_replay" else "cve"
    return value.replace("-", "_") or "exposure"


def _runner_finding_severity(finding_type: str) -> str:
    if finding_type in {"sqli", "ssti", "auth_bypass"}:
        return "high"
    if finding_type in {"idor", "exposure"}:
        return "medium"
    return "medium"


def _create_runner_finding(
    findings_dir: Path,
    summary: dict[str, Any],
    *,
    validation_status: str,
    validation_summary: str,
    vuln_class: str,
) -> dict[str, Any]:
    """Create a structured finding from deterministic runner evidence.

    This bridge is intentionally finding-grade only.  It lets case-state-first
    validation enter the report queue even when no scanner artifact created a
    prior findings.json row.
    """
    finding_id = str(summary.get("finding_id") or "").strip()
    target = str(summary.get("target") or "").strip()
    url = str(summary.get("url") or summary.get("raw_endpoint") or "").strip()
    lane = str(summary.get("lane") or "").strip()
    finding_type = _runner_finding_type(vuln_class, lane)
    path = findings_dir / "findings.json"
    payload = _read_json_object(path)
    if not payload:
        payload = {
            "schema_version": 1,
            "generated_at": now_utc(),
            "target": target,
            "findings_dir": str(findings_dir),
            "total": 0,
            "counts": {"severity": {}, "type": {}, "confidence": {}},
            "artifacts": {"summary_json": "", "summary_txt": ""},
            "findings": [],
        }

    findings = payload.setdefault("findings", [])
    if not isinstance(findings, list):
        findings = []
        payload["findings"] = findings

    finding = next(
        (item for item in findings if isinstance(item, dict) and item.get("id") == finding_id),
        None,
    )
    if finding is None:
        finding = {
            "id": finding_id,
            "type": finding_type,
            "category": finding_type,
            "title": f"Validated {vuln_class or finding_type} on {url or target}",
            "summary": str((summary.get("evidence_rubric") or {}).get("summary") or summary.get("result") or "")[:240],
            "url": url,
            "severity": _runner_finding_severity(finding_type),
            "confidence": "confirmed",
            "source_file": str(summary.get("summary_path") or ""),
            "line_number": 0,
            "template_id": "",
            "raw": f"validation_runner:{lane}:{finding_id}",
            "validation_status": "unvalidated",
            "report_status": "not_generated",
        }
        findings.append(finding)

    finding.update({
        "type": finding_type,
        "category": finding.get("category") or finding_type,
        "url": url or finding.get("url", ""),
        "confidence": "confirmed",
        "validation_status": validation_status,
        "validation_summary": validation_summary,
        "validated_at": str(summary.get("generated_at") or now_utc()),
        "vuln_class": vuln_class,
        "updated_at": now_utc(),
    })
    finding.setdefault("report_status", "not_generated")
    finding.setdefault("severity", _runner_finding_severity(finding_type))

    payload["total"] = len([item for item in findings if isinstance(item, dict)])
    severity_counts: dict[str, int] = {}
    type_counts: dict[str, int] = {}
    confidence_counts: dict[str, int] = {}
    for item in findings:
        if not isinstance(item, dict):
            continue
        severity = str(item.get("severity") or "medium")
        ftype = str(item.get("type") or "exposure")
        confidence = str(item.get("confidence") or "medium")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        type_counts[ftype] = type_counts.get(ftype, 0) + 1
        confidence_counts[confidence] = confidence_counts.get(confidence, 0) + 1
    payload["counts"] = {
        "severity": dict(sorted(severity_counts.items())),
        "type": dict(sorted(type_counts.items())),
        "confidence": dict(sorted(confidence_counts.items())),
    }

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return finding


def _endpoint_markers(url: str) -> list[str]:
    """Return full URL and path markers for matching validation queue items."""
    raw = str(url or "").strip()
    markers = [raw] if raw else []
    parsed = urllib.parse.urlparse(raw)
    if parsed.scheme and parsed.netloc:
        path_query = parsed.path or "/"
        if parsed.query:
            path_query = f"{path_query}?{parsed.query}"
        markers.extend([path_query, parsed.path or "/"])
    return [item for item in markers if item]


def _queue_action_matches_summary(action: dict[str, Any], summary: dict[str, Any]) -> bool:
    """Match active action-queue validation items to a runner result.

    The queue may have been created from checkpoint prose, so matching must work
    even when the only stable identifier is the finding id embedded in text.
    """
    finding_id = str(summary.get("finding_id") or "").strip()
    markers = _endpoint_markers(str(summary.get("url") or summary.get("endpoint") or ""))
    metadata = action.get("metadata") if isinstance(action.get("metadata"), dict) else {}
    case_state_ref = summary.get("case_state_ref") if isinstance(summary.get("case_state_ref"), dict) else {}
    case_state_write_back = (
        summary.get("case_state_write_back")
        if isinstance(summary.get("case_state_write_back"), dict)
        else {}
    )
    backlog_id = str(
        case_state_ref.get("backlog_id")
        or case_state_write_back.get("id")
        or ""
    ).strip()
    if backlog_id and str(metadata.get("backlog_id") or "").strip() == backlog_id:
        return True
    haystack = " ".join(
        str(value or "")
        for value in (
            action.get("id"),
            action.get("source_id"),
            action.get("type"),
            action.get("evidence"),
            action.get("next_question"),
            action.get("action"),
            action.get("command_hint"),
            metadata.get("finding_id"),
            metadata.get("endpoint"),
            metadata.get("url"),
            metadata.get("backlog_id"),
        )
    )
    if finding_id and finding_id in haystack:
        return True
    action_type = str(action.get("type") or "").lower()
    if action_type in {"validation", "candidate-evidence-gap", "ranked-surface", "surface-review", "coverage-gap"}:
        return any(marker and marker in haystack for marker in markers)
    return False


def _sync_finding_status(summary: dict[str, Any], *, repo_root: Path) -> dict[str, Any]:
    target = str(summary.get("target") or "").strip()
    finding_id = str(summary.get("finding_id") or "").strip()
    result = str(summary.get("result") or "").strip()
    status = RUNNER_RESULT_TO_FINDING_STATUS.get(result)
    if not target or not finding_id or not status:
        return {"status": "skipped", "reason": "missing target/finding/result or non-final runner result"}

    findings_dir = _findings_dir(repo_root, target)
    summary_path = _summary_path(summary, repo_root)
    vuln_class = str(summary.get("vuln_class") or "").strip() or LANE_TO_VULN_CLASS.get(
        str(summary.get("lane") or ""), ""
    )
    updated = update_finding_status(
        findings_dir,
        finding_id,
        validation_status=status,
        validation_summary=str(summary_path) if summary_path else str(summary.get("summary_path") or ""),
        validated_at=str(summary.get("generated_at") or now_utc()),
        vuln_class=vuln_class,
        confidence="confirmed" if result == "tested_finding" else "",
    )
    if not updated:
        finding_type = _runner_finding_type(vuln_class, str(summary.get("lane") or ""))
        existing_id = _find_existing_finding_id_by_url(
            findings_dir,
            url=str(summary.get("url") or summary.get("endpoint") or ""),
            finding_type=finding_type,
            vuln_class=vuln_class,
        )
        if existing_id:
            updated = update_finding_status(
                findings_dir,
                existing_id,
                validation_status=status,
                validation_summary=str(summary_path) if summary_path else str(summary.get("summary_path") or ""),
                validated_at=str(summary.get("generated_at") or now_utc()),
                vuln_class=vuln_class,
                confidence="confirmed" if result == "tested_finding" else "",
            )
            if updated:
                return {
                    "status": "updated",
                    "findings_dir": str(findings_dir),
                    "finding_id": existing_id,
                    "requested_finding_id": finding_id,
                    "validation_status": updated.get("validation_status", ""),
                    "matched_by": "url",
                }
    if not updated:
        if result == "tested_finding":
            created = _create_runner_finding(
                findings_dir,
                summary,
                validation_status=status,
                validation_summary=str(summary_path) if summary_path else str(summary.get("summary_path") or ""),
                vuln_class=vuln_class,
            )
            return {
                "status": "created",
                "findings_dir": str(findings_dir),
                "finding_id": finding_id,
                "validation_status": created.get("validation_status", ""),
            }
        return {
            "status": "skipped",
            "reason": "finding not found",
            "findings_dir": str(findings_dir),
            "finding_id": finding_id,
        }
    return {
        "status": "updated",
        "findings_dir": str(findings_dir),
        "finding_id": finding_id,
        "validation_status": updated.get("validation_status", ""),
    }


def _candidate_queue_followup(summary: dict[str, Any]) -> dict[str, Any]:
    """把 runner 的 candidate 结果转成下一步补证据动作。

    candidate 说明“同一条 replay 已经跑完，但证据还不够报告”。如果 action_queue
    仍保留原 surface-review 文案，下一轮会重复执行同一 runner。这里把动作降维成
    evidence-gap，让 Claude 补 policy/object/private-marker/impact，而不是机械重放。
    """
    rubric = summary.get("evidence_rubric") if isinstance(summary.get("evidence_rubric"), dict) else {}
    missing = [
        str(item).strip()
        for item in (rubric.get("missing_labels") or rubric.get("missing") or [])
        if str(item).strip()
    ]
    next_step = ""
    for item in rubric.get("next_actions") or []:
        next_step = str(item or "").strip()
        if next_step:
            break
    next_step = next_step.rstrip(".")
    finding_id = str(summary.get("finding_id") or "").strip()
    url = str(summary.get("url") or summary.get("endpoint") or "").strip()
    summary_ref = str(summary.get("summary_path") or "").strip()
    rubric_status = str(rubric.get("status") or "candidate").strip()
    lane = str(summary.get("lane") or "").strip()

    action = (
        "Candidate evidence gap for {id} on {url}: rubric={status}, missing={missing}. "
        "Next evidence step: {step}. Evidence summary: {summary_ref}. "
        "Do not rerun the same replay unless new actor/object/policy evidence changes the test."
    ).format(
        id=finding_id or "-",
        url=url or "-",
        status=rubric_status,
        missing=", ".join(missing[:4]) or "candidate evidence",
        step=next_step or "fill the missing candidate evidence item, then rerun /validate if reportable",
        summary_ref=summary_ref or "-",
    )
    return {
        "type": "candidate-evidence-gap",
        "action": action,
        "next_question": "Fill the missing evidence or downgrade this candidate; do not repeat the same replay blindly.",
        "command_hint": "fill missing rubric evidence, then /validate",
        "metadata": {
            "finding_id": finding_id,
            "url": url,
            "summary_path": summary_ref,
            "runner": lane,
            "rubric_status": rubric_status,
            "missing_evidence": missing,
            "next_evidence_step": next_step,
        },
    }


def _patch_candidate_queue_followup(
    repo_root: Path,
    *,
    target: str,
    action_id: str,
    summary: dict[str, Any],
) -> dict[str, Any]:
    """把已匹配 action 改写为 candidate-evidence-gap 并保存。"""
    followup = _candidate_queue_followup(summary)
    queue = load_queue(repo_root, target)
    patched = False
    for action in queue.get("actions", []):
        if not isinstance(action, dict):
            continue
        if str(action.get("id") or "") != action_id:
            continue
        action["type"] = followup["type"]
        action["action"] = followup["action"]
        action["next_question"] = followup["next_question"]
        action["command_hint"] = followup["command_hint"]
        metadata = action.get("metadata") if isinstance(action.get("metadata"), dict) else {}
        metadata.update(followup["metadata"])
        action["metadata"] = metadata
        patched = True
        break
    if not patched:
        return {"patched": False}
    path = save_queue(repo_root, target, queue)
    return {
        "patched": True,
        "path": str(path),
        "next": select_next_action(queue),
        "summary": summarize_queue(queue),
    }


def _sync_action_queue(summary: dict[str, Any], *, repo_root: Path) -> dict[str, Any]:
    target = str(summary.get("target") or "").strip()
    result = str(summary.get("result") or "").strip()
    queue_status = RUNNER_RESULT_TO_QUEUE_STATUS.get(result)
    if not target or not queue_status:
        return {"status": "skipped", "reason": "missing target or non-final runner result"}

    queue = load_queue(repo_root, target)
    matched: dict[str, Any] | None = None
    final_upgrade_match: dict[str, Any] | None = None
    for action in queue.get("actions", []):
        if not isinstance(action, dict):
            continue
        status = str(action.get("status") or "queued")
        if not _queue_action_matches_summary(action, summary):
            continue
        if status in ACTIVE_STATUSES:
            matched = action
            break
        if (
            queue_status in QUEUE_UPGRADE_TARGET_STATUSES
            and status in QUEUE_UPGRADABLE_FINAL_STATUSES
            and final_upgrade_match is None
        ):
            final_upgrade_match = action
    if not matched:
        matched = final_upgrade_match
    if not matched:
        return {"status": "skipped", "reason": "no matching active or upgradable action"}

    summary_ref = str(summary.get("summary_path") or "")
    resolved = resolve_action(
        repo_root,
        target=target,
        action_id=str(matched.get("id") or ""),
        status=queue_status,
        result=f"validation-runner-result={result}; summary={summary_ref}",
        notes=f"runner={summary.get('lane', '')}",
    )
    response = {
        "status": "updated",
        "id": resolved.get("id", ""),
        "action_status": resolved.get("status", ""),
    }
    if queue_status == "candidate" and response["id"]:
        patch = _patch_candidate_queue_followup(
            repo_root,
            target=target,
            action_id=str(response["id"]),
            summary=summary,
        )
        response["candidate_followup"] = patch
    return response


def sync_runner_artifacts(summary: dict[str, Any], *, repo_root: Path) -> dict[str, Any]:
    """Best-effort sync from deterministic runner output into autopilot state.

    Runner evidence is valuable only if `/autopilot` stops asking for the same
    validation again.  Keep this best-effort: evidence generation must not fail
    just because findings.json or action_queue state is absent.
    """
    if str(summary.get("result") or "") == "skeleton":
        return {"status": "skipped", "reason": "skeleton result does not close validation state"}
    updates: dict[str, Any] = {}
    try:
        updates["finding"] = _sync_finding_status(summary, repo_root=repo_root)
    except Exception as exc:  # pragma: no cover - defensive state sync
        updates["finding"] = {"status": "error", "error": str(exc)}
    try:
        updates["action_queue"] = _sync_action_queue(summary, repo_root=repo_root)
    except Exception as exc:  # pragma: no cover - defensive state sync
        updates["action_queue"] = {"status": "error", "error": str(exc)}
    return {"status": "updated", **updates}


def parse_headers(values: list[str] | None) -> dict[str, str]:
    headers: dict[str, str] = {}
    for raw in values or []:
        if ":" not in raw:
            raise ValueError(f"header must be 'Name: value': {raw!r}")
        name, value = raw.split(":", 1)
        name = name.strip()
        if not name:
            raise ValueError(f"header name is empty: {raw!r}")
        headers[name] = value.strip()
    return headers


def _format_request(method: str, url: str, headers: dict[str, str], body: str = "") -> str:
    parsed = urllib.parse.urlparse(url)
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"
    lines = [f"{method.upper()} {path} HTTP/1.1", f"Host: {parsed.netloc}"]
    for name, value in headers.items():
        lines.append(f"{name}: {value}")
    if body:
        lines.append(f"Content-Length: {len(body.encode('utf-8'))}")
    lines.append("")
    lines.append(body)
    return "\n".join(lines)


def _format_response(status: int, reason: str, headers: dict[str, str], body: str) -> str:
    lines = [f"HTTP/1.1 {status} {reason}".rstrip()]
    for name, value in headers.items():
        lines.append(f"{name}: {value}")
    lines.append("")
    lines.append(body)
    return "\n".join(lines)


def request_once(
    *,
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: str = "",
    timeout: int = 10,
) -> dict[str, Any]:
    """Replay one HTTP request and return raw evidence fields."""
    method_u = str(method or "GET").upper()
    headers = dict(headers or {})
    data = body.encode("utf-8") if body else None
    request = urllib.request.Request(url, data=data, headers=headers, method=method_u)
    request_text = _format_request(method_u, url, headers, body)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
            status = int(response.status)
            reason = str(response.reason or "")
            response_headers = {str(k): str(v) for k, v in response.headers.items()}
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        status = int(exc.code)
        reason = str(exc.reason or "")
        response_headers = {str(k): str(v) for k, v in exc.headers.items()}
    body_text = raw.decode("utf-8", errors="replace")
    return {
        "url": url,
        "method": method_u,
        "request_text": request_text,
        "status": status,
        "reason": reason,
        "headers": response_headers,
        "body": body_text,
        "response_text": _format_response(status, reason, response_headers, body_text),
    }


def public_exposure_markers(url: str, body: str) -> list[str]:
    return shared_public_exposure_markers(url, body)


def public_exposure_marker_sources(url: str, body: str) -> dict[str, list[str]]:
    """按共享 helper 提取 url/body marker，避免 path-only 或叙述文本误报。"""
    return shared_public_exposure_marker_sources(url, body)


def public_exposure_candidate_ready(status: int, marker_sources: dict[str, list[str]]) -> bool:
    return shared_public_exposure_candidate_ready(status, marker_sources)


def _public_exposure_impact_text(markers: list[str]) -> str:
    marker_set = set(markers or [])
    if "secret-like" in marker_set:
        return "business impact: sensitive secret/token/private data exposure"
    if "security-answer" in marker_set:
        return "business impact: sensitive security-question/account-recovery data exposure"
    if "oauth" in marker_set:
        return "business impact: oauth/client configuration exposure"
    if marker_set & {"admin", "configuration"}:
        return "business impact: admin/application configuration exposure"
    return "business impact: public data exposure"


def looks_like_sqli_probe(value: str) -> bool:
    """Return True when the perturbation is injection-shaped, not ordinary search text."""
    return bool(SQLI_PROBE_RE.search(str(value or "")))


def _sqli_probe_features(value: str) -> set[str]:
    """Classify the perturbation shape for SQLi evidence gating.

    A quote or comment is a useful probe, but it is not by itself proof of SQLi:
    search/filter endpoints often return fewer rows for odd punctuation.  The
    runner therefore separates probe shape from promotion evidence.
    """
    text = str(value or "").lower()
    features: set[str] = set()
    if re.search(r"['\"`]|--|/\*|\*/|\)\)", text):
        features.add("syntax-breaker")
    if re.search(r"\bunion\b|\bselect\b|\binformation_schema\b|\bfrom\b", text):
        features.add("union-or-select")
    if re.search(r"\b(?:or|and)\b|(?:\b|\D)[01]\s*=\s*[01](?:\D|$)|\btrue\b|\bfalse\b", text):
        features.add("boolean")
    if re.search(r"\bsleep\s*\(|benchmark\s*\(|pg_sleep\s*\(|waitfor\b", text):
        features.add("time-delay")
    if re.search(r"\$(?:ne|gt|regex|where)\b|\{\s*\"?\$", text):
        features.add("nosql-operator")
    if ";" in text:
        features.add("stacked-or-separator")
    return features


def _sqli_run_evidence(
    *,
    variant_value: str,
    baseline_body: str,
    variant_body: str,
    diff: dict[str, Any],
) -> dict[str, Any]:
    """Return lane-specific SQLi promotion evidence for one replay run.

    Strong evidence is deliberately narrower than a material diff.  This keeps
    the runner from promoting ordinary search-result changes, while still
    preserving the diff and next-action guidance for Claude to reason about.
    """
    features = _sqli_probe_features(variant_value)
    changed = diff.get("changed") or {}
    count_delta = (diff.get("json_count") or {}).get("delta")
    body_delta = int((diff.get("body_length") or {}).get("delta", 0) or 0)
    fields_added = list((diff.get("json_fields") or {}).get("added") or [])
    fields_removed = list((diff.get("json_fields") or {}).get("removed") or [])
    status = diff.get("status") or {}
    status_changed = bool(changed.get("status"))
    baseline_status = int(status.get("baseline") or 0)
    variant_status = int(status.get("variant") or 0)

    reasons: list[str] = []
    ambiguous: list[str] = []

    baseline_has_sql_error = bool(SQLI_ERROR_RE.search(str(baseline_body or "")))
    variant_has_sql_error = bool(SQLI_ERROR_RE.search(str(variant_body or "")))
    if variant_has_sql_error and not baseline_has_sql_error:
        reasons.append("variant-only database/parser error marker")

    if isinstance(count_delta, int) and count_delta > 0 and features & {
        "boolean",
        "union-or-select",
        "nosql-operator",
        "syntax-breaker",
    }:
        reasons.append(f"injection-shaped probe expanded JSON result count by {count_delta}")

    if fields_added and features & {"boolean", "union-or-select", "nosql-operator"}:
        reasons.append("injection-shaped probe added JSON fields: " + ",".join(fields_added[:5]))

    if status_changed and variant_status >= 500 and baseline_status < 500:
        if variant_has_sql_error:
            reasons.append(f"variant changed status {baseline_status}->{variant_status} with DB error marker")
        else:
            ambiguous.append(
                f"variant changed status {baseline_status}->{variant_status} without DB error marker"
            )

    if "time-delay" in features and not reasons:
        ambiguous.append("time-shaped probe needs a timing runner, not body diff alone")

    if not reasons and (changed.get("json_count") or changed.get("json_fields") or abs(body_delta) > 20):
        if isinstance(count_delta, int) and count_delta < 0:
            ambiguous.append(
                "variant reduced result count; ordinary search/filter/parser behavior is possible"
            )
        elif fields_removed and not fields_added:
            ambiguous.append(
                "variant only removed JSON fields; this is not enough for SQLi promotion"
            )
        else:
            ambiguous.append(
                "material response diff lacks DB error, result expansion, or boolean/union/nosql confirmation"
            )

    return {
        "strong": bool(reasons),
        "features": sorted(features),
        "reasons": reasons,
        "ambiguous": ambiguous,
    }


def _is_success_status(status: int) -> bool:
    return 200 <= int(status or 0) < 300


def _is_denied_status(status: int) -> bool:
    return int(status or 0) in {401, 403, 404}


def _actor_context_differs(
    *,
    url: str,
    peer_url: str,
    owner_headers: dict[str, str],
    peer_headers: dict[str, str],
    owner_body: str,
    peer_body: str,
) -> bool:
    """Avoid validating a fake actor diff with two identical request contexts."""
    return (
        url != peer_url
        or owner_headers != peer_headers
        or str(owner_body or "") != str(peer_body or "")
    )


PRIVATE_JSON_KEYS = {
    "email",
    "userid",
    "username",
    "account",
    "accountid",
    "address",
    "addressid",
    "order",
    "orderid",
    "invoice",
    "invoiceid",
    "basket",
    "basketid",
    "card",
    "cardnumber",
    "phone",
    "tenant",
    "tenantid",
    "org",
    "orgid",
    "organization",
    "organizationid",
    "token",
    "secret",
}
PRIVATE_TEXT_RE = re.compile(
    r"(?i)([A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}|user[_-]?id|account|address|order|invoice|basket|tenant|organization)"
)


def _meaningful_value(value: Any) -> bool:
    if value in (None, "", [], {}):
        return False
    if isinstance(value, str) and not value.strip():
        return False
    return True


def _json_has_private_shape(value: Any) -> bool:
    if isinstance(value, dict):
        for key, child in value.items():
            key_norm = re.sub(r"[^a-z0-9]+", "", str(key).lower())
            if key_norm in PRIVATE_JSON_KEYS and _meaningful_value(child):
                return True
            if _json_has_private_shape(child):
                return True
        return False
    if isinstance(value, list):
        return any(_json_has_private_shape(item) for item in value)
    if isinstance(value, str):
        return bool(PRIVATE_TEXT_RE.search(value))
    return False


def _private_body_match(owner_body: str, peer_body: str) -> bool:
    """Return true for exact matches that are actually private-object shaped.

    Empty collection responses such as `{"status":"success","data":[]}` often
    match across actors and are useful signals, but they are not finding-grade
    IDOR evidence without a private marker or private fields.
    """
    owner_text = str(owner_body or "").strip()
    peer_text = str(peer_body or "").strip()
    if owner_text != peer_text or len(peer_text) < 20:
        return False
    try:
        parsed = json.loads(peer_text)
    except json.JSONDecodeError:
        return bool(PRIVATE_TEXT_RE.search(peer_text))
    return _json_has_private_shape(parsed)


def _case_state_session_header(state: dict[str, Any], actor: str) -> tuple[str, dict[str, str]]:
    invalid = {"invalid", "expired", "revoked"}
    for session_id, session in (state.get("sessions") or {}).items():
        if not isinstance(session, dict) or session.get("actor") != actor:
            continue
        if str(session.get("validity") or "unknown").lower() in invalid:
            continue
        headers = session.get("headers") if isinstance(session.get("headers"), dict) else {}
        normalized = {
            str(name).strip(): str(value).strip()
            for name, value in headers.items()
            if str(name).strip() and str(value).strip()
        }
        name = str(session.get("header_name") or "").strip()
        value = str(session.get("header_value") or "").strip()
        if name and value:
            normalized.setdefault(name, value)
        if normalized:
            return str(session_id), normalized
    raise ValueError(f"case_state session missing for actor: {actor}")


def _case_state_backlog(state: dict[str, Any], backlog_id: str) -> dict[str, Any]:
    for item in state.get("validation_backlog") or []:
        if isinstance(item, dict) and item.get("id") == backlog_id:
            return item
    raise ValueError(f"case_state backlog id not found: {backlog_id}")


def resolve_idor_actor_pair_from_case_state(
    *,
    repo_root: Path,
    target: str,
    backlog_id: str = "",
    owner_actor: str = "",
    peer_actor: str = "",
    object_ref: str = "",
    url: str = "",
    peer_url: str = "",
    owner_headers: dict[str, str] | None = None,
    peer_headers: dict[str, str] | None = None,
    expect_marker: str = "",
) -> dict[str, Any]:
    """Resolve IDOR actor-pair replay material from target case_state.json."""
    state = load_case_state(repo_root, target)
    backlog: dict[str, Any] = _case_state_backlog(state, backlog_id) if backlog_id else {}
    if backlog and backlog.get("runner") != "idor-actor-pair":
        raise ValueError(f"case_state backlog is not idor-actor-pair: {backlog_id}")

    ref = object_ref or str(backlog.get("object_ref") or "")
    if not ref:
        raise ValueError("object_ref is required when using --from-case-state")
    obj = (state.get("objects") or {}).get(ref)
    if not isinstance(obj, dict):
        raise ValueError(f"case_state object_ref not found: {ref}")

    owner = owner_actor or str(backlog.get("owner_actor") or obj.get("owner_actor") or "")
    peer = peer_actor or str(backlog.get("peer_actor") or "")
    if not owner:
        raise ValueError(f"case_state owner actor missing for object_ref: {ref}")
    if not peer:
        raise ValueError("peer_actor is required when using --from-case-state")
    if owner == peer:
        raise ValueError("owner_actor and peer_actor must differ when using --from-case-state")
    if owner not in (state.get("actors") or {}):
        raise ValueError(f"case_state owner actor not found: {owner}")
    if peer not in (state.get("actors") or {}):
        raise ValueError(f"case_state peer actor not found: {peer}")

    owner_session_id, owner_session_header = _case_state_session_header(state, owner)
    peer_session_id, peer_session_header = _case_state_session_header(state, peer)
    merged_owner_headers = {**owner_session_header, **dict(owner_headers or {})}
    merged_peer_headers = {**peer_session_header, **dict(peer_headers or {})}
    endpoint = url or str(backlog.get("endpoint") or obj.get("endpoint") or "")
    if not endpoint:
        raise ValueError(f"case_state endpoint missing for object_ref: {ref}")

    return {
        "url": endpoint,
        "peer_url": peer_url or endpoint,
        "owner_headers": merged_owner_headers,
        "peer_headers": merged_peer_headers,
        "expect_marker": expect_marker or str(obj.get("private_marker") or ""),
        "case_state_ref": {
            "backlog_id": backlog_id,
            "object_ref": ref,
            "owner_actor": owner,
            "peer_actor": peer,
            "owner_session_id": owner_session_id,
            "peer_session_id": peer_session_id,
        },
    }


def _case_state_actor_ids_with_sessions(state: dict[str, Any]) -> list[str]:
    """Return deterministic actor ids that have usable session headers."""
    actors = state.get("actors") if isinstance(state.get("actors"), dict) else {}
    out: list[str] = []
    for actor in sorted(str(item) for item in actors):
        try:
            _case_state_session_header(state, actor)
        except ValueError:
            continue
        out.append(actor)
    return out


def resolve_authz_role_replay_from_case_state(
    *,
    repo_root: Path,
    target: str,
    owner_actor: str = "",
    peer_actor: str = "",
    owner_headers: dict[str, str] | None = None,
    peer_headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Resolve two authenticated actor contexts from target case_state.json."""
    state = load_case_state(repo_root, target)
    actors_with_sessions = _case_state_actor_ids_with_sessions(state)
    owner = str(owner_actor or "").strip()
    peer = str(peer_actor or "").strip()
    if owner and owner not in (state.get("actors") or {}):
        raise ValueError(f"case_state owner actor not found: {owner}")
    if peer and peer not in (state.get("actors") or {}):
        raise ValueError(f"case_state peer actor not found: {peer}")
    if not owner:
        owner = actors_with_sessions[0] if actors_with_sessions else ""
    if not peer:
        peer = next((actor for actor in actors_with_sessions if actor != owner), "")
    if not owner:
        raise ValueError("owner_actor is required or at least one case_state actor session must exist")
    if not peer:
        raise ValueError("peer_actor is required or at least two case_state actor sessions must exist")
    if owner == peer:
        raise ValueError("owner_actor and peer_actor must differ")
    owner_session_id, owner_session_header = _case_state_session_header(state, owner)
    peer_session_id, peer_session_header = _case_state_session_header(state, peer)
    return {
        "owner_actor": owner,
        "peer_actor": peer,
        "owner_headers": {**owner_session_header, **dict(owner_headers or {})},
        "peer_headers": {**peer_session_header, **dict(peer_headers or {})},
        "case_state_ref": {
            "owner_actor": owner,
            "peer_actor": peer,
            "owner_session_id": owner_session_id,
            "peer_session_id": peer_session_id,
        },
    }


def _record_ledger_if_needed(
    *,
    repo_root: Path,
    no_ledger: bool,
    target: str,
    endpoint: str,
    method: str,
    vuln_class: str,
    actor: str,
    object_scope: str,
    variant: str,
    result: str,
    source: str,
    evidence_ref: str,
    notes: str,
    browser_observed: bool,
    redline_checked: bool,
    state_changing: bool | None = None,
) -> dict[str, Any] | None:
    if no_ledger:
        return None
    return record_entry(
        repo_root,
        target=target,
        endpoint=endpoint,
        method=method,
        vuln_class=vuln_class,
        actor=actor,
        object_scope=object_scope,
        variant=variant,
        source=source,
        result=result,
        browser_observed=browser_observed,
        replayed=True,
        state_changing=bool(state_changing) if state_changing is not None else method.upper() not in SAFE_METHODS,
        redline_checked=redline_checked,
        evidence_ref=evidence_ref,
        notes=notes,
    )


def run_authz_public_exposure(
    *,
    repo_root: Path,
    target: str,
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: str = "",
    timeout: int = 10,
    finding_id: str = "",
    no_ledger: bool = False,
    browser_observed: bool = False,
) -> dict[str, Any]:
    finding_id = finding_id or _default_finding_id("authz-public-exposure", url)
    bundle = _bundle_dir(repo_root, target, finding_id)
    response = request_once(url=url, method=method, headers=headers, body=body, timeout=timeout)
    request_path = bundle / "baseline.request.txt"
    response_path = bundle / "baseline.response.txt"
    _write_text(request_path, response["request_text"])
    _write_text(response_path, response["response_text"])

    marker_sources = public_exposure_marker_sources(url, response["body"])
    markers = sorted(set(marker_sources["url"]) | set(marker_sources["body"]))
    candidate_ready = public_exposure_candidate_ready(response["status"], marker_sources)
    result = "tested_finding" if candidate_ready else "tested_clean"
    impact_text = _public_exposure_impact_text(markers) if candidate_ready else ""
    finding = {
        "type": "auth_bypass",
        "url": url,
        "summary": (
            f"{response['status']} {len(response['body'])} {url} "
            f"markers={','.join(markers)} unauthenticated public exposure {impact_text}".strip()
        ),
        "raw": f"anonymous replay returned {response['status']} with markers {markers}; {impact_text}".strip(),
        "confidence": "confirmed" if candidate_ready else "medium",
    }
    rubric = compact_evidence_rubric(evaluate_candidate_evidence(finding))
    if not candidate_ready:
        # The generic authz rubric sees words such as "admin" in URLs and can
        # otherwise look candidate-ready even when the lane-specific classifier
        # correctly rejected the response for lacking body-backed exposure.
        # Keep runner output internally consistent: path/name markers are useful
        # leads, not Candidate evidence.
        rubric.update({
            "status": "tested-clean",
            "ready": False,
            "score": 0,
            "missing": ["body_backed_sensitive_marker"],
            "missing_labels": ["body-backed sensitive/admin/config marker"],
            "next_actions": [
                "Do not promote path/name markers alone; pivot to body-backed exposure or role/object diff."
            ],
            "summary": "authz:tested-clean score=0 missing=body-backed sensitive/admin/config marker",
        })
    evidence_ref = _rel(response_path, repo_root)
    notes = (
        f"Validation runner authz-public-exposure: anonymous {method.upper()} returned "
        f"{response['status']} with markers={markers or []}."
    )
    ledger = _record_ledger_if_needed(
        repo_root=repo_root,
        no_ledger=no_ledger,
        target=target,
        endpoint=url,
        method=method,
        vuln_class="Authz",
        actor="anonymous",
        object_scope="none",
        variant="unauth_denied",
        result=result,
        source="validation-runner:authz-public-exposure",
        evidence_ref=evidence_ref,
        notes=notes,
        browser_observed=browser_observed,
        redline_checked=True,
    )

    summary = {
        "schema_version": SCHEMA_VERSION,
        "lane": "authz_public_exposure",
        "target": canonical_target_value(target),
        "finding_id": finding_id,
        "url": url,
        "method": method.upper(),
        "generated_at": now_utc(),
        "result": result,
        "candidate_ready": candidate_ready,
        "markers": markers,
        "marker_sources": marker_sources,
        "baseline": snapshot_response(response["status"], response["headers"], response["body"]),
        "artifacts": {
            "baseline_request": _rel(request_path, repo_root),
            "baseline_response": _rel(response_path, repo_root),
        },
        "evidence_rubric": rubric,
        "ledger_record": ledger,
        "ai_next": {
            "hypothesis": "anonymous user can read admin/config-like data",
            "next_action": "If business impact is meaningful, run /validate using this evidence bundle; otherwise downgrade to informational/dead-end.",
            "stop_condition": "No 200 response or no body-backed sensitive/admin/config marker.",
        },
    }
    summary_path = bundle / "summary.json"
    _write_json(summary_path, summary)
    summary["summary_path"] = _rel(summary_path, repo_root)
    _write_json(summary_path, summary)
    return summary


def _role_replay_material_diff(diff: dict[str, Any]) -> bool:
    """Return true for owner/peer response differences worth AI review."""
    details = diff.get("diff") if isinstance(diff.get("diff"), dict) else {}
    if not details:
        return False
    changed = details.get("changed") if isinstance(details.get("changed"), dict) else {}
    if changed.get("status"):
        return True
    if changed.get("json_count") or changed.get("json_fields"):
        return True
    # Length-only differences are common for nonce/CAPTCHA/randomized SVG,
    # timestamps, personalized copy, compression, and other dynamic-but-equivalent
    # responses. Without a status, JSON count, or field-shape delta, this is not
    # strong enough to create an Authz candidate; Claude can still inspect the
    # raw bundle if another signal makes the surface interesting.
    return False


AUTHENTICATED_COLLECTION_IDENTITY_FIELDS = {
    "account",
    "accountid",
    "address",
    "customer",
    "customerid",
    "email",
    "firstname",
    "ip",
    "lastloginip",
    "lastname",
    "phone",
    "profileimage",
    "tenant",
    "tenantid",
    "user",
    "userid",
    "username",
    "workspace",
    "workspaceid",
}
AUTHENTICATED_COLLECTION_AUTHZ_FIELDS = {
    "deletedat",
    "groups",
    "isactive",
    "isadmin",
    "org",
    "orgid",
    "permissions",
    "role",
    "roles",
}
AUTHENTICATED_COLLECTION_SECRET_FIELDS = {
    "apitoken",
    "apikey",
    "deluxetoken",
    "password",
    "passwordhash",
    "recoverytoken",
    "secret",
    "token",
}


def _normalized_json_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value or "").lower())


def _json_data_node(value: Any) -> Any:
    if isinstance(value, dict):
        for key in ("data", "items", "results", "users", "accounts", "records"):
            if key in value:
                return value.get(key)
    return value


def _collection_dict_items(value: Any) -> list[dict[str, Any]]:
    """Return top-level collection items without deep-scanning arbitrary prose."""
    node = _json_data_node(value)
    if isinstance(node, list):
        return [item for item in node if isinstance(item, dict)]
    return []


def _authenticated_broad_exposure_evidence(status: int, body: str) -> dict[str, Any]:
    """Detect authenticated-only broad data exposure candidates.

    这是 role-aware replay 的保守候选信号，不直接判定漏洞。只有当匿名不可读、
    登录态可读、响应是集合型 JSON，且集合字段体现身份/权限/账号敏感语义时，
    才返回 candidate。这样可覆盖“低权限用户能枚举用户目录/角色/账号元数据”的
    实战线索，同时避免把普通 public catalog 当成 authz finding。
    """
    evidence = {
        "candidate": False,
        "reason": "",
        "item_count": 0,
        "fields": [],
        "identity_fields": [],
        "authz_fields": [],
        "secret_fields": [],
    }
    if not _is_success_status(status):
        evidence["reason"] = "authenticated response was not successful"
        return evidence
    try:
        payload = json.loads(body or "")
    except (TypeError, ValueError, json.JSONDecodeError):
        evidence["reason"] = "authenticated response was not JSON"
        return evidence

    items = _collection_dict_items(payload)
    fields = sorted({_normalized_json_key(key) for item in items[:50] for key in item.keys()})
    identity_hits = sorted(set(fields) & AUTHENTICATED_COLLECTION_IDENTITY_FIELDS)
    authz_hits = sorted(set(fields) & AUTHENTICATED_COLLECTION_AUTHZ_FIELDS)
    secret_hits = sorted(set(fields) & AUTHENTICATED_COLLECTION_SECRET_FIELDS)

    evidence.update({
        "item_count": len(items),
        "fields": fields,
        "identity_fields": identity_hits,
        "authz_fields": authz_hits,
        "secret_fields": secret_hits,
    })

    has_sensitive_account_shape = bool(secret_hits) or (
        bool(identity_hits) and (bool(authz_hits) or len(identity_hits) >= 2)
    )
    if len(items) >= 2 and has_sensitive_account_shape:
        evidence["candidate"] = True
        evidence["reason"] = (
            "authenticated-only collection exposes account/identity/authz-shaped fields; "
            "requires policy and role expectation review"
        )
    else:
        evidence["reason"] = "no broad authenticated account/identity/authz collection shape"
    return evidence


def run_authz_role_replay(
    *,
    repo_root: Path,
    target: str,
    url: str,
    method: str = "GET",
    owner_headers: dict[str, str] | None = None,
    peer_headers: dict[str, str] | None = None,
    owner_body: str = "",
    peer_body: str | None = None,
    include_anonymous: bool = True,
    timeout: int = 10,
    finding_id: str = "",
    repeat: int = 1,
    no_ledger: bool = False,
    browser_observed: bool = False,
    state_changing: bool = False,
    redline_checked: bool = True,
    case_state_ref: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Replay one surface as anonymous/owner/peer without claiming object IDOR.

    This lane is intentionally conservative: role/status/body differences are
    ``candidate`` evidence for Claude to interpret, while only body-backed
    anonymous sensitive exposure promotes directly to ``tested_finding``.
    """
    method_u = method.upper()
    owner_headers = dict(owner_headers or {})
    peer_headers = dict(peer_headers or {})
    peer_body = owner_body if peer_body is None else peer_body
    if not _actor_context_differs(
        url=url,
        peer_url=url,
        owner_headers=owner_headers,
        peer_headers=peer_headers,
        owner_body=owner_body,
        peer_body=peer_body,
    ):
        raise ValueError("owner and peer request contexts are identical; provide distinct actor headers/body")

    finding_id = finding_id or _default_finding_id("authz-role-replay", url)
    bundle = _bundle_dir(repo_root, target, finding_id)
    repeat = max(1, int(repeat or 1))
    runs: list[dict[str, Any]] = []
    public_marker_sources: dict[str, list[str]] = {"url": [], "body": []}
    authenticated_exposure_checks: list[dict[str, Any]] = []

    for idx in range(1, repeat + 1):
        prefix = "" if repeat == 1 else f"{idx}."
        anonymous = (
            request_once(url=url, method=method_u, headers={}, body="", timeout=timeout)
            if include_anonymous else None
        )
        owner = request_once(url=url, method=method_u, headers=owner_headers, body=owner_body, timeout=timeout)
        peer = request_once(url=url, method=method_u, headers=peer_headers, body=peer_body, timeout=timeout)

        if anonymous is not None:
            anon_req = bundle / f"{prefix}anonymous.request.txt"
            anon_resp = bundle / f"{prefix}anonymous.response.txt"
            _write_text(anon_req, anonymous["request_text"])
            _write_text(anon_resp, anonymous["response_text"])
            public_marker_sources = public_exposure_marker_sources(url, anonymous["body"])
        owner_req = bundle / f"{prefix}owner.request.txt"
        owner_resp = bundle / f"{prefix}owner.response.txt"
        peer_req = bundle / f"{prefix}peer.request.txt"
        peer_resp = bundle / f"{prefix}peer.response.txt"
        _write_text(owner_req, owner["request_text"])
        _write_text(owner_resp, owner["response_text"])
        _write_text(peer_req, peer["request_text"])
        _write_text(peer_resp, peer["response_text"])

        owner_peer_diff = diff_responses(
            baseline_status=owner["status"],
            baseline_headers=owner["headers"],
            baseline_body=owner["body"],
            variant_status=peer["status"],
            variant_headers=peer["headers"],
            variant_body=peer["body"],
        )
        anonymous_owner_diff = (
            diff_responses(
                baseline_status=anonymous["status"],
                baseline_headers=anonymous["headers"],
                baseline_body=anonymous["body"],
                variant_status=owner["status"],
                variant_headers=owner["headers"],
                variant_body=owner["body"],
            )
            if anonymous is not None else {}
        )
        authenticated_exposure = _authenticated_broad_exposure_evidence(owner["status"], owner["body"])
        authenticated_exposure_checks.append(authenticated_exposure)
        runs.append({
            "iteration": idx,
            "url": url,
            "method": method_u,
            "anonymous_status": anonymous["status"] if anonymous is not None else None,
            "owner_status": owner["status"],
            "peer_status": peer["status"],
            "anonymous_success": _is_success_status(anonymous["status"]) if anonymous is not None else False,
            "owner_success": _is_success_status(owner["status"]),
            "peer_success": _is_success_status(peer["status"]),
            "peer_denied": _is_denied_status(peer["status"]),
            "owner_peer_material_diff": _role_replay_material_diff(owner_peer_diff),
            "anonymous_owner_material_diff": _role_replay_material_diff(anonymous_owner_diff) if anonymous_owner_diff else False,
            "authenticated_exposure_candidate": bool(authenticated_exposure.get("candidate")),
            "artifacts": {
                **({
                    "anonymous_request": _rel(anon_req, repo_root),
                    "anonymous_response": _rel(anon_resp, repo_root),
                } if anonymous is not None else {}),
                "owner_request": _rel(owner_req, repo_root),
                "owner_response": _rel(owner_resp, repo_root),
                "peer_request": _rel(peer_req, repo_root),
                "peer_response": _rel(peer_resp, repo_root),
            },
            "owner_peer_diff": owner_peer_diff,
            "anonymous_owner_diff": anonymous_owner_diff,
        })

    markers = sorted(set(public_marker_sources.get("url", [])) | set(public_marker_sources.get("body", [])))
    public_ready = (
        include_anonymous
        and all(bool(run["anonymous_success"]) for run in runs)
        and public_exposure_candidate_ready(runs[0]["anonymous_status"], public_marker_sources)
    )
    owner_success_all = all(bool(run["owner_success"]) for run in runs)
    role_diff_any = any(bool(run["owner_peer_material_diff"]) for run in runs)
    anonymous_denied_all = include_anonymous and all(
        run["anonymous_status"] is not None and not bool(run["anonymous_success"]) for run in runs
    )
    authenticated_exposure_any = (
        anonymous_denied_all
        and owner_success_all
        and all(bool(run["peer_success"]) for run in runs)
        and all(bool(item.get("candidate")) for item in authenticated_exposure_checks)
    )
    if public_ready:
        result = "tested_finding"
    elif not owner_success_all:
        result = "dead_end"
    elif role_diff_any or authenticated_exposure_any:
        result = "candidate"
    else:
        result = "tested_clean"
    candidate_ready = result == "tested_finding"
    authenticated_exposure_summary = {
        "candidate": bool(authenticated_exposure_any),
        "checks": authenticated_exposure_checks,
        "reason": (
            authenticated_exposure_checks[0].get("reason", "")
            if authenticated_exposure_checks else ""
        ),
    }

    diff_path = bundle / "diff.json"
    _write_json(diff_path, {
        "runs": runs,
        "authenticated_exposure": authenticated_exposure_summary,
    })
    finding = {
        "type": "auth_bypass",
        "url": url,
        "summary": (
            f"authz role replay result={result}; repeat={repeat}; "
            f"anonymous_statuses={[run['anonymous_status'] for run in runs]}; "
            f"owner_statuses={[run['owner_status'] for run in runs]}; "
            f"peer_statuses={[run['peer_status'] for run in runs]}"
        ),
        "raw": (
            f"anonymous markers={markers}; owner/peer material diff={role_diff_any}; "
            f"authenticated broad exposure={authenticated_exposure_any}; "
            "role-aware replay captured"
        ),
        "confidence": "confirmed" if candidate_ready else "medium",
    }
    rubric = compact_evidence_rubric(evaluate_candidate_evidence(finding, vuln_type="authz"))
    if result == "dead_end":
        rubric.update({
            "status": "dead-end",
            "ready": False,
            "score": 0,
            "missing": ["owner_baseline_success"],
            "missing_labels": ["valid owner/authenticated baseline"],
            "next_actions": [
                "Refresh or recapture the authenticated owner request/session before drawing any authz conclusion for this surface."
            ],
            "summary": "authz:dead-end score=0 missing=valid owner/authenticated baseline",
        })
    elif result == "tested_clean":
        rubric.update({
            "status": "tested-clean",
            "ready": False,
            "score": 0,
            "missing": ["role_or_body_backed_authz_delta"],
            "missing_labels": ["role/object/body-backed authorization delta"],
            "next_actions": [
                "No role-specific difference on this exact surface; pivot to object-specific or state-changing workflow evidence."
            ],
            "summary": "authz:tested-clean score=0 missing=role/object/body-backed authorization delta",
        })
    elif result == "candidate" and authenticated_exposure_any and not role_diff_any:
        first_check = authenticated_exposure_checks[0] if authenticated_exposure_checks else {}
        rubric.update({
            "status": "candidate",
            "ready": False,
            "missing": ["policy_or_role_expectation", "object_scope_or_private_marker"],
            "missing_labels": [
                "policy/role expectation for authenticated collection",
                "object-specific private marker or documented admin-only expectation",
            ],
            "next_actions": [
                "Review whether this collection should be admin-only or self-scoped; then pivot to object-specific endpoints, lower-role replay, or policy evidence before reporting."
            ],
            "summary": (
                "authz:candidate authenticated-only broad collection "
                f"items={first_check.get('item_count', 0)} "
                f"identity={first_check.get('identity_fields', [])} "
                f"authz={first_check.get('authz_fields', [])} "
                f"secret={first_check.get('secret_fields', [])}"
            ),
        })
    evidence_ref = _rel(diff_path, repo_root)
    notes = (
        f"Validation runner authz-role-replay: result={result}, repeat={repeat}, "
        f"anonymous_statuses={[run['anonymous_status'] for run in runs]}, "
        f"owner_statuses={[run['owner_status'] for run in runs]}, "
        f"peer_statuses={[run['peer_status'] for run in runs]}."
    )
    ledger = _record_ledger_if_needed(
        repo_root=repo_root,
        no_ledger=no_ledger,
        target=target,
        endpoint=url,
        method=method_u,
        vuln_class="Authz",
        actor="owner",
        object_scope="unknown",
        variant="role_diff",
        result=result,
        source="validation-runner:authz-role-replay",
        evidence_ref=evidence_ref,
        notes=notes,
        browser_observed=browser_observed,
        redline_checked=redline_checked,
        state_changing=state_changing,
    )
    summary = {
        "schema_version": SCHEMA_VERSION,
        "lane": "authz_role_replay",
        "target": canonical_target_value(target),
        "finding_id": finding_id,
        "url": url,
        "method": method_u,
        "generated_at": now_utc(),
        "result": result,
        "candidate_ready": candidate_ready,
        "markers": markers,
        "marker_sources": public_marker_sources,
        "authenticated_exposure": authenticated_exposure_summary,
        "case_state_ref": case_state_ref or {},
        "repeat": repeat,
        "runs": runs,
        "artifacts": {"diff": evidence_ref},
        "evidence_rubric": rubric,
        "ledger_record": ledger,
        "ai_next": {
            "hypothesis": "authenticated actor contexts may reveal a role/object authorization delta on this surface",
            "next_action": "If candidate, inspect raw owner/peer diff or authenticated-only collection fields, then add object/private marker, lower-role, or policy evidence before reporting. If tested_clean, pivot to object-specific endpoints or state-changing workflows.",
            "stop_condition": "Owner baseline fails, owner/peer responses are equivalent, and no authenticated-only account/identity/authz collection is present.",
        },
    }
    summary_path = bundle / "summary.json"
    summary["summary_path"] = _rel(summary_path, repo_root)
    _write_json(summary_path, summary)
    return summary


def _replace_query_param(url: str, param: str, value: str) -> str:
    parsed = urllib.parse.urlparse(url)
    pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    replaced = False
    out: list[tuple[str, str]] = []
    for key, old in pairs:
        if key == param:
            out.append((key, value))
            replaced = True
        else:
            out.append((key, old))
    if not replaced:
        out.append((param, value))
    query = urllib.parse.urlencode(out, doseq=True)
    return urllib.parse.urlunparse(parsed._replace(query=query))


def run_sqli_result_diff(
    *,
    repo_root: Path,
    target: str,
    url: str,
    param: str,
    baseline_value: str,
    variant_value: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    timeout: int = 10,
    finding_id: str = "",
    repeat: int = 1,
    no_ledger: bool = False,
    browser_observed: bool = False,
) -> dict[str, Any]:
    if method.upper() != "GET":
        raise ValueError("sqli-result-diff v1 supports GET query parameters only")
    finding_id = finding_id or _default_finding_id("sqli-result-diff", url)
    bundle = _bundle_dir(repo_root, target, finding_id)
    repeat = max(1, int(repeat or 1))
    baseline_url = _replace_query_param(url, param, baseline_value)
    variant_url = _replace_query_param(url, param, variant_value)
    runs: list[dict[str, Any]] = []

    for idx in range(1, repeat + 1):
        base = request_once(url=baseline_url, method=method, headers=headers, timeout=timeout)
        variant = request_once(url=variant_url, method=method, headers=headers, timeout=timeout)
        prefix = "" if repeat == 1 else f"{idx}."
        base_req = bundle / f"{prefix}baseline.request.txt"
        base_resp = bundle / f"{prefix}baseline.response.txt"
        var_req = bundle / f"{prefix}variant.request.txt"
        var_resp = bundle / f"{prefix}variant.response.txt"
        _write_text(base_req, base["request_text"])
        _write_text(base_resp, base["response_text"])
        _write_text(var_req, variant["request_text"])
        _write_text(var_resp, variant["response_text"])
        diff = diff_responses(
            baseline_status=base["status"],
            baseline_headers=base["headers"],
            baseline_body=base["body"],
            variant_status=variant["status"],
            variant_headers=variant["headers"],
            variant_body=variant["body"],
        )
        sqli_evidence = _sqli_run_evidence(
            variant_value=variant_value,
            baseline_body=base["body"],
            variant_body=variant["body"],
            diff=diff["diff"],
        )
        runs.append({
            "iteration": idx,
            "baseline_url": baseline_url,
            "variant_url": variant_url,
            "artifacts": {
                "baseline_request": _rel(base_req, repo_root),
                "baseline_response": _rel(base_resp, repo_root),
                "variant_request": _rel(var_req, repo_root),
                "variant_response": _rel(var_resp, repo_root),
            },
            **diff,
            "sqli_evidence": sqli_evidence,
        })

    material = [
        bool(run.get("diff", {}).get("changed", {}).get("json_count"))
        or bool(run.get("diff", {}).get("changed", {}).get("status"))
        or bool(run.get("diff", {}).get("changed", {}).get("json_fields"))
        or abs(int(run.get("diff", {}).get("body_length", {}).get("delta", 0) or 0)) > 20
        for run in runs
    ]
    probe_shape = looks_like_sqli_probe(variant_value)
    strong_sqli_evidence = [bool(run.get("sqli_evidence", {}).get("strong")) for run in runs]
    candidate_ready = probe_shape and all(material) and all(strong_sqli_evidence)
    result = "tested_finding" if candidate_ready else "tested_clean"
    diff_summaries = [str(run.get("diff", {}).get("summary") or "") for run in runs]
    sqli_reasons = _dedupe_keep_order([
        reason
        for run in runs
        for reason in (run.get("sqli_evidence", {}).get("reasons") or [])
    ])
    sqli_ambiguous = _dedupe_keep_order([
        reason
        for run in runs
        for reason in (run.get("sqli_evidence", {}).get("ambiguous") or [])
    ])
    finding = {
        "type": "sqli",
        "url": url,
        "summary": (
            f"baseline vs single-variable perturbation on {param}; "
            f"stable differential={all(material)}; strong SQLi evidence={candidate_ready}; "
            f"{'; '.join(diff_summaries)}"
        ),
        "raw": "SQLI-POC-VERIFIED read-only baseline perturbation repeat stable"
        if candidate_ready else "read-only SQLi perturbation did not produce strong SQLi evidence",
        "confidence": "confirmed" if candidate_ready else "medium",
    }
    rubric = compact_evidence_rubric(evaluate_candidate_evidence(finding))
    if not candidate_ready:
        missing = ["strong_sqli_signal"]
        missing_labels = ["DB error / boolean expansion / union-field / NoSQL operator confirmation"]
        if not probe_shape:
            missing.insert(0, "injection_shaped_probe")
            missing_labels.insert(0, "injection-shaped probe")
        if not all(material):
            missing.insert(0, "stable_material_diff")
            missing_labels.insert(0, "stable material response diff")
        rubric.update({
            "status": "tested-clean",
            "ready": False,
            "score": 0,
            "missing": missing,
            "missing_labels": missing_labels,
            "next_actions": [
                "Do not promote quote-only result shrinkage; require DB error, boolean true/false pair, result expansion, added fields, or a dedicated timing lane.",
            ],
            "summary": "sqli:tested-clean score=0 missing=" + ",".join(missing),
        })
    diff_path = bundle / "diff.json"
    _write_json(diff_path, {"runs": runs})
    notes = (
        f"Validation runner SQLi result diff on param={param!r}: "
        f"{'; '.join(diff_summaries[:3])}."
    )
    ledger = _record_ledger_if_needed(
        repo_root=repo_root,
        no_ledger=no_ledger,
        target=target,
        endpoint=url,
        method=method,
        vuln_class="SQLi",
        actor="anonymous",
        object_scope="none",
        variant="replay",
        result=result,
        source="validation-runner:sqli-result-diff",
        evidence_ref=_rel(diff_path, repo_root),
        notes=notes,
        browser_observed=browser_observed,
        redline_checked=True,
    )
    summary = {
        "schema_version": SCHEMA_VERSION,
        "lane": "sqli_result_diff",
        "target": canonical_target_value(target),
        "finding_id": finding_id,
        "url": url,
        "method": method.upper(),
        "param": param,
        "baseline_value": baseline_value,
        "variant_value": variant_value,
        "generated_at": now_utc(),
        "result": result,
        "candidate_ready": candidate_ready,
        "probe_shape": probe_shape,
        "sqli_evidence": {
            "strong": candidate_ready,
            "reasons": sqli_reasons,
            "ambiguous": sqli_ambiguous,
        },
        "repeat": repeat,
        "runs": runs,
        "artifacts": {"diff": _rel(diff_path, repo_root)},
        "evidence_rubric": rubric,
        "ledger_record": ledger,
        "ai_next": {
            "hypothesis": "single input perturbation changes server-side query result shape",
            "next_action": "If diff is stable and read-only, run /validate or add one minimal DBMS/type confirmation only when needed.",
            "stop_condition": "No stable status/count/field/length difference across repeats, or differences are attributable to WAF/router/cache noise.",
        },
    }
    summary_path = bundle / "summary.json"
    summary["summary_path"] = _rel(summary_path, repo_root)
    _write_json(summary_path, summary)
    return summary


def run_marker_replay(
    *,
    repo_root: Path,
    target: str,
    url: str,
    expect_marker: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: str = "",
    timeout: int = 10,
    finding_id: str = "",
    repeat: int = 1,
    vuln_class: str = "RCE",
    no_ledger: bool = False,
    browser_observed: bool = False,
    state_changing: bool = False,
    redline_checked: bool = True,
) -> dict[str, Any]:
    """Replay an exact request and require an inert marker in every response.

    This lane deliberately does not generate payloads. Claude/operator chooses
    the hypothesis and exact safe marker request; the runner only handles stable
    replay, evidence artifacts, rubric, and ledger output.
    """
    marker = str(expect_marker or "")
    if not marker:
        raise ValueError("expect_marker is required")
    finding_id = finding_id or _default_finding_id("marker-replay", url)
    bundle = _bundle_dir(repo_root, target, finding_id)
    repeat = max(1, int(repeat or 1))
    method_u = method.upper()
    runs: list[dict[str, Any]] = []

    for idx in range(1, repeat + 1):
        response = request_once(url=url, method=method_u, headers=headers, body=body, timeout=timeout)
        prefix = "" if repeat == 1 else f"{idx}."
        request_path = bundle / f"{prefix}request.txt"
        response_path = bundle / f"{prefix}response.txt"
        _write_text(request_path, response["request_text"])
        _write_text(response_path, response["response_text"])
        marker_found = marker in response["body"]
        runs.append({
            "iteration": idx,
            "url": url,
            "method": method_u,
            "status": response["status"],
            "marker_found": marker_found,
            "artifacts": {
                "request": _rel(request_path, repo_root),
                "response": _rel(response_path, repo_root),
            },
            "snapshot": snapshot_response(response["status"], response["headers"], response["body"]),
        })

    candidate_ready = all(bool(run["marker_found"]) for run in runs)
    result = "tested_finding" if candidate_ready else "tested_clean"
    finding = {
        "type": vuln_class,
        "url": url,
        "summary": (
            f"exact marker replay for {vuln_class}; marker_present={candidate_ready}; "
            f"repeat={repeat}; method={method_u}"
        ),
        "raw": (
            "rce-poc controlled marker exact request safe proof repeated"
            if candidate_ready
            else "exact marker replay did not show expected inert marker"
        ),
        "confidence": "confirmed" if candidate_ready else "medium",
    }
    rubric = compact_evidence_rubric(evaluate_candidate_evidence(finding, vuln_type=vuln_class))
    summary_path = bundle / "summary.json"
    evidence_ref = _rel(summary_path, repo_root)
    notes = (
        f"Validation runner marker-replay for {vuln_class}: "
        f"marker_present={candidate_ready}, repeat={repeat}, method={method_u}."
    )
    ledger = _record_ledger_if_needed(
        repo_root=repo_root,
        no_ledger=no_ledger,
        target=target,
        endpoint=url,
        method=method_u,
        vuln_class=vuln_class,
        actor="anonymous",
        object_scope="none",
        variant="replay",
        result=result,
        source="validation-runner:marker-replay",
        evidence_ref=evidence_ref,
        notes=notes,
        browser_observed=browser_observed,
        redline_checked=redline_checked,
        state_changing=state_changing,
    )
    summary = {
        "schema_version": SCHEMA_VERSION,
        "lane": "marker_replay",
        "target": canonical_target_value(target),
        "finding_id": finding_id,
        "url": url,
        "method": method_u,
        "vuln_class": vuln_class,
        "generated_at": now_utc(),
        "result": result,
        "candidate_ready": candidate_ready,
        "expect_marker": marker,
        "repeat": repeat,
        "runs": runs,
        "evidence_rubric": rubric,
        "ledger_record": ledger,
        "ai_next": {
            "hypothesis": "exact request causes server-side evaluation/execution observable through an inert marker",
            "next_action": "If marker is stable, use /validate to assess execution context and bounded impact; if absent, refine the hypothesis or downgrade.",
            "stop_condition": "Expected inert marker is absent, unstable across repeats, or only appears in client-side/static reflection without execution context.",
        },
    }
    summary["summary_path"] = _rel(summary_path, repo_root)
    _write_json(summary_path, summary)
    return summary


def run_idor_actor_pair(
    *,
    repo_root: Path,
    target: str,
    url: str,
    method: str = "GET",
    owner_headers: dict[str, str] | None = None,
    peer_headers: dict[str, str] | None = None,
    owner_body: str = "",
    peer_body: str | None = None,
    peer_url: str = "",
    expect_marker: str = "",
    timeout: int = 10,
    finding_id: str = "",
    repeat: int = 1,
    no_ledger: bool = False,
    browser_observed: bool = False,
    state_changing: bool = False,
    redline_checked: bool = True,
    case_state_ref: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Replay the same object/action as owner and peer, then preserve the diff.

    The strong finding gate is intentionally conservative:
    - owner must succeed;
    - peer must also succeed;
    - and either the peer response contains an operator-provided private marker
      or the peer body exactly matches the owner body with a non-trivial private
      object shape.

    If peer access is possible but the response is not strong enough, the runner
    records ``candidate`` rather than pretending the issue is clean or proven.
    """
    method_u = method.upper()
    owner_headers = dict(owner_headers or {})
    peer_headers = dict(peer_headers or {})
    peer_url = peer_url or url
    peer_body = owner_body if peer_body is None else peer_body
    if not _actor_context_differs(
        url=url,
        peer_url=peer_url,
        owner_headers=owner_headers,
        peer_headers=peer_headers,
        owner_body=owner_body,
        peer_body=peer_body,
    ):
        raise ValueError("owner and peer request contexts are identical; provide distinct actor headers/body/url")

    finding_id = finding_id or _default_finding_id("idor-actor-pair", url)
    bundle = _bundle_dir(repo_root, target, finding_id)
    repeat = max(1, int(repeat or 1))
    marker = str(expect_marker or "")
    runs: list[dict[str, Any]] = []

    for idx in range(1, repeat + 1):
        owner = request_once(url=url, method=method_u, headers=owner_headers, body=owner_body, timeout=timeout)
        peer = request_once(url=peer_url, method=method_u, headers=peer_headers, body=peer_body, timeout=timeout)
        prefix = "" if repeat == 1 else f"{idx}."
        owner_req = bundle / f"{prefix}owner.request.txt"
        owner_resp = bundle / f"{prefix}owner.response.txt"
        peer_req = bundle / f"{prefix}peer.request.txt"
        peer_resp = bundle / f"{prefix}peer.response.txt"
        _write_text(owner_req, owner["request_text"])
        _write_text(owner_resp, owner["response_text"])
        _write_text(peer_req, peer["request_text"])
        _write_text(peer_resp, peer["response_text"])
        diff = diff_responses(
            baseline_status=owner["status"],
            baseline_headers=owner["headers"],
            baseline_body=owner["body"],
            variant_status=peer["status"],
            variant_headers=peer["headers"],
            variant_body=peer["body"],
        )
        marker_found = bool(marker and marker in peer["body"])
        exact_body_match = owner["body"] == peer["body"] and len(str(peer["body"] or "").strip()) >= 20
        private_body_match = _private_body_match(owner["body"], peer["body"])
        owner_success = _is_success_status(owner["status"])
        peer_success = _is_success_status(peer["status"])
        peer_denied = _is_denied_status(peer["status"])
        strong_access = owner_success and peer_success and (marker_found if marker else private_body_match)
        ambiguous_access = owner_success and peer_success and not strong_access
        runs.append({
            "iteration": idx,
            "owner_url": url,
            "peer_url": peer_url,
            "method": method_u,
            "owner_status": owner["status"],
            "peer_status": peer["status"],
            "owner_success": owner_success,
            "peer_success": peer_success,
            "peer_denied": peer_denied,
            "marker_found": marker_found,
            "exact_body_match": exact_body_match,
            "private_body_match": private_body_match,
            "strong_access": strong_access,
            "ambiguous_access": ambiguous_access,
            "artifacts": {
                "owner_request": _rel(owner_req, repo_root),
                "owner_response": _rel(owner_resp, repo_root),
                "peer_request": _rel(peer_req, repo_root),
                "peer_response": _rel(peer_resp, repo_root),
            },
            **diff,
        })

    candidate_ready = all(bool(run["strong_access"]) for run in runs)
    owner_success_all = all(bool(run["owner_success"]) for run in runs)
    peer_denied_all = all(bool(run["peer_denied"]) or not bool(run["peer_success"]) for run in runs)
    ambiguous_any = any(bool(run["ambiguous_access"]) for run in runs)
    if not owner_success_all:
        result = "dead_end"
    elif candidate_ready:
        result = "tested_finding"
    elif ambiguous_any and not peer_denied_all:
        result = "candidate"
    else:
        result = "tested_clean"

    diff_path = bundle / "diff.json"
    _write_json(diff_path, {"runs": runs})
    finding = {
        "type": "idor",
        "url": url,
        "summary": (
            f"owner vs peer replay result={result}; repeat={repeat}; "
            f"peer_statuses={[run['peer_status'] for run in runs]}"
        ),
        "raw": (
            "owner peer other user response diff exact request private marker verified"
            if candidate_ready
            else "owner peer replay captured; strong private-data marker not proven"
        ),
        "confidence": "confirmed" if candidate_ready else "medium",
    }
    rubric = compact_evidence_rubric(evaluate_candidate_evidence(finding, vuln_type="idor"))
    notes = (
        f"Validation runner IDOR actor pair: result={result}, "
        f"repeat={repeat}, peer_statuses={[run['peer_status'] for run in runs]}."
    )
    ledger = _record_ledger_if_needed(
        repo_root=repo_root,
        no_ledger=no_ledger,
        target=target,
        endpoint=url,
        method=method_u,
        vuln_class="IDOR",
        actor="peer",
        object_scope="peer",
        variant="id_swap",
        result=result,
        source="validation-runner:idor-actor-pair",
        evidence_ref=_rel(diff_path, repo_root),
        notes=notes,
        browser_observed=browser_observed,
        redline_checked=redline_checked,
        state_changing=state_changing,
    )
    summary = {
        "schema_version": SCHEMA_VERSION,
        "lane": "idor_actor_pair",
        "target": canonical_target_value(target),
        "finding_id": finding_id,
        "url": url,
        "peer_url": peer_url,
        "method": method_u,
        "generated_at": now_utc(),
        "result": result,
        "candidate_ready": candidate_ready,
        "expect_marker": marker,
        "case_state_ref": case_state_ref or {},
        "repeat": repeat,
        "runs": runs,
        "artifacts": {"diff": _rel(diff_path, repo_root)},
        "evidence_rubric": rubric,
        "ledger_record": ledger,
        "ai_next": {
            "hypothesis": "server may return an owner object/action result when replayed as peer/lower-role",
            "next_action": "If result is dead_end, refresh the owner baseline/session/object endpoint before treating the lane as tested. If result is candidate, add a known private marker/object field or second object to distinguish public/generic data from IDOR.",
            "stop_condition": "Owner baseline is invalid, peer is consistently denied, actor contexts are unavailable, or peer response lacks a private marker/exact owner-body match.",
        },
    }
    summary_path = bundle / "summary.json"
    summary["summary_path"] = _rel(summary_path, repo_root)
    _write_json(summary_path, summary)
    return summary


def run_idor_skeleton(
    *,
    repo_root: Path,
    target: str,
    endpoint: str,
    finding_id: str = "",
) -> dict[str, Any]:
    finding_id = finding_id or _default_finding_id("idor-skeleton", endpoint)
    bundle = _bundle_dir(repo_root, target, finding_id)
    skeleton = {
        "schema_version": SCHEMA_VERSION,
        "lane": "idor_actor_pair_skeleton",
        "target": canonical_target_value(target),
        "finding_id": finding_id,
        "endpoint": endpoint,
        "generated_at": now_utc(),
        "result": "skeleton",
        "candidate_ready": False,
        "required_artifacts": {
            "owner_baseline_request": _rel(bundle / "owner.baseline.request.txt", repo_root),
            "owner_baseline_response": _rel(bundle / "owner.baseline.response.txt", repo_root),
            "peer_variant_request": _rel(bundle / "peer.variant.request.txt", repo_root),
            "peer_variant_response": _rel(bundle / "peer.variant.response.txt", repo_root),
            "diff": _rel(bundle / "diff.json", repo_root),
        },
        "ai_next": {
            "hypothesis": "server may trust object id without rebinding it to current actor",
            "next_action": "Capture owner baseline with a test-owned object, replay the same object id as peer/lower-role, then diff status/body/object ownership fields.",
            "stop_condition": "No second actor/session, no test-owned object, or stable 403/404/no sensitive field delta.",
        },
    }
    _write_text(
        bundle / "README.md",
        "# IDOR actor-pair validation skeleton\n\n"
        "Fill the four request/response files with test-owned actor A/B evidence, "
        "then run a response diff and record the ledger entry.\n",
    )
    summary_path = bundle / "summary.json"
    skeleton["summary_path"] = _rel(summary_path, repo_root)
    _write_json(summary_path, skeleton)
    return skeleton


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run deterministic validation evidence lanes")
    sub = parser.add_subparsers(dest="lane", required=True)

    def add_common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--target", required=True)
        p.add_argument("--finding-id", default="")
        p.add_argument("--repo-root", default=str(BASE_DIR))
        p.add_argument("--no-sync", action="store_true", help="Do not sync runner result into findings/action_queue state")

    authz = sub.add_parser("authz-public-exposure", help="Validate anonymous public admin/config exposure")
    add_common(authz)
    authz.add_argument("--url", required=True)
    authz.add_argument("--method", default="GET")
    authz.add_argument("--header", action="append", default=[])
    authz.add_argument("--body", default="")
    authz.add_argument("--timeout", type=int, default=10)
    authz.add_argument("--browser-observed", action="store_true")
    authz.add_argument("--no-ledger", action="store_true")

    authz_role = sub.add_parser("authz-role-replay", help="Replay anonymous/owner/peer actor contexts on one surface")
    add_common(authz_role)
    authz_role.add_argument("--url", required=True)
    authz_role.add_argument("--method", default="GET")
    authz_role.add_argument("--owner-header", action="append", default=[])
    authz_role.add_argument("--peer-header", action="append", default=[])
    authz_role.add_argument("--from-case-state", action="store_true")
    authz_role.add_argument("--owner-actor", default="")
    authz_role.add_argument("--peer-actor", default="")
    authz_role.add_argument("--body", default="")
    authz_role.add_argument("--owner-body", default=None)
    authz_role.add_argument("--peer-body", default=None)
    authz_role.add_argument("--timeout", type=int, default=10)
    authz_role.add_argument("--repeat", type=int, default=1)
    authz_role.add_argument("--no-anonymous", action="store_true")
    authz_role.add_argument("--browser-observed", action="store_true")
    authz_role.add_argument("--state-changing", action="store_true")
    authz_role.add_argument("--redline-checked", action="store_true", default=True)
    authz_role.add_argument("--no-ledger", action="store_true")

    sqli = sub.add_parser("sqli-result-diff", help="Validate read-only SQLi-style result differential")
    add_common(sqli)
    sqli.add_argument("--url", required=True)
    sqli.add_argument("--param", required=True)
    sqli.add_argument("--baseline-value", default="")
    sqli.add_argument("--variant-value", required=True)
    sqli.add_argument("--method", default="GET")
    sqli.add_argument("--header", action="append", default=[])
    sqli.add_argument("--timeout", type=int, default=10)
    sqli.add_argument("--repeat", type=int, default=1)
    sqli.add_argument("--browser-observed", action="store_true")
    sqli.add_argument("--no-ledger", action="store_true")

    marker = sub.add_parser("marker-replay", help="Replay exact request and check for an inert marker")
    add_common(marker)
    marker.add_argument("--url", required=True)
    marker.add_argument("--expect-marker", required=True)
    marker.add_argument("--method", default="GET")
    marker.add_argument("--header", action="append", default=[])
    marker.add_argument("--body", default="")
    marker.add_argument("--timeout", type=int, default=10)
    marker.add_argument("--repeat", type=int, default=1)
    marker.add_argument("--vuln-class", default="RCE")
    marker.add_argument("--browser-observed", action="store_true")
    marker.add_argument("--state-changing", action="store_true")
    marker.add_argument("--redline-checked", action="store_true", default=True)
    marker.add_argument("--no-ledger", action="store_true")

    idor_pair = sub.add_parser("idor-actor-pair", help="Replay owner vs peer actor pair and diff responses")
    add_common(idor_pair)
    idor_pair.add_argument("--url", default="")
    idor_pair.add_argument("--peer-url", default="")
    idor_pair.add_argument("--method", default="GET")
    idor_pair.add_argument("--owner-header", action="append", default=[])
    idor_pair.add_argument("--peer-header", action="append", default=[])
    idor_pair.add_argument("--from-case-state", action="store_true")
    idor_pair.add_argument("--backlog-id", default="")
    idor_pair.add_argument("--owner-actor", default="")
    idor_pair.add_argument("--peer-actor", default="")
    idor_pair.add_argument("--object-ref", default="")
    idor_pair.add_argument("--body", default="")
    idor_pair.add_argument("--owner-body", default=None)
    idor_pair.add_argument("--peer-body", default=None)
    idor_pair.add_argument("--expect-marker", default="")
    idor_pair.add_argument("--timeout", type=int, default=10)
    idor_pair.add_argument("--repeat", type=int, default=1)
    idor_pair.add_argument("--browser-observed", action="store_true")
    idor_pair.add_argument("--state-changing", action="store_true")
    idor_pair.add_argument("--redline-checked", action="store_true", default=True)
    idor_pair.add_argument("--no-ledger", action="store_true")
    idor_pair.add_argument("--complete-case-state", action="store_true", help="Write result back to case_state backlog after replay")

    idor = sub.add_parser("idor-skeleton", help="Create a two-actor IDOR validation skeleton")
    add_common(idor)
    idor.add_argument("--endpoint", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    repo_root = Path(args.repo_root)
    if args.lane == "authz-public-exposure":
        summary = run_authz_public_exposure(
            repo_root=repo_root,
            target=args.target,
            url=args.url,
            method=args.method,
            headers=parse_headers(args.header),
            body=args.body,
            timeout=args.timeout,
            finding_id=args.finding_id,
            no_ledger=args.no_ledger,
            browser_observed=args.browser_observed,
        )
    elif args.lane == "authz-role-replay":
        owner_body = args.body if args.owner_body is None else args.owner_body
        peer_body = owner_body if args.peer_body is None else args.peer_body
        owner_headers = parse_headers(args.owner_header)
        peer_headers = parse_headers(args.peer_header)
        case_state_ref: dict[str, Any] = {}
        if args.from_case_state:
            resolved = resolve_authz_role_replay_from_case_state(
                repo_root=repo_root,
                target=args.target,
                owner_actor=args.owner_actor,
                peer_actor=args.peer_actor,
                owner_headers=owner_headers,
                peer_headers=peer_headers,
            )
            owner_headers = resolved["owner_headers"]
            peer_headers = resolved["peer_headers"]
            case_state_ref = resolved["case_state_ref"]
        summary = run_authz_role_replay(
            repo_root=repo_root,
            target=args.target,
            url=args.url,
            method=args.method,
            owner_headers=owner_headers,
            peer_headers=peer_headers,
            owner_body=owner_body,
            peer_body=peer_body,
            include_anonymous=not args.no_anonymous,
            timeout=args.timeout,
            finding_id=args.finding_id,
            repeat=args.repeat,
            no_ledger=args.no_ledger,
            browser_observed=args.browser_observed,
            state_changing=args.state_changing,
            redline_checked=args.redline_checked,
            case_state_ref=case_state_ref,
        )
    elif args.lane == "sqli-result-diff":
        summary = run_sqli_result_diff(
            repo_root=repo_root,
            target=args.target,
            url=args.url,
            param=args.param,
            baseline_value=args.baseline_value,
            variant_value=args.variant_value,
            method=args.method,
            headers=parse_headers(args.header),
            timeout=args.timeout,
            finding_id=args.finding_id,
            repeat=args.repeat,
            no_ledger=args.no_ledger,
            browser_observed=args.browser_observed,
        )
    elif args.lane == "marker-replay":
        summary = run_marker_replay(
            repo_root=repo_root,
            target=args.target,
            url=args.url,
            expect_marker=args.expect_marker,
            method=args.method,
            headers=parse_headers(args.header),
            body=args.body,
            timeout=args.timeout,
            finding_id=args.finding_id,
            repeat=args.repeat,
            vuln_class=args.vuln_class,
            no_ledger=args.no_ledger,
            browser_observed=args.browser_observed,
            state_changing=args.state_changing,
            redline_checked=args.redline_checked,
        )
    elif args.lane == "idor-actor-pair":
        owner_body = args.body if args.owner_body is None else args.owner_body
        peer_body = owner_body if args.peer_body is None else args.peer_body
        owner_headers = parse_headers(args.owner_header)
        peer_headers = parse_headers(args.peer_header)
        url = args.url
        peer_url = args.peer_url
        expect_marker = args.expect_marker
        case_state_ref: dict[str, Any] = {}
        if args.from_case_state:
            resolved = resolve_idor_actor_pair_from_case_state(
                repo_root=repo_root,
                target=args.target,
                backlog_id=args.backlog_id,
                owner_actor=args.owner_actor,
                peer_actor=args.peer_actor,
                object_ref=args.object_ref,
                url=url,
                peer_url=peer_url,
                owner_headers=owner_headers,
                peer_headers=peer_headers,
                expect_marker=expect_marker,
            )
            url = resolved["url"]
            peer_url = resolved["peer_url"]
            owner_headers = resolved["owner_headers"]
            peer_headers = resolved["peer_headers"]
            expect_marker = resolved["expect_marker"]
            case_state_ref = resolved["case_state_ref"]
        if not url:
            raise ValueError("--url is required unless --from-case-state resolves an object endpoint")
        summary = run_idor_actor_pair(
            repo_root=repo_root,
            target=args.target,
            url=url,
            method=args.method,
            owner_headers=owner_headers,
            peer_headers=peer_headers,
            owner_body=owner_body,
            peer_body=peer_body,
            peer_url=peer_url,
            expect_marker=expect_marker,
            timeout=args.timeout,
            finding_id=args.finding_id,
            repeat=args.repeat,
            no_ledger=args.no_ledger,
            browser_observed=args.browser_observed,
            state_changing=args.state_changing,
            redline_checked=args.redline_checked,
            case_state_ref=case_state_ref,
        )
        if args.complete_case_state:
            backlog_id = str((case_state_ref or {}).get("backlog_id") or "")
            if not args.from_case_state or not backlog_id:
                raise ValueError("--complete-case-state requires --from-case-state with --backlog-id")
            summary["case_state_write_back"] = complete_backlog(
                repo_root,
                args.target,
                backlog_id=backlog_id,
                result=str(summary.get("result") or "candidate"),
                evidence_ref=str(summary.get("summary_path") or ""),
                notes="auto-written by validation_runner --complete-case-state",
            )
    elif args.lane == "idor-skeleton":
        summary = run_idor_skeleton(
            repo_root=repo_root,
            target=args.target,
            endpoint=args.endpoint,
            finding_id=args.finding_id,
        )
    else:  # pragma: no cover - argparse guards this
        raise ValueError(f"unknown lane: {args.lane}")
    if not getattr(args, "no_sync", False):
        summary["sync"] = sync_runner_artifacts(summary, repo_root=repo_root)
        summary_path = _summary_path(summary, repo_root)
        if summary_path is not None:
            _write_json(summary_path, summary)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
