#!/usr/bin/env python3
"""Shared helpers for structured finding follow-up summaries and rendering."""

from __future__ import annotations

import json
from pathlib import Path

try:
    from finding_index import verify_finalized_finding_owner_provenance
    from target_paths import canonical_target_value, target_storage_key
    from tools.target_store import ConflictError, FindingNotFoundError, runtime_store
except ImportError:  # pragma: no cover - package import path
    from tools.finding_index import verify_finalized_finding_owner_provenance
    from tools.target_paths import canonical_target_value, target_storage_key
    from tools.target_store import ConflictError, FindingNotFoundError, runtime_store


def _load_validation_summary_payload(finding: dict) -> tuple[dict, bool]:
    """Load validation_summary JSON and report whether a summary path was present."""
    value = str(finding.get("validation_summary") or "").strip()
    if not value:
        return {}, False
    path = Path(value)
    if not path.is_absolute():
        path = Path.cwd() / path
    if not path.is_file():
        return {}, True
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}, True
    return (payload if isinstance(payload, dict) else {}), True


def _relative_to_repo(path: Path, repo_root: Path) -> str:
    try:
        return str(path.relative_to(repo_root))
    except ValueError:
        return str(path)


def _runner_summary_is_candidate(payload: dict) -> bool:
    """Return whether validation_runner summary should be shown to Claude.

    这里不判断“可报告”，只判断这份 runner 证据是否值得 AI 复核。
    `/validate` 的 7-Question Gate / 4-gate 才能决定 report-ready。
    """
    if not isinstance(payload, dict) or not payload.get("lane"):
        return False
    result = str(payload.get("result") or "").strip().lower()
    return bool(
        payload.get("candidate_ready") is True
        or result in {"tested_finding", "candidate"}
    )


def _compact_runner_summary(payload: dict, path: Path, repo_root: Path) -> dict:
    return {
        "id": str(payload.get("finding_id") or path.parent.name or "").strip(),
        "attempt_id": str(payload.get("attempt_id") or "").strip(),
        "lane": str(payload.get("lane") or "").strip(),
        "evidence_shape": str(payload.get("evidence_shape") or "").strip(),
        "classifier": str(payload.get("classifier") or "").strip(),
        "vuln_class": str(payload.get("vuln_class") or "").strip(),
        "active_dimension": str(payload.get("active_dimension") or "").strip(),
        "request_spec_sha256": str(payload.get("request_spec_sha256") or "").strip(),
        "result": str(payload.get("result") or "").strip(),
        "candidate_ready": bool(payload.get("candidate_ready")),
        "url": str(payload.get("url") or "").strip(),
        "method": str(payload.get("method") or "").strip() or "GET",
        "generated_at": str(payload.get("generated_at") or "").strip(),
        "summary_path": _relative_to_repo(path, repo_root),
        "report_gate": "requires /validate seven-question + four validation gates before report",
    }


def _reviewed_runner_material(store, finding_id: str) -> dict[str, set[str]]:
    """Only exact assessed attempts/material can retire a raw review candidate."""
    try:
        finding = store.finding(finding_id)
    except FindingNotFoundError:
        return {}
    assessment = finding["assessment"]
    if not assessment or not (
        assessment["verdict"] == "refuted"
        or any(not report["stale"] for report in finding["reports"])
    ):
        return {}
    operations: dict[str, set[int]] = {}
    for ref in assessment["evidence"]:
        operations.setdefault(ref["operation_id"], set()).add(ref["step"])
    reviewed: dict[str, set[str]] = {}
    for operation_id, steps in operations.items():
        store.verify_operation(operation_id)
        execution = store.execution(operation_id)
        refs = reviewed.setdefault(execution["attempt_id"], set())
        for observation in execution["observations"]:
            if observation["step"] in steps:
                refs.update(artifact["ref"] for artifact in observation["artifacts"])
    return reviewed


def load_validation_runner_candidate_pool(
    repo_root: Path | str,
    target: str,
    *,
    limit: int = 12,
) -> list[dict]:
    """Load runner-produced candidate evidence as an AI review pool.

    validation_runner 负责 replay/diff/raw evidence 保存；本函数只把这些
    证据摘要暴露给 Claude 选择下一条 `/validate`，不会把它们升级成
    report-ready，也不会替 Claude 做价值排序。
    """
    repo = Path(repo_root)
    resolved_target = canonical_target_value(target)
    target_key = target_storage_key(resolved_target)
    store = runtime_store(repo, resolved_target)
    validation_dir = repo / "evidence" / target_key / "validation"
    if not validation_dir.is_dir():
        return []

    binding = store.binding()
    reviewed: dict[str, dict[str, set[str]]] = {}
    candidates: list[tuple[float, str, dict]] = []
    for path in validation_dir.rglob("summary.json"):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not _runner_summary_is_candidate(payload):
            continue
        compact = _compact_runner_summary(payload, path, repo)
        finding_id = compact["id"]
        if finding_id not in reviewed:
            reviewed[finding_id] = _reviewed_runner_material(store, finding_id)
        raw_refs = set()
        for run in payload.get("runs", []) if isinstance(payload.get("runs"), list) else []:
            artifacts = run.get("artifacts") if isinstance(run, dict) else None
            if isinstance(artifacts, dict):
                raw_refs.update(_relative_to_repo(Path(ref), repo) for ref in artifacts.values()
                                if isinstance(ref, str) and ref)
        if raw_refs and raw_refs <= reviewed[finding_id].get(compact["attempt_id"], set()):
            continue
        try:
            mtime = path.stat().st_mtime
        except OSError:
            mtime = 0.0
        candidates.append((mtime, compact["summary_path"], compact))

    # 只按证据新鲜度和路径稳定排序；不按漏洞价值/优先级排序，避免工具替 AI 决策。
    candidates.sort(key=lambda item: (item[0], item[1]), reverse=True)

    if store.binding() != binding:
        raise ConflictError("Store changed while reading Runner candidates; retry the query")
    return [item for _, _, item in candidates[:max(0, limit)]]


def _validation_report_ready(finding: dict) -> bool | None:
    """Return report-readiness when validation_summary exists.

    `validation_runner` summaries prove lane evidence, but they are not the
    `/validate` report-readiness gate. If a validation_summary path exists and
    lacks the 7-question / 4-gate fields, keep the finding as a validation
    follow-up instead of reporting it.
    """
    payload, summary_present = _load_validation_summary_payload(finding)
    if not summary_present:
        return None
    gate_fields = {
        "all_gates_passed",
        "seven_question_gate_passed",
        "four_validation_gates_passed",
        "seven_question_gate_decision",
    }
    if not payload or not any(field in payload for field in gate_fields):
        return False
    if payload.get("all_gates_passed") is False:
        return False
    if payload.get("seven_question_gate_passed") is False:
        return False
    if payload.get("four_validation_gates_passed") is False:
        return False
    decision = str(payload.get("seven_question_gate_decision") or "").strip().lower()
    if decision in {"kill", "chain_required", "needs_review"}:
        return False
    return bool(payload.get("all_gates_passed") or payload.get("seven_question_gate_passed"))


def _validation_needs_draft_completion(finding: dict) -> bool:
    """Return whether validation evidence passed but the generated draft is incomplete.

    This is distinct from a failed evidence gate.  Sending it back through
    `/validate` would make a completed replay look incomplete merely because a
    report template still has `[INSERT ...]` placeholders.
    """
    payload, summary_present = _load_validation_summary_payload(finding)
    if not summary_present or not payload:
        return False
    if payload.get("validation_evidence_passed") is not True:
        return False
    draft = payload.get("report_draft") if isinstance(payload.get("report_draft"), dict) else {}
    status = str(draft.get("status") or payload.get("report_draft_status") or "").strip().lower()
    return status == "incomplete"


def finding_rank_key(finding: dict) -> tuple[int, int]:
    """Order findings by their recorded severity and confidence, never keyword scores."""
    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    confidence_rank = {"confirmed": 4, "high": 3, "medium": 2, "needs_review": 1}
    severity = str(finding.get("severity", "") or "").lower()
    confidence = str(finding.get("confidence", "") or "").lower()
    return (
        severity_rank.get(severity, 0),
        confidence_rank.get(confidence, 0),
    )


def compact_structured_finding(finding: dict, findings_dir: Path) -> dict:
    """Return the compact structured finding shape used by resume/autopilot."""
    compact = {
        "id": finding.get("id", ""),
        "type": finding.get("type", ""),
        "severity": finding.get("severity", ""),
        "confidence": finding.get("confidence", ""),
        "url": finding.get("url", ""),
        "validation_status": finding.get("validation_status", "unvalidated"),
        "report_status": finding.get("report_status", "not_generated"),
        "source_file": finding.get("source_file", ""),
        "findings_dir": str(findings_dir),
        "validation_summary": finding.get("validation_summary", ""),
    }
    # Incomplete root claims intentionally have no fabricated URL.  Preserve
    # their recovery identity and missing fields so Claude can collect the
    # endpoint/evidence and checkpoint the same canonical candidate.
    for key in (
        "claim_id",
        "claim_source_file",
        "claim_target",
        "claim_status",
        "incomplete_fields",
        "claimed_validation_status",
        "claimed_report_status",
    ):
        value = finding.get(key)
        if value not in (None, "", [], {}):
            compact[key] = value
    return compact


def _compact_draft_completion(finding: dict, findings_dir: Path) -> dict:
    """Project the precise report-completion handoff without reopening evidence."""
    compact = compact_structured_finding(finding, findings_dir)
    payload, _ = _load_validation_summary_payload(finding)
    draft = payload.get("report_draft") if isinstance(payload.get("report_draft"), dict) else {}
    compact["report_draft_path"] = str(
        finding.get("report_draft_path") or payload.get("report_path") or ""
    )
    compact["report_draft_status"] = str(
        draft.get("status") or payload.get("report_draft_status") or "incomplete"
    )
    compact["report_draft_placeholder_count"] = int(draft.get("placeholder_count", 0) or 0)
    return compact


def _compact_owner_revalidation(
    finding: dict,
    findings_dir: Path,
    provenance: dict,
) -> dict:
    """Project an untrusted finality claim as a candidate-only recovery action."""
    compact = compact_structured_finding(finding, findings_dir)
    compact["claimed_validation_status"] = str(
        finding.get("claimed_validation_status") or compact.get("validation_status", "")
    )
    compact["claimed_report_status"] = str(
        finding.get("claimed_report_status") or compact.get("report_status", "")
    )
    compact["validation_status"] = "needs_owner_revalidation"
    compact["report_status"] = "not_generated"
    compact["lifecycle_status"] = "needs_owner_revalidation"
    compact["provenance_reason"] = str(provenance.get("reason") or "owner-provenance-invalid")
    compact["required_action"] = (
        "replay locatable raw evidence, then use /validate with the canonical finding id "
        "so finding_index records a new owner mutation"
    )
    return compact


def summarize_structured_findings(
    findings: list[dict],
    findings_dir: Path,
    *,
    target: str | None = None,
    enforce_owner_provenance: bool = False,
) -> dict:
    """Build validation/report follow-up state from structured findings.

    Runtime readers enable ``enforce_owner_provenance`` so a direct JSON edit
    that claims ``validated``/``generated`` is exposed as a candidate recovery
    item, never as a report or closure handoff.  The default remains useful for
    isolated pure-data callers that do not have an on-disk canonical index.
    """
    valid_findings = [
        item for item in findings
        if isinstance(item, dict) and item.get("id")
    ]
    if not valid_findings:
        return {
            "total": 0,
            "pending_validation": 0,
            "owner_revalidation_pending": 0,
            "draft_completion_pending": 0,
            "validated_pending_report": 0,
            "reported": 0,
            "findings_dir": str(findings_dir),
        }

    eligible_findings = []
    owner_revalidation_pending: list[tuple[dict, dict]] = []
    for item in valid_findings:
        if str(item.get("validation_status") or "").strip().lower() == "needs_owner_revalidation":
            owner_revalidation_pending.append(
                (
                    item,
                    {
                        "reason": str(
                            item.get("owner_revalidation_reason")
                            or "owner-provenance-invalid"
                        )
                    },
                )
            )
            continue
        if enforce_owner_provenance:
            provenance = verify_finalized_finding_owner_provenance(
                findings_dir,
                item,
                target=target,
            )
            if provenance.get("required") and not provenance.get("valid"):
                owner_revalidation_pending.append((item, provenance))
                continue
        eligible_findings.append(item)

    pending_validation = []
    draft_completion_pending = []
    for item in eligible_findings:
        validation_status = str(item.get("validation_status", "unvalidated") or "unvalidated")
        report_status = str(item.get("report_status", "not_generated") or "not_generated")
        if validation_status in {"unvalidated", "candidate", "partial", "needs_validation"}:
            pending_validation.append(item)
            continue
        if (
            validation_status == "validated"
            and report_status != "generated"
            and _validation_report_ready(item) is False
        ):
            if _validation_needs_draft_completion(item):
                draft_completion_pending.append(item)
            else:
                pending_validation.append(item)
    validated_pending_report = [
        item for item in eligible_findings
        if (
            str(item.get("validation_status", "") or "") == "validated"
            and str(item.get("report_status", "not_generated") or "not_generated") != "generated"
            and _validation_report_ready(item) is not False
        )
    ]
    reported = [
        item for item in eligible_findings
        if str(item.get("report_status", "") or "") == "generated"
    ]

    pending_validation.sort(key=finding_rank_key, reverse=True)
    owner_revalidation_pending.sort(key=lambda item: finding_rank_key(item[0]), reverse=True)
    draft_completion_pending.sort(key=finding_rank_key, reverse=True)
    validated_pending_report.sort(key=finding_rank_key, reverse=True)
    evidence_gap_count = len(owner_revalidation_pending)
    result = {
        "total": len(valid_findings),
        "pending_validation": len(pending_validation),
        "owner_revalidation_pending": len(owner_revalidation_pending),
        "draft_completion_pending": len(draft_completion_pending),
        "validated_pending_report": len(validated_pending_report),
        "reported": len(reported),
        "evidence_gap_count": evidence_gap_count,
        "findings_dir": str(findings_dir),
    }
    if pending_validation:
        result["next_validation"] = compact_structured_finding(pending_validation[0], findings_dir)
    if owner_revalidation_pending:
        finding, provenance = owner_revalidation_pending[0]
        result["next_owner_revalidation"] = _compact_owner_revalidation(
            finding,
            findings_dir,
            provenance,
        )
    if draft_completion_pending:
        result["next_draft_completion"] = _compact_draft_completion(
            draft_completion_pending[0],
            findings_dir,
        )
    if validated_pending_report:
        result["next_report"] = compact_structured_finding(validated_pending_report[0], findings_dir)
    return result


def format_structured_findings_lines(
    structured_findings: dict,
    *,
    header: str | None = None,
    inline_header: bool = False,
    indent: str = "",
    next_validation_label: str = "Next validation",
    next_report_label: str = "Next report",
) -> list[str]:
    """Render compact structured finding summary lines for human output."""
    if not structured_findings.get("total"):
        return []

    lines: list[str] = []
    if header and not inline_header:
        lines.append(f"{indent}{header}")
    summary = (
        "total={total}, pending_validation={pending_validation}, owner_revalidation_pending={owner_revalidation_pending}, draft_completion_pending={draft_completion_pending}, "
        "validated_pending_report={validated_pending_report}, reported={reported}, "
        "evidence_gaps={evidence_gap_count}".format(
            total=structured_findings.get("total", 0),
            pending_validation=structured_findings.get("pending_validation", 0),
            owner_revalidation_pending=structured_findings.get("owner_revalidation_pending", 0),
            draft_completion_pending=structured_findings.get("draft_completion_pending", 0),
            validated_pending_report=structured_findings.get("validated_pending_report", 0),
            reported=structured_findings.get("reported", 0),
            evidence_gap_count=structured_findings.get("evidence_gap_count", 0),
        )
    )
    if header and inline_header:
        lines.append(f"{indent}{header} {summary}")
    else:
        lines.append(f"{indent}{summary}")

    next_validation = structured_findings.get("next_validation") or {}
    if next_validation:
        lines.append(
            "{indent}{label}: {id} [{severity}/{confidence}] {type} {url}".format(
                indent=indent,
                label=next_validation_label,
                id=next_validation.get("id", "-"),
                severity=next_validation.get("severity", "-"),
                confidence=next_validation.get("confidence", "-"),
                type=next_validation.get("type", "-"),
                url=next_validation.get("url", ""),
            )
        )

    next_owner_revalidation = structured_findings.get("next_owner_revalidation") or {}
    if next_owner_revalidation:
        lines.append(
            "{indent}Owner revalidation: {id} claimed={validation}/{report} reason={reason}; "
            "treat as candidate until /validate records owner provenance.".format(
                indent=indent,
                id=next_owner_revalidation.get("id", "-"),
                validation=next_owner_revalidation.get("claimed_validation_status", "-"),
                report=next_owner_revalidation.get("claimed_report_status", "-"),
                reason=next_owner_revalidation.get("provenance_reason", "owner-provenance-invalid"),
            )
        )

    next_report = structured_findings.get("next_report") or {}
    if next_report:
        lines.append(
            "{indent}{label}: {id} [{severity}/{confidence}] {type} {url}".format(
                indent=indent,
                label=next_report_label,
                id=next_report.get("id", "-"),
                severity=next_report.get("severity", "-"),
                confidence=next_report.get("confidence", "-"),
                type=next_report.get("type", "-"),
                url=next_report.get("url", ""),
            )
        )
    next_draft_completion = structured_findings.get("next_draft_completion") or {}
    if next_draft_completion:
        lines.append(
            "{indent}Report draft completion: {id} status={status} placeholders={count} path={path}".format(
                indent=indent,
                id=next_draft_completion.get("id", "-"),
                status=next_draft_completion.get("report_draft_status", "incomplete"),
                count=next_draft_completion.get("report_draft_placeholder_count", 0),
                path=next_draft_completion.get("report_draft_path", ""),
            )
        )
    return lines


def format_validation_runner_candidate_lines(
    candidates: list[dict],
    *,
    header: str | None = None,
    indent: str = "",
    limit: int = 6,
) -> list[str]:
    """Render runner candidate evidence without implying report readiness."""
    if not candidates:
        return []
    lines: list[str] = []
    if header:
        lines.append(f"{indent}{header}")
    for item in candidates[:limit]:
        lines.append(
            "{indent}{id} [{lane}/{result}] {method} {url}; "
            "evidence={summary_path}; gate={gate}".format(
                indent=indent,
                id=item.get("id", "-"),
                lane=item.get("lane", "-"),
                result=item.get("result", "-"),
                method=item.get("method", "GET"),
                url=item.get("url", ""),
                summary_path=item.get("summary_path", ""),
                gate=item.get("report_gate", "requires /validate before report"),
            )
        )
    return lines
