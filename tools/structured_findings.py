#!/usr/bin/env python3
"""Shared helpers for structured finding follow-up summaries and rendering."""

from __future__ import annotations

import json
from pathlib import Path

try:
    from evidence_rubric import compact_evidence_rubric, evaluate_candidate_evidence
except ImportError:  # pragma: no cover - package import path
    from tools.evidence_rubric import compact_evidence_rubric, evaluate_candidate_evidence


def _load_validation_summary_rubric(finding: dict) -> dict:
    """从 validation_runner 的 summary.json 读取已计算好的证据 rubric。

    validation_runner 已经基于原始请求/响应给出 lane-specific rubric；
    structured_findings 只看 findings.json 的精简行时会丢掉这些细节，导致
    已验证 finding 在 checkpoint 里又显示 needs-evidence。这里优先复用
    summary.json，避免用标题/URL 的弱文本重新推断证据质量。
    """
    candidates: list[Path] = []
    for field in ("validation_summary", "source_file"):
        value = str(finding.get(field) or "").strip()
        if not value:
            continue
        path = Path(value)
        candidates.append(path if path.is_absolute() else Path.cwd() / path)

    for path in candidates:
        if not path.is_file():
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(payload, dict):
            continue
        rubric = payload.get("evidence_rubric")
        if isinstance(rubric, dict) and rubric:
            return rubric
    return {}


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


def _rubric_eval(finding: dict) -> dict:
    existing = finding.get("rubric") if isinstance(finding.get("rubric"), dict) else {}
    if existing:
        return existing
    existing = finding.get("evidence_rubric") if isinstance(finding.get("evidence_rubric"), dict) else {}
    if existing:
        return existing
    existing = _load_validation_summary_rubric(finding)
    if existing:
        return existing
    return evaluate_candidate_evidence(finding)


def finding_rank_key(finding: dict) -> tuple[int, int, int]:
    """Rank structured finding candidates by severity, confidence, and evidence quality."""
    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    confidence_rank = {"confirmed": 4, "high": 3, "medium": 2, "needs_review": 1}
    severity = str(finding.get("severity", "") or "").lower()
    confidence = str(finding.get("confidence", "") or "").lower()
    rubric = _rubric_eval(finding)
    return (
        severity_rank.get(severity, 0),
        confidence_rank.get(confidence, 0),
        int(rubric.get("score", 0) or 0),
    )


def _is_actionable_validation_candidate(finding: dict) -> bool:
    """Return whether a pending finding should drive the next validation action.

    Generic弱线索仍保留在 pending/evidence gap 统计里，避免隐藏攻击面；但在
    缺少 ready 证据前不抢占 checkpoint 的下一步动作。这样 Claude 会优先处理
    已有明确 lane/rubric 的候选，而不是被普通 `/metrics` 之类信息泄露噪声牵引。
    """
    rubric = _rubric_eval(finding)
    if rubric.get("ready", False):
        return True
    if rubric.get("rubric_id") == "generic":
        return False
    return True


def compact_structured_finding(finding: dict, findings_dir: Path) -> dict:
    """Return the compact structured finding shape used by resume/autopilot."""
    rubric = compact_evidence_rubric(_rubric_eval(finding))
    return {
        "id": finding.get("id", ""),
        "type": finding.get("type", ""),
        "severity": finding.get("severity", ""),
        "confidence": finding.get("confidence", ""),
        "url": finding.get("url", ""),
        "validation_status": finding.get("validation_status", "unvalidated"),
        "report_status": finding.get("report_status", "not_generated"),
        "source_file": finding.get("source_file", ""),
        "findings_dir": str(findings_dir),
        "rubric": rubric,
        "rubric_status": rubric.get("status", ""),
        "missing_evidence": rubric.get("missing_labels", []),
    }


def summarize_structured_findings(findings: list[dict], findings_dir: Path) -> dict:
    """Build validation/report follow-up state from structured findings."""
    valid_findings = [
        item for item in findings
        if isinstance(item, dict) and item.get("id")
    ]
    if not valid_findings:
        return {
            "total": 0,
            "pending_validation": 0,
            "validated_pending_report": 0,
            "reported": 0,
            "findings_dir": str(findings_dir),
        }

    pending_validation = []
    for item in valid_findings:
        validation_status = str(item.get("validation_status", "unvalidated") or "unvalidated")
        report_status = str(item.get("report_status", "not_generated") or "not_generated")
        if validation_status == "unvalidated":
            pending_validation.append(item)
            continue
        if (
            validation_status == "validated"
            and report_status != "generated"
            and _validation_report_ready(item) is False
        ):
            pending_validation.append(item)
    validated_pending_report = [
        item for item in valid_findings
        if (
            str(item.get("validation_status", "") or "") == "validated"
            and str(item.get("report_status", "not_generated") or "not_generated") != "generated"
            and _validation_report_ready(item) is not False
        )
    ]
    reported = [
        item for item in valid_findings
        if str(item.get("report_status", "") or "") == "generated"
    ]

    pending_validation.sort(key=finding_rank_key, reverse=True)
    validated_pending_report.sort(key=finding_rank_key, reverse=True)
    actionable_pending_validation = [
        item for item in pending_validation
        if _is_actionable_validation_candidate(item)
    ]
    evidence_gap_count = 0
    secret_followup_count = 0
    for item in pending_validation:
        rubric = _rubric_eval(item)
        if not rubric.get("ready", False):
            evidence_gap_count += 1
        if rubric.get("rubric_id") == "secret":
            secret_followup_count += 1

    result = {
        "total": len(valid_findings),
        "pending_validation": len(pending_validation),
        "validated_pending_report": len(validated_pending_report),
        "reported": len(reported),
        "evidence_gap_count": evidence_gap_count,
        "secret_followup_count": secret_followup_count,
        "findings_dir": str(findings_dir),
    }
    if actionable_pending_validation:
        result["next_validation"] = compact_structured_finding(actionable_pending_validation[0], findings_dir)
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
        "total={total}, pending_validation={pending_validation}, "
        "validated_pending_report={validated_pending_report}, reported={reported}, "
        "evidence_gaps={evidence_gap_count}".format(
            total=structured_findings.get("total", 0),
            pending_validation=structured_findings.get("pending_validation", 0),
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
        rubric = next_validation.get("rubric") if isinstance(next_validation.get("rubric"), dict) else {}
        rubric_suffix = ""
        if rubric.get("status"):
            missing = ", ".join(str(item) for item in (rubric.get("missing_labels") or [])[:2])
            rubric_suffix = f" rubric={rubric.get('status')}"
            if missing:
                rubric_suffix += f" missing={missing}"
        lines.append(
            "{indent}{label}: {id} [{severity}/{confidence}] {type} {url}{rubric_suffix}".format(
                indent=indent,
                label=next_validation_label,
                id=next_validation.get("id", "-"),
                severity=next_validation.get("severity", "-"),
                confidence=next_validation.get("confidence", "-"),
                type=next_validation.get("type", "-"),
                url=next_validation.get("url", ""),
                rubric_suffix=rubric_suffix,
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
    return lines
