#!/usr/bin/env python3
"""Shared helpers for structured finding follow-up summaries and rendering."""

from __future__ import annotations

from pathlib import Path

try:
    from evidence_rubric import compact_evidence_rubric, evaluate_candidate_evidence
except ImportError:  # pragma: no cover - package import path
    from tools.evidence_rubric import compact_evidence_rubric, evaluate_candidate_evidence


def _rubric_eval(finding: dict) -> dict:
    existing = finding.get("rubric") if isinstance(finding.get("rubric"), dict) else {}
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

    pending_validation = [
        item for item in valid_findings
        if str(item.get("validation_status", "unvalidated") or "unvalidated") == "unvalidated"
    ]
    validated_pending_report = [
        item for item in valid_findings
        if (
            str(item.get("validation_status", "") or "") == "validated"
            and str(item.get("report_status", "not_generated") or "not_generated") != "generated"
        )
    ]
    reported = [
        item for item in valid_findings
        if str(item.get("report_status", "") or "") == "generated"
    ]

    pending_validation.sort(key=finding_rank_key, reverse=True)
    validated_pending_report.sort(key=finding_rank_key, reverse=True)
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
    if pending_validation:
        result["next_validation"] = compact_structured_finding(pending_validation[0], findings_dir)
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
