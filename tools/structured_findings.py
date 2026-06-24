#!/usr/bin/env python3
"""Shared helpers for structured finding follow-up summaries and rendering."""

from __future__ import annotations

from pathlib import Path


def finding_rank_key(finding: dict) -> tuple[int, int]:
    """Rank structured finding candidates by severity and confidence."""
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

    result = {
        "total": len(valid_findings),
        "pending_validation": len(pending_validation),
        "validated_pending_report": len(validated_pending_report),
        "reported": len(reported),
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
        "validated_pending_report={validated_pending_report}, reported={reported}".format(
            total=structured_findings.get("total", 0),
            pending_validation=structured_findings.get("pending_validation", 0),
            validated_pending_report=structured_findings.get("validated_pending_report", 0),
            reported=structured_findings.get("reported", 0),
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
