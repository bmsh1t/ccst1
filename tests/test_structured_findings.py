from pathlib import Path

import structured_findings


def test_summarize_structured_findings_picks_next_validation_and_report(tmp_path):
    findings_dir = tmp_path / "findings" / "target.com"
    findings = [
        {
            "id": "low_pending",
            "type": "idor",
            "severity": "low",
            "confidence": "medium",
            "url": "https://target.com/low",
            "validation_status": "unvalidated",
            "report_status": "not_generated",
        },
        {
            "id": "high_pending",
            "type": "sqli",
            "severity": "high",
            "confidence": "confirmed",
            "url": "https://target.com/high",
            "validation_status": "unvalidated",
            "report_status": "not_generated",
        },
        {
            "id": "report_me",
            "type": "mfa",
            "severity": "medium",
            "confidence": "high",
            "url": "https://target.com/mfa",
            "validation_status": "validated",
            "report_status": "not_generated",
        },
        {
            "id": "done",
            "type": "xss",
            "severity": "medium",
            "confidence": "high",
            "url": "https://target.com/done",
            "validation_status": "validated",
            "report_status": "generated",
        },
    ]

    summary = structured_findings.summarize_structured_findings(findings, findings_dir)

    assert summary["total"] == 4
    assert summary["pending_validation"] == 2
    assert summary["validated_pending_report"] == 1
    assert summary["reported"] == 1
    assert summary["next_validation"]["id"] == "high_pending"
    assert summary["next_report"]["id"] == "report_me"
    assert summary["next_validation"]["findings_dir"] == str(findings_dir)


def test_format_structured_findings_lines_renders_expected_labels():
    lines = structured_findings.format_structured_findings_lines(
        {
            "total": 2,
            "pending_validation": 1,
            "validated_pending_report": 1,
            "reported": 0,
            "next_validation": {
                "id": "sqli_pending",
                "severity": "high",
                "confidence": "confirmed",
                "type": "sqli",
                "url": "https://api.target.com/search?q=1",
            },
            "next_report": {
                "id": "mfa_report",
                "severity": "medium",
                "confidence": "high",
                "type": "mfa",
                "url": "https://api.target.com/mfa",
            },
        },
        header="Structured Findings:",
        indent="  ",
        next_validation_label="Next validate",
    )

    assert lines == [
        "  Structured Findings:",
        "  total=2, pending_validation=1, validated_pending_report=1, reported=0",
        "  Next validate: sqli_pending [high/confirmed] sqli https://api.target.com/search?q=1",
        "  Next report: mfa_report [medium/high] mfa https://api.target.com/mfa",
    ]
