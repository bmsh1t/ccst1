from pathlib import Path
import json

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
    assert summary["evidence_gap_count"] >= 1
    assert summary["next_validation"]["rubric_status"] in {"needs-evidence", "signal-only", "candidate-ready"}
    assert "rubric" in summary["next_validation"]


def test_format_structured_findings_lines_renders_expected_labels():
    lines = structured_findings.format_structured_findings_lines(
        {
            "total": 2,
            "pending_validation": 1,
            "validated_pending_report": 1,
            "reported": 0,
            "evidence_gap_count": 1,
            "next_validation": {
                "id": "sqli_pending",
                "severity": "high",
                "confidence": "confirmed",
                "type": "sqli",
                "url": "https://api.target.com/search?q=1",
                "rubric": {
                    "status": "needs-evidence",
                    "missing_labels": ["baseline/perturbation pair"],
                },
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
        "  total=2, pending_validation=1, validated_pending_report=1, reported=0, evidence_gaps=1",
        "  Next validate: sqli_pending [high/confirmed] sqli https://api.target.com/search?q=1 rubric=needs-evidence missing=baseline/perturbation pair",
        "  Next report: mfa_report [medium/high] mfa https://api.target.com/mfa",
    ]


def test_validated_finding_reuses_runner_evidence_rubric(tmp_path):
    summary_path = tmp_path / "summary.json"
    summary_path.write_text(
        json.dumps(
            {
                "evidence_rubric": {
                    "rubric_id": "sqli",
                    "status": "candidate-ready",
                    "ready": True,
                    "score": 100,
                    "satisfied_count": 4,
                    "total": 4,
                    "missing": [],
                    "missing_labels": [],
                }
            }
        ),
        encoding="utf-8",
    )
    findings_dir = tmp_path / "findings" / "target.com"
    finding = {
        "id": "validated_sqli",
        "type": "sqli",
        "severity": "high",
        "confidence": "confirmed",
        "url": "https://target.com/rest/products/search?q=apple",
        "validation_status": "validated",
        "report_status": "not_generated",
        "validation_summary": str(summary_path),
        # 精简 finding 行本身没有 baseline/variant 细节；应复用 runner summary，
        # 不能重新按标题弱文本评成 needs-evidence。
        "summary": "sqli:candidate-ready score=100 satisfied=4/4",
    }

    summary = structured_findings.summarize_structured_findings([finding], findings_dir)

    assert summary["next_report"]["id"] == "validated_sqli"
    assert summary["next_report"]["rubric_status"] == "candidate-ready"
    assert summary["next_report"]["rubric"]["ready"] is True
    assert summary["next_report"]["missing_evidence"] == []
