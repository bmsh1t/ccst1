from pathlib import Path
import json

import finding_index
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


def test_generic_metrics_exposure_does_not_become_next_validation(tmp_path):
    findings_dir = tmp_path / "findings" / "target.com"
    findings = [
        {
            "id": "metrics",
            "type": "exposure",
            "severity": "medium",
            "confidence": "medium",
            "title": "prometheus-metrics on https://target.test/metrics",
            "summary": "[prometheus-metrics] [http] [medium] https://target.test/metrics",
            "url": "https://target.test/metrics",
            "validation_status": "unvalidated",
            "report_status": "not_generated",
        },
        {
            "id": "report_me",
            "type": "auth_bypass",
            "severity": "high",
            "confidence": "confirmed",
            "url": "https://target.test/rest/admin/application-configuration",
            "validation_status": "validated",
            "report_status": "not_generated",
        },
    ]

    summary = structured_findings.summarize_structured_findings(findings, findings_dir)

    assert summary["pending_validation"] == 1
    assert summary["evidence_gap_count"] == 1
    assert "next_validation" not in summary
    assert summary["next_report"]["id"] == "report_me"


def test_ready_generic_finding_can_still_drive_next_validation(tmp_path):
    findings_dir = tmp_path / "findings" / "target.com"
    findings = [
        {
            "id": "generic_ready",
            "type": "exposure",
            "severity": "medium",
            "confidence": "medium",
            "url": "https://target.test/debug",
            "validation_status": "unvalidated",
            "report_status": "not_generated",
            "rubric": {
                "rubric_id": "generic",
                "status": "candidate-ready",
                "ready": True,
                "score": 90,
                "missing": [],
                "missing_labels": [],
            },
        },
    ]

    summary = structured_findings.summarize_structured_findings(findings, findings_dir)

    assert summary["pending_validation"] == 1
    assert summary["evidence_gap_count"] == 0
    assert summary["next_validation"]["id"] == "generic_ready"


def test_runner_candidate_status_remains_pending_validation(tmp_path):
    findings_dir = tmp_path / "findings" / "target.com"
    findings = [
        {
            "id": "runner_candidate",
            "type": "sqli",
            "severity": "high",
            "confidence": "confirmed",
            "url": "https://target.test/rest/products/search?q=apple",
            "validation_status": "candidate",
            "report_status": "not_generated",
            "rubric": {
                "rubric_id": "sqli",
                "status": "candidate-ready",
                "ready": True,
                "score": 100,
                "missing": [],
                "missing_labels": [],
            },
        }
    ]

    summary = structured_findings.summarize_structured_findings(findings, findings_dir)

    assert summary["pending_validation"] == 1
    assert summary["validated_pending_report"] == 0
    assert summary["next_validation"]["id"] == "runner_candidate"


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
        "  total=2, pending_validation=1, owner_revalidation_pending=0, draft_completion_pending=0, validated_pending_report=1, reported=0, evidence_gaps=1",
        "  Next validate: sqli_pending [high/confirmed] sqli https://api.target.com/search?q=1 rubric=needs-evidence missing=baseline/perturbation pair",
        "  Next report: mfa_report [medium/high] mfa https://api.target.com/mfa",
    ]


def test_validated_incomplete_draft_requires_completion_not_revalidation(tmp_path):
    summary_path = tmp_path / "validation-summary.json"
    report_path = tmp_path / "findings" / "target.com-sqli" / "hackerone-report.md"
    summary_path.write_text(
        json.dumps(
            {
                "validation_evidence_passed": True,
                "all_gates_passed": False,
                "four_validation_gates_passed": True,
                "seven_question_gate_passed": True,
                "seven_question_gate_decision": "pass",
                "report_path": str(report_path),
                "report_draft": {
                    "status": "incomplete",
                    "placeholder_count": 4,
                },
            }
        ),
        encoding="utf-8",
    )
    finding = {
        "id": "validated_sqli_draft",
        "type": "sqli",
        "severity": "high",
        "confidence": "confirmed",
        "url": "https://target.com/rest/products/search?q=apple",
        "validation_status": "validated",
        "report_status": "not_generated",
        "validation_summary": str(summary_path),
    }

    summary = structured_findings.summarize_structured_findings(
        [finding],
        tmp_path / "findings" / "target.com",
    )

    assert summary["pending_validation"] == 0
    assert summary["draft_completion_pending"] == 1
    assert summary["validated_pending_report"] == 0
    assert summary["next_draft_completion"]["id"] == "validated_sqli_draft"
    assert summary["next_draft_completion"]["report_draft_path"] == str(report_path)
    assert summary["next_draft_completion"]["report_draft_placeholder_count"] == 4


def test_runner_validated_finding_reuses_rubric_but_still_needs_validate_gate(tmp_path):
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

    assert summary["validated_pending_report"] == 0
    assert summary["pending_validation"] == 1
    assert summary["next_validation"]["id"] == "validated_sqli"
    assert summary["next_validation"]["rubric_status"] == "candidate-ready"
    assert summary["next_validation"]["rubric"]["ready"] is True
    assert summary["next_validation"]["missing_evidence"] == []


def test_validate_summary_passed_finding_is_report_ready(tmp_path):
    summary_path = tmp_path / "validation-summary.json"
    summary_path.write_text(
        json.dumps(
            {
                "all_gates_passed": True,
                "seven_question_gate_passed": True,
                "seven_question_gate_decision": "pass",
                "four_validation_gates_passed": True,
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
    }

    summary = structured_findings.summarize_structured_findings([finding], findings_dir)

    assert summary["pending_validation"] == 0
    assert summary["validated_pending_report"] == 1
    assert summary["next_report"]["id"] == "validated_sqli"


def test_load_validation_runner_candidate_pool_keeps_runner_evidence_advisory(tmp_path):
    summary_dir = tmp_path / "evidence" / "target.com" / "validation" / "sqli-result-diff-search"
    summary_dir.mkdir(parents=True)
    (summary_dir / "summary.json").write_text(
        json.dumps(
            {
                "lane": "sqli_result_diff",
                "finding_id": "sqli-result-diff-search",
                "url": "https://target.com/rest/products/search?q=apple",
                "method": "GET",
                "result": "tested_finding",
                "candidate_ready": True,
                "evidence_rubric": {
                    "status": "candidate-ready",
                    "ready": True,
                    "summary": "sqli:candidate-ready score=100",
                    "missing_labels": [],
                },
                "ai_next": {
                    "next_action": "run /validate before report",
                },
            }
        ),
        encoding="utf-8",
    )
    clean_dir = tmp_path / "evidence" / "target.com" / "validation" / "authz-clean"
    clean_dir.mkdir(parents=True)
    (clean_dir / "summary.json").write_text(
        json.dumps(
            {
                "lane": "authz_role_replay",
                "url": "https://target.com/api/me",
                "result": "tested_clean",
                "candidate_ready": False,
            }
        ),
        encoding="utf-8",
    )

    pool = structured_findings.load_validation_runner_candidate_pool(tmp_path, "https://target.com/app")
    lines = structured_findings.format_validation_runner_candidate_lines(pool)

    assert len(pool) == 1
    assert pool[0]["id"] == "sqli-result-diff-search"
    assert pool[0]["rubric_status"] == "candidate-ready"
    assert "requires /validate" in pool[0]["report_gate"]
    assert "tested_clean" not in "\n".join(lines)


def test_load_validation_runner_candidate_pool_filters_finalized_findings(tmp_path):
    validation_root = tmp_path / "evidence" / "target.com" / "validation"
    for name, lane, url in [
        ("authz-public-exposure-api_Feedbacks", "authz_public_exposure", "https://target.com/api/Feedbacks"),
        ("sqli-result-diff-search", "sqli_result_diff", "https://target.com/rest/products/search?q=apple"),
        ("idor-fresh", "idor_actor_pair", "https://target.com/rest/orders/9"),
    ]:
        summary_dir = validation_root / name
        summary_dir.mkdir(parents=True)
        (summary_dir / "summary.json").write_text(
            json.dumps(
                {
                    "lane": lane,
                    "finding_id": name,
                    "url": url,
                    "method": "GET",
                    "result": "tested_finding",
                    "candidate_ready": True,
                    "evidence_rubric": {
                        "status": "candidate-ready",
                        "ready": True,
                    },
                }
            ),
            encoding="utf-8",
        )

    findings_dir = tmp_path / "findings" / "target.com"
    findings_dir.mkdir(parents=True)
    (findings_dir / "findings.json").write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "id": "auth_bypass_feedbacks",
                        "type": "auth_bypass",
                        "url": "https://target.com/api/Feedbacks",
                        "validation_status": "rejected",
                        "report_status": "not_generated",
                    },
                    {
                        "id": "sqli-result-diff-search",
                        "type": "sqli",
                        "url": "https://target.com/rest/products/search?q=apple",
                        "validation_status": "validated",
                        "report_status": "generated",
                        "source_file": "evidence/target.com/validation/sqli-result-diff-search/summary.json",
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    finding_index.update_finding_status(
        findings_dir,
        "auth_bypass_feedbacks",
        validation_status="rejected",
        report_status="not_generated",
    )
    finding_index.update_finding_status(
        findings_dir,
        "sqli-result-diff-search",
        validation_status="validated",
        report_status="generated",
    )

    pool = structured_findings.load_validation_runner_candidate_pool(tmp_path, "target.com")

    assert [item["id"] for item in pool] == ["idor-fresh"]


def test_load_validation_runner_candidate_pool_filters_ai_closed_ledger_rows(tmp_path):
    validation_root = tmp_path / "evidence" / "target.com" / "validation"
    for name, lane, url in [
        ("authz-order-history", "authz_role_replay", "https://target.com/rest/order-history"),
        ("idor-cards", "idor_actor_pair", "https://target.com/api/Cards"),
        ("authz-fresh", "authz_role_replay", "https://target.com/rest/memories"),
    ]:
        summary_dir = validation_root / name
        summary_dir.mkdir(parents=True)
        (summary_dir / "summary.json").write_text(
            json.dumps(
                {
                    "lane": lane,
                    "finding_id": name,
                    "url": url,
                    "method": "GET",
                    "result": "candidate",
                    "candidate_ready": True,
                    "evidence_rubric": {
                        "status": "candidate-ready",
                        "ready": True,
                    },
                }
            ),
            encoding="utf-8",
        )

    ledger_dir = tmp_path / "memory" / "evidence" / "target.com"
    ledger_dir.mkdir(parents=True)
    (ledger_dir / "ledger.jsonl").write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "method": "GET",
                        "endpoint": "/rest/order-history",
                        "vuln_class": "Authz",
                        "source": "ai-review",
                        "result": "tested_clean",
                    }
                ),
                json.dumps(
                    {
                        "method": "GET",
                        "endpoint": "/api/Cards",
                        "vuln_class": "IDOR",
                        "source": "ai-review",
                        "result": "dead_end",
                    }
                ),
                json.dumps(
                    {
                        "method": "GET",
                        "endpoint": "/rest/memories",
                        "vuln_class": "Authz",
                        "source": "validation-runner:authz-role-replay",
                        "result": "tested_finding",
                    }
                ),
            ]
        ),
        encoding="utf-8",
    )

    pool = structured_findings.load_validation_runner_candidate_pool(tmp_path, "target.com")

    assert [item["id"] for item in pool] == ["authz-fresh"]
