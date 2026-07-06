"""Tests for structured scanner finding index."""

import json
from pathlib import Path

import finding_index
import report_generator
import validate


def test_build_finding_index_extracts_scanner_candidates(tmp_path):
    findings_dir = tmp_path / "findings" / "example.com"
    sqli_dir = findings_dir / "sqli"
    ssti_dir = findings_dir / "ssti"
    sqli_dir.mkdir(parents=True)
    ssti_dir.mkdir(parents=True)
    (sqli_dir / "timebased_candidates.txt").write_text(
        "[SQLI-POC-VERIFIED] dialect=mysql param=1 url=https://example.com/item?id=1\n",
        encoding="utf-8",
    )
    (ssti_dir / "ssti_candidates.txt").write_text(
        "[SSTI-CONFIRMED] engine=jinja2 url=https://example.com/render?name={{7*7}}\n",
        encoding="utf-8",
    )

    payload = finding_index.write_finding_index(findings_dir, target="example.com")

    assert payload["schema_version"] == 1
    assert payload["target"] == "example.com"
    assert payload["total"] == 2
    assert payload["counts"]["type"] == {"sqli": 1, "ssti": 1}
    assert payload["counts"]["confidence"] == {"confirmed": 2}
    assert (findings_dir / "findings.json").is_file()

    first = payload["findings"][0]
    assert first["id"].startswith("sqli_")
    assert first["url"] == "https://example.com/item?id=1"
    assert first["validation_status"] == "unvalidated"
    assert first["report_status"] == "not_generated"

    updated = finding_index.update_finding_status(
        findings_dir,
        first["id"],
        validation_status="validated",
        validation_summary="validated/validation-summary.json",
    )

    assert updated is not None
    assert updated["validation_status"] == "validated"
    reloaded = finding_index.load_finding_index(findings_dir)
    assert reloaded["findings"][0]["validation_summary"] == "validated/validation-summary.json"


def test_build_finding_index_skips_off_target_urls(tmp_path):
    findings_dir = tmp_path / "findings" / "target.com"
    idor_dir = findings_dir / "idor"
    idor_dir.mkdir(parents=True)
    (idor_dir / "idor_candidates.txt").write_text(
        "https://target.com/api/orders/123\n"
        "https://github.com/org/repo/issues/123\n",
        encoding="utf-8",
    )

    payload = finding_index.write_finding_index(findings_dir, target="target.com")

    assert payload["total"] == 1
    assert payload["findings"][0]["url"] == "https://target.com/api/orders/123"
    assert all("github.com" not in item["url"] for item in payload["findings"])


def test_write_finding_index_preserves_validation_and_report_state(tmp_path):
    findings_dir = tmp_path / "findings" / "example.com"
    sqli_dir = findings_dir / "sqli"
    sqli_dir.mkdir(parents=True)
    (sqli_dir / "timebased_candidates.txt").write_text(
        "[SQLI-POC-VERIFIED] dialect=mysql param=1 url=https://example.com/item?id=1\n",
        encoding="utf-8",
    )

    first = finding_index.write_finding_index(findings_dir, target="example.com")
    finding_id = first["findings"][0]["id"]
    finding_index.update_finding_status(
        findings_dir,
        finding_id,
        validation_status="validated",
        report_status="generated",
        validation_summary="evidence/example.com/validation/sqli/summary.json",
        report_file="reports/example.com/sqli_001.md",
    )

    rebuilt = finding_index.write_finding_index(findings_dir, target="example.com")
    finding = rebuilt["findings"][0]

    assert finding["id"] == finding_id
    assert finding["validation_status"] == "validated"
    assert finding["report_status"] == "generated"
    assert finding["validation_summary"] == "evidence/example.com/validation/sqli/summary.json"
    assert finding["report_file"] == "reports/example.com/sqli_001.md"


def test_write_finding_index_preserves_runner_backed_orphan_findings(tmp_path):
    findings_dir = tmp_path / "findings" / "example.com"
    sqli_dir = findings_dir / "sqli"
    sqli_dir.mkdir(parents=True)
    (sqli_dir / "timebased_candidates.txt").write_text(
        "[SQLI-POC-VERIFIED] dialect=mysql param=1 url=https://example.com/item?id=1\n",
        encoding="utf-8",
    )

    first = finding_index.write_finding_index(findings_dir, target="example.com")
    first["findings"].append(
        {
            "id": "authz-role-replay-api_users",
            "type": "auth_bypass",
            "category": "auth_bypass",
            "title": "Runner-backed role replay candidate",
            "summary": "authz:candidate-ready score=100 satisfied=4/4",
            "url": "https://example.com/api/Users",
            "severity": "high",
            "confidence": "confirmed",
            "source_file": "evidence/example.com/validation/authz-role-replay-api_users/summary.json",
            "line_number": 0,
            "template_id": "",
            "raw": "validation_runner:authz_role_replay:authz-role-replay-api_users",
            "validation_status": "partial",
            "report_status": "not_generated",
            "evidence_rubric": {"status": "candidate-ready"},
        }
    )
    first["total"] = len(first["findings"])
    (findings_dir / "findings.json").write_text(json.dumps(first), encoding="utf-8")

    rebuilt = finding_index.write_finding_index(findings_dir, target="example.com")
    by_id = {item["id"]: item for item in rebuilt["findings"]}

    assert rebuilt["total"] == 2
    assert "authz-role-replay-api_users" in by_id
    assert by_id["authz-role-replay-api_users"]["validation_status"] == "partial"
    assert by_id["authz-role-replay-api_users"]["source_file"].startswith("evidence/")
    assert rebuilt["counts"]["type"] == {"auth_bypass": 1, "sqli": 1}


def test_write_finding_index_drops_default_scanner_orphans(tmp_path):
    findings_dir = tmp_path / "findings" / "example.com"
    sqli_dir = findings_dir / "sqli"
    sqli_dir.mkdir(parents=True)
    (sqli_dir / "current.txt").write_text(
        "[SQLI-POC-VERIFIED] dialect=mysql param=1 url=https://example.com/item?id=1\n",
        encoding="utf-8",
    )

    first = finding_index.write_finding_index(findings_dir, target="example.com")
    first["findings"].append(
        {
            "id": "sqli_old_orphan",
            "type": "sqli",
            "category": "sqli",
            "title": "Old scanner-only candidate",
            "summary": "old scanner-only row",
            "url": "https://example.com/old?id=1",
            "severity": "high",
            "confidence": "medium",
            "source_file": "sqli/old.txt",
            "line_number": 1,
            "template_id": "",
            "raw": "[SQLI] https://example.com/old?id=1",
            "validation_status": "unvalidated",
            "report_status": "not_generated",
        }
    )
    first["total"] = len(first["findings"])
    (findings_dir / "findings.json").write_text(json.dumps(first), encoding="utf-8")

    rebuilt = finding_index.write_finding_index(findings_dir, target="example.com")

    assert rebuilt["total"] == 1
    assert all(item["id"] != "sqli_old_orphan" for item in rebuilt["findings"])


def test_report_generator_consumes_structured_findings(monkeypatch, tmp_path):
    findings_dir = tmp_path / "findings" / "example.com"
    findings_dir.mkdir(parents=True)
    (findings_dir / "findings.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "target": "example.com",
                "total": 1,
                "findings": [
                    {
                        "id": "sqli_abc123",
                        "type": "sqli",
                        "category": "sqli",
                        "title": "SQLi on item",
                        "summary": "verified SQLi",
                        "url": "https://example.com/item?id=1",
                        "severity": "high",
                        "confidence": "confirmed",
                        "validation_status": "validated",
                        "report_status": "not_generated",
                        "source_file": "sqli/timebased_candidates.txt",
                        "line_number": 1,
                        "template_id": "",
                        "raw": "[SQLI-POC-VERIFIED] dialect=mysql param=1 url=https://example.com/item?id=1",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(report_generator, "REPORTS_DIR", str(tmp_path / "reports"))

    total, index = report_generator.process_findings_dir(str(findings_dir))

    assert total == 1
    assert index[0]["finding_id"] == "sqli_abc123"
    assert index[0]["type"] == "sqli"
    report_path = Path(index[0]["file"])
    assert report_path.is_file()
    report_text = report_path.read_text(encoding="utf-8")
    assert "SQL Injection" in report_text
    assert "**Finding Reference:**" in report_text
    assert "- **Finding ID:** sqli_abc123" in report_text
    assert "- **Source artifact:** sqli/timebased_candidates.txt" in report_text
    assert "- **Confidence:** confirmed" in report_text
    updated_index = json.loads((findings_dir / "findings.json").read_text(encoding="utf-8"))
    assert updated_index["findings"][0]["report_status"] == "generated"
    assert updated_index["findings"][0]["report_id"] == "sqli_001"
    assert updated_index["findings"][0]["report_file"] == str(report_path)


def test_report_generator_preserves_jwt_structured_finding_type(monkeypatch, tmp_path):
    findings_dir = tmp_path / "findings" / "example.com"
    findings_dir.mkdir(parents=True)
    (findings_dir / "findings.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "target": "example.com",
                "total": 1,
                "findings": [
                    {
                        "id": "jwt_alg_none_abc123",
                        "type": "jwt",
                        "category": "jwt",
                        "title": "JWT alg none role escalation",
                        "summary": "validated JWT alg=none role escalation",
                        "url": "https://example.com/rest/order-history/orders",
                        "severity": "high",
                        "confidence": "confirmed",
                        "validation_status": "validated",
                        "report_status": "not_generated",
                        "source_file": "evidence/example.com/jwt/validation-summary.json",
                        "raw": "validate:confirmed:evidence/example.com/jwt/validation-summary.json",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(report_generator, "REPORTS_DIR", str(tmp_path / "reports"))

    total, index = report_generator.process_findings_dir(str(findings_dir))

    assert total == 1
    assert index[0]["finding_id"] == "jwt_alg_none_abc123"
    assert index[0]["type"] == "jwt"
    report_path = Path(index[0]["file"])
    assert report_path.name == "jwt_001.md"
    report_text = report_path.read_text(encoding="utf-8")
    assert "JWT Validation Weakness" in report_text
    updated_index = json.loads((findings_dir / "findings.json").read_text(encoding="utf-8"))
    assert updated_index["findings"][0]["report_id"] == "jwt_001"


def test_report_generator_keeps_existing_generated_reports_in_index(monkeypatch, tmp_path):
    findings_dir = tmp_path / "findings" / "example.com"
    findings_dir.mkdir(parents=True)
    report_dir = tmp_path / "reports" / "example.com"
    report_dir.mkdir(parents=True)
    existing_report = report_dir / "sqli_001.md"
    existing_report.write_text("# Existing SQLi report\n", encoding="utf-8")
    validation_dir = tmp_path / "evidence" / "example.com" / "validation" / "xss-1"
    validation_dir.mkdir(parents=True)
    validation_summary = validation_dir / "validation-summary.json"
    validation_summary.write_text(
        json.dumps(
            {
                "all_gates_passed": True,
                "four_validation_gates_passed": True,
                "seven_question_gate_passed": True,
                "seven_question_gate_decision": "pass",
                "evidence_rubric": {"summary": "xss browser marker evidence"},
            }
        ),
        encoding="utf-8",
    )
    (findings_dir / "findings.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "target": "example.com",
                "total": 2,
                "findings": [
                    {
                        "id": "sqli_done",
                        "type": "sqli",
                        "category": "sqli",
                        "title": "SQLi on item",
                        "summary": "verified SQLi",
                        "url": "https://example.com/item?id=1",
                        "severity": "high",
                        "confidence": "confirmed",
                        "validation_status": "validated",
                        "report_status": "generated",
                        "report_id": "sqli_001",
                        "report_file": str(existing_report),
                        "source_file": "sqli/timebased_candidates.txt",
                        "raw": "[SQLI-POC-VERIFIED] https://example.com/item?id=1",
                    },
                    {
                        "id": "xss_new",
                        "type": "xss",
                        "category": "xss",
                        "title": "DOM XSS on search",
                        "summary": "browser marker XSS",
                        "url": "https://example.com/#/search?q=<img>",
                        "severity": "medium",
                        "confidence": "confirmed",
                        "validation_status": "validated",
                        "validation_summary": str(validation_summary),
                        "report_status": "not_generated",
                        "source_file": "xss/manual_ai_candidates.txt",
                        "raw": "[DOM-XSS-MARKER] https://example.com/#/search?q=<img>",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(report_generator, "REPORTS_DIR", str(tmp_path / "reports"))

    total, index = report_generator.process_findings_dir(str(findings_dir))

    assert total == 2
    assert {item["finding_id"] for item in index} == {"sqli_done", "xss_new"}
    saved = json.loads((report_dir / "INDEX.json").read_text(encoding="utf-8"))
    assert saved["total_reports"] == 2
    assert {item["finding_id"] for item in saved["reports"]} == {"sqli_done", "xss_new"}


def test_report_generator_uses_canonical_report_dir_for_url_target(monkeypatch, tmp_path):
    findings_dir = tmp_path / "findings" / "127.0.0.1:3002"
    findings_dir.mkdir(parents=True)
    validation_dir = tmp_path / "evidence" / "127.0.0.1:3002" / "validation" / "xss"
    validation_dir.mkdir(parents=True)
    validation_summary = validation_dir / "validation-summary.json"
    validation_summary.write_text(
        json.dumps(
            {
                "all_gates_passed": True,
                "four_validation_gates_passed": True,
                "seven_question_gate_passed": True,
                "seven_question_gate_decision": "pass",
            }
        ),
        encoding="utf-8",
    )
    (findings_dir / "findings.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "target": "http://127.0.0.1:3002",
                "total": 1,
                "findings": [
                    {
                        "id": "xss_url_target",
                        "type": "xss",
                        "category": "xss",
                        "title": "DOM XSS",
                        "summary": "DOM XSS marker",
                        "url": "http://127.0.0.1:3002/#/search?q=<img>",
                        "severity": "medium",
                        "confidence": "confirmed",
                        "validation_status": "validated",
                        "validation_summary": str(validation_summary),
                        "report_status": "not_generated",
                        "source_file": "xss/manual.txt",
                        "raw": "[DOM-XSS] http://127.0.0.1:3002/#/search?q=<img>",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(report_generator, "REPORTS_DIR", str(tmp_path / "reports"))

    total, index = report_generator.process_findings_dir(str(findings_dir))

    assert total == 1
    report_path = Path(index[0]["file"])
    assert report_path.parent == tmp_path / "reports" / "127.0.0.1:3002"
    assert (tmp_path / "reports" / "127.0.0.1:3002" / "INDEX.json").is_file()
    assert not (tmp_path / "reports" / "http:" / "127.0.0.1:3002").exists()


def test_report_generator_syncs_report_action_queue(monkeypatch, tmp_path):
    findings_dir = tmp_path / "findings" / "example.com"
    findings_dir.mkdir(parents=True)
    (findings_dir / "findings.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "target": "example.com",
                "total": 1,
                "findings": [
                    {
                        "id": "sqli_report_sync",
                        "type": "sqli",
                        "category": "sqli",
                        "title": "SQLi on item",
                        "summary": "verified SQLi",
                        "url": "https://example.com/item?id=1",
                        "severity": "high",
                        "confidence": "confirmed",
                        "validation_status": "validated",
                        "report_status": "not_generated",
                        "source_file": "sqli/timebased_candidates.txt",
                        "raw": "[SQLI-POC-VERIFIED] dialect=mysql param=1 url=https://example.com/item?id=1",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    queue_dir = tmp_path / "state" / "example.com"
    queue_dir.mkdir(parents=True)
    (queue_dir / "action_queue.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "target": "example.com",
                "actions": [
                    {
                        "id": "AQ-0001",
                        "status": "queued",
                        "type": "report",
                        "priority": 95,
                        "evidence": "Draft report for validated finding sqli_report_sync; do not submit without human review.",
                        "next_question": "Generate the report draft.",
                        "action": "Draft report for validated finding sqli_report_sync.",
                        "command_hint": "/report",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(report_generator, "BASE_DIR", str(tmp_path))
    monkeypatch.setattr(report_generator, "REPORTS_DIR", str(tmp_path / "reports"))

    total, index = report_generator.process_findings_dir(str(findings_dir))
    queue = json.loads((queue_dir / "action_queue.json").read_text(encoding="utf-8"))

    assert total == 1
    assert index[0]["queue_sync"]["status"] == "updated"
    assert queue["actions"][0]["status"] == "reported"
    assert "report_file=" in queue["actions"][0]["result"]


def test_report_generator_uses_validation_summary_for_auth_bypass_narrative(monkeypatch, tmp_path):
    findings_dir = tmp_path / "findings" / "example.com"
    findings_dir.mkdir(parents=True)
    validation_dir = tmp_path / "evidence" / "example.com" / "validation" / "authz-1"
    validation_dir.mkdir(parents=True)
    validation_summary = validation_dir / "summary.json"
    validation_summary.write_text(
        json.dumps(
            {
                "summary_path": "evidence/example.com/validation/authz-1/summary.json",
                "markers": ["secret-like"],
                "artifacts": {
                    "baseline_request": "evidence/example.com/validation/authz-1/baseline.request.txt",
                    "baseline_response": "evidence/example.com/validation/authz-1/baseline.response.txt",
                },
                "baseline": {"status": 200},
                "evidence_rubric": {"summary": "authz:candidate-ready score=100 satisfied=4/4"},
                "all_gates_passed": True,
                "seven_question_gate_passed": True,
                "seven_question_gate_decision": "pass",
                "four_validation_gates_passed": True,
            }
        ),
        encoding="utf-8",
    )
    (findings_dir / "findings.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "target": "example.com",
                "total": 1,
                "findings": [
                    {
                        "id": "authz_abc123",
                        "type": "auth_bypass",
                        "category": "auth_bypass",
                        "title": "AUTH_BYPASS on feedbacks",
                        "summary": "200 1734 https://example.com/api/Feedbacks",
                        "url": "https://example.com/api/Feedbacks",
                        "severity": "high",
                        "confidence": "confirmed",
                        "validation_status": "validated",
                        "validation_summary": str(validation_summary),
                        "report_status": "not_generated",
                        "source_file": "auth_bypass/unauth_api_access.txt",
                        "line_number": 1,
                        "template_id": "",
                        "raw": "200 1734 https://example.com/api/Feedbacks",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(report_generator, "REPORTS_DIR", str(tmp_path / "reports"))
    monkeypatch.setattr(report_generator, "BASE_DIR", str(tmp_path))

    total, index = report_generator.process_findings_dir(str(findings_dir))

    assert total == 1
    report_path = Path(index[0]["file"])
    report_text = report_path.read_text(encoding="utf-8")
    assert "Unauthenticated Sensitive Data Exposure" in report_text
    assert "secret-like" in report_text
    assert "Validation Summary" in report_text
    assert "Baseline Response" in report_text


def test_report_generator_uses_write_sink_auth_bypass_narrative(monkeypatch, tmp_path):
    findings_dir = tmp_path / "findings" / "example.com"
    findings_dir.mkdir(parents=True)
    validation_dir = tmp_path / "evidence" / "example.com" / "validation" / "forged-review"
    validation_dir.mkdir(parents=True)
    validation_summary = validation_dir / "summary.json"
    validation_summary.write_text(
        json.dumps(
            {
                "summary_path": "evidence/example.com/validation/forged-review/summary.json",
                "method": "PUT",
                "endpoint": "/rest/products/1/reviews",
                "markers": ["anonymous_state_change", "author_spoof", "public_ui_visibility"],
                "ai_assessment": (
                    "Anonymous requests can create public reviews whose author field is taken "
                    "from the request body."
                ),
                "artifacts": {
                    "anonymous_request": "evidence/example.com/validation/forged-review/request.txt",
                    "anonymous_response_body": "evidence/example.com/validation/forged-review/response.body",
                },
                "evidence_rubric": {
                    "summary": "authz/business-logic:validated via anonymous state change"
                },
                "all_gates_passed": True,
                "seven_question_gate_passed": True,
                "seven_question_gate_decision": "report",
                "four_validation_gates_passed": True,
            }
        ),
        encoding="utf-8",
    )
    (findings_dir / "findings.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "target": "example.com",
                "total": 1,
                "findings": [
                    {
                        "id": "authz_forged_review",
                        "type": "auth_bypass",
                        "category": "auth_bypass",
                        "title": "Forged review author",
                        "summary": (
                            "Anonymous PUT accepts author from request body and renders the "
                            "review as admin@example.com."
                        ),
                        "url": "https://example.com/rest/products/1/reviews",
                        "method": "PUT",
                        "severity": "medium",
                        "confidence": "confirmed",
                        "validation_status": "validated",
                        "validation_summary": str(validation_summary),
                        "report_status": "not_generated",
                        "source_file": "evidence/example.com/validation/forged-review/summary.json",
                        "line_number": 0,
                        "template_id": "",
                        "raw": "manual-ai-validated:forged-review",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(report_generator, "REPORTS_DIR", str(tmp_path / "reports"))
    monkeypatch.setattr(report_generator, "BASE_DIR", str(tmp_path))

    total, index = report_generator.process_findings_dir(str(findings_dir))

    assert total == 1
    report_text = Path(index[0]["file"]).read_text(encoding="utf-8")
    assert "Unauthenticated Content Impersonation" in report_text
    assert "unauthenticated `PUT` request" in report_text
    assert "Send a `PUT` request" in report_text
    assert "request.txt" in report_text
    assert "author field" in report_text
    assert "Navigate to the following URL" not in report_text
    assert "returned HTTP 200" not in report_text


def test_report_generator_skips_unvalidated_and_already_reported_structured_findings(
    monkeypatch,
    tmp_path,
):
    findings_dir = tmp_path / "findings" / "example.com"
    findings_dir.mkdir(parents=True)
    (findings_dir / "findings.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "target": "example.com",
                "total": 3,
                "findings": [
                    {
                        "id": "unvalidated_one",
                        "type": "sqli",
                        "url": "https://example.com/item?id=1",
                        "severity": "high",
                        "validation_status": "unvalidated",
                        "report_status": "not_generated",
                        "raw": "candidate",
                    },
                    {
                        "id": "validated_pending",
                        "type": "idor",
                        "url": "https://example.com/api/users/2",
                        "severity": "high",
                        "validation_status": "validated",
                        "report_status": "not_generated",
                        "raw": "validated candidate",
                    },
                    {
                        "id": "validated_done",
                        "type": "mfa",
                        "url": "https://example.com/mfa/verify",
                        "severity": "medium",
                        "validation_status": "validated",
                        "report_status": "generated",
                        "report_id": "mfa_001",
                        "report_file": "reports/example.com/mfa_001.md",
                        "raw": "already reported",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(report_generator, "REPORTS_DIR", str(tmp_path / "reports"))

    total, index = report_generator.process_findings_dir(str(findings_dir))

    assert total == 2
    assert len(index) == 2
    assert {item["finding_id"] for item in index} == {"validated_pending", "validated_done"}
    updated_index = json.loads((findings_dir / "findings.json").read_text(encoding="utf-8"))
    statuses = {item["id"]: item["report_status"] for item in updated_index["findings"]}
    assert statuses == {
        "unvalidated_one": "not_generated",
        "validated_pending": "generated",
        "validated_done": "generated",
    }


def test_report_generator_keeps_statusless_structured_findings_reportable_for_compat(
    monkeypatch,
    tmp_path,
):
    findings_dir = tmp_path / "findings" / "example.com"
    findings_dir.mkdir(parents=True)
    (findings_dir / "findings.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "target": "example.com",
                "total": 1,
                "findings": [
                    {
                        "id": "legacy_no_status",
                        "type": "sqli",
                        "url": "https://example.com/legacy?id=1",
                        "severity": "high",
                        "raw": "legacy candidate",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(report_generator, "REPORTS_DIR", str(tmp_path / "reports"))

    total, index = report_generator.process_findings_dir(str(findings_dir))

    assert total == 1
    assert index[0]["finding_id"] == "legacy_no_status"


def test_validate_prefill_loads_finding_candidate(tmp_path):
    findings_dir = tmp_path / "findings" / "example.com"
    findings_dir.mkdir(parents=True)
    (findings_dir / "findings.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "target": "example.com",
                "findings": [
                    {
                        "id": "mfa_abc123",
                        "type": "mfa",
                        "url": "https://example.com/mfa/verify",
                        "summary": "[MFA-NO-RATE-LIMIT] https://example.com/mfa/verify",
                        "source_file": "mfa/findings.txt",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    prefill = validate.load_finding_prefill(str(findings_dir), "mfa_abc123")

    assert prefill["target"] == "example.com"
    assert prefill["vuln_type"] == "MFA"
    assert prefill["endpoint"] == "https://example.com/mfa/verify"
    assert prefill["finding_id"] == "mfa_abc123"
    assert prefill["source_file"] == "mfa/findings.txt"
    assert prefill["summary"] == "[MFA-NO-RATE-LIMIT] https://example.com/mfa/verify"
    assert prefill["rubric"]["rubric_id"] == "authz"
    assert prefill["rubric"]["status"] in {"needs-evidence", "candidate-ready", "signal-only"}


def test_validate_prefill_uses_runner_evidence_rubric(tmp_path, monkeypatch):
    monkeypatch.setattr(validate, "BASE_DIR", tmp_path)
    summary_path = tmp_path / "evidence" / "target.com" / "validation" / "sqli-search" / "summary.json"
    summary_path.parent.mkdir(parents=True)
    summary_path.write_text(
        json.dumps(
            {
                "evidence_rubric": {
                    "rubric_id": "sqli",
                    "status": "candidate-ready",
                    "score": 100,
                    "missing_labels": [],
                    "summary": "sqli:candidate-ready score=100 satisfied=4/4",
                }
            }
        ),
        encoding="utf-8",
    )
    findings_dir = tmp_path / "findings" / "target.com"
    findings_dir.mkdir(parents=True)
    (findings_dir / "findings.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "target": "target.com",
                "findings": [
                    {
                        "id": "sqli-search",
                        "type": "sqli",
                        "url": "https://target.com/rest/products/search?q=apple",
                        "summary": "sqli:candidate-ready score=100 satisfied=4/4",
                        "source_file": "evidence/target.com/validation/sqli-search/summary.json",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    prefill = validate.load_finding_prefill(str(findings_dir), "sqli-search")

    assert prefill["rubric"]["rubric_id"] == "sqli"
    assert prefill["rubric"]["status"] == "candidate-ready"
    assert prefill["rubric"]["score"] == 100
