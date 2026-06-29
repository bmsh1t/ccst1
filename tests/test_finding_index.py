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

    assert total == 1
    assert len(index) == 1
    assert index[0]["finding_id"] == "validated_pending"
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
