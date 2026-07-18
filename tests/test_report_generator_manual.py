"""Regression tests for report_generator.py manual workflow."""

import json
from pathlib import Path
import sys

import pytest

import report_generator


def test_create_manual_report_generates_markdown_file(monkeypatch, tmp_path):
    monkeypatch.setattr(report_generator, "REPORTS_DIR", str(tmp_path / "reports"))

    report_file = report_generator.create_manual_report(
        "xss",
        "https://app.example.com/search?q=test",
        param="q",
        evidence="Reflected payload observed in response body.",
    )

    report_path = Path(report_file)
    assert report_path.exists()
    assert report_path.suffix == ".md"

    content = report_path.read_text(encoding="utf-8")
    assert "https://app.example.com/search?q=test" in content
    assert "XSS" in content.upper()
    assert "Parameter: q" in content


def test_attach_poc_images_copies_image_and_appends_markdown(monkeypatch, tmp_path):
    monkeypatch.setattr(report_generator, "REPORTS_DIR", str(tmp_path / "reports"))

    report_file = report_generator.create_manual_report(
        "ssrf",
        "https://api.example.com/fetch?url=http://169.254.169.254/",
        evidence="Server fetched internal metadata endpoint.",
    )

    image_path = tmp_path / "poc.png"
    image_path.write_bytes(b"\x89PNG\r\n\x1a\nfakepng")

    report_generator.attach_poc_images(report_file, [str(image_path)])

    report_path = Path(report_file)
    copied_image = report_path.parent / "poc_screenshots" / "poc.png"
    assert copied_image.exists()

    content = report_path.read_text(encoding="utf-8")
    assert "## PoC Screenshots" in content
    assert "![PoC 1](poc_screenshots/poc.png)" in content


def test_manual_mode_requires_type_and_url(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["report_generator.py", "--manual"])

    with pytest.raises(SystemExit) as excinfo:
        report_generator.main()

    assert excinfo.value.code == 1
    output = capsys.readouterr()
    assert "Manual mode requires --type and --url" in output.out


def test_report_includes_validation_gate_status(tmp_path):
    summary_path = tmp_path / "validation-summary.json"
    summary_path.write_text(
        json.dumps(
            {
                "all_gates_passed": True,
                "seven_question_gate_passed": True,
                "seven_question_gate_decision": "pass",
                "four_validation_gates_passed": True,
                "summary_path": str(summary_path),
            }
        ),
        encoding="utf-8",
    )
    finding = {
        "id": "idor_001",
        "type": "idor",
        "url": "https://api.example.com/orders/42",
        "severity": "high",
        "raw": "validated owner/peer response diff",
        "validation_summary": str(summary_path),
    }

    content, _title = report_generator.generate_report(finding, "idor", "example.com")

    assert "**7-Question Gate:** `PASS` (`pass`)" in content
    assert "**Four Validation Gates:** `PASS`" in content
    assert "**Combined Report Readiness:** `PASS`" in content


@pytest.mark.parametrize(
    ("raw_type", "template_type", "title", "cwe"),
    [
        ("remote_code_execution", "rce", "Remote Code Execution on example.com", "CWE-78"),
        ("unsafe_deserialization", "deserialization", "Unsafe Deserialization on example.com", "CWE-502"),
        ("xml_external_entity", "xxe", "XML External Entity Injection on example.com", "CWE-611"),
        ("path_traversal", "path_traversal", "Path Traversal on example.com", "CWE-22"),
    ],
)
def test_structured_report_vulnerability_aliases_select_template_and_file_prefix(
    tmp_path, raw_type, template_type, title, cwe
):
    finding = {
        "id": f"{template_type}_finding",
        "type": raw_type,
        "url": "https://example.com/api/resource",
        "raw": "Validated differential evidence.",
    }

    resolved_type = report_generator._report_vuln_type(finding)
    content, generated_title = report_generator.generate_report(finding, resolved_type, "example.com")
    report_id = report_generator._next_report_id(resolved_type, finding, tmp_path, {})

    assert resolved_type == template_type
    assert report_id == f"{template_type}_001"
    assert generated_title == title
    assert cwe in content


def test_structured_report_generation_rejects_failed_seven_question_gate(tmp_path):
    summary_path = tmp_path / "validation-summary.json"
    summary_path.write_text(
        json.dumps(
            {
                "all_gates_passed": False,
                "seven_question_gate_passed": False,
                "seven_question_gate_decision": "chain_required",
                "four_validation_gates_passed": True,
            }
        ),
        encoding="utf-8",
    )
    finding = {
        "id": "redirect_001",
        "url": "https://app.example.com/redirect?to=https://evil.example",
        "validation_status": "validated",
        "validation_summary": str(summary_path),
    }

    assert report_generator._is_reportable_structured_finding(finding) is False


def test_structured_report_generation_rejects_runner_summary_without_report_gate(tmp_path):
    summary_path = tmp_path / "runner-summary.json"
    summary_path.write_text(
        json.dumps(
            {
                "lane": "authz_public_exposure",
                "result": "tested_finding",
                "candidate_ready": True,
                "evidence_rubric": {
                    "rubric_id": "authz",
                    "status": "candidate-ready",
                    "ready": True,
                },
            }
        ),
        encoding="utf-8",
    )
    finding = {
        "id": "authz_001",
        "url": "https://app.example.com/api/Feedbacks",
        "validation_status": "validated",
        "validation_summary": str(summary_path),
    }

    assert report_generator._is_reportable_structured_finding(finding) is False
