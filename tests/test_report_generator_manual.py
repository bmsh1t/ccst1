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


def test_create_manual_report_uses_canonical_target_and_never_overwrites(monkeypatch, tmp_path):
    monkeypatch.setattr(report_generator, "REPORTS_DIR", str(tmp_path / "reports"))

    first = Path(
        report_generator.create_manual_report(
            "xss", "https://App.Example.COM/search?q=first", evidence="first evidence"
        )
    )
    second = Path(
        report_generator.create_manual_report(
            "xss", "https://app.example.com/search?q=second", evidence="second evidence"
        )
    )

    assert first.parent.name == "app.example.com"
    assert first.name == "xss_001.md"
    assert second.name == "xss_002.md"
    assert "first evidence" in first.read_text(encoding="utf-8")
    assert "second evidence" in second.read_text(encoding="utf-8")


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


def test_report_queue_match_does_not_confuse_prefix_finding_ids():
    action = {
        "id": "action-1",
        "status": "queued",
        "type": "report",
        "evidence": "Generate report for F-10",
        "metadata": {"finding_id": "F-10"},
    }
    assert report_generator._report_action_matches(action, {"id": "F-1"}, "") is False


def test_report_queue_sync_refuses_ambiguous_exact_identity(monkeypatch):
    actions = [
        {
            "id": f"action-{index}",
            "status": "queued",
            "type": "report",
            "metadata": {"finding_id": "F-1"},
        }
        for index in (1, 2)
    ]
    monkeypatch.setattr(report_generator, "load_queue", lambda *_args: {"actions": actions})

    result = report_generator.sync_report_action_queue(
        "example.test",
        {"id": "F-1", "url": "https://example.test/api"},
        "reports/F-1.md",
    )

    assert result["status"] == "ambiguous"
    assert result["ids"] == ["action-1", "action-2"]


def test_report_queue_sync_does_not_reuse_reported_endpoint_for_another_finding(monkeypatch):
    monkeypatch.setattr(
        report_generator,
        "load_queue",
        lambda *_args: {
            "actions": [
                {
                    "id": "action-old",
                    "status": "reported",
                    "type": "report",
                    "metadata": {"url": "https://example.test/api"},
                    "notes": "finding_id=F-old",
                    "result": "report_file=reports/F-old.md",
                }
            ]
        },
    )

    result = report_generator.sync_report_action_queue(
        "example.test",
        {"id": "F-new", "url": "https://example.test/api"},
        "reports/F-new.md",
    )

    assert result == {"status": "skipped", "reason": "no matching report action"}


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


def test_legacy_incremental_reports_use_unique_ids_without_overwrite(monkeypatch, tmp_path):
    findings_dir = tmp_path / "findings" / "target.test"
    sqli_dir = findings_dir / "sqli"
    sqli_dir.mkdir(parents=True)
    (sqli_dir / "nuclei.txt").write_text(
        "[sqli] [http] [high] https://target.test/search?q=test\n",
        encoding="utf-8",
    )
    reports_root = tmp_path / "reports"
    report_dir = reports_root / "target.test"
    report_dir.mkdir(parents=True)
    original = report_dir / "sqli_001.md"
    original.write_text("historical report\n", encoding="utf-8")

    monkeypatch.setattr(report_generator, "REPORTS_DIR", str(reports_root))
    monkeypatch.setattr(
        report_generator,
        "load_finding_index",
        lambda _path: {"target": "target.test", "findings": []},
    )

    report_generator.process_findings_dir(str(findings_dir), allow_legacy_drafts=True)

    assert original.read_text(encoding="utf-8") == "historical report\n"
    assert (report_dir / "sqli_002.md").is_file()


def test_report_index_replace_failure_preserves_previous_bytes(monkeypatch, tmp_path):
    report_dir = tmp_path / "reports" / "target.test"
    report_dir.mkdir(parents=True)
    index_file = report_dir / "INDEX.json"
    summary_file = report_dir / "SUMMARY.md"
    old_index = b'{"target":"old","reports":[]}\n'
    old_summary = b"old summary\n"
    index_file.write_bytes(old_index)
    summary_file.write_bytes(old_summary)

    original_replace = Path.replace

    def fail_index_replace(self, destination):
        if self.name.startswith(".INDEX.json."):
            raise OSError("simulated interrupted replace")
        return original_replace(self, destination)

    monkeypatch.setattr(Path, "replace", fail_index_replace)

    with pytest.raises(OSError, match="simulated interrupted replace"):
        report_generator.write_report_index(
            str(report_dir),
            "target.test",
            1,
            [{
                "id": "xss_001",
                "severity": "medium",
                "type": "xss",
                "title": "Example",
                "url": "https://target.test/",
            }],
        )

    assert index_file.read_bytes() == old_index
    assert summary_file.read_bytes() == old_summary
    assert not list(report_dir.glob(".INDEX.json.*.tmp"))
