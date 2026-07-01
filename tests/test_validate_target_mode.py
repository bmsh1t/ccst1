"""Regression tests for validate.py target-driven advisory behavior."""

import json

import validate
from runtime_state import load_runtime_state


def test_gate2_in_scope_is_target_driven_advisory(capsys):
    passed, notes = validate.gate2_in_scope("ignored-program")

    output = capsys.readouterr().out
    assert passed is True
    assert notes["advisory_only"] is True
    assert notes["matches_target_context"] is True
    assert notes["target_context"] == "ignored-program"
    assert "supplied target/program context directly" in output.lower()
    assert "external scope pages are advisory only" in output.lower()


def test_gate2_in_scope_marks_ctf_override_when_enabled(capsys):
    passed, notes = validate.gate2_in_scope("ignored-program", skip_scope=True)

    output = capsys.readouterr().out
    assert passed is True
    assert notes["skipped_in_ctf_mode"] is True
    assert "ctf mode is enabled" in output.lower()


def test_gate4_dup_policy_stays_advisory_only(capsys):
    passed, notes = validate.gate4_not_dup(
        "IDOR",
        "https://target.local/api/users/1",
        "ignored-program",
    )

    output = capsys.readouterr().out
    assert passed is True
    assert notes["advisory_only"] is True
    assert notes["target_context"] == "ignored-program"
    assert notes["endpoint"] == "https://target.local/api/users/1"
    assert "external disclosed-report and program-policy checks stay advisory only" in output.lower()


def test_write_validation_summary_updates_last_validate(tmp_path, monkeypatch):
    monkeypatch.setattr(validate, "BASE_DIR", tmp_path, raising=False)
    report_path = tmp_path / "findings" / "target-program-idor" / "hackerone-report.md"
    report_path.parent.mkdir(parents=True)

    info = {
        "target": "target-program",
        "vuln_type": "IDOR",
        "endpoint": "https://api.target.com/api/v2/orders/42",
        "impact": "Read another user's order",
        "cvss_score": 8.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
    }

    summary = validate.build_validation_summary(info, all_pass=True, report_path=report_path)
    validate.write_validation_summary(summary, report_path)

    report_summary = report_path.parent / "validation-summary.json"
    submission_notes = report_path.parent / "submission-notes.md"
    last_validate = tmp_path / "findings" / "last-validate.json"

    assert report_summary.exists()
    assert submission_notes.exists()
    assert last_validate.exists()

    saved = json.loads(report_summary.read_text(encoding="utf-8"))
    assert saved["target"] == "api.target.com"
    assert saved["program"] == "target-program"
    assert saved["vuln_class"] == "idor"
    assert saved["severity"] == "high"
    assert saved["result"] == "confirmed"
    assert saved["submission_notes_path"] == str(submission_notes)

    notes = submission_notes.read_text(encoding="utf-8")
    assert "Validation summary: `validation-summary.json`" in notes
    assert "Raw HTTP request" in notes
    assert "Four validation gates: `PASS`" in notes

    last_saved = json.loads(last_validate.read_text(encoding="utf-8"))
    assert last_saved["report_path"] == str(report_path)
    assert last_saved["submission_notes_path"] == str(submission_notes)



def test_submission_notes_include_scanner_and_evidence_handoff(tmp_path):
    report_path = tmp_path / "findings" / "target-program-ssrf" / "hackerone-report.md"
    summary = {
        "result": "partial",
        "severity": "medium",
        "cvss_score": 6.9,
        "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
        "all_gates_passed": False,
        "report_path": str(report_path),
        "scanner_summary_path": "findings/target/scanner-summary.json",
        "browser_evidence": {"summary_path": "evidence/target/browser/summary.json"},
    }

    notes_path = validate.write_submission_notes(summary, report_path)

    notes = notes_path.read_text(encoding="utf-8")
    assert "Scanner handoff reviewed: `findings/target/scanner-summary.json`" in notes
    assert "Evidence artifact path is attached: `evidence/target/browser/summary.json`" in notes
    assert "Four validation gates: `NEEDS REVIEW`" in notes

def test_validation_summary_preserves_finding_linkage(tmp_path):
    report_path = tmp_path / "findings" / "target-program-sqli" / "hackerone-report.md"
    info = {
        "target": "target-program",
        "vuln_type": "SQLI",
        "endpoint": "https://api.target.com/api/v2/orders?id=42",
        "impact": "Confirmed time-based SQL injection.",
        "cvss_score": 8.8,
        "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N",
        "finding_id": "sqli_deadbeef",
        "finding_source_file": "sqli/timebased_candidates.txt",
        "finding_summary": "[SQLI-POC-VERIFIED] https://api.target.com/api/v2/orders?id=42",
    }

    summary = validate.build_validation_summary(info, all_pass=True, report_path=report_path)

    assert summary["finding_id"] == "sqli_deadbeef"
    assert summary["finding_source_file"] == "sqli/timebased_candidates.txt"
    assert summary["finding_summary"].startswith("[SQLI-POC-VERIFIED]")


def test_validation_summary_carries_browser_evidence_linkage(tmp_path):
    report_path = tmp_path / "findings" / "target-program-xss" / "hackerone-report.md"
    info = {
        "target": "target-program",
        "vuln_type": "XSS",
        "endpoint": "https://target.local/profile",
        "impact": "Browser state confirms stored payload execution.",
        "cvss_score": 6.9,
        "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:L/VI:L/VA:N/SC:N/SI:L/SA:N",
        "browser_evidence": {
            "dir": "/tmp/evidence/target.local/browser/20260508T000000Z-validate",
            "summary_path": "/tmp/evidence/target.local/browser/20260508T000000Z-validate/summary.json",
            "session": "browser-target.local",
            "url": "https://target.local/profile",
            "request_count": 3,
            "console_count": 1,
            "screenshot_path": "/tmp/evidence/target.local/browser/20260508T000000Z-validate/screenshot.png",
            "artifacts": {"requests_json": "/tmp/large/requests.json"},
            "steps": [{"stdout": "x" * 4096}],
        },
    }

    summary = validate.build_validation_summary(info, all_pass=True, report_path=report_path)

    linkage = summary["browser_evidence"]
    assert linkage["dir"].endswith("-validate")
    assert linkage["session"] == "browser-target.local"
    assert linkage["request_count"] == 3
    assert linkage["console_count"] == 1
    assert linkage["screenshot_path"].endswith("screenshot.png")
    assert "artifacts" not in linkage
    assert "steps" not in linkage


def test_validate_browser_evidence_resolver_uses_last_capture(tmp_path, monkeypatch):
    monkeypatch.setattr(validate, "BASE_DIR", tmp_path, raising=False)
    capture_dir = tmp_path / "evidence" / "target.local" / "browser" / "20260508T000000Z-hunt"
    capture_dir.mkdir(parents=True)
    summary_path = capture_dir / "summary.json"
    summary_path.write_text(
        json.dumps(
            {
                "evidence_dir": str(capture_dir),
                "summary_path": str(summary_path),
                "session": "browser-target.local",
                "url": "https://target.local/app",
                "counts": {"requests": 2, "console": 0},
                "artifacts": {"screenshot_png": str(capture_dir / "screenshot.png")},
            }
        ),
        encoding="utf-8",
    )
    (capture_dir.parent / "last-capture.json").write_text(
        json.dumps({"summary_path": str(summary_path)}),
        encoding="utf-8",
    )

    linkage = validate.resolve_browser_evidence_for_validate("target.local")

    assert linkage["dir"] == str(capture_dir)
    assert linkage["summary_path"] == str(summary_path)
    assert linkage["request_count"] == 2


def test_validate_browser_evidence_resolver_captures_explicit_url(monkeypatch):
    captured = {}

    def fake_capture(target, browser_url, *, session="", label="", evidence_root=None, capture_screenshot=False):
        captured.update(
            {
                "target": target,
                "url": browser_url,
                "session": session,
                "label": label,
                "evidence_root": str(evidence_root),
                "capture_screenshot": capture_screenshot,
            }
        )
        return {
            "evidence_dir": "/tmp/evidence/target.local/browser/20260508T000000Z-validate",
            "summary_path": "/tmp/evidence/target.local/browser/20260508T000000Z-validate/summary.json",
            "session": session,
            "url": browser_url,
            "counts": {"requests": 1, "console": 0},
        }

    monkeypatch.setattr(validate, "capture_browser_evidence", fake_capture)

    linkage = validate.resolve_browser_evidence_for_validate(
        "target.local",
        browser_url="https://target.local/profile",
        browser_session="reuse-me",
    )

    assert captured["target"] == "target.local"
    assert captured["url"] == "https://target.local/profile"
    assert captured["session"] == "reuse-me"
    assert captured["label"] == "validate"
    assert captured["evidence_root"].endswith("/evidence")
    assert captured["capture_screenshot"] is False
    assert linkage["request_count"] == 1


def test_mark_finding_validated_updates_finding_index(tmp_path):
    findings_dir = tmp_path / "findings" / "target.com"
    findings_dir.mkdir(parents=True)
    (findings_dir / "findings.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "target": "target.com",
                "findings": [
                    {
                        "id": "sqli_deadbeef",
                        "type": "sqli",
                        "url": "https://target.com/item?id=1",
                        "validation_status": "unvalidated",
                        "report_status": "not_generated",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    summary = {
        "all_gates_passed": True,
        "validated_at": "2026-05-07T00:00:00Z",
    }
    summary_path = findings_dir / "validated" / "validation-summary.json"

    validate.mark_finding_validated(str(findings_dir), "sqli_deadbeef", summary, summary_path)

    payload = json.loads((findings_dir / "findings.json").read_text(encoding="utf-8"))
    finding = payload["findings"][0]
    assert finding["validation_status"] == "validated"
    assert finding["validation_summary"] == str(summary_path)
    assert finding["validated_at"] == "2026-05-07T00:00:00Z"


def test_update_runtime_state_after_validate_tracks_progress(tmp_path, monkeypatch):
    monkeypatch.setattr(validate, "BASE_DIR", tmp_path, raising=False)
    findings_dir = tmp_path / "findings" / "target.com"
    findings_dir.mkdir(parents=True)
    (findings_dir / "findings.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "target": "target.com",
                "findings": [
                    {
                        "id": "sqli_deadbeef",
                        "type": "sqli",
                        "url": "https://target.com/item?id=1",
                        "validation_status": "validated",
                        "report_status": "not_generated",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    summary = {
        "target": "target.com",
        "result": "confirmed",
        "finding_id": "sqli_deadbeef",
    }

    validate.update_runtime_state_after_validate(summary, str(findings_dir))

    runtime_state = load_runtime_state(tmp_path, "target.com")
    # v2 schema: stage-pipeline fields gone; remaining are breadcrumbs + counts via derive_state_view.
    assert runtime_state["mode"] == "validate"
    assert runtime_state["last_executed_workflow"] == "validate_finding"
    assert runtime_state["last_validated_finding_id"] == "sqli_deadbeef"
    # Derived counts via derive_state_view:
    from runtime_state import derive_state_view
    view = derive_state_view(tmp_path, "target.com")
    assert view["findings"]["validated_pending_report"] == 1
