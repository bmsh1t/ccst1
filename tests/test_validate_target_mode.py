"""Regression tests for validate.py target-driven advisory behavior."""

import json

import validate
from runtime_state import load_runtime_state


def test_validate_prompt_helpers_use_defaults_on_eof(monkeypatch):
    def raise_eof(_prompt):
        raise EOFError

    monkeypatch.setattr("builtins.input", raise_eof)

    assert validate.ask("Target", "target.local") == "target.local"
    assert validate.ask("No default") == ""
    assert validate.ask_yn("Continue?", default=False) is False
    assert validate.ask_choice("Attack Vector", [("N", "Network"), ("A", "Adjacent")]) == "N"
    assert validate.ask_choice("Integrity", [("H", "High"), ("L", "Low"), ("N", "None")], default="N") == "N"


def test_gate2_in_scope_is_target_driven_advisory(capsys):
    passed, notes = validate.gate2_in_scope("ignored-program")

    output = capsys.readouterr().out
    assert passed is True
    assert notes["advisory_only"] is True
    assert notes["matches_target_context"] is True
    assert notes["target_context"] == "ignored-program"
    assert "supplied target/program context directly" in output.lower()
    assert "external program pages are optional context only" in output.lower()


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
    assert saved["seven_question_gate_passed"] is True
    assert saved["seven_question_gate"]["source"] == "derived_from_4_gates"
    assert saved["submission_notes_path"] == str(submission_notes)

    notes = submission_notes.read_text(encoding="utf-8")
    assert "Validation summary: `validation-summary.json`" in notes
    assert "Raw HTTP request" in notes
    assert "7-Question Gate: `PASS`" in notes
    assert "Four validation gates: `PASS`" in notes

    last_saved = json.loads(last_validate.read_text(encoding="utf-8"))
    assert last_saved["report_path"] == str(report_path)
    assert last_saved["submission_notes_path"] == str(submission_notes)


def test_ensure_report_output_path_creates_explicit_output_parent(tmp_path):
    output_path = tmp_path / "new" / "nested" / "hackerone-report.md"

    resolved = validate.ensure_report_output_path(output_path)

    assert resolved == output_path
    assert output_path.parent.is_dir()


def test_validation_summary_records_explicit_seven_question_gate(tmp_path):
    report_path = tmp_path / "findings" / "target-program-idor" / "hackerone-report.md"
    explicit_gate = {
        "source": "ai_explicit",
        "questions": {
            "q1_replayable_now": {"status": "pass", "basis": "Exact owner/peer replay captured."},
            "q2_impact_demonstrated": {"status": "pass", "basis": "Peer private order returned."},
            "q3_target_context": {"status": "pass", "basis": "Endpoint host matches supplied target."},
            "q4_attacker_access": {"status": "pass", "basis": "Regular user session only."},
            "q5_not_known_behavior": {"status": "pass", "basis": "No matching disclosed issue found."},
            "q6_impact_beyond_possible": {"status": "pass", "basis": "Response includes private marker."},
            "q7_not_never_submit": {"status": "chain_required", "basis": "Standalone signal needs proven chain.", "next_action": "Report only the chained impact."},
        },
    }
    info = {
        "target": "target-program",
        "vuln_type": "Open Redirect",
        "endpoint": "https://target.local/oauth/redirect",
        "impact": "Redirect can become account takeover only with OAuth code theft chain.",
        "cvss_score": 5.3,
        "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
        "gate1_pass": True,
        "gate2_pass": True,
        "gate3_pass": True,
        "gate4_pass": True,
        "seven_question_gate": explicit_gate,
    }

    summary = validate.build_validation_summary(info, all_pass=True, report_path=report_path)

    assert summary["result"] == "partial"
    assert summary["all_gates_passed"] is False
    assert summary["four_validation_gates_passed"] is True
    assert summary["seven_question_gate_passed"] is False
    assert summary["seven_question_gate_decision"] == "chain_required"
    assert summary["seven_question_gate"]["source"] == "explicit"
    q7 = summary["seven_question_gate"]["questions"]["q7_not_never_submit"]
    assert q7["status"] == "chain_required"
    assert q7["next_action"] == "Report only the chained impact."



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



def test_sync_validation_artifacts_records_ledger_and_resolves_queue(tmp_path):
    from action_queue import add_manual_action, load_queue
    from evidence_ledger import load_entries

    add_manual_action(
        tmp_path,
        target="target.com",
        action_type="validation",
        evidence="Validate finding sqli_deadbeef before report.",
        next_question="Does the candidate pass validation gates?",
        action="python3 tools/validate.py --findings-dir findings/target.com --finding-id sqli_deadbeef",
        command_hint="python3 tools/validate.py --findings-dir findings/target.com --finding-id sqli_deadbeef",
        evidence_type="candidate-validation",
        stop_condition="Stop after validation-summary.json and submission-notes.md are written.",
    )
    report_path = tmp_path / "findings" / "target.com-sqli" / "hackerone-report.md"
    report_path.parent.mkdir(parents=True)
    summary = {
        "target": "target.com",
        "endpoint": "https://target.com/item?id=1",
        "vuln_class": "sqli",
        "result": "confirmed",
        "all_gates_passed": True,
        "finding_id": "sqli_deadbeef",
        "report_path": str(report_path),
        "submission_notes_path": str(report_path.parent / "submission-notes.md"),
    }

    sync = validate.sync_validation_artifacts(summary, repo_root=tmp_path)

    entries = load_entries(tmp_path, "target.com")
    queue = load_queue(tmp_path, "target.com")
    action = queue["actions"][0]

    assert sync["ledger"]["status"] == "updated"
    assert sync["action_queue"]["status"] == "updated"
    assert entries[-1]["source"] == "validate"
    assert entries[-1]["result"] == "tested_finding"
    assert entries[-1]["evidence_ref"].endswith("validation-summary.json")
    assert action["status"] == "validated"
    assert "validation-summary=" in action["result"]
    assert "submission-notes=" in action["notes"]


def test_sync_validation_artifacts_partial_keeps_queue_candidate(tmp_path):
    from action_queue import add_manual_action, load_queue
    from evidence_ledger import load_entries

    add_manual_action(
        tmp_path,
        target="target.com",
        action_type="candidate-evidence-gap",
        evidence="Endpoint /item?id=1 needs validation.",
        next_question="Is the candidate strong enough?",
        action="Run /validate for /item?id=1.",
        evidence_type="candidate-validation",
    )
    report_path = tmp_path / "findings" / "target.com-sqli" / "hackerone-report.md"
    summary = {
        "target": "target.com",
        "endpoint": "https://target.com/item?id=1",
        "vuln_class": "sqli",
        "result": "partial",
        "all_gates_passed": False,
        "report_path": str(report_path),
    }

    sync = validate.sync_validation_artifacts(summary, repo_root=tmp_path)

    entries = load_entries(tmp_path, "target.com")
    action = load_queue(tmp_path, "target.com")["actions"][0]

    assert sync["action_queue"]["action_status"] == "candidate"
    assert entries[-1]["result"] == "candidate"
    assert action["status"] == "candidate"

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
