"""Store-bound validation, read-only preflight and durable publication recovery."""

import hashlib
import json
from pathlib import Path

import pytest
import validate
import validation_runner
from runtime_state import load_runtime_state
from target_paths import target_storage_key
from target_store import StoreError, TargetStore, initialize_target_store


def _seed_machine_preflight(tmp_path, *, target="target.com", finding_id="sqli_preflight",
                            endpoint="https://target.com/rest/products/search?q=test", family="sqli", method="GET",
                            runner_result="tested_finding"):
    store = TargetStore(tmp_path, target)
    initialize_target_store(tmp_path, target)
    store.create_finding(command_id=f"claim:{finding_id}", finding_id=finding_id, endpoint=endpoint,
                         method=method, family=family, title=finding_id, claim="Candidate response difference", actor="operator")
    bundle = tmp_path / ".private" / "validation" / store.key / finding_id
    bundle.mkdir(parents=True)
    artifacts = {}
    for kind, body in (("request", f"{method} {endpoint} HTTP/1.1\n\n"),
                       ("response", 'HTTP/1.1 200 OK\n\n{"peer_data":"recorded"}')):
        path = bundle / f"{kind}.txt"
        path.write_text(body, encoding="utf-8")
        artifacts[kind] = path.relative_to(tmp_path).as_posix()
    evidence = {"schema_version": 1, "attempt_id": f"attempt:{finding_id}", "source": "native",
                "generated_at": "2026-09-24T00:00:00Z", "result": runner_result,
                "observed_difference": "Recorded peer data differs from the owner control response",
                "runs": [{"url": endpoint, "method": method, "actor": "peer", "artifacts": artifacts}]}
    summary = validation_runner.record_native_evidence(
        repo_root=tmp_path, target=target, finding_id=finding_id, evidence=evidence, state_changing=False,
    )
    assert validation_runner.sync_runner_artifacts(summary, repo_root=tmp_path)["status"] == "updated"
    summary_path = tmp_path / summary["summary_path"]
    summary_path.write_text(json.dumps(summary), encoding="utf-8")
    decision = {
        "schema_version": validate.MACHINE_DECISION_SCHEMA_VERSION,
        "target": target, "finding_id": finding_id, "endpoint": endpoint, "vuln_class": family,
        "method": method, "impact": "Recorded private peer data was disclosed", "severity": "critical",
        "gates": {key: {"passed": True, "notes": {"source": "recorded-response"}}
                  for key in validate.MACHINE_DECISION_GATE_KEYS},
        "seven_question_gate": {"questions": {
            key: {"status": "pass", "basis": "Recorded control and variant support this judgment"}
            for key, _ in validate.SEVEN_QUESTION_DEFINITIONS}},
        "cvss": {"score": 8.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "params": {}},
        "evidence": {"summary": "Recorded peer response", "refs": [str(summary_path)], "runner_summary": str(summary_path)},
        "report": {"path": f"findings/{store.key}/validated/{finding_id}.md",
                   "content": f"# {finding_id}\n\nSeverity: critical\n\nRecorded private peer data was disclosed.\n"},
    }
    decision_path = tmp_path / f"{finding_id}.decision.json"
    decision_path.write_text(json.dumps(decision), encoding="utf-8")
    return target, finding_id, tmp_path / "findings" / store.key, decision_path


def _file_snapshot(root: Path) -> dict[str, bytes]:
    return {
        str(path.relative_to(root)): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file() and not path.name.endswith("-shm")
        and not (path.name.endswith("-wal") and path.stat().st_size == 0)
    }


def test_non_tty_validate_without_decision_fails_closed_before_state_write(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(validate, "BASE_DIR", tmp_path, raising=False)
    monkeypatch.setattr(validate.sys.stdin, "isatty", lambda: False)

    exit_code = validate.main([])

    assert exit_code == 2
    assert "validation requires --decision-json" in capsys.readouterr().err
    assert not (tmp_path / "findings").exists()
    assert not (tmp_path / "state").exists()


def test_machine_decision_preflight_success_is_read_only(tmp_path, monkeypatch, capsys):
    target, finding_id, findings_dir, decision_path = _seed_machine_preflight(tmp_path)
    decision = json.loads(decision_path.read_text(encoding="utf-8"))
    decision.pop("cvss")
    decision_path.write_text(json.dumps(decision), encoding="utf-8")
    before = _file_snapshot(tmp_path)
    monkeypatch.setattr(validate, "BASE_DIR", tmp_path, raising=False)

    exit_code = validate.main(
        [
            "--target",
            target,
            "--finding-id",
            finding_id,
            "--decision-json",
            str(decision_path),
            "--preflight",
            "--json",
        ]
    )

    output = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert output["status"] == "preflight_ok"
    assert output["read_only"] is True
    assert output["finding_id"] == finding_id
    assert output["findings_dir"] == str(findings_dir)
    assert _file_snapshot(tmp_path) == before
    assert not (findings_dir / "validated").exists()


def test_machine_decision_preflight_aggregates_errors_without_writes(tmp_path, monkeypatch, capsys):
    target, finding_id, findings_dir, decision_path = _seed_machine_preflight(tmp_path)
    decision = json.loads(decision_path.read_text(encoding="utf-8"))
    decision["endpoint"] = "/wrong-path"
    decision["gates"] = {}
    decision["cvss"] = {}
    decision["evidence"] = {"summary": "", "refs": [str(tmp_path / "missing.raw")]}
    decision["report"] = {}
    decision_path.write_text(json.dumps(decision), encoding="utf-8")
    before = _file_snapshot(tmp_path)
    monkeypatch.setattr(validate, "BASE_DIR", tmp_path, raising=False)

    exit_code = validate.main(
        [
            "--target",
            target,
            "--finding-id",
            finding_id,
            "--decision-json",
            str(decision_path),
            "--preflight",
            "--json",
        ]
    )

    output = json.loads(capsys.readouterr().out)
    errors = output["errors"]
    assert exit_code == 2
    assert output["status"] == "preflight_invalid"
    assert output["read_only"] is True
    assert len(errors) >= 4
    assert any("canonical finding endpoint" in error for error in errors)
    assert any("decision.gates" in error for error in errors)
    assert any("decision.cvss" in error for error in errors)
    assert any("evidence.summary" in error for error in errors)
    assert _file_snapshot(tmp_path) == before
    assert not (findings_dir / "validated").exists()


def test_machine_preflight_rejects_ordinary_file_as_runner_witness(tmp_path, monkeypatch, capsys):
    target, finding_id, _, decision_path = _seed_machine_preflight(tmp_path)
    decision = json.loads(decision_path.read_text(encoding="utf-8"))
    ordinary = tmp_path / "evidence" / target / "ordinary.txt"
    ordinary.write_text("not a runner summary\n", encoding="utf-8")
    decision["evidence"]["refs"] = [str(ordinary)]
    decision["evidence"]["runner_summary"] = str(ordinary)
    decision_path.write_text(json.dumps(decision), encoding="utf-8")
    before = _file_snapshot(tmp_path)
    monkeypatch.setattr(validate, "BASE_DIR", tmp_path, raising=False)

    assert validate.main([
        "--target", target,
        "--finding-id", finding_id,
        "--decision-json", str(decision_path),
        "--preflight", "--json",
    ]) == 2
    output = json.loads(capsys.readouterr().out)

    assert any("runner_summary is invalid JSON" in error for error in output["errors"])
    assert _file_snapshot(tmp_path) == before


def test_machine_preflight_rejects_runner_artifact_digest_drift(tmp_path, monkeypatch, capsys):
    target, finding_id, _, decision_path = _seed_machine_preflight(tmp_path)
    decision = json.loads(decision_path.read_text(encoding="utf-8"))
    runner = json.loads(Path(decision["evidence"]["runner_summary"]).read_text(encoding="utf-8"))
    artifact = tmp_path / runner["artifact_bindings"][0]["ref"]
    artifact.write_text("tampered\n", encoding="utf-8")
    before = _file_snapshot(tmp_path)
    monkeypatch.setattr(validate, "BASE_DIR", tmp_path, raising=False)

    assert validate.main([
        "--target", target,
        "--finding-id", finding_id,
        "--decision-json", str(decision_path),
        "--preflight", "--json",
    ]) == 2
    output = json.loads(capsys.readouterr().out)

    assert any("changed" in error for error in output["errors"])
    assert _file_snapshot(tmp_path) == before


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
    report_summary = validate.write_validation_summary(summary, report_path)

    submission_notes = Path(summary["submission_notes_path"])
    last_validate = tmp_path / "findings" / "last-validate.json"

    assert report_summary.exists()
    assert submission_notes.exists()
    assert last_validate.exists()

    saved = json.loads(report_summary.read_text(encoding="utf-8"))
    assert saved["target"] == "api.target.com"
    assert saved["program"] == "target-program"
    assert saved["method"] == "GET"
    assert saved["vuln_class"] == "idor"
    assert saved["severity"] == "high"
    assert saved["result"] == "confirmed"
    assert saved["seven_question_gate_passed"] is True
    assert saved["seven_question_gate"]["source"] == "derived_from_4_gates"
    assert saved["submission_notes_path"] == str(submission_notes)

    notes = submission_notes.read_text(encoding="utf-8")
    assert f"Validation summary: `{report_summary.name}`" in notes
    assert "Raw HTTP request" in notes
    assert "7-Question Gate: `PASS`" in notes
    assert "Four validation gates: `PASS`" in notes

    last_saved = json.loads(last_validate.read_text(encoding="utf-8"))
    assert last_saved["report_path"] == str(report_path)
    assert last_saved["submission_notes_path"] == str(submission_notes)


def test_validation_summary_preserves_explicit_method(tmp_path):
    report_path = tmp_path / "findings" / "target-program-ssrf" / "hackerone-report.md"
    info = {
        "target": "target-program",
        "vuln_type": "SSRF",
        "endpoint": "https://api.target.com/profile/image/url",
        "method": "post",
        "impact": "Server-side request is stored and readable back.",
        "cvss_score": 5.3,
        "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    }

    summary = validate.build_validation_summary(info, all_pass=True, report_path=report_path)

    assert summary["method"] == "POST"


def test_validation_summary_without_cvss_keeps_recorded_severity(tmp_path):
    report_path = tmp_path / "findings" / "target-program-idor" / "report.md"
    info = {
        "target": "target-program",
        "vuln_type": "IDOR",
        "endpoint": "https://api.target.com/orders/42",
        "impact": "A peer actor can read the recorded private order.",
        "severity": "high",
    }

    summary = validate.build_validation_summary(info, all_pass=True, report_path=report_path)

    assert summary["severity"] == "high"
    assert "cvss_score" not in summary
    assert "cvss_vector" not in summary
    assert "CVSS:" not in validate.build_submission_notes(summary)


def test_generated_skeleton_separates_validation_evidence_from_report_readiness(tmp_path):
    report_path = tmp_path / "findings" / "target-program-sqli" / "hackerone-report.md"
    info = {
        "target": "target-program",
        "vuln_type": "SQLI",
        "endpoint": "https://api.target.com/rest/products/search?q=test",
        "impact": "The probe returns records outside the baseline result set.",
        "cvss_score": 8.8,
        "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N",
    }
    report_path.parent.mkdir(parents=True)
    report_path.write_text(validate.generate_report_skeleton(info), encoding="utf-8")

    summary = validate.build_validation_summary(info, all_pass=True, report_path=report_path)

    assert summary["validation_evidence_passed"] is True
    assert summary["result"] == "confirmed"
    assert summary["report_draft_status"] == "incomplete"
    assert summary["report_draft"]["placeholder_count"] > 0
    assert summary["report_ready"] is False
    assert summary["all_gates_passed"] is False


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


def test_native_record_evidence_closes_through_scaffold_preflight_and_validate(tmp_path, monkeypatch, capsys):
    """原生闭环：record-evidence 登记 → scaffold 预填 → preflight → validate 定级 → 可报告。

    这是 record-evidence 的存在理由：不重放请求的原生观察必须能走到正式验证。
    """
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from test_validation_runner import _native_fixture

    target, finding_id, evidence = _native_fixture(
        tmp_path, url="https://target.test/rest/orders/1", finding_id="NATIVE-E2E"
    )
    evidence["subject_step"] = 1
    evidence_path = tmp_path / "native-evidence.json"
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")

    monkeypatch.setattr(validate, "BASE_DIR", tmp_path, raising=False)
    monkeypatch.setattr(validate.sys.stdin, "isatty", lambda: False)

    # 1) 登记已执行的原生观察（不发请求）
    assert validation_runner.main([
        "record-evidence", "--repo-root", str(tmp_path), "--target", target,
        "--finding-id", finding_id, "--evidence-json", str(evidence_path),
        "--state-changing", "--redline-checked",
    ]) == 0
    capsys.readouterr()

    # 2) scaffold 预填机械字段，method 跟随 canonical finding（POST）
    assert validate.main(["--target", target, "--finding-id", finding_id, "--scaffold"]) == 0
    scaffold = json.loads(capsys.readouterr().out)
    assert scaffold["method"] == "POST"
    assert scaffold["endpoint"] == "https://target.test/rest/orders/1"
    assert scaffold["evidence"]["runner_summary"]
    assert Path(tmp_path / scaffold["evidence"]["runner_summary"]).is_file()

    # 3) AI 只填判断字段
    scaffold["impact"] = "Peer actor mutated state owned by the recorded identity."
    for key in validate.MACHINE_DECISION_GATE_KEYS:
        scaffold["gates"][key] = {"passed": True, "notes": {"source": "native-run"}}
    for key, _ in validate.SEVEN_QUESTION_DEFINITIONS:
        scaffold["seven_question_gate"]["questions"][key] = {
            "status": "pass", "basis": "Native observation recorded from the browser session.",
        }
    scaffold["cvss"] = {
        "score": 7.5,
        "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N",
        "params": {"AV": "N", "AC": "L", "PR": "L", "VC": "H"},
    }
    scaffold["evidence"]["summary"] = "Native observations recorded from the browser session."
    scaffold["report"]["content"] = (
        "# Native state transition\n\nA peer actor mutated state owned by the recorded identity.\n"
        + "Recorded artifacts are bound to the run summary. " * 5
    )
    decision_path = tmp_path / "native-decision.json"
    decision_path.write_text(json.dumps(scaffold), encoding="utf-8")

    # 4) preflight 只读通过
    assert validate.main([
        "--target", target, "--finding-id", finding_id,
        "--decision-json", str(decision_path), "--preflight", "--json",
    ]) == 0
    preflight = json.loads(capsys.readouterr().out)
    assert preflight["status"] == "preflight_ok"
    assert preflight["read_only"] is True

    # 5) validate 定级：native witness 与 request-diff witness 走同一条绑定
    assert validate.main([
        "--target", target, "--finding-id", finding_id,
        "--decision-json", str(decision_path), "--json",
    ]) == 0
    result = json.loads(capsys.readouterr().out)

    findings_dir = tmp_path / "findings" / validation_runner.target_storage_key(
        validation_runner.canonical_target_value(target)
    )
    store = TargetStore(tmp_path, target)
    finding = store.finding(finding_id)
    assert result["finding_id"] == finding_id
    assert finding["assessment"]["verdict"] == "confirmed"
    assert finding["method"] == "POST"
    assert finding["delivery_events"] == []
    assert len(finding["reports"]) == 1
    import report_generator
    total, index = report_generator.process_findings_dir(findings_dir)
    assert total == 1
    assert Path(index[0]["file"]).read_text() == scaffold["report"]["content"].rstrip() + "\n"


def _decision_args(findings_dir, finding_id, decision_path):
    return ["--findings-dir", str(findings_dir), "--finding-id", finding_id,
            "--decision-json", str(decision_path), "--json"]


@pytest.mark.parametrize("field,value", [
    ("target", "elsewhere.test"), ("finding_id", "missing"),
    ("endpoint", "https://target.com/rest/products/search?q=different"),
    ("method", "POST"), ("vuln_class", "unrelated-family"),
])
def test_machine_binding_rejects_identity_changes_before_writes(tmp_path, capsys, field, value):
    _, finding_id, findings_dir, decision_path = _seed_machine_preflight(tmp_path)
    decision = json.loads(decision_path.read_text())
    decision[field] = value
    decision_path.write_text(json.dumps(decision))
    before = _file_snapshot(tmp_path)
    args = _decision_args(findings_dir, finding_id, decision_path)
    assert validate.main([*args, "--preflight"]) == 2
    assert json.loads(capsys.readouterr().out)["errors"]
    assert _file_snapshot(tmp_path) == before
    assert validate.main(args) == 2
    capsys.readouterr()
    assert _file_snapshot(tmp_path) == before


@pytest.mark.parametrize("fault", ["uninitialized", "legacy", "missing-store", "bad-fence", "damaged-store"])
def test_validate_store_admission_never_recovers_old_owner(tmp_path, capsys, fault):
    target, finding_id, findings_dir, decision_path = _seed_machine_preflight(tmp_path)
    state = tmp_path / "state" / target
    if fault in {"uninitialized", "legacy", "missing-store"}:
        for path in state.glob("metadata.sqlite3*"):
            path.unlink()
    if fault in {"uninitialized", "legacy"}:
        (state / "legacy-frozen.json").unlink()
    if fault == "bad-fence":
        (state / "legacy-frozen.json").write_text("{}")
    if fault == "damaged-store":
        (state / "metadata.sqlite3").write_bytes(b"broken database")
    if fault == "legacy":
        findings_dir.mkdir(parents=True, exist_ok=True)
        (findings_dir / "findings.json").write_text(json.dumps([{"id": finding_id, "status": "confirmed"}]))
    before = _file_snapshot(tmp_path)
    assert validate.main([*_decision_args(findings_dir, finding_id, decision_path), "--preflight"]) == 2
    capsys.readouterr()
    assert _file_snapshot(tmp_path) == before


@pytest.mark.parametrize("existing_calibration", [False, True])
def test_machine_report_replay_preserves_body_and_isolated_root(
    tmp_path, monkeypatch, capsys, existing_calibration,
):
    root = tmp_path / "isolated root"
    _, finding_id, findings_dir, decision_path = _seed_machine_preflight(root, family="new-family")
    monkeypatch.setattr(validate, "BASE_DIR", tmp_path / "unrelated checkout")
    source_refs = ["source.example|idor|id swap"]
    decision = json.loads(decision_path.read_text())
    decision["source_knowledge_refs"] = source_refs
    decision_path.write_text(json.dumps(decision))
    original_store = TargetStore(root, "target.com")
    operation_id = json.loads(Path(decision["evidence"]["runner_summary"]).read_text())["store_operation_id"]
    original_evidence = [ref for ref in original_store.finding(finding_id)["evidence"]
                         if ref["operation_id"] == operation_id]
    original_digest = hashlib.sha256(json.dumps(
        [original_store.binding()["store_id"], decision, original_evidence],
        ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ).encode()).hexdigest()
    calibration = root / "hunt-memory" / "pattern_calibration.jsonl"
    historical = b'{"pattern_id":"historical|idor|swap","outcome":"helped"}\n'
    if existing_calibration:
        calibration.parent.mkdir(parents=True, exist_ok=True)
        calibration.write_bytes(historical)
    args = _decision_args(findings_dir, finding_id, decision_path)
    assert validate.main(args) == 0
    result = json.loads(capsys.readouterr().out)
    summary_path = Path(result["summary_path"])
    assert json.loads(summary_path.read_text())["source_knowledge_refs"] == source_refs
    assert result["validation_sync"]["assessment"]["id"] == f"assessment:{original_digest}"
    assert result["validation_sync"]["delivery"]["id"] == f"delivery:{original_digest}"
    assert result["validation_sync"]["report"]["id"] == f"report:{original_digest}"
    assert (calibration.read_bytes() if calibration.exists() else None) == (
        historical if existing_calibration else None
    )
    runtime = load_runtime_state(root, "target.com")
    assert runtime["last_validation_result"] == "confirmed"
    assert runtime["last_validated_finding_id"] == finding_id
    report = Path(result["report_path"])
    body, stat = report.read_bytes(), report.stat()
    store = TargetStore(root, "target.com")
    binding = store.binding()
    assert store.finding(finding_id)["family"] == "new-family"
    assert store.finding(finding_id)["assessment"]["verdict"] == "confirmed"
    assert len(store.finding(finding_id)["reports"]) == 1
    assert store.page("findings")["total"] == 1
    assert store.page("operations")["total"] == 1
    assert store.finding(finding_id)["delivery_events"] == []
    assert validate.main([*args, "--preflight"]) == 0
    capsys.readouterr()
    assert validate.main(args) == 0
    assert json.loads(capsys.readouterr().out)["validation_sync"]["status"] == "deduplicated"
    assert store.binding() == binding
    assert json.loads(summary_path.read_text())["source_knowledge_refs"] == source_refs
    assert (calibration.read_bytes() if calibration.exists() else None) == (
        historical if existing_calibration else None
    )
    assert load_runtime_state(root, "target.com")["last_validated_finding_id"] == finding_id
    assert report.read_bytes() == body
    assert report.stat().st_ino == stat.st_ino
    assert report.stat().st_mtime_ns == stat.st_mtime_ns
    assert not (tmp_path / "unrelated checkout").exists()


@pytest.mark.parametrize("registered,damage", [(False, "same"), (False, "changed"),
                                               (True, "changed"), (True, "missing")])
def test_machine_report_recovery_requires_unchanged_bytes(tmp_path, capsys, registered, damage):
    target, finding_id, findings_dir, decision_path = _seed_machine_preflight(tmp_path)
    decision = json.loads(decision_path.read_text())
    report = tmp_path / decision["report"]["path"]
    args = _decision_args(findings_dir, finding_id, decision_path)
    if registered:
        assert validate.main(args) == 0
        capsys.readouterr()
    else:
        report.parent.mkdir(parents=True)
    if damage == "missing":
        report.unlink()
    else:
        report.write_text(decision["report"]["content"] if damage == "same" else "interrupted or changed")
    before = _file_snapshot(tmp_path)
    assert validate.main(args) == (0 if damage == "same" else 2)
    capsys.readouterr()
    if damage == "same":
        assert len(TargetStore(tmp_path, target).finding(finding_id)["reports"]) == 1
    else:
        assert _file_snapshot(tmp_path) == before


def test_machine_report_cannot_reuse_another_findings_registered_path(tmp_path, capsys):
    _, finding_id, findings_dir, decision_path = _seed_machine_preflight(tmp_path)
    assert validate.main(_decision_args(findings_dir, finding_id, decision_path)) == 0
    capsys.readouterr()
    original = json.loads(decision_path.read_text())
    _, other_id, _, other_path = _seed_machine_preflight(tmp_path, finding_id="other-claim")
    decision = json.loads(other_path.read_text())
    decision["report"] = original["report"]
    other_path.write_text(json.dumps(decision))
    before = _file_snapshot(tmp_path)
    assert validate.main(_decision_args(findings_dir, other_id, other_path)) == 2
    assert "immutable" in capsys.readouterr().err
    assert _file_snapshot(tmp_path) == before


def test_machine_report_atomic_publication_failure_is_recoverable(tmp_path, monkeypatch, capsys):
    _, finding_id, findings_dir, decision_path = _seed_machine_preflight(tmp_path)
    args = _decision_args(findings_dir, finding_id, decision_path)
    decision = json.loads(decision_path.read_text())
    path = tmp_path / decision["report"]["path"]
    with monkeypatch.context() as failure:
        def interrupted(*a, **kw):
            raise OSError("publication interrupted")
        failure.setattr(validate.os, "link", interrupted)
        assert validate.main(args) == 2
        capsys.readouterr()
    assert not path.exists()
    assert list(path.parent.iterdir()) == []
    assert TargetStore(tmp_path, "target.com").finding(finding_id)["assessment"] is None
    assert validate.main(args) == 0
    capsys.readouterr()
    assert path.read_text() == decision["report"]["content"]


@pytest.mark.parametrize("runner_result", ["candidate", "tested_clean", "dead_end"])
@pytest.mark.parametrize("judgment", ["pass", "fail", "unknown"])
def test_machine_review_admission_is_independent_of_native_labels(tmp_path, capsys, runner_result, judgment):
    target, finding_id, findings_dir, decision_path = _seed_machine_preflight(
        tmp_path, runner_result=runner_result,
    )
    decision = json.loads(decision_path.read_text())
    decision["gates"]["gate3"]["passed"] = judgment == "pass"
    decision["seven_question_gate"]["questions"]["q6_impact_beyond_possible"] = {
        "status": judgment, "basis": "Explicit review of recorded response and claimed impact",
    }
    decision_path.write_text(json.dumps(decision))
    runner_path = Path(decision["evidence"]["runner_summary"])
    runner_bytes = runner_path.read_bytes()
    runner = json.loads(runner_bytes)
    assert runner["result"] == runner_result
    assert runner["candidate_ready"] is False
    store = TargetStore(tmp_path, target)
    operation_before = store.execution(runner["store_operation_id"])
    before = _file_snapshot(tmp_path)
    args = _decision_args(findings_dir, finding_id, decision_path)
    assert validate.main([*args, "--preflight"]) == 0
    capsys.readouterr()
    assert _file_snapshot(tmp_path) == before
    assert validate.main(args) == 0
    result = json.loads(capsys.readouterr().out)
    finding = store.finding(finding_id)
    assert finding["assessment"]["verdict"] == ("confirmed" if judgment == "pass" else "inconclusive")
    assert result["report_ready"] is (judgment == "pass")
    assert len(finding["reports"]) == (1 if judgment == "pass" else 0)
    assert finding["assessment"]["evidence"] == [{"operation_id": runner["store_operation_id"], "step": 0}]
    assert runner_path.read_bytes() == runner_bytes
    assert store.execution(runner["store_operation_id"]) == operation_before


def test_machine_reviews_request_diff_without_expected_or_new_execution(tmp_path, monkeypatch, capsys):
    from test_validation_runner import _fake_response

    target, finding_id, findings_dir, decision_path = _seed_machine_preflight(tmp_path)
    decision = json.loads(decision_path.read_text())
    endpoint = decision["endpoint"]
    bodies = iter(['{"value":"first"}', '{"value":"other"}'])
    monkeypatch.setattr(validation_runner, "request_once", lambda **kw: _fake_response(kw["url"], body=next(bodies)))
    summary = validation_runner.run_request_diff(
        repo_root=tmp_path, target=target, finding_id=finding_id, attempt_id="no-expected",
        request_spec={"schema_version": 1, "baseline_request": {"method": "GET", "url": endpoint},
                      "variant_request": {"method": "GET", "url": endpoint, "headers": {"X-Test": "variant"}},
                      "active_dimension": "header:X-Test", "classifier": "sqli"},
        state_changing=False,
    )
    assert summary["result"] == "candidate"
    assert summary["candidate_ready"] is False
    assert summary["expected_check"] == {}
    assert validation_runner.sync_runner_artifacts(summary, repo_root=tmp_path)["status"] == "updated"
    summary_path = tmp_path / summary["summary_path"]
    summary_path.write_text(json.dumps(summary))
    original = summary_path.read_bytes()
    decision["evidence"].update(runner_summary=str(summary_path), refs=[str(summary_path)])
    decision["gates"]["gate3"]["passed"] = False
    decision["seven_question_gate"]["questions"]["q6_impact_beyond_possible"] = {
        "status": "unknown", "basis": "A body difference alone does not demonstrate impact",
    }
    decision_path.write_text(json.dumps(decision))
    monkeypatch.setattr(validation_runner, "request_once", lambda **kw: pytest.fail("review must not execute requests"))
    args = _decision_args(findings_dir, finding_id, decision_path)
    before = _file_snapshot(tmp_path)
    assert validate.main([*args, "--preflight"]) == 0
    capsys.readouterr()
    assert _file_snapshot(tmp_path) == before
    assert validate.main(args) == 0
    capsys.readouterr()
    finding = TargetStore(tmp_path, target).finding(finding_id)
    assert finding["assessment"]["verdict"] == "inconclusive"
    assert finding["reports"] == []
    assert {ref["operation_id"] for ref in finding["assessment"]["evidence"]} == {summary["store_operation_id"]}
    assert summary_path.read_bytes() == original


@pytest.mark.parametrize("fault", ["partial", "unbound", "tampered"])
def test_candidate_admission_keeps_operation_guards(tmp_path, capsys, fault):
    target, finding_id, findings_dir, decision_path = _seed_machine_preflight(
        tmp_path, runner_result="partial" if fault == "partial" else "candidate",
    )
    decision = json.loads(decision_path.read_text())
    runner_path = Path(decision["evidence"]["runner_summary"])
    runner = json.loads(runner_path.read_text())
    expected_error = "complete primary runner evidence"
    if fault == "unbound":
        _, _, _, other_path = _seed_machine_preflight(tmp_path, finding_id="other", runner_result="candidate")
        other = json.loads(other_path.read_text())
        other_runner = json.loads(Path(other["evidence"]["runner_summary"]).read_text())
        runner["store_operation_id"] = other_runner["store_operation_id"]
        runner_path.write_text(json.dumps(runner))
        expected_error = "bind this finding"
    elif fault == "tampered":
        (tmp_path / runner["artifact_bindings"][0]["ref"]).write_text("changed raw bytes")
        expected_error = "changed"
    before = _file_snapshot(tmp_path)
    args = _decision_args(findings_dir, finding_id, decision_path)
    assert validate.main([*args, "--preflight"]) == 2
    errors = json.loads(capsys.readouterr().out)["errors"]
    assert any(expected_error in error for error in errors)
    assert validate.main(args) == 2
    capsys.readouterr()
    assert _file_snapshot(tmp_path) == before
    assert TargetStore(tmp_path, target).finding(finding_id)["assessment"] is None


def test_deferred_report_decision_publishes_real_owner_references(tmp_path, capsys, monkeypatch):
    import report_generator

    target, finding_id, findings_dir, decision_path = _seed_machine_preflight(tmp_path)
    monkeypatch.setattr(validate, "BASE_DIR", tmp_path / "unrelated checkout")
    assert validate.main(["--findings-dir", str(findings_dir), "--finding-id", finding_id, "--scaffold"]) == 0
    scaffold = json.loads(capsys.readouterr().out)
    assert set(scaffold["report"]) == {"path", "content"}
    decision = json.loads(decision_path.read_text())
    original_report = tmp_path / decision["report"]["path"]
    decision["report"] = {"mode": "deferred"}
    decision_path.write_text(json.dumps(decision))
    args = _decision_args(findings_dir, finding_id, decision_path)
    store = TargetStore(tmp_path, target)
    before, binding = _file_snapshot(tmp_path), store.binding()
    assert validate.main([*args, "--preflight"]) == 0
    preview = json.loads(capsys.readouterr().out)
    assert preview["report_mode"] == "deferred" and preview["report_path"] is None
    assert validate.main([*args[:-1], "--preflight"]) == 0
    text = capsys.readouterr().out
    assert "未写正文" in text and "None" not in text
    assert "assessment:" not in text and "delivery:" not in text
    assert _file_snapshot(tmp_path) == before and store.binding() == binding

    assert validate.main(args) == 0
    result = json.loads(capsys.readouterr().out)
    sync = result["validation_sync"]
    assert result["status"] == "updated" and result["report_mode"] == "deferred"
    assert result["report_path"] is None and result["report_ready"] is False
    assert sync["assessment"]["verdict"] == "confirmed"
    assert sync["delivery"]["status"] == "eligible"
    finding = store.finding(finding_id)
    assert finding["assessment"]["id"] == sync["assessment"]["id"]
    assert finding["deliveries"][0]["id"] == sync["delivery"]["id"]
    assert finding["reports"] == [] and not original_report.exists()
    summary_path = Path(result["summary_path"])
    assert summary_path.parent == findings_dir
    summary = json.loads(summary_path.read_text())
    assert summary["report_draft"] == {"status": "not_written", "path": None, "placeholder_count": 0, "placeholders": []}
    assert summary["all_gates_passed"] is False and summary["report_ready"] is False
    assert summary["machine_decision"]["report_mode"] == "deferred"
    notes = Path(result["submission_notes_path"])
    assert notes.parent == findings_dir and "未写正文" in notes.read_text() and "None" not in notes.read_text()
    binding = store.binding()
    assert validate.main(args[:-1]) == 0
    text = capsys.readouterr().out
    assert all(value in text for value in ("未写正文", sync["assessment"]["id"], sync["delivery"]["id"], str(summary_path)))
    assert store.binding() == binding and store.finding(finding_id) == finding

    total, entries = report_generator.process_findings_dir(findings_dir)
    assert total == 0 and entries == []
    index_path = tmp_path / "reports" / target / "INDEX.json"
    index = json.loads(index_path.read_text())
    assert index["pending_drafts"][0]["assessment_id"] == sync["assessment"]["id"]
    operation_id = finding["assessment"]["evidence"][0]["operation_id"]
    body = (f"# Authored report\r\n\r\nSeverity: high\r\nOperation: {operation_id}:0\r\n"
            f"Assessment: {sync['assessment']['id']}\r\nDelivery: {sync['delivery']['id']}\r\n").encode()
    draft = tmp_path / "reports" / target / "drafts" / "authored.md"
    draft.parent.mkdir()
    draft.write_bytes(body)
    total, entries = report_generator.process_findings_dir(
        findings_dir, finding_id=finding_id, assessment_id=sync["assessment"]["id"],
        delivery_id=sync["delivery"]["id"], body_file=draft,
    )
    assert total == 1 and entries[0]["severity"] == "high"
    published = Path(entries[0]["file"])
    assert published.read_bytes() == body
    assert entries[0]["artifact_sha256"] == hashlib.sha256(body).hexdigest()
    index_bytes, body_stat = index_path.read_bytes(), published.stat()
    binding, finding = store.binding(), store.finding(finding_id)
    assert validate.main(args) == 0
    replay = json.loads(capsys.readouterr().out)
    assert replay["validation_sync"]["status"] == "deduplicated"
    assert replay["report_path"] is None and replay["report_ready"] is False
    assert store.binding() == binding and store.finding(finding_id) == finding
    assert published.read_bytes() == body and published.stat().st_mtime_ns == body_stat.st_mtime_ns
    assert index_path.read_bytes() == index_bytes
    first_summary = summary_path.read_bytes()
    _, other_id, _, other_path = _seed_machine_preflight(tmp_path, finding_id="other-claim")
    other = json.loads(other_path.read_text())
    other["report"] = {"mode": "deferred"}
    other_path.write_text(json.dumps(other))
    assert validate.main(_decision_args(findings_dir, other_id, other_path)) == 0
    other_result = json.loads(capsys.readouterr().out)
    assert other_result["summary_path"] != str(summary_path)
    assert summary_path.read_bytes() == first_summary
    assert not (tmp_path / "unrelated checkout").exists()


@pytest.mark.parametrize("fault,value", [
    ("mode", "unknown"), ("mode", ""), ("mode", None), ("mode", []), ("mode", True),
    ("path", "draft.md"), ("path", ""), ("path", None), ("content", "body"), ("content", ""),
    ("content", None), ("extra", 1), ("report", {}), ("report", None),
    ("gates", {}), ("seven_question_gate", {}), ("impact", ""), ("endpoint", "/wrong"),
    ("method", "POST"), ("severity", "unknown"), ("severity", None), ("raw", None),
])
def test_deferred_report_decision_rejects_invalid_input_without_writes(tmp_path, capsys, fault, value):
    target, finding_id, findings_dir, decision_path = _seed_machine_preflight(tmp_path)
    decision = json.loads(decision_path.read_text())
    decision["report"] = {"mode": "deferred"}
    if fault in {"mode", "path", "content", "extra"}:
        decision["report"][fault] = value
    elif fault == "raw":
        runner = json.loads(Path(decision["evidence"]["runner_summary"]).read_text())
        (tmp_path / runner["artifact_bindings"][0]["ref"]).write_text("damaged raw")
    else:
        decision[fault] = value
    decision_path.write_text(json.dumps(decision))
    store = TargetStore(tmp_path, target)
    binding, before = store.binding(), _file_snapshot(tmp_path)
    args = _decision_args(findings_dir, finding_id, decision_path)
    assert validate.main([*args, "--preflight"]) == 2
    errors = json.loads(capsys.readouterr().out)["errors"]
    assert errors
    assert store.binding() == binding and _file_snapshot(tmp_path) == before
    assert validate.main(args) == 2
    stderr = capsys.readouterr().err
    assert any(error in stderr for error in errors)
    assert store.binding() == binding and _file_snapshot(tmp_path) == before


@pytest.mark.parametrize("gate,status,verdict,delivery", [
    (None, None, "confirmed", "eligible"), ("gate4", False, "confirmed", "ineligible"),
    *[(question, status, "confirmed", "ineligible" if status == "fail" else "deferred")
      for question in ("q5_not_known_behavior", "q7_not_never_submit")
      for status in ("fail", "unknown", "partial", "chain_required")],
    ("gate3", False, "inconclusive", "deferred"),
    ("q6_impact_beyond_possible", "fail", "inconclusive", "deferred"),
    ("q6_impact_beyond_possible", "unknown", "inconclusive", "deferred"),
])
def test_deferred_report_decision_keeps_judgments_separate(tmp_path, capsys, gate, status, verdict, delivery):
    target, finding_id, findings_dir, decision_path = _seed_machine_preflight(tmp_path)
    decision = json.loads(decision_path.read_text())
    decision["report"] = {"mode": "deferred"}
    decision.pop("severity")
    if gate and gate.startswith("gate"):
        decision["gates"][gate]["passed"] = status
    elif gate:
        decision["seven_question_gate"]["questions"][gate]["status"] = status
    decision_path.write_text(json.dumps(decision))
    assert validate.main(_decision_args(findings_dir, finding_id, decision_path)) == 0
    result = json.loads(capsys.readouterr().out)
    summary = json.loads(Path(result["summary_path"]).read_text())
    finding = TargetStore(tmp_path, target).finding(finding_id)
    assert finding["assessment"]["verdict"] == verdict
    assert finding["deliveries"][0]["status"] == delivery
    assert summary["severity"] == "unknown"
    assert summary["report_path"] is None and summary["report_ready"] is False
    assert summary["validation_evidence_passed"] is (verdict == "confirmed")
    assert finding["reports"] == []
    if delivery != "ineligible":
        assert summary["delivery_judgment"]["reason"] == (
            "validation gates passed; report publication deferred" if delivery == "eligible"
            else "validation/destination gate incomplete"
        )


def test_deferred_report_decision_retries_partial_sync(tmp_path, capsys, monkeypatch):
    target, finding_id, findings_dir, decision_path = _seed_machine_preflight(tmp_path)
    decision = json.loads(decision_path.read_text())
    decision["report"] = {"mode": "deferred"}
    decision_path.write_text(json.dumps(decision))
    store = TargetStore(tmp_path, target)
    binding = store.binding()
    args = _decision_args(findings_dir, finding_id, decision_path)
    with monkeypatch.context() as failure:
        def reject_delivery(*args, **kwargs):
            raise StoreError("fixture delivery interrupted")
        failure.setattr(TargetStore, "decide_delivery", reject_delivery)
        assert validate.main(args) == 2
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "retry" and result["retry"] is True
    assert result["report_mode"] == "deferred" and result["report_path"] is None
    assert result["validation_sync"]["status"] == "error"
    assert "assessment" not in result["validation_sync"] and "delivery" not in result["validation_sync"]
    assert Path(result["summary_path"]).is_file()
    partial = store.finding(finding_id)
    assert partial["assessment"]["verdict"] == "confirmed"
    assert partial["deliveries"] == [] and partial["reports"] == []
    assert store.binding()["revision"] == binding["revision"] + 1
    assert not (tmp_path / "state" / target / "session.json").exists()
    changed = dict(decision, impact="Changed judgment with stale predecessors")
    decision_path.write_text(json.dumps(changed))
    before = _file_snapshot(tmp_path)
    assert validate.main([*args, "--preflight"]) == 2
    assert "assessment changed" in " ".join(json.loads(capsys.readouterr().out)["errors"])
    assert validate.main(args) == 2
    capsys.readouterr()
    assert _file_snapshot(tmp_path) == before
    decision_path.write_text(json.dumps(decision))
    assert validate.main(args) == 0
    recovered = json.loads(capsys.readouterr().out)
    assert recovered["validation_sync"]["assessment"]["id"] == partial["assessment"]["id"]
    assert recovered["validation_sync"]["delivery"]["status"] == "eligible"
    assert store.binding()["revision"] == binding["revision"] + 2
    assert store.finding(finding_id)["reports"] == []
