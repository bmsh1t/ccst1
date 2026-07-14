"""Regression tests for validate.py target-driven advisory behavior."""

import json
from pathlib import Path

import pytest

import validate
from runtime_state import load_runtime_state


def test_validate_prompt_helpers_fail_closed_on_eof(monkeypatch):
    def raise_eof(_prompt):
        raise EOFError

    monkeypatch.setattr("builtins.input", raise_eof)

    with pytest.raises(validate.ValidationInputUnavailable):
        validate.ask("Target", "target.local")
    with pytest.raises(validate.ValidationInputUnavailable):
        validate.ask_yn("Continue?", default=False)
    with pytest.raises(validate.ValidationInputUnavailable):
        validate.ask_choice("Attack Vector", [("N", "Network"), ("A", "Adjacent")])


def _machine_decision(*, target: str, finding_id: str, endpoint: str, report_path: str, evidence_ref: str) -> dict:
    questions = {
        key: {"status": "pass", "basis": f"Replay evidence supports {key}."}
        for key, _ in validate.SEVEN_QUESTION_DEFINITIONS
    }
    return {
        "schema_version": validate.MACHINE_DECISION_SCHEMA_VERSION,
        "target": target,
        "finding_id": finding_id,
        "endpoint": endpoint,
        "vuln_class": "sqli",
        "method": "GET",
        "impact": "A controlled differential response exposes records outside the baseline result.",
        "gates": {
            key: {"passed": True, "notes": {"source": "raw-replay"}}
            for key in validate.MACHINE_DECISION_GATE_KEYS
        },
        "seven_question_gate": {"questions": questions},
        "cvss": {
            "score": 8.8,
            "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N",
            "params": {"AV": "N", "AC": "L", "PR": "N", "VC": "H"},
        },
        "evidence": {
            "summary": "Baseline and controlled variant response pair are stored at the linked artifact.",
            "refs": [evidence_ref],
        },
        "report": {
            "path": report_path,
            "content": "# SQL injection evidence\n\nThe linked raw replay proves the differential impact.\n",
        },
    }


def test_non_tty_validate_without_decision_fails_closed_before_state_write(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(validate, "BASE_DIR", tmp_path, raising=False)
    monkeypatch.setattr(validate.sys.stdin, "isatty", lambda: False)

    exit_code = validate.main([])

    assert exit_code == 2
    assert "non-TTY validation requires --decision-json" in capsys.readouterr().err
    assert not (tmp_path / "findings").exists()
    assert not (tmp_path / "state").exists()


def test_non_tty_machine_decision_binds_canonical_finding_and_uses_owner(tmp_path, monkeypatch, capsys):
    from finding_index import find_finding, upsert_finding, verify_finding_owner_provenance

    target = "target.com"
    findings_dir = tmp_path / "findings" / target
    evidence_ref = tmp_path / "evidence" / target / "validation" / "raw-pair.json"
    evidence_ref.parent.mkdir(parents=True)
    evidence_ref.write_text('{"baseline":"one","variant":"many"}\n', encoding="utf-8")
    created = upsert_finding(
        findings_dir,
        {
            "id": "sqli_machine",
            "type": "sqli",
            "url": "https://target.com/rest/products/search?q=test",
            "summary": "Candidate response difference.",
            "source_file": str(evidence_ref),
            "validation_status": "candidate",
            "report_status": "not_generated",
        },
        target=target,
    )
    assert created["finding"]["validation_status"] == "candidate"

    report_relative = "findings/target.com/validated/machine-report.md"
    decision = _machine_decision(
        target=target,
        finding_id="sqli_machine",
        endpoint="/rest/products/search?q=test",
        report_path=report_relative,
        evidence_ref=str(evidence_ref),
    )
    decision_path = tmp_path / "machine-decision.json"
    decision_path.write_text(json.dumps(decision), encoding="utf-8")
    monkeypatch.setattr(validate, "BASE_DIR", tmp_path, raising=False)
    monkeypatch.setattr(validate.sys.stdin, "isatty", lambda: False)

    exit_code = validate.main(
        [
            "--target",
            target,
            "--finding-id",
            "sqli_machine",
            "--decision-json",
            str(decision_path),
            "--json",
        ]
    )
    output = json.loads(capsys.readouterr().out)
    persisted = find_finding(findings_dir, "sqli_machine")
    summary_path = Path(output["summary_path"])

    assert exit_code == 0
    assert output["finding_id"] == "sqli_machine"
    assert persisted is not None
    assert persisted["validation_status"] == "validated"
    assert verify_finding_owner_provenance(findings_dir, persisted, target=target)["valid"] is True
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert summary["machine_decision"]["schema_version"] == 1
    assert summary["machine_decision"]["evidence_refs"] == [str(evidence_ref)]


def test_machine_decision_binding_error_has_no_new_validation_write(tmp_path, monkeypatch, capsys):
    from finding_index import upsert_finding

    target = "target.com"
    findings_dir = tmp_path / "findings" / target
    evidence_ref = tmp_path / "evidence" / target / "validation" / "raw-pair.json"
    evidence_ref.parent.mkdir(parents=True)
    evidence_ref.write_text("raw\n", encoding="utf-8")
    upsert_finding(
        findings_dir,
        {
            "id": "sqli_machine",
            "type": "sqli",
            "url": "https://target.com/rest/products/search?q=test",
            "source_file": str(evidence_ref),
            "validation_status": "candidate",
        },
        target=target,
    )
    decision = _machine_decision(
        target=target,
        finding_id="sqli_machine",
        endpoint="/wrong-path",
        report_path="findings/target.com/validated/should-not-exist.md",
        evidence_ref=str(evidence_ref),
    )
    decision_path = tmp_path / "bad-machine-decision.json"
    decision_path.write_text(json.dumps(decision), encoding="utf-8")
    monkeypatch.setattr(validate, "BASE_DIR", tmp_path, raising=False)
    monkeypatch.setattr(validate.sys.stdin, "isatty", lambda: False)

    exit_code = validate.main(
        [
            "--target", target,
            "--finding-id", "sqli_machine",
            "--decision-json", str(decision_path),
        ]
    )

    assert exit_code == 2
    assert "decision.endpoint does not match" in capsys.readouterr().err
    assert not (tmp_path / "findings" / target / "validated").exists()
    assert not (tmp_path / "findings" / "last-validate.json").exists()


def test_machine_decision_binding_error_does_not_migrate_legacy_finding_list(
    tmp_path,
    monkeypatch,
    capsys,
):
    target = "target.com"
    findings_dir = tmp_path / "findings" / target
    findings_dir.mkdir(parents=True)
    findings_path = findings_dir / "findings.json"
    findings_path.write_text(
        json.dumps(
            [
                {
                    "id": "legacy-sqli",
                    "type": "sqli",
                    "url": "https://target.com/item?id=1",
                    "validation_status": "validated",
                    "report_status": "generated",
                }
            ]
        ),
        encoding="utf-8",
    )
    original = findings_path.read_bytes()
    evidence_ref = tmp_path / "evidence" / target / "raw.txt"
    evidence_ref.parent.mkdir(parents=True)
    evidence_ref.write_text("raw\n", encoding="utf-8")
    decision = _machine_decision(
        target=target,
        finding_id="legacy-sqli",
        endpoint="/wrong-path",
        report_path="findings/target.com/validated/should-not-exist.md",
        evidence_ref=str(evidence_ref),
    )
    decision_path = tmp_path / "bad-legacy-decision.json"
    decision_path.write_text(json.dumps(decision), encoding="utf-8")
    monkeypatch.setattr(validate, "BASE_DIR", tmp_path, raising=False)
    monkeypatch.setattr(validate.sys.stdin, "isatty", lambda: False)

    exit_code = validate.main(
        [
            "--target",
            target,
            "--finding-id",
            "legacy-sqli",
            "--decision-json",
            str(decision_path),
        ]
    )

    assert exit_code == 2
    assert "decision.endpoint does not match" in capsys.readouterr().err
    assert findings_path.read_bytes() == original
    assert not (findings_dir / "mutation-events.jsonl").exists()
    assert not (findings_dir / "validated").exists()
    assert not (tmp_path / "findings" / "last-validate.json").exists()


def test_valid_machine_decision_revalidates_quarantined_legacy_finality(
    tmp_path,
    monkeypatch,
    capsys,
):
    from finding_index import find_finding, verify_finding_owner_provenance

    target = "target.com"
    findings_dir = tmp_path / "findings" / target
    findings_dir.mkdir(parents=True)
    (findings_dir / "findings.json").write_text(
        json.dumps(
            [
                {
                    "id": "legacy-sqli",
                    "type": "sqli",
                    "url": "https://target.com/item?id=1",
                    "validation_status": "validated",
                    "report_status": "generated",
                }
            ]
        ),
        encoding="utf-8",
    )
    evidence_ref = tmp_path / "evidence" / target / "raw.txt"
    evidence_ref.parent.mkdir(parents=True)
    evidence_ref.write_text("raw\n", encoding="utf-8")
    decision = _machine_decision(
        target=target,
        finding_id="legacy-sqli",
        endpoint="/item?id=1",
        report_path="findings/target.com/validated/legacy-sqli.md",
        evidence_ref=str(evidence_ref),
    )
    decision_path = tmp_path / "valid-legacy-decision.json"
    decision_path.write_text(json.dumps(decision), encoding="utf-8")
    monkeypatch.setattr(validate, "BASE_DIR", tmp_path, raising=False)
    monkeypatch.setattr(validate.sys.stdin, "isatty", lambda: False)

    assert validate.main(
        [
            "--target",
            target,
            "--finding-id",
            "legacy-sqli",
            "--decision-json",
            str(decision_path),
            "--json",
        ]
    ) == 0
    capsys.readouterr()
    finding = find_finding(findings_dir, "legacy-sqli")

    assert finding is not None
    assert finding["validation_status"] == "validated"
    assert finding["report_status"] == "not_generated"
    assert verify_finding_owner_provenance(findings_dir, finding, target=target)["valid"] is True


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


def test_machine_validation_isolates_artifacts_and_binds_summary_content(
    tmp_path,
    monkeypatch,
    capsys,
):
    from finding_index import find_finding, upsert_finding, verify_finding_owner_provenance

    target = "target.com"
    findings_dir = tmp_path / "findings" / target
    evidence_ref = tmp_path / "evidence" / target / "raw-pair.json"
    evidence_ref.parent.mkdir(parents=True)
    evidence_ref.write_text('{"baseline":"one","variant":"many"}\n', encoding="utf-8")
    monkeypatch.setattr(validate, "BASE_DIR", tmp_path, raising=False)
    monkeypatch.setattr(validate.sys.stdin, "isatty", lambda: False)

    outputs = []
    for finding_id, endpoint, report_name in (
        ("sqli-one", "/item?id=1", "one.md"),
        ("sqli-two", "/item?id=2", "two.md"),
    ):
        upsert_finding(
            findings_dir,
            {
                "id": finding_id,
                "type": "sqli",
                "url": f"https://target.com{endpoint}",
                "validation_status": "candidate",
            },
            target=target,
        )
        decision = _machine_decision(
            target=target,
            finding_id=finding_id,
            endpoint=endpoint,
            report_path=f"findings/{target}/validated/{report_name}",
            evidence_ref=str(evidence_ref),
        )
        decision_path = tmp_path / f"{finding_id}.decision.json"
        decision_path.write_text(json.dumps(decision), encoding="utf-8")

        assert validate.main(
            [
                "--target",
                target,
                "--finding-id",
                finding_id,
                "--decision-json",
                str(decision_path),
                "--json",
            ]
        ) == 0
        outputs.append(json.loads(capsys.readouterr().out))

    summary_paths = [Path(item["summary_path"]) for item in outputs]
    notes_paths = [Path(item["submission_notes_path"]) for item in outputs]
    assert summary_paths[0] != summary_paths[1]
    assert notes_paths[0] != notes_paths[1]
    assert [json.loads(path.read_text(encoding="utf-8"))["finding_id"] for path in summary_paths] == [
        "sqli-one",
        "sqli-two",
    ]

    first = find_finding(findings_dir, "sqli-one")
    second = find_finding(findings_dir, "sqli-two")
    assert first is not None and second is not None
    assert first["validation_summary"] == str(summary_paths[0])
    assert second["validation_summary"] == str(summary_paths[1])
    assert first["validation_summary_sha256"]
    assert second["validation_summary_sha256"]
    assert verify_finding_owner_provenance(findings_dir, first, target=target)["valid"] is True

    summary_paths[0].write_text('{"finding_id":"sqli-two"}\n', encoding="utf-8")
    invalid = verify_finding_owner_provenance(findings_dir, first, target=target)
    assert invalid["valid"] is False
    assert invalid["reason"] == "validation-summary-content-mismatch"


def test_machine_validation_rejects_report_path_owned_by_another_finding(
    tmp_path,
    monkeypatch,
    capsys,
):
    from finding_index import upsert_finding

    target = "target.com"
    findings_dir = tmp_path / "findings" / target
    evidence_ref = tmp_path / "evidence" / target / "raw.txt"
    evidence_ref.parent.mkdir(parents=True)
    evidence_ref.write_text("raw\n", encoding="utf-8")
    monkeypatch.setattr(validate, "BASE_DIR", tmp_path, raising=False)
    monkeypatch.setattr(validate.sys.stdin, "isatty", lambda: False)
    shared_report = f"findings/{target}/validated/shared.md"

    for finding_id, endpoint in (("sqli-one", "/item?id=1"), ("sqli-two", "/item?id=2")):
        upsert_finding(
            findings_dir,
            {
                "id": finding_id,
                "type": "sqli",
                "url": f"https://target.com{endpoint}",
                "validation_status": "candidate",
            },
            target=target,
        )

    first_decision = _machine_decision(
        target=target,
        finding_id="sqli-one",
        endpoint="/item?id=1",
        report_path=shared_report,
        evidence_ref=str(evidence_ref),
    )
    first_path = tmp_path / "first.json"
    first_path.write_text(json.dumps(first_decision), encoding="utf-8")
    assert validate.main(
        ["--target", target, "--finding-id", "sqli-one", "--decision-json", str(first_path), "--json"]
    ) == 0
    capsys.readouterr()
    report_path = tmp_path / shared_report
    original_report = report_path.read_bytes()

    second_decision = _machine_decision(
        target=target,
        finding_id="sqli-two",
        endpoint="/item?id=2",
        report_path=shared_report,
        evidence_ref=str(evidence_ref),
    )
    second_decision["report"]["content"] = "# Different finding\n"
    second_path = tmp_path / "second.json"
    second_path.write_text(json.dumps(second_decision), encoding="utf-8")

    assert validate.main(
        ["--target", target, "--finding-id", "sqli-two", "--decision-json", str(second_path)]
    ) == 2
    assert "report path is already owned by another finding" in capsys.readouterr().err
    assert report_path.read_bytes() == original_report
    second_summary, second_notes = validate.validation_artifact_paths(
        {"finding_id": "sqli-two"},
        report_path,
    )
    assert not second_summary.exists()
    assert not second_notes.exists()
    second_row = validate.load_finding_prefill(str(findings_dir), "sqli-two")
    assert second_row["validation_report_path"] == ""
    assert json.loads(
        (tmp_path / "findings" / "last-validate.json").read_text(encoding="utf-8")
    )["finding_id"] == "sqli-one"


def test_machine_validation_allows_same_finding_report_rerun(
    tmp_path,
    monkeypatch,
    capsys,
):
    from finding_index import find_finding, upsert_finding, verify_finding_owner_provenance

    target = "target.com"
    finding_id = "sqli-rerun"
    findings_dir = tmp_path / "findings" / target
    evidence_ref = tmp_path / "evidence" / target / "raw.txt"
    evidence_ref.parent.mkdir(parents=True)
    evidence_ref.write_text("raw\n", encoding="utf-8")
    upsert_finding(
        findings_dir,
        {
            "id": finding_id,
            "type": "sqli",
            "url": "https://target.com/item?id=1",
            "validation_status": "candidate",
        },
        target=target,
    )
    monkeypatch.setattr(validate, "BASE_DIR", tmp_path, raising=False)
    monkeypatch.setattr(validate.sys.stdin, "isatty", lambda: False)
    report_rel = f"findings/{target}/validated/rerun.md"

    outputs = []
    for run_number in (1, 2):
        decision = _machine_decision(
            target=target,
            finding_id=finding_id,
            endpoint="/item?id=1",
            report_path=report_rel,
            evidence_ref=str(evidence_ref),
        )
        decision["report"]["content"] = f"# Finding rerun {run_number}\n"
        decision_path = tmp_path / f"decision-{run_number}.json"
        decision_path.write_text(json.dumps(decision), encoding="utf-8")

        assert validate.main(
            [
                "--target",
                target,
                "--finding-id",
                finding_id,
                "--decision-json",
                str(decision_path),
                "--json",
            ]
        ) == 0
        outputs.append(json.loads(capsys.readouterr().out))

    assert outputs[0]["summary_path"] == outputs[1]["summary_path"]
    assert (tmp_path / report_rel).read_text(encoding="utf-8") == "# Finding rerun 2\n"
    finding = find_finding(findings_dir, finding_id)
    assert finding is not None
    assert finding["validation_status"] == "validated"
    assert verify_finding_owner_provenance(findings_dir, finding, target=target)["valid"] is True


def test_machine_validation_recovers_byte_identical_unowned_report_after_crash(
    tmp_path,
    monkeypatch,
    capsys,
):
    from finding_index import find_finding, upsert_finding

    target = "target.com"
    finding_id = "sqli-crash-replay"
    findings_dir = tmp_path / "findings" / target
    evidence_ref = tmp_path / "evidence" / target / "raw.txt"
    evidence_ref.parent.mkdir(parents=True)
    evidence_ref.write_text("raw\n", encoding="utf-8")
    upsert_finding(
        findings_dir,
        {
            "id": finding_id,
            "type": "sqli",
            "url": "https://target.com/item?id=1",
            "validation_status": "candidate",
        },
        target=target,
    )
    monkeypatch.setattr(validate, "BASE_DIR", tmp_path, raising=False)
    monkeypatch.setattr(validate.sys.stdin, "isatty", lambda: False)
    report_rel = f"findings/{target}/validated/crash-replay.md"
    decision = _machine_decision(
        target=target,
        finding_id=finding_id,
        endpoint="/item?id=1",
        report_path=report_rel,
        evidence_ref=str(evidence_ref),
    )
    report_path = tmp_path / report_rel
    report_path.parent.mkdir(parents=True)
    report_path.write_text(decision["report"]["content"].rstrip() + "\n", encoding="utf-8")
    decision_path = tmp_path / "crash-replay.json"
    decision_path.write_text(json.dumps(decision), encoding="utf-8")

    assert validate.main(
        [
            "--target",
            target,
            "--finding-id",
            finding_id,
            "--decision-json",
            str(decision_path),
            "--json",
        ]
    ) == 0
    output = json.loads(capsys.readouterr().out)
    finding = find_finding(findings_dir, finding_id)

    assert Path(output["summary_path"]).is_file()
    assert finding is not None
    assert finding["validation_report_path"] == str(report_path)


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


def test_validation_evidence_passed_keeps_durable_finding_and_queue_validated(tmp_path):
    from action_queue import add_manual_action, load_queue
    from evidence_ledger import load_entries

    report_path = tmp_path / "findings" / "target.com-sqli" / "hackerone-report.md"
    report_path.parent.mkdir(parents=True)
    report_path.write_text("# Draft\n[INSERT raw request]\n", encoding="utf-8")
    add_manual_action(
        tmp_path,
        target="target.com",
        action_type="candidate-evidence-gap",
        evidence="Candidate SQLi response difference on /rest/products/search.",
        next_question="Does the response difference reproduce?",
        action="Run /validate for /rest/products/search.",
        command_hint="/validate sqli-search",
        evidence_type="candidate-validation",
    )
    summary = {
        "target": "target.com",
        "endpoint": "https://target.com/rest/products/search?q=test",
        "vuln_class": "sqli",
        "result": "confirmed",
        "validation_evidence_passed": True,
        "four_validation_gates_passed": True,
        "seven_question_gate_passed": True,
        "seven_question_gate_decision": "pass",
        "all_gates_passed": False,
        "report_ready": False,
        "report_path": str(report_path),
        "report_draft": {"status": "incomplete", "placeholder_count": 1},
    }
    summary_path = report_path.parent / "validation-summary.json"
    summary_path.write_text(json.dumps(summary), encoding="utf-8")

    sync = validate.sync_validation_artifacts(summary, repo_root=tmp_path)
    entries = load_entries(tmp_path, "target.com")
    queue = load_queue(tmp_path, "target.com")
    finding_payload = json.loads(
        (tmp_path / "findings" / "target.com" / "findings.json").read_text(encoding="utf-8")
    )

    assert sync["ledger"]["result"] == "tested_finding"
    assert entries[-1]["result"] == "tested_finding"
    assert queue["actions"][0]["status"] == "validated"
    assert finding_payload["findings"][0]["validation_status"] == "validated"


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
    assert entries[-1]["method"] == "GET"
    assert entries[-1]["result"] == "tested_finding"
    assert entries[-1]["evidence_ref"].endswith("validation-summary.json")
    assert action["status"] == "validated"
    assert "validation-summary=" in action["result"]
    assert "submission-notes=" in action["notes"]


def test_sync_validation_artifacts_uses_summary_method(tmp_path):
    from evidence_ledger import load_entries
    from resume import load_structured_finding_followup

    report_path = tmp_path / "findings" / "target.com-ssrf" / "hackerone-report.md"
    summary = {
        "target": "target.com",
        "endpoint": "https://target.com/profile/image/url",
        "method": "POST",
        "vuln_class": "ssrf",
        "result": "confirmed",
        "all_gates_passed": True,
        "report_path": str(report_path),
        "validated_at": "2026-07-06T10:03:11Z",
        "severity": "medium",
        "impact": "server-side URL fetch with callback proof",
        "seven_question_gate_passed": True,
        "four_validation_gates_passed": True,
        "seven_question_gate_decision": "pass",
    }
    report_path.parent.mkdir(parents=True)
    (report_path.parent / "validation-summary.json").write_text(
        json.dumps(summary),
        encoding="utf-8",
    )
    summary["validation_summary_path"] = str(report_path.parent / "validation-summary.json")

    sync = validate.sync_validation_artifacts(summary, repo_root=tmp_path)

    entries = load_entries(tmp_path, "target.com")
    assert entries[-1]["method"] == "POST"
    assert entries[-1]["endpoint"] == "/profile/image/url"
    assert entries[-1]["raw_endpoint"] == "https://target.com/profile/image/url"
    assert sync["finding_index"]["status"] == "updated"

    followup = load_structured_finding_followup(tmp_path, "target.com")
    assert followup["validated_pending_report"] == 1
    assert followup["next_report"]["type"] == "ssrf"
    assert followup["next_report"]["url"] == "https://target.com/profile/image/url"
    assert followup["next_report"]["rubric"]["ready"] is True
    assert followup["next_report"]["missing_evidence"] == []


def test_sync_validation_artifacts_infers_missing_method_from_prior_ledger_candidate(tmp_path):
    from evidence_ledger import load_entries, record_entry

    report_path = tmp_path / "findings" / "target.com-ssrf" / "hackerone-report.md"
    report_path.parent.mkdir(parents=True)
    record_entry(
        tmp_path,
        target="target.com",
        endpoint="https://target.com/profile/image/url",
        method="POST",
        vuln_class="SSRF",
        workflow="complex-lane-pressure",
        actor="owner",
        object_scope="own_object",
        variant="replay",
        source="ai-pressure-test",
        result="candidate",
        replayed=True,
        state_changing=True,
        redline_checked=True,
        evidence_ref="evidence/target/ssrf-summary.json",
    )
    summary = {
        "target": "target.com",
        "endpoint": "https://target.com/profile/image/url",
        "vuln_class": "ssrf",
        "result": "confirmed",
        "all_gates_passed": True,
        "report_path": str(report_path),
    }

    sync = validate.sync_validation_artifacts(summary, repo_root=tmp_path)

    entries = load_entries(tmp_path, "target.com")
    assert sync["ledger"]["status"] == "updated"
    assert entries[-1]["source"] == "validate"
    assert entries[-1]["method"] == "POST"

    payload = json.loads((tmp_path / "findings" / "target.com" / "findings.json").read_text(encoding="utf-8"))
    created = payload["findings"][0]
    assert created["method"] == "POST"


def test_sync_validation_artifacts_linked_finding_does_not_create_duplicate(tmp_path):
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
    report_path = tmp_path / "findings" / "target.com-sqli" / "hackerone-report.md"
    summary = {
        "target": "target.com",
        "endpoint": "https://target.com/item?id=1",
        "vuln_class": "sqli",
        "result": "confirmed",
        "all_gates_passed": True,
        "finding_id": "sqli_deadbeef",
        "report_path": str(report_path),
    }

    sync = validate.sync_validation_artifacts(summary, repo_root=tmp_path)

    payload = json.loads((findings_dir / "findings.json").read_text(encoding="utf-8"))
    assert sync["finding_index"]["status"] == "skipped"
    assert len(payload["findings"]) == 1


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
    # This fixture represents a completed validation, so use the canonical
    # owner to issue the final lifecycle mutation and its provenance event.
    from finding_index import update_finding_status

    updated = update_finding_status(
        findings_dir,
        "sqli_deadbeef",
        validation_status="validated",
        report_status="not_generated",
    )
    assert updated is not None
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
