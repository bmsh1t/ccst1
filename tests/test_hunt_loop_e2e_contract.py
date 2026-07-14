"""End-to-end artifact contract test for the Claude Code hunt loop.

This test intentionally avoids real network calls and external scanners. It
checks that each local artifact produced by one phase can be consumed by the
next phase in the CLI workflow.
"""

import json
from pathlib import Path

import finding_index
import remember
import report_generator
import validate
from memory.target_profile import load_target_profile
from surface import format_surface_output, load_surface_context, rank_surface


def test_recon_surface_findings_validate_remember_report_contract(monkeypatch, tmp_path):
    target = "target.com"
    repo_root = tmp_path

    # Recon phase: nested recon layout produced by recon_engine.sh.
    recon_dir = repo_root / "recon" / target
    (recon_dir / "live").mkdir(parents=True)
    (recon_dir / "urls").mkdir(parents=True)
    (recon_dir / "js").mkdir(parents=True)
    (recon_dir / "live" / "urls.txt").write_text("https://api.target.com\n", encoding="utf-8")
    (recon_dir / "live" / "httpx_full.txt").write_text(
        "https://api.target.com [200] [API] [Next.js,GraphQL,Postgres] [1200]\n",
        encoding="utf-8",
    )
    (recon_dir / "urls" / "api_endpoints.txt").write_text(
        "https://api.target.com/graphql\nhttps://api.target.com/api/v2/orders/42\n",
        encoding="utf-8",
    )
    (recon_dir / "urls" / "with_params.txt").write_text(
        "https://api.target.com/api/v2/orders?id=42\n",
        encoding="utf-8",
    )
    (recon_dir / "urls" / "all.txt").write_text(
        "https://api.target.com/graphql\nhttps://api.target.com/api/v2/orders?id=42\n",
        encoding="utf-8",
    )
    (recon_dir / "js" / "endpoints.txt").write_text("/api/v2/export\n", encoding="utf-8")

    # Surface phase: cached recon can be ranked without running recon again.
    memory_dir = repo_root / "hunt-memory"
    (memory_dir / "targets").mkdir(parents=True)
    ranked = rank_surface(load_surface_context(repo_root, target, memory_dir=memory_dir))
    surface_text = format_surface_output(ranked, target)

    assert ranked["available"] is True
    assert ranked["p1"]
    assert "https://api.target.com/graphql" in surface_text

    # Scanner/finding phase: representative scanner artifact becomes findings.json.
    findings_dir = repo_root / "findings" / target
    (findings_dir / "sqli").mkdir(parents=True)
    (findings_dir / "sqli" / "timebased_candidates.txt").write_text(
        "[SQLI-POC-VERIFIED] dialect=postgres param=1 url=https://api.target.com/api/v2/orders?id=42\n",
        encoding="utf-8",
    )
    finding_payload = finding_index.write_finding_index(findings_dir, target=target)
    finding = finding_payload["findings"][0]

    assert finding_payload["total"] == 1
    assert finding["type"] == "sqli"
    assert finding["confidence"] == "confirmed"
    assert finding["validation_status"] == "unvalidated"

    # Validate phase: finding id can prefill validation context and write summary artifacts.
    prefill = validate.load_finding_prefill(str(findings_dir), finding["id"])
    assert prefill["target"] == target
    assert prefill["vuln_type"] == "SQLI"
    assert prefill["endpoint"] == "https://api.target.com/api/v2/orders?id=42"

    monkeypatch.setattr(validate, "BASE_DIR", repo_root)
    validation_report_path = findings_dir / "validated" / "hackerone-report.md"
    validation_info = {
        "target": prefill["target"],
        "vuln_type": prefill["vuln_type"],
        "endpoint": prefill["endpoint"],
        "impact": "Confirmed time-based SQL injection on the orders endpoint.",
        "cvss_score": 8.8,
        "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N",
        "gate1_pass": True,
        "gate2_pass": True,
        "gate3_pass": True,
        "gate4_pass": True,
        "finding_id": prefill["finding_id"],
        "finding_source_file": prefill["source_file"],
        "finding_summary": prefill["summary"],
    }
    validation_summary = validate.build_validation_summary(
        validation_info,
        all_pass=True,
        report_path=validation_report_path,
    )
    summary_path = validate.write_validation_summary(validation_summary, validation_report_path)
    validate.mark_finding_validated(
        str(findings_dir),
        prefill["finding_id"],
        validation_summary,
        summary_path,
    )

    assert summary_path.is_file()
    assert (repo_root / "findings" / "last-validate.json").is_file()
    saved_validation_summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert saved_validation_summary["finding_id"] == finding["id"]
    assert saved_validation_summary["finding_source_file"] == "sqli/timebased_candidates.txt"
    finding_payload_after_validate = finding_index.load_finding_index(findings_dir)
    assert finding_payload_after_validate["findings"][0]["validation_status"] == "validated"

    # Memory bridge: validation summary can be remembered into hunt-memory.
    remember_prefill = remember.load_validate_prefill(summary_path)
    remembered = remember.remember_finding(
        memory_dir=memory_dir,
        target=remember_prefill["target"],
        vuln_class=remember_prefill["vuln_class"],
        endpoint=remember_prefill["endpoint"],
        result=remember_prefill["result"],
        severity=remember_prefill["severity"],
        technique="time_based_sqli",
        notes=remember_prefill["notes"],
        tech_stack=["graphql", "postgres"],
    )

    assert remembered["finding_saved"] is True
    profile = load_target_profile(memory_dir, "api.target.com")
    assert profile is not None
    assert "/api/v2/orders?id=42" in profile["tested_endpoints"]
    assert profile["findings"][0]["vuln_class"] == "sqli"

    # A generated validation skeleton with unresolved placeholders is a working
    # draft, not a report-ready finding.  The report generator must not turn it
    # into a final report merely because replay evidence already passed.
    monkeypatch.setattr(report_generator, "REPORTS_DIR", str(repo_root / "reports"))
    total_reports, report_index = report_generator.process_findings_dir(str(findings_dir))

    assert saved_validation_summary["validation_evidence_passed"] is True
    assert saved_validation_summary["all_gates_passed"] is False
    assert total_reports == 0
    assert report_index == []

    # Completing the draft changes only report readiness; the validated finding
    # and its raw evidence remain the same.  A later report generation can then
    # consume the structured finding normally.
    validation_report_path.write_text(
        "# SQL Injection on /api/v2/orders\n\n"
        "The exact request and response diff are attached as validation evidence.\n",
        encoding="utf-8",
    )
    completed_summary = validate.build_validation_summary(
        validation_info,
        all_pass=True,
        report_path=validation_report_path,
    )
    completed_summary_path = validate.write_validation_summary(completed_summary, validation_report_path)
    validate.mark_finding_validated(
        str(findings_dir),
        prefill["finding_id"],
        completed_summary,
        completed_summary_path,
    )
    total_reports, report_index = report_generator.process_findings_dir(str(findings_dir))

    assert total_reports == 1
    assert report_index[0]["finding_id"] == finding["id"]
    report_path = Path(report_index[0]["file"])
    assert report_path.is_file()
    report_text = report_path.read_text(encoding="utf-8")
    assert "SQL Injection" in report_text
    assert f"- **Finding ID:** {finding['id']}" in report_text
    assert "- **Source artifact:** sqli/timebased_candidates.txt" in report_text

    index_path = repo_root / "reports" / target / "INDEX.json"
    assert index_path.is_file()
    report_index_payload = json.loads(index_path.read_text(encoding="utf-8"))
    assert report_index_payload["reports"][0]["finding_id"] == finding["id"]
    finding_payload_after_report = finding_index.load_finding_index(findings_dir)
    assert finding_payload_after_report["findings"][0]["report_status"] == "generated"
    assert finding_payload_after_report["findings"][0]["report_file"] == str(report_path)
