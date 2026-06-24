"""Tests for tools/resume.py."""

import json

import resume as resume_tool
from memory.hunt_journal import HuntJournal
from memory.pattern_db import PatternDB
from memory.schemas import make_journal_entry, make_pattern_entry
from memory.target_profile import make_target_profile, save_target_profile
from resume import format_resume_output, load_pickup_summary, load_resume_summary
from runtime_state import update_runtime_state


class TestResumeSummary:

    def test_loads_profile_journal_and_pattern_matches(self, tmp_hunt_dir, sample_target_profile):
        save_target_profile(tmp_hunt_dir, sample_target_profile)

        journal = HuntJournal(tmp_hunt_dir / "journal.jsonl")
        journal.append(make_journal_entry(
            target="target.com",
            action="remember",
            vuln_class="idor",
            endpoint="/api/v2/users/{id}/export",
            result="confirmed",
            severity="high",
            payout=1500,
            technique="numeric_id_swap_with_put_method",
        ))
        journal.append(make_journal_entry(
            target="target.com",
            action="remember",
            vuln_class="ssrf",
            endpoint="/api/proxy",
            result="rejected",
            severity="none",
            technique="metadata_probe",
        ))
        journal.log_session_summary(
            target="target.com",
            action="hunt",
            endpoints_tested=["/graphql", "/api/v2/users/42/export"],
            vuln_classes_tried=["recon", "idor"],
            findings_count=1,
            session_id="sess-777",
        )

        patterns = PatternDB(tmp_hunt_dir / "patterns.jsonl")
        patterns.save(make_pattern_entry(
            target="alpha.com",
            vuln_class="idor",
            technique="numeric_id_swap_with_put_method",
            tech_stack=["graphql", "postgresql"],
            payout=800,
        ))
        patterns.save(make_pattern_entry(
            target="target.com",
            vuln_class="idor",
            technique="same_target_pattern",
            tech_stack=["graphql"],
            payout=900,
        ))

        summary = load_resume_summary(tmp_hunt_dir, "target.com")
        assert summary is not None
        assert summary["sessions"] == 3
        assert summary["confirmed_findings"] == 1
        assert summary["confirmed_payout"] == 1500
        assert summary["untested_endpoints"] == ["/api/v2/users/{id}/export"]
        assert summary["matched_targets"] == 1
        assert summary["pattern_matches"][0]["target"] == "alpha.com"
        assert summary["latest_session_summary"]["session_id"] == "sess-777"
        assert summary["latest_session_summary"]["findings_count"] == 1
        assert "recon" in summary["latest_session_summary"]["vuln_classes"]
        assert "/graphql" in summary["latest_session_summary"]["endpoints_preview"]
        assert summary["recent_guard_advisories"] == []

    def test_includes_recent_guard_advisories(self, tmp_hunt_dir, sample_target_profile):
        save_target_profile(tmp_hunt_dir, sample_target_profile)

        journal = HuntJournal(tmp_hunt_dir / "journal.jsonl")
        journal.append(make_journal_entry(
            target="target.com",
            action="hunt",
            vuln_class="guard_advisory",
            endpoint="https://api.target.com/graphql",
            result="informational",
            severity="none",
            technique="request_guard",
            notes="request_guard advisory for GET https://api.target.com/graphql. Host: api.target.com. Action: breaker_advisory. Reason: circuit breaker active.",
            tags=["guard_advisory", "auto_logged", "breaker_advisory"],
        ))
        journal.append(make_journal_entry(
            target="target.com",
            action="hunt",
            vuln_class="guard_block",
            endpoint="https://legacy.target.com/graphql",
            result="informational",
            severity="none",
            technique="request_guard",
            notes="legacy request_guard block entry is still readable.",
            tags=["guard_block", "auto_logged", "block_breaker"],
        ))

        summary = load_resume_summary(tmp_hunt_dir, "target.com")

        assert summary is not None
        assert len(summary["recent_guard_advisories"]) == 2
        assert "breaker_advisory" in summary["recent_guard_advisories"][0]["notes"]
        assert "legacy request_guard block" in summary["recent_guard_advisories"][1]["notes"]

    def test_missing_profile_returns_none(self, tmp_hunt_dir):
        assert load_resume_summary(tmp_hunt_dir, "missing.com") is None

    def test_loads_host_list_profile_from_relative_target(self, tmp_hunt_dir, tmp_path, monkeypatch):
        list_file = tmp_path / "scope.txt"
        list_file.write_text("api.target.com\n", encoding="utf-8")
        monkeypatch.chdir(tmp_path)

        canonical_target = str(list_file.resolve())
        save_target_profile(
            tmp_hunt_dir,
            make_target_profile(
                canonical_target,
                tech_stack=["next.js"],
                untested_endpoints=["/graphql"],
                hunt_sessions=2,
            ),
        )

        HuntJournal(tmp_hunt_dir / "journal.jsonl").log_session_summary(
            target=canonical_target,
            action="hunt",
            endpoints_tested=["/graphql"],
            vuln_classes_tried=["recon"],
            findings_count=0,
            session_id="sess-list",
        )

        summary = load_resume_summary(tmp_hunt_dir, "scope.txt")

        assert summary is not None
        assert summary["sessions"] == 2
        assert summary["resolved_target"] == canonical_target
        assert summary["latest_session_summary"]["session_id"] == "sess-list"
        assert summary["latest_session_summary"]["endpoints_preview"] == ["/graphql"]

    def test_includes_repo_source_summary(self, tmp_hunt_dir, sample_target_profile, monkeypatch, tmp_path):
        save_target_profile(tmp_hunt_dir, sample_target_profile)

        repo_root = tmp_path
        exposure_dir = repo_root / "findings" / "target.com" / "exposure"
        exposure_dir.mkdir(parents=True)
        (exposure_dir / "repo_source_meta.json").write_text(
            '{"status":"ok","source_kind":"local_path","clone_performed":false}\n',
            encoding="utf-8",
        )
        (exposure_dir / "repo_summary.md").write_text(
            "# Repository Source Hunt Summary\n\n- Secret findings: 2\n- CI findings: 1\n",
            encoding="utf-8",
        )
        monkeypatch.setattr(resume_tool, "BASE_DIR", str(repo_root))

        summary = load_resume_summary(tmp_hunt_dir, "target.com")

        assert summary is not None
        assert summary["repo_source_summary"]["source_kind"] == "local_path"
        assert summary["repo_source_summary"]["secret_findings"] == 2
        assert summary["repo_source_summary"]["ci_findings"] == 1
        assert summary["repo_source_summary"]["summary_hint"] == "local_path, secrets=2, ci=1"

    def test_includes_structured_finding_followup(self, tmp_hunt_dir, sample_target_profile, monkeypatch, tmp_path):
        save_target_profile(tmp_hunt_dir, sample_target_profile)

        repo_root = tmp_path
        findings_dir = repo_root / "findings" / "target.com"
        findings_dir.mkdir(parents=True)
        (findings_dir / "findings.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "target": "target.com",
                    "findings": [
                        {
                            "id": "sqli_pending",
                            "type": "sqli",
                            "severity": "high",
                            "confidence": "confirmed",
                            "url": "https://api.target.com/search?q=1",
                            "validation_status": "unvalidated",
                            "report_status": "not_generated",
                        },
                        {
                            "id": "mfa_report",
                            "type": "mfa",
                            "severity": "medium",
                            "confidence": "high",
                            "url": "https://api.target.com/mfa",
                            "validation_status": "validated",
                            "report_status": "not_generated",
                        },
                    ],
                }
            ),
            encoding="utf-8",
        )
        monkeypatch.setattr(resume_tool, "BASE_DIR", str(repo_root))

        summary = load_resume_summary(tmp_hunt_dir, "target.com")
        output = format_resume_output(summary, "target.com")

        assert summary is not None
        assert summary["structured_findings"]["total"] == 2
        assert summary["structured_findings"]["pending_validation"] == 1
        assert summary["structured_findings"]["validated_pending_report"] == 1
        assert summary["structured_findings"]["next_validation"]["id"] == "sqli_pending"
        assert summary["structured_findings"]["next_report"]["id"] == "mfa_report"
        assert "Structured Findings:" in output
        assert "Next validate: sqli_pending [high/confirmed] sqli https://api.target.com/search?q=1" in output
        assert "Next report: mfa_report [medium/high] mfa https://api.target.com/mfa" in output

    def test_includes_runtime_state_and_recon_artifacts(self, tmp_hunt_dir, sample_target_profile, monkeypatch, tmp_path):
        save_target_profile(tmp_hunt_dir, sample_target_profile)
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)
        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://api.target.com [200] [API] [Next.js] [1000]\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://api.target.com/graphql\n",
            encoding="utf-8",
        )
        update_runtime_state(
            repo_root,
            "target.com",
            mode="hunt",
            last_executed_workflow="run_vuln_scan",
        )
        monkeypatch.setattr(resume_tool, "BASE_DIR", str(repo_root))

        summary = load_resume_summary(tmp_hunt_dir, "target.com")
        output = format_resume_output(summary, "target.com")

        assert summary["runtime_state"]["last_executed_workflow"] == "run_vuln_scan"
        assert summary["runtime_state"]["mode"] == "hunt"
        assert summary["recon_artifacts"]["ready"] is True
        assert "Last Workflow: run_vuln_scan" in output
        assert "Recon Cache: hosts=1, surface=1" in output

    def test_pickup_summary_includes_read_only_checkpoint(self, tmp_hunt_dir, sample_target_profile, monkeypatch, tmp_path):
        save_target_profile(tmp_hunt_dir, sample_target_profile)
        repo_root = tmp_path
        monkeypatch.setattr(resume_tool, "BASE_DIR", str(repo_root))

        summary = load_pickup_summary(tmp_hunt_dir, "target.com")
        output = format_resume_output(summary, "target.com")

        assert summary is not None
        assert summary["checkpoint"]["available"] is True
        assert summary["checkpoint"]["decision"] == "refresh-recon"
        assert "Checkpoint:" in output
        assert "Decision: refresh-recon" in output
        assert "Target write-back proposals:" in output
        assert "[c] Run checkpoint write-back when ready" in output


class TestResumeFormatting:

    def test_formats_missing_state(self):
        output = format_resume_output(None, "missing.com")
        assert "No previous hunt data for missing.com." in output
        assert "Run /recon missing.com first, then /hunt missing.com." in output

    def test_formats_summary_output(self):
        summary = {
            "target": "target.com",
            "sessions": 3,
            "last_hunted": "2026-03-24T21:00:00Z",
            "total_time_minutes": 125,
            "tech_stack": ["next.js", "graphql"],
            "tested_endpoints": ["/a"],
            "untested_endpoints": ["/b", "/c"],
            "findings": [],
            "finding_titles": [{"vuln_class": "idor", "endpoint": "/api/v2/users/{id}", "payout": 1500}],
            "journal_entries": 4,
            "confirmed_findings": 1,
            "confirmed_payout": 1500,
            "pattern_matches": [{"target": "alpha.com", "technique": "id_swap", "vuln_class": "idor", "payout": 800}],
            "matched_targets": 1,
            "latest_session_summary": {
                "ts": "2026-04-17T00:00:00Z",
                "session_id": "sess-777",
                "findings_count": 1,
                "vuln_classes": ["recon", "idor"],
                "endpoints_preview": ["/graphql"],
            },
        }
        output = format_resume_output(summary, "target.com")
        assert "PICKUP: target.com" in output
        assert "1 confirmed ($1500 total)" in output
        assert "2 endpoints from last recon" in output
        assert "alpha.com: id_swap [idor] ($800)" in output
        assert "Latest Session Snapshot:" in output
        assert "Session: sess-777" in output
        assert "Tried: recon, idor" in output
        assert "[r] Continue hunting untested endpoints" in output

    def test_formats_recent_guard_advisories(self):
        summary = {
            "target": "target.com",
            "sessions": 3,
            "last_hunted": "2026-03-24T21:00:00Z",
            "total_time_minutes": 125,
            "tech_stack": ["next.js", "graphql"],
            "tested_endpoints": ["/a"],
            "untested_endpoints": ["/b", "/c"],
            "findings": [],
            "finding_titles": [],
            "journal_entries": 4,
            "confirmed_findings": 0,
            "confirmed_payout": 0,
            "pattern_matches": [],
            "matched_targets": 0,
            "latest_session_summary": None,
            "recent_guard_advisories": [
                {
                    "ts": "2026-04-17T00:00:00Z",
                    "action": "hunt",
                    "endpoint": "https://api.target.com/graphql",
                    "notes": "request_guard advisory for GET https://api.target.com/graphql. Host: api.target.com. Action: breaker_advisory. Reason: circuit breaker active.",
                }
            ],
        }
        output = format_resume_output(summary, "target.com")
        assert "Recent Guard Advisories:" in output
        assert "breaker_advisory" in output

    def test_formats_repo_source_summary(self):
        summary = {
            "target": "target.com",
            "sessions": 3,
            "last_hunted": "2026-03-24T21:00:00Z",
            "total_time_minutes": 125,
            "tech_stack": ["next.js", "graphql"],
            "tested_endpoints": ["/a"],
            "untested_endpoints": ["/b", "/c"],
            "findings": [],
            "finding_titles": [],
            "journal_entries": 4,
            "confirmed_findings": 0,
            "confirmed_payout": 0,
            "pattern_matches": [],
            "matched_targets": 0,
            "latest_session_summary": None,
            "recent_guard_advisories": [],
            "repo_source_summary": {
                "summary_hint": "local_path, secrets=2, ci=1",
                "source_kind": "local_path",
                "secret_findings": 2,
                "ci_findings": 1,
            },
        }
        output = format_resume_output(summary, "target.com")
        assert "Repo Source:" in output
        assert "local_path, secrets=2, ci=1" in output

    def test_formats_checkpoint_followup(self):
        summary = {
            "target": "target.com",
            "sessions": 1,
            "last_hunted": "2026-03-24T21:00:00Z",
            "total_time_minutes": 30,
            "tech_stack": [],
            "tested_endpoints": [],
            "untested_endpoints": [],
            "findings": [],
            "finding_titles": [],
            "journal_entries": 1,
            "confirmed_findings": 0,
            "confirmed_payout": 0,
            "pattern_matches": [],
            "matched_targets": 0,
            "latest_session_summary": None,
            "recent_guard_advisories": [],
            "checkpoint": {
                "available": True,
                "decision": "continue",
                "next_action": "hunt_p1",
                "selected_skill": "skills/web2-vuln-classes/SKILL.md",
                "high_value_gaps_count": 3,
                "lead_count": 1,
                "next_count": 2,
                "dead_end_count": 0,
                "commands": [
                    'python3 tools/target_memory.py next "Cover high-value matrix gap" --target "target.com"'
                ],
            },
        }

        output = format_resume_output(summary, "target.com")

        assert "Checkpoint:" in output
        assert "Decision: continue" in output
        assert "Next action: hunt_p1" in output
        assert "Selected skill: skills/web2-vuln-classes/SKILL.md" in output
        assert "High-value gaps: 3" in output
        assert "Target write-back proposals: lead=1, next=2, dead-end=0" in output
