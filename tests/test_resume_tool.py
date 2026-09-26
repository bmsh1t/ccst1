"""Tests for tools/resume.py."""

import json
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

import finding_index
import resume as resume_tool
import tools.checkpoint as checkpoint_tool
from memory.hunt_journal import HuntJournal
from legacy_fixtures import append_legacy_pattern
from memory.schemas import make_journal_entry, make_pattern_entry
from memory.target_profile import make_target_profile
from legacy_fixtures import write_legacy_profile
from resume import format_resume_output, load_pickup_summary, load_resume_summary
from runtime_state import update_runtime_state
from tools.target_store import StoreError, TargetStore


@pytest.mark.parametrize("count", [0, 61])
def test_resume_domain_previews_have_exact_totals_and_complete_cli_expansion(tmp_path, count):
    repo = tmp_path / "isolated root"
    target = "resume-domain.test"
    store = TargetStore(repo, target)
    store.initialize()
    for index in range(count):
        store.create_finding(
            command_id=f"claim-{index}", finding_id=f"F-{index:04}",
            endpoint=f"https://{target}/open-{index:04}", method="GET", family="custom",
            title=f"Saved claim {index}", claim="Unassessed material", actor="operator",
        )
    if count:
        raw = repo / "evidence" / target / "response.txt"
        raw.parent.mkdir(parents=True)
        raw.write_text("Recorded response")
        store.start_attempt(attempt_id="read", source="native", started_at="2026-09-24T00:00:00Z", actor="operator")
        store.record_execution(attempt_id="read", outcome="complete", actor="operator", observations=[{
            "endpoint": f"https://{target}/tested-{index:04}", "method": "GET", "family": "sqli",
            "observed_at": "2026-09-24T00:00:00Z", "description": "Recorded response",
            "result": "tested_clean", "artifacts": {"response": raw.relative_to(repo).as_posix()},
            "state_changing": False,
        } for index in range(count)])
    before = store.binding()
    checkout = Path(__file__).resolve().parents[1]
    command = [sys.executable, "-B", "tools/resume.py", "--repo-root", str(repo), "--target", target]
    result = subprocess.run(command + ["--json"], cwd=checkout, capture_output=True, text=True, check=True)
    summary = json.loads(result.stdout)["summary"]
    expansion = summary["domain_windows"]["findings"]["expand_command"]
    expanded = subprocess.run(shlex.split(expansion), cwd=checkout, capture_output=True, text=True, check=True)
    full = json.loads(expanded.stdout)["summary"]
    expected = {
        "findings": [f"F-{index:04}" for index in range(count)],
        "tested_endpoints": [f"/tested-{index:04}" for index in range(count)],
        "untested_endpoints": [f"/open-{index:04}" for index in range(count)],
    }
    for field, values in expected.items():
        assert field not in summary["owner_projection"]
        actual = [row["id"] for row in summary[field]] if field == "findings" else summary[field]
        complete = [row["id"] for row in full[field]] if field == "findings" else full[field]
        assert actual == values[:5]
        assert complete == values
        window = summary["domain_windows"][field]
        assert (window["total"], window["returned"], window["remaining"]) == (count, min(count, 5), max(count - 5, 0))
        assert window["expand_command"] == expansion
        assert full["domain_windows"][field]["remaining"] == 0
    output = subprocess.run(command, cwd=checkout, capture_output=True, text=True, check=True).stdout
    assert expansion in output
    if count:
        assert "61 endpoints from current coverage; showing=5; remaining=56" in output
        assert "Finding preview: 5 of 61; remaining=56" in output
        assert "/tested-0004" in output and "/tested-0005" not in output
    assert store.binding() == before


@pytest.mark.parametrize("entry_count", [0, 7, 23])
def test_primary_resume_memory_window_is_complete_and_root_bound(tmp_path, entry_count):
    from tools.target_store import TargetStore

    repo = tmp_path / "isolated root"
    target = "resume-memory.test"
    store = TargetStore(repo, target)
    store.initialize()
    operation_id = ""
    if entry_count:
        artifact = repo / "evidence" / target / "response.txt"
        artifact.parent.mkdir(parents=True)
        artifact.write_text("Recorded object response", encoding="utf-8")
        store.start_attempt(attempt_id="read", source="native",
                            started_at="2026-09-24T00:00:00Z", actor="operator")
        store.record_execution(
            attempt_id="read", outcome="complete", actor="operator",
            observations=[{
                "endpoint": f"https://{target}/object", "method": "GET", "family": "Authz",
                "observed_at": "2026-09-24T00:00:00Z", "description": "Recorded object response",
                "artifacts": {"response": artifact.relative_to(repo).as_posix()},
                "result": "tested_clean", "state_changing": False,
            }],
        )
        operation_id = store.page("operations")["items"][0]["id"]
    for index in range(entry_count):
        negative = index == entry_count - 1
        store.remember(
            command_id=f"memory-{index:02d}", kind="negative" if negative else "note",
            statement=f"Saved observation {index}", conditions="same tenant",
            reopen_when="new peer session", next_intent="compare object IDs",
            evidence=[{"operation_id": operation_id, "step": 0}] if negative else [],
            actor="operator",
        )
    legacy = repo / "memory" / "goals" / "targets" / f"{target}.json"
    legacy.parent.mkdir(parents=True)
    legacy.write_text("{invalid legacy memory", encoding="utf-8")
    before = store.binding()
    checkout = Path(__file__).resolve().parents[1]
    command = [sys.executable, "-B", str(checkout / "tools" / "resume.py"),
               "--repo-root", str(repo), "--target", target]
    result = subprocess.run(command + ["--json"], capture_output=True, text=True, check=True)
    memory = json.loads(result.stdout)["summary"]["target_memory"]
    window = memory["experience_window"]
    entries = memory["recent_entries"]
    assert len(entries) == min(entry_count, 5)
    assert window["total"] == entry_count
    assert window["remaining"] == max(0, entry_count - 5)
    assert window["has_more"] == (entry_count > 5)
    recall_args = shlex.split(window["recall_command"])
    assert recall_args[recall_args.index("--repo-root") + 1] == str(repo.resolve())
    assert recall_args[recall_args.index("--limit") + 1] == "5"
    output = subprocess.run(command, capture_output=True, text=True, check=True).stdout
    seen = [entry["entry_id"] for entry in entries]
    if entry_count:
        assert entries[0]["kind"] == "negative"
        assert entries[0]["evidence_refs"] == [f"{operation_id}:0"]
        assert "conditions: same tenant" in output
        assert "reopen_when: new peer session" in output
        assert f"evidence: {operation_id}:0" in output
        expand = next(line.removeprefix("  Expand: ") for line in output.splitlines()
                      if line.startswith("  Expand: "))
        expanded = subprocess.run(shlex.split(expand) + ["--json"], cwd=checkout,
                                  capture_output=True, text=True, check=True)
        assert [row["entry_id"] for row in json.loads(expanded.stdout)["target_entries"]] == seen[:1]
        next_command = next(line.split("; ", 1)[1] for line in output.splitlines()
                            if line.startswith("  More: "))
        while next_command:
            page_result = subprocess.run(shlex.split(next_command) + ["--json"], cwd=checkout,
                                         capture_output=True, text=True, check=True)
            page = json.loads(page_result.stdout)
            ids = [row["entry_id"] for row in page["target_entries"]]
            assert ids and not set(ids).intersection(seen)
            seen.extend(ids)
            assert page["target_page"]["remaining"] == entry_count - len(seen)
            cursor = page["target_page"]["next_cursor"]
            next_command = f"{window['recall_command']} --cursor {shlex.quote(cursor)}" if cursor else ""
    else:
        assert "  More: " not in output
        assert "  Expand: " not in output
    assert seen == [f"memory-{index:02d}" for index in reversed(range(entry_count))]
    assert store.binding() == before
    assert legacy.read_text(encoding="utf-8") == "{invalid legacy memory"
    assert not (repo / "state" / target / "checkpoint_latest.json").exists()


def test_primary_three_round_pickup_keeps_store_memory_without_echo(tmp_path):
    from tools.target_store import TargetStore

    target = "round-memory.test"
    store = TargetStore(tmp_path, target)
    store.initialize()
    store.create_action(command_id="work-1", action_id="WORK-1", intent="Review owner boundary",
                        execution_key="owner-boundary", kind="work", subject={"target": target}, actor="operator")
    store.remember(command_id="memory-1", kind="note", statement="Peer role differs from owner",
                   conditions="same tenant", reopen_when="new peer session",
                   next_intent="compare object IDs", evidence=[], actor="operator")
    tools = Path(__file__).resolve().parent.parent / "tools"
    legacy = tmp_path / "memory" / "goals" / "targets" / f"{target}.json"
    legacy.parent.mkdir(parents=True)
    legacy.write_text("{invalid legacy memory", encoding="utf-8")

    for round_number in range(1, 4):
        store.remember(command_id=f"handoff-{round_number}", kind="handoff",
                       statement=f"Round {round_number}: continue owner-boundary review",
                       conditions="same tenant", reopen_when="", next_intent="compare object IDs",
                       evidence=[], actor="operator")
        revision = store.binding()["revision"]
        projection = tmp_path / "state" / target / "surface-projection.json"
        projection.unlink(missing_ok=True)
        checkpoint = subprocess.run(
            [sys.executable, str(tools / "checkpoint.py"), "--repo-root", str(tmp_path),
             "--target", target, "--no-refresh-coverage", "--json"],
            text=True, capture_output=True, check=True,
        )
        assert json.loads(checkpoint.stdout)["target_write_back"]["handoff"]
        pickup = subprocess.run(
            [sys.executable, str(tools / "resume.py"), "--repo-root", str(tmp_path),
             "--memory-dir", str(tmp_path / "hunt-memory"), "--target", target, "--json"],
            text=True, capture_output=True, check=True,
        )
        memory = json.loads(pickup.stdout)["summary"]["target_memory"]
        assert memory["source_kind"] == "store"
        assert memory["experience_window"]["total"] == round_number + 1
        assert {entry["entry_id"] for entry in memory["recent_entries"]} == {
            "memory-1", *(f"handoff-{index}" for index in range(1, round_number + 1))
        }
        assert any(entry.get("structured", {}).get("reopen_when") == "new peer session"
                   for entry in memory["recent_entries"])
        assert store.binding()["revision"] == revision
        assert store.page("actions")["total"] == 1
        assert store.page("experiences")["total"] == round_number + 1
    pickup_text = subprocess.run(
        [sys.executable, str(tools / "resume.py"), "--repo-root", str(tmp_path),
         "--memory-dir", str(tmp_path / "hunt-memory"), "--target", target],
        text=True, capture_output=True, check=True,
    ).stdout
    assert "conditions: same tenant" in pickup_text
    assert "reopen_when: new peer session" in pickup_text
    assert "--id handoff-3" in pickup_text
    assert legacy.read_text(encoding="utf-8") == "{invalid legacy memory"


def test_primary_resume_ignores_retired_profile(tmp_path):
    from tools.target_store import TargetStore

    target = "resume-profile.test"
    TargetStore(tmp_path, target).initialize()
    memory_dir = tmp_path / "hunt-memory"
    write_legacy_profile(memory_dir, make_target_profile(
        target, tech_stack=["retired-stack"], tested_endpoints=["/retired"],
        untested_endpoints=["/retired-open"], hunt_sessions=99,
    ))

    summary = load_resume_summary(memory_dir, target, repo_root=tmp_path)

    assert summary is not None
    assert summary["sessions"] == 0
    assert summary["tech_stack"] == []
    assert summary["tested_endpoints"] == []
    assert "/retired-open" not in summary["untested_endpoints"]
    assert "legacy_profile" not in summary


def test_primary_resume_does_not_promote_historical_journal_result(tmp_path):
    from tools.target_store import TargetStore

    target = "resume-journal.test"
    store = TargetStore(tmp_path, target)
    store.initialize()
    store.create_finding(
        command_id="finding-1", finding_id="F-1",
        endpoint=f"https://{target}/orders/1", method="GET",
        family="Authz", title="Owner boundary", claim="Unassessed claim", actor="tester",
    )
    memory_dir = tmp_path / "hunt-memory"
    HuntJournal(memory_dir / "journal.jsonl").append(make_journal_entry(
        target=target, action="remember", vuln_class="idor", endpoint="/orders/1",
        result="confirmed", severity="high", payout=1500,
    ))

    summary = load_resume_summary(memory_dir, target, repo_root=tmp_path)

    assert summary["findings"][0]["id"] == "F-1"
    assert summary["confirmed_findings"] == 0
    assert summary["confirmed_payout"] is None
    assert "0 confirmed" in format_resume_output(summary, target)


def test_resume_and_pack_bound_finding_reads_without_losing_counts(tmp_path, monkeypatch):
    from tools.context_pack import build_context_pack

    target = "resume-window.test"
    store = TargetStore(tmp_path, target)
    store.initialize()
    for index in range(12):
        store.create_finding(command_id=f"finding-{index}", finding_id=f"F-{index:02}",
                             endpoint=f"https://{target}/claim-{index}", method="GET", family="custom",
                             title=f"Claim {index}", claim="Unassessed", actor="tester")
    before = store.binding()
    materialized = []
    project = TargetStore._finding_states

    def record_rows(self, conn, rows):
        materialized.append(len(rows))
        return project(self, conn, rows)

    monkeypatch.setattr(TargetStore, "_finding_states", record_rows)
    monkeypatch.setattr(TargetStore, "_finding_projections", lambda *args: pytest.fail("expanded unused history"))
    summary = load_resume_summary(tmp_path / "memory", target, repo_root=tmp_path)
    assert materialized == [5]
    assert len(summary["findings"]) == 5
    assert summary["domain_windows"]["findings"]["total"] == 12
    assert summary["domain_windows"]["findings"]["remaining"] == 7
    assert summary["structured_findings"]["pending_validation"] == 12
    full = load_resume_summary(tmp_path / "memory", target, repo_root=tmp_path, full_domain_context=True)
    assert len(full["findings"]) == 12
    assert full["findings"][:5] == summary["findings"]
    assert full["domain_windows"]["findings"]["remaining"] == 0
    pack = build_context_pack(tmp_path, target=target)
    assert pack["source_summary"]["findings"] == 12
    assert store.binding() == before


class TestResumeSummary:

    def test_journal_audit_does_not_restore_retired_profile_or_patterns(self, tmp_hunt_dir, sample_target_profile):
        TargetStore(tmp_hunt_dir.parent, "target.com").initialize()
        write_legacy_profile(tmp_hunt_dir, sample_target_profile)

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

        append_legacy_pattern(tmp_hunt_dir / "patterns.jsonl", make_pattern_entry(
            target="alpha.com",
            vuln_class="idor",
            technique="numeric_id_swap_with_put_method",
            tech_stack=["graphql", "postgresql"],
            payout=800,
        ))
        append_legacy_pattern(tmp_hunt_dir / "patterns.jsonl", make_pattern_entry(
            target="target.com",
            vuln_class="idor",
            technique="same_target_pattern",
            tech_stack=["graphql"],
            payout=900,
        ))

        summary = load_resume_summary(tmp_hunt_dir, "target.com", repo_root=tmp_hunt_dir.parent)
        assert summary is not None
        assert summary["sessions"] == 1
        assert summary["confirmed_findings"] == 0
        assert summary["confirmed_payout"] is None
        assert summary["untested_endpoints"] == []
        assert summary["matched_targets"] == 0  # 跨目标匹配已移除
        assert summary["pattern_matches"] == []  # 跨目标模式匹配已移除（收敛裁定）
        assert summary["latest_session_summary"]["session_id"] == "sess-777"
        assert summary["latest_session_summary"]["findings_count"] == 1
        assert "recon" in summary["latest_session_summary"]["vuln_classes"]
        assert "/graphql" in summary["latest_session_summary"]["endpoints_preview"]
        assert summary["recent_guard_advisories"] == []

    def test_includes_recent_guard_advisories(self, tmp_hunt_dir, sample_target_profile):
        TargetStore(tmp_hunt_dir.parent, "target.com").initialize()
        write_legacy_profile(tmp_hunt_dir, sample_target_profile)

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

        summary = load_resume_summary(tmp_hunt_dir, "target.com", repo_root=tmp_hunt_dir.parent)

        assert summary is not None
        assert len(summary["recent_guard_advisories"]) == 2
        assert "breaker_advisory" in summary["recent_guard_advisories"][0]["notes"]
        assert "legacy request_guard block" in summary["recent_guard_advisories"][1]["notes"]

    def test_uninitialized_target_rejects_read_without_creating_state(self, tmp_hunt_dir):
        with pytest.raises(StoreError, match="initializ"):
            load_resume_summary(tmp_hunt_dir, "missing.com", repo_root=tmp_hunt_dir.parent)
        assert not (tmp_hunt_dir.parent / "state" / "missing.com" / "metadata.sqlite3").exists()


    def test_store_claim_resumes_without_legacy_profile(self, tmp_hunt_dir, tmp_path):
        store = TargetStore(tmp_path, "target.com")
        store.initialize()
        store.create_finding(command_id="claim", finding_id="canonical-only", endpoint="https://target.com/items?id=1",
                             method="GET", family="sqli", title="SQLi claim", claim="Unassessed claim", actor="operator")
        before = store.binding()
        summary = load_resume_summary(tmp_hunt_dir, "target.com", repo_root=tmp_path)
        assert "legacy_profile" not in summary
        assert summary["owner_projection"]["findings_authoritative"] is True
        assert summary["findings"][0]["id"] == "canonical-only"
        assert summary["tested_endpoints"] == []
        assert summary["sessions"] == 0
        assert store.binding() == before


    def test_corrupt_legacy_profile_does_not_hide_store_claim(self, tmp_hunt_dir, tmp_path):
        store = TargetStore(tmp_path, "target.com")
        store.initialize()
        store.create_finding(command_id="claim", finding_id="canonical-with-broken-profile",
                             endpoint="https://target.com/orders/1", method="GET", family="idor",
                             title="Owner boundary", claim="Unassessed claim", actor="operator")
        legacy = tmp_hunt_dir / "targets" / "target-com.json"
        legacy.write_text("{broken\n", encoding="utf-8")
        summary = load_resume_summary(tmp_hunt_dir, "target.com", repo_root=tmp_path)
        assert "legacy_profile" not in summary
        assert summary["findings"][0]["id"] == "canonical-with-broken-profile"
        assert legacy.read_text(encoding="utf-8") == "{broken\n"


    def test_store_work_resumes_without_profile_or_queue_file(self, tmp_hunt_dir, tmp_path):
        store = TargetStore(tmp_path, "target.com")
        store.initialize()
        store.create_action(command_id="work", action_id="WORK-1", intent="Review current evidence",
                            execution_key="review", kind="work", subject={"target": "target.com"}, actor="operator")
        queue_path = tmp_path / "state" / "target.com" / "action_queue.json"
        queue_path.mkdir()
        before = store.binding()
        summary = load_pickup_summary(tmp_hunt_dir, "target.com", repo_root=tmp_path)
        assert summary["canonical_sources"] == ["store"]
        assert "legacy_profile" not in summary
        assert summary["checkpoint"]["current_action"] == {}
        assert summary["checkpoint"]["next_action_queue"][0]["id"] == "WORK-1"
        assert "[WORK-1] queued: Review current evidence" in format_resume_output(summary, "target.com")
        assert queue_path.is_dir()
        assert store.binding() == before


    def test_resume_does_not_rewrite_legacy_finding_projection(self, tmp_hunt_dir, tmp_path):
        TargetStore(tmp_hunt_dir.parent, "target.com").initialize()
        findings_dir = tmp_path / "findings" / "target.com"
        findings_dir.mkdir(parents=True)
        findings_path = findings_dir / "findings.json"
        findings_path.write_text(
            json.dumps([{
                "id": "legacy-finding",
                "type": "idor",
                "url": "https://target.com/orders/1",
            }]),
            encoding="utf-8",
        )
        before = findings_path.read_bytes()

        summary = load_resume_summary(tmp_hunt_dir, "target.com", repo_root=tmp_path)

        assert summary is not None
        assert findings_path.read_bytes() == before

    def test_loads_host_list_profile_from_relative_target(self, tmp_hunt_dir, tmp_path, monkeypatch):
        list_file = tmp_path / "scope.txt"
        list_file.write_text("api.target.com\n", encoding="utf-8")
        monkeypatch.chdir(tmp_path)

        canonical_target = str(list_file.resolve())
        TargetStore(tmp_path, canonical_target).initialize()
        write_legacy_profile(
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

        summary = load_resume_summary(tmp_hunt_dir, "scope.txt", repo_root=tmp_path)

        assert summary is not None
        assert summary["sessions"] == 1
        assert summary["resolved_target"] == canonical_target
        assert summary["latest_session_summary"]["session_id"] == "sess-list"
        assert summary["latest_session_summary"]["endpoints_preview"] == ["/graphql"]

    def test_includes_repo_source_summary(self, tmp_hunt_dir, sample_target_profile, monkeypatch, tmp_path):
        TargetStore(tmp_hunt_dir.parent, "target.com").initialize()
        write_legacy_profile(tmp_hunt_dir, sample_target_profile)

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

        summary = load_resume_summary(tmp_hunt_dir, "target.com", repo_root=tmp_hunt_dir.parent)

        assert summary is not None
        assert summary["repo_source_summary"]["source_kind"] == "local_path"
        assert summary["repo_source_summary"]["secret_findings"] == 2
        assert summary["repo_source_summary"]["ci_findings"] == 1
        assert summary["repo_source_summary"]["summary_hint"] == "local_path, secrets=2, ci=1"

    def test_includes_structured_finding_followup(self, tmp_hunt_dir, tmp_path):
        store = TargetStore(tmp_path, "target.com")
        store.initialize()
        store.create_finding(command_id="claim-sqli", finding_id="sqli_pending", endpoint="https://api.target.com/search?q=1",
                             method="GET", family="sqli", title="SQLi claim", claim="Unassessed claim", actor="operator")
        candidate = {"id": "mfa_report", "endpoint": "https://api.target.com/mfa", "method": "GET", "family": "mfa",
                     "title": "MFA boundary", "claim": "Peer data returned"}
        raw = tmp_path / "evidence" / "target.com" / "response.txt"
        raw.parent.mkdir(parents=True)
        raw.write_text("Recorded peer data response", encoding="utf-8")
        store.start_attempt(attempt_id="read", source="native", started_at="2026-09-24T00:00:00Z", actor="operator")
        receipt = store.record_execution(attempt_id="read", outcome="complete", actor="operator", candidate=candidate,
            observations=[{"endpoint": candidate["endpoint"], "method": "GET", "family": "mfa",
                           "observed_at": "2026-09-24T00:00:00Z", "description": "Peer data returned",
                           "artifacts": {"response": raw.relative_to(tmp_path).as_posix()}, "state_changing": False}])
        store.assess(command_id="assess", finding_id="mfa_report", verdict="confirmed", reason="Compared peer boundary",
                     boundary="Owner/peer isolation", impact="Peer data disclosure", actor="operator",
                     evidence=[{"operation_id": receipt["entity_id"], "step": 0}], expected_assessment=None)
        store.decide_delivery(command_id="delivery", finding_id="mfa_report", assessment_id="assess", destination="default",
                              status="eligible", reason="Reviewed destination", actor="operator", expected_decision=None)
        before = store.binding()
        summary = load_resume_summary(tmp_hunt_dir, "target.com", repo_root=tmp_path)
        output = format_resume_output(summary, "target.com")
        assert summary["structured_findings"]["total"] == 2
        assert summary["structured_findings"]["pending_validation"] == 1
        assert summary["structured_findings"]["validated_pending_report"] == 1
        assert summary["structured_findings"]["next_validation"]["id"] == "sqli_pending"
        assert summary["structured_findings"]["next_report"]["id"] == "mfa_report"
        assert "Structured Findings:" in output
        assert "Next validate: sqli_pending" in output
        assert "Next report: mfa_report" in output
        assert "https://api.target.com/mfa" in output
        assert store.binding() == before


    def test_preserves_external_dependency_as_conditional_linked_note(self, tmp_hunt_dir, tmp_path):
        store = TargetStore(tmp_path, "target.com")
        store.initialize()
        store.create_finding(command_id="claim", finding_id="target-chain", endpoint="https://target.com/login",
                             method="GET", family="Authz", title="Login boundary", claim="Unassessed claim", actor="operator")
        store.remember(command_id="dependency-note", kind="note", finding_id="target-chain",
                       statement="target login -> external identity provider https://external.example/admin/; //protocol-relative.example/admin/",
                       conditions="External dependency is context; ownership remains unverified",
                       reopen_when="Scope ownership established", next_intent="Review target login integration",
                       evidence=[], actor="operator")
        before = store.binding()
        first = load_resume_summary(tmp_hunt_dir, "target.com", repo_root=tmp_path)
        second = load_resume_summary(tmp_hunt_dir, "target.com", repo_root=tmp_path)
        output = format_resume_output(first, "target.com")
        assert first["structured_findings"]["total"] == 1
        assert first["structured_findings"]["next_validation"]["id"] == "target-chain"
        assert first["target_memory"] == second["target_memory"]
        assert "target login -> external identity provider" in output
        assert "https://external.example/admin/" in output
        assert "//protocol-relative.example/admin/" in output
        assert "conditions: External dependency is context; ownership remains unverified" in output
        assert "--id dependency-note" in output
        assert store.experience("dependency-note")["finding_id"] == "target-chain"
        assert store.page("actions")["total"] == 0
        assert store.binding() == before


    def test_explicit_material_review_recovers_incomplete_root_claim_without_url(self, tmp_hunt_dir, tmp_path):
        store = TargetStore(tmp_path, "target.com")
        store.initialize()
        findings_dir = tmp_path / "findings" / "target.com"
        findings_dir.mkdir(parents=True)
        source = findings_dir / "jwt-claim.json"
        source.write_text(json.dumps({"title": "JWT authentication bypass", "target": "target.com",
            "vulnerability_class": "JWT", "impact": "Administrator view reached with a forged token."}), encoding="utf-8")
        before = store.binding()
        summary = load_resume_summary(tmp_hunt_dir, "target.com", repo_root=tmp_path)
        assert summary["structured_findings"]["total"] == 0
        assert store.page("actions")["total"] == 0
        assert store.binding() == before

        indexed = finding_index.index_scanner_material(findings_dir, target="target.com")
        claim = indexed["root_claims"][0]
        assert claim["url"] == ""
        assert claim["claim_status"] == "incomplete"
        assert "endpoint" in claim["incomplete_fields"]
        before = store.binding()
        pickup = load_pickup_summary(tmp_hunt_dir, "target.com", repo_root=tmp_path)
        assert pickup["checkpoint"]["current_action"] == {}
        assert pickup["checkpoint"]["next_action_queue"][0]["id"] == indexed["review_action_ids"][0]
        assert store.page("findings")["total"] == 0
        assert store.binding() == before


    def test_includes_runtime_state_and_recon_artifacts(self, tmp_hunt_dir, sample_target_profile, monkeypatch, tmp_path):
        TargetStore(tmp_hunt_dir.parent, "target.com").initialize()
        write_legacy_profile(tmp_hunt_dir, sample_target_profile)
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

        summary = load_resume_summary(tmp_hunt_dir, "target.com", repo_root=tmp_hunt_dir.parent)
        output = format_resume_output(summary, "target.com")

        assert summary["runtime_state"]["last_executed_workflow"] == "run_vuln_scan"
        assert summary["runtime_state"]["mode"] == "hunt"
        assert summary["recon_artifacts"]["ready"] is True
        assert "Last Workflow: run_vuln_scan" in output
        assert "Recon Cache: hosts=1, surface=1" in output

    def test_pickup_summary_includes_read_only_checkpoint(self, tmp_hunt_dir, sample_target_profile, monkeypatch, tmp_path):
        TargetStore(tmp_hunt_dir.parent, "target.com").initialize()
        write_legacy_profile(tmp_hunt_dir, sample_target_profile)
        repo_root = tmp_path
        monkeypatch.setattr(resume_tool, "BASE_DIR", str(repo_root))

        summary = load_pickup_summary(tmp_hunt_dir, "target.com", repo_root=tmp_hunt_dir.parent)
        output = format_resume_output(summary, "target.com")

        assert summary is not None
        assert summary["checkpoint"]["available"] is True
        assert summary["checkpoint"]["decision"] == "continue"
        assert set(summary["checkpoint"]) >= {
            "current_action",
            "recent_evidence",
            "blocker",
            "next_action",
        }
        assert "Checkpoint:" in output
        assert "Decision: continue" in output
        assert "Current action:" in output
        assert "Recent evidence:" in output
        assert "Blocker:" in output
        assert "Target write-back proposals:" in output
        assert "[c] Read a fresh Checkpoint; save handoff through target memory" in output

    def test_checkpoint_followup_projects_empty_running_and_wait_control_state(self, monkeypatch, tmp_path):
        cases = [
            ({"decision": "handoff", "next_action": "handoff"}, {}, [], ""),
            (
                {
                    "decision": "continue",
                    "next_action": "validation",
                    "recommended_executable_action": {
                        "id": "AQ-running",
                        "type": "validation",
                        "status": "running",
                        "action": "Replay the current lane.",
                        "evidence_ref": "evidence/target.com/running.json",
                    },
                },
                {"id": "AQ-running", "status": "running"},
                ["evidence/target.com/running.json"],
                "",
            ),
            (
                {
                    "decision": "wait_recon",
                    "next_action": "wait_recon",
                    "recommended_executable_action": {
                        "id": "runtime-wait",
                        "type": "wait_recon",
                        "status": "transient",
                        "action": "Wait for the existing recon phase.",
                        "evidence": "matching phase lock is active",
                    },
                },
                {"id": "runtime-wait", "status": "transient"},
                ["matching phase lock is active"],
                "wait_recon: an existing long-running phase owns the target",
            ),
        ]

        for payload, expected_action, expected_evidence, expected_blocker in cases:
            checkpoint = {
                "coverage": {"summary": {}},
                "target_write_back": {},
                "context_pack": {},
                "evidence_ledger": {},
                **payload,
            }
            monkeypatch.setattr(checkpoint_tool, "build_checkpoint", lambda *_args, **_kwargs: checkpoint)

            projection = resume_tool.load_checkpoint_followup(tmp_path, "target.com")

            assert {
                key: projection["current_action"].get(key)
                for key in expected_action
            } == expected_action
            assert projection["recent_evidence"] == expected_evidence
            assert projection["blocker"] == expected_blocker
            assert projection["next_action"] == payload["next_action"]


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
        assert "2 endpoints from current coverage; showing=2; remaining=0" in output
        assert "alpha.com" not in output  # 跨目标模式建议已移除
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
                "current_action": {"type": "validation", "action": "Replay the evidence lane."},
                "recent_evidence": ["evidence/target.com/summary.json"],
                "blocker": "red-line evidence remains unchecked",
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
        assert "Current action: Replay the evidence lane." in output
        assert "Recent evidence: evidence/target.com/summary.json" in output
        assert "Blocker: red-line evidence remains unchecked" in output
        # The retired pack skill slot no longer produces a resume recommendation.
        assert "Recommended skill:" not in output
        assert "High-value gaps: 3" in output
        assert "Target write-back proposals: lead=1, next=2, dead-end=0" in output
