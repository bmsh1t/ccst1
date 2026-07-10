"""Tests for intel_engine.py — memory-aware intel prioritization."""

import json
import os
import sys
from pathlib import Path

import pytest

import intel_engine
import intelligence_extractor
from intel_engine import load_memory_context, prioritize_intel


@pytest.fixture
def memory_dir(tmp_path):
    """Create a mock hunt-memory directory with test data."""
    targets_dir = tmp_path / "targets"
    targets_dir.mkdir()

    # Target profile
    profile = {
        "target": "target.com",
        "tech_stack": ["nextjs", "graphql", "postgresql"],
        "tested_endpoints": ["/api/v1/users", "/api/v1/login"],
        "findings": [{"vuln_class": "idor", "severity": "high"}],
        "last_hunted": "2026-03-24",
        "hunt_sessions": 3,
    }
    (targets_dir / "target-com.json").write_text(json.dumps(profile))

    # Journal with tested CVE
    journal_entries = [
        {
            "ts": "2026-03-24T10:00:00Z",
            "target": "target.com",
            "action": "test",
            "vuln_class": "ssrf",
            "endpoint": "/api/v1/proxy",
            "result": "rejected",
            "tags": ["CVE-2026-1234"],
            "schema_version": 1,
        },
        {
            "ts": "2026-03-24T11:00:00Z",
            "target": "other.com",
            "action": "test",
            "vuln_class": "xss",
            "endpoint": "/search",
            "result": "confirmed",
            "tags": [],
            "schema_version": 1,
        },
    ]
    journal_path = tmp_path / "journal.jsonl"
    with open(journal_path, "w") as f:
        for entry in journal_entries:
            f.write(json.dumps(entry) + "\n")

    # Patterns
    patterns = [
        {
            "target": "alpha.com",
            "vuln_class": "idor",
            "technique": "numeric_id_swap_put",
            "tech_stack": ["nextjs", "express"],
            "payout": 800,
            "schema_version": 1,
        },
        {
            "target": "beta.com",
            "vuln_class": "ssrf",
            "technique": "dns_rebinding",
            "tech_stack": ["django", "celery"],
            "payout": 1500,
            "schema_version": 1,
        },
    ]
    patterns_path = tmp_path / "patterns.jsonl"
    with open(patterns_path, "w") as f:
        for p in patterns:
            f.write(json.dumps(p) + "\n")

    return tmp_path


class TestLoadMemoryContext:

    def test_loads_target_profile(self, memory_dir):
        ctx = load_memory_context(str(memory_dir), "target.com")
        assert ctx["tech_stack"] == ["nextjs", "graphql", "postgresql"]
        assert ctx["last_hunted"] == "2026-03-24"
        assert ctx["hunt_sessions"] == 3
        assert "/api/v1/users" in ctx["tested_endpoints"]

    def test_url_target_loads_canonical_profile_and_journal(self, tmp_path):
        targets_dir = tmp_path / "targets"
        targets_dir.mkdir()
        (targets_dir / "127-0-0-1:3002.json").write_text(
            json.dumps({"target": "127.0.0.1:3002", "tech_stack": ["flask"]}),
            encoding="utf-8",
        )
        (tmp_path / "journal.jsonl").write_text(
            json.dumps({
                "target": "127.0.0.1:3002",
                "tags": ["CVE-2026-4321"],
            }) + "\n",
            encoding="utf-8",
        )

        ctx = load_memory_context(str(tmp_path), "http://127.0.0.1:3002/#/login")

        assert ctx["tech_stack"] == ["flask"]
        assert ctx["tested_cves"] == ["CVE-2026-4321"]

    def test_loads_tested_cves(self, memory_dir):
        ctx = load_memory_context(str(memory_dir), "target.com")
        assert "CVE-2026-1234" in ctx["tested_cves"]

    def test_loads_patterns(self, memory_dir):
        ctx = load_memory_context(str(memory_dir), "target.com")
        assert len(ctx["patterns"]) == 2

    def test_nonexistent_target(self, memory_dir):
        ctx = load_memory_context(str(memory_dir), "unknown.com")
        assert ctx["tested_endpoints"] == []
        assert ctx["tech_stack"] == []

    def test_nonexistent_directory(self):
        ctx = load_memory_context("/nonexistent/path", "target.com")
        assert ctx["tested_endpoints"] == []

    def test_empty_memory_dir(self):
        ctx = load_memory_context("", "target.com")
        assert ctx["tested_endpoints"] == []

    def test_corrupted_journal(self, memory_dir):
        journal_path = memory_dir / "journal.jsonl"
        with open(journal_path, "a") as f:
            f.write("not valid json\n")
        ctx = load_memory_context(str(memory_dir), "target.com")
        # Should still load the valid entries
        assert "CVE-2026-1234" in ctx["tested_cves"]

    def test_load_recon_tech_stack_uses_cidr_storage_key(self, tmp_path, monkeypatch):
        recon_file = tmp_path / "recon" / "1.2.3.0_24" / "live" / "httpx_full.txt"
        recon_file.parent.mkdir(parents=True)
        recon_file.write_text(
            "https://1.2.3.25 [200] [Target] [nextjs,graphql,cloudflare]\n",
            encoding="utf-8",
        )
        monkeypatch.setattr(intel_engine, "REPO_ROOT", str(tmp_path), raising=False)

        assert intel_engine.load_recon_tech_stack("1.2.3.0/24") == [
            "nextjs",
            "graphql",
            "cloudflare",
        ]


class TestPrioritizeIntel:

    def test_critical_untested(self):
        results = [
            {"id": "CVE-2026-9999", "severity": "CRITICAL", "summary": "RCE in Next.js"},
        ]
        memory = {"tested_cves": [], "tested_endpoints": [], "patterns": []}
        intel = prioritize_intel(results, memory)
        assert len(intel["critical"]) == 1
        assert intel["critical"][0]["note"] == "Untested critical vulnerability. Hunt candidate."

    def test_already_tested_cve(self):
        results = [
            {"id": "CVE-2026-1234", "severity": "CRITICAL", "summary": "Old vuln"},
        ]
        memory = {"tested_cves": ["CVE-2026-1234"], "tested_endpoints": [], "patterns": []}
        intel = prioritize_intel(results, memory)
        assert len(intel["critical"]) == 0
        assert len(intel["info"]) == 1
        assert intel["info"][0]["already_tested"] is True

    def test_high_severity(self):
        results = [
            {"id": "CVE-2026-5555", "severity": "HIGH", "summary": "Auth bypass"},
        ]
        memory = {"tested_cves": [], "tested_endpoints": [], "patterns": []}
        intel = prioritize_intel(results, memory)
        assert len(intel["high"]) == 1

    def test_medium_goes_to_info(self):
        results = [
            {"id": "CVE-2026-3333", "severity": "MEDIUM", "summary": "Info leak"},
        ]
        memory = {"tested_cves": [], "tested_endpoints": [], "patterns": []}
        intel = prioritize_intel(results, memory)
        assert len(intel["info"]) == 1

    def test_matching_patterns(self, memory_dir):
        results = []
        memory = load_memory_context(str(memory_dir), "target.com")
        intel = prioritize_intel(results, memory)
        # alpha.com pattern has nextjs overlap with target.com
        patterns = intel["memory_context"].get("matching_patterns", [])
        assert len(patterns) >= 1
        assert any(p["target"] == "alpha.com" for p in patterns)

    def test_memory_context_fields(self):
        results = []
        memory = {
            "tested_cves": ["CVE-1", "CVE-2"],
            "tested_endpoints": ["/a", "/b", "/c"],
            "patterns": [],
            "last_hunted": "2026-03-20",
            "hunt_sessions": 5,
            "tech_stack": ["react"],
        }
        intel = prioritize_intel(results, memory)
        mc = intel["memory_context"]
        assert mc["tested_endpoints_count"] == 3
        assert mc["tested_cves_count"] == 2
        assert mc["last_hunted"] == "2026-03-20"

    def test_total_count(self):
        results = [
            {"id": "1", "severity": "CRITICAL", "summary": "a"},
            {"id": "2", "severity": "HIGH", "summary": "b"},
            {"id": "3", "severity": "LOW", "summary": "c"},
        ]
        memory = {"tested_cves": [], "tested_endpoints": [], "patterns": []}
        intel = prioritize_intel(results, memory)
        assert intel["total"] == 3


class TestIdentityIntel:

    def test_resolve_emailfinder_prefers_shared_tools_dir(self, tmp_path, monkeypatch):
        tools_dir = tmp_path / "Tools"
        script = tools_dir / "emailfinder" / "emailfinder.py"
        script.parent.mkdir(parents=True)
        script.write_text("# fake emailfinder\n", encoding="utf-8")

        monkeypatch.setattr(intel_engine, "SHARED_TOOLS_DIR", str(tools_dir), raising=False)
        monkeypatch.setattr(intel_engine.shutil, "which", lambda name: "/usr/bin/emailfinder")

        assert intel_engine._resolve_emailfinder() == [sys.executable, str(script)]

    def test_resolve_leaksearch_uses_shared_venv_python(self, tmp_path, monkeypatch):
        tools_dir = tmp_path / "Tools"
        script = tools_dir / "LeakSearch" / "LeakSearch.py"
        python_bin = tools_dir / "LeakSearch" / "venv" / "bin" / "python3"
        script.parent.mkdir(parents=True)
        python_bin.parent.mkdir(parents=True)
        script.write_text("# fake LeakSearch\n", encoding="utf-8")
        python_bin.write_text("#!/bin/sh\n", encoding="utf-8")

        monkeypatch.setattr(intel_engine, "SHARED_TOOLS_DIR", str(tools_dir), raising=False)

        assert intel_engine._resolve_leaksearch() == [str(python_bin), str(script)]

    def test_run_identity_intel_missing_tools_writes_empty_artifacts(self, tmp_path, monkeypatch):
        monkeypatch.setattr(intel_engine, "REPO_ROOT", str(tmp_path), raising=False)
        monkeypatch.setattr(intel_engine, "_resolve_emailfinder", lambda: None)
        monkeypatch.setattr(intel_engine, "_resolve_leaksearch", lambda: None)

        result = intel_engine.run_identity_intel("target.com")

        assert result["emailfinder_status"] == "missing"
        assert result["leaksearch_status"] == "missing"
        assert result["email_count"] == 0
        assert result["leak_line_count"] == 0
        assert (tmp_path / "evidence" / "target.com" / "identity_intel" / "emails.txt").is_file()
        assert (tmp_path / "evidence" / "target.com" / "identity_intel" / "leaksearch.txt").is_file()
        summary = tmp_path / "evidence" / "target.com" / "identity_intel" / "summary.md"
        assert summary.is_file()
        assert "emailfinder: missing" in summary.read_text(encoding="utf-8")
        intelligence = tmp_path / "evidence" / "target.com" / "intelligence.md"
        assert "Identity Intel" in intelligence.read_text(encoding="utf-8")

    def test_run_identity_intel_url_target_is_canonical_and_idempotent(self, tmp_path, monkeypatch):
        monkeypatch.setattr(intel_engine, "REPO_ROOT", str(tmp_path), raising=False)
        monkeypatch.setattr(intel_engine, "_resolve_emailfinder", lambda: None)
        monkeypatch.setattr(intel_engine, "_resolve_leaksearch", lambda: None)
        target = "http://127.0.0.1:3002/#/login"

        intel_engine.run_identity_intel(target)
        intel_engine.run_identity_intel(target)

        intelligence = tmp_path / "evidence" / "127.0.0.1:3002" / "intelligence.md"
        content = intelligence.read_text(encoding="utf-8")
        assert content.count("ccst:intelligence:identity-intel:start") == 1
        assert content.count("# Identity Intel") == 1
        assert not (tmp_path / "evidence" / "http:").exists()

    def test_identity_and_local_intel_preserve_each_other_across_reruns(self, tmp_path, monkeypatch):
        monkeypatch.setattr(intel_engine, "REPO_ROOT", str(tmp_path), raising=False)
        monkeypatch.setattr(intel_engine, "_resolve_emailfinder", lambda: None)
        monkeypatch.setattr(intel_engine, "_resolve_leaksearch", lambda: None)
        recon_signal = tmp_path / "recon" / "target.com" / "data.txt"
        recon_signal.parent.mkdir(parents=True)
        recon_signal.write_text("ops@target.test\n", encoding="utf-8")

        intel_engine.run_identity_intel("target.com")
        intelligence_path = tmp_path / "evidence" / "target.com" / "intelligence.md"
        intelligence_path.write_text(
            intelligence_path.read_text(encoding="utf-8")
            + "\n# Operator Notes\n\nkeep-this-note\n",
            encoding="utf-8",
        )
        intelligence_extractor.write_intelligence("target.com", tmp_path)
        intel_engine.run_identity_intel("target.com")
        intelligence_extractor.write_intelligence("target.com", tmp_path)

        content = intelligence_path.read_text(encoding="utf-8")
        assert "ops@target.test" in content
        assert "keep-this-note" in content
        assert content.count("ccst:intelligence:identity-intel:start") == 1
        assert content.count("ccst:intelligence:local-extractor:start") == 1

    def test_run_identity_intel_records_tool_outputs(self, tmp_path, monkeypatch):
        monkeypatch.setattr(intel_engine, "REPO_ROOT", str(tmp_path), raising=False)
        monkeypatch.setattr(intel_engine, "_resolve_emailfinder", lambda: ["emailfinder"])
        monkeypatch.setattr(intel_engine, "_resolve_leaksearch", lambda: ["python3", "LeakSearch.py"])

        def fake_run(cmd, output_path, timeout):
            if "emailfinder" in cmd[0]:
                Path(output_path).write_text("admin@target.com\nops@target.com\n", encoding="utf-8")
            else:
                Path(output_path).write_text("target.com:leak-hit\n", encoding="utf-8")
            return True

        monkeypatch.setattr(intel_engine, "_run_command", fake_run)

        result = intel_engine.run_identity_intel("target.com")

        assert result["emailfinder_status"] == "ok"
        assert result["leaksearch_status"] == "ok"
        assert result["email_count"] == 2
        assert result["leak_line_count"] == 1

    def test_format_output_includes_identity_intel_summary(self, tmp_path, monkeypatch):
        artifact_dir = tmp_path / "evidence" / "target.com" / "identity_intel"
        monkeypatch.setattr(intel_engine, "REPO_ROOT", str(tmp_path), raising=False)
        output = intel_engine.format_output(
            "target.com",
            {
                "critical": [],
                "high": [],
                "info": [],
                "memory_context": {},
                "total": 0,
                "identity_intel": {
                    "emailfinder_status": "ok",
                    "leaksearch_status": "missing",
                    "email_count": 2,
                    "leak_line_count": 0,
                    "artifact_dir": str(artifact_dir),
                },
            },
        )

        assert "IDENTITY INTEL" in output
        assert "emailfinder: ok (2 lines)" in output
        assert "LeakSearch: missing (0 lines)" in output
        assert "evidence/target.com/identity_intel/" in output


class TestStandaloneTechResolution:

    def test_main_uses_memory_tech_when_cli_missing(self, memory_dir, monkeypatch, capsys):
        captured = {}

        def fake_fetch(techs, target, program=""):
            captured["techs"] = list(techs)
            captured["target"] = target
            return []

        monkeypatch.setattr(intel_engine, "fetch_all_intel", fake_fetch)
        monkeypatch.setattr(
            intel_engine,
            "prioritize_intel",
            lambda results, memory: {
                "critical": [],
                "high": [],
                "info": [],
                "memory_context": {"tech_stack": memory.get("tech_stack", [])},
                "total": len(results),
            },
        )
        monkeypatch.setattr(intel_engine, "format_output", lambda target, intel: f"OK:{target}")
        monkeypatch.setattr(intel_engine, "run_identity_intel", lambda target: {"emailfinder_status": "missing"})
        monkeypatch.setattr(
            sys,
            "argv",
            ["intel_engine.py", "--target", "target.com", "--memory-dir", str(memory_dir)],
        )

        intel_engine.main()

        out = capsys.readouterr().out
        assert captured["target"] == "target.com"
        assert captured["techs"] == ["nextjs", "graphql", "postgresql"]
        assert "Tech:" in out

    def test_main_canonicalizes_url_target_for_all_consumers(self, tmp_path, monkeypatch, capsys):
        captured = {}
        monkeypatch.setattr(
            intel_engine,
            "load_memory_context",
            lambda memory_dir, target: captured.setdefault("memory_target", target) or {},
        )
        monkeypatch.setattr(intel_engine, "resolve_tech_stack", lambda target, techs, memory: ["flask"])
        monkeypatch.setattr(
            intel_engine,
            "fetch_all_intel",
            lambda techs, target, program="": captured.setdefault("fetch_target", target) or [],
        )
        monkeypatch.setattr(
            intel_engine,
            "prioritize_intel",
            lambda results, memory: {"critical": [], "high": [], "info": [], "total": 0},
        )
        monkeypatch.setattr(
            intel_engine,
            "run_identity_intel",
            lambda target: captured.setdefault("identity_target", target) or {},
        )
        monkeypatch.setattr(intel_engine, "format_output", lambda target, intel: f"OK:{target}")
        monkeypatch.setattr(
            sys,
            "argv",
            ["intel_engine.py", "--target", "http://127.0.0.1:3002/#/login", "--tech", "flask"],
        )

        intel_engine.main()

        assert captured == {
            "memory_target": "127.0.0.1:3002",
            "fetch_target": "127.0.0.1:3002",
            "identity_target": "127.0.0.1:3002",
        }
        assert "OK:127.0.0.1:3002" in capsys.readouterr().out

    def test_main_uses_recon_tech_when_memory_empty(self, tmp_path, monkeypatch, capsys):
        captured = {}
        memory_dir = tmp_path / "hunt-memory"
        (memory_dir / "targets").mkdir(parents=True)
        recon_file = tmp_path / "recon" / "target.com" / "live" / "httpx_full.txt"
        recon_file.parent.mkdir(parents=True)
        recon_file.write_text(
            "https://target.com [200] [Target] [nextjs,graphql,cloudflare]\n",
            encoding="utf-8",
        )

        def fake_fetch(techs, target, program=""):
            captured["techs"] = list(techs)
            return []

        monkeypatch.setattr(intel_engine, "fetch_all_intel", fake_fetch)
        monkeypatch.setattr(
            intel_engine,
            "prioritize_intel",
            lambda results, memory: {
                "critical": [],
                "high": [],
                "info": [],
                "memory_context": {"tech_stack": memory.get("tech_stack", [])},
                "total": len(results),
            },
        )
        monkeypatch.setattr(intel_engine, "format_output", lambda target, intel: f"OK:{target}")
        monkeypatch.setattr(intel_engine, "run_identity_intel", lambda target: {"emailfinder_status": "missing"})
        monkeypatch.setattr(intel_engine, "REPO_ROOT", str(tmp_path), raising=False)
        monkeypatch.setattr(
            sys,
            "argv",
            ["intel_engine.py", "--target", "target.com", "--memory-dir", str(memory_dir)],
        )

        intel_engine.main()

        out = capsys.readouterr().out
        assert captured["techs"] == ["nextjs", "graphql", "cloudflare"]
        assert "Tech:" in out

    def test_main_exits_when_no_tech_available(self, tmp_path, monkeypatch, capsys):
        memory_dir = tmp_path / "hunt-memory"
        (memory_dir / "targets").mkdir(parents=True)
        monkeypatch.setattr(intel_engine, "REPO_ROOT", str(tmp_path), raising=False)
        monkeypatch.setattr(
            sys,
            "argv",
            ["intel_engine.py", "--target", "target.com", "--memory-dir", str(memory_dir)],
        )

        with pytest.raises(SystemExit) as exc:
            intel_engine.main()

        out = capsys.readouterr().out
        assert exc.value.code == 1
        assert "No tech stack specified" in out
