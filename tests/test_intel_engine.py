"""Tests for intel_engine.py — memory-aware intel prioritization."""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

import intel_engine
from tools.web_intel_artifact import record_web_intel
import intelligence_extractor
from intel_engine import load_memory_context, prioritize_intel
from tools.intel_sources import IntelSourceError


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

    @pytest.mark.parametrize(
        ("extra_args", "expected"),
        [([], False), (["--with-identity"], True)],
    )
    def test_main_makes_identity_intel_explicit(self, monkeypatch, capsys, extra_args, expected):
        captured = {}

        def fake_build(
            repo_root,
            target,
            *,
            techs,
            memory,
            program="",
            include_identity=False,
        ):
            captured["include_identity"] = include_identity
            return {
                "schema_version": 2,
                "target": target,
                "coverage_status": "ready",
                "inventory": {"components": []},
                "sources": [],
                "advisories": [],
                "critical": [],
                "high": [],
                "info": [],
                "identity_intel": {},
                "total": 0,
            }

        monkeypatch.setattr(intel_engine, "build_target_intel", fake_build)
        monkeypatch.setattr(intel_engine, "format_output", lambda *_args: "ok")

        result = intel_engine.main(["--target", "target.com", "--tech", "flask", *extra_args])

        assert result == 0
        assert captured["include_identity"] is expected
        capsys.readouterr()

    def test_main_uses_memory_tech_when_cli_missing(self, memory_dir, monkeypatch, capsys):
        captured = {}

        def fake_build(repo_root, target, *, techs, memory, program="", include_identity=False):
            captured["repo_root"] = repo_root
            captured["target"] = target
            captured["techs"] = list(techs)
            return {
                "schema_version": 2,
                "target": target,
                "coverage_status": "ready",
                "inventory": {"components": []},
                "sources": [],
                "advisories": [],
                "critical": [],
                "high": [],
                "info": [],
                "memory_context": {"tech_stack": memory.get("tech_stack", [])},
                "identity_intel": {},
                "total": 0,
            }

        monkeypatch.setattr(intel_engine, "build_target_intel", fake_build)
        monkeypatch.setattr(intel_engine, "format_output", lambda target, intel: f"OK:{target}")
        result = intel_engine.main(["--target", "target.com", "--memory-dir", str(memory_dir)])

        captured_io = capsys.readouterr()
        out = captured_io.out
        assert result == 0
        assert captured["target"] == "target.com"
        assert captured["techs"] == ["nextjs", "graphql", "postgresql"]
        assert out.strip() == "OK:target.com"
        assert "target=target.com" in captured_io.err

    def test_main_canonicalizes_url_target_for_all_consumers(self, tmp_path, monkeypatch, capsys):
        captured = {}
        monkeypatch.setattr(
            intel_engine,
            "load_memory_context",
            lambda memory_dir, target: captured.setdefault("memory_target", target) or {},
        )
        monkeypatch.setattr(
            intel_engine,
            "resolve_tech_stack",
            lambda target, techs, memory, **_kwargs: ["flask"],
        )
        def fake_build(repo_root, target, *, techs, memory, program="", include_identity=False):
            captured["build_target"] = target
            return {
                "schema_version": 2,
                "target": target,
                "coverage_status": "ready",
                "inventory": {"components": []},
                "sources": [],
                "advisories": [],
                "critical": [],
                "high": [],
                "info": [],
                "identity_intel": {},
                "total": 0,
            }

        monkeypatch.setattr(intel_engine, "build_target_intel", fake_build)
        monkeypatch.setattr(intel_engine, "format_output", lambda target, intel: f"OK:{target}")
        result = intel_engine.main([
            "--target",
            "http://127.0.0.1:3002/#/login",
            "--tech",
            "flask",
        ])

        assert captured == {
            "memory_target": "127.0.0.1:3002",
            "build_target": "127.0.0.1:3002",
        }
        assert result == 0
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

        def fake_build(repo_root, target, *, techs, memory, program="", include_identity=False):
            captured["techs"] = list(techs)
            return {
                "schema_version": 2,
                "target": target,
                "coverage_status": "ready",
                "inventory": {"components": []},
                "sources": [],
                "advisories": [],
                "critical": [],
                "high": [],
                "info": [],
                "memory_context": {"tech_stack": memory.get("tech_stack", [])},
                "identity_intel": {},
                "total": 0,
            }

        monkeypatch.setattr(intel_engine, "build_target_intel", fake_build)
        monkeypatch.setattr(intel_engine, "format_output", lambda target, intel: f"OK:{target}")
        monkeypatch.setattr(intel_engine, "REPO_ROOT", str(tmp_path), raising=False)
        result = intel_engine.main(["--target", "target.com", "--memory-dir", str(memory_dir)])

        out = capsys.readouterr().out
        assert result == 0
        assert captured["techs"] == ["nextjs", "graphql", "cloudflare"]
        assert out.strip() == "OK:target.com"

    def test_main_exits_when_no_tech_available(self, tmp_path, monkeypatch, capsys):
        memory_dir = tmp_path / "hunt-memory"
        (memory_dir / "targets").mkdir(parents=True)
        monkeypatch.setattr(intel_engine, "REPO_ROOT", str(tmp_path), raising=False)
        result = intel_engine.main(["--target", "target.com", "--memory-dir", str(memory_dir)])

        captured = capsys.readouterr()
        assert result == 1
        assert captured.out == ""
        assert "no technology components available" in captured.err

    def test_json_error_path_is_still_valid_json(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setattr(intel_engine, "REPO_ROOT", str(tmp_path), raising=False)

        result = intel_engine.main([
            "--target",
            "target.com",
            "--repo-root",
            str(tmp_path),
            "--json",
        ])

        captured = capsys.readouterr()
        assert result == 1
        assert json.loads(captured.out)["status"] == "error"
        assert "intel error:" in captured.err

    def test_json_mode_emits_only_machine_json(self, monkeypatch, capsys):
        payload = {
            "schema_version": 2,
            "target": "target.com",
            "coverage_status": "partial",
            "inventory": {"components": []},
            "sources": [],
            "advisories": [],
            "critical": [],
            "high": [],
            "info": [],
            "identity_intel": {},
            "total": 0,
        }
        monkeypatch.setattr(intel_engine, "build_target_intel", lambda *_args, **_kwargs: payload)

        result = intel_engine.main(["--target", "target.com", "--tech", "next.js", "--json"])

        captured = capsys.readouterr()
        assert result == 0
        assert json.loads(captured.out) == payload
        assert "intel: target=target.com" in captured.err

    def test_json_mode_returns_nonzero_for_full_source_failure(self, monkeypatch, capsys):
        payload = {
            "schema_version": 2,
            "target": "target.com",
            "coverage_status": "error",
            "inventory": {"components": []},
            "sources": [{"source": "osv", "status": "error", "error": "offline"}],
            "advisories": [],
            "critical": [],
            "high": [],
            "info": [],
            "identity_intel": {},
            "total": 0,
        }
        monkeypatch.setattr(intel_engine, "build_target_intel", lambda *_args, **_kwargs: payload)

        result = intel_engine.main(["--target", "target.com", "--tech", "next.js", "--json"])

        captured = capsys.readouterr()
        assert result == 2
        assert json.loads(captured.out)["coverage_status"] == "error"


class TestIntelV2Pipeline:

    def test_coarse_cve_memory_does_not_close_a_versioned_advisory(self):
        advisory = {
            "id": "CVE-2026-63030",
            "aliases": ["CVE-2026-63030"],
            "component": {"name": "givewp", "version": "4.16.3"},
            "applicability": "affected",
            "severity": "CRITICAL",
            "published": "2026-07-18T00:00:00Z",
        }

        result = intel_engine.prioritize_advisories(
            [advisory],
            {"tested_cves": ["CVE-2026-63030"]},
            now=datetime(2026, 7, 19, 12, 0, tzinfo=timezone.utc),
        )

        assert result["advisories"][0]["already_tested"] is False
        assert result["advisories"][0] not in result["info"]

        advisory["component"]["version"] = ""
        legacy_result = intel_engine.prioritize_advisories(
            [advisory],
            {"tested_cves": ["CVE-2026-63030"]},
        )
        assert legacy_result["advisories"][0]["already_tested"] is True

    def test_build_merges_sources_enriches_and_repeats_without_duplicates(self, tmp_path):
        live = tmp_path / "recon" / "target.com" / "live"
        live.mkdir(parents=True)
        (live / "httpx_full.txt").write_text(
            "https://target.com [200] [1234] [Target] [Next.js:15.2.1]\n",
            encoding="utf-8",
        )
        now = datetime(2026, 7, 19, 12, 0, tzinfo=timezone.utc)

        def fetcher(url, **kwargs):
            if "api.osv.dev" in url:
                return {"vulns": [{
                    "id": "GHSA-test-0001",
                    "aliases": ["CVE-2026-0001"],
                    "summary": "Middleware authorization bypass",
                    "published": "2026-07-18T00:00:00Z",
                    "modified": "2026-07-19T00:00:00Z",
                    "database_specific": {"severity": "HIGH"},
                    "affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": "15.2.2"}]}]}],
                    "references": [{"url": "https://github.com/advisories/GHSA-test-0001"}],
                }]}
            if "api.github.com" in url:
                return [{
                    "ghsa_id": "GHSA-test-0001",
                    "cve_id": "CVE-2026-0001",
                    "severity": "critical",
                    "summary": "Middleware authorization bypass",
                    "published_at": "2026-07-18T00:00:00Z",
                    "updated_at": "2026-07-19T00:00:00Z",
                    "cvss": {"score": 9.8},
                    "identifiers": [
                        {"type": "GHSA", "value": "GHSA-test-0001"},
                        {"type": "CVE", "value": "CVE-2026-0001"},
                    ],
                    "vulnerabilities": [{
                        "vulnerable_version_range": "< 15.2.2",
                        "first_patched_version": {"identifier": "15.2.2"},
                    }],
                    "html_url": "https://github.com/advisories/GHSA-test-0001",
                }]
            if "services.nvd.nist.gov" in url:
                return {"vulnerabilities": [{"cve": {
                    "id": "CVE-2026-0001",
                    "published": "2026-07-18T00:00:00Z",
                    "lastModified": "2026-07-19T00:00:00Z",
                    "descriptions": [{"lang": "en", "value": "Middleware authorization bypass"}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]},
                }}]}
            if "cisa.gov" in url:
                return {"vulnerabilities": [{"cveID": "CVE-2026-0001", "dateAdded": "2026-07-19"}]}
            if "api.first.org" in url:
                return {"data": [{
                    "cve": "CVE-2026-0001",
                    "epss": "0.91",
                    "percentile": "0.99",
                    "date": "2026-07-19",
                }]}
            raise AssertionError(url)

        first = intel_engine.build_target_intel(
            tmp_path,
            "target.com",
            techs=[],
            memory={"tested_cves": [], "patterns": [], "tested_endpoints": []},
            fetcher=fetcher,
            include_identity=False,
            now=now,
        )
        second = intel_engine.build_target_intel(
            tmp_path,
            "target.com",
            techs=[],
            memory={"tested_cves": [], "patterns": [], "tested_endpoints": []},
            fetcher=fetcher,
            include_identity=False,
            now=now,
        )

        assert first["coverage_status"] == "ready"
        assert first["stats"]["component_count"] == 1
        assert len(first["advisories"]) == 1
        assert [item["id"] for item in second["advisories"]] == ["CVE-2026-0001"]
        advisory = first["advisories"][0]
        assert advisory["id"] == "CVE-2026-0001"
        assert advisory["applicability"] == "affected"
        assert advisory["score_hint"] >= 90
        assert advisory["score_reasons"]
        assert advisory["kev"] is True
        assert advisory["epss"] == 0.91
        assert {ref["source"] for ref in advisory["source_refs"]} == {
            "osv",
            "github_advisory",
            "nvd",
        }
        artifact = json.loads(
            (tmp_path / "recon" / "target.com" / "intel.json").read_text(encoding="utf-8")
        )
        assert artifact == second
        assert artifact["advisories"][0]["score_hint"] == advisory["score_hint"]

    def test_alias_bridge_merges_previously_separate_identifiers(self):
        component = {"name": "next.js", "version": "15.2.1"}
        merged = intel_engine.merge_advisory_items([
            {"items": [{
                "id": "GHSA-test-0002",
                "aliases": [],
                "source": "osv",
                "component": component,
                "source_refs": [{"source": "osv", "id": "GHSA-test-0002", "url": "osv"}],
            }]},
            {"items": [{
                "id": "CVE-2026-0002",
                "aliases": [],
                "source": "nvd",
                "component": component,
                "source_refs": [{"source": "nvd", "id": "CVE-2026-0002", "url": "nvd"}],
            }]},
            {"items": [{
                "id": "GHSA-test-0002",
                "aliases": ["CVE-2026-0002"],
                "source": "github_advisory",
                "component": component,
                "source_refs": [{"source": "github_advisory", "id": "GHSA-test-0002", "url": "gh"}],
            }]},
        ])

        assert len(merged) == 1
        assert merged[0]["id"] == "CVE-2026-0002"
        assert merged[0]["aliases"] == ["CVE-2026-0002", "GHSA-TEST-0002"]
        assert len(merged[0]["source_refs"]) == 3

    def test_local_nuclei_signal_enriches_matching_cve_without_creating_finding(self, tmp_path):
        findings_dir = tmp_path / "findings" / "target.com"
        findings_dir.mkdir(parents=True)
        findings_path = findings_dir / "findings.json"
        original = {
            "schema_version": 1,
            "target": "target.com",
            "findings": [{
                "id": "scan-1",
                "template_id": "CVE-2026-0003",
                "source_file": "findings/target.com/cve/nuclei.txt",
                "validation_status": "unvalidated",
            }],
        }
        findings_path.write_text(json.dumps(original), encoding="utf-8")

        local = intel_engine.load_local_advisory_signals(tmp_path, "target.com")
        enriched = intel_engine.enrich_advisories(
            [{"id": "CVE-2026-0003", "aliases": ["CVE-2026-0003"]}],
            {"items": {}},
            {"items": {}},
            local,
        )

        assert local["status"] == "ok"
        assert enriched[0]["nuclei_templates"] == ["CVE-2026-0003"]
        assert enriched[0]["local_evidence_refs"][0]["finding_id"] == "scan-1"
        assert json.loads(findings_path.read_text(encoding="utf-8")) == original

    def test_all_advisory_sources_fail_but_artifact_is_published(self, tmp_path):
        live = tmp_path / "recon" / "target.com" / "live"
        live.mkdir(parents=True)
        (live / "httpx_full.txt").write_text(
            "https://target.com [200] [1234] [Target] [Next.js:15.2.1]\n",
            encoding="utf-8",
        )

        def failing_fetcher(*_args, **_kwargs):
            raise IntelSourceError("offline")

        payload = intel_engine.build_target_intel(
            tmp_path,
            "target.com",
            techs=[],
            memory={"tested_cves": [], "patterns": [], "tested_endpoints": []},
            fetcher=failing_fetcher,
            include_identity=False,
        )

        assert payload["coverage_status"] == "error"
        assert payload["advisories"] == []
        assert {source["status"] for source in payload["sources"][:3]} == {"error"}
        assert (tmp_path / "recon" / "target.com" / "intel.json").is_file()

    def test_web_intel_fills_official_zero_result_without_creating_finding(self, tmp_path):
        live = tmp_path / "recon" / "target.com" / "live"
        live.mkdir(parents=True)
        (live / "httpx_full.txt").write_text(
            "https://target.com [200] [1234] [Target] [GiveWP:4.16.3]\n",
            encoding="utf-8",
        )

        def empty_fetcher(url, **_kwargs):
            if "services.nvd.nist.gov" in url:
                return {"vulnerabilities": []}
            if "cisa.gov" in url:
                return {"vulnerabilities": []}
            if "api.first.org" in url:
                return {"data": []}
            if "api.github.com" in url:
                return []
            if "api.osv.dev" in url:
                return {"vulns": []}
            raise AssertionError(url)

        first = intel_engine.build_target_intel(
            tmp_path,
            "target.com",
            techs=[],
            memory={"tested_cves": [], "patterns": [], "tested_endpoints": []},
            fetcher=empty_fetcher,
            include_identity=False,
        )
        assert first["advisories"] == []
        assert first["intel_gaps"]["web_search_recommended"] is True
        assert first["intel_gaps"]["recommended"][0]["subject"] == "givewp@4.16.3"

        record_web_intel(tmp_path, "target.com", {
            "target": "target.com",
            "subject": "givewp@4.16.3",
            "intent": "component_advisory",
            "query": "GiveWP 4.16.3 vulnerability advisory",
            "provider": "claude-web-search",
            "status": "ok",
            "results": [{
                "url": "https://vendor.test/givewp-advisory",
                "source_tier": "A",
                "independent_source_group": "vendor-givewp-2026",
                "body_verified": True,
                "claims": [{
                    "identifiers": ["CVE-2026-63030"],
                    "component": {"name": "givewp", "version": "4.16.3"},
                    "applicability": "affected",
                    "severity": "critical",
                    "summary": "Vendor-confirmed issue",
                }],
            }],
        })
        second = intel_engine.build_target_intel(
            tmp_path,
            "target.com",
            techs=[],
            memory={"tested_cves": [], "patterns": [], "tested_endpoints": []},
            fetcher=empty_fetcher,
            include_identity=False,
        )

        assert [item["id"] for item in second["advisories"]] == ["CVE-2026-63030"]
        assert second["advisories"][0]["applicability"] == "affected"
        assert second["advisories"][0]["source_names"] == ["web_intel"]
        assert second["intel_gaps"]["web_search_recommended"] is False
        assert not (tmp_path / "findings" / "target.com" / "findings.json").exists()

    def test_web_intel_gap_is_scoped_to_component_version(self):
        gaps = intel_engine._web_intel_gap_projection(
            [
                {
                    "name": "givewp",
                    "display_name": "GiveWP",
                    "version": "4.16.2",
                    "kind": "web_component",
                },
                {
                    "name": "givewp",
                    "display_name": "GiveWP",
                    "version": "4.16.3",
                    "kind": "web_component",
                },
            ],
            [{"source": "nvd", "status": "ok"}],
            [{"component": {"name": "givewp", "version": "4.16.2"}}],
            {"covered_subjects": [], "blocked_subjects": [], "status": "missing"},
        )

        assert [item["subject"] for item in gaps["recommended"]] == ["givewp@4.16.3"]

    def test_blocked_web_intel_is_preserved_as_gap_not_clean_result(self, tmp_path):
        live = tmp_path / "recon" / "target.com" / "live"
        live.mkdir(parents=True)
        (live / "httpx_full.txt").write_text(
            "https://target.com [200] [1234] [Target] [GiveWP:4.16.3]\n",
            encoding="utf-8",
        )
        record_web_intel(tmp_path, "target.com", {
            "target": "target.com",
            "subject": "givewp@4.16.3",
            "intent": "component_advisory",
            "query": "GiveWP 4.16.3 vulnerability advisory",
            "provider": "unavailable-provider",
            "status": "blocked",
            "error": "provider unavailable",
            "results": [],
        })

        def empty_fetcher(url, **_kwargs):
            if "services.nvd.nist.gov" in url:
                return {"vulnerabilities": []}
            if "cisa.gov" in url:
                return {"vulnerabilities": []}
            if "api.first.org" in url:
                return {"data": []}
            if "api.github.com" in url:
                return []
            if "api.osv.dev" in url:
                return {"vulns": []}
            raise AssertionError(url)

        payload = intel_engine.build_target_intel(
            tmp_path,
            "target.com",
            techs=[],
            memory={"tested_cves": [], "patterns": [], "tested_endpoints": []},
            fetcher=empty_fetcher,
            include_identity=False,
        )

        web_source = next(item for item in payload["sources"] if item["source"] == "web_intel")
        assert web_source["status"] == "unavailable"
        assert payload["web_intel"]["status"] == "blocked"
        assert payload["intel_gaps"]["web_search_recommended"] is False
        assert payload["intel_gaps"]["blocked"][0]["subject"] == "givewp@4.16.3"
        assert payload["advisories"] == []
