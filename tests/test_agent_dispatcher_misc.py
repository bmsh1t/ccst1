"""Regression tests for misc agent dispatcher tool summaries."""

import importlib

import agent
import memory


def _build_dispatcher(tmp_path):
    memory = agent.HuntMemory(str(tmp_path / "agent_session.json"))
    return agent.ToolDispatcher("target.com", memory)


def test_dispatch_check_tools_formats_installed_and_missing(monkeypatch, tmp_path):
    dispatcher = _build_dispatcher(tmp_path)
    hunt = agent._h()
    monkeypatch.setattr(hunt, "check_tools", lambda: (["httpx", "nuclei"], ["sqlmap"]))

    output = dispatcher.dispatch("check_tools", {})

    assert "check_tools: 2 installed, 1 missing" in output
    assert "Installed: httpx, nuclei" in output
    assert "Missing: sqlmap" in output


def test_dispatch_generate_reports_summarizes_output(monkeypatch, tmp_path):
    report_dir = tmp_path / "reports" / "target.com"
    report_dir.mkdir(parents=True)
    (report_dir / "001-test.md").write_text("# report\n", encoding="utf-8")

    dispatcher = _build_dispatcher(tmp_path)
    hunt = agent._h()
    monkeypatch.setattr(hunt, "REPORTS_DIR", str(tmp_path / "reports"))
    monkeypatch.setattr(hunt, "generate_reports", lambda domain: 1)

    output = dispatcher.dispatch("generate_reports", {})

    assert "generate_reports: 1 report(s) generated" in output
    assert "Reports: 001-test.md" in output


def test_dispatch_generate_reports_bridge_backed_hunt_still_summarizes_report_count(
    monkeypatch,
    tmp_path,
):
    domain = "target.com"
    findings_dir = tmp_path / "findings" / domain
    report_dir = tmp_path / "reports" / domain
    findings_dir.mkdir(parents=True)
    report_dir.mkdir(parents=True)
    (report_dir / "001-bridge.md").write_text("# report\n", encoding="utf-8")

    dispatcher = _build_dispatcher(tmp_path)
    hunt = agent._h()
    seen = {}

    def fake_generate_legacy_reports(target_findings_dir, *, base_dir, timeout=600):
        seen["findings_dir"] = target_findings_dir
        seen["base_dir"] = base_dir
        seen["timeout"] = timeout
        return True, "generated"

    monkeypatch.setattr(hunt, "FINDINGS_DIR", str(tmp_path / "findings"))
    monkeypatch.setattr(hunt, "REPORTS_DIR", str(tmp_path / "reports"))
    monkeypatch.setattr(hunt._module, "generate_legacy_reports", fake_generate_legacy_reports)

    output = dispatcher.dispatch("generate_reports", {})

    assert seen == {
        "findings_dir": str(findings_dir),
        "base_dir": hunt.BASE_DIR,
        "timeout": 600,
    }
    assert "generate_reports: 1 report(s) generated" in output
    assert "Reports: 001-bridge.md" in output


def test_bridge_backed_hunt_agent_imports_hunt_journal_via_memory_package(monkeypatch):
    sentinel = object()

    with monkeypatch.context() as patch:
        patch.setattr(memory, "HuntJournal", sentinel)
        importlib.reload(agent)
        assert agent.HuntJournal is sentinel

    importlib.reload(agent)


def test_agent_system_mentions_intel_and_report_as_primary_workflows():
    system = agent._build_agent_system(autopilot_mode="normal")

    assert "run_intel" in system
    assert "run_source_intel" in system
    assert "run_browser_probe" in system
    assert "/intel" in system
    assert "primary /report reporting workflow" in system
    assert "generate_reports before finish" in system
    assert "findings or useful artifacts exist" in system
    assert "generate_reports" in system
    assert "/report" in system
    assert "compatibility" in system.lower()


def test_agent_system_prefers_browser_then_source_js_chain():
    system = agent._build_agent_system(autopilot_mode="normal")

    assert "run_browser_probe first" in system
    assert "prefer run_source_intel first" in system
    assert "run_js_read/read_js_intel" in system
    assert "run_js_analysis as a deeper legacy follow-up" in system


def test_new_browser_and_source_tools_are_exposed():
    assert "run_browser_probe" in agent.TOOL_NAMES
    assert "read_browser_surface" in agent.TOOL_NAMES
    assert "run_source_intel" in agent.TOOL_NAMES
    assert "read_source_intel" in agent.TOOL_NAMES
    assert "run_js_read" in agent.TOOL_NAMES
    assert "read_js_intel" in agent.TOOL_NAMES


def test_dispatch_browser_probe_and_source_intel(monkeypatch, tmp_path):
    dispatcher = _build_dispatcher(tmp_path)
    hunt = agent._h()
    seen = {}

    def fake_browser_probe(domain, url="", session=""):
        seen["browser"] = (domain, url, session)
        return True

    def fake_source_intel(domain, repo_path="", repo_url=""):
        seen["source"] = (domain, repo_path, repo_url)
        return True

    monkeypatch.setattr(hunt, "run_browser_probe", fake_browser_probe)
    monkeypatch.setattr(hunt, "read_browser_surface", lambda domain: f"BROWSER SURFACE: {domain}")
    monkeypatch.setattr(hunt, "run_source_intel", fake_source_intel)
    monkeypatch.setattr(hunt, "read_source_intel", lambda domain: f"Source Intelligence Summary {domain}")

    browser_output = dispatcher.dispatch(
        "run_browser_probe",
        {"url": "https://target.com/app", "session": "auth-session"},
    )
    source_output = dispatcher.dispatch("run_source_intel", {"repo_path": "/tmp/repo"})

    assert seen["browser"] == ("target.com", "https://target.com/app", "auth-session")
    assert seen["source"] == ("target.com", "/tmp/repo", "")
    assert "BROWSER SURFACE: target.com" in browser_output
    assert "Source Intelligence Summary target.com" in source_output


def test_dispatch_js_read(monkeypatch, tmp_path):
    dispatcher = _build_dispatcher(tmp_path)
    hunt = agent._h()
    seen = {}

    def fake_js_read(domain):
        seen["js_read"] = domain
        return True

    monkeypatch.setattr(hunt, "run_js_read", fake_js_read)
    monkeypatch.setattr(hunt, "read_js_intel", lambda domain: f"JS Reader Intel {domain}")

    output = dispatcher.dispatch("run_js_read", {})

    assert seen["js_read"] == "target.com"
    assert "JS Reader Intel target.com" in output


def test_dispatch_run_recon_uses_quick_mode_default(monkeypatch, tmp_path):
    memory = agent.HuntMemory(str(tmp_path / "agent_session.json"))
    dispatcher = agent.ToolDispatcher("target.com", memory, quick_mode=True)
    hunt = agent._h()
    seen = {}

    def fake_run_recon(domain, **kwargs):
        seen["domain"] = domain
        seen.update(kwargs)
        return True

    monkeypatch.setattr(hunt, "run_recon", fake_run_recon)

    output = dispatcher.dispatch("run_recon", {})

    assert seen == {
        "domain": "target.com",
        "scope_lock": False,
        "max_urls": 100,
        "quick": True,
    }
    assert "run_recon" in output


def test_dispatch_run_vuln_scan_passes_full_and_skip_options(monkeypatch, tmp_path):
    dispatcher = _build_dispatcher(tmp_path)
    hunt = agent._h()
    seen = {}

    def fake_run_vuln_scan(domain, **kwargs):
        seen["domain"] = domain
        seen.update(kwargs)
        return True

    monkeypatch.setattr(hunt._module, "run_vuln_scan", fake_run_vuln_scan)

    output = dispatcher.dispatch(
        "run_vuln_scan",
        {"quick": True, "full": True, "scanner_skip": "xss,ssti,mfa"},
    )

    assert seen == {
        "domain": "target.com",
        "quick": False,
        "scanner_full": True,
        "scanner_skip": "xss,ssti,mfa",
    }
    assert "run_vuln_scan" in output


def test_dispatch_run_vuln_scan_uses_quick_mode_default(monkeypatch, tmp_path):
    memory = agent.HuntMemory(str(tmp_path / "agent_session.json"))
    dispatcher = agent.ToolDispatcher("target.com", memory, quick_mode=True)
    hunt = agent._h()
    seen = {}

    def fake_run_vuln_scan(domain, **kwargs):
        seen["domain"] = domain
        seen.update(kwargs)
        return True

    monkeypatch.setattr(hunt._module, "run_vuln_scan", fake_run_vuln_scan)

    output = dispatcher.dispatch("run_vuln_scan", {})

    assert seen == {
        "domain": "target.com",
        "quick": True,
        "scanner_full": False,
        "scanner_skip": "",
    }
    assert "run_vuln_scan" in output


def test_dispatch_run_vuln_scan_full_overrides_quick_mode_default(monkeypatch, tmp_path):
    memory = agent.HuntMemory(str(tmp_path / "agent_session.json"))
    dispatcher = agent.ToolDispatcher("target.com", memory, quick_mode=True)
    hunt = agent._h()
    seen = {}

    def fake_run_vuln_scan(domain, **kwargs):
        seen["domain"] = domain
        seen.update(kwargs)
        return True

    monkeypatch.setattr(hunt._module, "run_vuln_scan", fake_run_vuln_scan)

    output = dispatcher.dispatch("run_vuln_scan", {"full": True})

    assert seen == {
        "domain": "target.com",
        "quick": False,
        "scanner_full": True,
        "scanner_skip": "",
    }
    assert "run_vuln_scan" in output
