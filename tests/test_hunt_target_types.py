import pytest
from pathlib import Path

import hunt


def test_classify_target_recognizes_ipv4():
    assert hunt.classify_target("1.2.3.4") == {"kind": "ip", "target": "1.2.3.4"}


def test_classify_target_recognizes_cidr():
    assert hunt.classify_target("1.2.3.0/24") == {"kind": "cidr", "target": "1.2.3.0/24"}


def test_classify_target_treats_domain_as_domain():
    assert hunt.classify_target("example.com") == {"kind": "domain", "target": "example.com"}


def test_classify_target_recognizes_readable_primary_domain_list(tmp_path):
    list_file = tmp_path / "scope.txt"
    list_file.write_text("api.example.com\nshop.example.com\n", encoding="utf-8")

    assert hunt.classify_target(str(list_file)) == {
        "kind": "list",
        "target": str(list_file.resolve()),
    }


def test_classify_target_rejects_invalid_ip_like_values():
    with pytest.raises(ValueError, match="invalid IP/CIDR target"):
        hunt.classify_target("999.1.2.3")


def test_classify_target_recognizes_ipv4_with_port():
    assert hunt.classify_target("127.0.0.1:3000") == {
        "kind": "ip",
        "target": "127.0.0.1:3000",
    }
    assert hunt.classify_target("192.168.1.10:8443") == {
        "kind": "ip",
        "target": "192.168.1.10:8443",
    }


def test_classify_target_recognizes_domain_with_port():
    assert hunt.classify_target("localhost:8080") == {
        "kind": "domain",
        "target": "localhost:8080",
    }
    assert hunt.classify_target("app.example.com:8443") == {
        "kind": "domain",
        "target": "app.example.com:8443",
    }


def test_classify_target_rejects_invalid_port_range():
    # Port 0 is reserved, port > 65535 is invalid.
    with pytest.raises(ValueError, match="invalid IP/CIDR target"):
        hunt.classify_target("127.0.0.1:0")
    with pytest.raises(ValueError, match="invalid IP/CIDR target"):
        hunt.classify_target("127.0.0.1:99999")


def test_run_recon_passes_ip_target_to_subprocess(monkeypatch):
    captured = {}

    class FakeProc:
        returncode = 0

        def wait(self, timeout=None):
            captured["timeout"] = timeout
            return 0

    def fake_popen(cmd, shell, cwd, **kwargs):
        captured["cmd"] = cmd
        captured["shell"] = shell
        captured["cwd"] = cwd
        captured["start_new_session"] = kwargs.get("start_new_session")
        captured["env"] = kwargs.get("env")
        return FakeProc()

    monkeypatch.setattr(hunt.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(hunt, "_AUTH_SESSION", hunt.AuthSession(["Cookie: session=abc"]))

    assert hunt.run_recon("1.2.3.4") is True
    assert '"1.2.3.4"' in captured["cmd"]
    assert captured["shell"] is True
    assert captured["cwd"] == hunt.BASE_DIR
    assert captured["start_new_session"] is True
    assert captured["timeout"] == 1800
    assert captured["env"]["BBHUNT_AUTH_HEADERS"] == "Cookie: session=abc"
    assert captured["env"]["BBHUNT_SESSION_ID"] == hunt._AUTH_SESSION.session_id()


def test_run_recon_kills_process_group_when_wait_times_out(monkeypatch):
    captured = []

    class FakeProc:
        pid = 5150
        returncode = None

        def wait(self, timeout=None):
            raise hunt.subprocess.TimeoutExpired(cmd="recon", timeout=timeout)

    monkeypatch.setattr(hunt.subprocess, "Popen", lambda *args, **kwargs: FakeProc())
    monkeypatch.setattr(hunt.os, "getpgid", lambda pid: pid)
    monkeypatch.setattr(hunt.os, "killpg", lambda pid, sig: captured.append((pid, sig)))

    assert hunt.run_recon("example.com") is False
    assert captured


def test_run_recon_skips_empty_primary_domain_list(tmp_path, monkeypatch):
    list_file = tmp_path / "empty.txt"
    list_file.write_text("# only comments\n\n   \n", encoding="utf-8")

    popen_called = False

    def fake_popen(*args, **kwargs):
        nonlocal popen_called
        popen_called = True
        raise AssertionError("subprocess should not start for an empty list")

    monkeypatch.setattr(hunt.subprocess, "Popen", fake_popen)

    assert hunt.run_recon(str(list_file)) is False
    assert popen_called is False


def test_recon_engine_dispatches_primary_domain_list_batch():
    recon_engine = (Path(__file__).resolve().parents[1] / "tools" / "recon_engine.sh").read_text(
        encoding="utf-8"
    )

    assert "run_domain_list_batch()" in recon_engine
    assert 'if [ -f "$TARGET" ] && [ -r "$TARGET" ]; then' in recon_engine
    assert 'run_domain_list_batch "$TARGET" "$QUICK_MODE"' in recon_engine
    assert "batch_manifest.jsonl" in recon_engine
    assert "batch_summary.md" in recon_engine
    assert "ai_handoff.md" in recon_engine
    assert "surface_ranking.txt" in recon_engine
    assert "high_value_targets.json" in recon_engine
    assert "grouped_targets.tsv" in recon_engine
    assert "grouped_links" in recon_engine
    assert "BBHUNT_BATCH_SIZE" in recon_engine
    assert "BBHUNT_BATCH_RESET" in recon_engine
    assert 'bash "$SCRIPT_PATH" "$batch_target" "$quick_mode" </dev/null' in recon_engine
    assert "phase                batch_recon" in recon_engine
    assert 'TARGET_KIND="list"' not in recon_engine
    assert "Domain-list target" not in recon_engine
    assert "resolve_pd_httpx" in recon_engine
    assert '"$HTTPX_BIN" -l "$HTTPX_INPUT_FILE"' in recon_engine


def test_hunt_target_list_recon_stops_before_aggregate_scan(monkeypatch, tmp_path):
    list_file = tmp_path / "targets.txt"
    list_file.write_text("example.com\nbe.com.vn\n", encoding="utf-8")

    seen = {"recon": [], "scan": [], "reports": [], "profile": [], "summary": [], "state": []}
    recon_root = tmp_path / "recon"
    batch_dir = recon_root / "targets"
    batch_dir.mkdir(parents=True)
    (batch_dir / "batch_manifest.jsonl").write_text(
        '{"target":"example.com","status":"ok"}\n',
        encoding="utf-8",
    )
    (batch_dir / "completed_targets.txt").write_text("example.com\n", encoding="utf-8")
    (batch_dir / "failed_targets.txt").write_text("", encoding="utf-8")

    monkeypatch.setattr(hunt, "RECON_DIR", str(recon_root))
    monkeypatch.setattr(hunt, "run_recon", lambda target, quick=False: seen["recon"].append(target) or True)
    monkeypatch.setattr(hunt, "run_vuln_scan", lambda target, **_kwargs: seen["scan"].append(target) or True)
    monkeypatch.setattr(hunt, "generate_reports", lambda target: seen["reports"].append(target) or 0)
    monkeypatch.setattr(
        hunt,
        "_run_classic_enrichment_hints",
        lambda target, **_kwargs: (_ for _ in ()).throw(AssertionError("list batch must not enrich aggregate dir")),
    )
    monkeypatch.setattr(
        hunt,
        "_update_target_profile",
        lambda target, *, elapsed_minutes=0, recon_completed=False: seen["profile"].append((target, recon_completed)),
    )
    monkeypatch.setattr(
        hunt,
        "_auto_log_session_summary",
        lambda target, **kwargs: seen["summary"].append((target, kwargs)),
    )
    monkeypatch.setattr(
        hunt,
        "_persist_runtime_state",
        lambda target, **kwargs: seen["state"].append((target, kwargs)),
    )

    result = hunt.hunt_target(str(list_file))

    assert result["batch"] is True
    assert result["recon"] is True
    assert result["scan"] is False
    assert result["reports"] == 0
    assert result["batch_completed_count"] == 1
    assert result["batch_failed_count"] == 0
    assert seen["recon"] == [str(list_file.resolve())]
    assert seen["scan"] == []
    assert seen["reports"] == []
    assert seen["profile"] == [(str(list_file.resolve()), True)]
    assert seen["state"][0][1]["mode"] == "batch_recon"


def test_hunt_target_uses_canonical_cidr_across_followup_paths(monkeypatch):
    seen = {
        "recon": [],
        "scan": [],
        "profile": [],
        "summary": [],
        "reports": [],
    }

    monkeypatch.setattr(hunt, "run_recon", lambda target, quick=False: seen["recon"].append(target) or True)
    monkeypatch.setattr(hunt, "run_vuln_scan", lambda target, **_kwargs: seen["scan"].append(target) or True)
    monkeypatch.setattr(
        hunt,
        "_update_target_profile",
        lambda target, *, elapsed_minutes=0, recon_completed=False: seen["profile"].append(target),
    )
    monkeypatch.setattr(
        hunt,
        "_auto_log_session_summary",
        lambda target, **kwargs: seen["summary"].append(target),
    )
    monkeypatch.setattr(hunt, "generate_reports", lambda target: seen["reports"].append(target) or 0)

    result = hunt.hunt_target("1.2.3.4/24")

    assert result["domain"] == "1.2.3.0/24"
    assert seen == {
        "recon": ["1.2.3.0/24"],
        "scan": ["1.2.3.0/24"],
        "profile": ["1.2.3.0/24"],
        "summary": ["1.2.3.0/24"],
        "reports": [],
    }
    assert result["reports"] == 0


def test_hunt_target_captures_browser_evidence_when_url_provided(monkeypatch):
    captured = {}

    monkeypatch.setattr(hunt, "run_recon", lambda target, quick=False: True)
    monkeypatch.setattr(hunt, "run_vuln_scan", lambda target, **_kwargs: True)
    monkeypatch.setattr(hunt, "generate_reports", lambda target: 0)
    monkeypatch.setattr(hunt, "_update_target_profile", lambda target, **_kwargs: None)
    monkeypatch.setattr(hunt, "_auto_log_session_summary", lambda target, **_kwargs: None)

    def fake_capture(target, browser_url="", browser_session="", capture_screenshot=False):
        captured["target"] = target
        captured["url"] = browser_url
        captured["session"] = browser_session
        captured["capture_screenshot"] = capture_screenshot
        return {"dir": "/tmp/evidence/target.local/browser/cap", "url": browser_url}

    monkeypatch.setattr(hunt, "_capture_browser_evidence_for_hunt", fake_capture)

    result = hunt.hunt_target(
        "target.local",
        browser_url="https://target.local/app",
        browser_session="reuse-me",
    )

    assert captured == {
        "target": "target.local",
        "url": "https://target.local/app",
        "session": "reuse-me",
        "capture_screenshot": False,
    }
    assert result["browser_evidence"]["dir"].endswith("/browser/cap")


def test_hunt_target_does_not_touch_browser_helper_without_url(monkeypatch):
    monkeypatch.setattr(hunt, "run_recon", lambda target, quick=False: True)
    monkeypatch.setattr(hunt, "run_vuln_scan", lambda target, **_kwargs: True)
    monkeypatch.setattr(hunt, "generate_reports", lambda target: 0)
    monkeypatch.setattr(hunt, "_update_target_profile", lambda target, **_kwargs: None)
    monkeypatch.setattr(hunt, "_auto_log_session_summary", lambda target, **_kwargs: None)

    def fail_capture(*_args, **_kwargs):
        raise AssertionError("browser helper must not run without --browser-url")

    monkeypatch.setattr(hunt, "_capture_browser_evidence_for_hunt", fail_capture)

    result = hunt.hunt_target("target.local")

    assert "browser_evidence" not in result


def test_run_vuln_scan_uses_cidr_storage_dir(monkeypatch, tmp_path):
    recon_root = tmp_path / "recon"
    findings_root = tmp_path / "findings"
    reports_root = tmp_path / "reports"
    stored_recon_dir = recon_root / "1.2.3.0_24"
    stored_recon_dir.mkdir(parents=True)

    monkeypatch.setattr(hunt, "RECON_DIR", str(recon_root))
    monkeypatch.setattr(hunt, "FINDINGS_DIR", str(findings_root))
    monkeypatch.setattr(hunt, "REPORTS_DIR", str(reports_root))

    captured = {}

    class FakeProc:
        returncode = 0

        def wait(self, timeout=None):
            captured["timeout"] = timeout
            return 0

    def fake_popen(cmd, shell, cwd, **kwargs):
        captured["cmd"] = cmd
        captured["shell"] = shell
        captured["cwd"] = cwd
        captured["start_new_session"] = kwargs.get("start_new_session")
        return FakeProc()

    monkeypatch.setattr(hunt.subprocess, "Popen", fake_popen)

    assert hunt.run_vuln_scan("1.2.3.0/24") is True
    assert str(stored_recon_dir) in captured["cmd"]
    assert "1.2.3.0/24" not in captured["cmd"]
    assert captured["cwd"] == hunt.BASE_DIR
    assert captured["start_new_session"] is True
    assert captured["timeout"] == 1800


def test_run_vuln_scan_passes_scanner_full_and_skip_flags(monkeypatch, tmp_path):
    recon_root = tmp_path / "recon"
    stored_recon_dir = recon_root / "example.com"
    stored_recon_dir.mkdir(parents=True)

    monkeypatch.setattr(hunt, "RECON_DIR", str(recon_root))

    captured = {}

    class FakeProc:
        returncode = 0

        def wait(self, timeout=None):
            captured["timeout"] = timeout
            return 0

    def fake_popen(cmd, shell, cwd, **kwargs):
        captured["cmd"] = cmd
        captured["shell"] = shell
        captured["cwd"] = cwd
        captured["start_new_session"] = kwargs.get("start_new_session")
        return FakeProc()

    monkeypatch.setattr(hunt.subprocess, "Popen", fake_popen)

    assert hunt.run_vuln_scan(
        "example.com",
        quick=True,
        scanner_full=True,
        scanner_skip="xss,ssti,mfa",
    ) is True
    assert "--full" in captured["cmd"]
    assert "--quick" not in captured["cmd"]
    assert "--skip xss,ssti,mfa" in captured["cmd"]
    assert str(stored_recon_dir) in captured["cmd"]


def test_run_vuln_scan_kills_process_group_when_wait_times_out(monkeypatch, tmp_path):
    recon_root = tmp_path / "recon"
    stored_recon_dir = recon_root / "example.com"
    stored_recon_dir.mkdir(parents=True)
    monkeypatch.setattr(hunt, "RECON_DIR", str(recon_root))

    captured = []

    class FakeProc:
        pid = 6160
        returncode = None

        def wait(self, timeout=None):
            raise hunt.subprocess.TimeoutExpired(cmd="scan", timeout=timeout)

    monkeypatch.setattr(hunt.subprocess, "Popen", lambda *args, **kwargs: FakeProc())
    monkeypatch.setattr(hunt.os, "getpgid", lambda pid: pid)
    monkeypatch.setattr(hunt.os, "killpg", lambda pid, sig: captured.append((pid, sig)))

    assert hunt.run_vuln_scan("example.com") is False
    assert captured


def test_generate_reports_uses_cidr_storage_dirs(monkeypatch, tmp_path):
    findings_root = tmp_path / "findings"
    reports_root = tmp_path / "reports"
    stored_findings_dir = findings_root / "1.2.3.0_24"
    stored_report_dir = reports_root / "1.2.3.0_24"
    stored_findings_dir.mkdir(parents=True)
    stored_report_dir.mkdir(parents=True)
    (stored_report_dir / "test.md").write_text("ok", encoding="utf-8")

    monkeypatch.setattr(hunt, "FINDINGS_DIR", str(findings_root))
    monkeypatch.setattr(hunt, "REPORTS_DIR", str(reports_root))

    captured = {}

    def fake_generate_legacy_reports(findings_dir, *, base_dir, timeout=600):
        captured["findings_dir"] = findings_dir
        captured["base_dir"] = base_dir
        captured["timeout"] = timeout
        return True, "generated"

    monkeypatch.setattr(hunt, "generate_legacy_reports", fake_generate_legacy_reports)

    assert hunt.generate_reports("1.2.3.0/24") == 1
    assert captured["findings_dir"] == str(stored_findings_dir)
    assert captured["base_dir"] == hunt.BASE_DIR
    assert captured["timeout"] == 600
