"""Regression tests for lightweight hunt.py helper wrappers."""

import base64
import json
import os
import sys
import types
from pathlib import Path

import hunt
from memory.hunt_journal import HuntJournal
from tools.auth_session import AuthSession


def _b64url_json(data):
    raw = json.dumps(data, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def test_run_js_analysis_extracts_endpoints_and_secrets(monkeypatch, tmp_path):
    domain = "example.com"
    monkeypatch.setattr(hunt, "RECON_DIR", str(tmp_path / "recon"))
    monkeypatch.setattr(hunt, "_collect_js_urls", lambda _domain, limit=None: ["https://app.example.com/static/app.js"])
    monkeypatch.setattr(
        hunt,
        "_fetch_url",
        lambda url, **kwargs: (
            200,
            'const endpoint="/api/v1/users"; const api_key="secret12345";',
            {},
        ),
    )

    assert hunt.run_js_analysis(domain) is True

    recon_dir = Path(hunt._resolve_recon_dir(domain))
    assert (recon_dir / "js" / "endpoints.txt").read_text(encoding="utf-8").splitlines() == ["/api/v1/users"]
    assert (recon_dir / "js" / "potential_secrets.txt").read_text(encoding="utf-8").splitlines() == [
        "api_key=secret12345"
    ]


def test_fetch_url_uses_request_guard_when_enabled(monkeypatch):
    captured = {}

    class FakeResponse:
        headers = {"Content-Type": "text/plain"}

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return b"ok"

        def getcode(self):
            return 200

    def fake_preflight_request(**kwargs):
        captured["preflight"] = kwargs
        return {"allowed": True, "action": "allow"}

    def fake_record_request(**kwargs):
        captured["record"] = kwargs
        return {"action": "success"}

    monkeypatch.setitem(
        sys.modules,
        "request_guard",
        types.SimpleNamespace(
            preflight_request=fake_preflight_request,
            record_request=fake_record_request,
        ),
    )
    monkeypatch.setattr(hunt, "urlopen", lambda *_args, **_kwargs: FakeResponse())

    status, body, headers = hunt._fetch_url(
        "https://api.example.com/v1/users/1",
        target="example.com",
        use_guard=True,
        vuln_class="idor",
    )

    assert status == 200
    assert body == "ok"
    assert headers["Content-Type"] == "text/plain"
    assert captured["preflight"]["scope_domains"] == ["example.com", "*.example.com"]
    assert captured["preflight"]["vuln_class"] == "idor"
    assert captured["record"]["response_status"] == 200
    assert captured["record"]["target"] == "example.com"


def test_fetch_url_uses_cidr_scope_domains_when_guard_enabled(monkeypatch):
    captured = {}

    class FakeResponse:
        headers = {"Content-Type": "text/plain"}

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return b"ok"

        def getcode(self):
            return 200

    def fake_preflight_request(**kwargs):
        captured["preflight"] = kwargs
        return {"allowed": True, "action": "allow"}

    def fake_record_request(**kwargs):
        captured["record"] = kwargs
        return {"action": "success"}

    monkeypatch.setitem(
        sys.modules,
        "request_guard",
        types.SimpleNamespace(
            preflight_request=fake_preflight_request,
            record_request=fake_record_request,
        ),
    )
    monkeypatch.setattr(hunt, "urlopen", lambda *_args, **_kwargs: FakeResponse())

    status, body, headers = hunt._fetch_url(
        "https://1.2.3.25/api",
        target="1.2.3.0/24",
        use_guard=True,
        vuln_class="idor",
    )

    assert status == 200
    assert body == "ok"
    assert headers["Content-Type"] == "text/plain"
    assert captured["preflight"]["scope_domains"] == ["1.2.3.0/24"]
    assert captured["record"]["target"] == "1.2.3.0/24"


def test_guard_scope_domains_expands_host_list_entries(tmp_path):
    host_list = tmp_path / "scope.txt"
    host_list.write_text(
        "# comment\n"
        "api.example.com\n"
        "https://shop.example.com/account\n"
        "10.10.10.0/24\n",
        encoding="utf-8",
    )

    assert hunt._guard_scope_domains(str(host_list)) == [
        "api.example.com",
        "*.api.example.com",
        "shop.example.com",
        "*.shop.example.com",
        "10.10.10.0/24",
    ]


def test_fetch_url_raw_merges_auth_headers(monkeypatch):
    captured = {}

    class FakeResponse:
        headers = {}

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return b"ok"

        def getcode(self):
            return 200

    def fake_urlopen(request, **_kwargs):
        captured["headers"] = {
            key.lower(): value
            for key, value in request.header_items()
        }
        return FakeResponse()

    monkeypatch.setattr(hunt, "_AUTH_SESSION", AuthSession(["Authorization: Bearer secret-token"]))
    monkeypatch.setattr(hunt, "urlopen", fake_urlopen)

    status, body, headers = hunt._fetch_url_raw(
        "https://api.example.com/v1/users/1",
        headers={"X-Test": "1"},
    )

    assert status == 200
    assert body == "ok"
    assert headers == {}
    assert captured["headers"]["authorization"] == "Bearer secret-token"
    assert captured["headers"]["x-test"] == "1"


def test_fetch_url_returns_none_when_request_guard_returns_disallow(monkeypatch):
    def fake_preflight_request(**_kwargs):
        return {"allowed": False, "reason": "circuit breaker active"}

    def fail_urlopen(*_args, **_kwargs):
        raise AssertionError("urlopen should not be called when request_guard returns disallow")

    monkeypatch.setitem(
        sys.modules,
        "request_guard",
        types.SimpleNamespace(
            preflight_request=fake_preflight_request,
            record_request=lambda **_kwargs: (_ for _ in ()).throw(
                AssertionError("record_request should not run when preflight blocks")
            ),
        ),
    )
    monkeypatch.setattr(hunt, "urlopen", fail_urlopen)

    status, body, headers = hunt._fetch_url(
        "https://api.example.com/v1/users/1",
        target="example.com",
        use_guard=True,
    )

    assert (status, body, headers) == (None, "", {})


def test_fetch_url_guard_advisory_is_written_to_journal(monkeypatch, tmp_hunt_dir):
    def fake_preflight_request(**_kwargs):
        return {
            "allowed": False,
            "reason": "circuit breaker active for 25.0s",
            "action": "breaker_advisory",
            "host": "api.example.com",
        }

    monkeypatch.setitem(
        sys.modules,
        "request_guard",
        types.SimpleNamespace(
            preflight_request=fake_preflight_request,
            record_request=lambda **_kwargs: None,
        ),
    )
    monkeypatch.setattr(hunt, "HUNT_MEMORY_DIR", str(tmp_hunt_dir))
    hunt._SEEN_GUARD_BLOCKS.clear()

    status, body, headers = hunt._fetch_url(
        "https://api.example.com/v1/users/1",
        target="example.com",
        use_guard=True,
        vuln_class="idor",
    )

    entries = HuntJournal(tmp_hunt_dir / "journal.jsonl").query(
        target="example.com",
        vuln_class="guard_advisory",
    )

    assert (status, body, headers) == (None, "", {})
    assert len(entries) == 1
    assert entries[0]["result"] == "informational"
    assert entries[0]["technique"] == "request_guard"
    assert "breaker_advisory" in entries[0]["tags"]
    assert "api.example.com" in entries[0]["notes"]


def test_run_api_fuzz_uses_guarded_fetch(monkeypatch, tmp_path):
    domain = "example.com"
    monkeypatch.setattr(hunt, "FINDINGS_DIR", str(tmp_path / "findings"))
    monkeypatch.setattr(hunt, "_collect_api_endpoints", lambda *_args, **_kwargs: ["https://api.example.com/api/users/42"])

    calls = []

    def fake_fetch(url, **kwargs):
        calls.append((url, kwargs))
        return 200, "x" * 600, {}

    monkeypatch.setattr(hunt, "_fetch_url", fake_fetch)

    assert hunt.run_api_fuzz(domain) is True
    assert calls
    assert calls[0][1]["target"] == domain
    assert calls[0][1]["use_guard"] is True
    assert calls[0][1]["vuln_class"] == "idor"


def test_run_post_param_discovery_uses_guarded_fetch(monkeypatch, tmp_path):
    domain = "example.com"
    monkeypatch.setattr(hunt, "RECON_DIR", str(tmp_path / "recon"))
    monkeypatch.setattr(hunt, "_collect_live_urls", lambda *_args, **_kwargs: ["https://app.example.com/login"])
    monkeypatch.setattr(hunt, "_command_exists", lambda _tool: False)

    calls = []

    def fake_fetch(url, **kwargs):
        calls.append((url, kwargs))
        return 200, '<form method="post" action="/login"><input name="email"></form>', {}

    monkeypatch.setattr(hunt, "_fetch_url", fake_fetch)

    assert hunt.run_post_param_discovery(domain) is True
    assert calls
    assert calls[0][1]["target"] == domain
    assert calls[0][1]["use_guard"] is True
    assert calls[0][1]["is_recon"] is True


def test_run_jwt_audit_summarizes_tokens_and_jwks(monkeypatch, tmp_path):
    domain = "example.com"
    monkeypatch.setattr(hunt, "RECON_DIR", str(tmp_path / "recon"))
    monkeypatch.setattr(hunt, "FINDINGS_DIR", str(tmp_path / "findings"))

    recon_dir = Path(hunt._resolve_recon_dir(domain))
    (recon_dir / "urls").mkdir(parents=True, exist_ok=True)
    token = ".".join(
        [
            _b64url_json({"alg": "HS256", "typ": "JWT"}),
            _b64url_json({"sub": "123", "role": "admin"}),
            "signature",
        ]
    )
    (recon_dir / "notes.txt").write_text(f"Bearer {token}\n", encoding="utf-8")
    (recon_dir / "urls" / "all.txt").write_text(
        "https://api.example.com/.well-known/jwks.json\n",
        encoding="utf-8",
    )

    assert hunt.run_jwt_audit(domain) is True

    output = (Path(hunt._resolve_findings_dir(domain)) / "manual_review" / "jwt_audit.txt").read_text(
        encoding="utf-8"
    )
    assert "alg=HS256 typ=JWT" in output
    assert "claims=role,sub" in output
    assert "jwks https://api.example.com/.well-known/jwks.json" in output


def test_run_jwt_audit_appends_jwt_tool_summary_when_available(monkeypatch, tmp_path):
    domain = "example.com"
    monkeypatch.setattr(hunt, "RECON_DIR", str(tmp_path / "recon"))
    monkeypatch.setattr(hunt, "FINDINGS_DIR", str(tmp_path / "findings"))

    recon_dir = Path(hunt._resolve_recon_dir(domain))
    recon_dir.mkdir(parents=True, exist_ok=True)
    token = ".".join(
        [
            _b64url_json({"alg": "HS256", "typ": "JWT"}),
            _b64url_json({"sub": "123", "role": "admin"}),
            "signature",
        ]
    )
    (recon_dir / "notes.txt").write_text(f"Bearer {token}\n", encoding="utf-8")

    monkeypatch.setattr(hunt, "_resolve_jwt_tool_command", lambda: "jwt_tool")
    monkeypatch.setattr(hunt, "_resolve_jwt_tool_wordlist", lambda _cmd="": "/root/Tools/jwt_tool/jwt.secrets.list")

    def fake_run_cmd(cmd, cwd=None, timeout=600):
        if cmd.startswith("jwt_tool ") and " -C -d /root/Tools/jwt_tool/jwt.secrets.list" in cmd:
            return True, (
                "\x1b[32mHeader:\x1b[0m {'alg': 'HS256', 'typ': 'JWT'}\n"
                "Payload: {'sub': '123', 'role': 'admin'}\n"
                "jwt.secrets.list loaded\n"
                "Signature is valid\n"
            )
        raise AssertionError(f"unexpected command: {cmd}")

    monkeypatch.setattr(hunt, "run_cmd", fake_run_cmd)

    assert hunt.run_jwt_audit(domain) is True

    output = (Path(hunt._resolve_findings_dir(domain)) / "manual_review" / "jwt_audit.txt").read_text(
        encoding="utf-8"
    )
    assert "alg=HS256 typ=JWT" in output
    assert "jwt_tool mode=crack cmd=jwt_tool" in output
    assert "wordlist=/root/Tools/jwt_tool/jwt.secrets.list" in output
    assert "Header: {'alg': 'HS256', 'typ': 'JWT'}" in output
    assert "Payload: {'sub': '123', 'role': 'admin'}" in output


def test_resolve_jwt_tool_command_supports_root_tools_path(monkeypatch):
    target_path = os.path.expanduser("~/Tools/jwt_tool/jwt_tool.py")

    monkeypatch.setattr(hunt, "_command_exists", lambda _tool: False)
    monkeypatch.setattr(
        hunt.os.path,
        "isfile",
        lambda path: path == target_path,
    )

    assert hunt._resolve_jwt_tool_command() == f"python3 {target_path}"


def test_resolve_jwt_tool_wordlist_supports_root_tools_path(monkeypatch):
    target_path = os.path.expanduser("~/Tools/jwt_tool/jwt.secrets.list")

    monkeypatch.setattr(
        hunt.os.path,
        "isfile",
        lambda path: path == target_path,
    )

    assert hunt._resolve_jwt_tool_wordlist("python3 /root/Tools/jwt_tool/jwt_tool.py") == target_path


def test_run_repo_source_hunt_delegates_to_source_hunt(monkeypatch):
    called = {}

    def fake_run_source_hunt(**kwargs):
        called.update(kwargs)
        return {"status": "ok"}

    monkeypatch.setitem(sys.modules, "source_hunt", types.SimpleNamespace(run_source_hunt=fake_run_source_hunt))

    assert hunt.run_repo_source_hunt(
        "example.com",
        repo_url="https://github.com/octo/demo",
        allow_large_repo=True,
    ) is True
    assert called["target"] == "example.com"
    assert called["repo_url"] == "https://github.com/octo/demo"
    assert called["allow_large_repo"] is True


def test_run_browser_probe_picks_cached_app_url(monkeypatch, tmp_path):
    domain = "example.com"
    monkeypatch.setattr(hunt, "RECON_DIR", str(tmp_path / "recon"))
    recon_dir = Path(hunt._resolve_recon_dir(domain)) / "urls"
    recon_dir.mkdir(parents=True)
    (recon_dir / "all.txt").write_text(
        "https://example.com/static/app.js\nhttps://example.com/dashboard\n",
        encoding="utf-8",
    )
    called = {}

    def fake_capture(target, browser_url="", browser_session="", capture_screenshot=False):
        called["target"] = target
        called["url"] = browser_url
        called["session"] = browser_session
        called["capture_screenshot"] = capture_screenshot
        return {"dir": "/tmp/evidence"}

    monkeypatch.setattr(hunt, "_capture_browser_evidence_for_hunt", fake_capture)

    assert hunt.run_browser_probe(domain, session="logged-in") is True
    assert called == {
        "target": domain,
        "url": "https://example.com/dashboard",
        "session": "logged-in",
        "capture_screenshot": False,
    }


def test_run_source_intel_wrapper_writes_and_reads_summary(monkeypatch, tmp_path):
    domain = "example.com"
    monkeypatch.setattr(hunt, "BASE_DIR", str(tmp_path))
    monkeypatch.setattr(hunt, "FINDINGS_DIR", str(tmp_path / "findings"))
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "routes.js").write_text('router.post("/api/orders/:id/approve", handler)\n', encoding="utf-8")

    assert hunt.run_source_intel(domain, repo_path=str(repo)) is True
    summary = hunt.read_source_intel(domain)

    assert "Source Intelligence Summary" in summary
    assert "/api/orders/:id/approve" in summary


def test_run_cve_hunt_uses_legacy_bridge(monkeypatch, tmp_path):
    domain = "example.com"
    monkeypatch.setattr(hunt, "RECON_DIR", str(tmp_path / "recon"))
    (tmp_path / "recon" / domain).mkdir(parents=True, exist_ok=True)

    called = {}

    def fake_run_legacy_cve_hunt(target, *, base_dir, recon_dir=None, timeout=600):
        called.update(
            {
                "target": target,
                "base_dir": base_dir,
                "recon_dir": recon_dir,
                "timeout": timeout,
            }
        )
        return True, "ok"

    monkeypatch.setattr(hunt, "run_legacy_cve_hunt", fake_run_legacy_cve_hunt)

    class FakeProc:
        returncode = 0

        def wait(self, timeout=None):
            return 0

    monkeypatch.setattr(hunt.subprocess, "Popen", lambda *args, **kwargs: FakeProc())

    assert hunt.run_cve_hunt(domain) is True
    assert called == {
        "target": domain,
        "base_dir": hunt.BASE_DIR,
        "recon_dir": hunt._resolve_recon_dir(domain),
        "timeout": 600,
    }


def test_run_cve_hunt_compatibility_hint(monkeypatch, tmp_path, capsys):
    domain = "example.com"
    monkeypatch.setattr(hunt, "RECON_DIR", str(tmp_path / "recon"))
    (tmp_path / "recon" / domain).mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(hunt, "run_legacy_cve_hunt", lambda *args, **kwargs: (True, "ok"))

    assert hunt.run_cve_hunt(domain) is True

    output = capsys.readouterr().out.lower()
    assert "legacy compatibility path" in output
    assert "/intel" in output


def test_generate_reports_uses_legacy_bridge(monkeypatch, tmp_path):
    domain = "example.com"
    monkeypatch.setattr(hunt, "FINDINGS_DIR", str(tmp_path / "findings"))
    monkeypatch.setattr(hunt, "REPORTS_DIR", str(tmp_path / "reports"))

    findings_dir = Path(hunt._resolve_findings_dir(domain))
    report_dir = Path(hunt._resolve_reports_dir(domain, create=True))
    findings_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / "alpha.md").write_text("ok", encoding="utf-8")

    called = {}

    def fake_generate_legacy_reports(target_findings_dir, *, base_dir, timeout=600):
        called.update(
            {
                "findings_dir": target_findings_dir,
                "base_dir": base_dir,
                "timeout": timeout,
            }
        )
        return True, "generated"

    monkeypatch.setattr(hunt, "generate_legacy_reports", fake_generate_legacy_reports)

    assert hunt.generate_reports(domain) == 1
    assert called == {
        "findings_dir": str(findings_dir),
        "base_dir": hunt.BASE_DIR,
        "timeout": 600,
    }


def test_generate_reports_compatibility_hint(monkeypatch, tmp_path, capsys):
    domain = "example.com"
    monkeypatch.setattr(hunt, "FINDINGS_DIR", str(tmp_path / "findings"))
    monkeypatch.setattr(hunt, "REPORTS_DIR", str(tmp_path / "reports"))

    findings_dir = Path(hunt._resolve_findings_dir(domain))
    report_dir = Path(hunt._resolve_reports_dir(domain, create=True))
    findings_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / "compat.md").write_text("ok", encoding="utf-8")

    monkeypatch.setattr(hunt, "generate_legacy_reports", lambda *args, **kwargs: (True, "generated"))

    assert hunt.generate_reports(domain) == 1

    output = capsys.readouterr().out.lower()
    assert "legacy compatibility path" in output
    assert "/report" in output


def test_generate_reports_prefers_current_generation_count_from_legacy_output(monkeypatch, tmp_path):
    domain = "example.com"
    monkeypatch.setattr(hunt, "FINDINGS_DIR", str(tmp_path / "findings"))
    monkeypatch.setattr(hunt, "REPORTS_DIR", str(tmp_path / "reports"))

    findings_dir = Path(hunt._resolve_findings_dir(domain))
    report_dir = Path(hunt._resolve_reports_dir(domain, create=True))
    findings_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / "old.md").write_text("old report", encoding="utf-8")

    monkeypatch.setattr(
        hunt,
        "generate_legacy_reports",
        lambda *args, **kwargs: (True, "=============================================\n[+] Generated 0 reports"),
    )

    assert hunt.generate_reports(domain) == 0


def test_hunt_target_auto_logs_session_summary(monkeypatch, tmp_hunt_dir, tmp_path):
    domain = "example.com"
    monkeypatch.setattr(hunt, "HUNT_MEMORY_DIR", str(tmp_hunt_dir))
    monkeypatch.setattr(hunt, "RECON_DIR", str(tmp_path / "recon"))
    monkeypatch.setattr(hunt, "REPORTS_DIR", str(tmp_path / "reports"))
    (tmp_path / "recon" / domain).mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(hunt, "run_recon", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(hunt, "run_vuln_scan", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(hunt, "generate_reports", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(
        hunt,
        "_load_report_findings",
        lambda _domain: [{"type": "idor", "url": "https://api.example.com/api/users/1"}],
    )
    monkeypatch.setattr(hunt, "_extract_recon_tech_stack", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(hunt, "_extract_recon_candidates", lambda *_args, **_kwargs: ["/api/users/1"])

    result = hunt.hunt_target(domain)

    entries = HuntJournal(tmp_hunt_dir / "journal.jsonl").query(
        target=domain,
        vuln_class="session_summary",
    )

    assert result["success"] is True
    assert len(entries) == 1
    assert entries[0]["action"] == "hunt"
    assert "auto_logged" in entries[0]["tags"]
    assert "idor" in entries[0]["notes"]


def test_classic_hunt_target_consumes_runtime_enrichment_hints_before_scan(monkeypatch, tmp_path):
    domain = "example.com"
    calls = []

    monkeypatch.setattr(hunt, "run_recon", lambda target, quick=False: calls.append(("recon", target)) or True)
    monkeypatch.setattr(hunt, "run_vuln_scan", lambda target, **_kwargs: calls.append(("scan", target)) or True)
    monkeypatch.setattr(hunt, "generate_reports", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("reports must be explicit")))
    monkeypatch.setattr(hunt, "_update_target_profile", lambda *args, **kwargs: None)
    monkeypatch.setattr(hunt, "_auto_log_session_summary", lambda *args, **kwargs: None)
    monkeypatch.setattr(hunt, "run_browser_probe", lambda target, url="", session="": calls.append(("browser", target, url, session)) or True)
    monkeypatch.setattr(hunt, "run_source_intel", lambda target, repo_path="", repo_url="": calls.append(("source", target, repo_path, repo_url)) or True)
    monkeypatch.setattr(hunt, "run_js_read", lambda target: calls.append(("js", target)) or True)
    monkeypatch.setattr(
        hunt,
        "_load_classic_autopilot_state",
        lambda target: {
            "next_tool_hint": "run_browser_probe",
            "enrichment_hints": [
                {"tool": "run_browser_probe", "reason": "app-like surface present"},
                {"tool": "run_source_intel", "reason": "repo source artifacts exist"},
                {"tool": "run_js_read", "reason": "cached JS artifacts exist"},
            ],
        },
    )

    result = hunt.hunt_target(domain, browser_url="https://example.com/app", browser_session="reuse-me")

    assert result["enrichment"] == ["run_browser_probe", "run_source_intel", "run_js_read"]
    assert calls == [
        ("recon", domain),
        ("browser", domain, "https://example.com/app", "reuse-me"),
        ("source", domain, "", ""),
        ("js", domain),
        ("scan", domain),
    ]
    assert result["reports"] == 0


def test_classic_hunt_target_continues_when_enrichment_hint_fails(monkeypatch, tmp_path):
    domain = "example.com"
    calls = []

    monkeypatch.setattr(hunt, "run_recon", lambda target, quick=False: calls.append(("recon", target)) or True)
    monkeypatch.setattr(hunt, "run_vuln_scan", lambda target, **_kwargs: calls.append(("scan", target)) or True)
    monkeypatch.setattr(hunt, "generate_reports", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("reports must be explicit")))
    monkeypatch.setattr(hunt, "_update_target_profile", lambda *args, **kwargs: None)
    monkeypatch.setattr(hunt, "_auto_log_session_summary", lambda *args, **kwargs: None)
    monkeypatch.setattr(hunt, "run_js_read", lambda target: calls.append(("js", target)) or False)
    monkeypatch.setattr(
        hunt,
        "_load_classic_autopilot_state",
        lambda target: {
            "next_tool_hint": "run_js_read",
            "enrichment_hints": [
                {"tool": "run_js_read", "reason": "cached JS artifacts exist"},
            ],
        },
    )

    result = hunt.hunt_target(domain)

    assert result["enrichment"] == []
    assert calls == [
        ("recon", domain),
        ("js", domain),
        ("scan", domain),
    ]
    assert result["reports"] == 0


def test_classic_hunt_target_recon_only_skips_enrichment_and_scan(monkeypatch):
    domain = "example.com"
    calls = []

    monkeypatch.setattr(hunt, "run_recon", lambda target, quick=False: calls.append(("recon", target)) or True)
    monkeypatch.setattr(hunt, "run_vuln_scan", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("scan must not run")))
    monkeypatch.setattr(hunt, "generate_reports", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("reports must not run")))
    monkeypatch.setattr(hunt, "_update_target_profile", lambda *args, **kwargs: None)
    monkeypatch.setattr(hunt, "_auto_log_session_summary", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        hunt,
        "_run_classic_enrichment_hints",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("enrichment must not run")),
    )

    result = hunt.hunt_target(domain, recon_only=True)

    assert result["recon"] is True
    assert result["scan"] is False
    assert "enrichment" not in result
    assert calls == [("recon", domain)]


def test_classic_hunt_target_scan_only_skips_enrichment_and_runs_scan(monkeypatch, tmp_path):
    domain = "example.com"
    calls = []
    recon_dir = tmp_path / "recon" / domain
    recon_dir.mkdir(parents=True)

    monkeypatch.setattr(hunt, "RECON_DIR", str(tmp_path / "recon"))
    monkeypatch.setattr(hunt, "run_recon", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("recon must not run")))
    monkeypatch.setattr(hunt, "run_vuln_scan", lambda target, **_kwargs: calls.append(("scan", target)) or True)
    monkeypatch.setattr(hunt, "generate_reports", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("reports must be explicit")))
    monkeypatch.setattr(hunt, "_update_target_profile", lambda *args, **kwargs: None)
    monkeypatch.setattr(hunt, "_auto_log_session_summary", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        hunt,
        "_run_classic_enrichment_hints",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("enrichment must not run in scan-only mode")),
    )

    result = hunt.hunt_target(domain, scan_only=True)

    assert result["recon"] is False
    assert result["scan"] is True
    assert "enrichment" not in result
    assert calls == [("scan", domain)]
    assert result["reports"] == 0
