"""Regression tests for lightweight hunt.py helper wrappers."""

import base64
import json
import os
import sys
import threading
import types
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import hunt
import pytest
from memory.hunt_journal import HuntJournal
from memory.target_profile import target_profile_path
from tools.auth_session import AuthSession


def _b64url_json(data):
    raw = json.dumps(data, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def test_check_tools_includes_runnable_external_eburst(monkeypatch):
    monkeypatch.setattr(hunt, "resolve_eburst", lambda: {"status": "ready"})
    monkeypatch.setattr(hunt, "run_cmd", lambda command, **_kwargs: (command.endswith("subfinder"), ""))

    installed, missing = hunt.check_tools()

    assert "eburst" in installed
    assert "eburst" not in missing


def test_runtime_child_env_exports_only_allowlisted_credentials(monkeypatch, tmp_path):
    (tmp_path / ".env").write_text(
        "CHAOS_API_KEY=file-chaos\nH1_API_TOKEN=file-h1\nRESIN_PROXY_TOKEN=file-resin\nUNRELATED_SECRET=private\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(hunt, "BASE_DIR", str(tmp_path))
    monkeypatch.setenv("CHAOS_API_KEY", "shell-chaos")
    monkeypatch.setenv("H1_API_TOKEN", "shell-h1")

    child_env = hunt._runtime_child_env("CHAOS_API_KEY")

    assert child_env["CHAOS_API_KEY"] == "shell-chaos"
    assert "H1_API_TOKEN" not in child_env
    assert "RESIN_PROXY_TOKEN" not in child_env
    assert "UNRELATED_SECRET" not in child_env
    assert all(key not in hunt._runtime_child_env() for key in hunt._MANAGED_CREDENTIAL_KEYS)


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

    class FakeOpener:
        def open(self, request, **kwargs):
            return fake_urlopen(request, **kwargs)

    monkeypatch.setattr(
        hunt,
        "_AUTH_SESSION",
        AuthSession(
            ["Authorization: Bearer secret-token"],
            target="example.com",
        ),
    )
    monkeypatch.setattr(hunt, "build_opener", lambda *_handlers: FakeOpener())

    status, body, headers = hunt._fetch_url_raw(
        "https://api.example.com/v1/users/1",
        headers={"X-Test": "1"},
    )

    assert status == 200
    assert body == "ok"
    assert headers == {}
    assert captured["headers"]["authorization"] == "Bearer secret-token"
    assert captured["headers"]["x-test"] == "1"


def test_fetch_url_raw_strips_auth_on_cross_target_redirect(monkeypatch):
    observed = {"first": "", "redirected": ""}

    class RedirectedHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            observed["redirected"] = self.headers.get("Authorization", "")
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *_args):
            return

    class InitialHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            observed["first"] = self.headers.get("Authorization", "")
            self.send_response(302)
            self.send_header(
                "Location",
                f"http://127.0.0.1:{redirected.server_port}/final",
            )
            self.end_headers()

        def log_message(self, *_args):
            return

    try:
        redirected = ThreadingHTTPServer(("127.0.0.1", 0), RedirectedHandler)
        initial = ThreadingHTTPServer(("127.0.0.1", 0), InitialHandler)
    except PermissionError:
        if "redirected" in locals():
            redirected.server_close()
        pytest.skip("sandbox forbids creating a local listening socket")
    threads = [
        threading.Thread(target=server.serve_forever, daemon=True)
        for server in (initial, redirected)
    ]
    for thread in threads:
        thread.start()

    try:
        monkeypatch.setattr(
            hunt,
            "_AUTH_SESSION",
            AuthSession(
                ["Authorization: Bearer secret-token"],
                target=f"127.0.0.1:{initial.server_port}",
            ),
        )
        status, body, _headers = hunt._fetch_url_raw(
            f"http://127.0.0.1:{initial.server_port}/start"
        )
    finally:
        initial.shutdown()
        redirected.shutdown()
        initial.server_close()
        redirected.server_close()

    assert (status, body) == (200, "ok")
    assert observed["first"] == "Bearer secret-token"
    assert observed["redirected"] == ""


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

    def fake_run_argv(cmd, cwd=None, timeout=600, env=None):
        if cmd[0] == "jwt_tool" and "-C" in cmd and cmd[cmd.index("-d") + 1] == "/root/Tools/jwt_tool/jwt.secrets.list":
            return True, (
                "\x1b[32mHeader:\x1b[0m {'alg': 'HS256', 'typ': 'JWT'}\n"
                "Payload: {'sub': '123', 'role': 'admin'}\n"
                "jwt.secrets.list loaded\n"
                "Signature is valid\n"
            )
        raise AssertionError(f"unexpected command: {cmd!r}")

    monkeypatch.setattr(hunt, "run_argv", fake_run_argv)

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


def test_nuclei_scan_passes_output_and_input_paths_as_argv(tmp_path, monkeypatch):
    output_path = tmp_path / "findings output" / "nuclei.txt"
    captured = {}
    input_paths = []
    monkeypatch.setattr(hunt, "_command_exists", lambda _tool: True)

    def fake_run_argv(argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        input_path = Path(argv[argv.index("-l") + 1])
        input_paths.append(input_path)
        captured["input_path"] = input_path
        assert input_path.read_text(encoding="utf-8") == "https://example.test/a?x=1&y=2\n"
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text("finding\n", encoding="utf-8")
        return True, ""

    monkeypatch.setattr(hunt, "run_argv", fake_run_argv)

    assert hunt._run_nuclei_scan(
        ["https://example.test/a?x=1&y=2"],
        tags="cve,exposure",
        output_path=str(output_path),
    ) is True
    assert captured["argv"][:2] == ["nuclei", "-l"]
    assert captured["input_path"].parent == output_path.parent
    assert captured["input_path"].name.startswith("_nuclei_targets_")
    assert not captured["input_path"].exists()
    assert captured["argv"][captured["argv"].index("-output") + 1] == str(output_path)
    assert captured["kwargs"]["cwd"] == hunt.BASE_DIR

    assert hunt._run_nuclei_scan(
        ["https://example.test/a?x=1&y=2"],
        tags="cve,exposure",
        output_path=str(output_path),
    ) is True
    assert len(input_paths) == 2
    assert len({path.name for path in input_paths}) == 2
    assert all(not path.exists() for path in input_paths)


def test_sqlmap_helpers_keep_url_and_request_path_as_single_argv(tmp_path, monkeypatch):
    domain = "example.test"
    monkeypatch.setattr(hunt, "FINDINGS_DIR", str(tmp_path / "findings output"))
    monkeypatch.setattr(hunt, "_collect_param_urls", lambda *_args, **_kwargs: [
        "https://example.test/item?id=1&next=%3Btouch"
    ])
    monkeypatch.setattr(hunt, "_command_exists", lambda _tool: True)
    calls = []
    monkeypatch.setattr(
        hunt,
        "run_argv",
        lambda argv, **_kwargs: calls.append(argv) or (True, "sqlmap output"),
    )

    assert hunt.run_sqlmap_targeted(domain) is True
    request_file = tmp_path / "request with spaces.txt"
    request_file.write_text("GET / HTTP/1.1\n", encoding="utf-8")
    assert hunt.run_sqlmap_request_file(str(request_file), domain=domain) is True

    assert calls[0][calls[0].index("-u") + 1] == "https://example.test/item?id=1&next=%3Btouch"
    assert calls[1][calls[1].index("-r") + 1] == str(request_file)
    assert all(isinstance(argv, list) for argv in calls)


def test_zero_day_fuzzer_passes_ipv6_recon_dir_and_deep_as_argv(tmp_path, monkeypatch):
    domain = "2001:db8::1"
    recon_dir = tmp_path / "recon output" / domain
    recon_dir.mkdir(parents=True)
    monkeypatch.setattr(hunt, "RECON_DIR", str(tmp_path / "recon output"))
    captured = {}

    class FakeProc:
        returncode = 0

        def wait(self, timeout=None):
            captured["timeout"] = timeout

    def fake_popen(argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return FakeProc()

    monkeypatch.setattr(hunt.subprocess, "Popen", fake_popen)

    assert hunt.run_zero_day_fuzzer(domain, deep=True) is True
    assert captured["argv"][0] == sys.executable
    assert captured["argv"][2] == "https://[2001:db8::1]"
    assert "--recon-dir" in captured["argv"]
    assert captured["argv"][captured["argv"].index("--recon-dir") + 1] == str(recon_dir)
    assert "--deep" in captured["argv"]
    assert "--adaptive-budget" in captured["argv"]
    assert captured["kwargs"]["shell"] is False


def test_setup_wordlists_uses_argv_for_curl_paths(tmp_path, monkeypatch):
    monkeypatch.setattr(hunt, "WORDLIST_DIR", str(tmp_path / "word lists"))
    calls = []

    def fake_run_argv(argv, **_kwargs):
        calls.append(argv)
        output_path = Path(argv[argv.index("-o") + 1])
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text("x" * 101, encoding="utf-8")
        return True, ""

    monkeypatch.setattr(hunt, "run_argv", fake_run_argv)
    hunt.setup_wordlists()

    assert len(calls) == 4
    assert all(argv[0:2] == ["curl", "-sL"] for argv in calls)
    assert all("-o" in argv for argv in calls)
    assert all(isinstance(argv, list) for argv in calls)


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


def test_run_cve_hunt_uses_direct_argv(monkeypatch, tmp_path):
    domain = "example.com"
    monkeypatch.setattr(hunt, "RECON_DIR", str(tmp_path / "recon"))
    (tmp_path / "recon" / domain).mkdir(parents=True, exist_ok=True)

    called = {}

    def fake_run_argv(argv, *, cwd=None, timeout=600, env=None):
        called.update({"argv": argv, "cwd": cwd, "timeout": timeout, "env": env})
        return True, "ok"

    monkeypatch.setattr(hunt, "run_argv", fake_run_argv)

    assert hunt.run_cve_hunt(domain) is True
    assert called == {
        "argv": [
            sys.executable,
            os.path.join(hunt.BASE_DIR, "tools", "cve_hunter.py"),
            domain,
            "--recon-dir",
            hunt._resolve_recon_dir(domain),
        ],
        "cwd": hunt.BASE_DIR,
        "timeout": 600,
        "env": None,
    }


def test_generate_reports_uses_direct_argv(monkeypatch, tmp_path):
    domain = "example.com"
    monkeypatch.setattr(hunt, "FINDINGS_DIR", str(tmp_path / "findings"))
    monkeypatch.setattr(hunt, "REPORTS_DIR", str(tmp_path / "reports"))

    findings_dir = Path(hunt._resolve_findings_dir(domain))
    report_dir = Path(hunt._resolve_reports_dir(domain, create=True))
    findings_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / "alpha.md").write_text("ok", encoding="utf-8")

    called = {}

    def fake_run_argv(argv, *, cwd=None, timeout=600, env=None):
        called.update({"argv": argv, "cwd": cwd, "timeout": timeout, "env": env})
        return True, "generated"

    monkeypatch.setattr(hunt, "run_argv", fake_run_argv)

    assert hunt.generate_reports(domain) == 1
    assert called == {
        "argv": [
            sys.executable,
            os.path.join(hunt.BASE_DIR, "tools", "report_generator.py"),
            str(findings_dir),
        ],
        "cwd": hunt.BASE_DIR,
        "timeout": 600,
        "env": None,
    }


def test_generate_reports_prefers_current_generation_count_from_generator_output(monkeypatch, tmp_path):
    domain = "example.com"
    monkeypatch.setattr(hunt, "FINDINGS_DIR", str(tmp_path / "findings"))
    monkeypatch.setattr(hunt, "REPORTS_DIR", str(tmp_path / "reports"))

    findings_dir = Path(hunt._resolve_findings_dir(domain))
    report_dir = Path(hunt._resolve_reports_dir(domain, create=True))
    findings_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / "old.md").write_text("old report", encoding="utf-8")

    monkeypatch.setattr(
        hunt,
        "run_argv",
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
    monkeypatch.setattr(hunt, "run_source_intel", lambda target, repo_path="", repo_url="": calls.append(("source", target, repo_path, repo_url)) or True)
    monkeypatch.setattr(hunt, "run_js_read", lambda target: calls.append(("js", target)) or True)
    monkeypatch.setattr(
        hunt,
        "_load_classic_autopilot_state",
        lambda target: {
            "next_tool_hint": "collect_browser_mcp_evidence",
            "enrichment_hints": [
                {"tool": "collect_browser_mcp_evidence", "reason": "app-like surface present"},
                {"tool": "run_source_intel", "reason": "repo source artifacts exist"},
                {"tool": "run_js_read", "reason": "cached JS artifacts exist"},
            ],
        },
    )

    result = hunt.hunt_target(domain)

    assert result["enrichment"] == ["run_source_intel", "run_js_read"]
    assert calls == [
        ("recon", domain),
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


def test_classic_full_run_releases_recon_lock_before_scan(monkeypatch, tmp_path):
    from runtime_state import runtime_phase_is_active

    domain = "example.com"
    monkeypatch.setattr(hunt, "RECON_DIR", str(tmp_path / "recon"))
    monkeypatch.setattr(hunt, "run_recon", lambda *_args, **_kwargs: (
        runtime_phase_is_active(tmp_path, domain, "recon")
        and not runtime_phase_is_active(tmp_path, domain, "scan")
    ))
    monkeypatch.setattr(hunt, "run_vuln_scan", lambda *_args, **_kwargs: (
        not runtime_phase_is_active(tmp_path, domain, "recon")
        and runtime_phase_is_active(tmp_path, domain, "scan")
    ))
    monkeypatch.setattr(hunt, "_run_classic_enrichment_hints", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(hunt, "_update_target_profile", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(hunt, "_auto_log_session_summary", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(hunt, "_persist_runtime_state", lambda *_args, **_kwargs: None)

    result = hunt.hunt_target(domain)

    assert result["recon"] is True
    assert result["scan"] is True
    assert not runtime_phase_is_active(tmp_path, domain, "recon")
    assert not runtime_phase_is_active(tmp_path, domain, "scan")


def test_classic_hunt_target_recon_only_skips_enrichment_and_scan(monkeypatch):
    domain = "example.com"
    calls = []
    runtime_updates = []

    monkeypatch.setattr(hunt, "run_recon", lambda target, quick=False: calls.append(("recon", target)) or True)
    monkeypatch.setattr(hunt, "run_vuln_scan", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("scan must not run")))
    monkeypatch.setattr(hunt, "generate_reports", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("reports must not run")))
    monkeypatch.setattr(hunt, "_update_target_profile", lambda *args, **kwargs: None)
    monkeypatch.setattr(hunt, "_auto_log_session_summary", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        hunt,
        "_persist_runtime_state",
        lambda target, **kwargs: runtime_updates.append((target, kwargs)),
    )
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
    assert runtime_updates[0][0] == domain
    assert runtime_updates[0][1]["mode"] == "recon_running"
    assert runtime_updates[0][1]["last_completed_step"] == "run_recon_started"
    assert runtime_updates[-1][1]["mode"] == "recon_only"
    assert runtime_updates[-1][1]["last_completed_step"] == "run_recon"


def test_classic_hunt_target_busy_recon_does_not_write_runtime_marker(monkeypatch, tmp_path):
    domain = "example.com"
    runtime_updates = []
    monkeypatch.setattr(hunt, "RECON_DIR", str(tmp_path / "recon"))
    monkeypatch.setattr(
        hunt,
        "_persist_runtime_state",
        lambda target, **kwargs: runtime_updates.append((target, kwargs)),
    )
    monkeypatch.setattr(
        hunt,
        "run_recon",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("busy recon must not start")),
    )

    with hunt.runtime_phase_lock(tmp_path, domain, "recon"):
        with pytest.raises(hunt.RuntimePhaseBusy, match="recon is already running"):
            hunt.hunt_target(domain, recon_only=True)

    assert runtime_updates == []


def test_classic_hunt_target_recon_exception_closes_running_marker(monkeypatch):
    domain = "example.com"
    runtime_updates = []

    def raise_recon(*_args, **_kwargs):
        raise RuntimeError("recon crashed")

    monkeypatch.setattr(hunt, "run_recon", raise_recon)
    monkeypatch.setattr(hunt, "run_vuln_scan", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("scan must not run")))
    monkeypatch.setattr(
        hunt,
        "_persist_runtime_state",
        lambda target, **kwargs: runtime_updates.append((target, kwargs)),
    )

    with pytest.raises(RuntimeError, match="recon crashed"):
        hunt.hunt_target(domain, recon_only=True)

    assert runtime_updates[0][1]["mode"] == "recon_running"
    assert runtime_updates[0][1]["last_completed_step"] == "run_recon_started"
    assert runtime_updates[-1][1]["mode"] == "recon_only"
    assert runtime_updates[-1][1]["last_completed_step"] == "run_recon"
    assert runtime_updates[-1][1]["recon_completed"] is False


def test_classic_hunt_target_batch_profile_exception_closes_running_marker(monkeypatch, tmp_path):
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("example.com\n", encoding="utf-8")
    runtime_updates = []

    monkeypatch.setattr(hunt, "RECON_DIR", str(tmp_path / "recon"))
    monkeypatch.setattr(hunt, "run_recon", lambda target, quick=False: True)
    monkeypatch.setattr(
        hunt,
        "_persist_runtime_state",
        lambda target, **kwargs: runtime_updates.append((target, kwargs)),
    )
    monkeypatch.setattr(
        hunt,
        "_update_target_profile",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("profile crashed")),
    )
    monkeypatch.setattr(hunt, "_auto_log_session_summary", lambda *args, **kwargs: None)

    with pytest.raises(RuntimeError, match="profile crashed"):
        hunt.hunt_target(str(scope_file), recon_only=True)

    assert runtime_updates[0][1]["mode"] == "recon_running"
    assert runtime_updates[0][1]["last_completed_step"] == "run_recon_started"
    assert runtime_updates[-1][1]["mode"] == "batch_recon"
    assert runtime_updates[-1][1]["last_completed_step"] == "run_recon_batch"
    assert runtime_updates[-1][1]["recon_completed"] is True


def test_target_profile_update_does_not_rebuild_corrupt_history(monkeypatch, tmp_path):
    memory_dir = tmp_path / "hunt-memory"
    path = target_profile_path(memory_dir, "target.com")
    path.parent.mkdir(parents=True)
    path.write_text("{broken", encoding="utf-8")
    original = path.read_bytes()
    monkeypatch.setattr(hunt, "HUNT_MEMORY_DIR", str(memory_dir))

    with pytest.raises(ValueError, match=str(path)):
        hunt._update_target_profile("target.com")

    assert path.read_bytes() == original


def test_classic_hunt_target_scan_only_skips_enrichment_and_runs_scan(monkeypatch, tmp_path):
    domain = "example.com"
    calls = []
    runtime_updates = []
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
    monkeypatch.setattr(
        hunt,
        "_persist_runtime_state",
        lambda target, **kwargs: runtime_updates.append((target, kwargs)),
    )

    result = hunt.hunt_target(domain, scan_only=True)

    assert result["recon"] is False
    assert result["scan"] is True
    assert result["scan_attempted"] is True
    assert "enrichment" not in result
    assert calls == [("scan", domain)]
    assert result["reports"] == 0
    assert runtime_updates[0][0] == domain
    assert runtime_updates[0][1]["mode"] == "scan_running"
    assert runtime_updates[0][1]["last_completed_step"] == "run_scan_started"
    assert runtime_updates[-1][1]["mode"] == "scan_only"
    assert runtime_updates[-1][1]["last_completed_step"] == "run_vuln_scan"


def test_classic_hunt_target_scan_failure_is_visible(monkeypatch, tmp_path, capsys):
    domain = "example.com"
    runtime_updates = []
    (tmp_path / "recon" / domain).mkdir(parents=True)

    monkeypatch.setattr(hunt, "RECON_DIR", str(tmp_path / "recon"))
    monkeypatch.setattr(hunt, "run_vuln_scan", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(hunt, "_update_target_profile", lambda *args, **kwargs: None)
    monkeypatch.setattr(hunt, "_auto_log_session_summary", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        hunt,
        "_persist_runtime_state",
        lambda target, **kwargs: runtime_updates.append((target, kwargs)),
    )

    result = hunt.hunt_target(domain, scan_only=True)
    hunt.print_dashboard([result])
    output = capsys.readouterr().out

    assert result["success"] is False
    assert result["scan"] is False
    assert result["scan_attempted"] is True
    assert runtime_updates[-1][1]["mode"] == "scan_failed"
    assert runtime_updates[-1][1]["last_completed_step"] == "run_vuln_scan_failed"
    assert "Scan: Failed" in output


def test_classic_hunt_target_scan_exception_closes_running_marker(monkeypatch, tmp_path):
    domain = "example.com"
    runtime_updates = []
    recon_dir = tmp_path / "recon" / domain
    recon_dir.mkdir(parents=True)

    def raise_scan(*_args, **_kwargs):
        raise RuntimeError("scan crashed")

    monkeypatch.setattr(hunt, "RECON_DIR", str(tmp_path / "recon"))
    monkeypatch.setattr(hunt, "run_recon", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("recon must not run")))
    monkeypatch.setattr(hunt, "run_vuln_scan", raise_scan)
    monkeypatch.setattr(
        hunt,
        "_run_classic_enrichment_hints",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("enrichment must not run in scan-only mode")),
    )
    monkeypatch.setattr(
        hunt,
        "_persist_runtime_state",
        lambda target, **kwargs: runtime_updates.append((target, kwargs)),
    )

    with pytest.raises(RuntimeError, match="scan crashed"):
        hunt.hunt_target(domain, scan_only=True)

    assert runtime_updates[0][1]["mode"] == "scan_running"
    assert runtime_updates[0][1]["last_completed_step"] == "run_scan_started"
    assert runtime_updates[-1][1]["mode"] == "scan_failed"
    assert runtime_updates[-1][1]["last_completed_step"] == "run_vuln_scan_failed"
    assert runtime_updates[-1][1]["scan_completed"] is False


def test_classic_hunt_target_scan_interrupt_closes_running_marker(monkeypatch, tmp_path):
    domain = "example.com"
    runtime_updates = []
    recon_dir = tmp_path / "recon" / domain
    recon_dir.mkdir(parents=True)

    monkeypatch.setattr(hunt, "RECON_DIR", str(tmp_path / "recon"))
    monkeypatch.setattr(hunt, "run_recon", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("recon must not run")))
    monkeypatch.setattr(hunt, "run_vuln_scan", lambda *args, **kwargs: (_ for _ in ()).throw(KeyboardInterrupt))
    monkeypatch.setattr(
        hunt,
        "_persist_runtime_state",
        lambda target, **kwargs: runtime_updates.append((target, kwargs)),
    )

    with pytest.raises(KeyboardInterrupt):
        hunt.hunt_target(domain, scan_only=True)

    assert runtime_updates[0][1]["mode"] == "scan_running"
    assert runtime_updates[-1][1]["mode"] == "scan_failed"
    assert runtime_updates[-1][1]["last_completed_step"] == "run_vuln_scan_failed"
    assert runtime_updates[-1][1]["scan_completed"] is False
