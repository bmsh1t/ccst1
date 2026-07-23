"""HTTP Spray request-spec 的 localhost 行为回归。"""

from __future__ import annotations

import json
import stat
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from tools import _spray_http_form as http_form
from tools.spray_contract import append_attempt, finish_run, prepare_run


class LoginHandler(BaseHTTPRequestHandler):
    gets = 0
    posts = 0
    last_password = ""

    def log_message(self, *args):
        return

    def do_GET(self):
        type(self).gets += 1
        body = b'<input name="csrf" value="csrf-token">'
        self.send_response(200)
        self.send_header("Set-Cookie", "preflight=cookie-token; Path=/")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        type(self).posts += 1
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if self.headers.get("Content-Type", "").startswith("application/json"):
            variables = json.loads(raw)["variables"]
            user, password, csrf = variables["username"], variables["password"], variables["csrf"]
        else:
            form = urllib.parse.parse_qs(raw.decode("utf-8"), keep_blank_values=True)
            user, password, csrf = form["username"][0], form["password"][0], form["csrf"][0]
        type(self).last_password = password
        cookie_ok = "preflight=cookie-token" in self.headers.get("Cookie", "")
        if password == "rate":
            status, body = 429, b"slow down"
        elif password == "ambiguous":
            status, body = 200, b"changed response"
        elif user == "alice@example.test" and password == 'p&+"' and csrf == "csrf-token" and cookie_ok:
            status, body = 200, b"Welcome"
        else:
            status, body = 401, b"Invalid credentials"
        self.send_response(status)
        if body == b"Welcome":
            self.send_header("Set-Cookie", "session=session-secret; Path=/")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def login_server():
    LoginHandler.gets = LoginHandler.posts = 0
    LoginHandler.last_password = ""
    server = ThreadingHTTPServer(("127.0.0.1", 0), LoginHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/login"
    finally:
        server.shutdown()
        thread.join(timeout=2)


def _configure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    url: str,
    *,
    body_format: str,
    password: str,
) -> Path:
    users = tmp_path / "users.txt"
    passes = tmp_path / "passes.txt"
    spec_path = tmp_path / "request.json"
    users.write_text("alice@example.test\n", encoding="utf-8")
    passes.write_text(password + "\n", encoding="utf-8")
    passes.chmod(0o600)
    if body_format == "form":
        body = {"username": "{USER}", "password": "{PASS}", "csrf": "{CSRF}"}
    else:
        body = {
            "query": "mutation Login",
            "variables": {"username": "{USER}", "password": "{PASS}", "csrf": "{CSRF}"},
        }
    spec_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "method": "POST",
                "url": url,
                "headers": {},
                "body_format": body_format,
                "body": body,
                "csrf": {"url": url, "regex": 'name="csrf" value="([^\"]+)"'},
                "success": {"body_regex": "Welcome", "cookie_name": "session"},
                "failure": {"body_regex": "Invalid credentials"},
                "guard": {"status_codes": [429]},
            }
        ),
        encoding="utf-8",
    )
    values = {
        "SPRAY_REPO_ROOT": str(tmp_path),
        "SPRAY_MODE": "http-form",
        "SPRAY_TARGET_URL": url,
        "SPRAY_USERS_FILE": str(users),
        "SPRAY_PASSES_FILE": str(passes),
        "SPRAY_DELAY": "0",
        "SPRAY_JITTER": "0",
        "SPRAY_CONTINUE_ON_HIT": "false",
        "SPRAY_DRY_RUN": "true",
        "SPRAY_I_UNDERSTAND": "true",
        "SPRAY_PREFLIGHT": "",
        "SPRAY_RESUME": "",
        "SPRAY_REQUEST_SPEC": str(spec_path),
    }
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    return passes


@pytest.mark.parametrize("body_format", ["form", "json"])
def test_csrf_cookie_session_and_special_password_round_trip(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    login_server: str,
    body_format: str,
):
    _configure(monkeypatch, tmp_path, login_server, body_format=body_format, password='p&+"')

    assert http_form.main() == 0
    assert LoginHandler.gets == LoginHandler.posts == 0
    preflight = next(tmp_path.glob("recon/*/spray/preflight-*.json"))
    monkeypatch.setenv("SPRAY_DRY_RUN", "false")
    monkeypatch.setenv("SPRAY_PREFLIGHT", str(preflight))

    assert http_form.main() == 0
    assert LoginHandler.gets == LoginHandler.posts == 1
    assert LoginHandler.last_password == 'p&+"'
    audit = next(tmp_path.glob("recon/*/spray/*/attempts.jsonl"))
    ordinary = audit.read_text(encoding="utf-8")
    assert 'p&+"' not in ordinary
    assert "session-secret" not in ordinary
    row = json.loads(ordinary)
    assert row["classification"] == "valid_session"
    summary = json.loads(next(tmp_path.glob("recon/*/spray/*/summary.json")).read_text(encoding="utf-8"))
    assert summary["stop_reason"] == "credential_valid"
    private = next(tmp_path.glob(".private/spray/*/*/response-*.json"))
    assert "session-secret" in private.read_text(encoding="utf-8")
    assert stat.S_IMODE(private.stat().st_mode) == 0o600


@pytest.mark.parametrize(
    ("password", "classification"),
    [("ambiguous", "ambiguous_candidate"), ("rate", "rate_limited")],
)
def test_ambiguous_and_rate_limit_stop_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    login_server: str,
    password: str,
    classification: str,
):
    _configure(monkeypatch, tmp_path, login_server, body_format="form", password=password)
    assert http_form.main() == 0
    preflight = next(tmp_path.glob("recon/*/spray/preflight-*.json"))
    monkeypatch.setenv("SPRAY_DRY_RUN", "false")
    monkeypatch.setenv("SPRAY_PREFLIGHT", str(preflight))

    assert http_form.main() == 0
    row = json.loads(next(tmp_path.glob("recon/*/spray/*/attempts.jsonl")).read_text(encoding="utf-8"))
    summary = json.loads(next(tmp_path.glob("recon/*/spray/*/summary.json")).read_text(encoding="utf-8"))
    assert row["classification"] == classification
    assert summary["status"] == "stopped"
    assert summary["stop_reason"] == classification


def test_resume_skips_recorded_builtin_attempt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    login_server: str,
):
    passes = _configure(
        monkeypatch,
        tmp_path,
        login_server,
        body_format="form",
        password="wrong",
    )
    passes.write_text('wrong\np&+"\n', encoding="utf-8")
    assert http_form.main() == 0
    preflight = next(tmp_path.glob("recon/*/spray/preflight-*.json"))
    monkeypatch.setenv("SPRAY_DRY_RUN", "false")
    monkeypatch.setenv("SPRAY_PREFLIGHT", str(preflight))
    spec = http_form.load_request_spec()
    context = prepare_run(
        "http-form",
        config_binding=http_form._binding_spec(spec),
        request_shape=http_form._request_shape(spec),
    )
    key = context.attempt_key("alice@example.test", "wrong")
    append_attempt(
        context,
        {
            "tool": "builtin",
            "round": 1,
            "user": "alice@example.test",
            "pwd_sha256_prefix": key.rsplit("\0", 1)[1],
            "attempt_key": key,
            "classification": "invalid_credentials",
            "credential_valid": False,
            "token_issued": False,
            "status_code": 401,
            "duration_ms": 1,
        },
    )
    finish_run(context, status="interrupted", stop_reason="sigint", counters={"invalid_credentials": 1}, exit_code=130)

    monkeypatch.setenv("SPRAY_PREFLIGHT", "")
    monkeypatch.setenv("SPRAY_RESUME", str(context.run_dir))
    assert http_form.main() == 0
    assert LoginHandler.posts == 1
    assert LoginHandler.last_password == 'p&+"'
    summary = json.loads(context.summary_path.read_text(encoding="utf-8"))
    assert summary["counts"] == {"invalid_credentials": 1, "valid_session": 1}
