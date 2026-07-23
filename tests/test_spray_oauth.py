"""OAuth Spray 的 localhost 成功、限速和脱敏回归。"""

from __future__ import annotations

import json
import ssl
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from tools import _spray_oauth as oauth


class OAuthHandler(BaseHTTPRequestHandler):
    posts = 0

    def log_message(self, *args):
        return

    def do_POST(self):
        type(self).posts += 1
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode("utf-8")
        fields = urllib.parse.parse_qs(raw)
        password = fields.get("password", [""])[0]
        if password == "Secret#1":
            status, payload = 200, {"access_token": "private-token", "token_type": "bearer"}
        elif password == "empty-token":
            status, payload = 200, {"access_token": ""}
        elif password == "rate":
            status, payload = 429, {"error": "slow_down"}
        elif password == "invalid-client":
            status, payload = 401, {"error": "invalid_client"}
        else:
            status, payload = 400, {"error": "invalid_grant", "error_description": "bad password"}
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def oauth_server():
    OAuthHandler.posts = 0
    server = ThreadingHTTPServer(("127.0.0.1", 0), OAuthHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/token"
    finally:
        server.shutdown()
        thread.join(timeout=2)


def _configure(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, url: str, password: str) -> None:
    users = tmp_path / "users.txt"
    passes = tmp_path / "passes.txt"
    users.write_text("alice@example.test\n", encoding="utf-8")
    passes.write_text(password + "\n", encoding="utf-8")
    passes.chmod(0o600)
    values = {
        "SPRAY_REPO_ROOT": str(tmp_path),
        "SPRAY_MODE": "oauth",
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
        "SPRAY_OAUTH_CLIENT_ID": "client",
        "SPRAY_OAUTH_CLIENT_SECRET": "client-secret",
        "SPRAY_OAUTH_SCOPE": "openid",
    }
    for key, value in values.items():
        monkeypatch.setenv(key, value)


@pytest.mark.parametrize(
    ("password", "classification"),
    [
        ("Secret#1", "valid_token"),
        ("empty-token", "ambiguous_candidate"),
        ("rate", "rate_limited"),
        ("invalid-client", "ambiguous_candidate"),
    ],
)
def test_oauth_classification_preflight_and_private_token(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    oauth_server: str,
    password: str,
    classification: str,
):
    _configure(monkeypatch, tmp_path, oauth_server, password)

    assert oauth.main() == 0
    assert OAuthHandler.posts == 0
    preflight = next(tmp_path.glob("recon/*/spray/preflight-*.json"))
    assert "client-secret" not in preflight.read_text(encoding="utf-8")
    monkeypatch.setenv("SPRAY_DRY_RUN", "false")
    monkeypatch.setenv("SPRAY_PREFLIGHT", str(preflight))

    assert oauth.main() == 0
    row = json.loads(next(tmp_path.glob("recon/*/spray/*/attempts.jsonl")).read_text(encoding="utf-8"))
    assert row["classification"] == classification
    ordinary = json.dumps(row)
    assert "password" not in row
    assert "private-token" not in ordinary
    if classification == "valid_token":
        private = next(tmp_path.glob(".private/spray/*/*/response-*.json"))
        assert "private-token" in private.read_text(encoding="utf-8")


def test_tls_verification_is_default_and_insecure_is_explicit(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("SPRAY_INSECURE", "false")
    assert oauth._ssl_context().verify_mode == ssl.CERT_REQUIRED
    monkeypatch.setenv("SPRAY_INSECURE", "true")
    assert oauth._ssl_context().verify_mode == ssl.CERT_NONE
