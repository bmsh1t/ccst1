from __future__ import annotations

import os
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class _SamlFixture(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        if self.path == "/saml/login":
            self._send(200, b"SAML login")
        elif self.path == "/protected":
            if self.headers.get("Cookie") == "saml_session=accepted":
                self._send(200, b"private account dashboard")
            else:
                self._send(302, b"", location="/login")
        else:
            self._send(404, b"not found")

    def do_POST(self):  # noqa: N802
        if self.path == "/saml/login":
            self.send_response(302)
            self.send_header("Location", "/protected")
            self.send_header("Set-Cookie", "saml_session=accepted; Path=/")
            self.end_headers()
        else:
            self._send(404, b"not found")

    def _send(self, status, body, *, location=""):
        self.send_response(status)
        if location:
            self.send_header("Location", location)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        return


def _run_saml_scanner(tmp_path: Path, endpoint: str, protected_url: str = ""):
    repo_root = Path(__file__).resolve().parents[1]
    target = endpoint.split("//", 1)[1]
    run_root = tmp_path / ("with-readback" if protected_url else "status-only")
    recon_dir = run_root / "recon" / target
    findings_dir = run_root / "findings"
    (recon_dir / "live").mkdir(parents=True)
    (recon_dir / "live" / "urls.txt").write_text(endpoint + "\n", encoding="utf-8")
    env = {
        **os.environ,
        "FINDINGS_OUT_DIR": str(findings_dir),
        "BBHUNT_RUNTIME_PHASE_LOCKED": "scan",
        "BBHUNT_RUNTIME_LOCK_TARGET": target,
        "PATH": "/usr/bin:/bin",
    }
    if protected_url:
        env["BBHUNT_SAML_PROTECTED_URL"] = protected_url
    completed = subprocess.run(
        [
            "bash",
            str(repo_root / "tools" / "vuln_scanner.sh"),
            str(recon_dir),
            "--quick",
            "--skip",
            "upload,sqli,xss,ssti,takeover,misconfig,exposure,ssrf,cves,redirects,idor,auth_bypass,auth_flow,cms,mfa",
        ],
        cwd=repo_root,
        env=env,
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    return findings_dir


def test_saml_signature_stripping_requires_protected_resource_readback(tmp_path):
    server = ThreadingHTTPServer(("127.0.0.1", 0), _SamlFixture)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    endpoint = f"http://127.0.0.1:{server.server_port}"
    stale_saml = tmp_path / "status-only" / "findings" / "saml"
    stale_saml.mkdir(parents=True)
    (stale_saml / "findings.txt").write_text(
        "[SAML-SIG-STRIP] http://stale.invalid/saml/login\n", encoding="utf-8"
    )
    (stale_saml / "endpoints.txt").write_text(
        "[SAML-ENDPOINT] http://stale.invalid/saml/login | HTTP 200\n",
        encoding="utf-8",
    )
    (stale_saml / "certs.txt").write_text("STALE_CERT\n", encoding="utf-8")
    try:
        status_only = _run_saml_scanner(tmp_path, endpoint)
        proven = _run_saml_scanner(tmp_path, endpoint, endpoint + "/protected")
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()

    assert not (status_only / "saml" / "findings.txt").exists()
    review = (status_only / "manual_review" / "saml_signature_review.txt").read_text()
    assert "[SAML-SIG-STRIP-CANDIDATE]" in review
    assert "BBHUNT_SAML_PROTECTED_URL required" in review
    assert "stale.invalid" not in (status_only / "saml" / "endpoints.txt").read_text()
    assert not (status_only / "saml" / "certs.txt").exists()

    finding = (proven / "saml" / "findings.txt").read_text()
    assert "[SAML-SIG-STRIP]" in finding
    assert "anon=302" in finding
    assert "post=302" in finding
    assert "readback=200" in finding
    assert "cookie=issued" in finding
    assert not (proven / ".tmp" / "saml_signature.cookies").exists()
