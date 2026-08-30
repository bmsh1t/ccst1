from __future__ import annotations

import json
import os
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from tools.autopilot_state import build_autopilot_state
from tools.finding_index import verify_finding_owner_provenance


class _GraphQLFixture(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        if "__schema" in body:
            payload = {"data": {"__schema": {"queryType": {"name": "Query"}, "types": []}}}
        elif "usr" in body:
            payload = {"errors": [{"message": "Did you mean 'user'?"}]}
        else:
            payload = {"data": {"__typename": "Query"}}
        encoded = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, _format, *_args):
        return


def test_graphql_audit_publishes_target_owned_candidate_visible_to_autopilot(tmp_path):
    repo_root = Path(__file__).resolve().parents[1]
    server = ThreadingHTTPServer(("127.0.0.1", 0), _GraphQLFixture)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    target = f"127.0.0.1:{server.server_port}"
    endpoint = f"http://{target}/graphql"
    try:
        completed = subprocess.run(
            ["bash", str(repo_root / "tools" / "graphql_audit.sh"), endpoint],
            cwd=repo_root,
            env={
                **os.environ,
                "BBHUNT_BASE_DIR": str(tmp_path),
                "GQL_CURL_TIMEOUT": "2",
                "HOME": str(tmp_path / "home"),
            },
            text=True,
            capture_output=True,
            timeout=20,
            check=False,
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()

    assert completed.returncode == 0, completed.stdout + completed.stderr
    findings_dir = tmp_path / "findings" / target
    summaries = list((findings_dir / "graphql").glob("*/run-summary.json"))
    assert len(summaries) == 1
    summary = json.loads(summaries[0].read_text(encoding="utf-8"))
    assert summary["target"] == target
    assert summary["endpoint"] == endpoint
    assert summary["signals"] == ["introspection_enabled", "field_suggestions"]
    assert summary["artifact_count"] >= 4
    assert all(item["ref"].startswith(f"findings/{target}/graphql/") for item in summary["artifacts"])
    assert all(len(item["sha256"]) == 64 for item in summary["artifacts"])

    index = json.loads((findings_dir / "findings.json").read_text(encoding="utf-8"))
    assert index["total"] == 1
    finding = index["findings"][0]
    assert finding["vuln_class"] == "GraphQL"
    assert finding["validation_status"] == "candidate"
    assert finding["rubric"]["ready"] is False
    assert verify_finding_owner_provenance(findings_dir, finding, target=target)["valid"] is True

    state = build_autopilot_state(tmp_path, target)
    assert state["structured_findings"]["pending_validation"] == 1
    assert state["structured_findings"]["next_validation"]["id"] == finding["id"]
