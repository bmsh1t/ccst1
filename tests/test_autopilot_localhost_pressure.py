"""隔离 localhost 靶场上的 `/autopilot` 顺序状态压测。"""

from __future__ import annotations

import errno
import json
import resource
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from tools.action_queue import resolve_action
from tools.autopilot_state import build_autopilot_state
from tools.checkpoint import build_checkpoint
from tools.runtime_state import RuntimePhaseBusy, runtime_phase_lock, update_runtime_state
from tools.target_paths import target_storage_key


class _LabHandler(BaseHTTPRequestHandler):
    def log_message(self, _format, *_args):
        return

    def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler API
        body = b'{"service":"autopilot-local-lab"}'
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def local_lab_server():
    try:
        server = ThreadingHTTPServer(("127.0.0.1", 0), _LabHandler)
    except PermissionError as exc:
        if exc.errno == errno.EPERM:
            pytest.skip("sandbox forbids the localhost autopilot pressure target")
        raise

    import threading

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _write_recon_fixture(repo_root, target: str, base_url: str) -> None:
    recon_dir = repo_root / "recon" / target_storage_key(target)
    (recon_dir / "live").mkdir(parents=True)
    (recon_dir / "urls").mkdir()
    (recon_dir / "js").mkdir()
    (recon_dir / "live" / "httpx_full.txt").write_text(
        f"{base_url} [200] [Autopilot Local Lab] [Python] [34]\n",
        encoding="utf-8",
    )
    (recon_dir / "urls" / "api_endpoints.txt").write_text(
        f"{base_url}/api/orders?id=1\n",
        encoding="utf-8",
    )
    (recon_dir / "urls" / "with_params.txt").write_text(
        f"{base_url}/api/orders?id=1\n",
        encoding="utf-8",
    )
    (recon_dir / "urls" / "all.txt").write_text(
        f"{base_url}/api/orders?id=1\n",
        encoding="utf-8",
    )
    (recon_dir / "js" / "endpoints.txt").write_text("", encoding="utf-8")


def _write_runner_candidate(repo_root, target: str, base_url: str) -> None:
    summary = repo_root / "evidence" / target_storage_key(target) / "validation" / "local-runner" / "summary.json"
    summary.parent.mkdir(parents=True)
    summary.write_text(
        json.dumps(
            {
                "lane": "authz_role_replay",
                "finding_id": "local-runner",
                "url": f"{base_url}/api/orders?id=1",
                "method": "GET",
                "result": "tested_finding",
                "candidate_ready": True,
                "evidence_rubric": {"status": "candidate-ready", "ready": True},
            }
        ),
        encoding="utf-8",
    )


def _write_queue_candidate(repo_root, target: str) -> None:
    path = repo_root / "state" / target_storage_key(target) / "action_queue.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "target": target,
                "actions": [
                    {
                        "id": "AQ-0001",
                        "target": target,
                        "status": "candidate",
                        "type": "candidate-evidence-gap",
                        "priority": 90,
                        "action": "Review the local owner/peer evidence diff.",
                        "command_hint": "/validate local-runner",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )


def test_localhost_sequential_fresh_resume_batch_queue_runner_and_checkpoint(
    tmp_path,
    local_lab_server,
):
    host, port = local_lab_server.server_address
    target = f"{host}:{port}"
    base_url = f"http://{target}"
    memory_dir = tmp_path / "hunt-memory"

    fresh = build_autopilot_state(str(tmp_path), target, memory_dir=str(memory_dir))
    assert fresh["next_action"] == "run_recon"
    with urllib.request.urlopen(base_url, timeout=2) as response:
        assert response.status == 200

    _write_recon_fixture(tmp_path, target, base_url)
    update_runtime_state(
        tmp_path,
        target,
        mode="recon_only",
        last_executed_workflow="run_recon",
    )
    existing = build_autopilot_state(str(tmp_path), target, memory_dir=str(memory_dir))
    assert existing["has_recon"] is True
    assert existing["next_action"] == "hunt_p1"
    inventory = existing["observation_inventory"]
    assert inventory["total"] >= 1
    assert inventory["untouched"] == inventory["total"]

    scope = tmp_path / "scope.txt"
    scope.write_text(f"{target}\n", encoding="utf-8")
    batch_dir = tmp_path / "recon" / "scope"
    batch_dir.mkdir()
    (batch_dir / "completed_targets.txt").write_text(f"{target}\n", encoding="utf-8")
    (batch_dir / "high_value_targets.json").write_text(
        json.dumps([{"target": target, "score": 8}]),
        encoding="utf-8",
    )
    batch = build_autopilot_state(str(tmp_path), str(scope), memory_dir=str(memory_dir))
    assert batch["next_action"] == "select_completed_domain"
    assert batch["batch"]["candidates"][0]["target"] == target

    _write_queue_candidate(tmp_path, target)
    _write_runner_candidate(tmp_path, target, base_url)
    runner = build_autopilot_state(str(tmp_path), target, memory_dir=str(memory_dir))
    assert runner["next_action"] == "review_validation_candidate"
    assert runner["action_queue_next"]["id"] == "AQ-0001"

    summary_path = (
        tmp_path / "evidence" / target_storage_key(target) / "validation" / "local-runner" / "summary.json"
    )
    summary_path.unlink()
    queued = build_autopilot_state(str(tmp_path), target, memory_dir=str(memory_dir))
    assert queued["next_action"] == "resume_action_queue"
    resolve_action(
        tmp_path,
        target=target,
        action_id="AQ-0001",
        status="tested",
        result="local lab replay produced no owner/peer divergence",
    )

    checkpoint = build_checkpoint(
        tmp_path,
        target=target,
        memory_dir=str(memory_dir),
        refresh_coverage=False,
    )
    assert checkpoint["target"] == target
    assert checkpoint["decision"] in {"continue", "hunt", "enrich", "checkpoint", "handoff", "report"}

    rss_before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    started = time.monotonic()
    snapshots = [
        build_autopilot_state(str(tmp_path), target, memory_dir=str(memory_dir))["next_action"]
        for _ in range(12)
    ]
    elapsed_seconds = time.monotonic() - started
    rss_delta_kib = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss - rss_before
    print(
        "localhost pressure polling: "
        f"12 calls in {elapsed_seconds:.3f}s; max_rss_delta_kib={rss_delta_kib}"
    )
    assert len(set(snapshots)) == 1
    assert elapsed_seconds < 5
    assert rss_delta_kib < 64 * 1024

    with runtime_phase_lock(tmp_path, target, "recon"):
        with pytest.raises(RuntimePhaseBusy):
            with runtime_phase_lock(tmp_path, target, "recon"):
                pass
