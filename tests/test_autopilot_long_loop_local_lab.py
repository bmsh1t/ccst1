"""Local compound-target witnesses for bounded Autopilot round recovery."""

from __future__ import annotations

import json
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.request import urlopen

import pytest

import tools.autopilot_round as autopilot_round_module
import tools.autopilot_state as autopilot_state_module
import tools.checkpoint as checkpoint_module
from tools.action_queue import (
    build_action,
    claim_next_action,
    load_queue,
    resolve_action,
    save_queue,
    upsert_actions,
)
from tools.autopilot_round import prepare_round, settle_round
from tools.checkpoint import record_round_lane, record_round_lane_result
from tools.target_paths import target_storage_key


REPO_ROOT = Path(__file__).resolve().parents[1]


class _CompoundHandler(BaseHTTPRequestHandler):
    def log_message(self, _format, *_args):
        return

    def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler API
        server = self.server
        server.paths.append(self.path)  # type: ignore[attr-defined]
        body = json.dumps({"path": self.path, "marker": "local-lab"}).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _CompoundServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, server_address, handler_class):
        super().__init__(server_address, handler_class)
        self.paths: list[str] = []


@pytest.fixture
def local_compound_target():
    server = _CompoundServer(("127.0.0.1", 0), _CompoundHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        yield f"{host}:{port}", server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _run_round_cli(repo_root: Path, target: str, operation: str, *, max_lanes: int = 1) -> dict:
    command = [
        sys.executable,
        str(REPO_ROOT / "tools" / "autopilot_round.py"),
        operation,
        "--repo-root",
        str(repo_root),
        "--target",
        target,
        "--json",
    ]
    if operation == "prepare":
        command.extend(["--max-lanes", str(max_lanes)])
    result = subprocess.run(
        command,
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr + result.stdout
    return json.loads(result.stdout)


def _write_evidence(repo_root: Path, target: str, name: str, payload: dict) -> str:
    ref = f"evidence/{target_storage_key(target)}/local-lab/{name}.json"
    path = repo_root / ref
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload) + "\n", encoding="utf-8")
    return ref


def _seed_queue(repo_root: Path, target: str) -> tuple[str, str]:
    queue = load_queue(repo_root, target)
    actions = [
        build_action(
            target=target,
            action_type="validation",
            evidence="localhost object surface is available",
            next_question="Does the object response remain scoped to the requested actor?",
            action="Replay the object surface and compare the owner boundary.",
            priority=90,
            source="local-lab",
            source_id="object-surface",
            metadata={"endpoint": "/api/object/42", "family": "authorization"},
        ),
        build_action(
            target=target,
            action_type="validation",
            evidence="localhost parser surface is available",
            next_question="Does the parser-shaped response create a useful continuation?",
            action="Replay the parser surface and record the bounded comparison.",
            priority=80,
            source="local-lab",
            source_id="parser-surface",
            metadata={"endpoint": "/render/template", "family": "parser-boundary"},
        ),
    ]
    upsert_actions(queue, actions)
    save_queue(repo_root, target, queue)
    stored = load_queue(repo_root, target)["actions"]
    return (
        next(item["id"] for item in stored if item.get("source_id") == "object-surface"),
        next(item["id"] for item in stored if item.get("source_id") == "parser-surface"),
    )


def test_localhost_two_rounds_preserve_queue_and_recover_started_lane(
    tmp_path, local_compound_target
):
    target, server = local_compound_target
    object_action_id, parser_action_id = _seed_queue(tmp_path, target)

    with urlopen(f"http://{target}/api/object/42", timeout=2) as response:
        object_payload = json.loads(response.read())
    with urlopen(f"http://{target}/render/template?name=sample", timeout=2) as response:
        parser_payload = json.loads(response.read())
    assert server.paths == ["/api/object/42", "/render/template?name=sample"]

    first = _run_round_cli(tmp_path, target, "prepare")
    assert first["status"] == "started"
    record_round_lane(tmp_path, target, lane="validation:object", max_lanes=1)
    claimed = claim_next_action(tmp_path, target, action_id=object_action_id)
    assert claimed["id"] == object_action_id
    object_evidence = _write_evidence(tmp_path, target, "object", object_payload)
    resolve_action(
        tmp_path,
        target=target,
        action_id=object_action_id,
        status="tested",
        result=object_evidence,
    )
    record_round_lane_result(
        tmp_path,
        target,
        lane="validation:object",
        status="completed",
        decision="tested clean",
        evidence_ref=object_evidence,
        next_action="continue parser surface",
    )
    loop_state = autopilot_state_module.build_autopilot_state(
        str(tmp_path), target, bounded=True
    )
    loop_state["loop_guard"] = autopilot_state_module._load_loop_guard_projection(
        str(tmp_path), loop_state
    )
    loop_projection = autopilot_state_module.build_decision_projection(
        loop_state, "loop_check"
    )
    assert loop_projection["kind"] == "autopilot_loop_check_projection"
    assert loop_projection["loop_guard"]["verdict"] == "continue"
    settled = _run_round_cli(tmp_path, target, "settle")
    assert settled["status"] == "settled"

    queue = load_queue(tmp_path, target)["actions"]
    assert next(item for item in queue if item["id"] == object_action_id)["status"] in {
        "tested",
        "validated",
    }
    assert next(item for item in queue if item["id"] == parser_action_id)["status"] == "queued"

    second = _run_round_cli(tmp_path, target, "prepare")
    assert second["status"] == "started"
    record_round_lane(tmp_path, target, lane="validation:parser", max_lanes=1)
    claimed_parser = claim_next_action(tmp_path, target, action_id=parser_action_id)
    assert claimed_parser["id"] == parser_action_id
    resumed = _run_round_cli(tmp_path, target, "prepare")
    assert resumed["status"] == "resumed"
    failed_settle = subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "tools" / "autopilot_round.py"),
            "settle",
            "--repo-root",
            str(tmp_path),
            "--target",
            target,
            "--json",
        ],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )
    assert failed_settle.returncode == 2
    assert "unfinished lanes" in failed_settle.stderr

    parser_evidence = _write_evidence(tmp_path, target, "parser", parser_payload)
    resolve_action(
        tmp_path,
        target=target,
        action_id=parser_action_id,
        status="tested",
        result=parser_evidence,
    )
    record_round_lane_result(
        tmp_path,
        target,
        lane="validation:parser",
        status="completed",
        decision="bounded continuation recorded",
        evidence_ref=parser_evidence,
        next_action="none",
    )
    final = _run_round_cli(tmp_path, target, "settle")
    replay = _run_round_cli(tmp_path, target, "settle")
    assert final["status"] == "settled"
    assert replay["status"] == "already_settled"
    assert all(
        item["status"] not in {"queued", "running"}
        for item in load_queue(tmp_path, target)["actions"]
        if item["id"] in {object_action_id, parser_action_id}
    )


def test_three_identical_local_rounds_end_in_stagnant_prerequisite(
    monkeypatch, tmp_path
):
    target = "127.0.0.1:39001"
    matrix_path = tmp_path / "evidence" / target_storage_key(target) / "coverage_matrix.json"
    matrix_path.parent.mkdir(parents=True, exist_ok=True)
    matrix_path.write_text(
        json.dumps({
            "endpoints": [{
                "endpoint": "/api/object/42",
                "weight": 3.0,
                "cells": {"IDOR": {"status": "tested_clean"}},
            }],
            "summary": {"total_cells": 1},
        }),
        encoding="utf-8",
    )
    fake_state = {
        "target": target,
        "resolved_target": target,
        "next_action": "handoff",
        "json_inject": {
            "status": "partial",
            "input_fingerprint": "local-lab-no-information",
            "request_count": 1,
        },
    }

    def fake_state_reader(*_args, **_kwargs):
        return dict(fake_state)

    monkeypatch.setattr(autopilot_round_module, "build_autopilot_state", fake_state_reader)
    monkeypatch.setattr(checkpoint_module, "build_autopilot_state", fake_state_reader)
    monkeypatch.setattr(
        autopilot_round_module,
        "build_checkpoint",
        lambda _repo, *, target, **_kwargs: {
            "target": target,
            "next_action_queue": [],
            "context_pack": {},
        },
    )

    guards = []
    for index in range(3):
        prepared = prepare_round(tmp_path, target, 1)
        assert prepared["status"] in {"started", "resumed"}
        lane = f"json:local-lab-{index}"
        record_round_lane(tmp_path, target, lane=lane, max_lanes=1)
        evidence_ref = _write_evidence(tmp_path, target, f"no-info-{index}", {"result": "none"})
        record_round_lane_result(
            tmp_path,
            target,
            lane=lane,
            status="completed",
            decision="no information",
            evidence_ref=evidence_ref,
            next_action="retry only with new evidence",
        )
        settled = settle_round(tmp_path, target, refresh_coverage=False)
        guards.append(settled["checkpoint"]["runtime_witness"])

    assert len(guards) == 3
    closure = autopilot_state_module.load_closure_projection(
        str(tmp_path), fake_state, max_lanes_reached=False
    )
    assert closure["verdict"] == "blocked"
    assert closure["reasons"] == ["stagnant_prerequisite"]
    assert closure["round_guard"]["consecutive"] == 3
