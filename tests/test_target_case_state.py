"""Tests for target-scoped actor/session/object validation state."""

from __future__ import annotations

import json

import pytest
import target_case_state


TARGET = "http://127.0.0.1:3002"


def _build_idor_state(tmp_path):
    target_case_state.add_actor(tmp_path, TARGET, actor="user_a", role="user", label="owner")
    target_case_state.add_actor(tmp_path, TARGET, actor="user_b", role="user", label="peer")
    target_case_state.add_session(
        tmp_path,
        TARGET,
        session="sess_user_a",
        actor="user_a",
        kind="bearer",
        header_value="Bearer owner-token",
        validity="valid",
    )
    target_case_state.add_session(
        tmp_path,
        TARGET,
        session="sess_user_b",
        actor="user_b",
        kind="bearer",
        header_value="Bearer peer-token",
        validity="valid",
    )
    target_case_state.add_object(
        tmp_path,
        TARGET,
        object_ref="order_123",
        object_type="order",
        object_id="123",
        owner_actor="user_a",
        endpoint=f"{TARGET}/rest/order-history/123",
        private_marker="owner@example.test",
    )


def test_empty_state_initializes_shape(tmp_path):
    state = target_case_state.load_case_state(tmp_path, TARGET)

    assert state["schema_version"] == 1
    assert state["target"] == TARGET
    assert state["target_key"] == "http:_127.0.0.1:3002"
    assert state["actors"] == {}
    assert state["sessions"] == {}
    assert state["objects"] == {}
    assert state["validation_backlog"] == []


def test_add_actor_session_object_and_summary(tmp_path):
    _build_idor_state(tmp_path)

    state = target_case_state.load_case_state(tmp_path, TARGET)
    summary = target_case_state.summary(tmp_path, TARGET)

    assert state["actors"]["user_a"]["role"] == "user"
    assert state["sessions"]["sess_user_a"]["header_name"] == "Authorization"
    assert state["objects"]["order_123"]["private_marker"] == "owner@example.test"
    assert summary["actors"] == 2
    assert summary["sessions"] == 2
    assert summary["objects"] == 1


def test_add_session_imports_multi_header_auth_file(tmp_path):
    target_case_state.add_actor(tmp_path, TARGET, actor="user_a", role="user")
    auth_file = tmp_path / "auth.json"
    auth_file.write_text(
        json.dumps({
            "cookie": "sid=owner",
            "headers": ["X-CSRF-Token: csrf-owner", "X-Tenant: tenant-a"],
        }),
        encoding="utf-8",
    )

    rc = target_case_state.main([
        "add-session",
        "--repo-root",
        str(tmp_path),
        "--target",
        TARGET,
        "--session",
        "sess_user_a",
        "--actor",
        "user_a",
        "--auth-file",
        str(auth_file),
        "--bearer",
        "owner-token",
        "--validity",
        "valid",
    ])
    state = target_case_state.load_case_state(tmp_path, TARGET)
    session = state["sessions"]["sess_user_a"]

    assert rc == 0
    assert session["validity"] == "valid"
    assert session["headers"] == {
        "X-CSRF-Token": "csrf-owner",
        "X-Tenant": "tenant-a",
        "Cookie": "sid=owner",
        "Authorization": "Bearer owner-token",
    }
    assert session["header_name"] in session["headers"]
    assert session["header_value"] == session["headers"][session["header_name"]]


def test_add_session_requires_existing_actor(tmp_path):
    with pytest.raises(ValueError, match="actor does not exist"):
        target_case_state.add_session(
            tmp_path,
            TARGET,
            session="sess_missing",
            actor="user_missing",
            kind="bearer",
            header_value="Bearer x",
        )


def test_add_hypothesis_and_backlog_then_next_outputs_ai_orchestration(tmp_path):
    _build_idor_state(tmp_path)
    hypothesis = target_case_state.add_hypothesis(
        tmp_path,
        TARGET,
        vuln_class="IDOR",
        endpoint=f"{TARGET}/rest/order-history/123",
        object_ref="order_123",
        actors=["user_a", "user_b"],
        why_now="browser observed owner order endpoint",
        next_action="Run idor actor-pair",
    )
    backlog = target_case_state.add_backlog(
        tmp_path,
        TARGET,
        runner="idor-actor-pair",
        owner_actor="user_a",
        peer_actor="user_b",
        object_ref="order_123",
        priority="high",
        required_evidence=["owner session", "peer session", "owner private marker"],
        stop_condition="peer 403/404 or no private marker",
        chain_extensions_if_blocked=["try export endpoint"],
    )

    next_item = target_case_state.next_action(tmp_path, TARGET)

    assert hypothesis["id"] == "hyp_001"
    assert backlog["id"] == "val_001"
    assert next_item["next_action"] == "run_validation_runner"
    assert next_item["ready"] is True
    assert next_item["runner"] == "idor-actor-pair"
    assert next_item["hypothesis"] == "peer user_b may access order_123 owned by user_a"
    assert "why_now" in next_item
    assert "chain_context" in next_item
    assert "downgrade_rule" in next_item
    assert "try export endpoint" in next_item["chain_extensions_if_blocked"]
    assert "validation_runner.py" in next_item["command"]
    assert "--from-case-state" in next_item["command"]
    assert "--backlog-id val_001" in next_item["command"]
    assert "Bearer owner-token" not in next_item["command"]
    assert "owner-token" not in next_item["redacted_command"]


def test_next_blocks_when_peer_session_missing(tmp_path):
    target_case_state.add_actor(tmp_path, TARGET, actor="user_a", role="user")
    target_case_state.add_actor(tmp_path, TARGET, actor="user_b", role="user")
    target_case_state.add_session(
        tmp_path,
        TARGET,
        session="sess_user_a",
        actor="user_a",
        kind="bearer",
        header_value="Bearer owner-token",
    )
    target_case_state.add_object(
        tmp_path,
        TARGET,
        object_ref="order_123",
        object_type="order",
        owner_actor="user_a",
        endpoint=f"{TARGET}/rest/order-history/123",
        private_marker="owner@example.test",
    )
    target_case_state.add_backlog(
        tmp_path,
        TARGET,
        runner="idor-actor-pair",
        owner_actor="user_a",
        peer_actor="user_b",
        object_ref="order_123",
        priority="high",
    )

    next_item = target_case_state.next_action(tmp_path, TARGET)

    assert next_item["next_action"] == "enrich_case_state"
    assert next_item["ready"] is False
    assert "peer session" in next_item["missing_evidence"]
    assert next_item["command"] == ""


def test_next_allows_replay_without_private_marker_as_optional_gap(tmp_path):
    target_case_state.add_actor(tmp_path, TARGET, actor="user_a", role="user")
    target_case_state.add_actor(tmp_path, TARGET, actor="user_b", role="user")
    target_case_state.add_session(tmp_path, TARGET, session="sess_a", actor="user_a", kind="bearer", header_value="Bearer a")
    target_case_state.add_session(tmp_path, TARGET, session="sess_b", actor="user_b", kind="bearer", header_value="Bearer b")
    target_case_state.add_object(
        tmp_path,
        TARGET,
        object_ref="order_123",
        object_type="order",
        owner_actor="user_a",
        endpoint=f"{TARGET}/rest/order-history/123",
    )
    target_case_state.add_backlog(
        tmp_path,
        TARGET,
        runner="idor-actor-pair",
        owner_actor="user_a",
        peer_actor="user_b",
        object_ref="order_123",
        priority="high",
    )

    next_item = target_case_state.next_action(tmp_path, TARGET)

    assert next_item["next_action"] == "run_validation_runner"
    assert next_item["ready"] is True
    assert next_item["missing_evidence"] == []
    assert next_item["optional_evidence_gaps"] == ["owner private marker"]
    assert any("exact owner-body match" in item for item in next_item["required_evidence"])
    assert "validation_runner.py" in next_item["command"]


def test_complete_backlog_writes_result_and_evidence_ref(tmp_path):
    _build_idor_state(tmp_path)
    target_case_state.add_backlog(
        tmp_path,
        TARGET,
        runner="idor-actor-pair",
        owner_actor="user_a",
        peer_actor="user_b",
        object_ref="order_123",
        priority="high",
    )

    updated = target_case_state.complete_backlog(
        tmp_path,
        TARGET,
        backlog_id="val_001",
        result="tested_finding",
        evidence_ref="evidence/http:_127.0.0.1:3002/validation/IDOR/summary.json",
    )
    next_item = target_case_state.next_action(tmp_path, TARGET)

    assert updated["status"] == "tested_finding"
    assert updated["evidence_ref"].endswith("summary.json")
    assert next_item["next_action"] == "none"


def test_cli_next_outputs_json(tmp_path, capsys):
    _build_idor_state(tmp_path)
    target_case_state.add_backlog(
        tmp_path,
        TARGET,
        runner="idor-actor-pair",
        owner_actor="user_a",
        peer_actor="user_b",
        object_ref="order_123",
        priority="high",
    )

    rc = target_case_state.main(["next", "--repo-root", str(tmp_path), "--target", TARGET])
    payload = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert payload["runner"] == "idor-actor-pair"
    assert payload["next_action"] == "run_validation_runner"
