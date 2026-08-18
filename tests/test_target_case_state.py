"""Tests for target-scoped actor/session/object validation state."""

from __future__ import annotations

import json
import shlex
from pathlib import Path

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
    assert state["target"] == "127.0.0.1:3002"
    assert state["target_key"] == "127.0.0.1:3002"
    assert state["actors"] == {}
    assert state["sessions"] == {}
    assert state["objects"] == {}
    assert state["validation_backlog"] == []


def test_existing_corrupt_state_fails_instead_of_resetting_to_empty(tmp_path):
    path = target_case_state.case_state_path(tmp_path, TARGET)
    path.parent.mkdir(parents=True)
    path.write_text("{broken", encoding="utf-8")

    with pytest.raises(ValueError, match="invalid target case state JSON"):
        target_case_state.load_case_state(tmp_path, TARGET)


def test_cli_reports_corrupt_state_with_stable_exit(tmp_path, capsys):
    path = target_case_state.case_state_path(tmp_path, TARGET)
    path.parent.mkdir(parents=True)
    path.write_text("{broken", encoding="utf-8")

    rc = target_case_state.main([
        "summary",
        "--repo-root",
        str(tmp_path),
        "--target",
        TARGET,
        "--json",
    ])
    captured = capsys.readouterr()

    assert rc == 2
    assert captured.out == ""
    assert "target case state command failed" in captured.err
    assert str(path) in captured.err


def test_add_session_cli_redacts_auth_material_from_stdout(tmp_path, capsys):
    target_case_state.add_actor(tmp_path, TARGET, actor="user_a", role="user")
    secret = "SECRET_CASE_SESSION"

    rc = target_case_state.main([
        "add-session",
        "--repo-root",
        str(tmp_path),
        "--target",
        TARGET,
        "--session",
        "sess_a",
        "--actor",
        "user_a",
        "--bearer",
        secret,
    ])

    output = capsys.readouterr().out
    assert rc == 0
    assert secret not in output
    assert "<redacted>" in output
    assert secret in target_case_state.load_case_state(tmp_path, TARGET)["sessions"]["sess_a"]["headers"]["Authorization"]


def test_add_session_cli_rejects_cross_target_auth_file_without_state_write(tmp_path, capsys):
    target_case_state.add_actor(tmp_path, TARGET, actor="user_a", role="user")
    secret = "SECRET_OTHER_TARGET"
    auth_file = tmp_path / "other-auth.json"
    auth_file.write_text(json.dumps({
        "target": "other.test",
        "cookie": secret,
    }), encoding="utf-8")

    rc = target_case_state.main([
        "add-session",
        "--repo-root",
        str(tmp_path),
        "--target",
        TARGET,
        "--session",
        "sess_a",
        "--actor",
        "user_a",
        "--auth-file",
        str(auth_file),
    ])
    captured = capsys.readouterr()

    assert rc == 2
    assert captured.out == ""
    assert "auth source target mismatch" in captured.err
    assert secret not in captured.err
    assert target_case_state.load_case_state(tmp_path, TARGET)["sessions"] == {}
    private_root = tmp_path / ".private" / "case-state"
    assert not private_root.exists() or not list(private_root.rglob("*.json"))


def test_case_state_public_file_contains_private_ref_only(tmp_path):
    target_case_state.add_actor(tmp_path, TARGET, actor="user_a", role="user")
    target_case_state.add_session(
        tmp_path,
        TARGET,
        session="sess_a",
        actor="user_a",
        kind="bearer",
        header_value="Bearer SECRET_CASE",
        validity="valid",
    )

    public_path = target_case_state.case_state_path(tmp_path, TARGET)
    public_text = public_path.read_text(encoding="utf-8")
    assert "SECRET_CASE" not in public_text
    payload = json.loads(public_text)
    session = payload["sessions"]["sess_a"]
    assert session["private_ref"].startswith(".private/case-state/")
    private_path = tmp_path / session["private_ref"]
    assert "SECRET_CASE" in private_path.read_text(encoding="utf-8")
    assert private_path.stat().st_mode & 0o777 == 0o600


def test_case_state_mutations_keep_concurrent_actor_updates(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    def add(index):
        return target_case_state.add_actor(tmp_path, TARGET, actor=f"user_{index}", role="user")

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(add, range(16)))

    state = target_case_state.load_case_state(tmp_path, TARGET)
    assert set(state["actors"]) == {f"user_{index}" for index in range(16)}


@pytest.mark.parametrize(
    "payload, message",
    [
        ([], "must contain one object"),
        ({"schema_version": 2}, "schema_version must be 1"),
        ({"schema_version": 1, "actors": []}, "field 'actors' must be dict"),
    ],
)
def test_existing_invalid_state_shape_fails_explicitly(tmp_path, payload, message):
    path = target_case_state.case_state_path(tmp_path, TARGET)
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match=message):
        target_case_state.load_case_state(tmp_path, TARGET)


@pytest.mark.parametrize("field", ["hypotheses", "validation_backlog"])
def test_existing_invalid_case_state_list_member_fails_explicitly(tmp_path, field):
    path = target_case_state.case_state_path(tmp_path, TARGET)
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({
        "schema_version": 1,
        "actors": {},
        "sessions": {},
        "objects": {},
        "hypotheses": [],
        "validation_backlog": [],
        field: ["invalid"],
    }), encoding="utf-8")

    with pytest.raises(ValueError, match=rf"field '{field}'\[0\] must be object"):
        target_case_state.load_case_state(tmp_path, TARGET)


@pytest.mark.parametrize("field", ["hypotheses", "validation_backlog"])
def test_existing_duplicate_case_state_id_fails_explicitly(tmp_path, field):
    path = target_case_state.case_state_path(tmp_path, TARGET)
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({
        "schema_version": 1,
        "actors": {},
        "sessions": {},
        "objects": {},
        "hypotheses": [],
        "validation_backlog": [],
        field: [{"id": "duplicate"}, {"id": "duplicate"}],
    }), encoding="utf-8")

    with pytest.raises(ValueError, match=rf"field '{field}' has duplicate id: duplicate"):
        target_case_state.load_case_state(tmp_path, TARGET)


def test_atomic_save_failure_preserves_previous_case_state(tmp_path, monkeypatch):
    _build_idor_state(tmp_path)
    path = target_case_state.case_state_path(tmp_path, TARGET)
    previous = path.read_bytes()
    state = target_case_state.load_case_state(tmp_path, TARGET)
    state["actors"]["user_a"]["label"] = "changed"
    original_replace = Path.replace

    def fail_case_state_replace(self, target):
        if Path(target) == path:
            raise OSError("synthetic replace failure")
        return original_replace(self, target)

    monkeypatch.setattr(Path, "replace", fail_case_state_replace)

    with pytest.raises(OSError, match="synthetic replace failure"):
        target_case_state.save_case_state(tmp_path, TARGET, state)

    assert path.read_bytes() == previous
    assert list(path.parent.glob(f".{path.name}.*.tmp")) == []


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
    assert "--complete-case-state" in next_item["command"]
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


def test_next_prefers_ready_item_over_higher_priority_missing_evidence(tmp_path):
    target_case_state.add_backlog(
        tmp_path,
        TARGET,
        runner="marker-replay",
        priority="critical",
    )
    ready = target_case_state.add_backlog(
        tmp_path,
        TARGET,
        runner="marker-replay",
        endpoint=f"{TARGET}/api/ready",
        expect_marker="MARKER",
        priority="high",
    )

    next_item = target_case_state.next_action(tmp_path, TARGET)

    assert next_item["backlog_id"] == ready["id"]
    assert next_item["ready"] is True
    assert next_item["backlog_id"] == ready["id"]
    assert "--expect-marker" in shlex.split(next_item["command"])


def test_marker_runner_builds_complete_command_when_contract_is_satisfied(tmp_path):
    ready = target_case_state.add_backlog(
        tmp_path,
        TARGET,
        runner="marker-replay",
        endpoint=f"{TARGET}/api/ready",
        expect_marker="MARKER",
        method="POST",
        priority="high",
    )

    next_item = target_case_state.next_action(tmp_path, TARGET)

    assert next_item["backlog_id"] == ready["id"]
    assert next_item["ready"] is True
    assert "--expect-marker MARKER" in next_item["command"]
    assert "--method POST" in next_item["command"]


def test_sqli_runner_requires_parameter_and_variant_and_builds_command(tmp_path):
    target_case_state.add_backlog(
        tmp_path,
        TARGET,
        runner="sqli-result-diff",
        endpoint=f"{TARGET}/search",
        priority="critical",
    )
    blocked = target_case_state.next_action(tmp_path, TARGET)
    assert blocked["ready"] is False
    assert {"param", "variant_value"}.issubset(set(blocked["missing_evidence"]))

    target_case_state.add_backlog(
        tmp_path,
        TARGET,
        runner="sqli-result-diff",
        endpoint=f"{TARGET}/search",
        param="q",
        baseline_value="safe",
        variant_value="'",
        priority="high",
    )
    ready = target_case_state.next_action(tmp_path, TARGET)
    assert ready["ready"] is True
    assert "--param q" in ready["command"]
    command = shlex.split(ready["command"])
    assert command[command.index("--variant-value") + 1] == "'"


def test_request_diff_runner_uses_spec_reference_without_copying_request_values(tmp_path):
    target_case_state.add_backlog(
        tmp_path,
        TARGET,
        runner="request-diff",
        request_spec_ref="evidence/target.test/request-pair.json",
        active_dimension="body:/filter/name",
        classifier="sqli",
        method="POST",
        priority="high",
    )
    item = target_case_state.next_action(tmp_path, TARGET)
    assert item["ready"] is True
    assert "--request-spec evidence/target.test/request-pair.json" in item["command"]
    assert "PAYLOAD" not in json.dumps(item)


def test_retired_payment_race_runner_fails_closed(tmp_path):
    target_case_state.add_backlog(
        tmp_path,
        TARGET,
        runner="payment-race",
        endpoint=f"{TARGET}/api",
        priority="critical",
    )
    next_item = target_case_state.next_action(tmp_path, TARGET)
    assert next_item["ready"] is False
    assert any("unsupported runner" in value for value in next_item["missing_evidence"])
    assert next_item["command"] == ""
    assert next_item["next_action"] == "enrich_case_state"


def test_candidate_routes_to_enrichment_without_replay(tmp_path):
    candidate = target_case_state.add_backlog(
        tmp_path,
        TARGET,
        runner="marker-replay",
        endpoint=f"{TARGET}/api/candidate",
        expect_marker="MARKER",
        priority="critical",
        status="candidate",
    )

    next_item = target_case_state.next_action(tmp_path, TARGET)

    assert next_item["backlog_id"] == candidate["id"]
    assert next_item["ready"] is False
    assert next_item["next_action"] == "enrich_case_state"
    assert next_item["command"] == ""
    assert next_item["redacted_command"] == ""
    assert "evidence enrichment" in next_item["why_now"]
    assert "set backlog" in next_item["write_back"]
    assert "to running before replay" in next_item["write_back"]

    target_case_state.complete_backlog(
        tmp_path,
        TARGET,
        backlog_id=candidate["id"],
        result="running",
        notes="new evidence was added",
    )
    resumed = target_case_state.next_action(tmp_path, TARGET)
    assert resumed["ready"] is True
    assert resumed["next_action"] == "run_validation_runner"


def test_unlinked_blocked_backlog_does_not_claim_hypothesis_recovery(tmp_path):
    target_case_state.add_backlog(
        tmp_path,
        TARGET,
        runner="marker-replay",
        endpoint=f"{TARGET}/api/blocked",
        expect_marker="MARKER",
        status="blocked",
    )

    next_item = target_case_state.next_action(tmp_path, TARGET)

    assert next_item["next_action"] == "enrich_case_state"
    assert next_item["hypothesis_id"] == ""
    assert next_item["recovery_next_action"] == ""
    assert next_item["command"] == ""
    assert "no linked hypothesis" in next_item["why_now"]


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
        evidence_ref="evidence/127.0.0.1:3002/validation/IDOR/summary.json",
    )
    next_item = target_case_state.next_action(tmp_path, TARGET)

    assert updated["status"] == "tested_finding"
    assert updated["evidence_ref"].endswith("summary.json")
    assert next_item["next_action"] == "none"


def test_hypothesis_backlog_outcome_projects_recovery_without_replaying_failure(tmp_path):
    _build_idor_state(tmp_path)
    hypothesis = target_case_state.add_hypothesis(
        tmp_path,
        TARGET,
        vuln_class="IDOR",
        endpoint=f"{TARGET}/rest/order-history/123",
        object_ref="order_123",
        next_action="compare owner and peer access",
        metadata={"source": "browser-observation"},
    )
    backlog = target_case_state.add_backlog(
        tmp_path,
        TARGET,
        hypothesis_id=hypothesis["id"],
        runner="idor-actor-pair",
        owner_actor="user_a",
        peer_actor="user_b",
        object_ref="order_123",
        chain_extensions_if_blocked=["try export/report endpoint for the same object"],
    )

    target_case_state.complete_backlog(
        tmp_path,
        TARGET,
        backlog_id=backlog["id"],
        result="blocked",
        notes="peer session expired",
    )
    state = target_case_state.load_case_state(tmp_path, TARGET)
    stored_hypothesis = state["hypotheses"][0]
    resumed = target_case_state.next_action(tmp_path, TARGET)

    assert stored_hypothesis["metadata"]["source"] == "browser-observation"
    assert stored_hypothesis["metadata"]["last_outcome"]["status"] == "blocked"
    assert stored_hypothesis["metadata"]["last_outcome"]["notes"] == "peer session expired"
    assert stored_hypothesis["metadata"]["recovery_next_action"] == "try export/report endpoint for the same object"
    assert resumed["next_action"] == "recover_hypothesis"
    assert resumed["ready"] is False
    assert resumed["recovery_next_action"] == "try export/report endpoint for the same object"
    assert resumed["command"] == ""


def test_case_state_rejects_duplicate_durable_ids(tmp_path):
    hypothesis = target_case_state.add_hypothesis(
        tmp_path,
        TARGET,
        hypothesis_id="hyp_001",
        vuln_class="IDOR",
    )
    with pytest.raises(ValueError, match="hypothesis id already exists: hyp_001"):
        target_case_state.add_hypothesis(
            tmp_path,
            TARGET,
            hypothesis_id=hypothesis["id"],
            vuln_class="IDOR",
        )

    backlog = target_case_state.add_backlog(
        tmp_path,
        TARGET,
        backlog_id="val_001",
        runner="marker-replay",
    )
    with pytest.raises(ValueError, match="backlog id already exists: val_001"):
        target_case_state.add_backlog(
            tmp_path,
            TARGET,
            backlog_id=backlog["id"],
            runner="marker-replay",
        )


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
