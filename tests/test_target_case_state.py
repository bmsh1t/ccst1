"""Tests for target-scoped actor/session/object validation state."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import target_case_state
from target_paths import target_storage_key
from tools.target_store import StoreError, TargetStore


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
    summary = target_case_state.summary(tmp_path, TARGET)

    assert state["schema_version"] == 1
    assert state["target"] == "127.0.0.1:3002"
    assert state["target_key"] == "127.0.0.1:3002"
    assert state["actors"] == {}
    assert state["sessions"] == {}
    assert state["objects"] == {}
    assert state["hypotheses"] == []
    # Case 不再初始化第二份待办：validation_backlog 只作为旧文件的迁移材料存在。
    assert "validation_backlog" not in state
    assert summary["authz_coverage"] == {
        "status": "missing",
        "authenticated_actor_count": 0,
        "authenticated_session_count": 0,
    }


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
    assert json.loads(output)["headers"] == {"Authorization": "<redacted>"}
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


def test_legacy_case_updates_preserve_defaulted_existing_values(tmp_path):
    target_case_state.add_actor(tmp_path, TARGET, actor="user_a", role="admin_like")
    target_case_state.add_session(tmp_path, TARGET, session="sess_a", actor="user_a",
                                  source="runner", validity="valid", kind="bearer",
                                  header_value="Bearer SECRET")
    target_case_state.add_object(tmp_path, TARGET, object_ref="obj_a", object_type="order",
                                 status="closed", owner_actor="user_a")

    target_case_state.add_actor(tmp_path, TARGET, actor="user_a", label="renamed")
    target_case_state.add_session(tmp_path, TARGET, session="sess_a", actor="user_a")
    target_case_state.add_object(tmp_path, TARGET, object_ref="obj_a", object_type="order")

    state = target_case_state.load_case_state(tmp_path, TARGET)
    assert state["actors"]["user_a"]["role"] == "admin_like"
    assert state["sessions"]["sess_a"]["source"] == "runner"
    assert state["sessions"]["sess_a"]["validity"] == "valid"
    assert state["objects"]["obj_a"]["status"] == "closed"


def test_legacy_case_state_rejects_foreign_target_identity(tmp_path):
    path = target_case_state.case_state_path(tmp_path, TARGET)
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({
        "schema_version": 1,
        "target": "https://foreign.test",
        "target_key": target_storage_key("https://foreign.test"),
        "actors": {}, "sessions": {}, "objects": {}, "hypotheses": [],
    }), encoding="utf-8")
    with pytest.raises(ValueError, match="target case state target mismatch"):
        target_case_state.load_case_state(tmp_path, TARGET)


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


def test_existing_invalid_case_state_list_member_fails_explicitly(tmp_path):
    path = target_case_state.case_state_path(tmp_path, TARGET)
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({
        "schema_version": 1,
        "actors": {},
        "sessions": {},
        "objects": {},
        "hypotheses": ["invalid"],
    }), encoding="utf-8")

    with pytest.raises(ValueError, match=r"field 'hypotheses'\[0\] must be object"):
        target_case_state.load_case_state(tmp_path, TARGET)


def test_existing_duplicate_case_state_id_fails_explicitly(tmp_path):
    path = target_case_state.case_state_path(tmp_path, TARGET)
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({
        "schema_version": 1,
        "actors": {},
        "sessions": {},
        "objects": {},
        "hypotheses": [{"id": "duplicate"}, {"id": "duplicate"}],
    }), encoding="utf-8")

    with pytest.raises(ValueError, match=r"field 'hypotheses' has duplicate id: duplicate"):
        target_case_state.load_case_state(tmp_path, TARGET)


@pytest.mark.parametrize(
    "backlog",
    [
        [{"id": "val_1", "status": "tested_clean"}],
        ["not-an-object"],
        [{"id": "dup"}, {"id": "dup"}],
        {"not": "a list"},
    ],
    ids=["records", "non-object-member", "duplicate-ids", "wrong-type"],
)
def test_legacy_validation_backlog_shape_is_not_validated_by_case(tmp_path, backlog):
    """Case 不再是 validation_backlog 的 owner，就不替迁移器判断它的形状。

    旧文件里带裁决的待办可能是任意历史形状；Case 唯一的义务是原样搬走而不改它，
    形状判定（含歧义隔离）属于迁移报告。
    """
    path = target_case_state.case_state_path(tmp_path, TARGET)
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({
        "schema_version": 1,
        "actors": {},
        "sessions": {},
        "objects": {},
        "hypotheses": [],
        "validation_backlog": backlog,
    }), encoding="utf-8")

    state = target_case_state.load_case_state(tmp_path, TARGET)

    assert state["validation_backlog"] == backlog


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
    assert summary["authz_coverage"]["status"] == "ready"
    assert summary["authz_coverage"]["authenticated_actor_count"] == 2
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
def test_add_hypothesis_records_context_only(tmp_path):
    _build_idor_state(tmp_path)
    hypothesis = target_case_state.add_hypothesis(
        tmp_path,
        TARGET,
        vuln_class="IDOR",
        endpoint=f"{TARGET}/rest/order-history/123",
        object_ref="order_123",
        actors=["user_a", "user_b"],
        why_now="browser observed the owner order endpoint",
    )
    stored = target_case_state.load_case_state(tmp_path, TARGET)["hypotheses"][0]
    summary = target_case_state.summary(tmp_path, TARGET)

    assert hypothesis["id"] == "hyp_001"
    assert stored["why_now"] == "browser observed the owner order endpoint"
    assert stored["status"] == "open"
    # 假设只记上下文：行动身份和执行状态在唯一行动源，Case 不复制“下一步做什么”。
    assert "next_action" not in stored
    assert summary["open_hypotheses"] == 1
    assert summary["actors"] == 2
    assert summary["objects"] == 1


def test_case_summary_reports_context_facts_without_actions_or_scores(tmp_path):
    _build_idor_state(tmp_path)
    target_case_state.add_hypothesis(tmp_path, TARGET, vuln_class="IDOR", object_ref="order_123")

    summary = target_case_state.summary(tmp_path, TARGET)

    assert set(summary) == {
        "target",
        "target_key",
        "actors",
        "sessions",
        "authz_coverage",
        "objects",
        "open_hypotheses",
        "object_samples",
    }
    for retired in (
        "top_next_action",
        "next_action",
        "score",
        "canonical_conflict_count",
        "pending_validation_backlog",
        "validation_backlog",
    ):
        assert retired not in summary


def test_case_module_exposes_no_backlog_or_ranking_api(tmp_path):
    for name in (
        "PRIORITY_SCORE",
        "add_backlog",
        "complete_backlog",
        "next_action",
        "_score_backlog_item",
        "LINKED_FINDING_STATUSES",
        "RUNNER_VULN_CLASS_MAP",
    ):
        assert not hasattr(target_case_state, name), name

    with pytest.raises(TypeError):
        target_case_state.add_hypothesis(  # type: ignore[call-arg]
            tmp_path,
            TARGET,
            vuln_class="IDOR",
            next_action="run the pair",
        )


def test_case_cli_has_no_action_verbs(tmp_path):
    for verb in ("next", "add-backlog", "complete-backlog"):
        with pytest.raises(SystemExit) as exit_info:
            target_case_state.main([verb, "--repo-root", str(tmp_path), "--target", TARGET])
        assert exit_info.value.code == 2


def test_add_hypothesis_rejects_next_action_flag(tmp_path, capsys):
    with pytest.raises(SystemExit) as exit_info:
        target_case_state.main([
            "add-hypothesis", "--repo-root", str(tmp_path), "--target", TARGET,
            "--vuln-class", "IDOR", "--next-action", "run the pair",
        ])
    captured = capsys.readouterr()

    assert exit_info.value.code == 2
    assert captured.out == ""
    assert "--next-action" in captured.err
    assert not target_case_state.case_state_path(tmp_path, TARGET).exists()


def test_legacy_backlog_and_unknown_keys_survive_case_mutations_verbatim(tmp_path):
    """旧 validation_backlog 只能被原样搬走：不改形状、不改裁决、不丢未知键。"""
    path = target_case_state.case_state_path(tmp_path, TARGET)
    path.parent.mkdir(parents=True)
    legacy_backlog = [
        {
            "id": "val_001",
            "runner": "request-diff",
            "vuln_class": "Authz",
            "endpoint": f"{TARGET}/rest/order-history/123",
            "owner_actor": "user_a",
            "peer_actor": "user_b",
            "object_ref": "order_123",
            "priority": "high",
            "status": "tested_clean",
            "result": "tested_clean",
            "evidence_ref": "evidence/127.0.0.1:3002/validation/x.json",
            "created_at": "2026-07-05T01:18:07Z",
            "unknown_legacy_key": {"nested": [1, 2, 3]},
        },
        {
            "id": "val_002",
            "runner": "marker-replay",
            "status": "blocked",
            "recover_hypothesis": "replay with owner session",
        },
    ]
    path.write_text(json.dumps({
        "schema_version": 1,
        "target": "127.0.0.1:3002",
        "target_key": target_storage_key(TARGET),
        "actors": {},
        "sessions": {},
        "objects": {},
        "hypotheses": [],
        "validation_backlog": legacy_backlog,
        "unknown_top_level_key": {"keep": True},
    }), encoding="utf-8")

    _build_idor_state(tmp_path)
    target_case_state.add_hypothesis(
        tmp_path, TARGET, vuln_class="IDOR", object_ref="order_123",
        why_now="owner endpoint observed",
    )
    state = target_case_state.load_case_state(tmp_path, TARGET)

    assert state["validation_backlog"] == legacy_backlog
    assert state["unknown_top_level_key"] == {"keep": True}
    assert state["hypotheses"][0]["why_now"] == "owner endpoint observed"
    assert json.loads(path.read_text(encoding="utf-8"))["validation_backlog"] == legacy_backlog


def test_cli_summary_outputs_context_json_only(tmp_path, capsys):
    _build_idor_state(tmp_path)
    target_case_state.add_hypothesis(tmp_path, TARGET, vuln_class="IDOR", object_ref="order_123")

    rc = target_case_state.main(["summary", "--repo-root", str(tmp_path), "--target", TARGET, "--json"])
    payload = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert payload["actors"] == 2
    assert payload["authz_coverage"]["status"] == "ready"
    assert payload["open_hypotheses"] == 1
    assert "top_next_action" not in payload
    assert "validation_backlog" not in payload


def test_cli_summary_text_lists_context_lines_only(tmp_path, capsys):
    _build_idor_state(tmp_path)

    rc = target_case_state.main(["summary", "--repo-root", str(tmp_path), "--target", TARGET])
    output = capsys.readouterr().out

    assert rc == 0
    assert "Open hypotheses: 0" in output
    assert "backlog" not in output.lower()
    assert "next action" not in output.lower()


def test_hypothesis_metadata_cli_round_trip_stores_what_the_validator_accepted(tmp_path, capsys):
    target = "target.com"
    metadata = {
        "family": "RCE",
        "primitive": "SSTI",
        "boundary": "template input",
        "impact": {"kind": "command execution"},
        "chain": ["template", "shell"],
        "chain_id": "chain-1",
        "dimensions": {"input_field": "name", "sink": "renderer"},
        "confidence": 0.82,
        "provenance": ["evidence/target.com/browser/response.json"],
        "evidence_refs": ["evidence/target.com/browser/response.json"],
        "next_question": "does output reach the renderer?",
        "stop_condition": "no template evaluation marker",
        "token_location": "Authorization header",
    }
    rc = target_case_state.main([
        "add-hypothesis", "--repo-root", str(tmp_path), "--target", target,
        "--vuln-class", "SSTI", "--why-now", "template reached from user input",
        "--metadata-json", json.dumps(metadata),
    ])
    output = capsys.readouterr().out

    assert rc == 0
    assert json.loads(output)["metadata"]["family"] == "RCE"
    stored = target_case_state.load_case_state(tmp_path, target)["hypotheses"][0]
    # Case 不再有"投影子集"：它存的是被校验器接受的原值，读的人也读原值。
    assert stored["metadata"] == {**metadata, "family": "RCE"}
    assert stored["why_now"] == "template reached from user input"
    assert "next_action" not in stored
    assert target_case_state.summary(tmp_path, target)["open_hypotheses"] == 1


def test_add_hypothesis_metadata_json_rejects_invalid_or_non_object(tmp_path, capsys):
    for raw in ("{broken", "[]"):
        rc = target_case_state.main([
            "add-hypothesis", "--repo-root", str(tmp_path), "--target", "target.com",
            "--vuln-class", "RCE", "--metadata-json", raw,
        ])
        captured = capsys.readouterr()
        assert rc == 2
        assert captured.out == ""
        assert "metadata-json" in captured.err

    for key in (
        "cookie", "accessToken", "authHeader", "clientSecret", "cookieValue",
        "secretAccessKey", "secretKey", "sessionId", "tokenValue",
    ):
        rc = target_case_state.main([
            "add-hypothesis", "--repo-root", str(tmp_path), "--target", "target.com",
            "--vuln-class", "RCE", "--metadata-json", json.dumps({key: "SECRET_VALUE"}),
        ])
        captured = capsys.readouterr()
        assert rc == 2
        assert captured.out == ""
        assert f"sensitive field metadata.{key}" in captured.err
        assert "SECRET_VALUE" not in captured.err
    assert target_case_state.load_case_state(tmp_path, "target.com")["hypotheses"] == []


@pytest.mark.parametrize(
    "metadata",
    [
        {"provenance": "Authorization: Bearer SECRET_VALUE"},
        {"next_question": {"prompt": "Cookie: sid=SECRET_VALUE"}},
        {"impact": {"description": "api-key: SECRET_VALUE"}},
        {"provenance": {"next-question": "Bearer SECRET_VALUE"}},
        {"nextQuestion": "Bearer SECRET_VALUE"},
        {"impact": {"api-key": "SECRET_VALUE"}},
    ],
    ids=["provenance", "next-question", "nested-impact", "kebab-nested", "camel", "kebab-key"],
)
def test_hypothesis_metadata_rejects_credential_values_before_case_state_mutation(
    tmp_path, metadata,
):
    with pytest.raises(ValueError, match="(?:credential-bearing value|sensitive field)") as raised:
        target_case_state.add_hypothesis(
            tmp_path,
            "target.com",
            vuln_class="RCE",
            metadata=metadata,
        )

    assert "SECRET_VALUE" not in str(raised.value)
    assert not target_case_state.case_state_path(tmp_path, "target.com").exists()


def test_legacy_credential_bearing_metadata_is_rejected_before_case_state_mutation(tmp_path):
    """旧字段里的凭证值仍在写入前被拒：Case 不存密钥，读它的人也就不可能拿到。"""
    metadata = {
        "provenance": "Authorization: Bearer SECRET_VALUE",
        "impact": {"description": "api-key: SECRET_VALUE"},
        "token_location": "Authorization header",
    }

    with pytest.raises(ValueError, match="(?:credential-bearing value|sensitive field)") as raised:
        target_case_state.add_hypothesis(
            tmp_path,
            "target.com",
            vuln_class="RCE",
            metadata=metadata,
        )

    assert "SECRET_VALUE" not in str(raised.value)
    assert not target_case_state.case_state_path(tmp_path, "target.com").exists()


def test_case_module_exposes_no_projection_or_ranking_api(tmp_path):
    """Case 不再提供任何"投影/排序/待办"API：上下文事实之外的能力一律不存在。"""
    for attribute in (
        "project_hypothesis_metadata", "HYPOTHESIS_METADATA_KEYS",
        "add_backlog", "complete_backlog", "next_action",
        "PRIORITY_SCORE", "_score_backlog_item", "_matching_final_findings",
    ):
        assert not hasattr(target_case_state, attribute), attribute


def test_add_hypothesis_rejects_unknown_actor_and_object(tmp_path):
    _build_idor_state(tmp_path)

    with pytest.raises(ValueError, match="actor does not exist: user_missing"):
        target_case_state.add_hypothesis(
            tmp_path, TARGET, vuln_class="IDOR", actors=["user_missing"],
        )
    with pytest.raises(ValueError, match="object_ref does not exist: order_404"):
        target_case_state.add_hypothesis(
            tmp_path, TARGET, vuln_class="IDOR", object_ref="order_404",
        )


def test_case_state_rejects_duplicate_hypothesis_ids(tmp_path):
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


def test_primary_case_context_uses_store_and_redacts_private_material(tmp_path):
    store = TargetStore(tmp_path, TARGET)
    store.initialize()
    target_case_state.add_actor(tmp_path, TARGET, actor="user_a", role="user")
    target_case_state.add_actor(tmp_path, TARGET, actor="user_b", role="user")
    target_case_state.add_session(
        tmp_path, TARGET, session="sess_a", actor="user_a", kind="bearer",
        header_value="Bearer SECRET_VALUE", validity="valid",
    )
    target_case_state.add_object(
        tmp_path, TARGET, object_ref="order_1", object_type="order",
        owner_actor="user_a", private_marker="owner@example.test",
    )
    hypothesis = target_case_state.add_hypothesis(
        tmp_path, TARGET, hypothesis_id="hyp_001", vuln_class="IDOR",
        object_ref="order_1", actors=["user_a", "user_b"], why_now="Peer object was observed",
    )

    assert not target_case_state.case_state_path(tmp_path, TARGET).exists()
    state = target_case_state.load_case_state(tmp_path, TARGET)
    assert state["hypotheses"][0]["id"] == hypothesis["id"]
    assert state["sessions"]["sess_a"]["headers"]["Authorization"] == "Bearer SECRET_VALUE"
    assert state["sessions"]["sess_a"]["private_ref"].startswith(".private/case-state/")
    assert target_case_state.summary(tmp_path, TARGET)["object_samples"][0]["private_marker"] == "<redacted>"
    assert store.page("experiences")["total"] == 1
    assert target_case_state.add_hypothesis(tmp_path, TARGET, vuln_class="IDOR")["id"] == "hyp_002"
    private_path = tmp_path / state["sessions"]["sess_a"]["private_ref"]
    private_path.unlink()
    with pytest.raises(StoreError, match="private case material unavailable"):
        store.case_context()
    with pytest.raises(StoreError, match="case_state.json is read-only"):
        target_case_state.save_case_state(tmp_path, TARGET, state)


def test_primary_case_updates_preserve_defaults_and_detect_tampering(tmp_path):
    store = TargetStore(tmp_path, TARGET)
    store.initialize()
    target_case_state.add_actor(tmp_path, TARGET, actor="user_a", role="user", label="owner")
    target_case_state.add_session(
        tmp_path, TARGET, session="sess_a", actor="user_a", kind="bearer",
        header_value="Bearer SECRET_VALUE", validity="valid",
    )
    target_case_state.add_actor(tmp_path, TARGET, actor="user_a", label="renamed")
    target_case_state.add_session(tmp_path, TARGET, session="sess_a", actor="user_a", notes="kept")

    state = target_case_state.load_case_state(tmp_path, TARGET)
    assert state["actors"]["user_a"]["role"] == "user"
    assert state["actors"]["user_a"]["label"] == "renamed"
    assert state["sessions"]["sess_a"]["kind"] == "bearer"
    assert state["sessions"]["sess_a"]["validity"] == "valid"
    private_path = tmp_path / state["sessions"]["sess_a"]["private_ref"]
    payload = json.loads(private_path.read_text(encoding="utf-8"))
    payload["headers"]["Authorization"] = "Bearer TAMPERED"
    private_path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(StoreError, match="digest mismatch"):
        store.case_context()
