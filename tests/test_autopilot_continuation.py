"""Batch-to-domain Scope/Auth continuation regressions."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools import autopilot_bootstrap
from tools.auth_session import AuthSession
from tools.autopilot_continuation import create_continuation, load_continuation
from tools.target_paths import target_storage_key


def _scope_and_auth(tmp_path: Path) -> tuple[Path, Path]:
    scope = tmp_path / "scope.json"
    scope.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "in_scope": ["api.target.example"],
                "out_of_scope": ["admin.target.example"],
            }
        ),
        encoding="utf-8",
    )
    auth = tmp_path / "auth.json"
    auth.write_text(
        json.dumps({"target": "api.target.example", "cookie": "session=secret"}),
        encoding="utf-8",
    )
    return scope, auth


def _clean_runtime(repo_root, runtime_root=None, kinds=None):
    return {
        "repo_root": str(repo_root),
        "runtime_root": str(runtime_root or repo_root),
        "clean": True,
        "drift_count": 0,
        "kinds": [],
    }


def test_continuation_round_trip_preserves_parent_scope_and_private_auth(tmp_path):
    scope, auth = _scope_and_auth(tmp_path)

    created = create_continuation(
        tmp_path,
        parent_target=str(scope),
        selected_target="api.target.example",
        auth_file=auth,
    )
    continuation = created["continuation"]
    assert Path(created["path"]).parent == (
        tmp_path / "state" / target_storage_key(str(scope)) / "continuations"
    )
    assert continuation["source_action_id"].startswith("batch-select:")
    assert continuation["auth_private_ref"].startswith(".private/")
    assert "session=secret" not in Path(created["path"]).read_text(encoding="utf-8")

    loaded = load_continuation(
        tmp_path,
        created["path"],
        selected_target="api.target.example",
    )
    session = (
        AuthSession.from_file(loaded["auth_file"])
        .bind_scope(loaded["scope_context"])
        .bind_target("api.target.example")
    )
    assert session.headers_for_url("https://api.target.example/orders") == {
        "Cookie": "session=secret"
    }
    assert session.headers_for_url("https://admin.target.example/orders") == {}


def test_continuation_rejects_target_scope_and_auth_drift(tmp_path):
    scope, auth = _scope_and_auth(tmp_path)
    created = create_continuation(
        tmp_path,
        parent_target=str(scope),
        selected_target="api.target.example",
        auth_file=auth,
    )

    with pytest.raises(ValueError, match="selected target"):
        load_continuation(tmp_path, created["path"], selected_target="other.target.example")

    private_auth = tmp_path / created["continuation"]["auth_private_ref"]
    private_auth.write_text("{}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="auth ref is missing or stale"):
        load_continuation(tmp_path, created["path"], selected_target="api.target.example")

    private_auth.write_text(auth.read_text(encoding="utf-8"), encoding="utf-8")
    scope.write_text(
        json.dumps({"schema_version": 1, "in_scope": ["other.target.example"]}),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="Scope hash is stale"):
        load_continuation(tmp_path, created["path"], selected_target="api.target.example")


def test_continuation_rejects_non_owner_path_and_identity_tamper(tmp_path):
    scope, _auth = _scope_and_auth(tmp_path)
    created = create_continuation(
        tmp_path,
        parent_target=str(scope),
        selected_target="api.target.example",
    )

    outside = tmp_path / "outside.json"
    outside.write_text(Path(created["path"]).read_text(encoding="utf-8"), encoding="utf-8")
    with pytest.raises(ValueError, match="repository state directory"):
        load_continuation(tmp_path, outside, selected_target="api.target.example")

    payload = json.loads(Path(created["path"]).read_text(encoding="utf-8"))
    payload["invocation_id"] = "0" * 16
    Path(created["path"]).write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="invocation identity is stale"):
        load_continuation(tmp_path, created["path"], selected_target="api.target.example")


def test_bootstrap_applies_continuation_before_runtime_or_target_state(monkeypatch, tmp_path):
    scope, auth = _scope_and_auth(tmp_path)
    created = create_continuation(
        tmp_path,
        parent_target=str(scope),
        selected_target="api.target.example",
        auth_file=auth,
    )
    monkeypatch.setattr(autopilot_bootstrap, "compare_runtime", _clean_runtime)
    monkeypatch.setattr(
        autopilot_bootstrap,
        "build_capability_profile",
        lambda _repo: {"schema_version": 1, "checked": True, "status": "ready"},
    )
    monkeypatch.setattr(
        autopilot_bootstrap,
        "build_autopilot_bootstrap_state",
        lambda _repo, target: {"target": target, "target_kind": "domain", "next_action": "run_recon"},
    )

    payload = autopilot_bootstrap.build_autopilot_bootstrap(
        ["api.target.example", f"--context-file={created['path']}"],
        repo_root=tmp_path,
        runtime_root=tmp_path / "runtime",
    )

    assert payload["action"] == "continue"
    assert payload["scope"]["scope_hash"] == created["continuation"]["scope_hash"]
    assert payload["arguments"]["auth_file"] == str(
        (tmp_path / created["continuation"]["auth_private_ref"]).resolve()
    )
    assert payload["state"]["continuation"]["selected_target"] == "api.target.example"
    assert "session=secret" not in json.dumps(payload)


@pytest.mark.parametrize("drift", ["scope", "auth"])
def test_bootstrap_blocks_stale_continuation_before_runtime(monkeypatch, tmp_path, drift):
    scope, auth = _scope_and_auth(tmp_path)
    created = create_continuation(
        tmp_path,
        parent_target=str(scope),
        selected_target="api.target.example",
        auth_file=auth,
    )
    if drift == "scope":
        scope.write_text(
            json.dumps({"schema_version": 1, "in_scope": ["other.target.example"]}),
            encoding="utf-8",
        )
    else:
        (tmp_path / created["continuation"]["auth_private_ref"]).unlink()

    def unexpected(*_args, **_kwargs):
        raise AssertionError("stale continuation must stop before runtime or target state")

    monkeypatch.setattr(autopilot_bootstrap, "compare_runtime", unexpected)
    monkeypatch.setattr(autopilot_bootstrap, "build_autopilot_bootstrap_state", unexpected)

    payload = autopilot_bootstrap.build_autopilot_bootstrap(
        ["api.target.example", f"--context-file={created['path']}"],
        repo_root=tmp_path,
    )
    assert payload["action"] == "stop_invalid_context"


def test_anonymous_continuation_rejects_child_auth_injection(monkeypatch, tmp_path):
    scope, auth = _scope_and_auth(tmp_path)
    created = create_continuation(
        tmp_path,
        parent_target=str(scope),
        selected_target="api.target.example",
    )

    def unexpected(*_args, **_kwargs):
        raise AssertionError("auth conflict must stop before runtime")

    monkeypatch.setattr(autopilot_bootstrap, "compare_runtime", unexpected)
    payload = autopilot_bootstrap.build_autopilot_bootstrap(
        [
            "api.target.example",
            f"--context-file={created['path']}",
            "--auth-file",
            str(auth),
        ],
        repo_root=tmp_path,
    )
    assert payload["action"] == "stop_invalid_context"


def test_batch_bootstrap_carries_auth_into_continuation_create_args(monkeypatch, tmp_path):
    scope = tmp_path / "targets.txt"
    scope.write_text("api.target.example\n", encoding="utf-8")
    auth = tmp_path / "auth.json"
    auth.write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(autopilot_bootstrap, "compare_runtime", _clean_runtime)
    monkeypatch.setattr(
        autopilot_bootstrap,
        "build_capability_profile",
        lambda _repo: {"schema_version": 1, "checked": True, "status": "ready"},
    )
    monkeypatch.setattr(
        autopilot_bootstrap,
        "build_autopilot_bootstrap_state",
        lambda _repo, target: {
            "target": target,
            "target_kind": "list",
            "next_action": "select_completed_domain",
            "batch": {
                "candidates": [
                    {
                        "target": "api.target.example",
                        "continuation_create_args": [
                            "--parent-target",
                            target,
                            "--selected-target",
                            "api.target.example",
                        ],
                    }
                ]
            },
        },
    )

    payload = autopilot_bootstrap.build_autopilot_bootstrap(
        [str(scope), "--auth-file", str(auth)], repo_root=tmp_path
    )
    assert payload["state"]["batch"]["candidates"][0]["continuation_create_args"][-2:] == [
        "--auth-file",
        str(auth.resolve()),
    ]
