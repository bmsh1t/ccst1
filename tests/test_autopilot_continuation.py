"""Batch-to-domain Scope/Auth continuation regressions."""

from __future__ import annotations

import json
import subprocess
import sys
import threading
from argparse import Namespace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from tools import autopilot_bootstrap
from tools.auth_session import AuthSession
from tools.autopilot_continuation import create_continuation, load_continuation
from tools.target_paths import target_storage_key
from tools.scope_context import ScopeContext
from tools.scope_source import load_scope_context, load_scope_source, publish_scope_source
from tools.target_store import TargetStore
from tools.validation_runner import request_once


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


@pytest.mark.parametrize("authenticated", [False, True])
def test_bootstrap_applies_continuation_before_runtime_or_target_state(monkeypatch, tmp_path, authenticated):
    scope, auth = _scope_and_auth(tmp_path)
    created = create_continuation(
        tmp_path,
        parent_target=str(scope),
        selected_target="api.target.example",
        auth_file=auth if authenticated else None,
    )
    monkeypatch.setattr(autopilot_bootstrap, "compare_runtime", _clean_runtime)
    monkeypatch.setattr(
        autopilot_bootstrap,
        "build_capability_profile",
        lambda _repo: {"schema_version": 2, "checked": True, "status": "checked"},
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
    if authenticated:
        assert payload["arguments"]["auth_file"] == str(
            (tmp_path / created["continuation"]["auth_private_ref"]).resolve()
        )
    else:
        assert not payload["arguments"]["auth_file"]
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
    monkeypatch.setattr(autopilot_bootstrap, "build_capability_profile", unexpected)
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
    monkeypatch.setattr(autopilot_bootstrap, "build_capability_profile", unexpected)
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
        lambda _repo: {"schema_version": 2, "checked": True, "status": "checked"},
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


@pytest.mark.parametrize("error_type", [PermissionError, OSError, FileNotFoundError])
@pytest.mark.parametrize("failure_stage", ["open", "read"])
def test_bootstrap_blocks_unreadable_private_auth_before_runtime(
    monkeypatch, tmp_path, capsys, error_type, failure_stage,
):
    from contextlib import contextmanager
    from types import SimpleNamespace

    scope, auth = _scope_and_auth(tmp_path)
    created = create_continuation(
        tmp_path,
        parent_target=str(scope),
        selected_target="api.target.example",
        auth_file=auth,
    )
    private_auth = (tmp_path / created["continuation"]["auth_private_ref"]).resolve()
    unchanged = {
        path: path.read_bytes()
        for path in (scope, auth, private_auth, Path(created["path"]))
    }
    injected = error_type("private auth I/O failed: session=secret")
    original_open = Path.open
    failures = []

    def fail_read(*_args, **_kwargs):
        failures.append("read")
        raise injected

    @contextmanager
    def unreadable_handle(path, *args, **kwargs):
        with original_open(path, *args, **kwargs):
            yield SimpleNamespace(read=fail_read)

    def auth_open(path, *args, **kwargs):
        if path == private_auth:
            assert private_auth.is_file()
            if failure_stage == "open":
                failures.append("open")
                raise injected
            return unreadable_handle(path, *args, **kwargs)
        return original_open(path, *args, **kwargs)

    def unexpected(*_args, **_kwargs):
        raise AssertionError("unreadable continuation must stop before runtime or target state")

    with monkeypatch.context() as patch:
        patch.setattr(Path, "open", auth_open)
        patch.setattr(autopilot_bootstrap, "compare_runtime", unexpected)
        patch.setattr(autopilot_bootstrap, "build_capability_profile", unexpected)
        patch.setattr(autopilot_bootstrap, "build_autopilot_bootstrap_state", unexpected)
        with pytest.raises(ValueError, match="continuation auth ref is not readable") as caught:
            load_continuation(tmp_path, created["path"], selected_target="api.target.example")
        assert caught.value.__cause__ is injected
        payload = autopilot_bootstrap.build_autopilot_bootstrap(
            ["api.target.example", f"--context-file={created['path']}"],
            repo_root=tmp_path,
        )

    assert failures == [failure_stage, failure_stage]
    assert payload["action"] == "stop_invalid_context"
    assert payload["error"]["type"] == "ValueError"
    assert "continuation auth ref is not readable" in payload["error"]["reason"]
    assert len(payload["error"]["reason"]) <= 500
    assert all(path.read_bytes() == before for path, before in unchanged.items())
    output = capsys.readouterr()
    public = json.dumps(payload) + output.out + output.err
    assert "session=secret" not in public
    assert "Traceback" not in public


def _audit_ex1_context(root, target, *, parent_excluded=(), child_excluded=(), auth=None):
    store = TargetStore(root, target)
    store.initialize()
    if child_excluded:
        publish_scope_source(root, target, {"schema_version": 1, "root_target": target,
            "out_of_scope": list(child_excluded)},
            expected_sha256=load_scope_source(root, target)["sha256"])
    parent = root / "parent-scope.json"
    parent.write_text(json.dumps({"schema_version": 1, "root_target": target,
                                 "out_of_scope": list(parent_excluded)}))
    auth_path = None
    if auth is not None:
        auth_path = root / "fixture-auth.json"
        auth_path.write_text(json.dumps(auth))
    created = create_continuation(root, parent_target=str(parent),
                                  selected_target=target, auth_file=auth_path)
    return store, parent, created


@pytest.fixture
def audit_ex1_http():
    received, hooks = [], {}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            received.append((self.server.server_port, self.path, self.headers.get("Authorization")))
            if self.path in hooks:
                hooks[self.path]()
            self.send_response(302 if self.path == "/redirect" else 200)
            if self.path == "/redirect":
                self.send_header("Location", f"http://127.0.0.1:{sink.server_port}/arrived")
            self.end_headers()
            self.wfile.write(b'{"ok":true}')

        def log_message(self, *_args):
            pass

    source = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    sink = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threads = [threading.Thread(target=s.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
               for s in (source, sink)]
    for thread in threads:
        thread.start()
    try:
        yield (f"http://127.0.0.1:{source.server_port}",
               f"http://127.0.0.1:{sink.server_port}", received, hooks)
    finally:
        for server, thread in zip((source, sink), threads):
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


@pytest.mark.parametrize("restriction", ["parent", "child", "allow", "source-drift"])
def test_audit_ex1_actual_send_and_each_redirect(tmp_path, audit_ex1_http, restriction):
    from tools.auth_session import session_from_args

    origin, sink, received, hooks = audit_ex1_http
    _store, parent, created = _audit_ex1_context(tmp_path, "127.0.0.1",
        parent_excluded=[sink] if restriction == "parent" else [],
        child_excluded=[sink] if restriction == "child" else [],
        auth={"target": "127.0.0.1", "allowed_origins": [origin], "bearer": "synthetic-ex1"})
    session = session_from_args(Namespace(target="127.0.0.1", repo_root=tmp_path,
        context_file=created["path"]), env={})
    assert request_once(repo_root=tmp_path, target="127.0.0.1", url=origin + "/allowed",
                        session=session)["status"] == 200
    assert received[0][2] == "Bearer synthetic-ex1"
    if restriction in {"parent", "child"}:
        with pytest.raises(ValueError, match="saved Scope"):
            request_once(repo_root=tmp_path, target="127.0.0.1", url=sink, session=session)
        assert len(received) == 1
    if restriction == "source-drift":
        hooks["/redirect"] = lambda: parent.write_text(parent.read_text() + "\n")
    if restriction == "allow":
        result = request_once(repo_root=tmp_path, target="127.0.0.1",
                              url=origin + "/redirect", session=session)
        assert result["final_url"] == sink + "/arrived"
        assert [row[1] for row in received] == ["/allowed", "/redirect", "/arrived"]
        assert received[-1][2] is None  # Scope does not transfer credentials across origins.
    else:
        with pytest.raises(ValueError, match="Scope"):
            request_once(repo_root=tmp_path, target="127.0.0.1",
                         url=origin + "/redirect", session=session)
        assert [row[1] for row in received] == ["/allowed", "/redirect"]
    assert session.context_file == created["path"]


@pytest.mark.parametrize("denied", [False, True])
def test_audit_ex1_bootstrap_flags_reach_real_runner_cli(tmp_path, monkeypatch, audit_ex1_http, denied):
    origin, _sink, received, _hooks = audit_ex1_http
    store, _parent, created = _audit_ex1_context(tmp_path, "127.0.0.1",
        parent_excluded=[origin] if denied else [],
        auth={"target": "127.0.0.1", "allowed_origins": [origin], "bearer": "synthetic-ex1"})
    monkeypatch.setattr(autopilot_bootstrap, "compare_runtime", _clean_runtime)
    monkeypatch.setattr(autopilot_bootstrap, "build_capability_profile", lambda _: {})
    monkeypatch.setattr(autopilot_bootstrap, "build_autopilot_bootstrap_state",
                        lambda _root, target: {"target": target, "target_kind": "domain"})
    payload = autopilot_bootstrap.build_autopilot_bootstrap(
        ["127.0.0.1", f"--context-file={created['path']}"],
        repo_root=tmp_path, runtime_root=tmp_path / "runtime")
    assert payload["action"] == "continue", payload.get("arguments", {}).get("errors")
    pair = {"baseline_request": {"url": origin + "/?id=1"},
            "variant_request": {"url": origin + "/?id=2"},
            "subject_side": "baseline", "active_dimension": "query:id"}
    spec = tmp_path / "pair.json"
    spec.write_text(json.dumps(pair))
    before = store.binding()
    proc = subprocess.run([sys.executable, str(Path(__file__).resolve().parents[1] / "tools/validation_runner.py"),
        "request-diff", "--repo-root", str(tmp_path), "--target", "127.0.0.1",
        "--request-spec", str(spec), *payload["arguments"]["hunt_auth_flags"], "--json"],
        capture_output=True, text=True, timeout=20)
    assert proc.returncode == (2 if denied else 0), (proc.stderr, received)
    if denied:
        assert "saved Scope" in proc.stderr
        assert received == [] and store.binding() == before
        assert not (tmp_path / ".private/validation").exists()
    else:
        summary = json.loads(proc.stdout)
        assert summary["result"] == "candidate"
        assert [row[1] for row in received] == ["/?id=1", "/?id=2"]
        assert all(row[2] == "Bearer synthetic-ex1" for row in received)


@pytest.mark.parametrize("source_kind", ["json", "text", "primary"])
def test_audit_ex1_full_source_identity_not_classification_hash(tmp_path, source_kind):
    target = "audit.test"
    if source_kind == "primary":
        parent_target = "parent.test"
        TargetStore(tmp_path, parent_target).initialize()
        manifest = {"schema_version": 1, "root_target": parent_target, "in_scope": [target]}
        publish_scope_source(tmp_path, parent_target, manifest,
                             expected_sha256=load_scope_source(tmp_path, parent_target)["sha256"])
    else:
        parent = tmp_path / ("scope.json" if source_kind == "json" else "scope.txt")
        parent.write_text(json.dumps({"schema_version": 1, "in_scope": [target]})
                          if source_kind == "json" else target + "\n")
        parent_target = str(parent)
    created = create_continuation(tmp_path, parent_target=parent_target, selected_target=target)
    original = Path(created["path"]).read_bytes()
    if source_kind == "primary":
        publish_scope_source(tmp_path, parent_target, {**manifest, "test_rps": 0.25},
                             expected_sha256=load_scope_source(tmp_path, parent_target)["sha256"])
    else:
        parent.write_text(parent.read_text() + ("\n" if source_kind == "json" else "# revised source\n"))
    assert load_scope_context(tmp_path, parent_target).scope_hash == created["continuation"]["scope_hash"]
    with pytest.raises(ValueError, match="Scope source.*stale"):
        load_continuation(tmp_path, created["path"], selected_target=target)
    refreshed = create_continuation(tmp_path, parent_target=parent_target, selected_target=target)
    assert refreshed["path"] != created["path"]
    assert Path(created["path"]).read_bytes() == original


def test_audit_ex1_context_cannot_disappear_or_change_target(tmp_path, monkeypatch):
    from tools import validation_runner
    from tools.auth_session import session_from_args

    store, _parent, created = _audit_ex1_context(tmp_path, "audit.test")
    session = session_from_args(Namespace(target="audit.test", repo_root=tmp_path,
        context_file=created["path"]), env={"BBHUNT_BEARER": "ambient-must-not-revive"})
    assert session.is_empty()
    calls = []
    monkeypatch.setattr(validation_runner.urllib.request, "build_opener", lambda *_: calls.append("transport"))
    before = store.binding()
    with pytest.raises(ValueError, match="selected target"):
        request_once(repo_root=tmp_path, target="other.test", url="https://other.test/", session=session)
    with pytest.raises(ValueError, match="conflicts"):
        request_once(repo_root=tmp_path, target="audit.test", url="https://audit.test/",
                     session=session, context_file=tmp_path / "different.json")
    with pytest.raises(ValueError, match="must not be empty"):
        request_once(repo_root=tmp_path, target="audit.test", url="https://audit.test/", context_file="")
    old = json.loads(Path(created["path"]).read_text())
    Path(created["path"]).write_text(json.dumps({**old, "schema_version": 1}))
    with pytest.raises(ValueError, match="recreate"):
        request_once(repo_root=tmp_path, target="audit.test", url="https://audit.test/", session=session)
    Path(created["path"]).unlink()
    with pytest.raises(ValueError, match="not readable"):
        request_once(repo_root=tmp_path, target="audit.test", url="https://audit.test/", session=session)
    assert calls == [] and store.binding() == before


@pytest.mark.parametrize("auth_option", [{"bearer": "injected"}, {"auth_from_env": True},
                                        {"auth_header": ["Cookie: injected"]}])
def test_audit_ex1_anonymous_context_refuses_explicit_auth(tmp_path, auth_option):
    from tools.auth_session import session_from_args

    _store, _parent, created = _audit_ex1_context(tmp_path, "audit.test")
    with pytest.raises(ValueError, match="conflicts"):
        session_from_args(Namespace(target="audit.test", repo_root=tmp_path,
            context_file=created["path"], **auth_option), env={})


def test_audit_ex1_preserves_narrower_auth_and_child_only_path(tmp_path, audit_ex1_http):
    origin, _sink, received, _hooks = audit_ex1_http
    _store, _parent, created = _audit_ex1_context(tmp_path, "127.0.0.1")
    narrow = ScopeContext("127.0.0.1", out_of_scope=[origin])
    session = AuthSession(["Authorization: Bearer synthetic-ex1"], target="127.0.0.1",
                           scope_context=narrow, context_file=created["path"])
    assert request_once(repo_root=tmp_path, target="127.0.0.1", url=origin, session=session)["status"] == 200
    assert session.headers_for_url(origin) == {} and received[-1][2] is None
    assert request_once(repo_root=tmp_path, target="127.0.0.1", url=origin)["status"] == 200
    assert len(received) == 2


def test_audit_ex1_forms_and_unsupported_scanners_cannot_bypass_parent(tmp_path, monkeypatch):
    from tools import hunt, param_discovery
    from tools.auth_session import session_from_args

    store, _parent, created = _audit_ex1_context(tmp_path, "audit.test",
                                               parent_excluded=["blocked.audit.test"])
    session = session_from_args(Namespace(target="audit.test", repo_root=tmp_path,
        context_file=created["path"]), env={}).bind_target("audit.test")
    calls = []

    def fetch(url):
        calls.append(url)
        return 200, ('<form method="POST" action="https://audit.test/ok"><input name="ok"></form>'
                     '<form method="POST" action="https://blocked.audit.test/no"><input name="no"></form>')

    forms, error = param_discovery._fetch_forms("https://audit.test/form", target="audit.test",
        repo_root=tmp_path, session=session, timeout=2, fetch_html=fetch)
    assert error is None and [f["action"] for f in forms] == ["https://audit.test/ok"]
    with pytest.raises(ValueError, match="Scope"):
        param_discovery._fetch_forms("https://blocked.audit.test/form", target="audit.test",
            repo_root=tmp_path, session=session, timeout=2, fetch_html=fetch)
    assert calls == ["https://audit.test/form"]
    before = store.binding()
    monkeypatch.setattr(hunt, "BASE_DIR", str(tmp_path))
    monkeypatch.setattr(hunt, "_AUTH_SESSION", session)
    monkeypatch.setattr(hunt, "initialize_target_store", lambda *_: pytest.fail("unexpected init"))
    monkeypatch.setattr(hunt, "load_config", lambda: pytest.fail("unexpected config read"))
    monkeypatch.setattr(param_discovery, "_run_tool", lambda *_args, **_kw: pytest.fail("unexpected scanner"))
    with pytest.raises(ValueError, match="cannot enforce parent Scope"):
        hunt.hunt_target("audit.test")
    with pytest.raises(ValueError, match="cannot enforce parent Scope"):
        param_discovery.discover_parameters(repo_root=tmp_path, target="audit.test", session=session)
    monkeypatch.setattr(sys, "argv", ["hunt.py", "--target", "audit.test", "--context-file", created["path"]])
    with pytest.raises(SystemExit) as stopped:
        hunt.main()
    assert stopped.value.code == 2
    assert store.binding() == before and not (tmp_path / "recon").exists()
