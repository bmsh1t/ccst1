import json
from pathlib import Path

from tools import param_discovery
from tools.auth_session import AuthSession


def test_param_discovery_rejects_off_target_before_tool(tmp_path, monkeypatch):
    called = False

    def fail_tool(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("off-target input must not reach a subprocess")

    monkeypatch.setattr(param_discovery, "_run_tool", fail_tool)
    summary = param_discovery.discover_parameters(
        repo_root=tmp_path,
        target="target.test",
        urls=["https://other.test/admin?debug=1"],
        tool_exists=lambda _name: True,
    )

    assert called is False
    assert summary["status"] == "partial"
    assert summary["counts"]["rejected"] == 1
    assert summary["action_queue"]["queue_status"] == "lead"


def test_authenticated_x8_uses_private_request_file_not_argv(tmp_path, monkeypatch):
    seen: dict[str, object] = {}

    def fake_tool(argv, *, cwd, timeout):
        seen["argv"] = argv
        output = Path(argv[argv.index("-o") + 1])
        output.write_text(json.dumps({"params": ["debug"]}), encoding="utf-8")
        request_path = Path(argv[argv.index("-r") + 1])
        seen["request"] = request_path.read_text(encoding="utf-8")
        return 0, ""

    monkeypatch.setattr(param_discovery, "_run_tool", fake_tool)
    session = AuthSession(["Cookie: SECRET_COOKIE"], target="target.test")
    summary = param_discovery.discover_parameters(
        repo_root=tmp_path,
        target="target.test",
        urls=["https://target.test/api/search"],
        session=session,
        tool_exists=lambda name: name == "x8",
    )

    argv = seen["argv"]
    assert isinstance(argv, list)
    assert "SECRET_COOKIE" not in " ".join(str(value) for value in argv)
    assert "Cookie: SECRET_COOKIE" in str(seen["request"])
    assert summary["counts"]["discoveries"] == 1
    assert not list((tmp_path / ".private").rglob("request-*.http"))
    action_queue = tmp_path / "state" / "target.test" / "action_queue.json"
    assert action_queue.is_file()
    assert json.loads(action_queue.read_text(encoding="utf-8"))["actions"][0]["status"] == "signal"


def test_authenticated_discovery_does_not_fallback_to_anonymous_arjun(tmp_path, monkeypatch):
    called = False

    def fail_tool(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("anonymous fallback must not run")

    monkeypatch.setattr(param_discovery, "_run_tool", fail_tool)
    summary = param_discovery.discover_parameters(
        repo_root=tmp_path,
        target="target.test",
        urls=["https://target.test/api/search"],
        session=AuthSession(["Cookie: SECRET_COOKIE"], target="target.test"),
        tool_exists=lambda name: name == "arjun",
    )

    assert called is False
    assert summary["status"] == "blocked"
    assert summary["errors"] == ["x8 is required for authenticated parameter discovery"]


def test_summary_survives_action_queue_sync_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(
        param_discovery,
        "_sync_action_queue",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("queue unavailable")),
    )

    summary = param_discovery.discover_parameters(
        repo_root=tmp_path,
        target="target.test",
        urls=["https://target.test/api/search?q=one"],
        tool_exists=lambda _name: False,
    )

    persisted = json.loads(
        (tmp_path / "recon" / "target.test" / "params" / "summary.json").read_text(encoding="utf-8")
    )
    assert summary["status"] == "blocked"
    assert persisted["status"] == "blocked"
    assert persisted["action_queue"]["status"] == "error"
    assert "queue unavailable" in persisted["action_queue"]["error"]
