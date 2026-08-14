import json
from pathlib import Path

import pytest

from tools import param_discovery
from tools.auth_session import AuthSession


def test_cli_missing_auth_file_stops_before_discovery(tmp_path, monkeypatch, capsys):
    called = False

    def fail_discovery(**_kwargs):
        nonlocal called
        called = True
        raise AssertionError("missing auth input must stop before target I/O")

    missing = tmp_path / "missing-auth.json"
    monkeypatch.setattr(param_discovery, "discover_parameters", fail_discovery)

    rc = param_discovery.main([
        "--repo-root",
        str(tmp_path),
        "--target",
        "target.test",
        "--url",
        "https://target.test/search",
        "--auth-file",
        str(missing),
    ])
    captured = capsys.readouterr()

    assert rc == 2
    assert called is False
    assert str(missing) in captured.err


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
    action = json.loads(action_queue.read_text(encoding="utf-8"))["actions"][0]
    assert action["status"] == "signal"
    assert action["metadata"]["route_required"] is True
    assert action["metadata"]["skill_route"]["skill_id"] == "web2-vuln-classes"


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


def test_param_discovery_uses_explicit_url_budget_without_changing_default(tmp_path, monkeypatch):
    calls: list[str] = []

    def fake_tool(argv, *, cwd, timeout):
        calls.append(argv[argv.index("-u") + 1])
        output = Path(argv[argv.index("-o") + 1])
        output.write_text(json.dumps({"params": ["debug"]}), encoding="utf-8")
        return 0, ""

    monkeypatch.setattr(param_discovery, "_run_tool", fake_tool)
    urls = [f"https://target.test/api/{index}" for index in range(8)]

    explicit = param_discovery.discover_parameters(
        repo_root=tmp_path / "explicit",
        target="target.test",
        urls=urls,
        max_urls=8,
        tool_exists=lambda name: name == "x8",
    )
    assert explicit["counts"]["runs"] == 8
    assert calls == urls

    calls.clear()
    default = param_discovery.discover_parameters(
        repo_root=tmp_path / "default",
        target="target.test",
        urls=urls,
        tool_exists=lambda name: name == "x8",
    )
    assert default["counts"]["runs"] == param_discovery.MAX_URLS == 5
    assert calls == urls[:param_discovery.MAX_URLS]


def test_param_discovery_deep_budget_uses_surface_signals(tmp_path, monkeypatch):
    calls: list[str] = []

    def fake_tool(argv, *, cwd, timeout):
        calls.append(argv[argv.index("-u") + 1])
        output = Path(argv[argv.index("-o") + 1])
        output.write_text(json.dumps({"params": ["debug"]}), encoding="utf-8")
        return 0, ""

    monkeypatch.setattr(param_discovery, "_run_tool", fake_tool)
    urls = [f"https://target.test/api/{index}" for index in range(20)]
    summary = param_discovery.discover_parameters(
        repo_root=tmp_path,
        target="target.test",
        urls=urls,
        max_urls=5,
        deep=True,
        tool_exists=lambda name: name == "x8",
    )

    assert summary["budget"]["adaptive"] is True
    assert summary["budget"]["budget"] == 8
    assert summary["requested_max_urls"] == 5
    assert len(calls) == 8
    assert summary["status"] == "partial"


@pytest.mark.parametrize("budget", [0, -1])
def test_param_discovery_rejects_non_positive_url_budget(tmp_path, budget):
    with pytest.raises(ValueError, match="max_urls must be a positive integer"):
        param_discovery.discover_parameters(
            repo_root=tmp_path,
            target="target.test",
            urls=["https://target.test/api/search"],
            max_urls=budget,
        )
    assert not (tmp_path / "recon").exists()


def test_param_discovery_resume_retries_failed_endpoint_before_tail(tmp_path, monkeypatch):
    calls: list[str] = []
    outcomes = iter([0, 7, 0, 0, 0, 0])

    def fake_tool(argv, *, cwd, timeout):
        calls.append(argv[argv.index("-u") + 1])
        output = Path(argv[argv.index("-o") + 1])
        output.write_text(json.dumps({"params": ["debug"]}), encoding="utf-8")
        return next(outcomes), "transport failure"

    monkeypatch.setattr(param_discovery, "_run_tool", fake_tool)
    urls = [f"https://target.test/api/{index}" for index in range(4)]
    first = param_discovery.discover_parameters(
        repo_root=tmp_path,
        target="target.test",
        urls=urls,
        max_urls=3,
        tool_exists=lambda name: name == "x8",
    )

    assert first["status"] == "partial"
    assert first["cursor"]["methods"]["GET"]["next_index"] == 1

    second = param_discovery.discover_parameters(
        repo_root=tmp_path,
        target="target.test",
        urls=urls,
        max_urls=3,
        resume=True,
        tool_exists=lambda name: name == "x8",
    )

    assert second["status"] == "completed"
    assert second["cursor"]["methods"]["GET"]["next_index"] == 4
    assert calls == [urls[0], urls[1], urls[2], urls[1], urls[2], urls[3]]


def test_param_discovery_resume_rejects_auth_change_without_writing(tmp_path, monkeypatch):
    calls: list[str] = []

    def fake_tool(argv, *, cwd, timeout):
        calls.append(argv[argv.index("-u") + 1])
        output = Path(argv[argv.index("-o") + 1])
        output.write_text("{}", encoding="utf-8")
        return 0, ""

    monkeypatch.setattr(param_discovery, "_run_tool", fake_tool)
    urls = ["https://target.test/api/one", "https://target.test/api/two"]
    param_discovery.discover_parameters(
        repo_root=tmp_path,
        target="target.test",
        urls=urls,
        max_urls=1,
        tool_exists=lambda name: name == "x8",
    )
    summary_path = tmp_path / "recon" / "target.test" / "params" / "summary.json"
    before = summary_path.read_bytes()

    with pytest.raises(ValueError, match="auth session differs"):
        param_discovery.discover_parameters(
            repo_root=tmp_path,
            target="target.test",
            urls=urls,
            max_urls=1,
            resume=True,
            session=AuthSession(["Cookie: changed"], target="target.test"),
            tool_exists=lambda name: name == "x8",
        )
    assert calls == [urls[0]]
    assert summary_path.read_bytes() == before


def test_param_discovery_resume_advances_cursor_and_preserves_batches(tmp_path, monkeypatch):
    calls: list[str] = []

    def fake_tool(argv, *, cwd, timeout):
        url = argv[argv.index("-u") + 1]
        calls.append(url)
        output = Path(argv[argv.index("-o") + 1])
        output.write_text(json.dumps({"params": ["debug"]}), encoding="utf-8")
        return 0, ""

    monkeypatch.setattr(param_discovery, "_run_tool", fake_tool)
    urls = [f"https://target.test/api/{index}" for index in range(7)]
    root = tmp_path / "resume"

    first = param_discovery.discover_parameters(
        repo_root=root,
        target="target.test",
        urls=urls,
        max_urls=3,
        tool_exists=lambda name: name == "x8",
    )
    assert first["status"] == "partial"
    assert first["cursor"]["methods"]["GET"]["next_index"] == 3
    first_output = first["runs"][0]["output"]

    second = param_discovery.discover_parameters(
        repo_root=root,
        target="target.test",
        urls=urls,
        max_urls=3,
        resume=True,
        tool_exists=lambda name: name == "x8",
    )
    assert second["status"] == "partial"
    assert second["cursor"]["methods"]["GET"]["next_index"] == 6
    assert calls == urls[:6]
    assert second["runs"][0]["output"] != first_output
    assert (root / "recon" / "target.test" / "params" / "summary.batch-0001.json").is_file()

    third = param_discovery.discover_parameters(
        repo_root=root,
        target="target.test",
        urls=urls,
        max_urls=3,
        resume=True,
        tool_exists=lambda name: name == "x8",
    )
    assert third["status"] == "completed"
    assert third["cursor"]["complete"] is True
    assert calls == urls
    assert (root / "recon" / "target.test" / "params" / "summary.batch-0002.json").is_file()

    before = (root / "recon" / "target.test" / "params" / "summary.json").read_bytes()
    fourth = param_discovery.discover_parameters(
        repo_root=root,
        target="target.test",
        urls=urls,
        max_urls=3,
        resume=True,
        tool_exists=lambda name: name == "x8",
    )
    assert fourth["batch_id"] == third["batch_id"]
    assert calls == urls
    assert (root / "recon" / "target.test" / "params" / "summary.json").read_bytes() == before


def test_param_discovery_resume_rejects_changed_input_without_writing(tmp_path, monkeypatch):
    monkeypatch.setattr(param_discovery, "_run_tool", lambda *_args, **_kwargs: (0, ""))
    root = tmp_path / "changed"
    urls = [f"https://target.test/api/{index}" for index in range(3)]
    param_discovery.discover_parameters(
        repo_root=root,
        target="target.test",
        urls=urls,
        max_urls=2,
        tool_exists=lambda name: name == "x8",
    )
    summary_path = root / "recon" / "target.test" / "params" / "summary.json"
    before = summary_path.read_bytes()

    with pytest.raises(ValueError, match="input URL digest changed"):
        param_discovery.discover_parameters(
            repo_root=root,
            target="target.test",
            urls=[*urls, "https://target.test/api/new"],
            max_urls=2,
            resume=True,
            tool_exists=lambda name: name == "x8",
        )
    assert summary_path.read_bytes() == before


def test_param_discovery_rejects_summary_without_target_without_writing(tmp_path, monkeypatch):
    monkeypatch.setattr(param_discovery, "_run_tool", lambda *_args, **_kwargs: (0, ""))
    root = tmp_path / "missing-target"
    urls = ["https://target.test/api/search"]
    param_discovery.discover_parameters(
        repo_root=root,
        target="target.test",
        urls=urls,
        tool_exists=lambda name: name == "x8",
    )
    summary_path = root / "recon" / "target.test" / "params" / "summary.json"
    payload = json.loads(summary_path.read_text(encoding="utf-8"))
    payload.pop("target")
    summary_path.write_text(json.dumps(payload), encoding="utf-8")
    before = summary_path.read_bytes()

    with pytest.raises(ValueError, match="target is required"):
        param_discovery.discover_parameters(
            repo_root=root,
            target="target.test",
            urls=urls,
            resume=True,
            tool_exists=lambda name: name == "x8",
        )
    assert summary_path.read_bytes() == before


def test_param_discovery_post_budget_and_resume_bound_form_fetches(tmp_path, monkeypatch):
    calls: list[str] = []
    fetched: list[str] = []

    def fake_tool(argv, *, cwd, timeout):
        calls.append(argv[argv.index("-u") + 1])
        output = Path(argv[argv.index("-o") + 1])
        output.write_text(json.dumps({"params": ["id"]}), encoding="utf-8")
        return 0, ""

    def fake_fetch(url: str):
        fetched.append(url)
        return 200, '<form method="post" action="/submit"><input name="id"></form>'

    monkeypatch.setattr(param_discovery, "_run_tool", fake_tool)
    urls = [f"https://target.test/form/{index}" for index in range(5)]
    root = tmp_path / "post-resume"
    first = param_discovery.discover_parameters(
        repo_root=root,
        target="target.test",
        urls=urls,
        methods=("POST",),
        max_urls=2,
        fetch_html=fake_fetch,
        tool_exists=lambda name: name == "x8",
    )
    assert first["status"] == "partial"
    assert first["cursor"]["methods"]["POST"]["next_index"] == 2
    assert fetched == urls[:2]
    assert len(calls) == 1

    second = param_discovery.discover_parameters(
        repo_root=root,
        target="target.test",
        urls=urls,
        methods=("POST",),
        max_urls=2,
        resume=True,
        fetch_html=fake_fetch,
        tool_exists=lambda name: name == "x8",
    )
    assert second["cursor"]["methods"]["POST"]["next_index"] == 4
    assert fetched == urls[:4]
