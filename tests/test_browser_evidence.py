"""Regression tests for minimal browser evidence capture."""

import json
from pathlib import Path
from types import SimpleNamespace

import browser_evidence
import pytest


def test_resolve_browser_backend_prefers_agent_browser_then_playwright():
    both = lambda tool: f"/fixture/{tool}" if tool in {"agent-browser", "playwright-cli"} else None
    playwright_only = lambda tool: f"/fixture/{tool}" if tool == "playwright-cli" else None

    assert browser_evidence.resolve_browser_backend("auto", which=both) == "agent-browser"
    assert browser_evidence.resolve_browser_backend("auto", which=playwright_only) == "playwright-cli"


def test_resolve_browser_backend_reports_missing_and_invalid_backends():
    with pytest.raises(RuntimeError, match="agent-browser.*playwright-cli"):
        browser_evidence.resolve_browser_backend("auto", which=lambda _tool: None)
    with pytest.raises(ValueError, match="Unsupported browser backend"):
        browser_evidence.resolve_browser_backend("selenium")


def test_capture_browser_evidence_writes_summary_and_last_pointer(monkeypatch, tmp_path):
    calls = []
    envs = []

    def fake_run(cmd, capture_output, text, timeout, check, env=None):
        calls.append(cmd)
        envs.append(env or {})
        stdout = ""
        if "requests" in cmd:
            stdout = json.dumps(
                {
                    "requests": [
                        {
                            "url": "https://target.local/api/me?account_id=123",
                            "method": "GET",
                            "resourceType": "xhr",
                        },
                        {
                            "request": {
                                "url": "https://target.local/graphql",
                                "method": "POST",
                                "postData": {"text": '{"query":"mutation Invite($user_id:ID!){invite(user_id:$user_id){id}}"}'},
                            },
                            "type": "fetch",
                        },
                        "https://target.local/static/app.js",
                    ]
                }
            )
        elif "console" in cmd:
            stdout = json.dumps([{"type": "log", "text": "ready"}])
        elif "cookie-list" in cmd:
            stdout = json.dumps([{"name": "sid", "value": "redacted"}])
        elif "localstorage-list" in cmd:
            stdout = json.dumps({"theme": "dark"})
        elif "sessionstorage-list" in cmd:
            stdout = json.dumps({"step": "1"})
        elif "snapshot" in cmd:
            stdout = "Page URL: https://target.local/app\nSnapshot: ok\n"
        elif "state-save" in cmd:
            Path(cmd[-1]).write_text(json.dumps({"cookies": []}), encoding="utf-8")
        elif "screenshot" in cmd:
            filename_arg = next(item for item in cmd if item.startswith("--filename="))
            Path(filename_arg.split("=", 1)[1]).write_bytes(b"fake-png")
        return SimpleNamespace(returncode=0, stdout=stdout, stderr="")

    monkeypatch.setattr(browser_evidence.subprocess, "run", fake_run)

    summary = browser_evidence.capture_browser_evidence(
        "target.local",
        "https://target.local/app",
        label="unit",
        evidence_root=tmp_path / "evidence",
        backend="playwright-cli",
    )

    summary_path = Path(summary["summary_path"])
    pointer_path = tmp_path / "evidence" / "target.local" / "browser" / "last-capture.json"
    saved_summary = json.loads(summary_path.read_text(encoding="utf-8"))
    pointer = json.loads(pointer_path.read_text(encoding="utf-8"))

    assert summary_path.is_file()
    assert pointer_path.is_file()
    assert saved_summary["counts"]["requests"] == 3
    assert saved_summary["counts"]["console"] == 1
    assert saved_summary["counts"]["browser_xhr_endpoints"] == 2
    assert saved_summary["counts"]["browser_api_endpoints"] == 2
    assert saved_summary["counts"]["browser_params"] == 3
    assert saved_summary["capture_backend"] == "playwright-cli"
    assert saved_summary["artifacts"]["snapshot_txt"].endswith("snapshot.txt")
    assert saved_summary["capture_screenshot"] is False
    assert "screenshot_png" not in saved_summary["artifacts"]
    assert saved_summary["browser_surface"]["counts"]["xhr_endpoints"] == 2
    assert pointer["summary_path"] == str(summary_path)
    assert pointer["request_count"] == 3
    assert pointer["browser_api_count"] == 2

    recon_browser = tmp_path / "recon" / "target.local" / "browser"
    assert (recon_browser / "xhr_endpoints.txt").read_text(encoding="utf-8").splitlines() == [
        "https://target.local/api/me?account_id=123",
        "https://target.local/graphql",
    ]
    assert (recon_browser / "api_endpoints.txt").read_text(encoding="utf-8").splitlines() == [
        "https://target.local/api/me?account_id=123",
        "https://target.local/graphql",
    ]
    assert (recon_browser / "browser_params.txt").read_text(encoding="utf-8").splitlines() == [
        "https://target.local/api/me?account_id=123 :: account_id",
        "https://target.local/graphql :: user_id",
        "https://target.local/graphql :: query",
    ]
    assert json.loads((recon_browser / "forms.json").read_text(encoding="utf-8"))["status"] == "placeholder"

    command_args = [cmd[2:] for cmd in calls]
    assert ["goto", "https://target.local/app"] in command_args
    assert ["--raw", "snapshot"] in command_args
    assert ["--raw", "requests"] in command_args
    assert ["--raw", "console"] in command_args
    assert any(args[0] == "state-save" and args[1].endswith("state.json") for args in command_args)
    assert all(env.get("PLAYWRIGHT_DAEMON_SESSION_DIR") for env in envs)
    assert not any(
        args[0] == "screenshot" and args[1].startswith("--filename=") and args[1].endswith("screenshot.png")
        for args in command_args
    )


def test_capture_browser_evidence_can_capture_screenshot_when_requested(monkeypatch, tmp_path):
    calls = []

    def fake_run(cmd, capture_output, text, timeout, check, env=None):
        calls.append(cmd)
        if "state-save" in cmd:
            Path(cmd[-1]).write_text(json.dumps({"cookies": []}), encoding="utf-8")
        if "screenshot" in cmd:
            filename_arg = next(item for item in cmd if item.startswith("--filename="))
            Path(filename_arg.split("=", 1)[1]).write_bytes(b"fake-png")
        return SimpleNamespace(returncode=0, stdout="[]", stderr="")

    monkeypatch.setattr(browser_evidence.subprocess, "run", fake_run)

    summary = browser_evidence.capture_browser_evidence(
        "target.local",
        "https://target.local/app",
        label="unit",
        evidence_root=tmp_path / "evidence",
        capture_screenshot=True,
        backend="playwright-cli",
    )

    command_args = [cmd[2:] for cmd in calls]
    assert summary["capture_screenshot"] is True
    assert summary["artifacts"]["screenshot_png"].endswith("screenshot.png")
    assert any(
        args[0] == "screenshot" and args[1].startswith("--filename=") and args[1].endswith("screenshot.png")
        for args in command_args
    )


def test_load_last_browser_evidence_returns_compact_linkage(monkeypatch, tmp_path):
    monkeypatch.setattr(browser_evidence.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="[]", stderr=""))

    summary = browser_evidence.capture_browser_evidence(
        "target.local",
        "https://target.local/",
        label="last",
        evidence_root=tmp_path / "evidence",
        backend="playwright-cli",
    )

    linkage = browser_evidence.load_last_browser_evidence(
        "target.local",
        evidence_root=tmp_path / "evidence",
    )

    assert linkage["dir"] == summary["evidence_dir"]
    assert linkage["summary_path"] == summary["summary_path"]
    assert linkage["url"] == "https://target.local/"


def test_capture_browser_evidence_url_target_uses_canonical_storage_key(monkeypatch, tmp_path):
    monkeypatch.setattr(
        browser_evidence.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="[]", stderr=""),
    )

    summary = browser_evidence.capture_browser_evidence(
        "http://127.0.0.1:3002",
        "http://127.0.0.1:3002/",
        label="url-target",
        evidence_root=tmp_path / "evidence",
        backend="playwright-cli",
    )

    target_key = "127.0.0.1:3002"
    assert summary["target_key"] == target_key
    assert summary["session"] == "browser-http___127.0.0.1_3002"
    assert Path(summary["evidence_dir"]).is_relative_to(tmp_path / "evidence" / target_key / "browser")
    assert (tmp_path / "evidence" / target_key / "browser" / "last-capture.json").is_file()
    assert (tmp_path / "recon" / target_key / "browser" / "summary.json").is_file()
    assert not (tmp_path / "evidence" / "http___127.0.0.1_3002").exists()

    linkage = browser_evidence.load_last_browser_evidence(
        "http://127.0.0.1:3002",
        evidence_root=tmp_path / "evidence",
    )
    assert linkage["summary_path"] == summary["summary_path"]


def test_custom_evidence_root_keeps_recon_in_the_same_staging_parent(monkeypatch, tmp_path):
    monkeypatch.setattr(
        browser_evidence.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="[]", stderr=""),
    )
    monkeypatch.setattr(browser_evidence, "DEFAULT_RECON_ROOT", tmp_path / "unexpected-default")

    browser_evidence.capture_browser_evidence(
        "target.local",
        "https://target.local/",
        evidence_root=tmp_path / "custom-evidence",
        backend="playwright-cli",
    )

    assert (tmp_path / "recon" / "target.local" / "browser" / "summary.json").is_file()
    assert not (tmp_path / "unexpected-default").exists()


def test_capture_browser_evidence_agent_browser_writes_raw_and_normalized_artifacts(monkeypatch, tmp_path):
    calls = []
    envs = []

    requests = [
        {
            "url": "https://target.local/api/me?account_id=123",
            "method": "GET",
            "resourceType": "xhr",
            "status": 200,
        },
        {
            "url": "https://target.local/graphql",
            "method": "POST",
            "resourceType": "fetch",
            "postData": {"query": "query User($id: ID!){user(id:$id){id}}"},
            "status": 200,
        },
    ]

    def fake_run(cmd, capture_output, text, timeout, check, env=None):
        calls.append(cmd)
        envs.append(env or {})
        args = cmd[4:]
        data = {}
        if args == ["snapshot"]:
            data = {"snapshot": "heading \"Dashboard\"", "refs": {}}
        elif args == ["network", "requests"]:
            data = {"requests": requests}
        elif args == ["console"]:
            data = {"messages": [{"type": "log", "text": "ready"}]}
        elif args == ["cookies", "get"]:
            data = {"cookies": [{"name": "sid", "value": "redacted"}]}
        elif args == ["storage", "local"]:
            data = {"storage": {"theme": "dark"}}
        elif args == ["storage", "session"]:
            data = {"storage": {"step": "1"}}
        elif args[:2] == ["state", "save"]:
            Path(args[-1]).write_text(json.dumps({"cookies": []}), encoding="utf-8")
            data = {"saved": True, "path": args[-1]}
        elif args and args[0] == "screenshot":
            Path(args[-1]).write_bytes(b"fake-png")
            data = {"path": args[-1]}
        elif args[:3] == ["network", "har", "stop"]:
            Path(args[-1]).write_text(json.dumps({"log": {"entries": []}}), encoding="utf-8")
            data = {"path": args[-1]}
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps({"success": True, "data": data, "error": None}),
            stderr="",
        )

    monkeypatch.setattr(browser_evidence.subprocess, "run", fake_run)

    summary = browser_evidence.capture_browser_evidence(
        "target.local",
        "https://target.local/app",
        label="agent",
        evidence_root=tmp_path / "evidence",
        capture_screenshot=True,
        backend="agent-browser",
    )

    capture_dir = Path(summary["evidence_dir"])
    pointer = json.loads(
        (tmp_path / "evidence" / "target.local" / "browser" / "last-capture.json").read_text(
            encoding="utf-8"
        )
    )
    normalized_requests = json.loads((capture_dir / "requests.json").read_text(encoding="utf-8"))
    raw_requests = json.loads((capture_dir / "requests.raw.json").read_text(encoding="utf-8"))
    storage = json.loads((capture_dir / "storage.json").read_text(encoding="utf-8"))

    assert summary["success"] is True
    assert summary["capture_backend"] == "agent-browser"
    assert summary["counts"]["requests"] == 2
    assert summary["counts"]["console"] == 1
    assert summary["counts"]["browser_xhr_endpoints"] == 2
    assert summary["counts"]["browser_params"] == 3
    assert pointer["capture_backend"] == "agent-browser"
    assert normalized_requests == {"requests": requests, "source": "agent-browser"}
    assert raw_requests["data"]["requests"] == requests
    assert (capture_dir / "snapshot.txt").read_text(encoding="utf-8") == 'heading "Dashboard"'
    assert storage == {
        "localStorage": {"theme": "dark"},
        "sessionStorage": {"step": "1"},
    }
    assert (capture_dir / "state.json").is_file()
    assert (capture_dir / "screenshot.png").read_bytes() == b"fake-png"
    assert (capture_dir / "network.har").is_file()
    assert summary["artifacts"]["requests_raw_json"].endswith("requests.raw.json")
    assert summary["artifacts"]["network_har"].endswith("network.har")

    command_args = [cmd[4:] for cmd in calls]
    assert command_args[:5] == [
        ["open"],
        ["network", "requests", "--clear"],
        ["console", "--clear"],
        ["network", "har", "start"],
        ["navigate", "https://target.local/app"],
    ]
    assert ["network", "requests"] in command_args
    assert ["cookies", "get"] in command_args
    assert ["storage", "local"] in command_args
    assert ["storage", "session"] in command_args
    assert all(cmd[0] == "agent-browser" for cmd in calls)
    assert all(env.get("AGENT_BROWSER_SOCKET_DIR") for env in envs)


def test_agent_browser_har_failure_keeps_basic_capture_and_does_not_switch_backend(monkeypatch, tmp_path):
    calls = []

    def fake_run(cmd, capture_output, text, timeout, check, env=None):
        calls.append(cmd)
        args = cmd[4:]
        if args == ["network", "har", "start"]:
            return SimpleNamespace(
                returncode=1,
                stdout=json.dumps({"success": False, "data": None, "error": "HAR unavailable"}),
                stderr="HAR unavailable",
            )
        if args[:3] == ["network", "har", "stop"]:
            Path(args[-1]).write_text('{"log":{"entries":[]}}', encoding="utf-8")
            data = {"path": args[-1]}
        elif args == ["network", "requests"]:
            data = {"requests": [{"url": "https://target.local/api/health", "method": "GET"}]}
        elif args == ["snapshot"]:
            data = {"snapshot": "heading \"Health\""}
        elif args == ["console"]:
            data = {"messages": []}
        elif args[:2] == ["state", "save"]:
            Path(args[-1]).write_text("{}", encoding="utf-8")
            data = {"saved": True}
        else:
            data = {}
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps({"success": True, "data": data, "error": None}),
            stderr="",
        )

    monkeypatch.setattr(browser_evidence.subprocess, "run", fake_run)

    summary = browser_evidence.capture_browser_evidence(
        "target.local",
        "https://target.local/health",
        evidence_root=tmp_path / "evidence",
        backend="agent-browser",
    )

    assert summary["success"] is True
    assert summary["capture_backend"] == "agent-browser"
    assert "network_har" not in summary["artifacts"]
    assert len([step for step in summary["steps"] if step["name"].startswith("network har") and not step["success"]]) == 1
    assert all(cmd[0] == "agent-browser" for cmd in calls)


def test_agent_browser_core_protocol_failure_marks_capture_failed_without_backend_switch(monkeypatch, tmp_path):
    calls = []

    def fake_run(cmd, capture_output, text, timeout, check, env=None):
        calls.append(cmd)
        args = cmd[4:]
        if args == ["network", "requests"]:
            return SimpleNamespace(
                returncode=1,
                stdout=json.dumps({"success": False, "data": None, "error": "request protocol failed"}),
                stderr="",
            )
        if args == ["snapshot"]:
            data = {"snapshot": "heading \"Target\""}
        elif args == ["console"]:
            data = {"messages": []}
        elif args[:2] == ["state", "save"]:
            Path(args[-1]).write_text("{}", encoding="utf-8")
            data = {"saved": True}
        else:
            data = {}
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps({"success": True, "data": data, "error": None}),
            stderr="",
        )

    monkeypatch.setattr(browser_evidence.subprocess, "run", fake_run)

    summary = browser_evidence.capture_browser_evidence(
        "target.local",
        "https://target.local/",
        evidence_root=tmp_path / "evidence",
        backend="agent-browser",
    )

    assert summary["success"] is False
    assert summary["error"] == "request protocol failed"
    assert all(cmd[0] == "agent-browser" for cmd in calls)


def test_agent_browser_optional_artifact_failure_keeps_core_capture(monkeypatch, tmp_path):
    def fake_run(cmd, capture_output, text, timeout, check, env=None):
        args = cmd[4:]
        if args in (["cookies", "get"], ["storage", "local"], ["storage", "session"]):
            return SimpleNamespace(
                returncode=1,
                stdout=json.dumps({"success": False, "data": None, "error": "optional denied"}),
                stderr="optional denied",
            )
        if args[:2] == ["state", "save"] or (args and args[0] == "screenshot"):
            return SimpleNamespace(
                returncode=1,
                stdout=json.dumps({"success": False, "data": None, "error": "artifact unavailable"}),
                stderr="artifact unavailable",
            )
        if args == ["snapshot"]:
            data = {"snapshot": "heading \"Target\""}
        elif args == ["network", "requests"]:
            data = {"requests": [{"url": "https://target.local/api", "method": "GET"}]}
        elif args == ["console"]:
            data = {"messages": []}
        else:
            data = {}
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps({"success": True, "data": data, "error": None}),
            stderr="",
        )

    monkeypatch.setattr(browser_evidence.subprocess, "run", fake_run)

    summary = browser_evidence.capture_browser_evidence(
        "target.local",
        "https://target.local/",
        evidence_root=tmp_path / "evidence",
        backend="agent-browser",
        capture_screenshot=True,
    )

    assert summary["success"] is True
    assert summary.get("error", "") == ""
    assert len(summary["warnings"]) >= 5
    assert any(item["step"].startswith("cookies get") for item in summary["warnings"])
