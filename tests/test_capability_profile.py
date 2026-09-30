"""Startup discovery reports local facts, never family or MCP readiness."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from tools import capability_profile
from tools.target_store import TargetStore
from tools.capability_profile import build_capability_profile, unknown_capability_profile
from tools.autopilot_bootstrap import build_autopilot_bootstrap


def test_local_discovery_full_and_empty_are_not_readiness(monkeypatch, tmp_path):
    calls = []

    def which(name):
        calls.append(name)
        return "/private/bin/" + name

    def unexpected(*args, **kwargs):
        raise AssertionError("discovery must not execute tools")

    monkeypatch.setattr(subprocess, "run", unexpected)
    monkeypatch.setattr(subprocess, "Popen", unexpected)
    monkeypatch.setattr(capability_profile, "resolve_eburst", lambda **kw: {"status": "ready"})
    for path in capability_profile.LOCAL_FILES:
        local = tmp_path / path
        local.parent.mkdir(parents=True, exist_ok=True)
        local.write_text("fixture")
    profile = build_capability_profile(tmp_path, which=which)
    assert profile["available"] == list(capability_profile.LOCAL_TOOLS)
    assert profile["missing"] == []
    assert all(profile["local_files"].values())
    assert len(calls) == len(set(calls)) == len(capability_profile.LOCAL_TOOLS) - 1
    assert "/private" not in json.dumps(profile)
    assert profile["status"] == "checked"
    assert profile["session_status"] == "unchecked"
    assert profile["session_managed"] == ["chrome-devtools-mcp", "playwright-mcp"]
    for path in capability_profile.LOCAL_FILES:
        (tmp_path / path).unlink()
    monkeypatch.setattr(capability_profile, "resolve_eburst", lambda **kw: {"status": "missing_interpreter"})
    missing = build_capability_profile(tmp_path, which=lambda _: None)
    assert missing["available"] == []
    assert missing["missing"] == list(capability_profile.LOCAL_TOOLS)
    assert not any(missing["local_files"].values())
    assert missing["checked"] is True
    assert missing["status"] == "checked"
    assert unknown_capability_profile()["checked"] is False
    assert unknown_capability_profile()["status"] == "unknown"
    assert set(profile) == {
        "schema_version", "checked", "status", "available", "missing", "local_files",
        "session_managed", "session_status",
    }
    assert profile["schema_version"] == 2


def test_importer_presence_does_not_claim_session_backend(monkeypatch, tmp_path):
    importer = tmp_path / "tools/browser_mcp_import.py"
    importer.parent.mkdir()
    importer.write_text("fixture")
    monkeypatch.setattr(capability_profile, "resolve_eburst", lambda **kw: {"status": "missing_script"})
    profile = build_capability_profile(tmp_path, which=lambda _: None)
    assert profile["local_files"]["tools/browser_mcp_import.py"] is True
    assert profile["available"] == []
    assert profile["session_status"] == "unchecked"
    assert "ready" not in json.dumps(profile)


def _prepare_runtime_fixture(tmp_path):
    """审计 F6：测试自备临时 runtime，不依赖开发者真实 ~/.claude 安装。

    把 repo 的 commands/agents/skills 复制进临时根（同 runtime_doctor 的
    RUNTIME_SUBDIRS 布局），并设置 CCST_RUNTIME_ROOT 指向它。
    """
    import shutil

    repo_root = Path(__file__).resolve().parent.parent
    runtime_root = tmp_path / "runtime-home" / ".claude"
    layout = {
        "commands": repo_root / "commands",
        "agents": repo_root / "agents",
        "skills": repo_root / "skills",
    }
    for subdir, src in layout.items():
        if not src.is_dir():
            continue
        shutil.copytree(src, runtime_root / subdir)
    return runtime_root


def test_bootstrap_carry_real_capability_profile(monkeypatch, tmp_path):
    """bootstrap 的 continue 路径必须带真实能力快照（回归 profile-error 降级）。

    审计 F6：真实 bootstrap 会先做 runtime drift 检查；干净环境（无
    ~/.claude 安装）缺三个 critical 文件时生产代码正确返回
    stop_runtime_drift，能力快照未检查——旧断言在这种情况下失败并依赖
    开发者本机安装。测试现在显式准备临时 runtime（CCST_RUNTIME_ROOT）。
    """
    runtime_root = _prepare_runtime_fixture(tmp_path)
    monkeypatch.setenv("CCST_RUNTIME_ROOT", str(runtime_root))
    import shutil
    for subdir in ("commands", "agents", "skills"):
        shutil.copytree(runtime_root / subdir, tmp_path / subdir)
    TargetStore(tmp_path, "capability.test").initialize()
    payload = build_autopilot_bootstrap(["capability.test", "--deep"], repo_root=tmp_path)
    assert payload["action"] != "stop_runtime_drift", (
        f"temp runtime fixture must satisfy critical drift gate: {payload.get('runtime', {}).get('missing_critical')}"
    )
    caps = payload["capabilities"]
    assert caps["checked"] is True
    assert caps["status"] == "checked"
    assert caps.get("reason", "") != "profile-error"
    assert "lanes" not in caps
    assert caps["session_status"] == "unchecked"


def test_bootstrap_stops_on_missing_runtime_short_circuits_capability(monkeypatch, tmp_path):
    """审计 F6 负例：缺 runtime 时 bootstrap 必须 stop_runtime_drift，
    能力快照保持未检查（checked=false）——生产短路行为本身是正确的。"""
    monkeypatch.setenv("CCST_RUNTIME_ROOT", str(tmp_path / "nowhere"))
    TargetStore(tmp_path, "capability.test").initialize()
    payload = build_autopilot_bootstrap(["capability.test", "--deep"], repo_root=tmp_path)
    assert payload["action"] == "stop_runtime_drift"
    assert payload["capabilities"]["checked"] is False
