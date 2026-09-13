"""capability_profile: lane construction must never crash the bootstrap.

回归：`_lane_record("workflow")` / `_lane_record("timing")` 曾漏传必填
`inputs`，`build_capability_profile()` 直接 TypeError，bootstrap 的能力快照
降级为 `unknown/profile-error`，14 条 lane 全部失明（外部实测报障）。
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.capability_profile import build_capability_profile
from tools.autopilot_bootstrap import build_autopilot_bootstrap


LANE_IDS = {
    "recon", "surface", "browser", "source_js", "sql", "workflow", "timing",
    "idor_authz", "waf", "cloud", "oast", "web3", "intel", "credential",
}


def test_capability_profile_builds_all_lanes_without_error():
    profile = build_capability_profile()
    assert profile["checked"] is True
    lane_ids = {lane["id"] for lane in profile["lanes"]}
    assert lane_ids == LANE_IDS
    for lane in profile["lanes"]:
        # 每条 lane 都是真实记录（不是 profile-error 占位）
        assert lane["checked"] is True
        assert lane["classification"] != "unknown"
        assert "profile-error" not in lane.get("degraded", [])


def test_ai_carried_lanes_bind_http_transport():
    """workflow/timing/sql 的 readiness 由 AI HTTP transport 决定，不再缺 inputs。"""
    profile = build_capability_profile()
    lanes = {lane["id"]: lane for lane in profile["lanes"]}
    for lane_id in ("workflow", "timing", "sql"):
        assert "ai-http-transport" in lanes[lane_id]["tool_refs"], lane_id


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
    payload = build_autopilot_bootstrap(["127.0.0.1:3001", "--deep"])
    assert payload["action"] != "stop_runtime_drift", (
        f"temp runtime fixture must satisfy critical drift gate: {payload.get('runtime', {}).get('missing_critical')}"
    )
    caps = payload["capabilities"]
    assert caps["checked"] is True
    assert caps["status"] in ("ready", "degraded")
    assert caps.get("reason", "") != "profile-error"
    assert len(caps["lanes"]) == len(LANE_IDS)


def test_bootstrap_stops_on_missing_runtime_short_circuits_capability(monkeypatch, tmp_path):
    """审计 F6 负例：缺 runtime 时 bootstrap 必须 stop_runtime_drift，
    能力快照保持未检查（checked=false）——生产短路行为本身是正确的。"""
    monkeypatch.setenv("CCST_RUNTIME_ROOT", str(tmp_path / "nowhere"))
    payload = build_autopilot_bootstrap(["127.0.0.1:3001", "--deep"])
    assert payload["action"] == "stop_runtime_drift"
    assert payload["capabilities"]["checked"] is False
