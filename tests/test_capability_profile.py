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


def test_bootstrap_carry_real_capability_profile():
    """bootstrap 的 continue 路径必须带真实能力快照（回归 profile-error 降级）。"""
    payload = build_autopilot_bootstrap(["127.0.0.1:3001", "--deep"])
    caps = payload["capabilities"]
    assert caps["checked"] is True
    assert caps["status"] in ("ready", "degraded")
    assert caps.get("reason", "") != "profile-error"
    assert len(caps["lanes"]) == len(LANE_IDS)
