"""`/autopilot` 最小工具能力快照回归。"""

from __future__ import annotations

import json
from pathlib import Path

from tools.capability_profile import (
    LANE_IDS,
    MAX_LIST_ITEMS,
    SESSION_MANAGED,
    TOOL_REGISTRY,
    build_capability_profile,
    unknown_capability_profile,
)


HELPERS = (
    "tools/recon_engine.sh",
    "tools/vuln_scanner.sh",
    "tools/source_intel.py",
    "tools/js_reader.py",
    "tools/browser_mcp_import.py",
    "tools/dns_expand.py",
    "tools/surface.py",
    "tools/surface_projection.py",
    "tools/sql_parameter_probe.py",
    "tools/json_inject_probe.py",
    "tools/workflow_sequence.py",
    "tools/timing_sql_runner.py",
    "tools/validation_runner.py",
    "tools/target_case_state.py",
    "tools/waf_pass_plan.py",
    "tools/waf_response_analyzer.py",
    "tools/cloud_recon.sh",
    "tools/oast_listen.py",
    "commands/web3-audit.md",
    "skills/web3-audit/SKILL.md",
)


def _repo_with_helpers(root: Path, helpers: tuple[str, ...] = HELPERS) -> Path:
    for relative_path in helpers:
        path = root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("# fixture\n", encoding="utf-8")
    return root


def _which_with(*available_tools: str):
    available = set(available_tools)
    return lambda tool: f"/fixture/bin/{tool}" if tool in available else None


def test_full_profile_is_ordered_bounded_and_path_free(tmp_path):
    repo = _repo_with_helpers(tmp_path)
    tools = [tool for category in TOOL_REGISTRY.values() for tool in category]

    profile = build_capability_profile(
        repo,
        which=_which_with(*tools, "curl"),
    )

    assert {key: value for key, value in profile.items() if key != "lanes"} == {
        "schema_version": 1,
        "checked": True,
        "status": "ready",
        "available": {
            "browser": [],
            "recon": ["subfinder", "httpx", "katana", "gau", "waybackurls", "ffuf"],
            "scanner": ["nuclei"],
            "dns-expansion": ["alterx", "dnsgen", "puredns"],
            "exchange": ["eburst"],
        },
        "session_managed": list(SESSION_MANAGED),
        "fallbacks": [
            "curl-native-http",
            "browser-mcp-evidence-import",
            "source-js-enrichment",
        ],
        "missing_core": [],
        "missing_optional": [],
        "recommended_paths": [
            "prefer-session-browser-mcp",
            "browser-mcp-evidence-import",
            "recon-engine-httpx",
            "dns-expansion-evidence-gated",
            "scanner-native-plus-nuclei",
        ],
    }
    lanes = {lane["id"]: lane for lane in profile["lanes"]}
    assert tuple(lanes) == LANE_IDS
    assert all(lane["checked"] and lane["ready"] for lane in lanes.values())
    assert lanes["browser"]["degraded"] == ["session-browser-mcp-unchecked"]
    assert lanes["oast"]["degraded"] == ["manual-oast-provider"]
    assert lanes["web3"]["degraded"] == ["static-review-only"]
    assert all(lane["input_fingerprint"].startswith("sha256:") for lane in lanes.values())
    encoded = json.dumps(profile, sort_keys=True)
    assert str(tmp_path) not in encoded
    assert len(encoded) < 10_000
    for value in (
        *profile["available"].values(),
        profile["session_managed"],
        profile["fallbacks"],
        profile["missing_core"],
        profile["missing_optional"],
        profile["recommended_paths"],
        profile["lanes"],
    ):
        assert len(value) <= MAX_LIST_ITEMS
    for lane in profile["lanes"]:
        for key in ("missing", "degraded", "evidence_required", "tool_refs"):
            assert len(lane[key]) <= MAX_LIST_ITEMS


def test_empty_path_keeps_session_capabilities_advisory_and_uses_source_fallback(tmp_path):
    repo = _repo_with_helpers(tmp_path)

    profile = build_capability_profile(repo, which=lambda _tool: None)

    assert profile["checked"] is True
    assert profile["status"] == "degraded"
    assert profile["available"] == {
        "browser": [],
        "recon": [],
        "scanner": [],
        "dns-expansion": [],
        "exchange": [],
    }
    assert profile["session_managed"] == list(SESSION_MANAGED)
    assert profile["fallbacks"] == ["browser-mcp-evidence-import", "source-js-enrichment"]
    assert profile["missing_core"] == ["curl", "httpx"]
    assert profile["missing_optional"] == [
        "subfinder",
        "katana",
        "gau",
        "waybackurls",
        "ffuf",
        "nuclei",
        "alterx",
        "dnsgen",
        "puredns",
        "eburst",
    ]
    assert profile["recommended_paths"] == [
        "prefer-session-browser-mcp",
        "browser-mcp-evidence-import",
        "recon-source-js-only",
        "scanner-manual-evidence-only",
    ]
    lanes = {lane["id"]: lane for lane in profile["lanes"]}
    assert lanes["recon"]["ready"] is False
    assert lanes["recon"]["missing"] == ["httpx-or-curl"]
    assert lanes["cloud"]["missing"] == ["cloud-provider-tool"]
    assert lanes["surface"]["ready"] is True


def test_browser_cli_presence_does_not_change_mcp_only_profile(tmp_path):
    repo = _repo_with_helpers(tmp_path)

    profile = build_capability_profile(
        repo,
        which=_which_with("curl", "httpx", "nuclei"),
    )

    assert profile["available"]["browser"] == []
    assert "browser-mcp-evidence-import" in profile["fallbacks"]
    assert profile["recommended_paths"][:2] == [
        "prefer-session-browser-mcp",
        "browser-mcp-evidence-import",
    ]


def test_fallbacks_require_their_local_helpers(tmp_path):
    repo = _repo_with_helpers(
        tmp_path,
        helpers=("tools/source_intel.py",),
    )

    profile = build_capability_profile(
        repo,
        which=_which_with("curl", "httpx", "nuclei"),
    )

    assert profile["status"] == "degraded"
    assert profile["fallbacks"] == []
    assert profile["missing_core"] == ["recon-engine", "vuln-scanner"]
    assert profile["recommended_paths"] == [
        "prefer-session-browser-mcp",
        "recon-manual-evidence-only",
        "scanner-manual-evidence-only",
    ]


def test_profile_is_read_only(tmp_path):
    repo = _repo_with_helpers(tmp_path)
    before = {
        path.relative_to(repo): path.read_bytes()
        for path in repo.rglob("*")
        if path.is_file()
    }

    build_capability_profile(repo, which=_which_with("curl", "httpx"))

    after = {
        path.relative_to(repo): path.read_bytes()
        for path in repo.rglob("*")
        if path.is_file()
    }
    assert after == before


def test_missing_sql_helper_only_degrades_sql_lane(tmp_path):
    helpers = tuple(path for path in HELPERS if path != "tools/sql_parameter_probe.py")
    repo = _repo_with_helpers(tmp_path, helpers=helpers)

    profile = build_capability_profile(
        repo,
        which=_which_with("curl", "httpx", "interactsh-client", "forge"),
    )
    lanes = {lane["id"]: lane for lane in profile["lanes"]}

    assert lanes["sql"]["ready"] is False
    assert lanes["sql"]["missing"] == ["tools/sql_parameter_probe.py+json_inject_probe.py"]
    assert all(lane["ready"] for lane_id, lane in lanes.items() if lane_id != "sql")


def test_unknown_profile_is_distinct_from_checked_but_degraded():
    profile = unknown_capability_profile("profile-error")

    assert {key: value for key, value in profile.items() if key != "lanes"} == {
        "schema_version": 1,
        "checked": False,
        "status": "unknown",
        "available": {
            "browser": [],
            "recon": [],
            "scanner": [],
            "dns-expansion": [],
            "exchange": [],
        },
        "session_managed": [],
        "fallbacks": [],
        "missing_core": [],
        "missing_optional": [],
        "recommended_paths": [],
        "reason": "profile-error",
    }
    assert [lane["id"] for lane in profile["lanes"]] == list(LANE_IDS)
    assert all(lane["checked"] is False for lane in profile["lanes"])
    assert all(lane["degraded"] == ["profile-error"] for lane in profile["lanes"])
