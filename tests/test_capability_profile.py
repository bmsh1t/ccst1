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
    "tools/workflow_sequence.py",
    "tools/timing_sql_runner.py",
    "tools/validation_runner.py",
    "tools/target_case_state.py",
    "tools/cloud_recon.sh",
    "tools/oast_listen.py",
    "commands/web3-audit.md",
    "skills/web3-audit/SKILL.md",
    "commands/intel.md",
    "tools/intel_engine.py",
    "tools/intel_artifact.py",
    "tools/intel_sources.py",
    "tools/intel_continuation.py",
    "tools/intelligence_extractor.py",
    "tools/technology_inventory.py",
    "tools/web_intel_artifact.py",
    "commands/spray.md",
    "skills/credential-attack/SKILL.md",
    "tools/auth_session.py",
    "tools/credential_store.py",
    "tools/spray_contract.py",
    "tools/spray_orchestrator.sh",
    "tools/_spray_http_form.py",
    "tools/_spray_oauth.py",
    "tools/_spray_trevor.py",
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
    assert all(lane["checked"] for lane in lanes.values())
    assert all(
        lane["ready"]
        for lane_id, lane in lanes.items()
        if lane_id not in {"browser", "cloud", "oast"}
    )
    assert lanes["browser"]["ready"] is False
    assert lanes["browser"]["classification"] == "artifact_bridge"
    assert lanes["browser"]["runtime_status"] == "unchecked"
    assert lanes["browser"]["bridge_ready"] is True
    assert lanes["browser"]["profile_version"] == 3
    assert lanes["browser"]["missing"] == ["session-browser-mcp"]
    assert lanes["browser"]["degraded"] == ["session-browser-mcp-unchecked"]
    assert lanes["oast"]["degraded"] == ["manual-oast-provider"]
    assert lanes["oast"]["ready"] is False
    assert lanes["oast"]["runtime_status"] == "degraded"
    assert lanes["oast"]["missing"] == ["interactsh-client"]
    assert lanes["cloud"]["ready"] is False
    assert lanes["cloud"]["runtime_status"] == "degraded"
    assert lanes["cloud"]["missing"] == ["cloud-provider-tool"]
    assert lanes["web3"]["degraded"] == ["static-review-only"]
    assert lanes["web3"]["ready"] is True
    assert lanes["web3"]["runtime_status"] == "degraded"
    assert lanes["web3"]["missing"] == ["foundry-forge"]
    assert lanes["intel"]["ready"] is True
    assert lanes["intel"]["runtime_status"] == "ready"
    assert lanes["intel"]["missing"] == []
    assert lanes["credential"]["ready"] is True
    assert lanes["credential"]["runtime_status"] == "ready"
    assert lanes["credential"]["missing"] == []
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
    assert lanes["intel"]["ready"] is True
    assert lanes["intel"]["runtime_status"] == "ready"
    assert lanes["credential"]["ready"] is True
    assert lanes["credential"]["runtime_status"] == "ready"


def test_browser_cli_presence_does_not_change_mcp_only_profile(tmp_path):
    repo = _repo_with_helpers(tmp_path)

    profile = build_capability_profile(
        repo,
        which=_which_with("curl", "httpx", "nuclei"),
    )

    assert profile["available"]["browser"] == []
    assert "browser-mcp-evidence-import" in profile["fallbacks"]
    lanes = {lane["id"]: lane for lane in profile["lanes"]}
    assert lanes["browser"]["ready"] is False
    assert lanes["browser"]["classification"] == "artifact_bridge"
    assert lanes["browser"]["bridge_ready"] is True
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
    browser = next(lane for lane in profile["lanes"] if lane["id"] == "browser")
    assert browser["ready"] is False
    assert browser["classification"] == "session_managed"
    assert browser["runtime_status"] == "unchecked"
    assert browser["bridge_ready"] is False
    assert profile["lanes"][-2]["id"] == "intel"
    assert profile["lanes"][-2]["ready"] is False
    assert profile["lanes"][-2]["runtime_status"] == "unavailable"
    assert profile["lanes"][-2]["missing"] == [
        "commands/intel.md+tools/intel_engine.py+intel_artifact.py",
        "tools/web_intel_artifact.py",
    ]
    assert profile["lanes"][-1]["id"] == "credential"
    assert profile["lanes"][-1]["ready"] is False
    assert profile["lanes"][-1]["runtime_status"] == "unavailable"
    assert profile["lanes"][-1]["missing"] == ["commands/spray.md+credential-attack"]


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


def test_sql_and_waf_lanes_use_ai_transport_and_recon_context(tmp_path):
    repo = _repo_with_helpers(tmp_path)

    profile = build_capability_profile(
        repo,
        which=_which_with("curl", "httpx", "interactsh-client", "forge"),
    )
    lanes = {lane["id"]: lane for lane in profile["lanes"]}

    assert lanes["sql"]["ready"] is True
    assert lanes["sql"]["classification"] == "ai_selected"
    assert lanes["sql"]["tool_refs"] == ["ai-http-transport"]
    assert lanes["waf"]["ready"] is True
    assert lanes["waf"]["classification"] == "context_only"
    assert lanes["waf"]["tool_refs"] == ["recon-waf-context"]
    assert lanes["browser"]["classification"] == "artifact_bridge"


def test_optional_backend_state_is_not_inferred_from_transport_or_docs(tmp_path):
    repo = _repo_with_helpers(tmp_path)
    profile = build_capability_profile(
        repo,
        which=_which_with("curl", "httpx"),
    )
    lanes = {lane["id"]: lane for lane in profile["lanes"]}

    assert lanes["cloud"]["ready"] is False
    assert lanes["cloud"]["missing"] == ["cloud-provider-tool"]
    assert lanes["cloud"]["runtime_status"] == "degraded"
    assert lanes["oast"]["ready"] is False
    assert lanes["oast"]["missing"] == ["interactsh-client"]
    assert lanes["oast"]["runtime_status"] == "degraded"
    assert lanes["web3"]["ready"] is True
    assert lanes["web3"]["missing"] == ["foundry-forge"]
    assert lanes["web3"]["runtime_status"] == "degraded"


def test_intel_and_credential_lanes_require_real_local_entrypoints(tmp_path):
    repo = _repo_with_helpers(tmp_path)
    (repo / "tools" / "web_intel_artifact.py").unlink()
    (repo / "tools" / "_spray_oauth.py").unlink()

    profile = build_capability_profile(repo, which=_which_with("curl", "httpx"))
    lanes = {lane["id"]: lane for lane in profile["lanes"]}

    assert lanes["intel"]["ready"] is False
    assert lanes["intel"]["runtime_status"] == "unavailable"
    assert lanes["intel"]["missing"] == ["tools/web_intel_artifact.py"]
    assert lanes["intel"]["degraded"] == ["web-intel-recorder-unavailable"]
    assert lanes["credential"]["ready"] is False
    assert lanes["credential"]["runtime_status"] == "unavailable"
    assert lanes["credential"]["missing"] == [
        "commands/spray.md+credential-attack"
    ]


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
    assert all(lane["classification"] == "unknown" for lane in profile["lanes"])
    assert all(lane["runtime_status"] == "unchecked" for lane in profile["lanes"])
