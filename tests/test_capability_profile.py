"""`/autopilot` 最小工具能力快照回归。"""

from __future__ import annotations

import json
from pathlib import Path

from tools.capability_profile import (
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
    "tools/browser_evidence.py",
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

    assert profile == {
        "schema_version": 1,
        "checked": True,
        "status": "ready",
        "available": {
            "browser": ["playwright-cli"],
            "recon": ["subfinder", "httpx", "katana", "gau", "waybackurls", "ffuf"],
            "scanner": ["nuclei"],
        },
        "session_managed": list(SESSION_MANAGED),
        "fallbacks": [
            "curl-native-http",
            "browser-evidence-cli",
            "source-js-enrichment",
        ],
        "missing_core": [],
        "missing_optional": [],
        "recommended_paths": [
            "prefer-session-browser-mcp",
            "browser-evidence-cli",
            "recon-engine-httpx",
            "scanner-native-plus-nuclei",
        ],
    }
    encoded = json.dumps(profile, sort_keys=True)
    assert str(tmp_path) not in encoded
    assert len(encoded) < 2_000
    for value in (
        *profile["available"].values(),
        profile["session_managed"],
        profile["fallbacks"],
        profile["missing_core"],
        profile["missing_optional"],
        profile["recommended_paths"],
    ):
        assert len(value) <= MAX_LIST_ITEMS


def test_empty_path_keeps_session_capabilities_advisory_and_uses_source_fallback(tmp_path):
    repo = _repo_with_helpers(tmp_path)

    profile = build_capability_profile(repo, which=lambda _tool: None)

    assert profile["checked"] is True
    assert profile["status"] == "degraded"
    assert profile["available"] == {
        "browser": [],
        "recon": [],
        "scanner": [],
    }
    assert profile["session_managed"] == list(SESSION_MANAGED)
    assert profile["fallbacks"] == ["source-js-enrichment"]
    assert profile["missing_core"] == ["curl", "httpx"]
    assert profile["missing_optional"] == [
        "playwright-cli",
        "subfinder",
        "katana",
        "gau",
        "waybackurls",
        "ffuf",
        "nuclei",
    ]
    assert profile["recommended_paths"] == [
        "prefer-session-browser-mcp",
        "source-js-enrichment",
        "recon-source-js-only",
        "scanner-manual-evidence-only",
    ]


def test_fallbacks_require_their_local_helpers(tmp_path):
    repo = _repo_with_helpers(
        tmp_path,
        helpers=("tools/source_intel.py",),
    )

    profile = build_capability_profile(
        repo,
        which=_which_with("curl", "httpx", "playwright-cli", "nuclei"),
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


def test_unknown_profile_is_distinct_from_checked_but_degraded():
    profile = unknown_capability_profile("profile-error")

    assert profile == {
        "schema_version": 1,
        "checked": False,
        "status": "unknown",
        "available": {"browser": [], "recon": [], "scanner": []},
        "session_managed": [],
        "fallbacks": [],
        "missing_core": [],
        "missing_optional": [],
        "recommended_paths": [],
        "reason": "profile-error",
    }
