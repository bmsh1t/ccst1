#!/usr/bin/env python3
"""生成 `/autopilot` 启动期最小工具能力快照。"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Callable


SCHEMA_VERSION = 1
MAX_LIST_ITEMS = 16
REPO_ROOT = Path(__file__).resolve().parents[1]

TOOL_REGISTRY: dict[str, tuple[str, ...]] = {
    "browser": ("agent-browser", "playwright-cli"),
    "recon": ("subfinder", "httpx", "katana", "gau", "waybackurls", "ffuf"),
    "scanner": ("nuclei",),
}
SESSION_MANAGED = ("chrome-devtools-mcp", "playwright-mcp")
CORE_EXTERNAL_TOOLS = ("curl", "httpx")

Which = Callable[[str], str | None]


def unknown_capability_profile(reason: str = "not-checked") -> dict:
    """返回 schema 合法的未检查视图，供启动短路和 fail-soft 使用。"""
    return {
        "schema_version": SCHEMA_VERSION,
        "checked": False,
        "status": "unknown",
        "available": {category: [] for category in TOOL_REGISTRY},
        "session_managed": [],
        "fallbacks": [],
        "missing_core": [],
        "missing_optional": [],
        "recommended_paths": [],
        "reason": reason,
    }


def _bounded(values: list[str]) -> list[str]:
    """固定启动 JSON 的最大体积，并保留 registry 声明顺序。"""
    return values[:MAX_LIST_ITEMS]


def _helpers_exist(repo_root: Path, *relative_paths: str) -> bool:
    return all((repo_root / relative_path).is_file() for relative_path in relative_paths)


def build_capability_profile(
    repo_root: str | Path | None = None,
    *,
    which: Which = shutil.which,
) -> dict:
    """只读检查固定核心工具，不执行版本 probe、网络请求或实际扫描。"""
    resolved_repo = Path(repo_root or REPO_ROOT).resolve()
    available: dict[str, list[str]] = {}
    missing_optional: list[str] = []

    for category, tools in TOOL_REGISTRY.items():
        category_available = []
        for tool in tools:
            if which(tool):
                category_available.append(tool)
            elif tool not in CORE_EXTERNAL_TOOLS:
                missing_optional.append(tool)
        available[category] = _bounded(category_available)

    curl_available = bool(which("curl"))
    recon_engine_ready = _helpers_exist(resolved_repo, "tools/recon_engine.sh")
    scanner_engine_ready = _helpers_exist(resolved_repo, "tools/vuln_scanner.sh")
    local_pipeline_ready = recon_engine_ready and scanner_engine_ready
    source_js_ready = _helpers_exist(
        resolved_repo,
        "tools/source_intel.py",
        "tools/js_reader.py",
    )
    browser_evidence_ready = _helpers_exist(resolved_repo, "tools/browser_evidence.py")
    agent_browser_ready = "agent-browser" in available["browser"] and browser_evidence_ready
    playwright_ready = "playwright-cli" in available["browser"] and browser_evidence_ready

    missing_core: list[str] = []
    if not curl_available:
        missing_core.append("curl")
    if "httpx" not in available["recon"]:
        missing_core.append("httpx")
    if not recon_engine_ready:
        missing_core.append("recon-engine")
    if not scanner_engine_ready:
        missing_core.append("vuln-scanner")

    fallbacks: list[str] = []
    if curl_available and local_pipeline_ready:
        fallbacks.append("curl-native-http")
    if agent_browser_ready:
        fallbacks.append("agent-browser-evidence-cli")
    if playwright_ready:
        fallbacks.append("playwright-browser-evidence-cli")
    if source_js_ready:
        fallbacks.append("source-js-enrichment")

    recommended_paths = []
    if agent_browser_ready:
        recommended_paths.append("agent-browser-evidence-cli")
    recommended_paths.append("prefer-session-browser-mcp")
    if playwright_ready:
        recommended_paths.append("playwright-browser-evidence-cli")
    elif source_js_ready:
        recommended_paths.append("source-js-enrichment")

    if "httpx" in available["recon"] and local_pipeline_ready:
        recommended_paths.append("recon-engine-httpx")
    elif "curl-native-http" in fallbacks:
        recommended_paths.append("recon-limited-native-http")
    elif source_js_ready:
        recommended_paths.append("recon-source-js-only")
    else:
        recommended_paths.append("recon-manual-evidence-only")

    if "nuclei" in available["scanner"] and "curl-native-http" in fallbacks:
        recommended_paths.append("scanner-native-plus-nuclei")
    elif "curl-native-http" in fallbacks:
        recommended_paths.append("scanner-native-http")
    else:
        recommended_paths.append("scanner-manual-evidence-only")

    return {
        "schema_version": SCHEMA_VERSION,
        "checked": True,
        "status": "ready" if not missing_core else "degraded",
        "available": available,
        "session_managed": _bounded(list(SESSION_MANAGED)),
        "fallbacks": _bounded(fallbacks),
        "missing_core": _bounded(missing_core),
        "missing_optional": _bounded(missing_optional),
        "recommended_paths": _bounded(recommended_paths),
    }
