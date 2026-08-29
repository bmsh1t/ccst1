#!/usr/bin/env python3
"""生成 `/autopilot` 启动期最小工具能力快照。"""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from typing import Callable

try:
    from tools.eburst_lane import resolve_eburst
except ImportError:  # pragma: no cover - direct tools/ execution
    from eburst_lane import resolve_eburst  # type: ignore


SCHEMA_VERSION = 1
MAX_LIST_ITEMS = 16
REPO_ROOT = Path(__file__).resolve().parents[1]

TOOL_REGISTRY: dict[str, tuple[str, ...]] = {
    # 浏览器执行由 Claude 会话中的 MCP 管理，不再探测本地浏览器 CLI。
    "browser": (),
    "recon": ("subfinder", "httpx", "katana", "gau", "waybackurls", "ffuf"),
    "scanner": ("nuclei",),
    "dns-expansion": ("alterx", "dnsgen", "puredns"),
    "exchange": ("eburst",),
}
SESSION_MANAGED = ("chrome-devtools-mcp", "playwright-mcp")
CORE_EXTERNAL_TOOLS = ("curl", "httpx")
LANE_PROFILE_VERSION = 3
LANE_IDS = (
    "recon",
    "surface",
    "browser",
    "source_js",
    "sql",
    "workflow",
    "timing",
    "idor_authz",
    "waf",
    "cloud",
    "oast",
    "web3",
    "intel",
    "credential",
)

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
        "lanes": [
            {
                "id": lane_id,
                "checked": False,
                "ready": False,
                "missing": [],
                "degraded": [reason],
                "evidence_required": [],
                "tool_refs": [],
                "classification": "unknown",
                "runtime_status": "unchecked",
                "profile_version": LANE_PROFILE_VERSION,
                "input_fingerprint": "",
            }
            for lane_id in LANE_IDS
        ],
        "reason": reason,
    }


def _bounded(values: list[str]) -> list[str]:
    """固定启动 JSON 的最大体积，并保留 registry 声明顺序。"""
    return values[:MAX_LIST_ITEMS]


def _helpers_exist(repo_root: Path, *relative_paths: str) -> bool:
    return all((repo_root / relative_path).is_file() for relative_path in relative_paths)


def _lane_record(
    lane_id: str,
    inputs: dict[str, bool],
    *,
    evidence_required: tuple[str, ...],
    degraded: tuple[str, ...] = (),
    classification: str = "executable",
    runtime_status: str | None = None,
    ready_override: bool | None = None,
) -> dict:
    encoded = json.dumps(inputs, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    ready = all(inputs.values()) if ready_override is None else ready_override
    return {
        "id": lane_id,
        "checked": True,
        "ready": ready,
        "missing": _bounded([name for name, present in inputs.items() if not present]),
        "degraded": _bounded(list(degraded)),
        "evidence_required": _bounded(list(evidence_required)),
        "tool_refs": _bounded(list(inputs)),
        "classification": classification,
        "runtime_status": runtime_status or ("ready" if ready else "unavailable"),
        "profile_version": LANE_PROFILE_VERSION,
        "input_fingerprint": f"sha256:{hashlib.sha256(encoded.encode('utf-8')).hexdigest()}",
    }


def build_capability_profile(
    repo_root: str | Path | None = None,
    *,
    which: Which | None = None,
) -> dict:
    """只读检查固定核心工具，不执行版本 probe、网络请求或实际扫描。"""
    resolved_repo = Path(repo_root or REPO_ROOT).resolve()
    resolver = which or shutil.which
    available: dict[str, list[str]] = {}
    missing_optional: list[str] = []

    for category, tools in TOOL_REGISTRY.items():
        category_available = []
        for tool in tools:
            is_available = (
                resolve_eburst(which=resolver).get("status") == "ready"
                if tool == "eburst"
                else bool(resolver(tool))
            )
            if is_available:
                category_available.append(tool)
            elif tool not in CORE_EXTERNAL_TOOLS:
                missing_optional.append(tool)
        available[category] = _bounded(category_available)

    curl_available = bool(resolver("curl"))
    recon_engine_ready = _helpers_exist(resolved_repo, "tools/recon_engine.sh")
    scanner_engine_ready = _helpers_exist(resolved_repo, "tools/vuln_scanner.sh")
    local_pipeline_ready = recon_engine_ready and scanner_engine_ready
    source_js_ready = _helpers_exist(
        resolved_repo,
        "tools/source_intel.py",
        "tools/js_reader.py",
    )
    browser_mcp_import_ready = _helpers_exist(resolved_repo, "tools/browser_mcp_import.py")
    dns_expansion_ready = _helpers_exist(resolved_repo, "tools/dns_expand.py")
    surface_ready = _helpers_exist(resolved_repo, "tools/surface.py", "tools/surface_projection.py")
    sql_ready = _helpers_exist(resolved_repo, "tools/sql_parameter_probe.py", "tools/json_inject_probe.py")
    workflow_ready = _helpers_exist(resolved_repo, "tools/workflow_sequence.py")
    timing_ready = _helpers_exist(resolved_repo, "tools/timing_sql_runner.py")
    idor_authz_ready = _helpers_exist(
        resolved_repo,
        "tools/validation_runner.py",
        "tools/target_case_state.py",
    )
    waf_ready = _helpers_exist(
        resolved_repo,
        "tools/waf_pass_plan.py",
        "tools/waf_response_analyzer.py",
    )
    cloud_ready = _helpers_exist(resolved_repo, "tools/cloud_recon.sh")
    oast_ready = _helpers_exist(resolved_repo, "tools/oast_listen.py")
    web3_ready = _helpers_exist(
        resolved_repo,
        "commands/web3-audit.md",
        "skills/web3-audit/SKILL.md",
    )
    intel_ready = _helpers_exist(
        resolved_repo,
        "commands/intel.md",
        "tools/intel_engine.py",
        "tools/intel_artifact.py",
        "tools/intel_sources.py",
        "tools/intel_continuation.py",
        "tools/intelligence_extractor.py",
        "tools/technology_inventory.py",
    )
    web_intel_ready = _helpers_exist(resolved_repo, "tools/web_intel_artifact.py")
    credential_ready = _helpers_exist(
        resolved_repo,
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
    interactsh_available = bool(resolver("interactsh-client"))
    forge_available = bool(resolver("forge"))
    # curl is a transport primitive, not proof that a cloud enumeration
    # provider is installed.  Keep the provider requirement explicit so the
    # profile cannot advertise keyword enumeration on a curl-only host.
    cloud_provider_available = any(
        bool(resolver(tool)) for tool in ("cloud_enum", "s3scanner")
    )

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
    if browser_mcp_import_ready:
        fallbacks.append("browser-mcp-evidence-import")
    if source_js_ready:
        fallbacks.append("source-js-enrichment")

    recommended_paths = []
    recommended_paths.append("prefer-session-browser-mcp")
    if browser_mcp_import_ready:
        recommended_paths.append("browser-mcp-evidence-import")
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

    if (
        dns_expansion_ready
        and "puredns" in available["dns-expansion"]
        and any(tool in available["dns-expansion"] for tool in ("alterx", "dnsgen"))
    ):
        recommended_paths.append("dns-expansion-evidence-gated")

    if "nuclei" in available["scanner"] and "curl-native-http" in fallbacks:
        recommended_paths.append("scanner-native-plus-nuclei")
    elif "curl-native-http" in fallbacks:
        recommended_paths.append("scanner-native-http")
    else:
        recommended_paths.append("scanner-manual-evidence-only")

    lanes = [
        _lane_record(
            "recon",
            {
                "tools/recon_engine.sh": recon_engine_ready,
                "httpx-or-curl": "httpx" in available["recon"] or curl_available,
            },
            evidence_required=("target-owned-host-or-url",),
            degraded=("source-js-enrichment",) if source_js_ready and not ("httpx" in available["recon"] or curl_available) else (),
        ),
        _lane_record(
            "surface",
            {"tools/surface.py+surface_projection.py": surface_ready},
            evidence_required=("recon-or-browser-artifact",),
        ),
        {
            **_lane_record(
                "browser",
                {
                    "session-browser-mcp": False,
                    "tools/browser_mcp_import.py": browser_mcp_import_ready,
                },
                evidence_required=("session-browser-network-or-dom",),
                degraded=("session-browser-mcp-unchecked",),
                classification=(
                    "artifact_bridge" if browser_mcp_import_ready else "session_managed"
                ),
                runtime_status="unchecked",
            ),
            "bridge_ready": browser_mcp_import_ready,
        },
        _lane_record(
            "source_js",
            {"tools/source_intel.py+js_reader.py": source_js_ready},
            evidence_required=("target-source-or-javascript",),
        ),
        _lane_record(
            "sql",
            {"tools/sql_parameter_probe.py+json_inject_probe.py": sql_ready},
            evidence_required=("reviewed-parameterized-request",),
        ),
        _lane_record(
            "workflow",
            {"tools/workflow_sequence.py": workflow_ready},
            evidence_required=("ordered-same-target-requests",),
        ),
        _lane_record(
            "timing",
            {"tools/timing_sql_runner.py": timing_ready},
            evidence_required=("time-shaped-candidate",),
        ),
        _lane_record(
            "idor_authz",
            {"tools/validation_runner.py+target_case_state.py": idor_authz_ready},
            evidence_required=("actor-session-object-context",),
        ),
        _lane_record(
            "waf",
            {"tools/waf_pass_plan.py+waf_response_analyzer.py": waf_ready},
            evidence_required=("waf-or-parser-delta",),
        ),
        _lane_record(
            "cloud",
            {
                "tools/cloud_recon.sh": cloud_ready,
                "cloud-provider-tool": cloud_provider_available,
            },
            evidence_required=("reviewed-brand-or-host", "provider-ownership-review"),
            degraded=("manual-provider-review",) if not cloud_provider_available else (),
            classification="evidence_gated",
            runtime_status=(
                "ready"
                if cloud_ready and cloud_provider_available
                else "degraded"
                if cloud_ready
                else "unavailable"
            ),
            ready_override=cloud_ready and cloud_provider_available,
        ),
        _lane_record(
            "oast",
            {
                "tools/oast_listen.py": oast_ready,
                "interactsh-client": interactsh_available,
            },
            evidence_required=("callback-capable-sink", "callback-correlation"),
            degraded=("manual-oast-provider",) if not interactsh_available else (),
            classification="evidence_gated",
            runtime_status=(
                "ready"
                if oast_ready and interactsh_available
                else "degraded"
                if oast_ready
                else "unavailable"
            ),
            ready_override=oast_ready and interactsh_available,
        ),
        _lane_record(
            "web3",
            {
                "commands/web3-audit.md+skills/web3-audit/SKILL.md": web3_ready,
                "foundry-forge": forge_available,
            },
            evidence_required=("contract-source",),
            degraded=("static-review-only",) if not forge_available else (),
            classification="static_review",
            runtime_status=(
                "ready"
                if web3_ready and forge_available
                else "degraded"
                if web3_ready
                else "unavailable"
            ),
            # Static contract review is a real capability even without a
            # local Foundry toolchain; expose the missing execution backend
            # without hiding that bounded review path.
            ready_override=web3_ready,
        ),
        _lane_record(
            "intel",
            {
                "commands/intel.md+tools/intel_engine.py+intel_artifact.py": intel_ready,
                "tools/web_intel_artifact.py": web_intel_ready,
            },
            evidence_required=("component-version-or-advisory-signal",),
            classification="evidence_gated",
            degraded=("web-intel-recorder-unavailable",) if intel_ready and not web_intel_ready else (),
            runtime_status="ready" if intel_ready else "unavailable",
            ready_override=intel_ready,
        ),
        _lane_record(
            "credential",
            {
                "commands/spray.md+credential-attack": credential_ready,
            },
            evidence_required=("reviewed-identity-and-request-spec",),
            classification="evidence_gated",
            runtime_status="ready" if credential_ready else "unavailable",
            ready_override=credential_ready,
        ),
    ]

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
        "lanes": lanes,
    }
