#!/usr/bin/env python3
"""
agent.py — ReAct hunting agent for target-driven automation.

ReAct loop:
    Observe (state) → Think (LLM) → Act (tool) → Observe (result) → loop
    ↳ LLM picks next tool based on ALL prior findings, not a priority table
    ↳ Working memory is compressed every 5 steps to stay within context window
    ↳ Full finding history persists to JSON session — survives crashes/restarts

Memory layers
─────────────
  working_memory  : LLM-maintained running notes (updated after each step)
  findings_log    : [{tool, severity, summary, timestamp}, ...]
  observation_buf : last 5 raw tool outputs (sliding window, avoids bloat)
  session_file    : everything above persisted to disk (JSON)

Usage
─────
  python3 agent.py --target example.com                      # starts a fresh local session
  python3 agent.py --target 10.0.0.0/24 --quick --normal
  python3 agent.py --target example.com --cookie "JSESSIONID=abc" --time 4
  python3 agent.py --target example.com --auth-file auth.json --scope-lock
  python3 agent.py --target targets.txt --resume latest      # primary-domain batch manifest first

From tools/hunt.py:
  tools/hunt.py --target x --agent              # drops into agent mode
  tools/hunt.py --target x --agent --quick      # lower-cost autonomous path
  tools/hunt.py --target x --agent --auth-file .private/auth.json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
import traceback
from datetime import datetime
from pathlib import Path
from typing import Any

from memory import HuntJournal
from memory.target_profile import default_memory_dir, load_target_profile
from tools.auth_session import AuthSession, add_cli_args, session_from_args
from tools.repo_source_artifacts import (
    list_repo_source_artifacts,
    repo_source_exposure_dir,
)
from tools.runtime_config import is_ctf_mode_enabled, load_runtime_config

# ── Ollama native tool calling (fallback / always available) ───────────────────
try:
    import ollama as _ollama_lib
    _OLLAMA_OK = True
except ImportError:
    _ollama_lib = None
    _OLLAMA_OK = False

# ── tools/hunt.py compatibility loader (avoids running main()) ─────────────────
_hunt = None

DEFAULT_AGENT_MAX_STEPS = 20
DEFAULT_AGENT_TIME_HOURS = 2.0
DEEP_AGENT_MAX_STEPS = 60
DEEP_AGENT_TIME_HOURS = 4.0
DEEP_FINISH_FLOOR = 20


class _HuntCompat:
    """Bridge the newer autonomous agent onto this repo's current hunt module."""

    _SYNC_ATTRS = {
        "BASE_DIR",
        "TOOLS_DIR",
        "TARGETS_DIR",
        "RECON_DIR",
        "FINDINGS_DIR",
        "REPORTS_DIR",
    }

    _OPTIONAL_TOOL_FUNCS = {
        "check_tools": "check_tools",
        "run_js_analysis": "run_js_analysis",
        "run_secret_hunt": "run_secret_hunt",
        "run_repo_source_hunt": "run_repo_source_hunt",
        "run_source_intel": "run_source_intel",
        "read_source_intel": "read_source_intel",
        "run_js_read": "run_js_read",
        "read_js_intel": "read_js_intel",
        "run_browser_probe": "run_browser_probe",
        "read_browser_surface": "read_browser_surface",
        "run_param_discovery": "run_param_discovery",
        "run_post_param_discovery": "run_post_param_discovery",
        "run_api_fuzz": "run_api_fuzz",
        "run_cors_check": "run_cors_check",
        "run_cms_exploit": "run_cms_exploit",
        "run_rce_scan": "run_rce_scan",
        "run_sqlmap_targeted": "run_sqlmap_targeted",
        "run_sqlmap_on_file": "run_sqlmap_request_file",
        "run_json_inject_probe": "run_json_inject_probe",
        "run_jwt_audit": "run_jwt_audit",
        "run_cve_hunt": "run_cve_hunt",
        "run_zero_day_fuzzer": "run_zero_day_fuzzer",
        "generate_reports": "generate_reports",
    }

    def __init__(self, module):
        self._module = module
        self.BASE_DIR = module.BASE_DIR
        self.TOOLS_DIR = module.TOOLS_DIR
        self.TARGETS_DIR = module.TARGETS_DIR
        self.RECON_DIR = module.RECON_DIR
        self.FINDINGS_DIR = module.FINDINGS_DIR
        self.REPORTS_DIR = module.REPORTS_DIR

    def __setattr__(self, name: str, value: Any) -> None:
        object.__setattr__(self, name, value)
        module = getattr(self, "_module", None)
        if module is not None and name in self._SYNC_ATTRS:
            setattr(module, name, value)

    def __getattr__(self, name: str):
        return getattr(self._module, name)

    def supported_tool_names(self) -> set[str]:
        supported = {"run_recon", "run_vuln_scan"}
        for tool_name, func_name in self._OPTIONAL_TOOL_FUNCS.items():
            if hasattr(self._module, func_name):
                supported.add(tool_name)
        return supported

    def _target_storage_key(self, domain: str) -> str:
        storage_key = getattr(self._module, "_target_storage_key", None)
        if callable(storage_key):
            return storage_key(domain)
        return domain

    def _resolve_recon_dir(self, domain: str) -> str:
        resolver = getattr(self._module, "_resolve_recon_dir", None)
        if callable(resolver):
            return resolver(domain)
        return os.path.join(self.RECON_DIR, self._target_storage_key(domain))

    def _resolve_findings_dir(self, domain: str, create: bool = False) -> str:
        resolver = getattr(self._module, "_resolve_findings_dir", None)
        if callable(resolver):
            return resolver(domain, create=create)
        path = os.path.join(self.FINDINGS_DIR, self._target_storage_key(domain))
        if create:
            os.makedirs(path, exist_ok=True)
        return path

    def _new_session_id(self, session_root: str) -> str:
        """Return a new timestamped session id that does not collide on disk."""
        base = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        candidate = base
        suffix = 2
        while os.path.exists(os.path.join(session_root, candidate)):
            candidate = f"{base}-{suffix}"
            suffix += 1
        return candidate

    def _activate_recon_session(
        self,
        domain: str,
        *,
        requested_session_id: str | None = "new",
        create: bool = True,
    ) -> tuple[str, str]:
        """Create or resume a lightweight session directory for agent traces.

        Fresh local sessions are the default to avoid accidentally carrying
        stale agent state into a new Claude Code run. Passing `latest` or an
        explicit session id preserves the resume behavior.
        """
        session_root = os.path.join(self.TARGETS_DIR, self._target_storage_key(domain), "sessions")
        if create:
            os.makedirs(session_root, exist_ok=True)

        session_request = (requested_session_id or "new").strip()
        if session_request in {"", "new", "fresh"}:
            session_id = self._new_session_id(session_root)
        elif session_request == "latest":
            existing = [
                name for name in os.listdir(session_root)
                if os.path.isdir(os.path.join(session_root, name))
            ] if os.path.isdir(session_root) else []
            session_id = sorted(existing)[-1] if existing else self._new_session_id(session_root)
        else:
            session_id = session_request

        session_dir = os.path.join(session_root, session_id)
        recon_dir = os.path.join(session_dir, "recon")
        if create:
            os.makedirs(recon_dir, exist_ok=True)
        return session_id, recon_dir

    def run_recon(
        self,
        domain: str,
        *,
        scope_lock: bool = False,
        max_urls: int = 100,
        quick: bool = False,
    ) -> bool:
        # Current orchestrator only supports quick/full split.
        _ = (scope_lock, max_urls)
        return self._module.run_recon(domain, quick=quick)

    def run_vuln_scan(
        self,
        domain: str,
        *,
        quick: bool = False,
        full: bool = False,
        scanner_skip: str = "",
    ) -> bool:
        return self._module.run_vuln_scan(
            domain,
            quick=False if full else quick,
            scanner_full=full,
            scanner_skip=scanner_skip,
        )


def _h():
    """Lazy-load the current tools/hunt.py module once."""
    global _hunt
    if _hunt is None:
        import importlib.util

        _here = os.path.dirname(os.path.abspath(__file__))
        hunt_path = os.path.join(_here, "tools", "hunt.py")
        spec = importlib.util.spec_from_file_location("hunt_tools", hunt_path)
        module = importlib.util.module_from_spec(spec)
        sys.modules.setdefault("hunt_tools", module)
        spec.loader.exec_module(module)
        _hunt = _HuntCompat(module)
    return _hunt


def _open_hunt_journal(memory_dir: str | Path):
    """Resolve the legacy bridge journal opener without depending on _h() mocks."""
    try:
        from legacy_bridge import open_hunt_journal
    except ModuleNotFoundError:
        tools_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tools")
        if tools_dir not in sys.path:
            sys.path.insert(0, tools_dir)
        from legacy_bridge import open_hunt_journal
    return open_hunt_journal(memory_dir)

def _normalize_autopilot_mode(mode: str | None) -> str:
    """Normalize autopilot checkpoint mode with a safe default."""
    normalized = str(mode or "").strip().lower()
    return normalized if normalized in {"paranoid", "normal", "yolo"} else "paranoid"


def _resolve_cli_autopilot_mode(args: argparse.Namespace) -> str:
    """Resolve checkpoint mode flags for the direct agent CLI."""
    if getattr(args, "yolo", False):
        return "yolo"
    if getattr(args, "normal", False):
        return "normal"
    return "paranoid"


def _load_agent_runtime_config() -> dict:
    """Load repo-local config.json for agent runtime flags."""
    return load_runtime_config(Path(__file__).resolve().parent)


def _resolve_ctf_mode(explicit: bool | None = None) -> bool:
    """Resolve repo-local CTF mode, allowing an explicit override."""
    return is_ctf_mode_enabled(Path(__file__).resolve().parent, explicit=explicit)


def _apply_hunt_auth_session(session: AuthSession | None) -> AuthSession:
    """Sync direct agent CLI auth state into the hunt bridge and subprocess env."""
    resolved = session or AuthSession()
    resolved.export_to_env(os.environ)
    _h()._module._AUTH_SESSION = None if resolved.is_empty() else resolved
    return resolved


def _finish_floor_for_mode(mode: str) -> int:
    """Set a conservative minimum number of tool runs before finish."""
    normalized = _normalize_autopilot_mode(mode)
    return {
        "paranoid": 8,
        "normal": 6,
        "yolo": 4,
    }[normalized]

# ── brain.py import ───────────────────────────────────────────────────────────
try:
    _here = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, _here)
    from brain import Brain, BRAIN_SYSTEM, MODEL_PRIORITY, OLLAMA_HOST, _pick_model
    _BRAIN_OK = True
except Exception as _brain_err:
    _BRAIN_OK = False
    BRAIN_SYSTEM = ""
    MODEL_PRIORITY = ["qwen3:8b"]
    OLLAMA_HOST = "http://localhost:11434"

# ── Colours ───────────────────────────────────────────────────────────────────
GREEN   = "\033[0;32m"
CYAN    = "\033[0;36m"
YELLOW  = "\033[1;33m"
RED     = "\033[0;31m"
MAGENTA = "\033[0;35m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
NC      = "\033[0m"

MAX_OBS_CHARS    = 3000    # truncate tool output kept in observation buffer
MAX_CTX_CHARS    = 18000   # max chars sent to LLM per step
MAX_FINDINGS_LOG = 200     # cap stored findings
MEMORY_REFRESH_N = 5       # compress working_memory every N steps


# ──────────────────────────────────────────────────────────────────────────────
#  Tool definitions  (JSON Schema — compatible with Ollama native tool calling)
# ──────────────────────────────────────────────────────────────────────────────

_ALL_TOOL_SPECS: list[dict] = [
    {
        "type": "function",
        "function": {
            "name": "run_recon",
            "description": (
                "Run full subdomain enumeration + live host discovery on the target domain. "
                "This MUST be the first step if recon data does not exist. "
                "Returns: number of live hosts found, key tech stacks detected."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "scope_lock": {
                        "type": "boolean",
                        "description": "If true, skip subdomain enum and only probe the exact target given.",
                        "default": False,
                    },
                    "max_urls": {
                        "type": "integer",
                        "description": "Max URLs to collect (default 100, use 200+ for thorough recon).",
                        "default": 100,
                    },
                    "quick": {
                        "type": "boolean",
                        "description": "If true, use the lower-cost recon path for this run.",
                        "default": False,
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_tools",
            "description": (
                "Check which external security tools are installed locally. "
                "Use when scans fail unexpectedly or you need to understand environment limits "
                "before choosing a tool-heavy next step."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_vuln_scan",
            "description": (
                "Run the core vulnerability scanner. Tests active upload canaries, SQLi timing, "
                "dalfox/SSTI, CVEs, misconfigs, exposure, takeover, IDOR/auth bypass candidates, "
                "MFA, and SAML/SSO checks. Standard/quick runs skip the XSS lane by default; "
                "use full=true for expanded scanner limits and to include XSS unless scanner_skip "
                "explicitly contains xss. scanner_skip should stay unset unless the current "
                "user turn explicitly asks to skip additional modules for this target/invocation."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "quick": {
                        "type": "boolean",
                        "description": "If true, run fast subset of templates only.",
                        "default": False,
                    },
                    "full": {
                        "type": "boolean",
                        "description": "If true, run expanded scanner limits even if recon was quick.",
                        "default": False,
                    },
                    "scanner_skip": {
                        "type": "string",
                        "description": (
                            "Comma-separated additional scanner modules to skip for this invocation only. "
                            "Do not set it merely to preserve the built-in standard/quick XSS default; "
                            "use full=true to include XSS. Never infer it from prior targets, prior CLI "
                            "sessions, examples, or old agent traces."
                        ),
                        "default": "",
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_js_analysis",
            "description": (
                "Legacy deep JS body analysis. Downloads and scans discovered JavaScript files for "
                "API keys, secrets, hardcoded tokens, internal endpoints, GraphQL schemas, and "
                "auth-bypass hints. Prefer run_source_intel and run_js_read first when cached JS "
                "or source/browser artifacts already exist; use this when you specifically need "
                "direct JS-body extraction or secret-heavy follow-up."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_secret_hunt",
            "description": (
                "Scan for leaked secrets: TruffleHog on JS/git repos, GitHound on GitHub, "
                "hardcoded AWS/GCP/Azure keys, API tokens, private keys. "
                "Always worth running — secrets bypass all other controls."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_repo_source_hunt",
            "description": (
                "Scan a GitHub public repo or local repo path for leaked secrets, risky configs, "
                "and GitHub Actions / CI issues."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "repo_url": {
                        "type": "string",
                        "description": "GitHub public repo URL or owner/repo reference",
                        "default": "",
                    },
                    "repo_path": {
                        "type": "string",
                        "description": "Local repository path already present on disk",
                        "default": "",
                    },
                    "allow_large_repo": {
                        "type": "boolean",
                        "description": "Allow clone even when source-hunt thresholds are exceeded",
                        "default": False,
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_source_intel",
            "description": (
                "Extract lightweight source intelligence from a local repo path and cached recon JS/browser artifacts. "
                "Outputs business-logic, IDOR, auth-bypass, route/API, and GraphQL hypotheses under findings/<target>/source_intel. "
                "This is the preferred first interpretation step when JS, browser, or repo-source "
                "artifacts already exist, before repeating broad scanners or legacy JS analysis."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "repo_path": {
                        "type": "string",
                        "description": "Optional local repository path already present on disk.",
                        "default": "",
                    },
                    "repo_url": {
                        "type": "string",
                        "description": "Optional repo URL for operator context only; this tool does not clone by itself.",
                        "default": "",
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_source_intel",
            "description": (
                "Read previously generated source-intel hypotheses for this target, including routes, "
                "GraphQL operations, business verbs, and auth/tenant/object-id candidates."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_js_read",
            "description": (
                "Prepare JS materials for the js-reader agent. Collects cached recon JS files, applies "
                "vendor / minified / oversize filters, and bundles them with recon-extracted artifacts and "
                "any prior source_intel hypothesis. Outputs findings/<target>/js_intel/materials.json plus "
                "a markdown summary. Hand the materials to the js-reader agent for LLM-driven attack-surface "
                "hypothesis generation. Prefer this after run_source_intel (or when source_intel is not "
                "available yet) instead of jumping straight to legacy JS-body analysis. Does NOT itself call any LLM."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_js_intel",
            "description": (
                "Read previously generated js-reader hypotheses (or fall back to the materials summary). "
                "Returns endpoints, auth model, sink hot spots, and ranked attack-surface leads with rationale."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_browser_probe",
            "description": (
                "Fallback browser capture via playwright-cli when MCP artifacts are unavailable; capture one browser-context page and feed observed XHR/API/GraphQL "
                "requests plus params into recon/<target>/browser. Use for login/register/dashboard/app/portal, "
                "SPA, XHR, GraphQL, or account-gated surfaces. Prefer chrome-devtools/playwright MCP plus "
                "tools/browser_mcp_import.py for live browser work when available before reducing the target to curl-only testing."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Optional URL to open; if empty, choose a cached login/app/dashboard/live URL.",
                        "default": "",
                    },
                    "session": {
                        "type": "string",
                        "description": "Optional playwright-cli session name to reuse authenticated browser state.",
                        "default": "",
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_browser_surface",
            "description": (
                "Read browser-observed XHR/API endpoints and parameters from recon/<target>/browser. "
                "Use after run_browser_probe or before surface ranking when browser artifacts already exist."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_param_discovery",
            "description": (
                "Brute-force GET URL parameters using arjun + paramspider on all live hosts. "
                "Use when parameterized URLs are sparse or the site returns data conditionally. "
                "Returns: new parameterized URLs added to the attack surface."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_post_param_discovery",
            "description": (
                "Discover POST form endpoints and their parameter names using lightpanda "
                "(JS-rendered HTML) + arjun POST brute-force. "
                "Mandatory for JSP/Java/Spring apps, ASP.NET WebForms, any app with login forms. "
                "Then runs sqlmap on discovered POST endpoints automatically. "
                "Pass cookies if the forms are behind authentication."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "cookies": {
                        "type": "string",
                        "description": "Session cookie string e.g. 'JSESSIONID=abc; token=xyz'",
                        "default": "",
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_api_fuzz",
            "description": (
                "Fuzz API endpoints for IDOR, auth bypass, privilege escalation, "
                "and unauthenticated access. Tests REST + GraphQL + gRPC. "
                "Use when API endpoints or numeric IDs were found in recon."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_cors_check",
            "description": (
                "Test all live hosts for CORS misconfigurations: null origin, "
                "wildcard with credentials, trusted subdomain bypass. "
                "High-priority when authenticated API endpoints are present."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_cms_exploit",
            "description": (
                "Run CMS-specific exploit checks: Drupalgeddon (CVE-2014-3704, CVE-2018-7600), "
                "WordPress plugin vulns + user enum, Joomla RCE, Magento SQLi. "
                "Use immediately when a CMS is detected — especially Drupal < 8 or WordPress."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_rce_scan",
            "description": (
                "Scan for Remote Code Execution vectors: Log4Shell (JNDI), Tomcat PUT upload, "
                "JBoss admin consoles, SSTI (Jinja2/Twig/Freemarker), shellshock, "
                "interactsh OOB callbacks. Use when Java/Tomcat/JBoss/Struts is detected."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_sqlmap_targeted",
            "description": (
                "Run sqlmap against parameterized GET URLs found in recon. "
                "Tests error-based, boolean-blind, time-blind, UNION injection. "
                "Use when parameterized URLs exist OR nuclei flagged SQL-related findings."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_sqlmap_on_file",
            "description": (
                "Run sqlmap against a specific raw HTTP request file (Burp-style). "
                "Use when you know a specific endpoint with POST params that needs SQLi testing. "
                "Provide the full path to the saved request file."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "request_file": {
                        "type": "string",
                        "description": "Absolute path to raw HTTP request file.",
                    },
                    "level": {
                        "type": "integer",
                        "description": "sqlmap level 1-5 (default 5).",
                        "default": 5,
                    },
                    "risk": {
                        "type": "integer",
                        "description": "sqlmap risk 1-3 (default 3).",
                        "default": 3,
                    },
                },
                "required": ["request_file"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_json_inject_probe",
            "description": (
                "AI-callable POST-JSON injection probe — surgical alternative to bulk scanners. "
                "Tests 11 payload classes (sqli auth-bypass / sqli error / sqli time / ssti / "
                "cmd injection / open redirect / path traversal / xss / nosql operator injection / "
                "nosql regex bypass / graphql introspection) against JSON-body endpoints "
                "with 4-stage detection (JWT+admin markers, SQL-error+structural diff, time delay, "
                "GraphQL __schema baseline diff). NoSQL payloads re-shape string fields into Mongo "
                "operator objects ({$ne:null}, {$regex:.*}) — fire on /api/login when stack is "
                "Node+Mongo; GraphQL probe fires on `query`-shaped fields targeting /graphql. "
                "Auto-loads endpoints from recon/<t>/browser/xhr_endpoints.txt and "
                "findings/<t>/js_intel/hypotheses.json. "
                "Use AFTER run_browser_probe or run_js_read have populated POST endpoint "
                "candidates, OR when a confirmed/suspected POST endpoint needs targeted testing "
                "(e.g. login, mutation, importer, webhook). Fast (~30s for 50 endpoints) — "
                "preferred over run_sqlmap_targeted for REST APIs with JSON bodies."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "endpoints_file": {
                        "type": "string",
                        "description": (
                            "Optional path to file with one URL per line OR JSONL "
                            "{method,url,body}. Defaults to "
                            "recon/<t>/browser/xhr_endpoints.txt when present."
                        ),
                    },
                    "js_intel": {
                        "type": "string",
                        "description": (
                            "Optional path to findings/<t>/js_intel/hypotheses.json "
                            "for LLM-derived endpoint seeds. Auto-discovered when "
                            "the standard path exists."
                        ),
                    },
                    "max_requests": {
                        "type": "integer",
                        "description": "Hard cap on probe requests per endpoint (default 60).",
                        "default": 60,
                    },
                    "add_default_seeds": {
                        "type": "boolean",
                        "description": (
                            "When no other endpoint source yields candidates, probe "
                            "common login paths (/rest/user/login, /api/login, etc.). "
                            "Default true."
                        ),
                        "default": True,
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_jwt_audit",
            "description": (
                "Audit JWT tokens found in recon artifacts: algorithm confusion (alg=none, "
                "RS256→HS256), weak HMAC secret cracking, forged claims. "
                "Use when JWT tokens appear in URLs, cookies, or response headers."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_cve_hunt",
            "description": (
                "Run the CVE hunter against detected technologies and live targets. "
                "Correlates recon tech fingerprints with known CVEs and nuclei CVE templates. "
                "Use when tech stack has been identified and you want fast known-vuln coverage."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_zero_day_fuzzer",
            "description": (
                "Run the zero-day/logic fuzzer against the target to probe unusual methods, "
                "header handling, parameter edge cases, and business-logic style flaws. "
                "Use after recon when standard scans have not exhausted the attack surface."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "deep": {
                        "type": "boolean",
                        "description": "If true, use deeper and slower fuzzing routines.",
                        "default": False,
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "generate_reports",
            "description": (
                "Generate markdown reports from current findings artifacts for this target. "
                "Use near the end after meaningful findings or scans have completed."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_autopilot_state",
            "description": (
                "Load the combined autopilot bootstrap view for this target: cached recon status, "
                "memory summary, recommended first targets, guard cooldowns, and the next action. "
                "Use this before active testing to resume quickly with minimal context."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "repo_root": {
                        "type": "string",
                        "description": "Optional repository root override (defaults to current checkout).",
                        "default": "",
                    },
                    "memory_dir": {
                        "type": "string",
                        "description": "Optional hunt-memory directory override.",
                        "default": "",
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_intelligence",
            "description": (
                "Read the local intelligence layer for this target at "
                "evidence/<target>/intelligence.md. This file is produced by "
                "tools/intelligence_extractor.py and contains non-vulnerability "
                "signals (tech stack notes, vendor advisories, source-derived "
                "context). The F4 finish-gate requires this tool to be called "
                "this session whenever intelligence.md exists."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "repo_root": {
                        "type": "string",
                        "description": "Optional repository root override (defaults to current checkout).",
                        "default": "",
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "pattern_calibration_summary",
            "description": (
                "(B12d) Read the per-pattern precision/recall table from "
                "hunt-memory/pattern_calibration.jsonl. Use this during a "
                "hunt to see which historical patterns are reliable vs. "
                "low-precision so the agent can deprioritise the latter."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "format": {
                        "type": "string",
                        "description": "Either 'json' (default) or 'text'.",
                        "default": "json",
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_browser_screenshot",
            "description": (
                "(B12b) Return the most recent vision-captured screenshot "
                "for this target as a path. Only meaningful when --vision is "
                "set AND the active model supports image input. Vision-capable "
                "models can then inspect the visible layout for clickable "
                "elements not represented in the DOM, overlay-hidden inputs, "
                "or visual-only state."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "seq": {
                        "type": "integer",
                        "description": "Optional explicit sequence number; defaults to the latest screenshot.",
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_vision_probe",
            "description": (
                "(P5-W1 R3) Capture a fresh sequence-tagged screenshot of a "
                "URL via Playwright and persist screenshot_{seq}.png + "
                "dom_{seq}.html under evidence/<target>/browser/. Only "
                "exposed when --vision is set AND the active model supports "
                "image input. Use this when you need a NEW screenshot of a "
                "page; use read_browser_screenshot to recall the latest one."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Absolute URL of the page to capture.",
                    },
                    "label": {
                        "type": "string",
                        "description": "Optional human-readable label folded into the evidence dir name.",
                        "default": "vision",
                    },
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_sibling_probe",
            "description": (
                "(P5-W1 R1) Expand a confirmed finding into sibling probes "
                "and test them. When --parallel is set, spawns up to "
                "--max-parallel sibling workers concurrently and consolidates "
                "their findings with dedup. Otherwise runs sequentially. Use "
                "after a confirmed bug to check related endpoints/IDs."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "seed_findings": {
                        "type": "array",
                        "description": "List of seed finding dicts. Each must have at least {id, endpoint}.",
                        "items": {"type": "object"},
                    },
                },
                "required": ["seed_findings"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_hypothesis_fleet",
            "description": (
                "(P5-W1 R2) Test multiple attack hypotheses in parallel via "
                "run_fanout. When --parallel-hypotheses is set, runs up to "
                "--max-parallel worker waves and ranks results by outcome "
                "(validated_finding > strong_signal > leads_only), demoting "
                "losers to the journal. When the flag is off, runs the same "
                "set sequentially and returns the same ranked result."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "hypotheses": {
                        "type": "array",
                        "description": "List of hypothesis dicts (at least one).",
                        "items": {"type": "object"},
                    },
                },
                "required": ["hypotheses"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_self_review",
            "description": (
                "(P5-W1 R4) Adversarial pre-finish self-review. For each "
                "candidate finding, spawn a red-team worker that tries to "
                "disqualify it, parse VERDICT, and decide keep / demote / "
                "kill. Definitive-disqualifier candidates are recorded as "
                "false-positive patterns to teach future runs. Only runs "
                "when --self-review is set; otherwise returns no-op."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "candidates": {
                        "type": "array",
                        "description": "List of candidate finding dicts (at least {id, target}).",
                        "items": {"type": "object"},
                    },
                },
                "required": ["candidates"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_guard_status",
            "description": (
                "Read the persisted request guard state for this target: tracked hosts, failure counts, "
                "and active cooldowns. Use this when active testing slows down or you need to avoid tripped hosts."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "memory_dir": {
                        "type": "string",
                        "description": "Optional hunt-memory directory override.",
                        "default": "",
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_repo_source_summary",
            "description": (
                "Read previously generated repository source-hunt artifacts for this target: "
                "repo metadata, secret findings count, CI findings count, and the saved markdown summary."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_resume_summary",
            "description": (
                "Read hunt-memory history for this target and summarize prior sessions, "
                "untested endpoints, and cross-target pattern matches before resuming work."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "memory_dir": {
                        "type": "string",
                        "description": "Optional hunt-memory directory override.",
                        "default": "",
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_surface_summary",
            "description": (
                "Rank cached recon output with hunt-memory context and return a prioritized "
                "attack surface summary. Use after recon to decide where to hunt first."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "repo_root": {
                        "type": "string",
                        "description": "Optional repository root override (defaults to current checkout).",
                        "default": "",
                    },
                    "memory_dir": {
                        "type": "string",
                        "description": "Optional hunt-memory directory override.",
                        "default": "",
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_intel",
            "description": (
                "Fetch memory-aware CVE and disclosure intel for the target. "
                "Automatically falls back to recon-detected tech stack when no tech list is provided."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "tech": {
                        "type": "string",
                        "description": "Optional comma-separated tech stack override.",
                        "default": "",
                    },
                    "program": {
                        "type": "string",
                        "description": "Optional HackerOne program handle for disclosed-report lookups.",
                        "default": "",
                    },
                    "memory_dir": {
                        "type": "string",
                        "description": "Optional hunt-memory directory override.",
                        "default": "",
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "remember_finding",
            "description": (
                "Persist a confirmed/partial/rejected finding into hunt memory so future hunts "
                "can reuse the endpoint, technique, and tech stack context."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Optional target override; defaults to the current domain.",
                        "default": "",
                    },
                    "vuln_class": {
                        "type": "string",
                        "description": "Vulnerability class, e.g. idor or ssrf.",
                    },
                    "endpoint": {
                        "type": "string",
                        "description": "Affected URL or normalized path.",
                    },
                    "result": {
                        "type": "string",
                        "description": "Remember outcome: confirmed, rejected, partial, or informational.",
                    },
                    "severity": {
                        "type": "string",
                        "description": "Optional severity label.",
                        "default": "",
                    },
                    "payout": {
                        "type": "number",
                        "description": "Optional payout amount.",
                    },
                    "technique": {
                        "type": "string",
                        "description": "Optional technique label.",
                        "default": "",
                    },
                    "notes": {
                        "type": "string",
                        "description": "Optional notes describing the finding.",
                        "default": "",
                    },
                    "tags": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional list of tags.",
                        "default": [],
                    },
                    "tech_stack": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional list of technologies for pattern learning.",
                        "default": [],
                    },
                    "memory_dir": {
                        "type": "string",
                        "description": "Optional hunt-memory directory override.",
                        "default": "",
                    },
                },
                "required": ["vuln_class", "endpoint", "result"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_recon_summary",
            "description": (
                "Read and summarize current recon data: live hosts, tech stack, "
                "discovered paths, parameterized URLs, CMS detections. "
                "Use to refresh your understanding before deciding next action."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_findings_summary",
            "description": (
                "Read and summarize all vulnerability findings discovered so far. "
                "Returns severity breakdown, top findings, and suggested exploit chains. "
                "Use before deciding to run additional tools or write the final report."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "update_working_memory",
            "description": (
                "Update your working notes about this target. Call this after making "
                "a significant discovery or after each tool run to keep your notes current. "
                "These notes persist across all steps and are always visible to you."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "notes": {
                        "type": "string",
                        "description": "Your updated notes about the target, findings, and next priorities.",
                    }
                },
                "required": ["notes"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "finish",
            "description": (
                "Signal that the hunt is complete. Call this when: all high-priority tools "
                "have run, time budget is close to exhausted, or no further tools would "
                "add new findings. Provide a brief verdict."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "verdict": {
                        "type": "string",
                        "description": "Brief summary: what was found, what's worth reporting.",
                    }
                },
                "required": ["verdict"],
            },
        },
    },
]

_DISPATCHER_ONLY_TOOLS = {
    "read_autopilot_state",
    "read_guard_status",
    "read_repo_source_summary",
    "read_resume_summary",
    "read_surface_summary",
    "read_intelligence",
    "run_intel",
    "remember_finding",
    "read_recon_summary",
    "read_findings_summary",
    "update_working_memory",
    "pattern_calibration_summary",
    "read_browser_screenshot",
    "run_vision_probe",
    "run_sibling_probe",
    "run_hypothesis_fleet",
    "run_self_review",
    "finish",
}

_FINISH_FLOOR_PROGRESS_TOOLS = {
    "run_recon",
    "run_vuln_scan",
    "run_js_analysis",
    "run_secret_hunt",
    "run_repo_source_hunt",
    "run_source_intel",
    "run_js_read",
    "run_browser_probe",
    "run_param_discovery",
    "run_post_param_discovery",
    "run_api_fuzz",
    "run_cors_check",
    "run_cms_exploit",
    "run_rce_scan",
    "run_sqlmap_targeted",
    "run_sqlmap_on_file",
    "run_json_inject_probe",
    "run_jwt_audit",
    "run_cve_hunt",
    "run_zero_day_fuzzer",
    "run_intel",
}


def _enabled_tool_specs() -> list[dict]:
    """Expose only tools that are wired into the current checkout."""
    available = _h().supported_tool_names() | _DISPATCHER_ONLY_TOOLS
    return [spec for spec in _ALL_TOOL_SPECS if spec["function"]["name"] in available]


TOOLS = _enabled_tool_specs()
TOOL_NAMES = {t["function"]["name"] for t in TOOLS}


def _finish_floor_progress_count(completed_steps: list[str]) -> int:
    """Count only substantive hunt actions toward the finish floor."""
    return sum(1 for step in completed_steps if step in _FINISH_FLOOR_PROGRESS_TOOLS)


# ── Finish gate invariants F3 (coverage matrix) and F4 (intelligence) ────────
#
# These are programmatic counterparts to the prose invariants documented in
# commands/autopilot.md (F1–F4). They run before the `finish` tool is allowed
# to commit. Returned tuple is (passed, [SYSTEM] message). Empty message means
# the gate passed.
#
# Per tasks 05-16-b1-f3-finish-gate and 05-16-b2-f4-finish-gate:
#   - F3: refuse finish while coverage_matrix.find-gaps returns non-empty
#   - F4: refuse finish if evidence/<target>/intelligence.md exists but the
#         agent did not call `read_intelligence` this session
#
# In `--yolo` mode both gates only emit an audit warning and allow finish.
# `--paranoid` and `--normal` are hard blocks.


def _f3_coverage_gate(
    target: str,
    repo_root: Path | str | None = None,
) -> tuple[bool, str]:
    """Return (passed, message). Pass if there are no high-value untested
    cells in `tools/coverage_matrix.py find-gaps` output."""
    repo = Path(repo_root) if repo_root else Path(__file__).resolve().parent
    matrix_script = repo / "tools" / "coverage_matrix.py"
    if not matrix_script.is_file():
        # No matrix tool present — gate cannot run. Treat as pass with audit note.
        return True, ""
    try:
        result = subprocess.run(
            [sys.executable, str(matrix_script), "find-gaps",
             "--target", target, "--repo-root", str(repo)],
            capture_output=True, text=True, timeout=30,
        )
    except Exception as exc:
        # Gate failure to execute → audit and pass (do not block on infra error).
        return True, f"[AUDIT] F3 gate could not run coverage_matrix: {exc}"
    if result.returncode != 0:
        return True, (
            f"[AUDIT] F3 gate: coverage_matrix find-gaps exited {result.returncode}; "
            f"stderr={result.stderr.strip()[:200]}"
        )
    try:
        gaps = json.loads(result.stdout or "[]")
    except Exception:
        return True, "[AUDIT] F3 gate: coverage_matrix output was not JSON; skipping"
    if not isinstance(gaps, list):
        return True, "[AUDIT] F3 gate: coverage_matrix output not a list; skipping"
    if not gaps:
        return True, ""
    # gaps present — block finish
    sample = gaps[:5]
    sample_lines = [
        f"  - {g.get('endpoint','?')}  vuln_class={g.get('vuln_class','?')}  "
        f"weight={g.get('weight','?')}"
        for g in sample
    ]
    msg = (
        f"[SYSTEM] F3 finish-gate blocked: {len(gaps)} high-value coverage "
        f"matrix gap(s) untested for target {target!r}.\n"
        + "\n".join(sample_lines)
        + (f"\n  ... ({len(gaps) - len(sample)} more)" if len(gaps) > len(sample) else "")
        + "\n\nClose them with run_vuln_scan / run_api_fuzz / targeted tests, "
        "or mark them n_a via `tools/coverage_matrix.py mark`, before finish."
    )
    return False, msg


def _f4_intelligence_gate(
    target: str,
    completed_steps: list[str],
    repo_root: Path | str | None = None,
) -> tuple[bool, str]:
    """Return (passed, message). Pass if intelligence.md is absent OR has
    been read this session via `read_intelligence`."""
    repo = Path(repo_root) if repo_root else Path(__file__).resolve().parent
    intel_path = repo / "evidence" / target / "intelligence.md"
    if not intel_path.is_file():
        # No intelligence layer — gate satisfied. Per B2 R3 emit a single audit line.
        return True, f"[AUDIT] F4 gate: no intelligence layer for target {target!r}"
    if "read_intelligence" in completed_steps:
        return True, ""
    msg = (
        f"[SYSTEM] F4 finish-gate blocked: intelligence layer exists at "
        f"{intel_path} but was not consulted this session.\n"
        "Run the `read_intelligence` tool to load it before calling finish."
    )
    return False, msg


def _finish_gate_block_or_warn(
    gate_msg: str,
    mode: str,
) -> tuple[bool, str]:
    """Return (block, message_to_emit).

    paranoid / normal: hard block (block=True) with the gate's SYSTEM message.
    yolo: do not block; emit a `[YOLO-OVERRIDE]` warning that includes the message.
    """
    if not gate_msg:
        return False, ""
    normalized = _normalize_autopilot_mode(mode)
    if normalized == "yolo":
        return False, f"[YOLO-OVERRIDE] {gate_msg}"
    return True, gate_msg


def _phase_flags(completed_steps: list[str]) -> dict[str, bool]:
    completed = set(completed_steps)
    return {
        "recon": "run_recon" in completed,
        "scan": "run_vuln_scan" in completed,
        "tool_check": "check_tools" in completed,
        "js_analysis": "run_js_analysis" in completed,
        "secret_hunt": "run_secret_hunt" in completed,
        "source_intel": "run_source_intel" in completed,
        "browser_probe": "run_browser_probe" in completed,
        "param_discovery": "run_param_discovery" in completed,
        "post_param_discovery": "run_post_param_discovery" in completed,
        "api_fuzz": "run_api_fuzz" in completed,
        "cors": "run_cors_check" in completed,
        "cms_exploit": "run_cms_exploit" in completed,
        "rce_scan": "run_rce_scan" in completed,
        "sqlmap": "run_sqlmap_targeted" in completed or "run_sqlmap_on_file" in completed,
        "jwt_audit": "run_jwt_audit" in completed,
        "cve_hunt": "run_cve_hunt" in completed,
        "zero_day_fuzzer": "run_zero_day_fuzzer" in completed,
        "reports_generated": "generate_reports" in completed,
    }


# ──────────────────────────────────────────────────────────────────────────────
#  Memory
# ──────────────────────────────────────────────────────────────────────────────

class HuntMemory:
    """
    Three-layer memory:
      1. working_memory   — LLM's rolling notes (updated by update_working_memory tool)
      2. findings_log     — structured list of all discoveries [{tool, severity, text, ts}]
      3. observation_buf  — last N raw tool outputs, used to build LLM context
    All layers are persisted to a JSON session file.
    """

    def __init__(self, session_file: str):
        self.session_file    = session_file
        self.working_memory  = ""
        self.bootstrap_context = ""
        self.bootstrap_state: dict[str, Any] = {}
        self.findings_log:   list[dict] = []
        self.observation_buf: list[dict] = []   # {tool, ts, text}
        self.completed_steps: list[str]  = []
        self.step_count      = 0
        self._load()

    def _load(self) -> None:
        if os.path.isfile(self.session_file):
            try:
                data = json.loads(Path(self.session_file).read_text())
                self.working_memory   = data.get("working_memory", "")
                self.findings_log     = data.get("findings_log", [])
                self.observation_buf  = data.get("observation_buf", [])[-10:]
                self.completed_steps  = data.get("completed_steps", [])
                self.step_count       = data.get("step_count", 0)
                # (P5-B9 R2/R3) Restore bootstrap_context across resume.
                # Older session files won't have these keys; default to empty.
                self.bootstrap_context = data.get("bootstrap_context", "") or ""
                bs = data.get("bootstrap_state", {})
                self.bootstrap_state = bs if isinstance(bs, dict) else {}
            except Exception:
                pass

    def save(self) -> None:
        Path(self.session_file).parent.mkdir(parents=True, exist_ok=True)
        data = {
            "working_memory":  self.working_memory,
            "findings_log":    self.findings_log[-MAX_FINDINGS_LOG:],
            "observation_buf": self.observation_buf[-10:],
            "completed_steps": self.completed_steps,
            "step_count":      self.step_count,
            # (P5-B9 R1) Persist bootstrap_context across resume so operator
            # focus, lane skips, and exclusion notes survive --resume.
            "bootstrap_context": self.bootstrap_context or "",
            "bootstrap_state":   self.bootstrap_state if isinstance(self.bootstrap_state, dict) else {},
            "saved_at":        datetime.now().isoformat(),
        }
        Path(self.session_file).write_text(json.dumps(data, indent=2))

    def update_bootstrap_context(self, new_context: str,
                                 *, audit_path: Path | str | None = None) -> dict:
        """(P5-B9 R4) Replace bootstrap_context and write an audit row.

        Returns the audit record dict. Best-effort on audit-log errors —
        the in-memory update always succeeds even if the log write fails.
        """
        old = self.bootstrap_context or ""
        self.bootstrap_context = new_context or ""
        record = {
            "ts": datetime.now().isoformat(),
            "session_file": str(self.session_file),
            "old_len": len(old),
            "new_len": len(self.bootstrap_context),
        }
        try:
            base = Path(self.session_file).resolve().parent.parent.parent
            log_path = Path(audit_path) if audit_path else (
                base / "hunt-memory" / "audit" / "bootstrap_changes.jsonl"
            )
            log_path.parent.mkdir(parents=True, exist_ok=True)
            with open(log_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, separators=(",", ":")) + "\n")
        except Exception:
            pass
        return record

    def add_observation(self, tool: str, text: str) -> None:
        """Record a tool output to the sliding observation window."""
        entry = {
            "tool": tool,
            "ts":   datetime.now().isoformat(),
            "text": text[:MAX_OBS_CHARS],
        }
        self.observation_buf.append(entry)
        if len(self.observation_buf) > 15:
            self.observation_buf = self.observation_buf[-10:]

    def add_finding(self, tool: str, severity: str, text: str) -> None:
        finding = {
            "tool":     tool,
            "severity": severity,
            "text":     text[:500],
            "ts":       datetime.now().isoformat(),
        }
        self.findings_log.append(finding)

        # Lightweight chain-hint injection: append a one-liner reminder to
        # working_memory so the LLM sees the next attack class without us
        # spawning new workers. Best-effort — never break add_finding.
        try:
            from tools.chain_hints import derive_chain_hint
            hint = derive_chain_hint(finding)
            if hint:
                cur = self.working_memory or ""
                # Cap working_memory size to avoid runaway growth (keep last 8000 chars)
                combined = (cur + ("\n" if cur else "") + hint)
                if len(combined) > 8000:
                    combined = combined[-8000:]
                self.working_memory = combined
        except Exception:
            pass

    def findings_summary(self) -> str:
        """Compact summary of all findings for LLM context."""
        if not self.findings_log:
            return "No findings yet."
        by_sev: dict[str, list[str]] = {}
        for f in self.findings_log[-50:]:
            by_sev.setdefault(f["severity"].upper(), []).append(f"{f['tool']}: {f['text'][:120]}")
        lines = []
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            if sev in by_sev:
                lines.append(f"[{sev}] ({len(by_sev[sev])} items)")
                lines.extend(f"  • {x}" for x in by_sev[sev][:5])
        return "\n".join(lines) or "No classified findings."

    def recent_observations(self, n: int = 3) -> str:
        """Last n tool outputs formatted for LLM context."""
        recents = self.observation_buf[-n:]
        if not recents:
            return "No tool outputs yet."
        parts = []
        for obs in recents:
            parts.append(f"[{obs['tool']}]\n{obs['text']}")
        return "\n\n".join(parts)


# ──────────────────────────────────────────────────────────────────────────────
#  Tool dispatcher  (maps tool names → hunt.py functions)
# ──────────────────────────────────────────────────────────────────────────────

class ToolDispatcher:
    """Execute tool calls and return plain-text observations."""

    def __init__(self, domain: str, memory: HuntMemory,
                 scope_lock: bool = False, max_urls: int = 100,
                 default_cookies: str = "", quick_mode: bool = False,
                 vision_enabled: bool = False, max_screenshots: int = 5,
                 model_id: str = "",
                 parallel_enabled: bool = False, max_parallel: int = 3,
                 worker_timeout_secs: int = 300,
                 parallel_hypotheses: bool = False,
                 self_review_enabled: bool = False,
                 calibrate_patterns: bool = False,
                 autopilot_mode: str = "normal",
                 deep_mode: bool = False):
        self.domain          = domain
        self.memory          = memory
        self.scope_lock      = scope_lock
        self.max_urls        = max_urls
        self.default_cookies = default_cookies
        self.quick_mode      = quick_mode
        # (P5-W1 R3) vision write-path gating context
        self.vision_enabled  = bool(vision_enabled)
        self.max_screenshots = int(max_screenshots or 5)
        self.model_id        = str(model_id or "")
        # (P5-W1 R1/R2/R4) parallel + self-review wiring context
        self.parallel_enabled       = bool(parallel_enabled)
        self.parallel_hypotheses    = bool(parallel_hypotheses)
        self.self_review_enabled    = bool(self_review_enabled)
        self.calibrate_patterns     = bool(calibrate_patterns)
        self.autopilot_mode         = str(autopilot_mode or "normal")
        self.deep_mode              = bool(deep_mode)
        # Coerce max_parallel against mode (paranoid forces 1, normal caps at 3, yolo caps at 8)
        try:
            from tools.parallel_workers import coerce_max_parallel
            self.max_parallel = coerce_max_parallel(int(max_parallel or 3), self.autopilot_mode)
        except Exception:
            self.max_parallel = int(max_parallel or 3)
        self.worker_timeout_secs = int(worker_timeout_secs or 300)

    def _resolve_memory_dir(self, override: str = "") -> str:
        resolved = str(override or "").strip()
        if resolved:
            return resolved
        return str(default_memory_dir(_h().BASE_DIR))

    def dispatch(self, name: str, args: dict) -> str:
        """Execute named tool and return text observation."""
        h = _h()
        domain = self.domain
        t0 = time.time()

        try:
            if name == "run_recon":
                ok = h.run_recon(
                    domain,
                    scope_lock=args.get("scope_lock", self.scope_lock),
                    max_urls=int(args.get("max_urls", self.max_urls)),
                    quick=bool(args.get("quick", self.quick_mode)),
                )
                obs = self._summarize_recon(domain, ok)

            elif name == "check_tools":
                installed, missing = h.check_tools()
                obs = self._summarize_tools(installed, missing)

            elif name == "run_vuln_scan":
                ok = h.run_vuln_scan(
                    domain,
                    quick=bool(args.get("quick", self.quick_mode)),
                    full=bool(args.get("full", False)),
                    scanner_skip=str(args.get("scanner_skip", "")),
                )
                obs = self._summarize_findings(domain, "scan", ok)

            elif name == "run_js_analysis":
                ok = h.run_js_analysis(domain)
                obs = self._summarize_findings(domain, "js", ok)

            elif name == "run_secret_hunt":
                ok = h.run_secret_hunt(domain)
                obs = self._summarize_findings(domain, "secrets", ok)

            elif name == "run_repo_source_hunt":
                ok = h.run_repo_source_hunt(
                    domain,
                    repo_url=str(args.get("repo_url", "")),
                    repo_path=str(args.get("repo_path", "")),
                    allow_large_repo=bool(args.get("allow_large_repo", False)),
                )
                obs = self._summarize_repo_source(domain, ok)

            elif name == "run_source_intel":
                ok = h.run_source_intel(
                    domain,
                    repo_path=str(args.get("repo_path", "")),
                    repo_url=str(args.get("repo_url", "")),
                )
                obs = h.read_source_intel(domain)
                if not ok:
                    obs = "run_source_intel: no source/JS signals were available.\n" + obs

            elif name == "read_source_intel":
                obs = h.read_source_intel(domain)

            elif name == "run_js_read":
                ok = h.run_js_read(domain)
                obs = h.read_js_intel(domain)
                if not ok:
                    obs = "run_js_read: no cached JS or recon-extracted JS artifacts were available.\n" + obs

            elif name == "read_js_intel":
                obs = h.read_js_intel(domain)

            elif name == "run_browser_probe":
                ok = h.run_browser_probe(
                    domain,
                    url=str(args.get("url", "")),
                    session=str(args.get("session", "")),
                )
                obs = h.read_browser_surface(domain)
                if not ok:
                    obs = "run_browser_probe: no browser capture was created.\n" + obs

            elif name == "read_browser_surface":
                obs = h.read_browser_surface(domain)

            elif name == "run_param_discovery":
                ok = h.run_param_discovery(domain)
                obs = self._summarize_params(domain, ok)

            elif name == "run_post_param_discovery":
                cookies = args.get("cookies", self.default_cookies)
                ok = h.run_post_param_discovery(domain, cookies=cookies)
                obs = self._summarize_post_params(domain, ok)

            elif name == "run_api_fuzz":
                ok = h.run_api_fuzz(domain)
                obs = self._summarize_findings(domain, "api", ok)

            elif name == "run_cors_check":
                ok = h.run_cors_check(domain)
                obs = self._summarize_findings(domain, "cors", ok)

            elif name == "run_cms_exploit":
                ok = h.run_cms_exploit(domain)
                obs = self._summarize_findings(domain, "cms", ok)

            elif name == "run_rce_scan":
                ok = h.run_rce_scan(domain)
                obs = self._summarize_findings(domain, "rce", ok)

            elif name == "run_sqlmap_targeted":
                ok = h.run_sqlmap_targeted(domain)
                obs = self._summarize_findings(domain, "sqlmap", ok)

            elif name == "run_sqlmap_on_file":
                req_file = args.get("request_file", "")
                if not req_file or not os.path.isfile(req_file):
                    return f"ERROR: request_file not found: {req_file}"
                ok = h.run_sqlmap_request_file(
                    req_file, domain=domain,
                    level=int(args.get("level", 5)),
                    risk=int(args.get("risk", 3)),
                )
                obs = f"sqlmap (request-file) completed. Injectable: {ok}"

            elif name == "run_json_inject_probe":
                ok = h.run_json_inject_probe(
                    domain,
                    endpoints_file=str(args.get("endpoints_file", "")),
                    js_intel=str(args.get("js_intel", "")),
                    max_requests=int(args.get("max_requests", 60)),
                    add_default_seeds=bool(args.get("add_default_seeds", True)),
                )
                obs = self._summarize_findings(domain, "json_inject", ok)

            elif name == "run_jwt_audit":
                ok = h.run_jwt_audit(domain)
                obs = self._summarize_findings(domain, "jwt", ok)

            elif name == "run_cve_hunt":
                ok = h.run_cve_hunt(domain)
                obs = self._summarize_findings(domain, "cve", ok)

            elif name == "run_zero_day_fuzzer":
                ok = h.run_zero_day_fuzzer(domain, deep=bool(args.get("deep", self.deep_mode)))
                obs = self._summarize_findings(domain, "zero-day", ok)

            elif name == "generate_reports":
                count = h.generate_reports(domain)
                obs = self._summarize_reports(domain, count)

            elif name == "read_autopilot_state":
                obs = self._read_autopilot_state(
                    domain,
                    repo_root=str(args.get("repo_root", "")),
                    memory_dir=str(args.get("memory_dir", "")),
                )

            elif name == "read_intelligence":
                obs = self._read_intelligence(
                    domain,
                    repo_root=str(args.get("repo_root", "")),
                )

            elif name == "pattern_calibration_summary":
                obs = self._pattern_calibration_summary(
                    format=str(args.get("format", "json")),
                )

            elif name == "read_browser_screenshot":
                obs = self._read_browser_screenshot(
                    domain,
                    seq=args.get("seq"),
                )

            elif name == "run_vision_probe":
                obs = self._run_vision_probe(
                    domain,
                    url=str(args.get("url", "")),
                    label=str(args.get("label", "vision")),
                )

            elif name == "run_sibling_probe":
                obs = self._run_sibling_probe(
                    domain,
                    seed_findings=args.get("seed_findings") or [],
                )

            elif name == "run_hypothesis_fleet":
                obs = self._run_hypothesis_fleet(
                    domain,
                    hypotheses=args.get("hypotheses") or [],
                )

            elif name == "run_self_review":
                obs = self._run_self_review(
                    domain,
                    candidates=args.get("candidates") or [],
                )

            elif name == "read_guard_status":
                obs = self._read_guard_status(
                    domain,
                    memory_dir=str(args.get("memory_dir", "")),
                )

            elif name == "read_repo_source_summary":
                obs = self._read_repo_source_summary(domain)

            elif name == "read_resume_summary":
                obs = self._read_resume_summary(
                    domain,
                    memory_dir=str(args.get("memory_dir", "")),
                )

            elif name == "read_surface_summary":
                obs = self._read_surface_summary(
                    domain,
                    repo_root=str(args.get("repo_root", "")),
                    memory_dir=str(args.get("memory_dir", "")),
                )

            elif name == "run_intel":
                obs = self._run_intel(
                    domain,
                    tech=str(args.get("tech", "")),
                    program=str(args.get("program", "")),
                    memory_dir=str(args.get("memory_dir", "")),
                )

            elif name == "remember_finding":
                obs = self._remember_finding(
                    domain,
                    target=str(args.get("target", "")),
                    vuln_class=str(args.get("vuln_class", "")),
                    endpoint=str(args.get("endpoint", "")),
                    result=str(args.get("result", "")),
                    severity=str(args.get("severity", "")),
                    payout=args.get("payout", None),
                    technique=str(args.get("technique", "")),
                    notes=str(args.get("notes", "")),
                    tags=args.get("tags", []),
                    tech_stack=args.get("tech_stack", []),
                    memory_dir=str(args.get("memory_dir", "")),
                )

            elif name == "read_recon_summary":
                obs = self._read_recon_files(domain)

            elif name == "read_findings_summary":
                obs = self._read_findings_files(domain)

            elif name == "update_working_memory":
                notes = args.get("notes", "")
                self.memory.working_memory = notes
                self.memory.save()
                return f"Working memory updated ({len(notes)} chars)."

            elif name == "finish":
                return f"FINISH: {args.get('verdict', 'Hunt complete.')}"

            else:
                return f"Unknown tool: {name}"

        except Exception as exc:
            tb = traceback.format_exc()
            return f"Tool {name} raised exception: {exc}\n{tb[:500]}"

        # (P5-B11) Cap large tool returns and log overflow. Applied to the
        # read_* tools where 200KB+ outputs are realistic; other tools are
        # left untouched.
        if name in {
            "read_recon_summary",
            "read_surface_summary",
            "read_intelligence",
            "read_findings_summary",
            "read_repo_source_summary",
        } and isinstance(obs, str):
            try:
                from tools.output_cap import cap_with_log
                obs = cap_with_log(obs, tool=name)
            except Exception:
                pass

        elapsed = round(time.time() - t0, 1)
        obs_full = f"{obs}\n\n[{name} completed in {elapsed}s]"

        # Update memory
        self.memory.add_observation(name, obs_full)
        self.memory.completed_steps.append(name)
        self.memory.step_count += 1

        # Classify any critical/high findings into findings_log
        self._classify_obs(name, obs_full)
        self.memory.save()

        return obs_full

    # ── Observation formatters ──────────────────────────────────────────────

    def _summarize_recon(self, domain: str, ok: bool) -> str:
        h = _h()
        lines = [f"run_recon: {'OK' if ok else 'PARTIAL'}"]
        recon_dir = h._resolve_recon_dir(domain)

        live_urls = h._collect_live_urls(domain)
        if live_urls:
            lines.append(f"Live hosts: {len(live_urls)}")

        for fn in ("resolved.txt", "all.txt"):
            fp = os.path.join(recon_dir, fn)
            if os.path.isfile(fp):
                count = sum(1 for _ in open(fp) if _.strip())
                lines.append(f"Subdomains: {count}")
                break

        techs = h._extract_recon_tech_stack(domain, limit=10)
        if techs:
            lines.append(f"Tech detected: {', '.join(techs)}")

        all_urls = h._collect_all_urls(domain)
        if all_urls:
            lines.append(f"All URLs: {len(all_urls)}")

        param_urls = h._collect_param_urls(domain)
        if param_urls:
            lines.append(f"Parameterized URLs: {len(param_urls)}")

        api_urls = h._collect_api_endpoints(domain)
        if api_urls:
            lines.append(f"API endpoints: {len(api_urls)}")

        js_urls = h._collect_js_urls(domain)
        if js_urls:
            lines.append(f"JavaScript assets: {len(js_urls)}")

        return "\n".join(lines)

    def _summarize_tools(self, installed: list[str], missing: list[str]) -> str:
        lines = [f"check_tools: {len(installed)} installed, {len(missing)} missing"]
        if installed:
            lines.append("Installed: " + ", ".join(installed[:12]))
        if missing:
            lines.append("Missing: " + ", ".join(missing[:12]))
        return "\n".join(lines)

    def _summarize_findings(self, domain: str, label: str, ok: bool) -> str:
        h = _h()
        findings_dir = h._resolve_findings_dir(domain, create=False)
        lines = [f"{label}: {'OK' if ok else 'ran (check manually)'}"]

        # Walk findings dir for any .txt with content
        if findings_dir and os.path.isdir(findings_dir):
            scanner_summary = self._format_scanner_summary(findings_dir)
            if scanner_summary:
                lines.append(scanner_summary)
            finding_index = self._format_finding_index(findings_dir)
            if finding_index:
                lines.append(finding_index)

            for root, _, files in os.walk(findings_dir):
                for fn in files:
                    if not fn.endswith(".txt"):
                        continue
                    fp = os.path.join(root, fn)
                    try:
                        content = Path(fp).read_text(errors="replace")
                        if any(kw in content.lower() for kw in
                               ("critical", "high", "vulnerable", "injectable",
                                "rce", "sqli", "open redirect", "exposed", "default cred")):
                            head = content[:400].replace("\n", " ")
                            lines.append(f"  [{fn}] {head}")
                    except Exception:
                        pass

        if len(lines) == 1:
            lines.append("  No HIGH/CRITICAL findings in artifacts (check logs above for details).")
        return "\n".join(lines[:20])

    def _summarize_repo_source(self, domain: str, ok: bool) -> str:
        h = _h()
        repo_root = Path(h.FINDINGS_DIR).parent
        exposure_dir = repo_source_exposure_dir(repo_root, domain)
        lines = [f"run_repo_source_hunt: {'OK' if ok else 'confirmation required / check artifacts'}"]

        meta_path = exposure_dir / "repo_source_meta.json"
        if meta_path.is_file():
            try:
                meta = json.loads(meta_path.read_text())
                lines.append(
                    "  source={source_kind} files={file_count} size={size_bytes} clone={clone_performed}".format(**meta)
                )
            except Exception:
                pass

        for filename in ("repo_secrets.json", "repo_ci_findings.json"):
            file_path = exposure_dir / filename
            if not file_path.is_file():
                continue
            try:
                payload = json.loads(file_path.read_text())
                lines.append(f"  {filename}: {len(payload)} findings")
            except Exception:
                pass

        summary_path = exposure_dir / "repo_summary.md"
        if summary_path.is_file():
            summary = summary_path.read_text(errors="replace")[:400].replace("\n", " ")
            lines.append(f"  [repo_summary.md] {summary}")

        return "\n".join(lines)

    def _summarize_reports(self, domain: str, count: int) -> str:
        h = _h()
        report_dir = os.path.join(h.REPORTS_DIR, domain)
        lines = [f"generate_reports: {count} report(s) generated"]
        if os.path.isdir(report_dir):
            index_path = os.path.join(report_dir, "INDEX.json")
            if os.path.isfile(index_path):
                try:
                    payload = json.loads(Path(index_path).read_text(encoding="utf-8"))
                    report_index = payload.get("reports", []) if isinstance(payload, dict) else []
                    if report_index:
                        lines.append("Report index:")
                        for item in report_index[:8]:
                            if not isinstance(item, dict):
                                continue
                            report_file = os.path.basename(str(item.get("file", "")))
                            lines.append(
                                "  - {id} [{severity}] {type} finding={finding_id} file={file}".format(
                                    id=item.get("id", "-"),
                                    severity=item.get("severity", "-"),
                                    type=item.get("type", "-"),
                                    finding_id=item.get("finding_id", "-") or "-",
                                    file=report_file or "-",
                                )
                            )
                except Exception:
                    pass
            reports = sorted(
                fn for fn in os.listdir(report_dir)
                if fn.endswith(".md") and fn != "SUMMARY.md"
            )
            if reports:
                lines.append("Reports: " + ", ".join(reports[:8]))
        return "\n".join(lines)

    def _read_autopilot_state(self, domain: str, repo_root: str = "", memory_dir: str = "") -> str:
        from tools.autopilot_state import build_autopilot_state, format_autopilot_state

        resolved_repo_root = repo_root or _h().BASE_DIR
        resolved_memory_dir = self._resolve_memory_dir(memory_dir)
        state = build_autopilot_state(resolved_repo_root, domain, memory_dir=resolved_memory_dir)
        return format_autopilot_state(state)

    def _read_intelligence(self, domain: str, repo_root: str = "") -> str:
        """Read evidence/<target>/intelligence.md if present.

        Backs the `read_intelligence` tool. The F4 finish-gate relies on this
        tool being recorded in `memory.completed_steps` when the LLM consults
        the local intelligence layer.
        """
        resolved_repo_root = Path(repo_root) if repo_root else Path(_h().BASE_DIR)
        intel_path = resolved_repo_root / "evidence" / domain / "intelligence.md"
        if not intel_path.is_file():
            return (
                f"No intelligence layer at {intel_path}. "
                "Run tools/intelligence_extractor.py to populate it first."
            )
        try:
            content = intel_path.read_text(encoding="utf-8")
        except Exception as exc:
            return f"Failed to read {intel_path}: {exc}"
        # Cap context: trim very long intelligence files to avoid blowing the window.
        if len(content) > 12000:
            content = content[:12000] + "\n\n[...truncated; read full file at evidence/<target>/intelligence.md]"
        return f"# intelligence.md ({intel_path})\n\n{content}"

    def _pattern_calibration_summary(self, format: str = "json") -> str:
        """Return per-pattern precision/recall table (B12d R7).

        Backs the `pattern_calibration_summary` dispatcher tool.
        """
        try:
            from tools.pattern_calibration import summarise, excluded_pattern_ids
        except Exception as exc:
            return f"pattern_calibration unavailable: {exc}"
        try:
            rows = summarise()
            excluded = sorted(excluded_pattern_ids())
        except Exception as exc:
            return f"pattern_calibration error: {exc}"
        payload = {
            "rows": rows,
            "excluded_pattern_ids": excluded,
            "exclusion_rule": "samples>=5 AND precision<0.2",
        }
        if str(format).lower() == "text":
            if not rows:
                return "pattern_calibration: no data"
            lines = ["pattern_id  samples  helped  no_signal  fp  precision  recall_proxy"]
            for r in rows:
                prec = f"{r['precision']:.2f}" if r["precision"] is not None else "n/a"
                rec = f"{r['recall_proxy']:.2f}" if r["recall_proxy"] is not None else "n/a"
                lines.append(
                    f"{r['pattern_id']}  {r['samples']}  {r['helped']}  "
                    f"{r['no_signal']}  {r['false_positive']}  {prec}  {rec}"
                )
            if excluded:
                lines.append("")
                lines.append(f"excluded (samples>=5, precision<0.2): {', '.join(excluded)}")
            return "\n".join(lines)
        return json.dumps(payload, indent=2)

    def _read_browser_screenshot(self, domain: str, seq=None) -> str:
        """Return latest vision-captured screenshot path for the target (B12b).

        Backs the `read_browser_screenshot` dispatcher tool. Returns a JSON
        payload with the screenshot path + correlated DOM path; the caller
        (vision-capable LLM) is responsible for loading the image.
        """
        try:
            from tools.vision_browser import find_latest_screenshot, list_screenshots
        except Exception as exc:
            return f"vision_browser unavailable: {exc}"
        try:
            if seq is not None:
                rows = list_screenshots(domain)
                for r in rows:
                    if r["seq"] == int(seq):
                        return json.dumps(r, indent=2)
                return json.dumps({"error": f"no screenshot with seq={seq}"}, indent=2)
            latest = find_latest_screenshot(domain)
            if latest is None:
                return json.dumps({"error": "no screenshots captured yet; run a vision probe first"}, indent=2)
            seq_match = re.search(r"screenshot_(\d+)\.png$", latest.name)
            seq_num = int(seq_match.group(1)) if seq_match else 0
            dom = latest.parent / f"dom_{seq_num}.html"
            return json.dumps({
                "seq": seq_num,
                "screenshot_path": str(latest),
                "dom_path": str(dom) if dom.exists() else "",
                "hint": (
                    "Inspect the visible layout for clickable elements not "
                    "represented in the DOM, overlay-hidden inputs, or "
                    "visual-only state."
                ),
            }, indent=2)
        except Exception as exc:
            return f"read_browser_screenshot error: {exc}"

    def _run_vision_probe(self, domain: str, url: str = "", label: str = "vision") -> str:
        """Capture a fresh sequence-tagged screenshot (P5-W1 R3).

        Hard-gated: refuses to run unless --vision is set AND the active
        model is on the vision allowlist. Returns JSON with screenshot_path,
        dom_path, screenshot_seq, capped flag.
        """
        try:
            from tools.vision_browser import (
                capture_with_screenshot_sequence,
                should_expose_vision_tool,
            )
        except Exception as exc:
            return f"vision_browser unavailable: {exc}"

        if not should_expose_vision_tool(
            vision_enabled=self.vision_enabled,
            model_name=self.model_id,
        ):
            return json.dumps({
                "error": (
                    "run_vision_probe disabled: requires --vision flag AND a "
                    "vision-capable model"
                ),
                "vision_flag": bool(self.vision_enabled),
                "model_id": self.model_id,
            }, indent=2)

        if not url:
            return json.dumps({"error": "url is required"}, indent=2)

        try:
            out = capture_with_screenshot_sequence(
                target=domain,
                url=url,
                label=label,
                max_screenshots=self.max_screenshots,
            )
            # Trim raw capture detail to keep tool return compact for LLMs.
            return json.dumps({
                "screenshot_seq": out.get("screenshot_seq"),
                "screenshot_path": out.get("screenshot_path", ""),
                "dom_path": out.get("dom_path", ""),
                "capped": bool(out.get("capped")),
            }, indent=2)
        except Exception as exc:
            return f"run_vision_probe error: {exc}"

    def _run_sibling_probe(self, domain: str, seed_findings) -> str:
        """Expand seed findings into sibling probes (P5-W1 R1).

        When self.parallel_enabled is True and len(seed_findings) > 1, spawn
        up to self.max_parallel sibling workers concurrently and consolidate
        with dedup. Otherwise execute sequentially (one worker at a time).
        Returns a JSON summary of consolidated findings.
        """
        if not isinstance(seed_findings, list) or not seed_findings:
            return json.dumps({"error": "seed_findings is required (non-empty list)"}, indent=2)

        try:
            from tools.parallel_workers import (
                spawn_sibling_worker,
                wait_for_workers,
                _consolidate_findings,
            )
        except Exception as exc:
            return f"parallel_workers unavailable: {exc}"

        timeout = self.worker_timeout_secs
        seeds = [s for s in seed_findings if isinstance(s, dict) and s.get("endpoint")]
        if not seeds:
            return json.dumps({"error": "no usable seed_findings (each needs at least 'endpoint')"}, indent=2)

        try:
            if self.parallel_enabled and len(seeds) > 1:
                # Parallel branch: spawn up to max_parallel workers
                batch = seeds[: self.max_parallel]
                handles = []
                for i, seed in enumerate(batch):
                    h = spawn_sibling_worker(
                        seed_finding=seed,
                        worker_id=f"sibling-{i:02d}",
                        target=domain,
                        timeout_secs=timeout,
                        parent_session=getattr(self.memory, "session_id", None),
                    )
                    handles.append(h)
                results = wait_for_workers(handles, timeout_secs=timeout)
                consolidated = _consolidate_findings(results)
                return json.dumps({
                    "mode": "parallel",
                    "workers_spawned": len(handles),
                    "max_parallel": self.max_parallel,
                    "findings_count": len(consolidated),
                    "findings": consolidated[:25],  # cap inline output
                }, indent=2)
            else:
                # Sequential branch: one worker at a time
                all_results = []
                for i, seed in enumerate(seeds):
                    h = spawn_sibling_worker(
                        seed_finding=seed,
                        worker_id=f"sibling-{i:02d}",
                        target=domain,
                        timeout_secs=timeout,
                        parent_session=getattr(self.memory, "session_id", None),
                    )
                    rs = wait_for_workers([h], timeout_secs=timeout)
                    all_results.extend(rs)
                consolidated = _consolidate_findings(all_results)
                return json.dumps({
                    "mode": "sequential",
                    "workers_spawned": len(seeds),
                    "findings_count": len(consolidated),
                    "findings": consolidated[:25],
                }, indent=2)
        except Exception as exc:
            return f"run_sibling_probe error: {exc}"

    def _run_hypothesis_fleet(self, domain: str, hypotheses) -> str:
        """Test multiple attack hypotheses; parallel via run_fanout (P5-W1 R2).

        Branches on self.parallel_hypotheses:
          True  → tools.hypothesis_fleet.run_fanout (parallel, ranked, demoted)
          False → run each hypothesis sequentially using the same fan-out
                  primitive with max_parallel=1 so output schema stays uniform.
        """
        if not isinstance(hypotheses, list) or not hypotheses:
            return json.dumps({"error": "hypotheses is required (non-empty list)"}, indent=2)

        try:
            from tools.hypothesis_fleet import run_fanout
        except Exception as exc:
            return f"hypothesis_fleet unavailable: {exc}"

        effective_parallel = self.max_parallel if self.parallel_hypotheses else 1
        try:
            result = run_fanout(
                hypotheses=hypotheses,
                target=domain,
                max_parallel=effective_parallel,
                parent_session=getattr(self.memory, "session_id", None),
                timeout_secs=self.worker_timeout_secs,
            )
            # Compact output for the LLM. Winner + demoted_count is enough.
            winner = result.get("winner")
            return json.dumps({
                "mode": "parallel" if self.parallel_hypotheses else "sequential",
                "max_parallel": effective_parallel,
                "workers_total": result.get("workers_total", 0),
                "winner": winner,
                "demoted_count": result.get("demoted_count", 0),
            }, indent=2)
        except Exception as exc:
            return f"run_hypothesis_fleet error: {exc}"

    def _run_self_review(self, domain: str, candidates) -> str:
        """Adversarial pre-finish self-review (P5-W1 R4).

        For each candidate, spawn a red-team worker, parse its VERDICT,
        and decide keep/demote/kill. Kill decisions are recorded as
        false-positive patterns so future runs avoid the same trap.

        No-op when self.self_review_enabled is False — returns a JSON
        stub so the LLM understands the flag is off.
        """
        if not self.self_review_enabled:
            return json.dumps({
                "skipped": True,
                "reason": "--self-review not enabled; nothing to do",
            }, indent=2)

        if not isinstance(candidates, list) or not candidates:
            return json.dumps({"error": "candidates is required (non-empty list)"}, indent=2)

        try:
            from tools.parallel_workers import spawn_red_team_worker, wait_for_workers
            from tools.self_review import (
                parse_verdict_file,
                decision_for,
                red_team_path_for,
                record_disqualifier_as_false_positive,
                build_audit_record,
            )
        except Exception as exc:
            return f"self_review modules unavailable: {exc}"

        timeout = self.worker_timeout_secs
        valid = [c for c in candidates if isinstance(c, dict) and c.get("id")]
        if not valid:
            return json.dumps({"error": "no usable candidates (each needs at least 'id')"}, indent=2)

        try:
            handles = []
            for i, cand in enumerate(valid):
                h = spawn_red_team_worker(
                    candidate_finding=cand,
                    worker_id=f"rt-{i:02d}",
                    target=domain,
                    timeout_secs=timeout,
                    parent_session=getattr(self.memory, "session_id", None),
                )
                handles.append((cand, h))
            wait_for_workers([h for _, h in handles], timeout_secs=timeout)

            decisions = []
            keep = demote = kill = 0
            for cand, handle in handles:
                fid = str(cand.get("id", ""))
                vpath = red_team_path_for(domain, fid)
                verdict = parse_verdict_file(vpath)
                decision = decision_for(verdict)
                if decision == "kill":
                    kill += 1
                    try:
                        record_disqualifier_as_false_positive(
                            finding=cand,
                            target=domain,
                        )
                    except Exception:
                        pass
                elif decision == "demote":
                    demote += 1
                else:
                    keep += 1
                decisions.append({
                    "finding_id": fid,
                    "verdict": verdict or "missing",
                    "decision": decision,
                    "worker_id": handle.worker_id,
                })

            return json.dumps({
                "candidates_reviewed": len(handles),
                "keep_count": keep,
                "demote_count": demote,
                "kill_count": kill,
                "decisions": decisions,
            }, indent=2)
        except Exception as exc:
            return f"run_self_review error: {exc}"

    def _read_guard_status(self, domain: str, memory_dir: str = "") -> str:
        from tools.request_guard import format_guard_output, load_guard_status

        resolved_memory_dir = self._resolve_memory_dir(memory_dir)
        status = load_guard_status(resolved_memory_dir, domain)
        return format_guard_output(status, "status")

    def _read_repo_source_summary(self, domain: str) -> str:
        h = _h()
        repo_root = Path(h.FINDINGS_DIR).parent
        if not list_repo_source_artifacts(repo_root, domain):
            return f"No repo source artifacts found for {domain}."
        return self._summarize_repo_source(domain, ok=True)

    def _read_resume_summary(self, domain: str, memory_dir: str = "") -> str:
        from tools.resume import format_resume_output, load_resume_summary

        resolved_memory_dir = self._resolve_memory_dir(memory_dir)
        summary = load_resume_summary(resolved_memory_dir, domain)
        return format_resume_output(summary, domain)

    def _read_surface_summary(self, domain: str, repo_root: str = "", memory_dir: str = "") -> str:
        from tools.surface import format_surface_output, load_surface_context, rank_surface

        resolved_repo_root = repo_root or _h().BASE_DIR
        resolved_memory_dir = self._resolve_memory_dir(memory_dir)
        context = load_surface_context(resolved_repo_root, domain, memory_dir=resolved_memory_dir)
        ranked = rank_surface(context)
        return format_surface_output(ranked, domain)

    def _run_intel(self, domain: str, tech: str = "", program: str = "", memory_dir: str = "") -> str:
        from tools.intel_engine import (
            fetch_all_intel,
            format_output,
            load_memory_context,
            prioritize_intel,
            run_identity_intel,
        )

        resolved_memory_dir = self._resolve_memory_dir(memory_dir)
        memory = load_memory_context(resolved_memory_dir, domain)

        techs = [item.strip().lower() for item in tech.split(",") if item.strip()]
        for item in memory.get("tech_stack", []):
            normalized = str(item).strip().lower()
            if normalized and normalized not in techs:
                techs.append(normalized)
        for item in _h()._extract_recon_tech_stack(domain, limit=12):
            normalized = str(item).strip().lower()
            if normalized and normalized not in techs:
                techs.append(normalized)

        if not techs:
            return (
                f"No tech stack available for {domain}.\n"
                f"Run read_recon_summary or pass tech explicitly before run_intel."
            )

        results = fetch_all_intel(techs, domain, program)
        intel = prioritize_intel(results, memory)
        intel["identity_intel"] = run_identity_intel(domain)
        self._write_intel_artifact(domain, intel)
        return format_output(domain, intel)

    def _write_intel_artifact(self, domain: str, intel: dict) -> None:
        """Persist structured /intel output for later surface reranking."""
        h = _h()
        recon_dir = h._resolve_recon_dir(domain)
        try:
            os.makedirs(recon_dir, exist_ok=True)
            payload = {
                "target": domain,
                "generated_at": datetime.now().astimezone().isoformat(),
                **intel,
            }
            Path(os.path.join(recon_dir, "intel.json")).write_text(
                json.dumps(payload, indent=2),
                encoding="utf-8",
            )
        except Exception:
            # Intel persistence is an optimization for rerank; do not fail the hunt.
            return

    def _remember_finding(
        self,
        domain: str,
        *,
        target: str = "",
        vuln_class: str = "",
        endpoint: str = "",
        result: str = "",
        severity: str = "",
        payout: Any = None,
        technique: str = "",
        notes: str = "",
        tags: Any = None,
        tech_stack: Any = None,
        memory_dir: str = "",
    ) -> str:
        from tools.remember import remember_finding

        resolved_target = target or domain
        if not vuln_class or not endpoint or not result:
            return "ERROR: remember_finding requires vuln_class, endpoint, and result."

        resolved_memory_dir = self._resolve_memory_dir(memory_dir)
        resolved_tags = tags if isinstance(tags, list) else []
        resolved_tech_stack = tech_stack if isinstance(tech_stack, list) else []
        numeric_payout = None if payout in ("", None) else float(payout)

        summary = remember_finding(
            memory_dir=resolved_memory_dir,
            target=resolved_target,
            vuln_class=vuln_class,
            endpoint=endpoint,
            result=result,
            severity=severity or None,
            payout=numeric_payout,
            technique=technique or None,
            notes=notes or None,
            tags=resolved_tags,
            tech_stack=resolved_tech_stack,
        )

        lines = [
            "REMEMBERED",
            f"Target: {summary['target']}",
            f"Endpoint: {summary['endpoint']}",
            f"Journal: {'yes' if summary['journal_saved'] else 'no'}",
            f"Target profile updated: {'yes' if summary['finding_saved'] or summary['journal_saved'] else 'no'}",
            f"Pattern saved: {'yes' if summary['pattern_saved'] else 'no'}",
        ]
        if summary["tech_stack"]:
            lines.append(f"Tech stack: {', '.join(summary['tech_stack'])}")
        return "\n".join(lines)

    def _summarize_params(self, domain: str, ok: bool) -> str:
        h = _h()
        recon_dir  = h._resolve_recon_dir(domain)
        params_dir = os.path.join(recon_dir, "params")
        lines = [f"run_param_discovery: {'OK' if ok else 'partial'}"]

        interesting_path = os.path.join(params_dir, "interesting_params.txt")
        if os.path.isfile(interesting_path):
            count = sum(1 for _ in open(interesting_path) if _.strip())
            lines.append(f"  interesting_params.txt: {count} candidates")

        arjun_outputs = sorted(
            fn for fn in os.listdir(params_dir)
            if fn.startswith("arjun_") and fn.endswith(".txt")
        ) if os.path.isdir(params_dir) else []
        if arjun_outputs:
            lines.append(f"  arjun outputs: {len(arjun_outputs)} files")

        if len(lines) == 1:
            lines.append("  No parameter discovery artifacts found.")
        return "\n".join(lines)

    def _summarize_post_params(self, domain: str, ok: bool) -> str:
        h = _h()
        recon_dir  = h._resolve_recon_dir(domain)
        params_dir = os.path.join(recon_dir, "params")
        lines = [f"run_post_param_discovery: {'found POST params' if ok else 'no POST params found'}"]
        fp = os.path.join(params_dir, "post_params.json")
        if os.path.isfile(fp):
            try:
                data = json.loads(Path(fp).read_text())
                for url, info in list(data.items())[:8]:
                    params = ", ".join(info.get("params", [])[:6])
                    lines.append(f"  POST {url}  →  [{params}]")
            except Exception:
                pass
        return "\n".join(lines)

    def _read_recon_files(self, domain: str) -> str:
        h = _h()
        parts = []

        live_urls = h._collect_live_urls(domain)
        if live_urls:
            parts.append(
                f"=== Live hosts ({len(live_urls)} total) ===\n" + "\n".join(live_urls[:20])
            )

        techs = h._extract_recon_tech_stack(domain, limit=12)
        if techs:
            parts.append("=== Tech stack ===\n" + "\n".join(techs))

        api_urls = h._collect_api_endpoints(domain)
        if api_urls:
            parts.append(
                f"=== API endpoints ({len(api_urls)} total) ===\n" + "\n".join(api_urls[:20])
            )

        param_urls = h._collect_param_urls(domain)
        if param_urls:
            parts.append(
                f"=== Parameterized URLs ({len(param_urls)} total) ===\n" + "\n".join(param_urls[:20])
            )

        js_urls = h._collect_js_urls(domain)
        if js_urls:
            parts.append(
                f"=== JavaScript assets ({len(js_urls)} total) ===\n" + "\n".join(js_urls[:20])
            )

        all_urls = h._collect_all_urls(domain)
        if all_urls:
            parts.append(
                f"=== All URLs ({len(all_urls)} total) ===\n" + "\n".join(all_urls[:20])
            )

        post_params_path = os.path.join(h._resolve_recon_dir(domain), "params", "post_params.json")
        if os.path.isfile(post_params_path):
            try:
                post_params = json.loads(Path(post_params_path).read_text())
                sample = []
                for url, info in list(post_params.items())[:10]:
                    params = ", ".join(info.get("params", [])[:6])
                    sample.append(f"{url} -> {params}")
                if sample:
                    parts.append(
                        f"=== POST params ({len(post_params)} forms) ===\n" + "\n".join(sample)
                    )
            except Exception:
                pass

        repo_root = Path(h.FINDINGS_DIR).parent
        if list_repo_source_artifacts(repo_root, domain):
            parts.append(
                "=== Repo source artifacts ===\n"
                "Repository source-hunt artifacts already exist under findings/<target>/exposure.\n"
                "Use read_repo_source_summary before re-running run_repo_source_hunt."
            )

        return "\n\n".join(parts) if parts else "No recon data found. Run run_recon first."

    def _format_scanner_summary(self, findings_dir: str) -> str:
        """Return a compact, LLM-readable view of scanner summary.json."""
        summary_path = os.path.join(findings_dir, "summary.json")
        if not os.path.isfile(summary_path):
            return ""

        try:
            payload = json.loads(Path(summary_path).read_text(encoding="utf-8"))
        except Exception:
            return ""

        if not isinstance(payload, dict):
            return ""

        totals = payload.get("totals") if isinstance(payload.get("totals"), dict) else {}
        high_value = totals.get("high_value") if isinstance(totals.get("high_value"), dict) else {}
        categories = payload.get("categories") if isinstance(payload.get("categories"), dict) else {}

        def as_int(value: Any) -> int:
            try:
                return int(value or 0)
            except (TypeError, ValueError):
                return 0

        lines = [
            "=== scanner_summary ===",
            (
                f"target={payload.get('target', '-')}"
                f" mode={payload.get('mode', '-')}"
                f" live={payload.get('live_count', 0)}"
                f" scan_targets={payload.get('ordered_scan_count', 0)}"
                f" total_findings={totals.get('findings', 0)}"
                f" manual_review={totals.get('manual_review_items', 0)}"
            ),
        ]

        active_high_value = [
            f"{name}={count}"
            for name, count in sorted(high_value.items())
            if as_int(count) > 0
        ]
        if active_high_value:
            lines.append("high_value: " + ", ".join(active_high_value))

        active_categories = [
            f"{name}: {data.get('total', 0)}"
            for name, data in sorted(categories.items())
            if isinstance(data, dict) and as_int(data.get("total")) > 0
        ]
        if active_categories:
            lines.append("categories: " + "; ".join(active_categories[:12]))

        skipped_checks = payload.get("skipped_checks")
        if isinstance(skipped_checks, list) and skipped_checks:
            lines.append("skipped_checks: " + ", ".join(str(item) for item in skipped_checks))

        return "\n".join(lines)

    def _format_finding_index(self, findings_dir: str) -> str:
        """Return compact structured finding candidates when findings.json exists."""
        try:
            from tools.finding_index import format_finding_index, load_finding_index
        except Exception:
            return ""

        try:
            return format_finding_index(load_finding_index(findings_dir))
        except Exception:
            return ""

    def _format_next_validation_hint(self, findings_dir: str) -> str:
        """Suggest the highest-value structured finding to validate next."""
        try:
            from tools.finding_index import load_finding_index
        except Exception:
            return ""

        try:
            payload = load_finding_index(findings_dir)
        except Exception:
            return ""

        findings = [
            item for item in payload.get("findings", [])
            if isinstance(item, dict) and item.get("id")
        ]
        if not findings:
            return ""

        severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        confidence_rank = {"confirmed": 4, "high": 3, "medium": 2, "needs_review": 1}

        def rank_key(item: dict) -> tuple[int, int]:
            severity = str(item.get("severity", "")).lower()
            confidence = str(item.get("confidence", "")).lower()
            return (
                severity_rank.get(severity, 0),
                confidence_rank.get(confidence, 0),
            )

        top = max(findings, key=rank_key)
        return (
            "=== next_validation ===\n"
            f"Next validation: {top.get('id')} "
            f"[{top.get('severity', '-')}/{top.get('confidence', '-')}] "
            f"{top.get('type', '-')} {top.get('url', '')}\n"
            "Command: "
            f"python3 tools/validate.py --findings-dir {findings_dir} --finding-id {top.get('id')}"
        )

    def _read_findings_files(self, domain: str) -> str:
        h = _h()
        findings_dir = h._resolve_findings_dir(domain, create=False)
        if not findings_dir or not os.path.isdir(findings_dir):
            return "No findings directory. Run vulnerability scans first."

        parts = []
        scanner_summary = self._format_scanner_summary(findings_dir)
        if scanner_summary:
            parts.append(scanner_summary)

        finding_index = self._format_finding_index(findings_dir)
        if finding_index:
            parts.append(finding_index)
            next_validation = self._format_next_validation_hint(findings_dir)
            if next_validation:
                parts.append(next_validation)

        exposure_dir = os.path.join(findings_dir, "exposure")
        if os.path.isdir(exposure_dir):
            repo_summary = self._summarize_repo_source(domain, ok=True)
            if repo_summary.strip():
                parts.append("=== repo_source_overview ===\n" + repo_summary)

        for root, _, files in os.walk(findings_dir):
            for fn in sorted(files):
                if not fn.endswith((".txt", ".json", ".md")):
                    continue
                fp = os.path.join(root, fn)
                rel = os.path.relpath(fp, findings_dir)
                if scanner_summary and rel == "summary.json":
                    continue
                if finding_index and rel == "findings.json":
                    continue
                try:
                    content = Path(fp).read_text(errors="replace")
                    if content.strip():
                        parts.append(f"=== {rel} ===\n{content[:800]}")
                except Exception:
                    pass

        if not parts:
            return "Findings directory exists but is empty."
        combined = "\n\n".join(parts)
        # Truncate to avoid blowing context
        if len(combined) > MAX_CTX_CHARS:
            combined = combined[:MAX_CTX_CHARS] + "\n...[truncated]"
        return combined

    def _classify_obs(self, tool: str, obs: str) -> None:
        """Extract severity labels from observation text and add to findings_log."""
        obs_l = obs.lower()
        if any(kw in obs_l for kw in ("rce_confirmed", "injectable", "critical")):
            sev = "CRITICAL"
        elif any(kw in obs_l for kw in ("high", "sql injection", "rce", "default cred")):
            sev = "HIGH"
        elif any(kw in obs_l for kw in ("medium", "exposed", "open redirect", "cors")):
            sev = "MEDIUM"
        elif any(kw in obs_l for kw in ("low", "info")):
            sev = "LOW"
        else:
            return  # not a finding, skip

        # Take first relevant line as summary
        for ln in obs.splitlines():
            if any(kw in ln.lower() for kw in
                   ("critical", "high", "injectable", "rce", "exposed", "found", "medium", "sql")):
                self.memory.add_finding(tool, sev, ln.strip()[:300])
                break


# ──────────────────────────────────────────────────────────────────────────────
#  Core ReAct agent  (Ollama native tool calling)
# ──────────────────────────────────────────────────────────────────────────────

# ──────────────────────────────────────────────────────────────────────────────
#  Loop Detector  (ctf-agent technique: signature hashing, sliding window 12)
# ──────────────────────────────────────────────────────────────────────────────

class LoopDetector:
    """
    Detects when the agent is repeating the same tool call in a loop.
    Sliding window of last 12 tool signatures.
    Warn at 3 repetitions, force direction change at 5.
    Signature = tool_name + first 300 chars of serialised args.

    (P5-B3) Also tracks semantic loops via response_hash + endpoint family.
    See record_with_response() and is_semantic_loop().
    """
    WINDOW = 12
    WARN_AT  = 3
    BREAK_AT = 5

    # P5-B3 thresholds
    SEM_WINDOW = 20
    SEM_FAMILY_HASH_REPEATS = 3   # same (family, response_hash) ≥ 3 times → loop
    SEM_HASH_REPEATS = 5          # same response_hash alone ≥ 5 times → loop

    def __init__(self):
        self._history: list[str] = []
        self._counts:  dict[str, int] = {}
        # P5-B3 semantic history: list[(family, response_hash)]
        self._sem_history: list[tuple[str, str]] = []
        self._last_loop_reason: str = ""

    def record(self, tool: str, args: dict) -> tuple[bool, bool]:
        """
        Record a tool call. Returns (warn, must_break).
        warn=True at WARN_AT repeats; must_break=True at BREAK_AT.
        """
        sig = tool + ":" + json.dumps(args, sort_keys=True)[:300]
        self._history.append(sig)
        if len(self._history) > self.WINDOW:
            evicted = self._history.pop(0)
            self._counts[evicted] = max(0, self._counts.get(evicted, 0) - 1)
        self._counts[sig] = self._counts.get(sig, 0) + 1
        n = self._counts[sig]
        return n >= self.WARN_AT, n >= self.BREAK_AT

    def reset(self) -> None:
        self._history.clear()
        self._counts.clear()
        self._sem_history.clear()
        self._last_loop_reason = ""

    # ── P5-B3 semantic loop detector ─────────────────────────────────────

    _SEM_NORMALIZE_PATTERNS = [
        # ISO-ish timestamps
        (re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"), "<TS>"),
        # bare HH:MM:SS times
        (re.compile(r"\b\d{2}:\d{2}:\d{2}\b"), "<TIME>"),
        # UUIDs
        (re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"), "<UUID>"),
        # Long hex strings (session ids, tokens, ETags)
        (re.compile(r"\b[0-9a-fA-F]{32,}\b"), "<HEX>"),
        # Trace / request IDs
        (re.compile(r'"(request|trace|nonce|x-?request-?id)"\s*:\s*"[^"]+"', re.IGNORECASE),
            r'"\1":"<ID>"'),
    ]

    @classmethod
    def _normalise_response(cls, body: str) -> str:
        if not isinstance(body, str):
            body = str(body)
        for pat, repl in cls._SEM_NORMALIZE_PATTERNS:
            body = pat.sub(repl, body)
        return body

    @staticmethod
    def _hash_body(body: str) -> str:
        import hashlib
        return hashlib.sha1(body.encode("utf-8", errors="ignore")).hexdigest()[:12]

    # Endpoint family templating: replace numeric ids, hex-ish, and UUIDs
    # with placeholders so /api/v1/users/123 and /api/v1/users/456 collapse
    # to the same family.
    _FAMILY_NUMERIC_PAT = re.compile(r"/\d+(?=/|$|\?)")
    _FAMILY_UUID_PAT = re.compile(
        r"/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?=/|$|\?)"
    )
    _FAMILY_HEX_PAT = re.compile(r"/[0-9a-fA-F]{12,}(?=/|$|\?)")

    @classmethod
    def endpoint_family(cls, endpoint: str) -> str:
        if not endpoint:
            return ""
        # Strip query string for family computation
        base = endpoint.split("?", 1)[0]
        base = cls._FAMILY_UUID_PAT.sub("/{uuid}", base)
        base = cls._FAMILY_HEX_PAT.sub("/{hex}", base)
        base = cls._FAMILY_NUMERIC_PAT.sub("/{id}", base)
        return base

    def record_with_response(self, endpoint: str, response_body: str) -> None:
        """Record an endpoint+response pair for semantic loop detection."""
        family = self.endpoint_family(endpoint or "")
        normalised = self._normalise_response(response_body or "")
        h = self._hash_body(normalised)
        self._sem_history.append((family, h))
        if len(self._sem_history) > self.SEM_WINDOW:
            self._sem_history = self._sem_history[-self.SEM_WINDOW:]

    def is_semantic_loop(self) -> tuple[bool, str]:
        """Check if the recent semantic history indicates a loop.

        Returns (yes_or_no, reason_tag).
        Rule 1: same (family, response_hash) ≥ 3 times in last 10 calls
        Rule 2: same response_hash (regardless of family) ≥ 5 times in last 20
        """
        if not self._sem_history:
            return False, ""

        # Rule 1: family+hash repeats ≥ 3 in last 10
        recent10 = self._sem_history[-10:]
        from collections import Counter
        fam_hash_counts = Counter(recent10)
        for (fam, h), n in fam_hash_counts.items():
            if n >= self.SEM_FAMILY_HASH_REPEATS:
                self._last_loop_reason = f"same_family_hash:{fam}:{h}"
                return True, self._last_loop_reason

        # Rule 2: same hash ≥ 5 in last 20
        hash_only = Counter(h for _, h in self._sem_history[-self.SEM_WINDOW:])
        for h, n in hash_only.items():
            if n >= self.SEM_HASH_REPEATS:
                self._last_loop_reason = f"same_hash:{h}"
                return True, self._last_loop_reason

        self._last_loop_reason = ""
        return False, ""

    def rotation_hint(self) -> str:
        """If a semantic loop is detected, return an injectable hint string."""
        looped, reason = self.is_semantic_loop()
        if not looped:
            return ""
        if reason.startswith("same_family_hash:"):
            parts = reason.split(":", 2)
            fam = parts[1] if len(parts) > 1 else "<unknown>"
            return (
                f"[loop-detector] You appear to be looping on family `{fam}` "
                f"with the same response. Try a different attack class, a "
                f"different endpoint family, or move to a new lane."
            )
        if reason.startswith("same_hash:"):
            return (
                "[loop-detector] You appear to be looping with the same "
                "response across endpoints. Try changing the technique, "
                "request method, or auth context."
            )
        return ""


# ──────────────────────────────────────────────────────────────────────────────
#  JSONL Tracer  (ctf-agent technique: append-only, immediate flush, tail -f)
# ──────────────────────────────────────────────────────────────────────────────

class AgentTracer:
    """
    Append-only JSONL event log — one JSON object per line, flushed immediately.
    `tail -f session.jsonl` gives live stream of what the agent is doing.
    """

    def __init__(self, log_path: str):
        self.log_path = log_path
        Path(log_path).parent.mkdir(parents=True, exist_ok=True)
        self._f = open(log_path, "a", buffering=1)  # line-buffered

    def _write(self, event: dict) -> None:
        event.setdefault("ts", datetime.now().isoformat())
        self._f.write(json.dumps(event) + "\n")
        self._f.flush()

    def tool_call(self, tool: str, args: dict, step: int) -> None:
        self._write({"event": "tool_call", "step": step, "tool": tool, "args": args})

    def tool_result(self, tool: str, result: str, elapsed: float, step: int) -> None:
        self._write({"event": "tool_result", "step": step, "tool": tool,
                     "elapsed_s": elapsed, "result_preview": result[:400]})

    def loop_warn(self, tool: str, count: int, step: int) -> None:
        self._write({"event": "loop_warn", "step": step, "tool": tool, "count": count})

    def loop_break(self, tool: str, step: int) -> None:
        self._write({"event": "loop_break", "step": step, "tool": tool})

    def bump(self, message: str, step: int) -> None:
        self._write({"event": "bump", "step": step, "message": message})

    def finding(self, severity: str, tool: str, text: str) -> None:
        self._write({"event": "finding", "severity": severity, "tool": tool, "text": text[:300]})

    def finish(self, verdict: str, step: int, elapsed_mins: float) -> None:
        self._write({"event": "finish", "step": step,
                     "elapsed_mins": elapsed_mins, "verdict": verdict})

    def close(self) -> None:
        self._f.close()


# ──────────────────────────────────────────────────────────────────────────────
#  Multi-model racer  (ctf-agent: asyncio FIRST_COMPLETED pattern)
# ──────────────────────────────────────────────────────────────────────────────

def race_analysis(prompt: str, models: list[str], client,
                  system: str = "", timeout: int = 120) -> str:
    """
    Ask multiple Ollama models the same analysis question.
    Return whichever completes first with a non-empty answer.
    Used for: triage decisions, next-action advice, finding classification.
    Falls back to sequential if only one model available.
    """
    import threading

    result_holder: dict[str, str] = {}
    done_event = threading.Event()

    def _call(model: str) -> None:
        try:
            resp = client.chat(
                model=model,
                messages=[
                    {"role": "system", "content": system or AGENT_SYSTEM},
                    {"role": "user",   "content": prompt},
                ],
                options={"num_predict": 800, "temperature": 0.1, "num_ctx": 8192},
            )
            text = (resp.get("message", {}).get("content") or "").strip()
            if text and not done_event.is_set():
                result_holder["winner"] = model
                result_holder["text"]   = text
                done_event.set()
        except Exception:
            pass

    threads = [threading.Thread(target=_call, args=(m,), daemon=True) for m in models]
    for t in threads:
        t.start()
    done_event.wait(timeout=timeout)

    if "text" in result_holder:
        winner = result_holder["winner"]
        print(f"{DIM}[Race] Winner: {winner}{NC}", flush=True)
        return result_holder["text"]

    # Sequential fallback
    for m in models:
        try:
            resp = client.chat(
                model=m,
                messages=[
                    {"role": "system", "content": system or AGENT_SYSTEM},
                    {"role": "user",   "content": prompt},
                ],
                options={"num_predict": 800, "temperature": 0.1, "num_ctx": 8192},
            )
            text = (resp.get("message", {}).get("content") or "").strip()
            if text:
                return text
        except Exception:
            continue
    return ""


def _build_agent_system(
    autopilot_mode: str = "paranoid",
    quick_mode: bool = False,
    ctf_mode: bool = False,
    deep_mode: bool = False,
) -> str:
    autopilot_mode = _normalize_autopilot_mode(autopilot_mode)
    mode_block = "MODE:\n"
    if ctf_mode:
        mode_block += (
            "- Repo-local CTF mode is enabled.\n"
            "- Treat the supplied target set as the authoritative lab target record for this session.\n"
            "- All provided and recon-discovered targets remain available for full active coverage.\n"
            "- Do not ask for authorization proof, ownership confirmation, or public-program validation while this mode is active.\n"
            "- Do not downgrade /hunt, /autopilot, or /pickup flows into passive-only analysis merely because a hostname looks public or government-like.\n"
            "- Keep every request-centric lane available in CTF mode, including browser-state flows, raw-request replay, scanner expansion, OAST follow-up, and second-stage replays.\n"
        )
    mode_block += (
        "- Authorization posture: the supplied target set is this run's active target context. Do not ask for authorization proof, ownership proof, or public-program confirmation before routine recon, scanning, or evidence-driven hunting.\n"
        "- Pause only for ambiguous target identity, unavailable credentials that cannot be derived through the controlled Credential Lane, report submission, a new target not present in the current input/context, or explicit destructive side effects / irreversible mutations / high-pressure actions.\n"
        "- Treat the provided targets as the active execution target set for this run.\n"
        "- Read local repo config early; if it marks the run as CTF/lab or sandbox mode, treat that as authoritative for this session and do not ask for external authorization before loading the config.\n"
        "- Treat recon-discovered subdomains, live hosts, URLs, JS files, parameters, and exposure candidates under the supplied targets as part of the working target set.\n"
        "- Bulk recon is allowed through the integrated recon engine: primary-domain batch dispatch, subfinder/assetfinder/puredns, httpx probing, katana/gau/waymore crawling, bounded directory and parameter fuzzing, JS/config exposure discovery, API leak detection, lightweight identity/cloud intel, and scanner lanes against the supplied/discovered target surface.\n"
        "- request_guard data is advisory audit/replay telemetry, not a hard execution gate.\n"
        "- Use the supplied target set directly; external policy pages and ownership notes are optional context only.\n"
        "- Treat production-looking brands, public-sector/government-style labels, account/login/register wording, and account-gated surfaces as target context, not automatic lane removals.\n"
        "- Old target-history caution notes are pickup context only; only the current user command can exclude a lane or bug class.\n"
        "- Fresh target coverage starts with only the scanner's built-in XSS default skip; do not inherit skipped bug classes or focus lanes from prior targets or sessions.\n"
        "- Focus on root cause, reproducible behavior, and practical attack paths.\n"
    )
    mode_block += (
        "- localhost, private IPs, CIDRs, and primary-domain batch lists remain valid target inputs.\n"
        "- Treat external bounty metadata and scope_snapshot.json as non-applicable hints.\n"
    )

    guard_rules = (
        "4. Treat guard/breaker/cooldown/rate-limit data as advisory telemetry for replay and pacing, not as a hard stop.\n"
        "5. If testing returns 403/429/timeouts or progress stalls, continue coverage with alternate paths, transports, or scanner lanes instead of waiting for guard cooldown.\n"
    )

    checkpoint_block = {
        "paranoid": (
            "CHECKPOINT MODE:\n"
            "- Checkpoint mode: paranoid.\n"
            "- Autonomously choose the next best A/B/C action from ranked evidence; do not ask the operator to pick the next branch.\n"
            "- Favor frequent checkpoints after meaningful findings or strong partial signals, not before routine branch selection.\n"
            "- Summarize meaningful signals early and avoid skipping suspicious branches.\n"
        ),
        "normal": (
            "CHECKPOINT MODE:\n"
            "- Checkpoint mode: normal.\n"
            "- Batch related findings before checkpointing.\n"
            "- Balance coverage with momentum; rotate when a branch stalls.\n"
        ),
        "yolo": (
            "CHECKPOINT MODE:\n"
            "- Checkpoint mode: yolo.\n"
            "- Keep moving until the surface is exhausted or the time budget is low.\n"
            "- Minimize checkpoints, but still preserve evidence and clear operator handoff notes.\n"
        ),
    }[autopilot_mode]

    quick_block = (
        "RUNTIME MODE:\n"
        "- Quick mode is active for this session.\n"
        "- Prefer lower-cost recon/scanner defaults unless a specific branch justifies broader coverage.\n"
        "- If you need expanded active coverage, use run_vuln_scan with full=true explicitly.\n"
    ) if quick_mode else ""

    deep_block = (
        "DEEP HUNT MODE:\n"
        "- Deep mode is active: value-first comprehensive depth, not a separate workflow, checkpoint mode, high-pressure scan mode, or step-padding mode.\n"
        "- Aggressive persistence: assume there is still a hidden high-value path until the time/step budget is exhausted, the attack surface is genuinely exhausted, or the remaining evidence gaps are explicit.\n"
        "- Scanner-negative results are not a conclusion; they mark the start of manual, AI-guided deep work. Keep pushing through repeated failures and turn each failure into a sharper next test.\n"
        "- Use rules/hunting.md#high-intensity-hunting-posture and the value-first coverage model: prioritize by practical impact, exploitability, evidence strength, affected data/workflow, validation safety, and coverage gaps.\n"
        "- Rotate across high-value vulnerability families before declaring exhaustion; do not lock onto authz/IDOR or any other fixed favorite class.\n"
        "- Cover evidence routes for access/identity, injection/RCE, server-side/file/network, client-side, business workflow, and infrastructure/supply-chain bugs.\n"
        "- Browser-observed APIs, JS/source-derived routes, recon output, errors, parameters, workflows, and target memory are evidence sources. They can point to SQLi/NoSQLi, SSRF, XXE, RCE/SSTI/command injection, unsafe deserialization, LFI/RFI/path traversal, upload/parser chains, XSS/DOM XSS, OAuth/JWT/CSRF, race/state-machine bugs, secrets/CI/CD/cloud exposure, or authz/IDOR/business logic.\n"
        "- Convert failures into next questions: sibling endpoint expansion, bypass attempt, role/object diff, source/JS/browser enrichment, or lane rotation.\n"
        "- Exploitation strategy: start with basic techniques, then escalate to advanced parser mismatch, state-machine, cross-boundary, source-informed, browser-observed, and chain-building techniques when standard methods fail.\n"
        "- Chain aggressively: when you find A, immediately look for B/C that turns it into stronger impact — sibling endpoints, alternate roles, old API versions, exports/downloads, admin render paths, callbacks, or source-confirmed sinks.\n"
        "- Focus on demonstrable business impact: data exposure, auth/tenant boundary break, privileged action reachability, account/session compromise path, internal-service reachability, or source/secret-backed pivot.\n"
        "- Bug bounty mindset: one reward-worthy, high-impact finding is worth more than many info-level observations. Do not spend deep-mode energy polishing low-impact issues unless they are evidence for a stronger chain.\n"
        "- If a candidate looks unlikely to be reward-worthy on its own, keep hunting or chain it into stronger impact: data exposure, cross-tenant access, account/session compromise, privileged workflow reachability, or meaningful internal pivot.\n"
        "- Prefer evidence-driven depth over random tool spray, but do not be timid. Use run_vuln_scan full=true, run_zero_day_fuzzer deep=true, run_js_analysis, run_secret_hunt, equivalent helpers, or small custom probes when the target is high-value, the surface is broad, a lane plateaus, or partial evidence suggests the extra cost may pay off.\n"
        "- Substantive actions must add, confirm, disprove, block, or record target evidence; do not pad the run with repeated scans or cosmetic steps.\n"
        "- Deep exhaustion checklist before finish: confirm recon/state and surface ranking were consulted; coverage matrix was rebuilt; Evidence Ledger / actor matrix was reviewed; scanner-negative results received manual follow-up; JS/source/browser/exposure context was used or explicitly ruled out; sibling/bypass/role-diff/parser/chain-building attempts were made where applicable; high-value vuln-family directions are tested, blocked, not applicable, or listed with reasons.\n"
        "- Deep mode never overrides live-action boundaries: payment/funds/order lifecycle writes, report submission, destructive side effects, and irreversible mutations still require explicit current-turn operator intent; HTTP method alone is advisory, not the boundary.\n"
        "- Before finishing, write concrete evidence gaps rather than a generic 'no findings' conclusion.\n"
    ) if deep_mode else ""

    tool_failure_block = (
        "TOOL FAILURE DISCIPLINE:\n"
        "- A failed tool is not a failed hypothesis. Inspect the error and classify it: missing tool, bad arguments, timeout/rate-limit, auth/session issue, target-format problem, network/proxy issue, or genuine negative signal.\n"
        "- Retry once with corrected arguments when the fix is obvious; otherwise use an equivalent helper, curl/python/playwright custom probe, cached artifact, or partial output to keep the lane alive.\n"
        "- If partial output exists, mine it before moving on. If the lane cannot be completed, record the exact evidence gap and rotate to the next best high-impact test instead of silently killing the path.\n"
    )

    working_hypothesis_block = (
        "WORKING HYPOTHESIS DISCIPLINE:\n"
        "On every non-trivial turn, emit a working hypothesis statement carrying\n"
        "these six anchor field names. Anchor NAMES are mandatory; CONTENT is\n"
        "free text — describe what you actually observe, never reduce a field to\n"
        "a fixed enum or pick-from-menu form.\n"
        "  working_hypothesis: one or two sentences claiming what is most likely\n"
        "    vulnerable on this target and why.\n"
        "  evidence_for: observed signals supporting the claim.\n"
        "  evidence_against: signals weakening the claim, or 'none yet'.\n"
        "  next_question: the specific fact the next tool call is meant to\n"
        "    surface — NOT 'which tool to run', but 'what do I need to learn'.\n"
        "  expected_learning: both branches — if outcome A, hypothesis becomes\n"
        "    X; if B, hypothesis becomes Y.\n"
        "  kill_condition: a concrete trigger after which this hypothesis is\n"
        "    abandoned (for example '4 bypass variants all return 403 within\n"
        "    30 min on this endpoint').\n"
        "Skip rule: mechanical-obvious turns (polling a long-running scan,\n"
        "reading a cached artifact, exiting) may omit emission — say\n"
        "'no hypothesis update — <reason>' rather than emit empty anchors.\n"
        "You are explicitly allowed to propose actions that are NOT in the\n"
        "predefined tool list. If the cheapest test of your hypothesis is a\n"
        "short custom probe written via Bash/Write/Edit (curl, python,\n"
        "playwright script), write it and save under evidence/<target>/probes/.\n"
    )

    business_model_block = (
        "STEP 0: BUSINESS MODEL READ (before recon):\n"
        "Before running run_recon for a target, ensure\n"
        "evidence/<target>/business_model.md exists and is fresh (file age\n"
        "< 30 days). If absent or stale, spend up to 15 minutes producing it\n"
        "from these sources (all free text answers — never enumerate from a\n"
        "fixed taxonomy):\n"
        "  - the live homepage (use playwright-cli when available for vision)\n"
        "  - any visible pricing page\n"
        "  - the most recent changelog / blog / status / what's-new entry\n"
        "  - openapi.json or /api/docs if discoverable\n"
        "  - one disclosed report from the same target if HackerOne MCP\n"
        "    surfaces one\n"
        "The document MUST include these five section headers as anchors\n"
        "(content under each header is free text; 'cannot answer from\n"
        "available evidence' is a valid answer):\n"
        "  ## What this company sells (and to whom)\n"
        "  ## Top 3 revenue-generating workflows\n"
        "  ## Top 3 brand-damage scenarios\n"
        "  ## Subdomain / path map to revenue surface\n"
        "  ## Features added in last 90 days\n"
        "Why this matters: senior hunters spend the first 15 minutes\n"
        "understanding how the target makes money before scanning. The\n"
        "business model document drives surface prioritization — testing\n"
        "should bias toward revenue workflows and brand-damage scenarios,\n"
        "not toward whatever the scanner enumerates first.\n"
        "Skip when: business_model.md exists and was written within 30 days\n"
        "of the current run. Do NOT regenerate just because a new session\n"
        "started.\n"
    )

    return f"""\
You are an elite autonomous security hunter. You have a set of tools that execute real security scans. Use them strategically.

{mode_block}
{checkpoint_block}
{quick_block}
{deep_block}
{tool_failure_block}
{working_hypothesis_block}
{business_model_block}
CORE RULES:
1. If scans fail unexpectedly or the environment looks incomplete, use check_tools once to understand local capability limits.
2. Prefer read_autopilot_state early to see whether recon/memory already exist, which targets are hottest, and whether any host is cooling down.
3. If no recon data exists yet, start with run_recon. Do not replace the default recon refresh with ad-hoc archive crawling; run_recon already drives the integrated `recon_engine.sh` path (`httpx`, `katana`, `gau`, `waymore`, JS/config exposure discovery). After recon, use read_autopilot_state or read_surface_summary before choosing next tool.
{guard_rules.rstrip()}
6. If repository source-hunt artifacts already exist for this target, use read_repo_source_summary before re-running run_repo_source_hunt.
7. Prioritize by impact: CMS exploits > RCE > SQLi > IDOR/auth bypass > secrets > info.
8. If Drupal or WordPress is detected → run_cms_exploit immediately. If any stack is clearly identified, prefer run_intel for the primary /intel workflow; run_cve_hunt is the legacy compatibility path.
9. If Java/Tomcat/JBoss/Spring is detected → run_rce_scan + run_post_param_discovery.
10. If login/register/dashboard/app/portal, SPA/XHR/GraphQL, or account-gated surface is present → prefer MCP-first browser-state work (chrome-devtools MCP live network, playwright MCP automation/snapshots, import via tools/browser_mcp_import.py); use run_browser_probe as the playwright-cli fallback, then read_browser_surface/read_surface_summary before reducing the surface to curl-only tests.
11. If cached JS, browser, or repo-source artifacts exist → prefer run_source_intel first, then run_js_read/read_js_intel before repeating broad scanners. Use run_js_analysis as a deeper legacy follow-up when you specifically need direct JS-body extraction or secret-heavy review. If secrets/tokens/config leaks are plausible, add run_secret_hunt.
12. If ranked workflow leads already exist → read_surface_summary and spend at least one focused step on the best lead before defaulting back to another broad scanner pass.
13. Do not get trapped in enrichment-only loops: after one or two focused lead-driven attempts, either promote/demote the lead with evidence and widen back into the next best active lane.
14. If API endpoints or numeric-object URLs exist → run_api_fuzz. If authenticated surfaces exist → run_cors_check.
15. If parameterized URLs found → run_param_discovery and run_sqlmap_targeted. Use run_sqlmap_on_file for specific raw requests. For POST JSON endpoints discovered via browser_probe or js_read (REST APIs, GraphQL, login/auth/import/mutation paths), prefer run_json_inject_probe — it is surgical (≈30s for 50 endpoints), AI-callable, and tests 8 payload classes (sqli auth-bypass/error/time, ssti, cmd-injection, open-redirect, path-traversal, xss) with 3-stage detection.
16. If JWT tokens appear in recon data → run_jwt_audit.
17. When standard scans have plateaued but attack surface remains, use run_zero_day_fuzzer.
18. For the primary /report reporting workflow, generate reports with generate_reports before finish when findings or useful artifacts exist; generate_reports is the compatibility path behind /report.
19. Maintain your notes via update_working_memory after each significant discovery.
20. Call finish when: all high-priority tools done, time running low, or no new attack surface.
21. DO NOT repeat a tool that already completed in this session unless explicitly justified.
22. Treat focus/skip requests as current-message overrides only. Never carry `scanner_skip`, excluded bug classes, or “ignore this bug class” from another target, older Claude Code CLI session, README example, or non-resumed trace. Production-looking brands, public-sector/government-style labels, account/login/register wording, account-gated surfaces, and old caution notes are not implicit skip gates. Standard/quick scanner runs skip XSS by default; use `full=true` when the current run needs broader coverage that includes XSS, and keep `scanner_skip` unset unless the current command explicitly sets additional skips.

Think step by step. Pick the highest-impact next action given what you know."""


AGENT_SYSTEM = _build_agent_system(autopilot_mode="paranoid", ctf_mode=False)


class ReActAgent:
    """
    Built-in ReAct loop using Ollama native tool calling.
    Works with only the Ollama client installed — `pip install ollama`.
    """

    MIN_STEPS_BEFORE_FINISH = 6  # persistence: must run at least N tools before finish allowed

    def __init__(self, domain: str, memory: HuntMemory,
                 dispatcher: ToolDispatcher,
                 max_steps: int = 20,
                 time_budget_hours: float = 2.0,
                 model: str | None = None,
                 tracer: AgentTracer | None = None,
                 autopilot_mode: str = "paranoid",
                 quick_mode: bool = False,
                 ctf_mode: bool = False,
                 deep_mode: bool = False):
        self.domain     = domain
        self.memory     = memory
        self.dispatcher = dispatcher
        self.max_steps  = max_steps
        self.time_start = time.time()
        self.time_budget_secs = time_budget_hours * 3600
        self.done       = False
        self.verdict    = ""
        self.autopilot_mode = _normalize_autopilot_mode(autopilot_mode)
        self.quick_mode = quick_mode
        self.ctf_mode   = ctf_mode
        self.deep_mode  = bool(deep_mode)
        self.min_steps_before_finish = _finish_floor_for_mode(self.autopilot_mode)
        if self.deep_mode:
            self.min_steps_before_finish = max(self.min_steps_before_finish, DEEP_FINISH_FLOOR)
        self.system_prompt = _build_agent_system(
            autopilot_mode=self.autopilot_mode,
            quick_mode=quick_mode,
            ctf_mode=self.ctf_mode,
            deep_mode=self.deep_mode,
        )

        # ctf-agent techniques
        self.loop_detector = LoopDetector()
        self.tracer        = tracer  # set externally after session_file is known
        self.bump_file     = ""      # set by run_agent_hunt — path to bump file

        # racing models (analysis + triage) — baron-llm races qwen3 on quick decisions
        self._race_models: list[str] = []

        if not _OLLAMA_OK:
            raise RuntimeError("Ollama Python package not installed: pip install ollama")

        self.client = _ollama_lib.Client(host=OLLAMA_HOST)
        self.model  = model or self._pick_tool_capable_model()
        if not self.model:
            raise RuntimeError("No Ollama model available. Pull one: ollama pull qwen2.5:32b")

        # Build race roster: primary model + baron-llm if available and different
        try:
            available = [m.model for m in self.client.list().models]
            if "baron-llm:latest" in available and "baron-llm:latest" != self.model:
                self._race_models = [self.model, "baron-llm:latest"]
            else:
                self._race_models = [self.model]
        except Exception:
            self._race_models = [self.model]

        print(f"{GREEN}[Agent] ReAct loop online — model: {BOLD}{self.model}{NC}", flush=True)
        race_note = f"  race_models={self._race_models}" if len(self._race_models) > 1 else ""
        print(f"{DIM}[Agent] max_steps={max_steps}  budget={time_budget_hours}h  "
              f"tool_calling=native{race_note}{NC}", flush=True)
        print(f"{DIM}[Agent] checkpoint_mode={self.autopilot_mode}  "
              f"finish_floor={self.min_steps_before_finish}  "
              f"quick_mode={'on' if self.quick_mode else 'off'}  "
              f"deep_mode={'on' if self.deep_mode else 'off'}{NC}", flush=True)
        if self.ctf_mode:
            print(f"{YELLOW}[Agent] CTF mode enabled — full active coverage stays available for this session.{NC}", flush=True)

    def _pick_tool_capable_model(self) -> str | None:
        """Prefer models with confirmed Ollama tool-calling support."""
        tool_capable_first = [
            "qwen3-coder-64k:latest",
            "qwen3-coder:30b",
            "qwen2.5:32b",
            "qwen2.5-coder:32b",
            "qwen3:30b-a3b",
            "qwen3:14b",
            "qwen3:8b",
            "mistral:7b-instruct-v0.3-q8_0",
        ]
        try:
            available = [m.model for m in self.client.list().models]
        except Exception:
            return None

        for pref in tool_capable_first:
            if pref in available:
                return pref
        # Fall back to first available
        return available[0] if available else None

    def _build_context(self) -> str:
        """Build the current state block that prefixes every LLM message."""
        elapsed_mins = round((time.time() - self.time_start) / 60, 1)
        budget_mins  = round(self.time_budget_secs / 60, 1)
        remaining    = round((self.time_budget_secs - (time.time() - self.time_start)) / 60, 1)

        completed = list(dict.fromkeys(self.memory.completed_steps))
        ctx_parts = [
            f"## Autonomous Hunt — {self.domain}",
            "Mode: Target-driven",
            f"Checkpoint mode: {self.autopilot_mode}",
            f"Quick mode defaults: {'on' if self.quick_mode else 'off'}",
            f"Deep mode: {'on' if getattr(self, 'deep_mode', False) else 'off'}",
            f"Step {self.memory.step_count + 1}/{self.max_steps}  "
            f"| Elapsed {elapsed_mins}m / {budget_mins}m budget  "
            f"| {remaining}m remaining",
            "",
            f"## Completed steps ({len(completed)})",
            ", ".join(completed) if completed else "(none yet)",
            "",
        ]
        bootstrap = _active_bootstrap_context(self.memory)
        if bootstrap:
            ctx_parts.extend([
                "## Bootstrap focus",
                bootstrap,
                "",
            ])
        ctx_parts.extend([
            "## Working memory (your notes)",
            self.memory.working_memory or "(empty — use update_working_memory to take notes)",
            "",
            "## Findings so far",
            self.memory.findings_summary(),
            "",
            "## Recent tool outputs (last 3)",
            self.memory.recent_observations(3),
        ])
        return "\n".join(ctx_parts)

    def _check_bump(self) -> str | None:
        """Check if operator has injected guidance via bump file."""
        if not self.bump_file or not os.path.isfile(self.bump_file):
            return None
        try:
            msg = Path(self.bump_file).read_text().strip()
            if msg:
                Path(self.bump_file).write_text("")  # consume
                return msg
        except Exception:
            pass
        return None

    def step(self) -> str | None:
        """Execute one ReAct step. Returns observation string or None if finished."""
        if self.done:
            return None

        time_left = self.time_budget_secs - (time.time() - self.time_start)
        if time_left < 60:
            print(f"{YELLOW}[Agent] Time budget exhausted — stopping.{NC}", flush=True)
            self.done = True
            return None

        # ── Check operator bump (guidance injection mid-run) ─────────────
        bump_msg = self._check_bump()
        if bump_msg:
            print(f"{YELLOW}[Agent] BUMP received: {bump_msg}{NC}", flush=True)
            if self.tracer:
                self.tracer.bump(bump_msg, self.memory.step_count)
            self.loop_detector.reset()  # fresh start after guidance
            self.memory.working_memory += f"\n\n[OPERATOR GUIDANCE] {bump_msg}"
            self.memory.save()

        bootstrap_hint = _bootstrap_tool_hint(self.memory)
        if bootstrap_hint:
            tool_name = bootstrap_hint["tool"]
            reason = bootstrap_hint.get("reason", "")
            note = f"[BOOTSTRAP] Prioritizing {tool_name} from runtime hint."
            if reason:
                note += f" Reason: {reason}"
            print(f"{CYAN}[Agent] {note}{NC}", flush=True)
            if self.tracer:
                self.tracer.tool_call(tool_name, {}, self.memory.step_count)
            t0 = time.time()
            obs = self.dispatcher.dispatch(tool_name, {})
            elapsed = round(time.time() - t0, 1)
            if self.tracer:
                self.tracer.tool_result(tool_name, obs, elapsed, self.memory.step_count)
            return f"{note}\n\n{obs}"

        context  = self._build_context()
        user_msg = f"{context}\n\nWhat is the best next action? Call the appropriate tool."

        print(f"\n{CYAN}{'─'*60}{NC}", flush=True)
        print(f"{BOLD}[Agent] Step {self.memory.step_count + 1} — calling LLM...{NC}", flush=True)

        try:
            response = self.client.chat(
                model=self.model,
                messages=[
                    {"role": "system",    "content": self.system_prompt},
                    {"role": "user",      "content": user_msg},
                ],
                tools=TOOLS,
                options={
                    "num_ctx":     16384,
                    "num_predict": 1024,
                    "temperature": 0.1,
                },
            )
        except Exception as e:
            print(f"{RED}[Agent] LLM call failed: {e}{NC}", flush=True)
            return f"LLM error: {e}"

        msg = response.get("message", {})

        # ── Native tool calling path ─────────────────────────────────────
        tool_calls = msg.get("tool_calls", [])
        if tool_calls:
            results = []
            for tc in tool_calls:
                fn   = tc.get("function", {})
                name = fn.get("name", "")
                args = fn.get("arguments", {})
                if isinstance(args, str):
                    try:
                        args = json.loads(args)
                    except Exception:
                        args = {}

                # ── Persistence advisory: block in paranoid/normal, audit-only in yolo ─
                progress_steps = _finish_floor_progress_count(self.memory.completed_steps)
                if name == "finish" and progress_steps < self.min_steps_before_finish:
                    remaining_needed = self.min_steps_before_finish - progress_steps
                    advisory = (
                        f"[SYSTEM] Too early to finish. You have only run "
                        f"{progress_steps} substantive tools. Run at least "
                        f"{remaining_needed} more high-impact tools before concluding."
                    )
                    if self.autopilot_mode == "yolo" and not getattr(self, "deep_mode", False):
                        # Yolo: emit advisory, let finish proceed to F3/F4 gates and dispatch.
                        print(f"{YELLOW}[Agent] Persistence advisory (yolo, allow-through): "
                              f"{progress_steps}/{self.min_steps_before_finish} substantive steps.{NC}",
                              flush=True)
                        results.append(advisory)
                    else:
                        print(f"{YELLOW}[Agent] Finish blocked — only {progress_steps} substantive steps done, "
                              f"need {remaining_needed} more. Continuing...{NC}", flush=True)
                        results.append(advisory)
                        continue

                # ── F3 invariant: coverage matrix gap gate ───────────────
                if name == "finish":
                    f3_passed, f3_msg = _f3_coverage_gate(self.domain)
                    if f3_msg:
                        block, emit = _finish_gate_block_or_warn(f3_msg, self.autopilot_mode)
                        if block:
                            print(f"{YELLOW}[Agent] F3 finish-gate blocked finish.{NC}", flush=True)
                            results.append(emit)
                            continue
                        # yolo: emit warning, allow finish through this gate
                        results.append(emit)

                # ── F4 invariant: intelligence layer consulted ───────────
                if name == "finish":
                    f4_passed, f4_msg = _f4_intelligence_gate(
                        self.domain, self.memory.completed_steps,
                    )
                    if f4_msg:
                        block, emit = _finish_gate_block_or_warn(f4_msg, self.autopilot_mode)
                        if block:
                            print(f"{YELLOW}[Agent] F4 finish-gate blocked finish.{NC}", flush=True)
                            results.append(emit)
                            continue
                        # yolo or audit-only F4 (no intelligence file): emit and pass
                        results.append(emit)

                # ── Loop detection ───────────────────────────────────────
                warn, must_break = self.loop_detector.record(name, args)
                if must_break:
                    print(f"{RED}[Agent] Loop detected on '{name}' — forcing direction change{NC}",
                          flush=True)
                    if self.tracer:
                        self.tracer.loop_break(name, self.memory.step_count)
                    self.loop_detector.reset()
                    results.append(
                        f"[SYSTEM] Loop detected: '{name}' called 5+ times with identical args. "
                        f"You MUST switch strategy. Try a completely different tool or angle. "
                        f"What have you NOT tried yet?"
                    )
                    continue
                if warn:
                    print(f"{YELLOW}[Agent] Loop warning: '{name}' repeated — consider switching{NC}",
                          flush=True)
                    if self.tracer:
                        self.tracer.loop_warn(name, LoopDetector.WARN_AT, self.memory.step_count)

                print(f"{MAGENTA}[Agent] Tool: {BOLD}{name}{NC}{MAGENTA}  args={json.dumps(args)}{NC}",
                      flush=True)
                if self.tracer:
                    self.tracer.tool_call(name, args, self.memory.step_count)

                t0  = time.time()
                obs = self.dispatcher.dispatch(name, args)
                elapsed = round(time.time() - t0, 1)

                if self.tracer:
                    self.tracer.tool_result(name, obs, elapsed, self.memory.step_count)

                results.append(obs)

                # ── P5-B3 semantic loop detection ─────────────────────
                # Track endpoint-bearing tool calls and check for repeats
                # in normalised response space.
                ep_arg = (args.get("endpoint")
                          or args.get("url")
                          or args.get("path")
                          or "")
                if ep_arg:
                    try:
                        self.loop_detector.record_with_response(str(ep_arg), str(obs or ""))
                        hint = self.loop_detector.rotation_hint()
                        if hint:
                            print(f"{YELLOW}[Agent] Semantic loop: {hint[:80]}…{NC}", flush=True)
                            results.append(hint)
                            # Reset semantic state so the same hint doesn't re-fire next turn
                            self.loop_detector._sem_history.clear()
                            self.loop_detector._last_loop_reason = ""
                    except Exception:
                        pass

                if name == "finish":
                    self.done    = True
                    self.verdict = args.get("verdict", "")
                    if self.tracer:
                        self.tracer.finish(self.verdict, self.memory.step_count,
                                           round((time.time() - self.time_start) / 60, 1))

            return "\n\n---\n\n".join(results)

        # ── Text-based fallback (model didn't use tool calling) ──────────
        content = msg.get("content", "")
        if content:
            print(f"{DIM}[Agent] LLM text response (no tool call):\n{content[:300]}{NC}",
                  flush=True)
            # Try to parse ReAct-format: Action: tool_name / Action Input: {...}
            parsed = self._parse_react_text(content)
            if parsed:
                name, args = parsed
                print(f"{MAGENTA}[Agent] Parsed from text: {name}{NC}", flush=True)
                obs = self.dispatcher.dispatch(name, args)
                if name == "finish":
                    self.done    = True
                    self.verdict = args.get("verdict", "")
                return obs

        # LLM produced nothing useful — nudge it
        self.memory.step_count += 1
        return "(LLM produced no tool call — will retry next step)"

    def _parse_react_text(self, text: str) -> tuple[str, dict] | None:
        """Parse old-style ReAct text format as fallback for non-tool-calling models."""
        import re
        # Match: Action: tool_name\nAction Input: {...}
        m = re.search(
            r"Action:\s*(\w+)\s*\nAction\s+Input:\s*(\{.*?\})",
            text, re.DOTALL
        )
        if m:
            name = m.group(1)
            try:
                args = json.loads(m.group(2))
            except Exception:
                args = {}
            if name in TOOL_NAMES:
                return name, args

        # Simpler: just "Action: tool_name" with no args
        m2 = re.search(r"Action:\s*(\w+)", text)
        if m2:
            name = m2.group(1)
            if name in TOOL_NAMES:
                return name, {}

        return None

    def run(self) -> dict:
        """Run the full ReAct loop until done or max_steps reached."""
        print(f"\n{BOLD}{CYAN}╔══════════════════════════════════════════╗{NC}")
        print(f"{BOLD}{CYAN}║  ReAct Hunt Agent — {self.domain:<20}  ║{NC}")
        print(f"{BOLD}{CYAN}╚══════════════════════════════════════════╝{NC}\n")

        for i in range(self.max_steps):
            if self.done:
                break

            obs = self.step()
            if obs:
                # Print first 500 chars of observation
                preview = obs[:500] + ("..." if len(obs) > 500 else "")
                print(f"{DIM}[Observation]\n{preview}{NC}\n", flush=True)

        if not self.done:
            print(f"{YELLOW}[Agent] Max steps ({self.max_steps}) reached.{NC}", flush=True)

        elapsed = round((time.time() - self.time_start) / 60, 1)
        print(f"\n{GREEN}[Agent] Hunt complete. ({elapsed} min){NC}")
        print(f"  Steps executed:  {self.memory.step_count}")
        print(f"  Completed tools: {', '.join(dict.fromkeys(self.memory.completed_steps))}")
        print(f"  Findings:        {len(self.memory.findings_log)}")
        print(f"  Checkpoint mode: {self.autopilot_mode}")
        if self.tracer:
            print(f"  Trace log:       {self.tracer.log_path}")
        if self.bump_file:
            print(f"  Bump file:       {self.bump_file}")
        if self.verdict:
            print(f"  Verdict:         {self.verdict}")

        return {
            "domain":           self.domain,
            "success":          True,
            "model":            self.model,
            "steps":            self.memory.step_count,
            "completed_steps":  list(dict.fromkeys(self.memory.completed_steps)),
            "reports":          len(self.memory.findings_log),
            "findings":         len(self.memory.findings_log),
            "findings_log":     self.memory.findings_log,
            "working_memory":   self.memory.working_memory,
            "verdict":          self.verdict,
            "session_file":     self.memory.session_file,
            "autopilot_mode":   self.autopilot_mode,
            **_phase_flags(self.memory.completed_steps),
        }


def _active_bootstrap_context(memory: HuntMemory) -> str:
    """Only inject bootstrap guidance on the first step to cap token cost."""
    if int(getattr(memory, "step_count", 0) or 0) > 0:
        return ""
    return str(getattr(memory, "bootstrap_context", "") or "").strip()


def _bootstrap_tool_hint(memory: HuntMemory) -> dict[str, str]:
    """Return a first-step runtime hint for a specific tool, if any."""
    if int(getattr(memory, "step_count", 0) or 0) > 0:
        return {}

    state = getattr(memory, "bootstrap_state", {}) or {}
    tool = str(state.get("next_tool_hint", "") or "").strip()
    if not tool:
        surface_state = state.get("surface") or {}
        workflow_leads = surface_state.get("workflow_leads", []) or []
        completed = set(getattr(memory, "completed_steps", []) or [])
        if workflow_leads and "read_surface_summary" in TOOL_NAMES and "read_surface_summary" not in completed:
            return {
                "tool": "read_surface_summary",
                "reason": "workflow leads are available; read the ranked surface summary before picking the first focused lane",
            }
    if not tool or tool not in TOOL_NAMES:
        return {}
    if tool in set(getattr(memory, "completed_steps", []) or []):
        return {}

    reason = ""
    for item in state.get("enrichment_hints", []) or []:
        if str(item.get("tool", "") or "").strip() == tool:
            reason = str(item.get("reason", "") or "").strip()
            break
    return {"tool": tool, "reason": reason}


def _load_agent_bootstrap_state(
    domain: str,
    *,
    repo_root: str = "",
    memory_dir: str = "",
) -> dict:
    """Load runtime autopilot bootstrap state once for agent startup."""
    try:
        from tools.autopilot_state import build_autopilot_state

        resolved_repo_root = repo_root or _h().BASE_DIR
        resolved_memory_dir = memory_dir or str(default_memory_dir(resolved_repo_root))
        return build_autopilot_state(
            resolved_repo_root,
            domain,
            memory_dir=resolved_memory_dir,
        )
    except Exception:
        return {}


def _build_agent_bootstrap_context(
    domain: str,
    *,
    repo_root: str = "",
    memory_dir: str = "",
    state: dict | None = None,
) -> str:
    """Build a concise runtime bootstrap block from autopilot/resume state."""
    state = state if state is not None else _load_agent_bootstrap_state(
        domain,
        repo_root=repo_root,
        memory_dir=memory_dir,
    )
    if not state:
        return ""

    lines = []
    next_action = str(state.get("next_action", "") or "").strip()
    if next_action:
        lines.append(f"Next action hint: {next_action}")

    next_tool_hint = str(state.get("next_tool_hint", "") or "").strip()
    if next_tool_hint:
        lines.append(f"Next tool hint: {next_tool_hint}")

    enrichment_hints = state.get("enrichment_hints") or []
    if enrichment_hints:
        lines.append("Enrichment hints:")
        for item in enrichment_hints[:3]:
            tool = str(item.get("tool", "") or "").strip()
            reason = str(item.get("reason", "") or "").strip()
            if tool and reason:
                lines.append(f"- {tool}: {reason}")
            elif tool:
                lines.append(f"- {tool}")

    guard_hint = str(state.get("guard_hint", "") or "").strip()
    if guard_hint:
        lines.append(f"Guard hint: {guard_hint}")

    guard_status = state.get("guard_status") or {}
    tripped_hosts = [item for item in guard_status.get("tripped_hosts", []) if item.get("host")]
    if tripped_hosts:
        cooling = ", ".join(
            f"{item['host']} ({float(item.get('remaining_seconds', 0.0) or 0.0):.1f}s)"
            for item in tripped_hosts[:3]
        )
        lines.append(f"Cooling hosts: {cooling}")

    recent_guard_advisories = state.get("recent_guard_advisories") or state.get("recent_guard_blocks", []) or []
    if recent_guard_advisories:
        lines.append("Recent guard advisories:")
        for item in recent_guard_advisories[:3]:
            details = str(item.get("notes", "") or item.get("endpoint", "") or "").strip()
            if details:
                lines.append(f"- {details}")

    repo_source_summary = state.get("repo_source_summary") or {}
    repo_source_hint = str(repo_source_summary.get("summary_hint", "") or "").strip()
    if repo_source_hint:
        lines.append(f"Repo source summary: {repo_source_hint}")

    surface_state = state.get("surface") or {}
    workflow_leads = surface_state.get("workflow_leads", []) or []
    if workflow_leads:
        lines.append("Top workflow leads:")
        for raw_item in workflow_leads[:3]:
            item = {}
            if isinstance(raw_item, dict):
                item = raw_item
            elif isinstance(raw_item, str):
                try:
                    item = json.loads(raw_item)
                except json.JSONDecodeError:
                    item = {}
            if not item:
                continue
            priority = str(item.get("priority", "medium") or "medium").strip()
            category = str(item.get("category", "other") or "other").strip()
            title = str(item.get("title", "") or "").strip()
            next_action = str(item.get("next_action", "") or "").strip()
            rationale = str(item.get("rationale", "") or "").strip()
            if title:
                lines.append(f"- [{priority}] {category}: {title}")
            if next_action:
                lines.append(f"  Next: {next_action}")
            if rationale:
                lines.append(f"  Why: {rationale[:160]}")

    pivot_hint = str(state.get("pivot_hint", "") or "").strip()
    if pivot_hint:
        lines.append(f"Pivot hint: {pivot_hint}")

    resume_targets = [item for item in state.get("resume_targets", []) if item]
    if resume_targets:
        lines.append(f"Resume targets: {', '.join(resume_targets[:3])}")

    summary = state.get("resume_summary") or {}
    latest_session = summary.get("latest_session_summary") or {}
    vuln_classes = [item for item in latest_session.get("vuln_classes", []) if item]
    if vuln_classes:
        lines.append(f"Last vuln classes: {', '.join(vuln_classes[:4])}")
    if latest_session:
        lines.append(f"Last session findings: {int(latest_session.get('findings_count', 0) or 0)}")

    recommended_targets = state.get("recommended_targets", []) or []
    if recommended_targets:
        top = recommended_targets[0]
        top_url = str(top.get("url", "") or "").strip()
        top_suggested = str(top.get("suggested", "") or "").strip()
        if top.get("tripped"):
            cooldown = float(top.get("remaining_seconds", 0.0) or 0.0)
            if top_url:
                lines.append(f"Top ranked target cooling down: {top_url} ({cooldown:.1f}s)")
        elif top_url and top_suggested:
            lines.append(f"Top ready target: {top_url} ({top_suggested})")
        elif top_url:
            lines.append(f"Top ready target: {top_url}")

    if not lines:
        return ""

    return "## Resume / autopilot bootstrap\n" + "\n".join(f"- {line}" for line in lines)


def _session_summary_vuln_classes_from_agent(memory: HuntMemory) -> list[str]:
    """Derive minimal vuln-class / scan-mode labels from agent activity."""
    alias_map = {
        "run_recon": "recon",
        "run_vuln_scan": "vuln_scan",
        "run_sqlmap_on_file": "sqlmap",
        "run_sqlmap_targeted": "sqlmap",
        "run_cve_hunt": "cve",
        "run_zero_day_fuzzer": "zero_day",
    }
    ignored_steps = {
        "check_tools",
        "generate_reports",
        "finish",
        "read_autopilot_state",
        "read_findings_summary",
        "read_guard_status",
        "read_recon_summary",
        "read_repo_source_summary",
        "read_resume_summary",
        "read_surface_summary",
        "remember_finding",
        "run_intel",
        "update_working_memory",
    }

    classes: list[str] = []

    def _collect(label: str) -> None:
        if not label or label in ignored_steps:
            return
        if label.startswith("read_"):
            return
        if label in alias_map:
            classes.append(alias_map[label])
            return
        if label.startswith("run_"):
            classes.append(label.removeprefix("run_"))

    for step in dict.fromkeys(memory.completed_steps):
        _collect(str(step))

    if not classes:
        for finding in memory.findings_log:
            _collect(str(finding.get("tool", "")))

    return list(dict.fromkeys(classes))


def _session_summary_profile_endpoints(profile: dict[str, Any]) -> list[str]:
    """Resolve tested endpoints from target profile with findings fallback."""
    endpoints = []
    if isinstance(profile, dict):
        endpoints.extend(str(item).strip() for item in profile.get("tested_endpoints", []) if str(item).strip())
        if not endpoints:
            for finding in profile.get("findings", []):
                endpoint = str(finding.get("endpoint", "")).strip()
                if endpoint:
                    endpoints.append(endpoint)
    return list(dict.fromkeys(endpoints))


def _session_summary_vuln_classes_from_profile(profile: dict[str, Any]) -> list[str]:
    """Resolve remembered vuln classes from persisted target profile findings."""
    classes = []
    if isinstance(profile, dict):
        for finding in profile.get("findings", []):
            vuln_class = str(finding.get("vuln_class", "")).strip().lower()
            if vuln_class:
                classes.append(vuln_class)
    return list(dict.fromkeys(classes))


def _auto_log_agent_session_summary(domain: str, memory: HuntMemory, session_id: str | None) -> None:
    """Auto-log a non-fatal session summary for agent-driven runs."""
    try:
        memory_dir = default_memory_dir(_h().BASE_DIR)
        profile = load_target_profile(memory_dir, domain) or {}
        endpoints_tested = _session_summary_profile_endpoints(profile)
        remembered_findings = profile.get("findings", []) if isinstance(profile, dict) else []
        vuln_classes = list(
            dict.fromkeys(
                _session_summary_vuln_classes_from_agent(memory)
                + _session_summary_vuln_classes_from_profile(profile)
            )
        )
        journal = _open_hunt_journal(memory_dir)
        journal.log_session_summary(
            target=domain,
            action="hunt",
            endpoints_tested=endpoints_tested,
            vuln_classes_tried=vuln_classes,
            findings_count=max(len(memory.findings_log), len(remembered_findings)),
            session_id=session_id,
        )
    except Exception as exc:
        print(f"{YELLOW}[Agent] Auto session memory failed (non-fatal): {exc}{NC}", flush=True)


# ──────────────────────────────────────────────────────────────────────────────
#  Public entry point  (called by tools/hunt.py --agent)
# ──────────────────────────────────────────────────────────────────────────────

def run_agent_hunt(
    domain: str,
    *,
    scope_lock: bool = False,
    max_urls: int = 100,
    quick: bool = False,
    max_steps: int = 20,
    time_budget_hours: float = 2.0,
    cookies: str = "",
    model: str | None = None,
    resume_session_id: str | None = None,
    autopilot_mode: str = "paranoid",
    ctf_mode: bool | None = None,
    vision_enabled: bool = False,
    max_screenshots: int = 5,
    parallel_enabled: bool = False,
    max_parallel: int = 3,
    worker_timeout_secs: int = 300,
    parallel_hypotheses: bool = False,
    self_review_enabled: bool = False,
    calibrate_patterns: bool = False,
    deep_mode: bool = False,
) -> dict:
    """
    Main entry point for agent-driven autonomous hunting.
    Called by tools/hunt.py when --agent flag is passed.
    """
    h = _h()
    autopilot_mode = _normalize_autopilot_mode(autopilot_mode)
    ctf_mode = _resolve_ctf_mode(ctf_mode)
    if deep_mode:
        if max_steps <= DEFAULT_AGENT_MAX_STEPS:
            max_steps = DEEP_AGENT_MAX_STEPS
        if time_budget_hours <= DEFAULT_AGENT_TIME_HOURS:
            time_budget_hours = DEEP_AGENT_TIME_HOURS
    classify_target = getattr(h, "classify_target", None)
    canonical_target = classify_target(domain)["target"] if callable(classify_target) else domain

    # ── Resolve session ───────────────────────────────────────────────────
    session_request = resume_session_id or "new"
    session_mode = "resumed" if resume_session_id else "fresh"
    session_id, recon_dir = h._activate_recon_session(
        canonical_target,
        requested_session_id=session_request,
        create=True,
    )
    session_dir  = os.path.dirname(recon_dir)
    session_file = os.path.join(session_dir, "agent_session.json")

    print(f"{GREEN}[Agent] Session: {session_id} ({session_mode}) → {recon_dir}{NC}", flush=True)
    print(f"{DIM}[Agent] Checkpoint mode: {autopilot_mode}{NC}", flush=True)
    print(
        f"{DIM}[Agent] Authorization posture: supplied target set is active target context; "
        "no authorization prompts before routine recon/scanning/hunting."
        f"{NC}",
        flush=True,
    )
    if quick:
        print(f"{DIM}[Agent] Quick mode enabled — recon/scanner default to lower-cost paths unless expanded explicitly.{NC}", flush=True)
    if deep_mode:
        print(f"{DIM}[Agent] Deep mode enabled — require deeper high-impact lane rotation before finish.{NC}", flush=True)
    if ctf_mode:
        print(f"{YELLOW}[Agent] CTF mode enabled — treating the provided target as lab/practice context with full coverage.{NC}", flush=True)

    # ── Init memory + dispatcher ──────────────────────────────────────────
    memory     = HuntMemory(session_file)
    base_dir = getattr(h, "BASE_DIR", os.getcwd())
    memory.bootstrap_state = _load_agent_bootstrap_state(
        canonical_target,
        repo_root=base_dir,
        memory_dir=str(default_memory_dir(base_dir)),
    )
    memory.bootstrap_context = _build_agent_bootstrap_context(
        canonical_target,
        repo_root=base_dir,
        memory_dir=str(default_memory_dir(base_dir)),
        state=memory.bootstrap_state,
    )
    dispatcher = ToolDispatcher(
        canonical_target, memory,
        scope_lock=scope_lock,
        max_urls=max_urls,
        default_cookies=cookies,
        quick_mode=quick,
        vision_enabled=vision_enabled,
        max_screenshots=max_screenshots,
        model_id=str(model or ""),
        parallel_enabled=parallel_enabled,
        max_parallel=max_parallel,
        worker_timeout_secs=worker_timeout_secs,
        parallel_hypotheses=parallel_hypotheses,
        self_review_enabled=self_review_enabled,
        calibrate_patterns=calibrate_patterns,
        autopilot_mode=autopilot_mode,
        deep_mode=deep_mode,
    )

    # ── Run built-in ReAct loop ───────────────────────────────────────────
    log_path  = os.path.join(session_dir, "agent_trace.jsonl")
    bump_path = os.path.join(session_dir, "agent_bump.txt")
    tracer    = AgentTracer(log_path)

    print(f"{GREEN}[Agent] Trace: tail -f {log_path}{NC}", flush=True)
    print(f"{GREEN}[Agent] Bump:  echo 'guidance here' > {bump_path}{NC}", flush=True)

    agent = ReActAgent(
        domain      = canonical_target,
        memory      = memory,
        dispatcher  = dispatcher,
        max_steps   = max_steps,
        time_budget_hours = time_budget_hours,
        model       = model,
        tracer      = tracer,
        autopilot_mode = autopilot_mode,
        quick_mode  = quick,
        ctf_mode    = ctf_mode,
        deep_mode   = deep_mode,
    )
    agent.bump_file = bump_path

    result = agent.run()
    tracer.close()
    _auto_log_agent_session_summary(canonical_target, memory, session_id)
    result["backend"]    = "builtin-react"
    result["trace_path"] = log_path
    result["bump_path"]  = bump_path
    result["autopilot_mode"] = autopilot_mode
    result["quick_mode"] = quick
    result["deep_mode"] = deep_mode
    result["ctf_mode"] = ctf_mode
    result["domain"] = canonical_target
    result["session_id"] = session_id
    result["session_mode"] = session_mode
    return result


# ──────────────────────────────────────────────────────────────────────────────
#  CLI
# ──────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="ReAct hunting agent — target-driven autonomous testing with Ollama tool calling",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 agent.py --target example.com                 Fresh local session
  python3 agent.py --target 10.0.0.0/24 --quick --normal
  python3 agent.py --target example.com --deep --normal
  python3 agent.py --target example.com --time 4 --max-steps 30
  python3 agent.py --target example.com --auth-file auth.json --bearer eyJ...
  python3 agent.py --target example.com --scope-lock --max-urls 50 --yolo
  python3 agent.py --target targets.txt --resume latest
  python3 agent.py --target example.com --resume SESSION_ID
  python3 agent.py --list-models
"""
    )
    parser.add_argument("--target",      required=False, help="Target to hunt (domain, IP, CIDR, or primary-domain batch file)")
    parser.add_argument("--time",        type=float, default=2.0, help="Time budget in hours (default 2)")
    parser.add_argument("--max-steps",   type=int,   default=20,  help="Max ReAct iterations (default 20)")
    parser.add_argument("--cookie",      type=str,   default="",  help="Session cookie for auth-aware requests and POST discovery")
    parser.add_argument("--scope-lock",  action="store_true",     help="Stick to exact target only")
    parser.add_argument("--max-urls",    type=int,   default=100, help="Max URLs in recon (default 100)")
    parser.add_argument("--quick",       action="store_true",     help="Lower-cost recon/scanner defaults where supported")
    parser.add_argument("--deep",        action="store_true",     help="Deep high-impact hunting mode; increases persistence without relaxing live-action boundaries")
    parser.add_argument("--model",       type=str,   default=None, help="Ollama model override")
    parser.add_argument(
        "--resume",
        type=str,
        default=None,
        help="Resume agent session ID; use 'latest' to continue the most recent session",
    )
    parser.add_argument("--list-models", action="store_true",     help="List available Ollama models")
    parser.add_argument("--bump",        type=str,   default=None,
                        help="Inject operator guidance mid-run: --bump SESSION_DIR 'message'",
                        nargs=2, metavar=("SESSION_DIR", "MESSAGE"))
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument("--paranoid", action="store_true", help="Frequent checkpoints (default)")
    mode_group.add_argument("--normal", action="store_true", help="Batch related findings before checkpointing")
    mode_group.add_argument("--yolo", action="store_true", help="Keep moving with minimal checkpoints")
    parser.add_argument(
        "--parallel",
        action="store_true",
        help="(B6) Enable parallel sibling-probe workers when a primary finding is confirmed",
    )
    parser.add_argument(
        "--max-parallel",
        type=int,
        default=3,
        help="Cap on concurrent workers (paranoid forces 1; yolo allows up to 8). Default 3.",
    )
    parser.add_argument(
        "--worker-timeout-secs",
        type=int,
        default=300,
        help="Per-worker wall-clock timeout in seconds (default 300).",
    )
    parser.add_argument(
        "--calibrate-patterns",
        action="store_true",
        help="(B12d) Pass calibrated=True to PatternDB.match() in the agent path",
    )
    parser.add_argument(
        "--self-review",
        action="store_true",
        help="(B12c) Run adversarial red-team review before /validate→/report",
    )
    parser.add_argument(
        "--parallel-hypotheses",
        action="store_true",
        help="(B12a) Fan out viable hypothesis candidates to workers in parallel",
    )
    parser.add_argument(
        "--vision",
        action="store_true",
        help="(B12b) Capture playwright screenshots and expose read_browser_screenshot",
    )
    parser.add_argument(
        "--max-screenshots",
        type=int,
        default=5,
        help="(B12b) Cap screenshots per page navigation (default 5)",
    )
    add_cli_args(parser, include_cookie=False)
    args = parser.parse_args()
    auth_session = _apply_hunt_auth_session(session_from_args(args))
    autopilot_mode = _resolve_cli_autopilot_mode(args)
    ctf_mode = _resolve_ctf_mode()

    if args.list_models:
        if not _OLLAMA_OK:
            print("Ollama not installed: pip install ollama")
            return
        client = _ollama_lib.Client(host=OLLAMA_HOST)
        try:
            models = [m.model for m in client.list().models]
            print(f"\nAvailable Ollama models ({len(models)}):")
            for m in models:
                marker = " ← recommended" if any(m.startswith(p.split(":")[0]) for p in
                         ["qwen3-coder", "qwen2.5", "qwen3"]) else ""
                print(f"  {m}{marker}")
        except Exception as e:
            print(f"Cannot reach Ollama: {e}")
        print(f"Ollama available:    {_OLLAMA_OK}")
        return

    if args.bump:
        session_dir, message = args.bump
        bump_file = os.path.join(session_dir, "agent_bump.txt")
        Path(bump_file).write_text(message.strip())
        print(f"[Bump] Wrote guidance to {bump_file}")
        print(f"[Bump] Agent will pick it up on next step.")
        return

    if not args.target:
        parser.print_help()
        sys.exit(1)

    if not auth_session.is_empty():
        print(f"{DIM}[Agent] {auth_session.describe()}{NC}", flush=True)

    try:
        result = run_agent_hunt(
            args.target,
            scope_lock=args.scope_lock,
            max_urls=args.max_urls,
            quick=args.quick,
            max_steps=args.max_steps,
            time_budget_hours=args.time,
            cookies=args.cookie,
            model=args.model,
            resume_session_id=args.resume,
            autopilot_mode=autopilot_mode,
            ctf_mode=ctf_mode,
            deep_mode=bool(getattr(args, "deep", False)),
            vision_enabled=bool(getattr(args, "vision", False)),
            max_screenshots=int(getattr(args, "max_screenshots", 5)),
            parallel_enabled=bool(getattr(args, "parallel", False)),
            max_parallel=int(getattr(args, "max_parallel", 3)),
            worker_timeout_secs=int(getattr(args, "worker_timeout_secs", 300)),
            parallel_hypotheses=bool(getattr(args, "parallel_hypotheses", False)),
            self_review_enabled=bool(getattr(args, "self_review", False)),
            calibrate_patterns=bool(getattr(args, "calibrate_patterns", False)),
        )
    except RuntimeError as exc:
        print(f"{RED}[Agent] {exc}{NC}")
        sys.exit(1)

    print(f"\n{BOLD}{'═'*60}{NC}")
    print(f"{BOLD}Hunt Result: {result['domain']}{NC}")
    print(f"  Backend:   {result.get('backend', 'unknown')}")
    print(f"  Model:     {result.get('model', 'unknown')}")
    mode_label = result.get("autopilot_mode", autopilot_mode)
    if result.get("ctf_mode"):
        mode_label = f"{mode_label} + ctf"
    print(f"  Mode:      {mode_label}")
    print(f"  Quick:     {'on' if result.get('quick_mode') else 'off'}")
    print(f"  Steps:     {result.get('steps', 0)}")
    print(f"  Findings:  {result.get('findings', 0)}")
    print(f"  Session:   {result.get('session_id', '')} ({result.get('session_mode', 'unknown')})")
    print(f"  File:      {result.get('session_file', '')}")
    if result.get("trace_path"):
        print(f"  Trace:     {result['trace_path']}")
    if result.get("bump_path"):
        print(f"  Bump:      echo 'guidance' > {result['bump_path']}")
    if result.get("verdict"):
        print(f"\nVerdict:\n{result['verdict']}")
    print(f"{BOLD}{'═'*60}{NC}\n")


if __name__ == "__main__":
    main()
