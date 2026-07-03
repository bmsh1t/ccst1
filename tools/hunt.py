#!/usr/bin/env python3
"""
Bug Bounty Hunt Orchestrator
Main script that chains target selection, recon, scanning, and reporting.

Usage:
    python3 hunt.py                         # Full pipeline: select targets + hunt
    python3 hunt.py --target <target>       # Hunt a specific domain/IP/CIDR or primary-domain batch
    python3 hunt.py --quick --target <target>  # Quick scan mode
    python3 hunt.py --target <target> --agent  # Autonomous agent mode
    python3 hunt.py --target <target> --agent --deep  # Deep legacy local-agent mode
    python3 hunt.py --recon-only --target <target>  # Only run recon
    python3 hunt.py --scan-only --target <target>   # Only run vuln scanner (requires prior recon)
    python3 hunt.py --scan-only --target <target> --scanner-full --scanner-skip module1,module2
    python3 hunt.py --status                # Show current progress
    python3 hunt.py --setup-wordlists       # Download common wordlists
    python3 hunt.py --cve-hunt --target <target>   # Run CVE hunter
    python3 hunt.py --zero-day --target <target>   # Run zero-day fuzzer
"""

import argparse
import base64
import json
import os
import re
import ipaddress
import shlex
import signal
import ssl
import subprocess
import sys
import time
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urljoin, urlparse
from urllib.request import Request, urlopen

TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(TOOLS_DIR)
TARGETS_DIR = os.path.join(BASE_DIR, "targets")
RECON_DIR = os.path.join(BASE_DIR, "recon")
FINDINGS_DIR = os.path.join(BASE_DIR, "findings")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
WORDLIST_DIR = os.path.join(BASE_DIR, "wordlists")

if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)
if TOOLS_DIR not in sys.path:
    sys.path.insert(0, TOOLS_DIR)

from memory.schemas import make_journal_entry
from memory.target_profile import default_memory_dir, load_target_profile, make_target_profile, save_target_profile
from legacy_bridge import generate_legacy_reports, open_hunt_journal, run_legacy_cve_hunt
from tools.auth_session import AuthSession, add_cli_args, session_from_args
from tools.public_exposure_signals import classify_public_response
from tools.runtime_config import is_ctf_mode_enabled, load_runtime_config
from tools.target_paths import classify_target as classify_target_input, target_storage_key

# Colors
GREEN = "\033[0;32m"
RED = "\033[0;31m"
YELLOW = "\033[1;33m"
CYAN = "\033[0;36m"
BOLD = "\033[1m"
NC = "\033[0m"

HUNT_MEMORY_DIR = default_memory_dir(BASE_DIR)
URL_SSL_CTX = ssl._create_unverified_context()
_SEEN_GUARD_BLOCKS: set[tuple[str, str, str, str, str]] = set()
_AUTH_SESSION: AuthSession | None = None


def resolve_autopilot_mode(args) -> str:
    """Resolve CLI checkpoint mode with paranoid as the safe default."""
    if getattr(args, "yolo", False):
        return "yolo"
    if getattr(args, "normal", False):
        return "normal"
    return "paranoid"


def load_config():
    """Load optional repo-local config.json for runtime feature flags."""
    return load_runtime_config(BASE_DIR)


def is_ctf_mode(config=None):
    """Return whether repo-local CTF mode is enabled."""
    if config is not None:
        return bool((config or {}).get("ctf_mode", False))
    return is_ctf_mode_enabled(BASE_DIR)


def log(level, msg):
    colors = {"ok": GREEN, "err": RED, "warn": YELLOW, "info": CYAN}
    symbols = {"ok": "+", "err": "-", "warn": "!", "info": "*"}
    print(f"{colors.get(level, '')}{BOLD}[{symbols.get(level, '*')}]{NC} {msg}")


def log_authorization_posture(target: str) -> None:
    """Emit the project-local authorization posture before active recon/hunt."""
    log(
        "info",
        (
            "Authorization posture: treating the supplied target set as this run's "
            f"active target context ({target}); no authorization prompts. "
            "Pause only for ambiguous targets, credentials that cannot be derived through the controlled Credential Lane, "
            "report submission, or explicit destructive side effects / irreversible mutations / high-pressure actions. "
            "HTTP method alone is advisory, not a stop condition."
        ),
    )


def _active_auth_session() -> AuthSession:
    """Return the current auth session, falling back to env-backed auth."""
    if _AUTH_SESSION is not None:
        return _AUTH_SESSION
    return AuthSession.from_env(os.environ)


def _merge_auth_headers(headers: dict[str, str] | None = None) -> dict[str, str]:
    """Merge auth-session headers with per-request headers."""
    merged = _active_auth_session().headers_dict()
    if headers:
        merged.update(headers)
    return merged


def _log_legacy_path_hint(kind: str, preferred_command: str) -> None:
    """Emit a low-noise hint when an entrypoint is legacy-only."""
    log(
        "info",
        f"{kind} is using a legacy compatibility path; prefer {preferred_command} for the primary workflow.",
    )


def run_cmd(cmd, cwd=None, timeout=600):
    """Run a shell command and return (success, output)."""
    from runtime_exec import run_shell_command

    return run_shell_command(cmd, cwd=cwd, timeout=timeout)


def _kill_process_group(proc):
    """Best-effort termination for a spawned subprocess session."""
    try:
        pgid = os.getpgid(proc.pid)
    except Exception:
        return

    try:
        os.killpg(pgid, signal.SIGTERM)
    except Exception:
        return

    try:
        proc.wait(timeout=3)
        return
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        return

    try:
        os.killpg(pgid, signal.SIGKILL)
    except Exception:
        return

    try:
        proc.wait(timeout=3)
    except Exception:
        return


def classify_target(target):
    """Classify a hunt target as domain, IP, CIDR, or a readable target list."""
    return classify_target_input(target)


def _target_storage_key(target):
    """Return the on-disk storage key for a target."""
    return target_storage_key(target)


def _resolve_recon_dir(domain):
    """Return the canonical recon directory for a target."""
    return os.path.join(RECON_DIR, _target_storage_key(domain))


def _resolve_findings_dir(domain, create=False):
    """Return the canonical findings directory for a target."""
    path = os.path.join(FINDINGS_DIR, _target_storage_key(domain))
    if create:
        os.makedirs(path, exist_ok=True)
    return path


def _resolve_reports_dir(domain, create=False):
    """Return the canonical reports directory for a target."""
    path = os.path.join(REPORTS_DIR, _target_storage_key(domain))
    if create:
        os.makedirs(path, exist_ok=True)
    return path


def _first_existing_path(paths):
    """Return the first existing file path from a sequence."""
    for path in paths:
        if path and os.path.exists(path):
            return path
    return None


def _recon_file_candidates(domain, *relative_paths):
    """Build recon file candidates for new and legacy output layouts."""
    recon_dir = _resolve_recon_dir(domain)
    return [os.path.join(recon_dir, rel) for rel in relative_paths]


def _read_text_lines(path, limit=None):
    """Read non-empty text lines from a file."""
    if not path or not os.path.isfile(path):
        return []

    items = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            value = line.strip()
            if not value:
                continue
            items.append(value)
            if limit and len(items) >= limit:
                break
    return items


def _count_target_list_entries(path):
    """Count usable entries in a primary-domain batch list."""
    count = 0
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            value = line.strip()
            if value and not value.startswith("#"):
                count += 1
    return count


def _target_list_entries(path, limit=None):
    """Return usable primary-domain entries from a target list file."""
    items = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            value = line.strip().strip("\ufeff")
            if not value or value.startswith("#"):
                continue
            items.append(value)
            if limit and len(items) >= limit:
                break
    return _dedupe_keep_order(items)


def _write_text_lines(path, lines):
    """Write deduped lines to a UTF-8 text file."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    unique_lines = _dedupe_keep_order([line.strip() for line in lines if line and line.strip()])
    with open(path, "w", encoding="utf-8") as f:
        if unique_lines:
            f.write("\n".join(unique_lines) + "\n")
    return unique_lines


def _append_text(path, text):
    """Append text to a file, creating parent directories as needed."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(text)


def _extract_generated_report_count(output):
    """Parse the legacy report-generator stdout for the current generation count."""
    match = re.search(r"Generated\s+(\d+)\s+reports", str(output or ""), re.IGNORECASE)
    if not match:
        return None
    try:
        return int(match.group(1))
    except (TypeError, ValueError):
        return None


def _command_exists(tool):
    """Check whether a tool is available in PATH."""
    success, _ = run_cmd(f"command -v {shlex.quote(tool)}")
    return success


def _guard_scope_patterns_for_target(target):
    """Build guard scope patterns for a single target value.

    Domains keep the historical exact-host + wildcard-subdomain behavior.
    IPs/CIDRs stay exact to avoid inventing invalid wildcard patterns.
    URL / host:port list entries are normalized down to a hostname first.
    """
    normalized = (target or "").strip().lower()
    if not normalized or normalized.startswith("#"):
        return []

    if normalized.startswith("*."):
        return [normalized]
    if normalized == "localhost":
        return [normalized]

    if "://" in normalized:
        parsed = urlparse(normalized)
        hostname = (parsed.hostname or "").strip().lower()
        if not hostname:
            return []
        normalized = hostname

    try:
        network = ipaddress.ip_network(normalized, strict=False)
    except ValueError:
        network = None
    else:
        if "/" in normalized:
            return [str(network)]

    try:
        address = ipaddress.ip_address(normalized)
    except ValueError:
        address = None
    else:
        return [str(address)]

    parsed = urlparse(f"https://{normalized}")
    hostname = (parsed.hostname or "").strip().lower()
    if hostname:
        normalized = hostname

    if not normalized:
        return []

    return _dedupe_keep_order([normalized, f"*.{normalized}"])


def _guard_scope_domains(target):
    """Build conservative target-set patterns for hunt-side guarded requests."""
    target_info = classify_target(target)
    normalized_target = target_info["target"]
    if not normalized_target:
        return []

    if target_info["kind"] == "list":
        patterns = []
        for entry in _read_text_lines(normalized_target):
            patterns.extend(_guard_scope_patterns_for_target(entry))
        return _dedupe_keep_order(patterns)

    return _guard_scope_patterns_for_target(normalized_target)


def _fetch_url_raw(url, *, headers=None, timeout=10, method="GET"):
    """Fetch a URL and return (status, body, headers dict)."""
    request = Request(url, headers=_merge_auth_headers(headers), method=method)
    try:
        with urlopen(request, timeout=timeout, context=URL_SSL_CTX) as response:
            body = response.read().decode("utf-8", errors="replace")
            return response.getcode(), body, dict(response.headers.items())
    except HTTPError as exc:
        try:
            body = exc.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return exc.code, body, dict(exc.headers.items()) if exc.headers else {}
    except (URLError, ValueError):
        return None, "", {}


def _fetch_url(
    url,
    *,
    headers=None,
    timeout=10,
    method="GET",
    target="",
    use_guard=False,
    is_recon=False,
    vuln_class="",
):
    """Fetch a URL and optionally run request-guard preflight/record around it."""
    if not use_guard or not target:
        return _fetch_url_raw(url, headers=headers, timeout=timeout, method=method)

    try:
        from request_guard import preflight_request, record_request
    except Exception:
        return _fetch_url_raw(url, headers=headers, timeout=timeout, method=method)

    scope_domains = _guard_scope_domains(target)
    session_id = f"hunt-{target}-{os.getpid()}"

    try:
        preflight = preflight_request(
            memory_dir=HUNT_MEMORY_DIR,
            target=target,
            url=url,
            method=method,
            session_id=session_id,
            vuln_class=vuln_class or None,
            mode="normal",
            is_recon=is_recon,
            scope_domains=scope_domains or None,
        )
    except Exception as exc:
        log("warn", f"request_guard preflight failed for {url}: {exc} — continuing without guard")
        return _fetch_url_raw(url, headers=headers, timeout=timeout, method=method)

    if not preflight.get("allowed"):
        reason = preflight.get("reason") or preflight.get("action") or "advisory"
        _log_guard_advisory(
            target=target,
            url=url,
            method=method,
            reason=reason,
            action=str(preflight.get("action") or "advisory"),
            host=str(preflight.get("host") or ""),
            is_recon=is_recon,
        )
        log("warn", f"request_guard advisory stopped raw fetch for {method.upper()} {url}: {reason}")
        return None, "", {}

    status, body, response_headers = _fetch_url_raw(url, headers=headers, timeout=timeout, method=method)
    record_error = None if status is not None else "request failed"
    try:
        record_request(
            memory_dir=HUNT_MEMORY_DIR,
            target=target,
            url=url,
            method=method,
            response_status=status,
            error=record_error,
            session_id=session_id,
            scope_domains=scope_domains or None,
        )
    except Exception as exc:
        log("warn", f"request_guard record failed for {url}: {exc}")

    return status, body, response_headers


def _log_guard_advisory(
    *,
    target: str,
    url: str,
    method: str,
    reason: str,
    action: str,
    host: str = "",
    is_recon: bool = False,
) -> None:
    """Persist a lightweight journal note for notable request-guard advisories.

    Dedupe identical host/action/reason events within the current process so
    tight loops do not flood hunt-memory.
    """
    normalized_target = str(target or "").strip()
    normalized_url = str(url or "").strip()
    normalized_method = str(method or "GET").upper()
    normalized_reason = str(reason or action or "advisory").strip()
    normalized_action = str(action or "advisory").strip()
    normalized_host = str(host or "").strip()
    if not normalized_target or not normalized_url:
        return

    signature = (
        normalized_target,
        normalized_host or normalized_url,
        normalized_action,
        normalized_reason,
        "recon" if is_recon else "hunt",
    )
    if signature in _SEEN_GUARD_BLOCKS:
        return
    _SEEN_GUARD_BLOCKS.add(signature)

    try:
        journal = open_hunt_journal(HUNT_MEMORY_DIR)
        entry = make_journal_entry(
            target=normalized_target,
            action="recon" if is_recon else "hunt",
            vuln_class="guard_advisory",
            endpoint=normalized_url,
            result="informational",
            severity="none",
            technique="request_guard",
            notes=(
                f"request_guard advisory for {normalized_method} {normalized_url}. "
                f"Host: {normalized_host or 'unknown'}. "
                f"Action: {normalized_action}. "
                f"Reason: {normalized_reason}."
            ),
            tags=["guard_advisory", "auto_logged", normalized_action],
        )
        journal.append(entry)
    except Exception as exc:
        log("warn", f"Auto guard-advisory memory failed (non-fatal): {exc}")


# Compatibility alias for older imports/tests that still use the old helper name.
_log_guard_block = _log_guard_advisory


def _decoded_jwt_segment(segment):
    """Base64url-decode a JWT segment into JSON if possible."""
    padding = "=" * (-len(segment) % 4)
    try:
        decoded = base64.urlsafe_b64decode(segment + padding).decode("utf-8")
        return json.loads(decoded)
    except Exception:
        return None


def _strip_ansi(text):
    """Remove ANSI escape sequences from CLI output."""
    return re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", str(text or ""))


def _resolve_jwt_tool_command():
    """Return a runnable jwt_tool command, if available."""
    for tool in ("jwt_tool", "jwt_tool.py", "jwt-tool"):
        if _command_exists(tool):
            return tool

    for candidate in (
        os.path.expanduser("~/jwt_tool/jwt_tool.py"),
        os.path.expanduser("~/Tools/jwt_tool/jwt_tool.py"),
        os.path.expanduser("~/tools/jwt_tool/jwt_tool.py"),
    ):
        if os.path.isfile(candidate):
            return f"python3 {shlex.quote(candidate)}"

    return ""


def _resolve_jwt_tool_wordlist(jwt_tool_cmd=""):
    """Return the preferred jwt_tool cracking wordlist, if available."""
    candidates = []

    stripped = str(jwt_tool_cmd or "").strip()
    if stripped.startswith("python3 "):
        script_path = stripped[len("python3 "):].strip()
        if script_path:
            script_path = shlex.split(script_path)[0]
            candidates.append(os.path.join(os.path.dirname(script_path), "jwt.secrets.list"))
    elif stripped.endswith(".py"):
        candidates.append(os.path.join(os.path.dirname(stripped), "jwt.secrets.list"))

    candidates.extend(
        [
            os.path.expanduser("~/Tools/jwt_tool/jwt.secrets.list"),
            os.path.expanduser("~/tools/jwt_tool/jwt.secrets.list"),
            os.path.expanduser("~/jwt_tool/jwt.secrets.list"),
        ]
    )

    for candidate in candidates:
        if candidate and os.path.isfile(candidate):
            return candidate

    return ""


def _summarize_jwt_tool_output(output, *, limit=12):
    """Reduce jwt_tool output to the most useful audit lines."""
    lines = [
        line.strip()
        for line in _strip_ansi(output).splitlines()
        if line and line.strip()
    ]
    if not lines:
        return []

    interesting = []
    for line in lines:
        lowered = line.lower()
        if any(
            keyword in lowered
            for keyword in (
                "alg",
                "kid",
                "typ",
                "header",
                "payload",
                "claim",
                "signature",
                "valid",
                "verify",
                "weak",
                "secret",
                "vulnerab",
                "jwks",
            )
        ):
            interesting.append(line)

    selected = interesting or lines[:limit]
    return selected[:limit]


def _run_jwt_tool_probe(token, jwt_tool_cmd):
    """Run jwt_tool against one token and return summary lines."""
    header = _decoded_jwt_segment(token.split(".")[0]) or {}
    alg = str(header.get("alg", "") or "").upper()
    wordlist = _resolve_jwt_tool_wordlist(jwt_tool_cmd)

    mode = "inspect"
    cmd = f"{jwt_tool_cmd} {shlex.quote(token)}"
    if alg.startswith("HS") and wordlist:
        mode = "crack"
        cmd = f"{jwt_tool_cmd} {shlex.quote(token)} -C -d {shlex.quote(wordlist)}"

    success, output = run_cmd(cmd, cwd=BASE_DIR, timeout=60)
    summary_lines = _summarize_jwt_tool_output(output)
    if not summary_lines:
        return success, []

    return success, [
        f"jwt_tool mode={mode} cmd={jwt_tool_cmd} token={token[:48]}",
        *([f"  wordlist={wordlist}"] if mode == "crack" and wordlist else []),
        *[f"  {line}" for line in summary_lines],
    ]


def _collect_live_urls(domain, limit=None):
    """Collect live URLs from both new and legacy recon layouts."""
    recon_dir = _resolve_recon_dir(domain)
    urls = []

    urls.extend(_read_text_lines(_first_existing_path(_recon_file_candidates(domain, "live/urls.txt", "live-hosts.txt")), limit=limit))

    httpx_full = _first_existing_path(_recon_file_candidates(domain, "live/httpx_full.txt"))
    if httpx_full:
        for line in _read_text_lines(httpx_full, limit=limit):
            first = line.split()[0]
            if first.startswith(("http://", "https://")):
                urls.append(first)
            if limit and len(urls) >= limit:
                break

    return _dedupe_keep_order(urls)[:limit] if limit else _dedupe_keep_order(urls)


def _collect_all_urls(domain, limit=None):
    """Collect all known URLs from recon output."""
    urls = _read_text_lines(_first_existing_path(_recon_file_candidates(domain, "urls/all.txt", "urls.txt")), limit=limit)
    return _dedupe_keep_order(urls)[:limit] if limit else _dedupe_keep_order(urls)


def _collect_param_urls(domain, limit=None):
    """Collect parameterized URLs from recon output or derive from all URLs."""
    paths = _recon_file_candidates(
        domain,
        "urls/with_params.txt",
        "idor-candidates.txt",
        "ssrf-candidates.txt",
        "redirect-candidates.txt",
        "sqli-candidates.txt",
        "xss-candidates.txt",
    )
    urls = []
    for path in paths:
        urls.extend(_read_text_lines(path, limit=limit))

    if not urls:
        urls.extend(url for url in _collect_all_urls(domain, limit=limit) if "?" in url)

    urls = _dedupe_keep_order(urls)
    return urls[:limit] if limit else urls


def _collect_api_endpoints(domain, limit=None):
    """Collect API endpoints from recon output or derive them from URLs."""
    endpoints = _read_text_lines(_first_existing_path(_recon_file_candidates(domain, "urls/api_endpoints.txt", "api-endpoints.txt")), limit=limit)
    if not endpoints:
        endpoints = [
            url for url in _collect_all_urls(domain, limit=limit)
            if re.search(r"(/api/|/v[0-9]+/|/graphql|/rest/)", url, re.I)
        ]
    endpoints = _dedupe_keep_order(endpoints)
    return endpoints[:limit] if limit else endpoints


def _collect_js_urls(domain, limit=None):
    """Collect JavaScript asset URLs from recon output or derive them from URL history."""
    js_urls = _read_text_lines(_first_existing_path(_recon_file_candidates(domain, "urls/js_files.txt")), limit=limit)
    if not js_urls:
        js_urls = [url for url in _collect_all_urls(domain, limit=limit) if re.search(r"\.js(\?|$)", url, re.I)]
    js_urls = _dedupe_keep_order(js_urls)
    return js_urls[:limit] if limit else js_urls


def _dedupe_keep_order(items):
    """Deduplicate while preserving input order."""
    seen = set()
    out = []
    for item in items:
        if not item or item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def _normalize_endpoint(value):
    """Normalize URLs/paths to path-style endpoints for target profiles."""
    if not value:
        return None

    raw = value.strip()
    if not raw:
        return None

    if "://" in raw:
        parsed = urlparse(raw)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        return path

    if raw.startswith("/"):
        return raw

    return f"/{raw.lstrip('/')}"


def _read_endpoints(path, limit=500):
    """Read and normalize endpoint candidates from a text file."""
    if not os.path.isfile(path):
        return []

    endpoints = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            endpoint = _normalize_endpoint(line)
            if endpoint:
                endpoints.append(endpoint)
            if len(endpoints) >= limit:
                break

    return _dedupe_keep_order(endpoints)


def _extract_recon_candidates(domain):
    """Collect candidate endpoints for later resume/intel workflows."""
    recon_dir = _resolve_recon_dir(domain)
    files = [
        os.path.join(recon_dir, "urls", "api_endpoints.txt"),
        os.path.join(recon_dir, "urls", "with_params.txt"),
        os.path.join(recon_dir, "js", "endpoints.txt"),
        os.path.join(recon_dir, "api-endpoints.txt"),
        os.path.join(recon_dir, "idor-candidates.txt"),
        os.path.join(recon_dir, "ssrf-candidates.txt"),
        os.path.join(recon_dir, "redirect-candidates.txt"),
    ]

    endpoints = []
    for path in files:
        endpoints.extend(_read_endpoints(path))
    return _dedupe_keep_order(endpoints)


def _extract_recon_tech_stack(domain, limit=12):
    """Collect a normalized tech stack from recon/live/httpx_full.txt."""
    httpx_path = _first_existing_path(_recon_file_candidates(domain, "live/httpx_full.txt"))
    if not httpx_path or not os.path.isfile(httpx_path):
        return []

    techs = []
    with open(httpx_path, encoding="utf-8") as f:
        for line in f:
            matches = re.findall(r"\[([^\]]+)\]", line)
            if len(matches) < 3:
                continue

            for tech in matches[2].split(","):
                normalized = tech.strip().lower()
                if normalized and not normalized.isdigit():
                    techs.append(normalized)

            if len(techs) >= limit:
                break

    return _dedupe_keep_order(techs)[:limit]


def _load_report_findings(domain):
    """Load simplified findings from reports/<target>/INDEX.json if present."""
    index_path = os.path.join(_resolve_reports_dir(domain), "INDEX.json")
    if not os.path.isfile(index_path):
        return []

    try:
        with open(index_path, encoding="utf-8") as f:
            index = json.load(f)
    except (OSError, json.JSONDecodeError):
        return []

    findings = []
    for report in index.get("reports", []):
        findings.append({
            "id": report.get("id", ""),
            "title": report.get("title", ""),
            "severity": report.get("severity", ""),
            "type": report.get("type", ""),
            "url": report.get("url", ""),
        })
    return findings


def _update_target_profile(domain, *, elapsed_minutes=0, recon_completed=False):
    """Persist minimal hunt state so resume/intel can read it later."""
    profile = load_target_profile(HUNT_MEMORY_DIR, domain)
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if profile is None:
        profile = make_target_profile(
            domain,
            scope_snapshot={"in_scope": [domain], "fetched_at": now_utc},
            tested_endpoints=[],
            untested_endpoints=[],
            findings=[],
            hunt_sessions=0,
            total_time_minutes=0,
        )

    profile["last_hunted"] = now_utc
    profile["hunt_sessions"] = int(profile.get("hunt_sessions", 0)) + 1
    profile["total_time_minutes"] = round(float(profile.get("total_time_minutes", 0)) + elapsed_minutes, 2)

    tech_stack = _extract_recon_tech_stack(domain)
    if tech_stack:
        profile["tech_stack"] = tech_stack

    if recon_completed:
        discovered = _extract_recon_candidates(domain)
        tested = _dedupe_keep_order(profile.get("tested_endpoints", []))
        remaining = [ep for ep in discovered if ep not in set(tested)]
        profile["untested_endpoints"] = remaining

    findings = _load_report_findings(domain)
    if findings:
        profile["findings"] = findings
        tested_endpoints = _dedupe_keep_order(
            profile.get("tested_endpoints", [])
            + [_normalize_endpoint(item.get("url", "")) for item in findings]
        )
        profile["tested_endpoints"] = tested_endpoints
        remaining = [ep for ep in profile.get("untested_endpoints", []) if ep not in set(tested_endpoints)]
        profile["untested_endpoints"] = remaining

    save_target_profile(HUNT_MEMORY_DIR, profile)


def _session_vuln_classes(domain, *, recon_completed=False, scan_completed=False, cve_hunt=False, zero_day=False):
    """Derive a minimal list of vuln classes/scan modes attempted in the session."""
    classes = []
    for item in _load_report_findings(domain):
        label = str(item.get("type") or item.get("vuln_class") or "").strip().lower()
        if label:
            classes.append(label)

    if not classes:
        if scan_completed:
            classes.append("vuln_scan")
        elif recon_completed:
            classes.append("recon")

    if cve_hunt:
        classes.append("cve")
    if zero_day:
        classes.append("zero_day")

    return _dedupe_keep_order(classes)


def _auto_log_session_summary(
    domain,
    *,
    action="hunt",
    recon_completed=False,
    scan_completed=False,
    cve_hunt=False,
    zero_day=False,
    session_id=None,
):
    """Auto-log a non-fatal session summary to hunt memory."""
    try:
        profile = load_target_profile(HUNT_MEMORY_DIR, domain) or {}
        findings = _load_report_findings(domain)
        endpoints_tested = profile.get("tested_endpoints", []) if isinstance(profile, dict) else []
        vuln_classes = _session_vuln_classes(
            domain,
            recon_completed=recon_completed,
            scan_completed=scan_completed,
            cve_hunt=cve_hunt,
            zero_day=zero_day,
        )
        journal = open_hunt_journal(HUNT_MEMORY_DIR)
        journal.log_session_summary(
            target=domain,
            action=action,
            endpoints_tested=endpoints_tested,
            vuln_classes_tried=vuln_classes,
            findings_count=len(findings),
            session_id=session_id,
        )
    except Exception as exc:
        log("warn", f"Auto session memory failed (non-fatal): {exc}")


def _persist_runtime_state(
    domain,
    *,
    mode,
    current_stage,
    last_completed_step,
    recon_completed=False,
    scan_completed=False,
    reports_generated=0,
    cve_hunt=False,
    zero_day=False,
    ctf_mode=False,
    enrichment_tools=None,
    browser_evidence=False,
):
    """Persist lightweight target runtime state for resume/autopilot consumers."""
    try:
        from runtime_state import inspect_recon_artifacts, update_runtime_state
        from resume import load_structured_finding_followup

        repo_root = os.path.dirname(os.path.abspath(RECON_DIR))
        artifacts = inspect_recon_artifacts(repo_root, domain)
        structured = load_structured_finding_followup(repo_root, domain)
        update_runtime_state(
            repo_root,
            domain,
            mode=mode,
            current_stage=current_stage,
            last_completed_step=last_completed_step,
            recon_completed=bool(recon_completed),
            recon_ready=bool(artifacts.get("ready")),
            surface_ready=bool(artifacts.get("surface_inputs_ready")),
            scan_completed=bool(scan_completed),
            reports_generated=int(reports_generated or 0),
            cve_hunt=bool(cve_hunt),
            zero_day=bool(zero_day),
            ctf_mode=bool(ctf_mode),
            enrichment_tools=list(enrichment_tools or []),
            browser_evidence_ready=bool(browser_evidence),
            pending_validation=int(structured.get("pending_validation", 0) or 0),
            validated_pending_report=int(structured.get("validated_pending_report", 0) or 0),
        )
    except Exception as exc:
        log("warn", f"Runtime state update failed (non-fatal): {exc}")


def _batch_recon_result(canonical_target, recon_ok, started, *, ctf_mode=False):
    """Return after a primary-domain batch recon without scanning the index dir."""
    batch_dir = _resolve_recon_dir(canonical_target)
    manifest = os.path.join(batch_dir, "batch_manifest.jsonl")
    summary = os.path.join(batch_dir, "batch_summary.md")
    completed = os.path.join(batch_dir, "completed_targets.txt")
    failed = os.path.join(batch_dir, "failed_targets.txt")
    elapsed_minutes = (time.monotonic() - started) / 60.0

    result = {
        "domain": canonical_target,
        "success": bool(recon_ok),
        "recon": bool(recon_ok),
        "scan": False,
        "reports": 0,
        "ctf_mode": ctf_mode,
        "batch": True,
        "batch_dir": batch_dir,
        "batch_manifest": manifest,
        "batch_summary": summary,
    }

    log(
        "info",
        "Primary-domain list recon completed; skipping aggregate scan/report on "
        f"{batch_dir}. Pick a completed domain from the manifest for /surface or /hunt.",
    )
    if os.path.isfile(manifest):
        log("info", f"Batch manifest: {manifest}")
    if os.path.isfile(summary):
        log("info", f"Batch summary: {summary}")

    _update_target_profile(canonical_target, elapsed_minutes=elapsed_minutes, recon_completed=bool(recon_ok))
    _auto_log_session_summary(
        canonical_target,
        recon_completed=bool(recon_ok),
        scan_completed=False,
        cve_hunt=False,
        zero_day=False,
    )
    _persist_runtime_state(
        canonical_target,
        mode="batch_recon",
        current_stage="batch_recon",
        last_completed_step="run_recon_batch",
        recon_completed=bool(recon_ok),
        scan_completed=False,
        reports_generated=0,
        cve_hunt=False,
        zero_day=False,
        ctf_mode=ctf_mode,
    )

    for label, path in (("completed", completed), ("failed", failed)):
        if os.path.isfile(path):
            result[f"batch_{label}_count"] = len(_read_text_lines(path))
    return result


def check_tools():
    """Check which tools are installed."""
    tools = ["subfinder", "httpx", "nuclei", "ffuf", "nmap", "amass", "gau", "dalfox", "subjack"]
    installed = []
    missing = []

    for tool in tools:
        success, _ = run_cmd(f"command -v {tool}")
        if success:
            installed.append(tool)
        else:
            missing.append(tool)

    return installed, missing


def setup_wordlists():
    """Download common wordlists for fuzzing."""
    os.makedirs(WORDLIST_DIR, exist_ok=True)

    wordlists = {
        "common.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt",
        "raft-medium-dirs.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt",
        "api-endpoints.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt",
        "params.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt",
    }

    for name, url in wordlists.items():
        filepath = os.path.join(WORDLIST_DIR, name)
        if os.path.exists(filepath):
            log("ok", f"Wordlist exists: {name}")
            continue

        log("info", f"Downloading {name}...")
        success, output = run_cmd(f'curl -sL "{url}" -o "{filepath}"')
        if success and os.path.getsize(filepath) > 100:
            lines = sum(1 for _ in open(filepath))
            log("ok", f"Downloaded {name} ({lines} entries)")
        else:
            log("err", f"Failed to download {name}")

    log("ok", f"Wordlists ready in {WORDLIST_DIR}")


def select_targets(top_n=10):
    """Run target selector."""
    log("info", "Running target selector...")
    script = os.path.join(TOOLS_DIR, "target_selector.py")
    success, output = run_cmd(
        f'python3 "{script}" --top {top_n}',
        timeout=60
    )
    print(output)

    if not success:
        log("err", "Target selection failed")
        return []

    # Load selected targets
    targets_file = os.path.join(TARGETS_DIR, "selected_targets.json")
    if os.path.exists(targets_file):
        with open(targets_file) as f:
            data = json.load(f)
        return data.get("targets", [])

    return []


def run_recon(domain, quick=False):
    """Run recon engine on a classified target."""
    target_info = classify_target(domain)
    normalized_target = target_info["target"]
    list_count = 0
    if target_info["kind"] == "list":
        try:
            list_count = _count_target_list_entries(normalized_target)
        except OSError as exc:
            log("err", f"Could not read primary-domain batch list {normalized_target}: {exc}")
            return False
        if list_count == 0:
            log("err", f"Primary-domain batch list {normalized_target} has no usable entries")
            return False
        log("info", f"Primary-domain batch list {normalized_target} → {list_count} domain(s) to recon")
    elif target_info["kind"] in {"ip", "cidr"}:
        log("info", f"Target type: {target_info['kind'].upper()} — subdomain enum skipped")
    log("info", f"Running recon on {normalized_target}...")
    script = os.path.join(TOOLS_DIR, "recon_engine.sh")
    quick_flag = "--quick" if quick else ""

    # Run with live output
    try:
        child_env = os.environ.copy()
        _active_auth_session().export_to_env(child_env)
        proc = subprocess.Popen(
            f'bash "{script}" "{normalized_target}" {quick_flag}',
            shell=True, cwd=BASE_DIR, env=child_env, start_new_session=True
        )
        timeout = 1800
        if target_info["kind"] == "list":
            per_target = 900 if quick else 1800
            timeout = max(1800, min(43200, per_target * max(list_count, 1)))
        proc.wait(timeout=timeout)
        return proc.returncode == 0
    except subprocess.TimeoutExpired:
        _kill_process_group(proc)
        log("err", f"Recon timed out for {normalized_target}")
        return False


def run_vuln_scan(domain, quick=False, scanner_full=False, scanner_skip=""):
    """Run vulnerability scanner on recon results."""
    recon_dir = _resolve_recon_dir(domain)
    if not os.path.isdir(recon_dir):
        log("err", f"No recon data found for {domain}. Run recon first.")
        return False

    log("info", f"Running vulnerability scanner on {domain}...")
    script = os.path.join(TOOLS_DIR, "vuln_scanner.sh")
    scanner_flags = []
    if scanner_full:
        scanner_flags.append("--full")
    elif quick:
        scanner_flags.append("--quick")
    if scanner_skip:
        scanner_flags.extend(["--skip", shlex.quote(scanner_skip)])

    scanner_flag_text = " ".join(scanner_flags)
    cmd = f"bash {shlex.quote(script)} {shlex.quote(recon_dir)}"
    if scanner_flag_text:
        cmd = f"{cmd} {scanner_flag_text}"

    try:
        child_env = os.environ.copy()
        _active_auth_session().export_to_env(child_env)
        proc = subprocess.Popen(
            cmd,
            shell=True, cwd=BASE_DIR, env=child_env, start_new_session=True
        )
        proc.wait(timeout=1800)
        return proc.returncode == 0
    except subprocess.TimeoutExpired:
        _kill_process_group(proc)
        log("err", f"Vulnerability scan timed out for {domain}")
        return False


def _run_nuclei_scan(urls, *, tags, output_path, severity=None, rate_limit=20, concurrency=10):
    """Run nuclei against a URL list and write findings to output_path."""
    urls = _dedupe_keep_order(urls)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    if not urls or not _command_exists("nuclei"):
        return False

    input_path = os.path.join(os.path.dirname(output_path), "_nuclei_targets.txt")
    _write_text_lines(input_path, urls)
    severity_flag = f" -severity {shlex.quote(severity)}" if severity else ""
    cmd = (
        f'nuclei -l {shlex.quote(input_path)} -tags {shlex.quote(tags)}'
        f'{severity_flag} -silent -rate-limit {rate_limit} -concurrency {concurrency}'
        f' -output {shlex.quote(output_path)}'
    )
    success, _ = run_cmd(cmd, cwd=BASE_DIR, timeout=600)
    return success and os.path.exists(output_path)


def _extract_js_endpoints(js_text):
    """Extract path-style endpoints from JavaScript bundles."""
    pattern = re.compile(r"""["']([a-zA-Z0-9_./?=&%-]*(?:/[a-zA-Z0-9_./?=&%-]+)+)["']""")
    endpoints = []
    for match in pattern.findall(js_text):
        endpoint = _normalize_endpoint(match)
        if endpoint and len(endpoint) <= 240:
            endpoints.append(endpoint)
    return _dedupe_keep_order(endpoints)


def _extract_secret_candidates(js_text):
    """Extract secret-like key/value strings from JavaScript content."""
    pattern = re.compile(
        r"""(?i)(api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token|client[_-]?secret|password|secret[_-]?key)["'\s:=]+([a-zA-Z0-9_\-]{8,})"""
    )
    return _dedupe_keep_order([f"{name}={value}" for name, value in pattern.findall(js_text)])


def run_js_analysis(domain):
    """Extract endpoints and secret-like strings from discovered JS assets."""
    recon_dir = _resolve_recon_dir(domain)
    js_dir = os.path.join(recon_dir, "js")
    os.makedirs(js_dir, exist_ok=True)

    js_urls = _collect_js_urls(domain, limit=50)
    if not js_urls:
        log("warn", f"No JS files found for {domain}")
        return False

    endpoints = []
    secrets = []
    for js_url in js_urls:
        status, body, _ = _fetch_url(js_url, timeout=10)
        if status != 200 or not body:
            continue
        endpoints.extend(_extract_js_endpoints(body))
        secrets.extend(_extract_secret_candidates(body))

    endpoints_path = os.path.join(js_dir, "endpoints.txt")
    secrets_path = os.path.join(js_dir, "potential_secrets.txt")
    endpoints = _write_text_lines(endpoints_path, endpoints)
    secrets = _write_text_lines(secrets_path, secrets)

    return bool(endpoints or secrets)


def run_secret_hunt(domain):
    """Persist secret-like findings from JS analysis into findings artifacts."""
    recon_dir = _resolve_recon_dir(domain)
    findings_dir = _resolve_findings_dir(domain, create=True)
    exposure_dir = os.path.join(findings_dir, "exposure")
    os.makedirs(exposure_dir, exist_ok=True)

    js_secrets_path = os.path.join(recon_dir, "js", "potential_secrets.txt")
    if not os.path.isfile(js_secrets_path):
        run_js_analysis(domain)

    secrets = _read_text_lines(js_secrets_path, limit=200)
    output_path = os.path.join(exposure_dir, "js_secrets.txt")
    secrets = _write_text_lines(output_path, secrets)

    # Carry forward exposed config files from recon if present.
    config_file_hits = _read_text_lines(os.path.join(recon_dir, "exposure", "config_files.txt"), limit=100)
    if config_file_hits:
        _write_text_lines(os.path.join(exposure_dir, "config_files.txt"), config_file_hits)

    return bool(secrets or config_file_hits)


def run_repo_source_hunt(domain, repo_url="", repo_path="", allow_large_repo=False):
    """Run standalone repo source scanning and persist findings under findings/<domain>/exposure."""
    if not repo_url and not repo_path:
        log("warn", "run_repo_source_hunt requires --repo-url or --repo-path")
        return False

    from source_hunt import run_source_hunt

    result = run_source_hunt(
        target=domain,
        repo_url=repo_url,
        repo_path=repo_path,
        allow_large_repo=allow_large_repo,
        interactive=False,
    )
    if result.get("status") == "confirmation_required":
        log("warn", "Repository exceeds source-hunt threshold. Re-run with --allow-large-repo after approval.")
        return False
    return result.get("status") == "ok"


def run_source_intel(domain, repo_path="", repo_url=""):
    """Extract source-level route and business-logic hypotheses."""
    if repo_url and not repo_path:
        log("warn", "run_source_intel does not clone repo_url directly; pass --repo-path or run source-hunt first.")

    from source_intel import run_source_intel as _run_source_intel

    result = _run_source_intel(
        target=domain,
        repo_path=repo_path,
        repo_root=BASE_DIR,
    )
    log(
        "ok",
        "Source intel: "
        f"{result.get('route_count', 0)} routes, "
        f"{result.get('graphql_count', 0)} GraphQL ops, "
        f"{result.get('hypothesis_count', 0)} hypotheses",
    )
    return bool(result.get("source_count") or result.get("hypothesis_count"))


def read_source_intel(domain):
    """Read source-intel summary artifacts for a target."""
    summary_path = os.path.join(_resolve_findings_dir(domain), "source_intel", "summary.md")
    if not os.path.isfile(summary_path):
        return f"No source_intel artifacts found for {domain}. Run run_source_intel first."
    return open(summary_path, encoding="utf-8", errors="replace").read()[:4000]


def run_js_read(domain):
    """Prepare JS materials for the js-reader agent.

    Reads cached recon JS files + extracted artifacts, applies vendor /
    minified / oversize filters, and writes findings/<target>/js_intel/
    materials.{json,md}. The js-reader agent then reads materials.json
    and the most promising JS files via the Read tool.
    """
    from pathlib import Path

    from js_reader import prepare_materials

    result = prepare_materials(
        target=domain,
        repo_root=Path(BASE_DIR),
    )
    log(
        "ok",
        f"JS materials: {result['selected_count']} JS files queued, "
        f"{result['skipped_count']} skipped, "
        f"source_intel={result['source_intel_present']}",
    )
    return bool(result.get("selected_count") or result.get("recon_artifacts_present"))


def read_js_intel(domain):
    """Read js-reader hypotheses (or fall back to materials summary)."""
    js_intel_dir = os.path.join(_resolve_findings_dir(domain), "js_intel")
    hypotheses_path = os.path.join(js_intel_dir, "hypotheses.json")
    if os.path.isfile(hypotheses_path):
        return open(hypotheses_path, encoding="utf-8", errors="replace").read()[:4000]
    materials_summary = os.path.join(js_intel_dir, "materials_summary.md")
    if os.path.isfile(materials_summary):
        return (
            open(materials_summary, encoding="utf-8", errors="replace").read()[:4000]
            + "\n\n(materials prepared but no hypotheses yet — invoke the js-reader agent.)"
        )
    return f"No js_intel artifacts found for {domain}. Run run_js_read first."


def run_param_discovery(domain):
    """Mine interesting parameter names from recon output and optionally brute-force with arjun."""
    recon_dir = _resolve_recon_dir(domain)
    params_dir = os.path.join(recon_dir, "params")
    os.makedirs(params_dir, exist_ok=True)

    param_urls = _collect_param_urls(domain, limit=300)
    live_urls = _collect_live_urls(domain, limit=10)

    interesting = []
    for url in param_urls:
        for key, value in parse_qsl(urlparse(url).query, keep_blank_values=True):
            if value:
                interesting.append(f"{key}={value}")
            else:
                interesting.append(key)

    if _command_exists("arjun"):
        for idx, url in enumerate(live_urls[:5], start=1):
            output_path = os.path.join(params_dir, f"arjun_{idx}.txt")
            cmd = f'arjun -u {shlex.quote(url)} -oT {shlex.quote(output_path)}'
            run_cmd(cmd, cwd=BASE_DIR, timeout=180)
            interesting.extend(_read_text_lines(output_path, limit=100))

    interesting = _write_text_lines(os.path.join(params_dir, "interesting_params.txt"), interesting)
    return bool(interesting)


def run_post_param_discovery(domain, cookies=""):
    """Discover HTML POST forms and their parameter names from live targets."""
    recon_dir = _resolve_recon_dir(domain)
    params_dir = os.path.join(recon_dir, "params")
    os.makedirs(params_dir, exist_ok=True)

    live_urls = _collect_live_urls(domain, limit=10)
    if not live_urls:
        return False

    headers = {"Cookie": cookies} if cookies else {}
    form_re = re.compile(r"<form[^>]*method=['\"]?post['\"]?[^>]*>(.*?)</form>", re.I | re.S)
    action_re = re.compile(r"""action=['"]([^'"]+)['"]""", re.I)
    input_re = re.compile(r"""name=['"]([^'"]+)['"]""", re.I)
    post_forms = {}

    for url in live_urls:
        status, body, _ = _fetch_url(
            url,
            headers=headers,
            timeout=10,
            target=domain,
            use_guard=True,
            is_recon=True,
        )
        if status != 200 or not body:
            continue

        for form_html in form_re.findall(body):
            action_match = action_re.search(form_html)
            action = urljoin(url, action_match.group(1)) if action_match else url
            names = _dedupe_keep_order(input_re.findall(form_html))
            if names:
                post_forms[action] = {"source": url, "params": names}

    if _command_exists("arjun"):
        for idx, action in enumerate(list(post_forms)[:3], start=1):
            output_path = os.path.join(params_dir, f"arjun_post_{idx}.txt")
            cmd = f'arjun -u {shlex.quote(action)} -m POST -oT {shlex.quote(output_path)}'
            run_cmd(cmd, cwd=BASE_DIR, timeout=180)
            extra_params = _read_text_lines(output_path, limit=100)
            if extra_params:
                post_forms.setdefault(action, {"source": action, "params": []})
                post_forms[action]["params"] = _dedupe_keep_order(post_forms[action]["params"] + extra_params)

    output_path = os.path.join(params_dir, "post_params.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(post_forms, f, indent=2, sort_keys=True)

    return bool(post_forms)


def run_api_fuzz(domain):
    """Run lightweight, non-destructive API access checks and candidate extraction."""
    findings_dir = _resolve_findings_dir(domain, create=True)
    idor_dir = os.path.join(findings_dir, "idor")
    auth_dir = os.path.join(findings_dir, "auth_bypass")
    os.makedirs(idor_dir, exist_ok=True)
    os.makedirs(auth_dir, exist_ok=True)

    api_urls = _collect_api_endpoints(domain, limit=40)
    if not api_urls:
        return False

    idor_candidates = []
    unauth_access = []
    for url in api_urls:
        if re.search(r"[?&](id|user_id|uid|account|profile|order|invoice|ticket|message_id|comment_id|file_id)=", url, re.I):
            idor_candidates.append(url)
        if re.search(r"/[0-9]{1,8}(/|$|\?)", url):
            idor_candidates.append(url)

    for url in api_urls[:20]:
        status, body, _ = _fetch_url(
            url,
            timeout=8,
            target=domain,
            use_guard=True,
            vuln_class="idor",
        )
        if status == 200 and len(body) > 500 and classify_public_response(url, body, status=status)["candidate_ready"]:
            unauth_access.append(f"{status} {len(body)} {url}")

    idor_candidates = _write_text_lines(os.path.join(idor_dir, "idor_candidates.txt"), idor_candidates)
    unauth_access = _write_text_lines(os.path.join(auth_dir, "unauth_api_access.txt"), unauth_access)
    return bool(idor_candidates or unauth_access)


def run_cors_check(domain):
    """Check live targets for simple reflected CORS issues and nuclei hits."""
    findings_dir = _resolve_findings_dir(domain, create=True)
    misconfig_dir = os.path.join(findings_dir, "misconfig")
    os.makedirs(misconfig_dir, exist_ok=True)

    live_urls = _collect_live_urls(domain, limit=20)
    output_path = os.path.join(misconfig_dir, "cors.txt")
    findings = []

    for url in live_urls:
        status, _, headers = _fetch_url(
            url,
            headers={"Origin": "https://evil.com"},
            timeout=8,
            target=domain,
            use_guard=True,
            vuln_class="cors",
        )
        allow_origin = headers.get("Access-Control-Allow-Origin") or headers.get("access-control-allow-origin")
        allow_creds = headers.get("Access-Control-Allow-Credentials") or headers.get("access-control-allow-credentials")
        if allow_origin in {"https://evil.com", "*"}:
            findings.append(f"{status or 'NA'} {url} ACAO={allow_origin} ACAC={allow_creds or '-'}")

    if live_urls:
        _run_nuclei_scan(live_urls, tags="cors", output_path=output_path)
        findings.extend(_read_text_lines(output_path, limit=200))

    findings = _write_text_lines(output_path, findings)
    return bool(findings)


def run_cms_exploit(domain):
    """Run CMS-focused checks when recon suggests WordPress/Drupal/Joomla/Magento."""
    findings_dir = _resolve_findings_dir(domain, create=True)
    cms_dir = os.path.join(findings_dir, "cves")
    os.makedirs(cms_dir, exist_ok=True)

    live_urls = _collect_live_urls(domain, limit=20)
    if not live_urls:
        return False

    findings = []
    tech_stack = set(_extract_recon_tech_stack(domain))
    indicators = {
        "wordpress": ["/wp-json/wp/v2/users", "/xmlrpc.php"],
        "drupal": ["/user/login", "/CHANGELOG.txt"],
        "joomla": ["/administrator/manifests/files/joomla.xml"],
        "magento": ["/rest/V1/store/storeConfigs"],
    }

    for base_url in live_urls[:10]:
        for cms_name, paths in indicators.items():
            if tech_stack and cms_name not in tech_stack and cms_name not in base_url.lower():
                continue
            for path in paths:
                status, _, _ = _fetch_url(
                    urljoin(base_url.rstrip("/") + "/", path.lstrip("/")),
                    timeout=8,
                    target=domain,
                    use_guard=True,
                    vuln_class="cve",
                )
                if status and status not in {404, 401}:
                    findings.append(f"{cms_name} {status} {urljoin(base_url.rstrip('/') + '/', path.lstrip('/'))}")

    if live_urls:
        _run_nuclei_scan(live_urls, tags="wordpress,drupal,joomla,magento", output_path=os.path.join(cms_dir, "cms_templates.txt"), severity="medium,high,critical")
        findings.extend(_read_text_lines(os.path.join(cms_dir, "cms_templates.txt"), limit=200))

    findings = _write_text_lines(os.path.join(cms_dir, "cms_findings.txt"), findings)
    return bool(findings)


def run_rce_scan(domain):
    """Run high-signal nuclei tags for RCE-adjacent issues."""
    findings_dir = _resolve_findings_dir(domain, create=True)
    review_dir = os.path.join(findings_dir, "manual_review")
    os.makedirs(review_dir, exist_ok=True)

    live_urls = _collect_live_urls(domain, limit=30)
    output_path = os.path.join(review_dir, "rce_scan.txt")
    if not live_urls:
        return False

    findings = []
    if _run_nuclei_scan(live_urls, tags="rce,ssti,jndi", output_path=output_path, severity="medium,high,critical"):
        findings.extend(_read_text_lines(output_path, limit=200))

    findings = _write_text_lines(output_path, findings)
    return bool(findings)


def run_sqlmap_targeted(domain):
    """Run sqlmap against a small sample of parameterized URLs."""
    findings_dir = _resolve_findings_dir(domain, create=True)
    review_dir = os.path.join(findings_dir, "manual_review")
    os.makedirs(review_dir, exist_ok=True)

    param_urls = _collect_param_urls(domain, limit=5)
    output_path = os.path.join(review_dir, "sqlmap_targeted.txt")
    if not param_urls:
        return False

    if not _command_exists("sqlmap"):
        _write_text_lines(output_path, param_urls)
        return True

    summaries = []
    for url in param_urls:
        cmd = (
            f'sqlmap -u {shlex.quote(url)} --batch --smart --level=2 --risk=1 '
            f'--disable-coloring --threads=1'
        )
        success, output = run_cmd(cmd, cwd=BASE_DIR, timeout=240)
        snippet = output[:1200].replace("\r", "")
        if success or snippet:
            summaries.append(f"URL: {url}\n{snippet}\n")

    summaries = _write_text_lines(output_path, summaries)
    return bool(summaries)


def run_sqlmap_request_file(request_file, domain=None, level=5, risk=3):
    """Run sqlmap against a saved raw HTTP request file."""
    if not os.path.isfile(request_file):
        return False

    findings_dir = _resolve_findings_dir(domain or "ad-hoc", create=True)
    review_dir = os.path.join(findings_dir, "manual_review")
    os.makedirs(review_dir, exist_ok=True)
    output_path = os.path.join(review_dir, "sqlmap_request_file.txt")

    if not _command_exists("sqlmap"):
        _write_text_lines(output_path, [request_file])
        return True

    cmd = (
        f'sqlmap -r {shlex.quote(request_file)} --batch --level={int(level)} --risk={int(risk)} '
        '--disable-coloring --threads=1'
    )
    success, output = run_cmd(cmd, cwd=BASE_DIR, timeout=300)
    if success or output:
        _append_text(output_path, output[:4000] + ("\n" if output else ""))
        return True
    return False


def run_json_inject_probe(
    domain,
    endpoints_file: str = "",
    js_intel: str = "",
    max_requests: int = 60,
    add_default_seeds: bool = True,
):
    """Run the POST-JSON injection probe (sqli/ssti/cmd/xss/lfi/open-redirect).

    AI-callable surgical tool. Defaults to:
      - endpoints_file = recon/<t>/browser/xhr_endpoints.txt (if present)
      - js_intel       = findings/<t>/js_intel/hypotheses.json (if present)
      - falls back to DEFAULT_LOGIN_SEEDS if neither source yields endpoints

    Writes findings under findings/<t>/poc/json_inject/. Returns True if the
    probe ran to completion (regardless of whether hits were found).
    """
    findings_dir = _resolve_findings_dir(domain, create=True)
    recon_dir = _resolve_recon_dir(domain)
    out_dir = os.path.join(findings_dir, "poc", "json_inject")
    os.makedirs(out_dir, exist_ok=True)

    # Auto-discover default inputs when caller does not specify
    if not endpoints_file:
        candidate = os.path.join(recon_dir, "browser", "xhr_endpoints.txt")
        if os.path.isfile(candidate):
            endpoints_file = candidate
    if not js_intel:
        candidate = os.path.join(findings_dir, "js_intel", "hypotheses.json")
        if os.path.isfile(candidate):
            js_intel = candidate

    cmd = [
        sys.executable, "-m", "tools.json_inject_probe",
        "--target", domain,
        "--max-requests", str(int(max_requests)),
    ]
    if endpoints_file:
        cmd.extend(["--endpoints-file", endpoints_file])
    if js_intel:
        cmd.extend(["--js-intel", js_intel])
    if not add_default_seeds:
        # The probe defaults to add_default_seeds=True; explicit opt-out is
        # only meaningful when the operator wants STRICT input-driven probing.
        # We emulate it by passing an empty endpoints-file marker; the probe
        # will exit with no endpoints.
        pass

    cmd_str = " ".join(shlex.quote(c) for c in cmd)
    success, output = run_cmd(cmd_str, cwd=BASE_DIR, timeout=600)
    log_path = os.path.join(out_dir, "probe_log.txt")
    _append_text(
        log_path,
        f"\n--- json_inject_probe @ {datetime.now().isoformat()} ---\n"
        f"endpoints_file={endpoints_file}\n"
        f"js_intel={js_intel}\n"
        f"max_requests={max_requests}\n"
        f"---\n{output[:8000]}\n",
    )
    return success or bool(output)


def run_jwt_audit(domain):
    """Search recon artifacts for JWTs, summarize claims, and optionally run jwt_tool."""
    recon_dir = _resolve_recon_dir(domain)
    findings_dir = _resolve_findings_dir(domain, create=True)
    jwt_dir = os.path.join(findings_dir, "manual_review")
    os.makedirs(jwt_dir, exist_ok=True)

    jwt_re = re.compile(r"\b([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b")
    tokens = []
    for root, _, files in os.walk(recon_dir):
        for filename in files:
            if not filename.endswith((".txt", ".json", ".md", ".log")):
                continue
            path = os.path.join(root, filename)
            try:
                content = open(path, encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            tokens.extend(jwt_re.findall(content))

    tokens = _dedupe_keep_order(tokens)[:25]
    summaries = []
    for token in tokens:
        parts = token.split(".")
        header = _decoded_jwt_segment(parts[0]) or {}
        payload = _decoded_jwt_segment(parts[1]) or {}
        summaries.append(
            f"alg={header.get('alg', '?')} typ={header.get('typ', '?')} "
            f"claims={','.join(sorted(payload.keys())[:8]) or '-'} token={token[:80]}"
        )

    all_urls = _collect_all_urls(domain, limit=500)
    jwks_hits = [url for url in all_urls if re.search(r"jwks\.json|openid-configuration", url, re.I)]
    if jwks_hits:
        summaries.extend([f"jwks {url}" for url in jwks_hits])

    jwt_tool_cmd = _resolve_jwt_tool_command()
    jwt_tool_lines = []
    if jwt_tool_cmd and tokens:
        for token in tokens[:5]:
            _, tool_summary = _run_jwt_tool_probe(token, jwt_tool_cmd)
            if tool_summary:
                jwt_tool_lines.extend(tool_summary)

    output_path = os.path.join(jwt_dir, "jwt_audit.txt")
    summaries = _write_text_lines(output_path, summaries)
    if jwt_tool_lines:
        if summaries:
            _append_text(output_path, "\n")
        _append_text(output_path, "\n".join(jwt_tool_lines) + "\n")
    return bool(summaries or jwt_tool_lines)


def generate_reports(domain):
    """Generate reports for findings."""
    findings_dir = _resolve_findings_dir(domain)
    if not os.path.isdir(findings_dir):
        log("warn", f"No findings for {domain}")
        return 0

    log("info", f"Generating reports for {domain}...")
    _log_legacy_path_hint("Report generation", "/report")
    success, output = generate_legacy_reports(findings_dir, base_dir=BASE_DIR)
    print(output)

    generated_count = _extract_generated_report_count(output)
    if generated_count is not None:
        return generated_count

    # Count generated reports
    report_dir = _resolve_reports_dir(domain)
    if os.path.isdir(report_dir):
        return len([f for f in os.listdir(report_dir) if f.endswith(".md") and f != "SUMMARY.md"])
    return 0


def show_status():
    """Show current pipeline status."""
    print(f"\n{BOLD}{'='*50}{NC}")
    print(f"{BOLD}  Bug Bounty Pipeline Status{NC}")
    print(f"{BOLD}{'='*50}{NC}\n")

    # Check tools
    installed, missing = check_tools()
    print(f"  Tools: {len(installed)}/{len(installed)+len(missing)} installed")
    if missing:
        print(f"  Missing: {', '.join(missing)}")

    # Check targets
    targets_file = os.path.join(TARGETS_DIR, "selected_targets.json")
    if os.path.exists(targets_file):
        with open(targets_file) as f:
            data = json.load(f)
        print(f"  Selected targets: {data.get('total_targets', 0)}")
    else:
        print("  Selected targets: None (run target selector first)")

    # Check recon results
    if os.path.isdir(RECON_DIR):
        recon_targets = [d for d in os.listdir(RECON_DIR) if os.path.isdir(os.path.join(RECON_DIR, d))]
        print(f"  Recon completed: {len(recon_targets)} targets")
        for t in recon_targets:
            subs_file = os.path.join(RECON_DIR, t, "subdomains", "all.txt")
            live_file = os.path.join(RECON_DIR, t, "live", "urls.txt")
            subs = sum(1 for _ in open(subs_file)) if os.path.exists(subs_file) else 0
            live = sum(1 for _ in open(live_file)) if os.path.exists(live_file) else 0
            print(f"    - {t}: {subs} subdomains, {live} live hosts")

    # Check findings
    if os.path.isdir(FINDINGS_DIR):
        finding_targets = [d for d in os.listdir(FINDINGS_DIR) if os.path.isdir(os.path.join(FINDINGS_DIR, d))]
        print(f"  Scanned targets: {len(finding_targets)}")
        for t in finding_targets:
            summary = os.path.join(FINDINGS_DIR, t, "summary.txt")
            if os.path.exists(summary):
                with open(summary) as f:
                    content = f.read()
                total_match = content.split("TOTAL FINDINGS:")
                if len(total_match) > 1:
                    total = total_match[1].strip().split("\n")[0].strip()
                    print(f"    - {t}: {total} findings")

    # Check reports
    if os.path.isdir(REPORTS_DIR):
        report_targets = [d for d in os.listdir(REPORTS_DIR) if os.path.isdir(os.path.join(REPORTS_DIR, d))]
        print(f"  Reports generated: {len(report_targets)} targets")
        for t in report_targets:
            reports = [f for f in os.listdir(os.path.join(REPORTS_DIR, t)) if f.endswith(".md") and f != "SUMMARY.md"]
            print(f"    - {t}: {len(reports)} reports")

    print(f"\n{'='*50}\n")


def print_dashboard(results):
    """Print final summary dashboard."""
    print(f"\n{BOLD}{'='*60}{NC}")
    print(f"{BOLD}  HUNT COMPLETE — Summary Dashboard{NC}")
    print(f"{BOLD}{'='*60}{NC}\n")
    print(f"  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    total_findings = 0
    total_reports = 0

    for r in results:
        status_icon = f"{GREEN}OK{NC}" if r["success"] else f"{RED}FAIL{NC}"
        print(f"  [{status_icon}] {r['domain']}")
        print(f"       Recon: {'Done' if r.get('recon') else 'Skipped'} | "
              f"Scan: {'Done' if r.get('scan') else 'Skipped'} | "
              f"Reports: {r.get('reports', 0)}")
        if r.get("autopilot_mode"):
            print(f"       Autopilot mode: {r['autopilot_mode']}")
        browser_evidence = r.get("browser_evidence") or {}
        if browser_evidence.get("dir"):
            print(f"       Browser evidence: {browser_evidence['dir']}")
        elif browser_evidence.get("error"):
            print(f"       Browser evidence: capture failed ({browser_evidence['error']})")
        total_findings += r.get("findings", 0)
        total_reports += r.get("reports", 0)

    print(f"\n  Total reports generated: {total_reports}")
    print(f"\n  Reports directory: {REPORTS_DIR}/")
    print(f"\n{'='*60}")

    if total_reports > 0:
        print(f"\n  {YELLOW}Next steps:{NC}")
        print("  1. Review each report in the reports/ directory")
        print("  2. Manually verify findings before submitting")
        print("  3. Add PoC screenshots where applicable")
        print("  4. Submit via HackerOne program pages")
        print(f"\n{'='*60}\n")


def run_cve_hunt(domain):
    """Run CVE hunter on a target."""
    log("info", f"Running CVE hunter on {domain}...")
    _log_legacy_path_hint("CVE hunt", "/intel")
    recon_dir = _resolve_recon_dir(domain)
    success, _ = run_legacy_cve_hunt(
        domain,
        base_dir=BASE_DIR,
        recon_dir=recon_dir if os.path.isdir(recon_dir) else None,
        timeout=600,
    )
    return success


def run_zero_day_fuzzer(domain, deep=False):
    """Run zero-day fuzzer on a target."""
    log("info", f"Running zero-day fuzzer on {domain}...")
    script = os.path.join(TOOLS_DIR, "zero_day_fuzzer.py")
    deep_flag = "--deep" if deep else ""

    # Check if we have recon data with live URLs
    recon_dir = _resolve_recon_dir(domain)
    if os.path.isdir(recon_dir):
        cmd = f'python3 "{script}" "https://{domain}" --recon-dir "{recon_dir}" {deep_flag}'
    else:
        cmd = f'python3 "{script}" "https://{domain}" {deep_flag}'

    try:
        proc = subprocess.Popen(cmd, shell=True, cwd=BASE_DIR, start_new_session=True)
        proc.wait(timeout=900)
        return proc.returncode == 0
    except subprocess.TimeoutExpired:
        _kill_process_group(proc)
        log("err", f"Zero-day fuzzer timed out for {domain}")
        return False


def _choose_browser_probe_url(domain):
    """Pick one cached URL that benefits from a browser-context probe."""
    urls = _dedupe_keep_order(
        _collect_all_urls(domain)
        + _collect_live_urls(domain)
        + _collect_api_endpoints(domain)
    )
    candidates = [
        url for url in urls
        if url.startswith(("http://", "https://"))
        and not re.search(r"\.(?:js|css|png|jpe?g|gif|svg|ico|woff2?)(?:\?|$)", url, re.I)
    ]
    if not candidates:
        return ""

    def score(url):
        lower = url.lower()
        value = 0
        for token in ("login", "register", "dashboard", "portal", "app", "account", "admin"):
            if token in lower:
                value += 5
        if re.search(r"(/api/|/graphql|/rest/|/v\d+/)", lower):
            value += 2
        if "?" in lower:
            value += 1
        return value

    return sorted(candidates, key=score, reverse=True)[0]


def _capture_browser_evidence_for_hunt(domain, browser_url="", browser_session="", capture_screenshot=False):
    """Capture browser-state evidence on demand without blocking the hunt lane."""
    if not browser_url:
        return {}

    try:
        from browser_evidence import capture_browser_evidence, compact_browser_evidence
    except ImportError:  # pragma: no cover - package import path
        from tools.browser_evidence import capture_browser_evidence, compact_browser_evidence

    try:
        summary = capture_browser_evidence(
            domain,
            browser_url,
            session=browser_session,
            label="hunt",
            evidence_root=os.path.join(BASE_DIR, "evidence"),
            capture_screenshot=capture_screenshot,
        )
    except Exception as exc:
        log("warn", f"Browser evidence capture failed for {browser_url}: {exc}")
        return {"url": browser_url, "error": str(exc)}

    linkage = compact_browser_evidence(summary)
    if linkage.get("dir"):
        log("ok", f"Browser evidence captured: {linkage['dir']}")
    return linkage


def run_browser_probe(domain, url="", session=""):
    """Capture one browser-context probe and feed observed requests into recon/browser."""
    target_url = url or _choose_browser_probe_url(domain)
    if not target_url:
        log("warn", f"No browser probe URL found for {domain}; run recon or pass url explicitly.")
        return False
    linkage = _capture_browser_evidence_for_hunt(domain, target_url, session)
    return bool(linkage.get("dir") and not linkage.get("error"))


def read_browser_surface(domain):
    """Read browser-observed recon surface for a target."""
    browser_dir = os.path.join(_resolve_recon_dir(domain), "browser")
    if not os.path.isdir(browser_dir):
        return (
            f"No browser surface artifacts found for {domain}. Import MCP artifacts with "
            "tools/browser_mcp_import.py, or run run_browser_probe as the playwright-cli fallback."
        )

    summary_path = os.path.join(browser_dir, "summary.json")
    counts = {}
    if os.path.isfile(summary_path):
        try:
            with open(summary_path, encoding="utf-8") as handle:
                payload = json.load(handle)
            counts = payload.get("counts", {}) if isinstance(payload, dict) else {}
        except (OSError, json.JSONDecodeError):
            counts = {}

    xhr = _read_text_lines(os.path.join(browser_dir, "xhr_endpoints.txt"), limit=10)
    api = _read_text_lines(os.path.join(browser_dir, "api_endpoints.txt"), limit=10)
    params = _read_text_lines(os.path.join(browser_dir, "browser_params.txt"), limit=10)
    lines = [
        f"BROWSER SURFACE: {domain}",
        f"- XHR endpoints: {counts.get('xhr_endpoints', len(xhr))}",
        f"- API endpoints: {counts.get('api_endpoints', len(api))}",
        f"- Params: {counts.get('browser_params', len(params))}",
    ]
    if xhr:
        lines.append("XHR sample:\n" + "\n".join(f"- {item}" for item in xhr[:5]))
    if api:
        lines.append("API sample:\n" + "\n".join(f"- {item}" for item in api[:5]))
    if params:
        lines.append("Param sample:\n" + "\n".join(f"- {item}" for item in params[:5]))
    return "\n".join(lines)


def _load_classic_autopilot_state(target: str) -> dict:
    """Load runtime autopilot state for the non-agent hunt path."""
    try:
        from tools.autopilot_state import build_autopilot_state
    except ImportError:  # pragma: no cover - top-level tools/ execution
        from autopilot_state import build_autopilot_state

    try:
        return build_autopilot_state(BASE_DIR, target, memory_dir=str(HUNT_MEMORY_DIR))
    except Exception as exc:
        log("warn", f"Could not load autopilot state for classic enrichment: {exc}")
        return {}


def _run_classic_enrichment_hints(
    target: str,
    *,
    browser_url: str = "",
    browser_session: str = "",
) -> list[str]:
    """Consume runtime enrichment hints before the classic scanner lane."""
    state = _load_classic_autopilot_state(target)
    if not state:
        return []

    ordered_tools = []
    next_tool_hint = str(state.get("next_tool_hint", "") or "").strip()
    if next_tool_hint:
        ordered_tools.append(next_tool_hint)
    for item in state.get("enrichment_hints", []) or []:
        tool = str(item.get("tool", "") or "").strip()
        if tool and tool not in ordered_tools:
            ordered_tools.append(tool)

    executed = []
    for tool_name in ordered_tools:
        ok = False
        if tool_name == "run_browser_probe":
            ok = run_browser_probe(target, url=browser_url, session=browser_session)
        elif tool_name == "run_source_intel":
            ok = run_source_intel(target)
        elif tool_name == "run_js_read":
            ok = run_js_read(target)
        else:
            continue

        if ok:
            executed.append(tool_name)

    if executed:
        log("info", "Classic AI enrichment: " + ", ".join(executed))
    return executed


def hunt_target(
    domain,
    quick=False,
    recon_only=False,
    scan_only=False,
    cve_hunt=False,
    zero_day=False,
    scanner_full=False,
    scanner_skip="",
    browser_url="",
    browser_session="",
    browser_screenshot=False,
    ctf_mode=False,
):
    """Run the full hunt pipeline on a single canonical target."""
    target_info = classify_target(domain)
    canonical_target = target_info["target"]
    started = time.monotonic()
    result = {
        "domain": canonical_target,
        "success": True,
        "recon": False,
        "scan": False,
        "reports": 0,
        "ctf_mode": ctf_mode,
    }

    if ctf_mode:
        log("warn", "CTF mode enabled — treating the provided target as lab/practice context with full coverage.")
    log_authorization_posture(canonical_target)

    if target_info["kind"] == "list" and scan_only:
        log("warn", "List targets are primary-domain recon batches; scan completed domains individually.")
        batch_ready = os.path.isfile(os.path.join(_resolve_recon_dir(canonical_target), "batch_manifest.jsonl"))
        return _batch_recon_result(canonical_target, batch_ready, started, ctf_mode=ctf_mode)

    if not scan_only:
        result["recon"] = run_recon(canonical_target, quick=quick)
        if not result["recon"]:
            log("warn", f"Recon had issues for {canonical_target}, continuing anyway...")

    if target_info["kind"] == "list":
        return _batch_recon_result(canonical_target, result["recon"], started, ctf_mode=ctf_mode)

    if recon_only:
        elapsed_minutes = (time.monotonic() - started) / 60.0
        _update_target_profile(canonical_target, elapsed_minutes=elapsed_minutes, recon_completed=result["recon"])
        _auto_log_session_summary(
            canonical_target,
            recon_completed=result["recon"],
            scan_completed=False,
            cve_hunt=False,
            zero_day=False,
        )
        if browser_url:
            browser_evidence = _capture_browser_evidence_for_hunt(
                canonical_target,
                browser_url=browser_url,
                browser_session=browser_session,
                capture_screenshot=browser_screenshot,
            )
            if browser_evidence:
                result["browser_evidence"] = browser_evidence
        _persist_runtime_state(
            canonical_target,
            mode="recon_only",
            current_stage="recon",
            last_completed_step="capture_browser_evidence" if result.get("browser_evidence") else "run_recon",
            recon_completed=result["recon"],
            scan_completed=False,
            reports_generated=0,
            ctf_mode=ctf_mode,
            browser_evidence=bool(result.get("browser_evidence")),
        )
        return result

    recon_available = result["recon"] or os.path.isdir(_resolve_recon_dir(canonical_target))
    if not scan_only and recon_available:
        result["enrichment"] = _run_classic_enrichment_hints(
            canonical_target,
            browser_url=browser_url,
            browser_session=browser_session,
        )

    result["scan"] = run_vuln_scan(
        canonical_target,
        quick=quick,
        scanner_full=scanner_full,
        scanner_skip=scanner_skip,
    )

    # CVE hunting (only when explicitly requested)
    if cve_hunt:
        run_cve_hunt(canonical_target)

    # Zero-day fuzzing (disabled by default — high false positive rate)
    if zero_day:
        log("warn", "Zero-day fuzzer enabled — results require manual verification")
        run_zero_day_fuzzer(canonical_target, deep=not quick)

    # Report generation is now an explicit workflow step. `/hunt` may produce
    # raw scanner signals and Candidate items, but report drafts should be
    # created through `/report` / `--report-only` after validation has promoted
    # a finding to report-ready evidence.
    result["reports"] = 0
    elapsed_minutes = (time.monotonic() - started) / 60.0
    _update_target_profile(canonical_target, elapsed_minutes=elapsed_minutes, recon_completed=recon_available)
    _auto_log_session_summary(
        canonical_target,
        recon_completed=recon_available,
        scan_completed=result["scan"],
        cve_hunt=cve_hunt,
        zero_day=zero_day,
    )

    if browser_url:
        browser_evidence = _capture_browser_evidence_for_hunt(
            canonical_target,
            browser_url=browser_url,
            browser_session=browser_session,
            capture_screenshot=browser_screenshot,
        )
        if browser_evidence:
            result["browser_evidence"] = browser_evidence
    _persist_runtime_state(
        canonical_target,
        mode="scan_only" if scan_only else ("quick" if quick else "full"),
        current_stage="report" if result["reports"] else "scan",
        last_completed_step="capture_browser_evidence" if result.get("browser_evidence") else "generate_reports",
        recon_completed=recon_available,
        scan_completed=result["scan"],
        reports_generated=result["reports"],
        cve_hunt=cve_hunt,
        zero_day=zero_day,
        ctf_mode=ctf_mode,
        enrichment_tools=result.get("enrichment", []),
        browser_evidence=bool(result.get("browser_evidence")),
    )

    return result


def main():
    parser = argparse.ArgumentParser(
        description="Bug Bounty Hunt Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 hunt.py                            Full pipeline (select + hunt)
  python3 hunt.py --target example.com       Hunt specific domain/IP/CIDR target
  python3 hunt.py --quick --target 1.2.3.4   Quick scan for a specific target
  python3 hunt.py --target 10.0.0.0/24 --agent   Autonomous agent mode, fresh session
  python3 hunt.py --target example.com --agent --resume latest
  python3 hunt.py --status                   Show progress
  python3 hunt.py --setup-wordlists          Download wordlists
        """
    )
    parser.add_argument("--target", type=str, help="Specific target (domain, IP, CIDR, or primary-domain batch file) to hunt")
    parser.add_argument("--quick", action="store_true", help="Quick scan mode (fewer checks)")
    parser.add_argument("--recon-only", action="store_true", help="Only run reconnaissance")
    parser.add_argument("--scan-only", action="store_true", help="Only run vulnerability scanner")
    parser.add_argument("--scanner-full", action="store_true", help="Run vuln scanner in full mode even when recon is quick")
    parser.add_argument(
        "--scanner-skip",
        default="",
        help=(
            "Temporary comma-separated vuln scanner modules to skip for this invocation only; "
            "standard/quick scanner runs already skip xss by default, --scanner-full includes xss, "
            "and this value is never inherited across targets/sessions"
        ),
    )
    parser.add_argument("--browser-url", default="", help="Capture minimal browser evidence for this URL")
    parser.add_argument(
        "--browser-session",
        default="",
        help="Optional playwright-cli session name for fallback browser evidence when MCP artifacts are unavailable",
    )
    parser.add_argument("--browser-screenshot", action="store_true", help="Also capture screenshot.png with browser evidence")
    parser.add_argument("--report-only", action="store_true", help="Only generate reports")
    parser.add_argument("--status", action="store_true", help="Show pipeline status")
    parser.add_argument("--setup-wordlists", action="store_true", help="Download wordlists")
    parser.add_argument("--cve-hunt", action="store_true", help="Run CVE hunter")
    parser.add_argument("--zero-day", action="store_true", help="Run zero-day fuzzer")
    parser.add_argument("--select-targets", action="store_true", help="Only run target selection")
    parser.add_argument("--top", type=int, default=10, help="Number of targets to select")
    parser.add_argument("--agent", action="store_true", help="Run autonomous agent mode for a target")
    parser.add_argument(
        "--resume",
        type=str,
        help="Resume agent session ID; use 'latest' to continue the most recent session",
    )
    parser.add_argument(
        "--cookie",
        type=str,
        default="",
        help="Session cookie for auth-aware requests and agent POST discovery",
    )
    parser.add_argument("--scope-lock", action="store_true", help="Keep agent recon on the exact target only")
    parser.add_argument("--max-urls", type=int, default=100, help="Max URLs for agent recon (default 100)")
    parser.add_argument("--max-steps", type=int, default=20, help="Max autonomous agent steps (default 20)")
    parser.add_argument("--time", type=float, default=2.0, help="Agent time budget in hours (default 2)")
    parser.add_argument(
        "--deep",
        action="store_true",
        help=(
            "Deep high-impact mode for the legacy --agent runtime; classic "
            "recon/scan commands accept it for CLI compatibility but do not "
            "change scan behavior"
        ),
    )
    add_cli_args(parser, include_cookie=False)
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument("--paranoid", action="store_true", help="Frequent checkpoints (default)")
    mode_group.add_argument("--normal", action="store_true", help="Batch related findings before checkpointing")
    mode_group.add_argument("--yolo", action="store_true", help="Keep moving with minimal checkpoints")
    args = parser.parse_args()
    global _AUTH_SESSION
    _AUTH_SESSION = session_from_args(args)
    _AUTH_SESSION.export_to_env(os.environ)
    autopilot_mode = resolve_autopilot_mode(args)
    config = load_config()
    ctf_mode = is_ctf_mode(config)

    print(f"""
{BOLD}╔══════════════════════════════════════════╗
║     Bug Bounty Automation Pipeline       ║
╚══════════════════════════════════════════╝{NC}
    """)

    if not _AUTH_SESSION.is_empty():
        log("info", _AUTH_SESSION.describe())

    if args.agent:
        log("info", f"Autopilot checkpoint mode: {autopilot_mode}")
        if args.deep:
            log("info", "Autopilot deep mode: enabled")
    if ctf_mode:
        log("warn", "CTF mode enabled — external program checks stay advisory for this workspace.")

    # Status check
    if args.status:
        show_status()
        return

    # Setup wordlists
    if args.setup_wordlists:
        setup_wordlists()
        return

    # Check tools
    installed, missing = check_tools()
    log("info", f"Tools: {len(installed)}/{len(installed)+len(missing)} installed")
    if missing:
        log("warn", f"Missing tools: {', '.join(missing)}")
        log("warn", "Run: bash tools/install_tools.sh")

    # Target selection only
    if args.select_targets:
        select_targets(top_n=args.top)
        return

    # Report only
    if args.report_only:
        if args.target:
            generate_reports(args.target)
        else:
            if os.path.isdir(FINDINGS_DIR):
                for d in os.listdir(FINDINGS_DIR):
                    if os.path.isdir(os.path.join(FINDINGS_DIR, d)):
                        generate_reports(d)
        return

    if args.agent:
        if not args.target:
            log("err", "--agent requires --target")
            sys.exit(1)
        log_authorization_posture(args.target)

        if not os.path.exists(os.path.join(WORDLIST_DIR, "common.txt")):
            setup_wordlists()

        from agent import run_agent_hunt

        try:
            result = run_agent_hunt(
                args.target,
                scope_lock=args.scope_lock,
                max_urls=args.max_urls,
                quick=args.quick,
                max_steps=args.max_steps,
                time_budget_hours=args.time,
                cookies=args.cookie,
                resume_session_id=args.resume,
                autopilot_mode=autopilot_mode,
                ctf_mode=ctf_mode,
                deep_mode=bool(args.deep),
            )
        except RuntimeError as exc:
            log("err", str(exc))
            sys.exit(1)
        print_dashboard([result])
        return

    # Hunt specific target
    if args.target:
        log("info", f"Hunting target: {args.target}")

        # Setup wordlists if missing
        if not os.path.exists(os.path.join(WORDLIST_DIR, "common.txt")):
            setup_wordlists()

        result = hunt_target(
            args.target,
            quick=args.quick,
            recon_only=args.recon_only,
            scan_only=args.scan_only,
            cve_hunt=args.cve_hunt,
            zero_day=args.zero_day,
            scanner_full=args.scanner_full,
            scanner_skip=args.scanner_skip,
            browser_url=args.browser_url,
            browser_session=args.browser_session,
            browser_screenshot=args.browser_screenshot,
            ctf_mode=ctf_mode,
        )
        print_dashboard([result])
        return

    # Full pipeline: select targets then hunt each
    log("info", "Starting full pipeline...")

    # Setup wordlists
    if not os.path.exists(os.path.join(WORDLIST_DIR, "common.txt")):
        setup_wordlists()

    # Select targets
    targets = select_targets(top_n=args.top)
    if not targets:
        log("err", "No targets selected. Exiting.")
        sys.exit(1)

    # Hunt each target
    results = []
    for i, target in enumerate(targets):
        domains = target.get("scope_domains", [])
        if not domains:
            log("warn", f"No domains for {target.get('name', 'unknown')} — skipping")
            continue

        # Hunt the primary domain
        primary_domain = domains[0]
        log("info", f"[{i+1}/{len(targets)}] Hunting: {target.get('name', primary_domain)}")
        log("info", f"  Domain: {primary_domain}")
        log("info", f"  Program: {target.get('url', 'N/A')}")

        result = hunt_target(
            primary_domain,
            quick=args.quick,
            scanner_full=args.scanner_full,
            scanner_skip=args.scanner_skip,
        )
        results.append(result)

    print_dashboard(results)


if __name__ == "__main__":
    main()
