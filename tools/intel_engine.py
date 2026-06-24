#!/usr/bin/env python3
"""
intel_engine.py — On-demand intelligence fetch for a target.

Wraps learn.py data sources + HackerOne MCP + hunt memory context.
Called by /intel command. Outputs prioritized intel with memory context.

Usage:
    python3 intel_engine.py --target target.com --tech "nextjs,graphql"
    python3 intel_engine.py --target target.com --tech "nextjs" --program target-program
    python3 intel_engine.py --target target.com --tech "nextjs" --memory-dir ~/.claude/projects/proj/hunt-memory
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone

# Import learn.py functions (same repo)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(BASE_DIR)
sys.path.insert(0, BASE_DIR)

# 与 Osmedeus 01-osint.yaml 的 toolsDir 约定对齐，默认复用 $HOME/Tools。
SHARED_TOOLS_DIR = os.environ.get(
    "BBHUNT_TOOLS_DIR",
    os.environ.get("OSMEDEUS_TOOLS_DIR", os.path.join(os.path.expanduser("~"), "Tools")),
)

from learn import fetch_github_advisories, fetch_nvd_cves, severity_order
try:
    from tools.target_paths import target_storage_key
except ImportError:  # pragma: no cover - direct tools/ execution
    from target_paths import target_storage_key

# Try importing HackerOne MCP server
try:
    sys.path.insert(0, os.path.join(BASE_DIR, "..", "mcp", "hackerone-mcp"))
    from server import search_disclosed_reports, get_program_stats, HackerOneAPIError
    H1_MCP_AVAILABLE = True
except ImportError:
    H1_MCP_AVAILABLE = False

# ─── Color codes ─────────────────────────────────────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"


def load_memory_context(memory_dir: str, target: str) -> dict:
    """Load hunt memory context for a target.

    Returns:
        Dict with tested_endpoints, findings, tech_stack, last_hunted, patterns.
    """
    context = {
        "tested_endpoints": [],
        "findings": [],
        "tech_stack": [],
        "last_hunted": None,
        "hunt_sessions": 0,
        "patterns": [],
        "tested_cves": [],
    }

    if not memory_dir or not os.path.isdir(memory_dir):
        return context

    # Load target profile
    targets_dir = os.path.join(memory_dir, "targets")
    if os.path.isdir(targets_dir):
        # Normalize target name to filename
        target_file = target.replace(".", "-").replace("/", "-") + ".json"
        target_path = os.path.join(targets_dir, target_file)
        if os.path.isfile(target_path):
            try:
                with open(target_path) as f:
                    profile = json.load(f)
                context["tested_endpoints"] = profile.get("tested_endpoints", [])
                context["findings"] = profile.get("findings", [])
                context["tech_stack"] = profile.get("tech_stack", [])
                context["last_hunted"] = profile.get("last_hunted")
                context["hunt_sessions"] = profile.get("hunt_sessions", 0)
            except (json.JSONDecodeError, OSError):
                pass

    # Load journal entries for this target to find tested CVEs
    journal_path = os.path.join(memory_dir, "journal.jsonl")
    if os.path.isfile(journal_path):
        try:
            with open(journal_path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        if entry.get("target") == target:
                            # Check if any tag looks like a CVE
                            for tag in entry.get("tags", []):
                                if tag.upper().startswith("CVE-"):
                                    context["tested_cves"].append(tag.upper())
                    except json.JSONDecodeError:
                        continue
        except OSError:
            pass

    # Load patterns
    patterns_path = os.path.join(memory_dir, "patterns.jsonl")
    if os.path.isfile(patterns_path):
        try:
            with open(patterns_path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        pattern = json.loads(line)
                        context["patterns"].append(pattern)
                    except json.JSONDecodeError:
                        continue
        except OSError:
            pass

    return context


def dedupe_tech_stack(items: list[str]) -> list[str]:
    """Normalize and dedupe tech names while preserving order."""
    deduped = []
    seen = set()
    for item in items:
        value = item.strip().lower()
        if not value or value in seen:
            continue
        seen.add(value)
        deduped.append(value)
    return deduped


def load_recon_tech_stack(target: str, limit: int = 12) -> list[str]:
    """Best-effort tech extraction from recon/<target>/live/httpx_full.txt."""
    httpx_path = os.path.join(REPO_ROOT, "recon", target_storage_key(target), "live", "httpx_full.txt")
    if not os.path.isfile(httpx_path):
        return []

    techs = []
    with open(httpx_path, encoding="utf-8", errors="replace") as f:
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

    return dedupe_tech_stack(techs)[:limit]


def resolve_tech_stack(target: str, cli_techs: list[str], memory: dict, limit: int = 12) -> list[str]:
    """Resolve effective tech stack from CLI, then memory, then recon fallback."""
    techs = dedupe_tech_stack(cli_techs)

    if memory.get("tech_stack"):
        techs = dedupe_tech_stack(techs + list(memory["tech_stack"]))

    if techs:
        return techs[:limit]

    return load_recon_tech_stack(target, limit=limit)


def _run_command(cmd: list[str], output_path: str, timeout: int) -> bool:
    """运行外部情报工具并把 stdout/stderr 合并写入文件，失败不抛出。"""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    try:
        with open(output_path, "w", encoding="utf-8", errors="replace") as handle:
            completed = subprocess.run(
                cmd,
                stdout=handle,
                stderr=subprocess.STDOUT,
                timeout=timeout,
                check=False,
            )
        return completed.returncode == 0
    except (OSError, subprocess.TimeoutExpired) as exc:
        with open(output_path, "a", encoding="utf-8", errors="replace") as handle:
            handle.write(f"[tool-error] {' '.join(cmd)}: {exc}\n")
        return False


def _line_count(path: str) -> int:
    try:
        with open(path, encoding="utf-8", errors="ignore") as handle:
            return sum(1 for line in handle if line.strip())
    except OSError:
        return 0


def _resolve_emailfinder() -> list[str] | None:
    """解析 emailfinder：优先复用 Osmedeus toolsDir，缺失时再走 PATH。"""
    script = os.path.join(SHARED_TOOLS_DIR, "emailfinder", "emailfinder.py")
    if os.path.isfile(script):
        return [sys.executable, script]

    binary = shutil.which("emailfinder")
    if binary:
        return [binary]
    return None


def _resolve_leaksearch() -> list[str] | None:
    """解析 LeakSearch：按 Osmedeus toolsDir/LeakSearch 约定复用 venv。"""
    script = os.path.join(SHARED_TOOLS_DIR, "LeakSearch", "LeakSearch.py")
    if not os.path.isfile(script):
        return None

    python_bin = os.path.join(SHARED_TOOLS_DIR, "LeakSearch", "venv", "bin", "python3")
    if not os.path.exists(python_bin):
        python_bin = sys.executable
    return [python_bin, script]


def run_identity_intel(target: str, timeout: int = 180) -> dict:
    """运行轻量身份/凭据情报采集。

    这不是 finding，也不会尝试登录或撞库；结果仅作为 /intel 假设燃料。
    """
    target_key = target_storage_key(target)
    out_dir = os.path.join(REPO_ROOT, "evidence", target_key, "identity_intel")
    os.makedirs(out_dir, exist_ok=True)

    emails_path = os.path.join(out_dir, "emails.txt")
    leaksearch_path = os.path.join(out_dir, "leaksearch.txt")
    summary_path = os.path.join(out_dir, "summary.md")

    emailfinder_status = "missing"
    emailfinder_cmd = _resolve_emailfinder()
    if emailfinder_cmd:
        emailfinder_status = "ok" if _run_command(
            emailfinder_cmd + ["-d", target],
            emails_path,
            timeout=min(timeout, 120),
        ) else "partial"
    else:
        open(emails_path, "w", encoding="utf-8").close()

    leaksearch_status = "missing"
    leaksearch_cmd = _resolve_leaksearch()
    if leaksearch_cmd:
        leaksearch_status = "ok" if _run_command(
            leaksearch_cmd + ["-k", target, "-o", leaksearch_path],
            leaksearch_path,
            timeout=timeout,
        ) else "partial"
    else:
        open(leaksearch_path, "w", encoding="utf-8").close()

    email_count = _line_count(emails_path)
    leak_line_count = _line_count(leaksearch_path)
    summary = [
        f"# Identity Intel — {target}",
        "",
        "这些是身份/凭据情报，不是漏洞结论；用于指导 SSO、找回密码、邀请流、租户枚举等后续假设。",
        "",
        f"- emailfinder: {emailfinder_status} ({email_count} non-empty lines)",
        f"- LeakSearch: {leaksearch_status} ({leak_line_count} non-empty lines)",
        f"- emails: `{os.path.relpath(emails_path, REPO_ROOT)}`",
        f"- leaksearch: `{os.path.relpath(leaksearch_path, REPO_ROOT)}`",
        "",
        "Next hypotheses:",
        "- 检查登录/SSO/找回密码是否存在账号枚举或租户枚举。",
        "- 若 LeakSearch 有命中，只做最小化验证和归属确认，不做自动登录/撞库。",
        "- 将邮箱模式与邀请流、OAuth/SAML、support/admin 面结合验证。",
        "",
    ]
    with open(summary_path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(summary))

    intelligence_path = os.path.join(REPO_ROOT, "evidence", target_key, "intelligence.md")
    os.makedirs(os.path.dirname(intelligence_path), exist_ok=True)
    with open(intelligence_path, "a", encoding="utf-8") as handle:
        handle.write("\n\n")
        handle.write("\n".join(summary))

    return {
        "emailfinder_status": emailfinder_status,
        "leaksearch_status": leaksearch_status,
        "email_count": email_count,
        "leak_line_count": leak_line_count,
        "artifact_dir": out_dir,
        "summary_path": summary_path,
        "emails_path": emails_path,
        "leaksearch_path": leaksearch_path,
    }


def fetch_all_intel(techs: list[str], target: str, program: str = "") -> list[dict]:
    """Fetch intel from all sources."""
    all_results = []

    for tech in techs:
        print(f"  {CYAN}[{tech}]{RESET} GitHub Advisory DB...")
        all_results.extend(fetch_github_advisories(tech))

        print(f"  {CYAN}[{tech}]{RESET} NVD CVE API...")
        all_results.extend(fetch_nvd_cves(tech))

    # HackerOne via MCP server (preferred) or learn.py fallback
    if H1_MCP_AVAILABLE:
        print(f"  {CYAN}[H1 MCP]{RESET} Searching disclosed reports...")
        try:
            if program:
                reports = search_disclosed_reports(program=program, limit=15)
            else:
                for tech in techs[:3]:
                    reports = search_disclosed_reports(keyword=tech, limit=5)
                    for r in reports:
                        all_results.append({
                            "id": r.get("url", ""),
                            "source": "HackerOne",
                            "tech": tech,
                            "severity": r.get("severity", "UNKNOWN"),
                            "summary": r.get("title", ""),
                            "published": r.get("disclosed_at", ""),
                            "program": r.get("program", ""),
                        })
            if program:
                for r in reports:
                    all_results.append({
                        "id": r.get("url", ""),
                        "source": f"HackerOne/{program}",
                        "tech": "program",
                        "severity": r.get("severity", "UNKNOWN"),
                        "summary": r.get("title", ""),
                        "published": r.get("disclosed_at", ""),
                        "program": r.get("program", ""),
                    })
        except HackerOneAPIError as e:
            print(f"  {YELLOW}HackerOne MCP error: {e}{RESET}")
    else:
        print(f"  {DIM}[H1 MCP not available — using learn.py fallback]{RESET}")
        from learn import fetch_hackerone_hacktivity, TECH_H1_KEYWORDS
        for tech in techs:
            keywords = TECH_H1_KEYWORDS.get(tech.lower(), [tech])
            for kw in keywords[:2]:
                print(f"  {CYAN}[{tech}]{RESET} HackerOne Hacktivity '{kw}'...")
                h1_results = fetch_hackerone_hacktivity(kw, limit=5)
                all_results.extend(h1_results)

    # Program stats if available
    if program and H1_MCP_AVAILABLE:
        print(f"  {CYAN}[H1 MCP]{RESET} Program stats for {program}...")
        try:
            stats = get_program_stats(program)
            if "error" not in stats:
                all_results.append({
                    "id": f"program:{program}",
                    "source": "HackerOne/stats",
                    "tech": "program",
                    "severity": "INFO",
                    "summary": (
                        f"{stats.get('name', program)}: "
                        f"{'bounty' if stats.get('offers_bounties') else 'no bounty'}, "
                        f"{stats.get('resolved_reports', '?')} resolved, "
                        f"avg {stats.get('avg_days_to_first_response', '?')}d response"
                    ),
                    "published": stats.get("launched_at", ""),
                    "stats": stats,
                })
        except HackerOneAPIError as e:
            print(f"  {YELLOW}Stats error: {e}{RESET}")

    return all_results


def prioritize_intel(results: list[dict], memory: dict) -> dict:
    """Prioritize intel against memory context.

    Returns:
        Dict with categorized alerts: critical, high, info, memory_context.
    """
    tested_endpoints = set(memory.get("tested_endpoints", []))
    tested_cves = set(memory.get("tested_cves", []))

    critical = []
    high = []
    info = []

    for r in results:
        sev = r.get("severity", "UNKNOWN").upper()
        cve_id = r.get("id", "")

        # Check if this CVE was already tested
        already_tested = cve_id.upper() in tested_cves if cve_id.startswith("CVE") else False

        entry = {
            **r,
            "already_tested": already_tested,
        }

        if already_tested:
            entry["note"] = "Already tested in a previous hunt session."
            info.append(entry)
        elif sev in ("CRITICAL",):
            entry["note"] = "Untested critical vulnerability. Hunt candidate."
            critical.append(entry)
        elif sev in ("HIGH",):
            entry["note"] = "Untested high-severity finding. Priority target."
            high.append(entry)
        else:
            info.append(entry)

    # Sort each category by severity
    critical.sort(key=lambda x: severity_order(x.get("severity", "UNKNOWN")))
    high.sort(key=lambda x: severity_order(x.get("severity", "UNKNOWN")))

    memory_context = {}
    if memory.get("last_hunted"):
        memory_context["last_hunted"] = memory["last_hunted"]
    if memory.get("tech_stack"):
        memory_context["tech_stack"] = memory["tech_stack"]
    if memory.get("hunt_sessions"):
        memory_context["hunt_sessions"] = memory["hunt_sessions"]
    memory_context["tested_endpoints_count"] = len(tested_endpoints)
    memory_context["tested_cves_count"] = len(tested_cves)

    # Find matching patterns from other targets
    matching_patterns = []
    target_tech = set(t.lower() for t in memory.get("tech_stack", []))
    for pattern in memory.get("patterns", []):
        pattern_tech = set(t.lower() for t in pattern.get("tech_stack", []))
        if target_tech & pattern_tech:
            matching_patterns.append({
                "target": pattern.get("target", ""),
                "technique": pattern.get("technique", ""),
                "vuln_class": pattern.get("vuln_class", ""),
                "payout": pattern.get("payout", 0),
            })
    if matching_patterns:
        memory_context["matching_patterns"] = matching_patterns

    return {
        "critical": critical,
        "high": high,
        "info": info,
        "memory_context": memory_context,
        "total": len(results),
    }


def format_output(target: str, intel: dict) -> str:
    """Format intel output for terminal display."""
    lines = [
        f"",
        f"{BOLD}INTEL: {target}{RESET}",
        f"{'═' * 50}",
        f"",
    ]

    if intel["critical"]:
        lines.append(f"{BOLD}ALERTS:{RESET}")
        for item in intel["critical"]:
            lines.append(f"  {RED}[CRITICAL]{RESET} {item.get('id', '')} — {item.get('summary', '')}")
            if item.get("note"):
                lines.append(f"    → {item['note']}")
        lines.append("")

    if intel["high"]:
        if not intel["critical"]:
            lines.append(f"{BOLD}ALERTS:{RESET}")
        for item in intel["high"]:
            lines.append(f"  {YELLOW}[HIGH]{RESET} {item.get('id', '')} — {item.get('summary', '')}")
            if item.get("note"):
                lines.append(f"    → {item['note']}")
        lines.append("")

    if intel["info"]:
        info_count = len(intel["info"])
        tested = sum(1 for i in intel["info"] if i.get("already_tested"))
        lines.append(f"  {GREEN}[INFO]{RESET} {info_count} additional findings ({tested} already tested)")
        lines.append("")

    # Memory context
    mc = intel.get("memory_context", {})
    if mc:
        lines.append(f"{BOLD}MEMORY CONTEXT:{RESET}")
        if mc.get("last_hunted"):
            lines.append(f"  Last hunted: {mc['last_hunted']}")
        if mc.get("hunt_sessions"):
            lines.append(f"  Hunt sessions: {mc['hunt_sessions']}")
        if mc.get("tech_stack"):
            lines.append(f"  Tech stack: {', '.join(mc['tech_stack'])}")
        lines.append(f"  Tested endpoints: {mc.get('tested_endpoints_count', 0)}")
        lines.append(f"  Tested CVEs: {mc.get('tested_cves_count', 0)}")

        if mc.get("matching_patterns"):
            lines.append(f"  {CYAN}Cross-target patterns:{RESET}")
            for p in mc["matching_patterns"][:3]:
                payout = f" (${p['payout']})" if p.get("payout") else ""
                lines.append(f"    • {p['target']}: {p['technique']} [{p['vuln_class']}]{payout}")

    lines.append("")

    identity = intel.get("identity_intel") or {}
    if identity:
        artifact_dir = identity.get("artifact_dir", "")
        if artifact_dir:
            artifact_dir = os.path.relpath(artifact_dir, REPO_ROOT)
        lines.append(f"{BOLD}IDENTITY INTEL:{RESET}")
        lines.append(
            f"  emailfinder: {identity.get('emailfinder_status', 'unknown')} "
            f"({identity.get('email_count', 0)} lines)"
        )
        lines.append(
            f"  LeakSearch: {identity.get('leaksearch_status', 'unknown')} "
            f"({identity.get('leak_line_count', 0)} lines)"
        )
        if artifact_dir:
            lines.append(f"  Artifacts: {artifact_dir}/")
        lines.append("")

    lines.append(f"{DIM}Total: {intel['total']} findings from GitHub Advisory, NVD, HackerOne{RESET}")
    lines.append("")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="On-demand intel for a target")
    parser.add_argument("--target", required=True, help="Target domain")
    parser.add_argument("--tech", default="", help="Comma-separated tech stack")
    parser.add_argument("--program", default="", help="HackerOne program handle")
    parser.add_argument("--memory-dir", default="", help="Path to hunt-memory directory")
    parser.add_argument("--json", action="store_true", help="Output as JSON instead of formatted text")
    args = parser.parse_args()

    techs = [t.strip() for t in args.tech.split(",") if t.strip()] if args.tech else []

    # Load memory context before enforcing --tech so standalone /intel can reuse prior recon/hunt state.
    memory = load_memory_context(args.memory_dir, args.target)
    techs = resolve_tech_stack(args.target, techs, memory)

    if not techs:
        print(f"{YELLOW}No tech stack specified. Use --tech to specify technologies.{RESET}")
        print(f"Example: python3 intel_engine.py --target {args.target} --tech nextjs,graphql")
        sys.exit(1)

    print(f"\n{BOLD}Intel Engine{RESET}")
    print(f"Target: {CYAN}{args.target}{RESET}")
    print(f"Tech: {CYAN}{', '.join(techs)}{RESET}")
    if args.program:
        print(f"Program: {CYAN}{args.program}{RESET}")
    print()

    # Fetch all intel
    results = fetch_all_intel(techs, args.target, args.program)

    # Prioritize against memory
    intel = prioritize_intel(results, memory)
    intel["identity_intel"] = run_identity_intel(args.target)

    if args.json:
        print(json.dumps(intel, indent=2))
    else:
        print(format_output(args.target, intel))


if __name__ == "__main__":
    main()
