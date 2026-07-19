#!/usr/bin/env python3
"""
CVE Hunter
Detects technologies on targets and searches for known CVEs.
Uses httpx tech detection + public CVE databases.

Usage:
    python3 cve_hunter.py <domain>
    python3 cve_hunter.py --recon-dir <recon_dir>
"""

import argparse
import os
import re
import sys

from intel_engine import build_target_intel
from runtime_exec import run_shell_command_split
from target_paths import target_storage_key
from technology_inventory import (
    load_or_build_inventory_for_recon_dir,
    parse_httpx_json_line,
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FINDINGS_DIR = os.path.join(BASE_DIR, "findings")


def run_cmd(cmd, timeout=30):
    success, stdout, _stderr = run_shell_command_split(cmd, timeout=timeout)
    return success, stdout.strip()


def detect_technologies(domain, recon_dir=None):
    """Detect technologies running on the target."""
    print(f"[*] Detecting technologies on {domain}...")
    techs = {}

    # Method 1: Check httpx output from recon
    if recon_dir:
        inventory = load_or_build_inventory_for_recon_dir(recon_dir, target=domain)
        for component in inventory.get("components") or []:
            label = str(component.get("name") or "").strip()
            version = str(component.get("version") or "").strip()
            if label:
                tech_key = f"{label}:{version}" if version else label
                techs[tech_key] = techs.get(tech_key, 0) + 1

    # Method 2: Direct httpx probe
    if not techs:
        success, output = run_cmd(
            f'echo "{domain}" | httpx -silent -json -tech-detect -status-code 2>/dev/null',
            timeout=30
        )
        if success and output:
            for line in output.splitlines():
                parsed = parse_httpx_json_line(line)
                if parsed is None:
                    continue
                for component in parsed.get("components") or []:
                    label = str(component.get("name") or "").strip()
                    version = str(component.get("version") or "").strip()
                    if label:
                        tech_key = f"{label}:{version}" if version else label
                        techs[tech_key] = 1

    # Method 3: Manual header analysis
    success, output = run_cmd(
        f'curl -sI "https://{domain}" --max-time 10 2>/dev/null',
        timeout=15
    )
    if success and output:
        headers = output.lower()

        # Server header
        server_match = re.search(r'server:\s*(.+)', headers)
        if server_match:
            server = server_match.group(1).strip()
            techs[server] = techs.get(server, 0) + 1
            # Extract version
            ver_match = re.search(r'(nginx|apache|iis|lighttpd|caddy|tomcat|jetty)[/ ]*([0-9.]+)', server)
            if ver_match:
                techs[f"{ver_match.group(1)}/{ver_match.group(2)}"] = 1

        # X-Powered-By
        powered_match = re.search(r'x-powered-by:\s*(.+)', headers)
        if powered_match:
            powered = powered_match.group(1).strip()
            techs[powered] = techs.get(powered, 0) + 1

        # Common headers indicating tech
        if "x-aspnet-version" in headers:
            techs["asp.net"] = 1
        if "x-drupal" in headers:
            techs["drupal"] = 1
        if "x-wordpress" in headers or "wp-" in headers:
            techs["wordpress"] = 1
        if "x-shopify" in headers:
            techs["shopify"] = 1
        if "x-amz" in headers:
            techs["aws"] = 1
        if "cf-ray" in headers:
            techs["cloudflare"] = 1

    # Method 4: Check common CMS/framework fingerprints
    print("    [>] Checking CMS/framework fingerprints...")
    fingerprints = {
        "/wp-login.php": "wordpress",
        "/wp-admin/": "wordpress",
        "/wp-includes/": "wordpress",
        "/administrator/": "joomla",
        "/user/login": "drupal",
        "/misc/drupal.js": "drupal",
        "/typo3/": "typo3",
        "/umbraco/": "umbraco",
        "/sitecore/": "sitecore",
        "/sitefinity/": "sitefinity",
    }

    for path, tech in fingerprints.items():
        success, output = run_cmd(
            f'curl -s -o /dev/null -w "%{{http_code}}" "https://{domain}{path}" --max-time 5',
            timeout=10
        )
        if success and output in ("200", "301", "302", "403"):
            techs[tech] = techs.get(tech, 0) + 1

    if techs:
        print(f"    [+] Detected technologies:")
        for tech, count in sorted(techs.items(), key=lambda x: -x[1]):
            print(f"        - {tech}")
    else:
        print("    [!] No technologies detected")

    return techs


def run_nuclei_cve_scan(domain, recon_dir=None):
    """Run nuclei with CVE templates against the target."""
    print(f"\n[*] Running nuclei CVE scan on {domain}...")

    targets_file = None
    if recon_dir:
        live_file = os.path.join(recon_dir, "live", "urls.txt")
        if os.path.exists(live_file):
            targets_file = live_file

    if targets_file:
        cmd = f'cat "{targets_file}" | nuclei -tags cve -severity medium,high,critical -silent -rate-limit 30 2>/dev/null'
    else:
        cmd = f'echo "https://{domain}" | nuclei -tags cve -severity medium,high,critical -silent -rate-limit 30 2>/dev/null'

    success, output = run_cmd(cmd, timeout=300)

    findings = []
    if success and output:
        for line in output.strip().split("\n"):
            if line.strip():
                findings.append(line.strip())
                print(f"    [VULN] {line.strip()}")

    if not findings:
        print("    [+] No CVEs detected by nuclei")

    return findings


def check_exposed_configs(domain, recon_dir=None):
    """Check for exposed config files (env.js, app_env.js, etc.)."""
    print(f"\n[*] Checking for exposed config files on {domain}...")
    exposed = []

    config_paths = [
        "/env.js", "/app_env.js", "/config.js", "/settings.js",
        "/.env", "/.env.local", "/.env.production",
        "/static/env.js", "/assets/env.js", "/config/env.js",
    ]

    hosts = [f"https://{domain}"]
    if recon_dir:
        live_file = os.path.join(recon_dir, "live", "urls.txt")
        if os.path.exists(live_file):
            with open(live_file) as f:
                hosts = [line.strip() for line in f if line.strip()][:20]

    for host in hosts:
        for path in config_paths:
            url = f"{host}{path}"
            success, output = run_cmd(
                f'curl -s -o /tmp/cfg_check.txt -w "%{{http_code}}" --max-time 5 "{url}"',
                timeout=10
            )
            if success and output.strip() == "200":
                # Verify it's not an HTML error page
                _, content = run_cmd('file /tmp/cfg_check.txt', timeout=5)
                _, head = run_cmd('head -1 /tmp/cfg_check.txt', timeout=5)
                if 'HTML' not in content and '<!DOCTYPE' not in head and '<html' not in head.lower():
                    exposed.append(url)
                    print(f"    [VULN] Config exposed: {url}")

    if not exposed:
        print("    [+] No exposed config files found")

    return exposed


def hunt_cves(domain, recon_dir=None):
    """Full CVE hunting pipeline."""
    print("=" * 50)
    print(f"  CVE Hunter — {domain}")
    print("=" * 50)

    findings_dir = os.path.join(FINDINGS_DIR, target_storage_key(domain), "cves")
    os.makedirs(findings_dir, exist_ok=True)

    # Step 0: Check for exposed config files
    exposed_configs = check_exposed_configs(domain, recon_dir)
    if exposed_configs:
        config_file = os.path.join(findings_dir, "exposed_configs.txt")
        with open(config_file, "w") as f:
            f.write("\n".join(exposed_configs))
        print(f"    [+] Saved {len(exposed_configs)} exposed config URLs to {config_file}")

    # Step 1: Detect technologies
    techs = detect_technologies(domain, recon_dir)

    # Step 2: 复用 Intel v2 owner；本兼容入口不再维护第二套 CVE API/parser。
    all_cves = []
    if techs:
        print(f"\n[*] Building Intel v2 for {len(techs)} technologies...")
        intel = build_target_intel(
            BASE_DIR,
            domain,
            techs=list(techs.keys()),
            memory={"tested_cves": [], "tested_endpoints": [], "patterns": []},
            include_identity=False,
        )
        for advisory in intel.get("advisories") or []:
            component = advisory.get("component") if isinstance(advisory.get("component"), dict) else {}
            cve = {
                "id": advisory.get("id", ""),
                "description": str(advisory.get("summary") or "")[:200],
                "cvss_score": advisory.get("cvss") or 0,
                "severity": str(advisory.get("severity") or "unknown").lower(),
                "technology": component.get("name", ""),
                "applicability": advisory.get("applicability", "unknown"),
                "kev": bool(advisory.get("kev")),
                "epss": advisory.get("epss"),
            }
            all_cves.append(cve)
            severity_str = f"[{cve['severity'].upper()}]" if cve["severity"] != "unknown" else ""
            print(
                f"    {cve['id']} {severity_str} CVSS:{cve['cvss_score']} "
                f"applicability={cve['applicability']} — {cve['description'][:80]}..."
            )
        print(f"    [+] Intel artifact: recon/{target_storage_key(domain)}/intel.json")

    # Step 3: Run nuclei CVE detection
    nuclei_findings = run_nuclei_cve_scan(domain, recon_dir)
    if nuclei_findings:
        nuclei_file = os.path.join(findings_dir, "nuclei_cve_confirmed.txt")
        with open(nuclei_file, "w") as f:
            f.write("\n".join(nuclei_findings))
        print(f"    [+] Saved {len(nuclei_findings)} nuclei CVE findings")

    # Summary
    print(f"\n{'=' * 50}")
    print(f"  CVE Hunt Summary — {domain}")
    print(f"{'=' * 50}")
    print(f"  Technologies detected: {len(techs)}")
    print(f"  CVEs from databases: {len(all_cves)}")
    print(f"  Confirmed by nuclei: {len(nuclei_findings)}")

    high_cves = [c for c in all_cves if c.get("cvss_score", 0) >= 7.0]
    if high_cves:
        print(f"\n  HIGH/CRITICAL CVEs ({len(high_cves)}):")
        for cve in sorted(high_cves, key=lambda x: -x.get("cvss_score", 0)):
            print(f"    - {cve['id']} (CVSS {cve['cvss_score']}) [{cve['technology']}]")
            print(f"      {cve['description'][:100]}")

    print(f"\n  Results: {findings_dir}/")
    print(f"{'=' * 50}")

    return all_cves, nuclei_findings


def main():
    parser = argparse.ArgumentParser(description="CVE Hunter — Find known vulnerabilities")
    parser.add_argument("domain", nargs="?", help="Target domain")
    parser.add_argument("--recon-dir", type=str, help="Path to recon results directory")
    args = parser.parse_args()

    if not args.domain and not args.recon_dir:
        parser.print_help()
        sys.exit(1)

    domain = args.domain
    recon_dir = args.recon_dir

    if recon_dir and not domain:
        domain = os.path.basename(recon_dir)

    if not recon_dir and domain:
        potential = os.path.join(BASE_DIR, "recon", target_storage_key(domain))
        if os.path.isdir(potential):
            recon_dir = potential

    hunt_cves(domain, recon_dir)


if __name__ == "__main__":
    main()
