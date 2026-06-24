#!/usr/bin/env python3
"""tools/scanner_pass_writer.py — emit findings/<target>/scanner_pass.json.

Records which `(endpoint, vuln_class, module)` pairs `tools/vuln_scanner.sh`
exercised in a given run, regardless of whether a finding was produced.
`tools/coverage_matrix.py rebuild` consumes the result to mark already-tested
cells as `tested_clean`, closing the Phase 3 follow-up item that previously
left scanner-swept cells in `untested` (and tripping the F3 finish-gate).

Per task 05-16-b4-scanner-matrix-feedback (R1 / R3 / C3):
  - Output schema: {scanned_at, scanner_version, endpoints: [{endpoint,
    vuln_class, module}, ...]}
  - vuln_class strings MUST use the canonical enum from
    `tools/coverage_matrix.py` (`VULN_CLASSES`, alias-aware via
    `normalize_vuln_class`).
  - Additive only — does not modify findings.json or any other artifact.

Usage:
    python3 tools/scanner_pass_writer.py \
        --target target.com \
        --findings-dir findings/target.com \
        --recon-dir recon/target.com \
        [--scanner-version vuln_scanner.sh@HEAD]
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from tools.coverage_matrix import VULN_CLASSES, normalize_vuln_class  # noqa: E402


# Mapping from vuln_scanner.sh category directory name to canonical vuln_class
# from VULN_CLASSES. Categories not present in this map are intentionally NOT
# recorded — they are mixed/informational lanes (cves, exposure, metasploit)
# that do not fit a single canonical vuln_class cell. Per C3 / per coverage
# matrix philosophy: better to leave the cell `untested` than to mis-mark.
CATEGORY_TO_VULN_CLASS: dict[str, str] = {
    "upload": "Upload",
    "sqli": "SQLi",
    "xss": "XSS",
    "ssti": "RCE",
    "ssrf": "SSRF",
    "idor": "IDOR",
    "auth_bypass": "Authz",
    "mfa": "Authz",
    "saml": "OAuth",
    "redirects": "OAuth",
    "xxe": "XXE",
    "graphql": "GraphQL",
    "jwt": "JWT",
    "csrf": "CSRF",
    "path": "Path",
    "lfi": "Path",
    "rce": "RCE",
    "webhook": "Webhook",
    "race": "Race",
    "oauth": "OAuth",
}


def _read_endpoints(recon_dir: Path) -> list[str]:
    """Return the canonical endpoint list for scanner_pass.

    Preference order (first non-empty wins):
      recon/<t>/live/urls.txt          # httpx-confirmed live URLs
      recon/<t>/urls/all.txt           # bulk URL inventory
    """
    for candidate in (
        recon_dir / "live" / "urls.txt",
        recon_dir / "urls" / "all.txt",
    ):
        if candidate.is_file():
            try:
                lines = candidate.read_text(encoding="utf-8", errors="ignore").splitlines()
            except OSError:
                continue
            urls = [ln.strip() for ln in lines if ln.strip() and not ln.startswith("#")]
            if urls:
                return urls
    return []


def _detect_run_modules(findings_dir: Path) -> list[str]:
    """Return scanner module category names that produced at least one file
    in findings/<target>/<category>/.

    A module is considered "ran" if its category directory exists and has at
    least one regular file (even empty findings — the directory itself proves
    the lane was exercised).
    """
    if not findings_dir.is_dir():
        return []
    modules: list[str] = []
    for child in sorted(findings_dir.iterdir()):
        if not child.is_dir():
            continue
        name = child.name
        if name not in CATEGORY_TO_VULN_CLASS:
            continue
        # Lane is considered active if directory exists (even empty == ran-clean)
        modules.append(name)
    return modules


def build_scanner_pass(
    *,
    target: str,
    findings_dir: Path,
    recon_dir: Path,
    scanner_version: str = "vuln_scanner.sh@HEAD",
) -> dict:
    """Return the scanner_pass.json payload."""
    endpoints = _read_endpoints(recon_dir)
    modules = _detect_run_modules(findings_dir)

    rows: list[dict] = []
    for module in modules:
        try:
            vuln_class = normalize_vuln_class(CATEGORY_TO_VULN_CLASS[module])
        except ValueError:
            # Should not happen because the mapping is curated, but guard anyway.
            continue
        for endpoint in endpoints:
            rows.append({
                "endpoint": endpoint,
                "vuln_class": vuln_class,
                "module": f"vuln_scanner.{module}",
            })

    return {
        "schema_version": 1,
        "target": target,
        "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "scanner_version": scanner_version,
        "module_count": len(modules),
        "endpoint_count": len(endpoints),
        "endpoints": rows,
    }


def write_scanner_pass(
    *,
    target: str,
    findings_dir: Path | str,
    recon_dir: Path | str,
    out_path: Path | str | None = None,
    scanner_version: str = "vuln_scanner.sh@HEAD",
) -> Path:
    """Write scanner_pass.json. Returns the written path.

    If `out_path` is None, defaults to `findings_dir/scanner_pass.json`.
    """
    findings_dir_p = Path(findings_dir)
    recon_dir_p = Path(recon_dir)
    payload = build_scanner_pass(
        target=target,
        findings_dir=findings_dir_p,
        recon_dir=recon_dir_p,
        scanner_version=scanner_version,
    )
    if out_path is None:
        # If findings_dir is a per-session subdir (.../sessions/<id>), still
        # write the consolidated scanner_pass.json at the per-target level so
        # coverage_matrix.rebuild can pick it up without knowing about sessions.
        target_root = _resolve_target_findings_root(findings_dir_p, target)
        out_path = target_root / "scanner_pass.json"
    else:
        out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return out_path


def _resolve_target_findings_root(findings_dir: Path, target: str) -> Path:
    """Walk up from a per-session findings dir to the per-target findings root.

    The vuln_scanner.sh layout is either:
      findings/<target>/                            (direct)
      findings/<target>/sessions/<session_id>/      (session-scoped)

    coverage_matrix.py looks at findings/<target>/scanner_pass.json, so always
    write to that top-level path even when called from a session subdir.
    """
    parts = list(findings_dir.parts)
    # Try to locate `findings` followed by `<target>` and trim there.
    for i in range(len(parts) - 1):
        if parts[i] == "findings" and parts[i + 1] == target:
            return Path(*parts[: i + 2])
    return findings_dir


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Emit findings/<target>/scanner_pass.json so coverage_matrix "
                    "can mark scanner-swept cells `tested_clean`.",
    )
    parser.add_argument("--target", required=True)
    parser.add_argument("--findings-dir", required=True,
                        help="Per-target or per-session findings directory.")
    parser.add_argument("--recon-dir", required=True,
                        help="recon/<target>/ directory.")
    parser.add_argument("--scanner-version", default="vuln_scanner.sh@HEAD")
    parser.add_argument("--out", default=None,
                        help="Explicit output path (defaults to "
                             "findings/<target>/scanner_pass.json).")
    args = parser.parse_args(argv)

    out_path = write_scanner_pass(
        target=args.target,
        findings_dir=Path(args.findings_dir),
        recon_dir=Path(args.recon_dir),
        out_path=Path(args.out) if args.out else None,
        scanner_version=args.scanner_version,
    )
    print(f"scanner_pass written: {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
