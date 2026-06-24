#!/usr/bin/env python3
"""Build a structured finding index from scanner artifacts.

The scanner still writes human-readable ``.txt`` files.  This module adds a
small stable JSON contract so Claude Code agents, validation, and report
workflows can consume candidate findings without reparsing every directory in
slightly different ways.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
URL_RE = re.compile(r"https?://[^\s|`>'\")]+")
BRACKET_RE = re.compile(r"\[([^\]]+)\]")

CATEGORY_TYPE_MAP = {
    "upload": "upload",
    "sqli": "sqli",
    "xss": "xss",
    "ssti": "ssti",
    "takeover": "takeover",
    "misconfig": "misconfig",
    "exposure": "exposure",
    "ssrf": "ssrf",
    "cves": "cve",
    "redirects": "redirect",
    "idor": "idor",
    "auth_bypass": "auth_bypass",
    "mfa": "mfa",
    "saml": "saml",
}

DEFAULT_SEVERITY = {
    "upload": "high",
    "sqli": "high",
    "xss": "medium",
    "ssti": "critical",
    "takeover": "high",
    "misconfig": "medium",
    "exposure": "medium",
    "ssrf": "high",
    "cve": "high",
    "redirect": "low",
    "idor": "medium",
    "auth_bypass": "high",
    "mfa": "medium",
    "saml": "high",
}

CONFIRMED_MARKERS = (
    "RCE-POC",
    "SQLI-POC-VERIFIED",
    "SSTI-CONFIRMED",
    "SAML-SIG-STRIP",
)

HIGH_CONFIDENCE_MARKERS = CONFIRMED_MARKERS + (
    "MFA-NO-RATE-LIMIT",
    "MFA-WORKFLOW-SKIP",
    "UNAUTH",
)

REPORTABLE_TYPES = {
    "upload",
    "sqli",
    "xss",
    "ssti",
    "takeover",
    "misconfig",
    "exposure",
    "ssrf",
    "cve",
    "redirect",
    "idor",
    "auth_bypass",
    "mfa",
    "saml",
}


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _line_count(path: Path) -> int:
    if not path.is_file():
        return 0
    with path.open(encoding="utf-8", errors="replace") as handle:
        return sum(1 for line in handle if line.rstrip("\n"))


def _extract_url(raw: str) -> str:
    match = URL_RE.search(raw)
    return match.group(0) if match else ""


def _extract_template_id(raw: str) -> str:
    brackets = BRACKET_RE.findall(raw)
    if len(brackets) >= 3 and brackets[1].lower() in {"http", "dns", "ssl", "tcp", "file"}:
        return brackets[0]
    if brackets and not brackets[0].isupper():
        return brackets[0]
    return ""


def _extract_nuclei_severity(raw: str) -> str:
    brackets = [item.lower() for item in BRACKET_RE.findall(raw)]
    for value in brackets:
        if value in {"critical", "high", "medium", "low", "info"}:
            return value
    return ""


def _severity_for(raw: str, vuln_type: str) -> str:
    explicit = _extract_nuclei_severity(raw)
    if explicit:
        return explicit

    if "RCE-POC" in raw or "SSTI-CONFIRMED" in raw or "SAML-SIG-STRIP" in raw:
        return "critical"
    if "SQLI-POC-VERIFIED" in raw or "DEFAULT" in raw.upper():
        return "high"
    return DEFAULT_SEVERITY.get(vuln_type, "medium")


def _confidence_for(raw: str, source_file: str) -> str:
    if any(marker in raw for marker in CONFIRMED_MARKERS):
        return "confirmed"
    if any(marker in raw for marker in HIGH_CONFIDENCE_MARKERS):
        return "high"
    if "manual" in source_file.lower() or "candidate" in raw.lower():
        return "needs_review"
    return "medium"


def _title_for(vuln_type: str, raw: str, url: str) -> str:
    marker = ""
    brackets = BRACKET_RE.findall(raw)
    if brackets:
        marker = brackets[0]
    elif raw.startswith("[") and "]" in raw:
        marker = raw.split("]", 1)[0].lstrip("[")

    label = marker or vuln_type.upper()
    if url:
        return f"{label} on {url}"
    return label


def _stable_id(category: str, rel_path: str, line_number: int, raw: str) -> str:
    digest = hashlib.sha1(f"{rel_path}:{line_number}:{raw}".encode("utf-8")).hexdigest()[:10]
    return f"{category}_{digest}"


def _finding_from_line(findings_dir: Path, path: Path, line_number: int, raw: str) -> dict[str, Any] | None:
    raw = raw.strip()
    if not raw:
        return None

    rel_path = str(path.relative_to(findings_dir))
    category = rel_path.split("/", 1)[0]
    vuln_type = CATEGORY_TYPE_MAP.get(category, category)
    if vuln_type not in REPORTABLE_TYPES:
        return None

    url = _extract_url(raw)
    template_id = _extract_template_id(raw)
    severity = _severity_for(raw, vuln_type)
    confidence = _confidence_for(raw, rel_path)

    return {
        "id": _stable_id(category, rel_path, line_number, raw),
        "type": vuln_type,
        "category": category,
        "title": _title_for(vuln_type, raw, url),
        "summary": raw[:240],
        "url": url,
        "severity": severity,
        "confidence": confidence,
        "source_file": rel_path,
        "line_number": line_number,
        "template_id": template_id,
        "raw": raw,
        "validation_status": "unvalidated",
        "report_status": "not_generated",
    }


def build_finding_index(findings_dir: str | Path, *, target: str | None = None) -> dict[str, Any]:
    """Build a structured index from category ``.txt`` artifacts."""
    root = Path(findings_dir)
    resolved_target = target or root.name
    findings: list[dict[str, Any]] = []

    for category in sorted(CATEGORY_TYPE_MAP):
        category_dir = root / category
        if not category_dir.is_dir():
            continue

        for path in sorted(category_dir.glob("*.txt")):
            with path.open(encoding="utf-8", errors="replace") as handle:
                for line_number, line in enumerate(handle, 1):
                    finding = _finding_from_line(root, path, line_number, line)
                    if finding:
                        findings.append(finding)

    severity_counts: dict[str, int] = {}
    type_counts: dict[str, int] = {}
    confidence_counts: dict[str, int] = {}
    for finding in findings:
        severity_counts[finding["severity"]] = severity_counts.get(finding["severity"], 0) + 1
        type_counts[finding["type"]] = type_counts.get(finding["type"], 0) + 1
        confidence_counts[finding["confidence"]] = confidence_counts.get(finding["confidence"], 0) + 1

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": _now_utc(),
        "target": resolved_target,
        "findings_dir": str(root),
        "total": len(findings),
        "counts": {
            "severity": dict(sorted(severity_counts.items())),
            "type": dict(sorted(type_counts.items())),
            "confidence": dict(sorted(confidence_counts.items())),
        },
        "artifacts": {
            "summary_json": "summary.json" if (root / "summary.json").is_file() else "",
            "summary_txt": "summary.txt" if (root / "summary.txt").is_file() else "",
        },
        "findings": findings,
    }


def write_finding_index(findings_dir: str | Path, *, target: str | None = None, output: str | Path | None = None) -> dict[str, Any]:
    payload = build_finding_index(findings_dir, target=target)
    output_path = Path(output) if output else Path(findings_dir) / "findings.json"
    output_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return payload


def load_finding_index(findings_dir: str | Path) -> dict[str, Any]:
    path = Path(findings_dir) / "findings.json"
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def find_finding(findings_dir: str | Path, finding_id: str) -> dict[str, Any] | None:
    payload = load_finding_index(findings_dir)
    for finding in payload.get("findings", []):
        if isinstance(finding, dict) and finding.get("id") == finding_id:
            return finding
    return None


def update_finding_status(findings_dir: str | Path, finding_id: str, **updates: Any) -> dict[str, Any] | None:
    """Update one finding in findings.json and return the updated finding."""
    path = Path(findings_dir) / "findings.json"
    payload = load_finding_index(findings_dir)
    if not payload:
        return None

    updated_finding = None
    for finding in payload.get("findings", []):
        if not isinstance(finding, dict) or finding.get("id") != finding_id:
            continue
        for key, value in updates.items():
            if value in (None, ""):
                continue
            finding[key] = value
        finding["updated_at"] = _now_utc()
        updated_finding = finding
        break

    if updated_finding is None:
        return None

    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return updated_finding


def format_finding_index(payload: dict[str, Any], *, limit: int = 8) -> str:
    """Return a compact text summary for Claude Code context."""
    if not payload:
        return ""

    lines = [
        "=== finding_index ===",
        f"total={payload.get('total', 0)} target={payload.get('target', '-')}",
    ]

    counts = payload.get("counts") if isinstance(payload.get("counts"), dict) else {}
    for key in ("severity", "type", "confidence"):
        values = counts.get(key) if isinstance(counts.get(key), dict) else {}
        if values:
            rendered = ", ".join(f"{name}={count}" for name, count in sorted(values.items()))
            lines.append(f"{key}: {rendered}")

    for finding in payload.get("findings", [])[:limit]:
        if not isinstance(finding, dict):
            continue
        lines.append(
            "- {id} [{severity}/{confidence}] {type} {url} status={validation}/{report} :: {summary}".format(
                id=finding.get("id", "-"),
                severity=finding.get("severity", "medium"),
                confidence=finding.get("confidence", "medium"),
                type=finding.get("type", "unknown"),
                url=finding.get("url") or "no-url",
                validation=finding.get("validation_status", "unvalidated"),
                report=finding.get("report_status", "not_generated"),
                summary=(finding.get("summary") or "")[:120],
            )
        )

    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Build findings.json from scanner artifacts")
    parser.add_argument("findings_dir", help="Directory containing scanner findings")
    parser.add_argument("--target", default="", help="Target name override")
    parser.add_argument("--output", default="", help="Output JSON path; defaults to <findings_dir>/findings.json")
    args = parser.parse_args()

    payload = write_finding_index(
        args.findings_dir,
        target=args.target or None,
        output=args.output or None,
    )
    print(f"wrote {payload['total']} finding(s) to {args.output or str(Path(args.findings_dir) / 'findings.json')}")


if __name__ == "__main__":
    main()
