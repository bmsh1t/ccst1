#!/usr/bin/env python3
"""
remember.py — persist a finding into hunt memory.

Writes:
- journal.jsonl (always)
- patterns.jsonl (confirmed + payout > 0 + technique + tech stack)
- hunt-memory/targets/<target>.json (tested endpoints + findings)
"""

import argparse
import json
import os
import sys
from pathlib import Path
from urllib.parse import urlparse

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

try:
    # Support `import tools.remember`.
    from .legacy_bridge import open_hunt_journal
except ImportError:
    # Keep legacy top-level `import remember` working.
    from legacy_bridge import open_hunt_journal
from memory.pattern_db import PatternDB
from memory.schemas import make_journal_entry, make_pattern_entry
from memory.target_profile import default_memory_dir, load_target_profile, make_target_profile, save_target_profile
try:
    from tools.target_paths import canonical_target_value
except ImportError:  # pragma: no cover - direct tools/ execution
    from target_paths import canonical_target_value


def normalize_endpoint(value: str) -> str:
    """Normalize URLs/paths to a profile-friendly endpoint path."""
    raw = value.strip()
    if "://" in raw:
        parsed = urlparse(raw)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        return path
    if raw.startswith("/"):
        return raw
    return f"/{raw.lstrip('/')}"


def dedupe_keep_order(items: list[str]) -> list[str]:
    seen = set()
    out = []
    for item in items:
        if not item or item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def parse_csv(value: str) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def resolve_validate_summary_path(path: str | Path | None = None) -> Path:
    """Resolve validate summary path with cwd-local summary preferred over repo fallback."""
    if path:
        return Path(path)

    cwd_summary = Path.cwd() / "validation-summary.json"
    if cwd_summary.is_file():
        return cwd_summary

    return Path(BASE_DIR) / "findings" / "last-validate.json"


def _normalize_target_for_compare(value: str) -> str:
    """Normalize a target-ish value for cross-target leakage checks."""
    raw = (value or "").strip().lower()
    if raw.startswith(("http://", "https://")):
        raw = urlparse(raw).netloc.lower()
    raw = raw.split("@")[-1].split("/")[0].split(":")[0].strip()
    return raw.strip(".")


def _targets_compatible(requested: str, loaded: str) -> bool:
    """Return whether an explicit target is compatible with a validate summary target."""
    requested_norm = _normalize_target_for_compare(requested)
    loaded_norm = _normalize_target_for_compare(loaded)
    if not requested_norm or not loaded_norm:
        return True
    if requested_norm == loaded_norm:
        return True
    return loaded_norm.endswith(f".{requested_norm}") or requested_norm.endswith(f".{loaded_norm}")


def _is_repo_global_last_validate(path: str | Path) -> bool:
    """Return whether a path is the repo-global last validate pointer."""
    try:
        candidate = Path(path).resolve()
        fallback = (Path(BASE_DIR) / "findings" / "last-validate.json").resolve()
    except OSError:
        return False
    return candidate == fallback


def load_validate_prefill(path: str | Path | None = None) -> dict:
    """Load prefill values from the latest validate summary JSON."""
    summary_path = resolve_validate_summary_path(path)
    if not summary_path.is_file():
        raise FileNotFoundError(f"Validate summary not found: {summary_path}")

    with open(summary_path, encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, dict):
        raise ValueError(f"Invalid validate summary: {summary_path}")

    result = (data.get("result") or "").strip().lower()
    if not result:
        result = "confirmed" if data.get("all_gates_passed") else "partial"

    return {
        "target": (data.get("target") or "").strip(),
        "vuln_class": (data.get("vuln_class") or data.get("vuln_type") or "").strip().lower(),
        "endpoint": (data.get("endpoint") or "").strip(),
        "result": result,
        "severity": (data.get("severity") or "").strip().lower(),
        "notes": (data.get("notes") or data.get("impact") or "").strip(),
    }


def load_or_create_target_profile(memory_dir: str | Path, target: str) -> dict:
    canonical_target = canonical_target_value(target)
    profile = load_target_profile(memory_dir, canonical_target)
    if profile is not None:
        return profile
    return make_target_profile(
        canonical_target,
        tested_endpoints=[],
        untested_endpoints=[],
        findings=[],
        hunt_sessions=0,
        total_time_minutes=0,
    )


def merge_finding(profile: dict, finding: dict) -> None:
    """Replace an equivalent finding or append a new one."""
    existing = profile.get("findings", [])
    keep = []
    for item in existing:
        same_endpoint = item.get("endpoint") == finding.get("endpoint")
        same_class = item.get("vuln_class") == finding.get("vuln_class")
        same_technique = item.get("technique", "") == finding.get("technique", "")
        if same_endpoint and same_class and same_technique:
            continue
        keep.append(item)
    keep.append(finding)
    profile["findings"] = keep


def remember_finding(
    *,
    memory_dir: str | Path,
    target: str,
    vuln_class: str,
    endpoint: str,
    result: str,
    severity: str | None = None,
    payout: float | None = None,
    technique: str | None = None,
    notes: str | None = None,
    tags: list[str] | None = None,
    tech_stack: list[str] | None = None,
) -> dict:
    """Persist a finding to hunt memory and return a summary."""
    memory_dir = Path(memory_dir)
    requested_target = target
    canonical_target = canonical_target_value(target)
    normalized_endpoint = normalize_endpoint(endpoint)
    tags = tags or []
    requested_tech_stack = dedupe_keep_order([t.lower() for t in (tech_stack or [])])

    journal = open_hunt_journal(memory_dir)
    pattern_db = PatternDB(memory_dir / "patterns.jsonl")
    profile = load_or_create_target_profile(memory_dir, canonical_target)
    profile["target"] = canonical_target

    entry = make_journal_entry(
        target=canonical_target,
        action="remember",
        vuln_class=vuln_class,
        endpoint=normalized_endpoint,
        result=result,
        severity=severity,
        payout=payout,
        technique=technique,
        notes=notes,
        tags=tags,
    )
    journal.append(entry)

    if requested_tech_stack:
        merged_tech = dedupe_keep_order(profile.get("tech_stack", []) + requested_tech_stack)
        profile["tech_stack"] = merged_tech

    tested_endpoints = dedupe_keep_order(profile.get("tested_endpoints", []) + [normalized_endpoint])
    profile["tested_endpoints"] = tested_endpoints
    profile["untested_endpoints"] = [
        item for item in profile.get("untested_endpoints", [])
        if item != normalized_endpoint
    ]

    finding_saved = False
    if result != "rejected":
        merge_finding(profile, {
            "ts": entry["ts"],
            "endpoint": normalized_endpoint,
            "vuln_class": vuln_class,
            "result": result,
            "severity": severity or "",
            "payout": payout or 0,
            "technique": technique or "",
            "notes": notes or "",
            "tags": tags,
        })
        finding_saved = True

    save_target_profile(memory_dir, profile)

    pattern_saved = False
    effective_tech_stack = profile.get("tech_stack", [])
    if result == "confirmed" and payout and payout > 0 and technique and effective_tech_stack:
        pattern = make_pattern_entry(
            target=canonical_target,
            vuln_class=vuln_class,
            technique=technique,
            tech_stack=effective_tech_stack,
            endpoint=normalized_endpoint,
            payout=payout,
            notes=notes,
            tags=tags,
        )
        pattern_saved = pattern_db.save(pattern)

    return {
        "target": requested_target,
        "resolved_target": canonical_target,
        "endpoint": normalized_endpoint,
        "journal_saved": True,
        "finding_saved": finding_saved,
        "pattern_saved": pattern_saved,
        "tech_stack": effective_tech_stack,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Persist a finding into hunt memory")
    parser.add_argument("--target", default="", help="Target domain")
    parser.add_argument("--vuln-class", default="", help="Vulnerability class, e.g. idor")
    parser.add_argument("--endpoint", default="", help="Affected URL or path")
    parser.add_argument(
        "--result",
        default=None,
        choices=["confirmed", "rejected", "partial", "informational"],
        help="Remember outcome",
    )
    parser.add_argument(
        "--severity",
        default="",
        choices=["", "critical", "high", "medium", "low", "informational", "none"],
        help="Optional severity",
    )
    parser.add_argument("--payout", type=float, default=None, help="Optional payout amount")
    parser.add_argument("--technique", default="", help="Optional technique name")
    parser.add_argument("--notes", default="", help="Optional notes")
    parser.add_argument("--tags", default="", help="Comma-separated tags")
    parser.add_argument("--tech-stack", default="", help="Comma-separated tech stack override")
    parser.add_argument("--memory-dir", default="", help="Optional hunt-memory directory")
    parser.add_argument("--from-validate", action="store_true", help="Prefill fields from last /validate run")
    parser.add_argument("--validate-json", default="", help="Optional validate summary JSON path")
    parser.add_argument("--json", action="store_true", help="Output JSON summary")
    args = parser.parse_args()

    prefill = {}
    validate_summary_path = None
    if args.from_validate:
        try:
            validate_summary_path = resolve_validate_summary_path(args.validate_json or None)
            prefill = load_validate_prefill(validate_summary_path)
        except (FileNotFoundError, json.JSONDecodeError, ValueError) as exc:
            parser.error(str(exc))
        if not args.validate_json and not args.target and _is_repo_global_last_validate(validate_summary_path):
            parser.error(
                "--from-validate resolved repo-global findings/last-validate.json; "
                "pass --target or --validate-json to avoid cross-target leakage"
            )
        if args.target and prefill.get("target") and not _targets_compatible(args.target, prefill["target"]):
            parser.error(
                f"--target {args.target!r} does not match validate summary target "
                f"{prefill['target']!r}; pass the correct --validate-json or omit --from-validate"
            )

    target = args.target or prefill.get("target", "")
    vuln_class = args.vuln_class or prefill.get("vuln_class", "")
    endpoint = args.endpoint or prefill.get("endpoint", "")
    result = args.result or prefill.get("result", "")
    severity = (args.severity or prefill.get("severity", "")).lower()
    notes = args.notes or prefill.get("notes", "")

    missing = [
        flag for flag, value in (
            ("--target", target),
            ("--vuln-class", vuln_class),
            ("--endpoint", endpoint),
            ("--result", result),
        )
        if not value
    ]
    if missing:
        parser.error(
            f"Missing required fields: {', '.join(missing)}. "
            "Provide them directly or use --from-validate with a complete validate summary."
        )

    memory_dir = args.memory_dir or str(default_memory_dir(BASE_DIR))
    summary = remember_finding(
        memory_dir=memory_dir,
        target=target,
        vuln_class=vuln_class,
        endpoint=endpoint,
        result=result,
        severity=severity or None,
        payout=args.payout,
        technique=args.technique or None,
        notes=notes or None,
        tags=parse_csv(args.tags),
        tech_stack=parse_csv(args.tech_stack),
    )
    if validate_summary_path is not None:
        summary["validate_summary"] = str(validate_summary_path)

    if args.json:
        print(json.dumps(summary, indent=2))
        return

    print("REMEMBERED")
    print(f"Target: {summary['target']}")
    print(f"Endpoint: {summary['endpoint']}")
    print(f"Journal: {'yes' if summary['journal_saved'] else 'no'}")
    print(f"Target profile updated: {'yes' if summary['finding_saved'] or summary['journal_saved'] else 'no'}")
    print(f"Pattern saved: {'yes' if summary['pattern_saved'] else 'no'}")
    if summary.get("validate_summary"):
        print(f"Validate summary: {summary['validate_summary']}")
    if summary["tech_stack"]:
        print(f"Tech stack: {', '.join(summary['tech_stack'])}")


if __name__ == "__main__":
    main()
