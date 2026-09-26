#!/usr/bin/env python3
"""
remember.py — persist a finding into hunt memory.

Primary targets write explicit experience to TargetStore and retain journal audit.
Legacy target history is available through explicit Store import.
"""

import argparse
import json
import os
import sys
import uuid
from pathlib import Path
from urllib.parse import urlparse

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from memory.hunt_journal import HuntJournal
from memory.schemas import SchemaError, make_journal_entry
from memory.target_profile import default_memory_dir
from tools.target_memory import _operation_refs
from tools.target_store import StoreError, runtime_store
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


def resolve_validate_summary_path(
    path: str | Path | None = None,
    *,
    repo_root: str | Path | None = None,
) -> Path:
    """Resolve validate summary path with cwd-local summary preferred over repo fallback."""
    if path:
        return Path(path)

    cwd_summary = Path.cwd() / "validation-summary.json"
    if cwd_summary.is_file():
        return cwd_summary

    root = Path(repo_root) if repo_root is not None else Path(BASE_DIR)
    return root / "findings" / "last-validate.json"


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


def _is_repo_global_last_validate(
    path: str | Path,
    *,
    repo_root: str | Path | None = None,
) -> bool:
    """Return whether a path is the repo-global last validate pointer."""
    try:
        candidate = Path(path).resolve()
        root = Path(repo_root) if repo_root is not None else Path(BASE_DIR)
        fallback = (root / "findings" / "last-validate.json").resolve()
    except OSError:
        return False
    return candidate == fallback


def load_validate_prefill(
    path: str | Path | None = None,
    *,
    repo_root: str | Path | None = None,
) -> dict:
    """Load prefill values from the latest validate summary JSON."""
    summary_path = resolve_validate_summary_path(path, repo_root=repo_root)
    if not summary_path.is_file():
        raise FileNotFoundError(f"Validate summary not found: {summary_path}")

    with open(summary_path, encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, dict):
        raise ValueError(f"Invalid validate summary: {summary_path}")

    result = (data.get("result") or "").strip().lower()
    seven_decision = str(data.get("seven_question_gate_decision") or "").strip().lower()
    gate_fields_present = any(
        key in data
        for key in (
            "all_gates_passed",
            "seven_question_gate_passed",
            "four_validation_gates_passed",
            "seven_question_gate_decision",
        )
    )
    if gate_fields_present:
        report_ready = bool(data.get("all_gates_passed"))
        if data.get("seven_question_gate_passed") is False:
            report_ready = False
        if data.get("four_validation_gates_passed") is False:
            report_ready = False
        if seven_decision in {"kill", "chain_required", "needs_review"}:
            report_ready = False
        if not report_ready:
            result = "partial"
        elif not result:
            result = "confirmed"
    elif not result:
        result = "confirmed" if data.get("all_gates_passed") else "partial"

    return {
        "target": (data.get("target") or "").strip(),
        "vuln_class": (data.get("vuln_class") or data.get("vuln_type") or "").strip().lower(),
        "endpoint": (data.get("endpoint") or "").strip(),
        "result": result,
        "severity": (data.get("severity") or "").strip().lower(),
        "notes": (data.get("notes") or data.get("impact") or "").strip(),
    }


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
    repo_root: str | Path | None = None,
    conditions: str = "",
    reopen_when: str = "",
    next_intent: str = "",
    operation_refs: list[str] | None = None,
    command_id: str | None = None,
    actor: str = "operator",
) -> dict:
    """Append an explicit Store experience and journal audit without a verdict."""
    memory_dir = Path(memory_dir)
    requested_target = target
    canonical_target = canonical_target_value(target)
    normalized_endpoint = normalize_endpoint(endpoint)
    tags = tags or []
    requested_tech_stack = dedupe_keep_order([t.lower() for t in (tech_stack or [])])

    root = Path(repo_root or memory_dir.parent)
    store = runtime_store(root, canonical_target)
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
    refs = _operation_refs(operation_refs or [])
    if not (technique or notes or refs) and (conditions or reopen_when or next_intent or command_id):
        raise StoreError("experience conditions or command ID require technique, notes or operation refs")
    negative = result in {"rejected", "false-positive", "dead-end"}
    if refs and negative and (not isinstance(conditions, str) or not conditions.strip()
                              or not isinstance(reopen_when, str) or not reopen_when.strip()):
        raise StoreError("negative experience requires conditions and reopen_when")
    receipt = None
    if technique or notes or refs:
        kind = "negative" if refs and negative else "primitive" if refs and result == "confirmed" else "note"
        statement = f"{vuln_class} {normalized_endpoint}: {technique or notes or result}"
        if notes and technique:
            statement += f"; {notes}"
        if kind == "note":
            statement = f"Unverified {result} account: {statement}"
        receipt = store.remember(
            command_id=command_id or f"remember:{uuid.uuid4().hex}", kind=kind,
            statement=statement, conditions=conditions or "unknown",
            reopen_when=reopen_when, next_intent=next_intent,
            evidence=refs, actor=actor,
        )
    journal_saved = False
    if receipt is None or not receipt["replayed"]:
        try:
            HuntJournal(memory_dir / "journal.jsonl").append(entry)
        except OSError as exc:
            if receipt is not None:
                raise OSError(f"Store experience committed as {receipt['entity_id']}; journal append failed: {exc}") from exc
            raise
        journal_saved = True
    return {
        "target": requested_target, "resolved_target": canonical_target,
        "endpoint": normalized_endpoint, "journal_saved": journal_saved,
        "finding_saved": False, "pattern_saved": False,
        "experience_saved": receipt is not None,
        "experience_id": receipt["entity_id"] if receipt else None,
        "tech_stack": requested_tech_stack,
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
    parser.add_argument("--conditions", default="", help="conditions for this target experience")
    parser.add_argument("--reopen-when", default="", help="condition that reopens a negative result")
    parser.add_argument("--next-intent", default="", help="suggested next investigation step")
    parser.add_argument("--operation-ref", action="append", default=[], help="OPERATION_ID:STEP; repeatable")
    parser.add_argument("--command-id", default=None, help="idempotent Store command ID")
    parser.add_argument("--actor", default="operator", help="experience author")
    parser.add_argument("--memory-dir", default="", help="Optional hunt-memory directory")
    parser.add_argument("--repo-root", default="", help="Repository root for default memory and validation summary")
    parser.add_argument("--from-validate", action="store_true", help="Prefill fields from last /validate run")
    parser.add_argument("--validate-json", default="", help="Optional validate summary JSON path")
    parser.add_argument("--json", action="store_true", help="Output JSON summary")
    args = parser.parse_args()
    repo_root = Path(args.repo_root) if args.repo_root else Path(BASE_DIR)

    prefill = {}
    validate_summary_path = None
    if args.from_validate:
        try:
            validate_summary_path = resolve_validate_summary_path(
                args.validate_json or None,
                repo_root=repo_root,
            )
            prefill = load_validate_prefill(validate_summary_path, repo_root=repo_root)
        except (FileNotFoundError, json.JSONDecodeError, ValueError) as exc:
            parser.error(str(exc))
        if (
            not args.validate_json
            and not args.target
            and _is_repo_global_last_validate(validate_summary_path, repo_root=repo_root)
        ):
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

    memory_dir = args.memory_dir or str(default_memory_dir(repo_root))
    try:
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
            repo_root=repo_root,
            conditions=args.conditions,
            reopen_when=args.reopen_when,
            next_intent=args.next_intent,
            operation_refs=args.operation_ref,
            command_id=args.command_id,
            actor=args.actor,
        )
    except (SchemaError, StoreError, ValueError) as exc:
        parser.error(str(exc))
    if validate_summary_path is not None:
        summary["validate_summary"] = str(validate_summary_path)

    if args.json:
        print(json.dumps(summary, indent=2))
        return

    print("REMEMBERED")
    print(f"Target: {summary['target']}")
    print(f"Endpoint: {summary['endpoint']}")
    print(f"Journal: {'yes' if summary['journal_saved'] else 'no'}")
    print(f"Target profile updated: {'yes' if summary['finding_saved'] else 'no'}")
    print(f"Pattern saved: {'yes' if summary['pattern_saved'] else 'no'}")
    if summary.get("experience_saved"):
        print(f"Store experience: {summary['experience_id']}")
    if summary.get("validate_summary"):
        print(f"Validate summary: {summary['validate_summary']}")
    if summary["tech_stack"]:
        print(f"Tech stack: {', '.join(summary['tech_stack'])}")


if __name__ == "__main__":
    main()
