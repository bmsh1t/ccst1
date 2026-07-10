#!/usr/bin/env python3
"""
self_review.py — adversarial verdict parsing + parent decision routing.

B12c: After /validate would PASS a candidate AND --self-review is set,
the parent spawns a red_team worker (B6 primitive). The worker writes
`evidence/<target>/findings/<id>/red_team.md` with one of:

    VERDICT: no_flaw_found
    VERDICT: likely_flaw
    VERDICT: definitive_disqualifier

The parent reads the VERDICT line and routes:

    no_flaw_found             → keep validated → /report
    likely_flaw               → demote to Candidate
    definitive_disqualifier   → kill + record false-positive pattern

This module:
  * parses the red_team.md verdict line
  * formats the decision payload the parent records in audit.jsonl
  * exposes a small CLI for ops inspection
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

try:
    from tools.target_paths import target_storage_key
except ImportError:  # pragma: no cover - direct tools/ execution
    from target_paths import target_storage_key  # type: ignore


VERDICT_NO_FLAW = "no_flaw_found"
VERDICT_LIKELY = "likely_flaw"
VERDICT_DISQUALIFY = "definitive_disqualifier"
VALID_VERDICTS = frozenset({VERDICT_NO_FLAW, VERDICT_LIKELY, VERDICT_DISQUALIFY})

DECISION_KEEP = "keep"
DECISION_DEMOTE = "demote"
DECISION_KILL = "kill"


_VERDICT_RE = re.compile(r"^\s*VERDICT\s*:\s*([A-Za-z_]+)\s*$", re.MULTILINE)


# ---------------------------------------------------------------------
#  Verdict parsing (R2)
# ---------------------------------------------------------------------

def parse_verdict_text(text: str) -> Optional[str]:
    """Return the first VERDICT value or None if absent / invalid."""
    if not text:
        return None
    match = _VERDICT_RE.search(text)
    if not match:
        return None
    candidate = match.group(1).strip()
    if candidate not in VALID_VERDICTS:
        return None
    return candidate


def parse_verdict_file(path: Path | str) -> Optional[str]:
    """Read red_team.md from disk and parse the VERDICT line."""
    p = Path(path)
    if not p.is_file():
        return None
    try:
        text = p.read_text(encoding="utf-8")
    except OSError:
        return None
    return parse_verdict_text(text)


def red_team_path_for(target: str, finding_id: str, repo_root: Path | str | None = None) -> Path:
    """Canonical evidence path for a red-team review of a single finding."""
    repo = Path(repo_root) if repo_root else BASE_DIR
    return repo / "evidence" / target_storage_key(target) / "findings" / finding_id / "red_team.md"


# ---------------------------------------------------------------------
#  Parent decision routing (R3)
# ---------------------------------------------------------------------

def decision_for(verdict: Optional[str]) -> str:
    """Map VERDICT → parent decision string.

    Mapping per PRD R3:
        no_flaw_found             → keep
        likely_flaw               → demote
        definitive_disqualifier   → kill

    A missing/invalid verdict is treated as `keep` (the worker did not
    find a flaw; the original /validate PASS stands).
    """
    if verdict == VERDICT_DISQUALIFY:
        return DECISION_KILL
    if verdict == VERDICT_LIKELY:
        return DECISION_DEMOTE
    return DECISION_KEEP


def build_audit_record(
    *,
    target: str,
    finding_id: str,
    verdict: Optional[str],
    worker_id: str,
    parent_session: Optional[str],
    rationale: str = "",
) -> dict:
    """Build the audit-log payload parent writes after self-review."""
    return {
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "kind": "self_review",
        "target": target,
        "finding_id": finding_id,
        "verdict": verdict or "missing",
        "decision": decision_for(verdict),
        "worker_id": worker_id,
        "parent_session": parent_session,
        "rationale_snippet": (rationale or "")[:240],
    }


# ---------------------------------------------------------------------
#  False-positive pattern recording (R3 → definitive_disqualifier branch)
# ---------------------------------------------------------------------

def record_disqualifier_as_false_positive(
    *,
    finding: dict,
    target: str,
    journal_path: Path | str | None = None,
) -> Optional[dict]:
    """When verdict is definitive_disqualifier, append a row to
    hunt-memory/journal.jsonl tagging the failed pattern as a false_positive.

    Returns the entry written, or None on schema error / missing input.
    """
    try:
        from memory.hunt_journal import HuntJournal
        from memory.schemas import CURRENT_SCHEMA_VERSION
    except Exception:
        return None
    if journal_path is None:
        journal_path = BASE_DIR / "hunt-memory" / "journal.jsonl"
    journal = HuntJournal(journal_path)
    # Build a schema-compliant journal entry.
    payload = {
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "schema_version": CURRENT_SCHEMA_VERSION,
        "target": target,
        "action": "validate",       # schema enum: hunt/intel/recon/remember/report/resume/validate
        "vuln_class": str(finding.get("vuln_class") or "Unknown"),
        "endpoint": str(finding.get("endpoint") or finding.get("url") or ""),
        "result": "rejected",
        "technique": "adversarial_self_review",
        "notes": "self-review flagged definitive_disqualifier; pattern tagged as false_positive",
    }
    try:
        journal.append(payload)
    except Exception:
        return None
    return payload


# ---------------------------------------------------------------------
#  CLI
# ---------------------------------------------------------------------

def _cmd_parse(args) -> int:
    verdict = parse_verdict_file(args.path)
    decision = decision_for(verdict)
    print(json.dumps({"verdict": verdict, "decision": decision}, indent=2))
    return 0 if verdict is not None else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="self-review verdict parser (B12c)")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("parse", help="parse VERDICT line from a red_team.md path")
    p.add_argument("--path", required=True)
    p.set_defaults(func=_cmd_parse)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
