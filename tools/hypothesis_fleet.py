#!/usr/bin/env python3
"""
hypothesis_fleet.py — fan-out, join, and ranking for B12a.

Given N viable working_hypothesis candidates and a parallel budget M:
  * spawn up to M hypothesis workers (parallel_workers.spawn_hypothesis_worker)
  * queue the remainder for a follow-up wave
  * wait for the first wave to join, then run any queued hypotheses
  * rank worker outcomes at join time and pick the single most-converged
    hypothesis as the continuing thread
  * demote the rest to hunt-memory/journal.jsonl as parallel leads

Outcome ranking (PRD R3):
    validated_finding > strong_signal > leads_only
"""

from __future__ import annotations

import json
import sys
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from tools import parallel_workers as pw       # noqa: E402


OUTCOME_VALIDATED = "validated_finding"
OUTCOME_STRONG = "strong_signal"
OUTCOME_LEADS = "leads_only"

_OUTCOME_RANK = {
    OUTCOME_VALIDATED: 3,
    OUTCOME_STRONG: 2,
    OUTCOME_LEADS: 1,
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------------
#  Fanout planning (R1, C4)
# ---------------------------------------------------------------------

def plan_fanout(hypotheses: list[dict], max_parallel: int) -> tuple[list[dict], list[dict]]:
    """Split hypotheses into (first_wave, queue).

    first_wave is up to max_parallel entries.
    queue contains the remainder, FIFO.
    """
    if max_parallel <= 0:
        max_parallel = 1
    first = list(hypotheses)[:max_parallel]
    rest = list(hypotheses)[max_parallel:]
    return first, rest


# ---------------------------------------------------------------------
#  Outcome classification (per worker done.flag summary)
# ---------------------------------------------------------------------

def classify_worker_outcome(result: pw.WorkerResult, done_flag_summary: dict | None = None) -> str:
    """Map worker result → ranking bucket.

    Rules:
      * if findings.json contains rows with `severity in (high,critical)` → validated_finding
      * if findings.json contains ANY row → strong_signal
      * if done_flag_summary["outcome"] is one of the OUTCOME_* constants → use it
      * else → leads_only
    """
    if not result.findings:
        if done_flag_summary and done_flag_summary.get("outcome") in _OUTCOME_RANK:
            return done_flag_summary["outcome"]
        return OUTCOME_LEADS
    # Prefer findings-based judgement; promote to validated only if a high-sev row is present
    has_high = any(
        str(f.get("severity") or "").lower() in {"high", "critical"}
        for f in result.findings
    )
    if has_high:
        return OUTCOME_VALIDATED
    return OUTCOME_STRONG


# ---------------------------------------------------------------------
#  Ranking + winner selection (R3)
# ---------------------------------------------------------------------

def rank_results(results: Iterable[pw.WorkerResult]) -> list[dict]:
    """Rank workers; return a list sorted highest-rank first.

    Each entry:
        {
          worker_id, hypothesis_id, outcome, rank, finding_count,
          scratch_dir, parent_session, working_hypothesis (if available)
        }
    """
    out: list[dict] = []
    for r in results:
        summary = _read_done_summary(r)
        outcome = classify_worker_outcome(r, done_flag_summary=summary)
        out.append({
            "worker_id": r.worker_id,
            "hypothesis_id": (summary or {}).get("hypothesis_id") or r.worker_id,
            "working_hypothesis": (summary or {}).get("working_hypothesis", ""),
            "outcome": outcome,
            "rank": _OUTCOME_RANK[outcome],
            "finding_count": len(r.findings),
            "scratch_dir": r.scratch_dir,
            "parent_session": r.parent_session,
        })
    out.sort(key=lambda d: (d["rank"], d["finding_count"]), reverse=True)
    return out


def pick_winner(ranked: list[dict]) -> Optional[dict]:
    """Return the single highest-rank hypothesis to continue, or None."""
    return ranked[0] if ranked else None


def _read_done_summary(result: pw.WorkerResult) -> dict | None:
    path = Path(result.scratch_dir) / "done.flag"
    if not path.is_file():
        return None
    try:
        text = path.read_text(encoding="utf-8").strip()
        if not text:
            return None
        return json.loads(text.splitlines()[0])
    except (OSError, ValueError):
        return None


# ---------------------------------------------------------------------
#  Demote losers to hunt-memory journal (R3)
# ---------------------------------------------------------------------

def demote_losers_to_journal(
    ranked: list[dict],
    winner: dict | None,
    target: str,
    *,
    journal_path: Path | str | None = None,
) -> list[dict]:
    """Append a journal row for each non-winning hypothesis as a parallel lead."""
    if not ranked or winner is None:
        return []
    try:
        from memory.hunt_journal import HuntJournal
        from memory.schemas import CURRENT_SCHEMA_VERSION
    except Exception:
        return []
    if journal_path is None:
        journal_path = BASE_DIR / "hunt-memory" / "journal.jsonl"
    journal = HuntJournal(journal_path)
    written: list[dict] = []
    for entry in ranked:
        if entry["worker_id"] == winner["worker_id"]:
            continue
        # The schema requires action ∈ {hunt,intel,recon,remember,report,resume,validate}
        payload = {
            "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "schema_version": CURRENT_SCHEMA_VERSION,
            "target": target,
            "action": "hunt",
            "vuln_class": "Unknown",
            "endpoint": "",
            "result": "partial",
            "technique": "parallel_hypothesis_lead",
            "notes": (
                f"parallel-hypothesis demoted lead from worker {entry['worker_id']}; "
                f"outcome={entry['outcome']}; hypothesis={entry['working_hypothesis']}"
            )[:1000],
        }
        try:
            journal.append(payload)
            written.append(payload)
        except Exception:
            continue
    return written


# ---------------------------------------------------------------------
#  Audit record (R5)
# ---------------------------------------------------------------------

def build_audit_records(
    ranked: list[dict],
    *,
    parent_session: Optional[str],
) -> list[dict]:
    """Return one audit-style row per worker carrying hypothesis_id."""
    out: list[dict] = []
    for r in ranked:
        out.append({
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "kind": "hypothesis_fanout",
            "worker_id": r["worker_id"],
            "hypothesis_id": r["hypothesis_id"],
            "outcome": r["outcome"],
            "rank": r["rank"],
            "finding_count": r["finding_count"],
            "parent_session": parent_session or r.get("parent_session"),
        })
    return out


# ---------------------------------------------------------------------
#  End-to-end fanout (R1, R3, C4)
# ---------------------------------------------------------------------

def run_fanout(
    hypotheses: list[dict],
    target: str,
    *,
    max_parallel: int = 3,
    repo_root: Path | None = None,
    parent_session: Optional[str] = None,
    spawn=pw.spawn_hypothesis_worker,
    wait=pw.wait_for_workers,
    timeout_secs: int = pw.DEFAULT_TIMEOUT_SECS,
) -> dict:
    """Run the full fanout → wait → queue overflow → rank → demote cycle.

    `spawn` and `wait` are injectable for tests.
    """
    queue = deque(hypotheses)
    all_results: list[pw.WorkerResult] = []
    wave = 1
    while queue:
        first_wave = []
        for _ in range(max_parallel):
            if not queue:
                break
            first_wave.append(queue.popleft())
        handles = []
        for i, hyp in enumerate(first_wave):
            worker_id = f"hyp-w{wave}-{i}"
            handles.append(spawn(
                hypothesis=hyp,
                worker_id=worker_id,
                target=target,
                repo_root=repo_root,
                parent_session=parent_session,
            ))
        results = wait(handles, timeout_secs=timeout_secs)
        all_results.extend(results)
        wave += 1

    ranked = rank_results(all_results)
    winner = pick_winner(ranked)
    demoted = demote_losers_to_journal(ranked, winner, target)
    audit_rows = build_audit_records(ranked, parent_session=parent_session)
    return {
        "workers_total": len(all_results),
        "ranked": ranked,
        "winner": winner,
        "demoted_count": len(demoted),
        "audit_rows": audit_rows,
    }
