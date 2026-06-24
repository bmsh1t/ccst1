#!/usr/bin/env python3
"""
pattern_calibration.py — per-pattern outcome tracking & precision/recall.

PRD: B12d. The `PatternDB.match()` helper exposes hunting leads from
prior wins, but nothing tracks whether those leads ever paid off. This
tool maintains a parallel JSONL of outcome labels and exposes
aggregated stats so `/surface` (and a calibrated PatternDB.match() kwarg)
can deprioritise low-precision patterns.

Outcome labels:
  - helped          — pattern led to a confirmed finding or strong signal
  - no_signal       — pattern was tested but produced no signal
  - false_positive  — pattern misled the agent into wasted attempts

Calibration thresholds:
  - A pattern is excluded ONLY if samples >= 5 AND precision < 0.2.

Layout:
  hunt-memory/pattern_calibration.jsonl   — one record per outcome
  (size-based rotation, 10MB cap, 3 backups; same as patterns.jsonl)
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from memory.rotation import DEFAULT_KEEP, DEFAULT_MAX_BYTES, rotate_if_needed  # noqa: E402


OUTCOME_HELPED = "helped"
OUTCOME_NO_SIGNAL = "no_signal"
OUTCOME_FALSE_POSITIVE = "false_positive"
VALID_OUTCOMES = frozenset({OUTCOME_HELPED, OUTCOME_NO_SIGNAL, OUTCOME_FALSE_POSITIVE})

EXCLUDE_MIN_SAMPLES = 5
EXCLUDE_MAX_PRECISION = 0.2


def default_calibration_path(repo_root: Path | str | None = None) -> Path:
    repo = Path(repo_root) if repo_root else BASE_DIR
    return repo / "hunt-memory" / "pattern_calibration.jsonl"


def pattern_id_for(pattern: dict) -> str:
    """Stable composite ID for a PatternDB entry.

    Patterns don't carry an explicit `id` column — they are uniquely
    identified by (target, vuln_class, technique). The calibration
    pattern_id MUST match this composite so /surface and PatternDB.match()
    can join calibration rows against pattern rows without a schema
    migration.
    """
    return "|".join([
        str(pattern.get("target", "")),
        str(pattern.get("vuln_class", "")),
        str(pattern.get("technique", "")),
    ])


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------------
#  Record (R1, R2, C4)
# ---------------------------------------------------------------------

def record_outcome(
    *,
    pattern_id: str,
    outcome: str,
    session_id: str = "",
    target: str = "",
    path: Path | str | None = None,
    max_bytes: int = DEFAULT_MAX_BYTES,
    keep_backups: int = DEFAULT_KEEP,
) -> dict:
    """Append a calibration row. Returns the validated dict written."""
    if outcome not in VALID_OUTCOMES:
        raise ValueError(f"outcome must be one of {sorted(VALID_OUTCOMES)}, got {outcome!r}")
    if not isinstance(pattern_id, str) or not pattern_id.strip():
        raise ValueError("pattern_id must be a non-empty string")
    record = {
        "ts": _utc_now(),
        "pattern_id": pattern_id.strip(),
        "outcome": outcome,
        "session_id": str(session_id or ""),
        "target": str(target or ""),
    }
    target_path = Path(path) if path else default_calibration_path()
    target_path.parent.mkdir(parents=True, exist_ok=True)

    rotate_if_needed(target_path, max_bytes=max_bytes, keep=keep_backups)
    line = (json.dumps(record, separators=(",", ":")) + "\n").encode("utf-8")
    fd = os.open(str(target_path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            os.write(fd, line)
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)
    return record


def read_all(path: Path | str | None = None) -> list[dict]:
    """Stream the calibration JSONL. Corrupt lines are skipped silently."""
    target_path = Path(path) if path else default_calibration_path()
    if not target_path.exists():
        return []
    out: list[dict] = []
    with open(target_path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(row, dict):
                continue
            if row.get("outcome") not in VALID_OUTCOMES:
                continue
            if not row.get("pattern_id"):
                continue
            out.append(row)
    return out


# ---------------------------------------------------------------------
#  Aggregate (R3)
# ---------------------------------------------------------------------

def summarise(path: Path | str | None = None) -> list[dict]:
    """Aggregate per-pattern stats.

    Returns a list of dicts sorted by samples descending:
        [
          {pattern_id, samples, helped, no_signal, false_positive,
           precision, recall_proxy},
          ...
        ]
    Where:
        precision      = helped / (helped + false_positive)   (None if denom=0)
        recall_proxy   = helped / samples
    """
    rows = read_all(path)
    counts_by_pid: dict[str, Counter[str]] = {}
    for r in rows:
        pid = r["pattern_id"]
        counts_by_pid.setdefault(pid, Counter())[r["outcome"]] += 1

    stats: list[dict] = []
    for pid, counter in counts_by_pid.items():
        helped = counter.get(OUTCOME_HELPED, 0)
        no_signal = counter.get(OUTCOME_NO_SIGNAL, 0)
        fp = counter.get(OUTCOME_FALSE_POSITIVE, 0)
        samples = helped + no_signal + fp
        precision_denom = helped + fp
        precision = (helped / precision_denom) if precision_denom > 0 else None
        recall_proxy = (helped / samples) if samples > 0 else None
        stats.append({
            "pattern_id": pid,
            "samples": samples,
            "helped": helped,
            "no_signal": no_signal,
            "false_positive": fp,
            "precision": precision,
            "recall_proxy": recall_proxy,
        })
    stats.sort(key=lambda d: (d["samples"], d["helped"]), reverse=True)
    return stats


def excluded_pattern_ids(
    path: Path | str | None = None,
    *,
    min_samples: int = EXCLUDE_MIN_SAMPLES,
    max_precision: float = EXCLUDE_MAX_PRECISION,
) -> set[str]:
    """Pattern IDs to deprioritise when `calibrated=True`. Per PRD R4."""
    out: set[str] = set()
    for row in summarise(path):
        precision = row.get("precision")
        if row["samples"] >= min_samples and precision is not None and precision < max_precision:
            out.add(row["pattern_id"])
    return out


# ---------------------------------------------------------------------
#  CLI (R3)
# ---------------------------------------------------------------------

def _cmd_record(args) -> int:
    rec = record_outcome(
        pattern_id=args.pattern_id,
        outcome=args.outcome,
        session_id=args.session_id or "",
        target=args.target or "",
        path=args.path,
    )
    print(json.dumps(rec, indent=2))
    return 0


def _cmd_summarise(args) -> int:
    rows = summarise(args.path)
    if args.format == "json":
        print(json.dumps(rows, indent=2))
    else:
        # text — table
        if not rows:
            print("no calibration data")
            return 0
        header = ["pattern_id", "samples", "helped", "no_signal", "fp", "precision", "recall_proxy"]
        widths = [max(len(h), 12) for h in header]
        print("  ".join(h.ljust(w) for h, w in zip(header, widths)))
        for r in rows:
            prec = f"{r['precision']:.2f}" if r["precision"] is not None else "n/a"
            rec = f"{r['recall_proxy']:.2f}" if r["recall_proxy"] is not None else "n/a"
            row = [
                r["pattern_id"],
                str(r["samples"]),
                str(r["helped"]),
                str(r["no_signal"]),
                str(r["false_positive"]),
                prec,
                rec,
            ]
            print("  ".join(c.ljust(w) for c, w in zip(row, widths)))
    return 0


def _cmd_excluded(args) -> int:
    ids = sorted(excluded_pattern_ids(args.path))
    print(json.dumps(ids, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="pattern calibration loop (B12d)")
    parser.add_argument("--path", default=None, help="alt JSONL path (default hunt-memory/pattern_calibration.jsonl)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    rec = sub.add_parser("record", help="record a per-match outcome")
    rec.add_argument("--pattern-id", required=True)
    rec.add_argument("--outcome", required=True, choices=sorted(VALID_OUTCOMES))
    rec.add_argument("--session-id", default="")
    rec.add_argument("--target", default="")
    rec.set_defaults(func=_cmd_record)

    s = sub.add_parser("summarise", help="aggregate precision/recall per pattern")
    s.add_argument("--format", choices=("json", "text"), default="json")
    s.set_defaults(func=_cmd_summarise)

    ex = sub.add_parser("excluded", help="list pattern_ids excluded by calibration")
    ex.set_defaults(func=_cmd_excluded)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
