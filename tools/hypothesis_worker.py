#!/usr/bin/env python3
"""
hypothesis_worker.py — single-hypothesis execution worker (B12a).

Spawned by parallel_workers.spawn_hypothesis_worker. Tests ONE seed
hypothesis to completion. The worker is intentionally narrow — it
inspects the cached recon URLs that match the hypothesis's hint
patterns and records observations, then writes findings.json when a
strong signal emerges.

For deterministic testing the worker supports --mock-mode which seeds
findings.json from the seed payload's `mock_outcome` field. In real
use the worker would dispatch to Ollama with the hypothesis text.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import sys
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _install_timeout_alarm(timeout_secs: int) -> None:
    def _on_alarm(signum, frame):  # pragma: no cover - exit path
        sys.stderr.write(f"hypothesis_worker: timeout after {timeout_secs}s\n")
        os._exit(2)
    try:
        signal.signal(signal.SIGALRM, _on_alarm)
        signal.alarm(int(max(1, timeout_secs)))
    except (AttributeError, ValueError):
        pass


def _cancel_timeout_alarm() -> None:
    try:
        signal.alarm(0)
    except (AttributeError, ValueError):
        pass


def run_worker(seed_path: Path, scratch: Path, *, mock_mode: bool = False) -> dict:
    seed = json.loads(Path(seed_path).read_text(encoding="utf-8"))
    hypothesis = seed.get("hypothesis") or {}

    summary = {
        "kind": "hypothesis",
        "worker_id": seed.get("worker_id"),
        "target": seed.get("target"),
        "hypothesis_id": str(hypothesis.get("id") or seed.get("worker_id")),
        "working_hypothesis": str(hypothesis.get("working_hypothesis") or ""),
        "started_at": _utc_now(),
        "parent_session": seed.get("parent_session"),
        "outcome": "leads_only",
        "exit_reason": "completed",
    }

    findings = []
    # Mock-mode seeds findings.json from the hypothesis payload for tests
    if mock_mode:
        mock = hypothesis.get("mock_outcome") or {}
        outcome = str(mock.get("outcome") or "leads_only")
        for f in mock.get("findings", []) or []:
            findings.append(dict(f))
        summary["outcome"] = outcome
    else:  # pragma: no cover - real-mode placeholder
        # Real-mode: the worker would dispatch the hypothesis to an LLM
        # with a small HTTP toolset. For now we conservatively record
        # leads only.
        summary["outcome"] = "leads_only"

    (scratch / "findings.json").write_text(json.dumps(findings, indent=2), encoding="utf-8")
    summary["finished_at"] = _utc_now()
    return summary


def _touch_done(scratch: Path, summary: dict) -> None:
    (scratch / "done.flag").write_text(
        json.dumps(summary, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="hypothesis worker (B12a)")
    parser.add_argument("--target", required=True)
    parser.add_argument("--seed", required=True)
    parser.add_argument("--scratch-dir", required=True)
    parser.add_argument("--budget-tools", type=int, default=12)
    parser.add_argument("--timeout-secs", type=int, default=300)
    parser.add_argument("--parent-session", default=None)
    parser.add_argument("--mock-mode", action="store_true",
                        help="Skip LLM and use the seed's mock_outcome (tests)")
    args = parser.parse_args(argv)

    scratch = Path(args.scratch_dir)
    scratch.mkdir(parents=True, exist_ok=True)
    _install_timeout_alarm(args.timeout_secs)

    try:
        summary = run_worker(
            seed_path=Path(args.seed),
            scratch=scratch,
            mock_mode=args.mock_mode,
        )
    except Exception as exc:  # pragma: no cover
        summary = {
            "kind": "hypothesis",
            "target": args.target,
            "exit_reason": f"worker_exception:{exc}",
            "finished_at": _utc_now(),
        }
    finally:
        _touch_done(scratch, summary)
        _cancel_timeout_alarm()
    return 0


if __name__ == "__main__":
    sys.exit(main())
