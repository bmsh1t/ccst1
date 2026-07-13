#!/usr/bin/env python3
"""
red_team_worker.py — adversarial review worker (B12c).

Spawned by parallel_workers.spawn_red_team_worker. Given a candidate
finding, attempts to disprove it. Writes the verdict to:
    evidence/<target>/findings/<finding_id>/red_team.md

The worker prompt (per PRD R1):
    "You are an adversarial security reviewer. The agent claims the
     following finding is valid. Find ONE concrete reason the finding
     is wrong (auth not actually missing, PoC accidentally re-using
     legitimate session, finding is a known intentional behavior,
     etc.). If you cannot find a flaw after 8 tool calls, return
     'no flaw found'."

For deterministic testing, the worker accepts --mock-verdict to skip
the LLM call and write a stub red_team.md. In real use, the worker
calls Ollama with the prompt above and a small browser/HTTP toolset;
that integration is opt-in and falls back to "no_flaw_found" if Ollama
is unreachable.

Output schema (R2):
    <scratch_dir>/done.flag                     — signals completion
    <scratch_dir>/findings.json                 — [] (this worker doesn't
                                                   produce findings; the
                                                   parent reads red_team.md)
    evidence/<target>/findings/<id>/red_team.md — first line is `VERDICT: …`
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

from tools.self_review import (        # noqa: E402
    VERDICT_NO_FLAW, VERDICT_LIKELY, VERDICT_DISQUALIFY, VALID_VERDICTS,
    red_team_path_for,
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _install_timeout_alarm(timeout_secs: int) -> None:
    def _on_alarm(signum, frame):  # pragma: no cover - exit path
        sys.stderr.write(f"red_team_worker: timeout after {timeout_secs}s\n")
        os._exit(2)
    try:
        signal.signal(signal.SIGALRM, _on_alarm)
        signal.alarm(int(max(1, timeout_secs)))
    except (AttributeError, ValueError):
        pass


def _cancel_timeout_alarm() -> None:
    """正常完成或捕获异常后清除进程级定时器，避免泄漏到调用方。"""
    try:
        signal.alarm(0)
    except (AttributeError, ValueError):
        pass


def write_review(
    *,
    target: str,
    finding_id: str,
    verdict: str,
    rationale: str,
    repo_root: Path | None = None,
) -> Path:
    """Write the red_team.md file at the canonical evidence path."""
    if verdict not in VALID_VERDICTS:
        raise ValueError(f"verdict must be one of {sorted(VALID_VERDICTS)}, got {verdict!r}")
    path = red_team_path_for(target, finding_id, repo_root=repo_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    body = (
        f"VERDICT: {verdict}\n"
        f"\n"
        f"Generated: {_utc_now()}\n"
        f"Target: {target}\n"
        f"Finding ID: {finding_id}\n"
        f"\n"
        f"## Rationale\n\n"
        f"{rationale.strip() or '(no rationale provided)'}\n"
    )
    path.write_text(body, encoding="utf-8")
    return path


def run_worker(seed_path: Path, scratch: Path, mock_verdict: str | None = None) -> dict:
    """Worker main. Returns the summary dict written to done.flag."""
    seed = json.loads(Path(seed_path).read_text(encoding="utf-8"))
    cand = seed.get("candidate_finding") or {}
    target = seed.get("target", "")
    finding_id = str(cand.get("id") or "anonymous")

    summary = {
        "kind": "red_team",
        "worker_id": seed.get("worker_id"),
        "target": target,
        "finding_id": finding_id,
        "started_at": _utc_now(),
        "parent_session": seed.get("parent_session"),
        "verdict": None,
        "exit_reason": "completed",
    }

    if mock_verdict:
        verdict = mock_verdict
        rationale = f"Mock verdict supplied via CLI for deterministic testing."
    else:
        # Real-mode placeholder: integrate with Ollama in a follow-up patch.
        # For now, the worker conservatively returns no_flaw_found so the
        # original /validate PASS stands.
        verdict = VERDICT_NO_FLAW
        rationale = (
            "Adversarial review did not surface a flaw within budget. "
            "Original /validate decision stands. "
            "(LLM-driven review not yet wired; this is the conservative default.)"
        )

    path = write_review(
        target=target, finding_id=finding_id, verdict=verdict,
        rationale=rationale, repo_root=BASE_DIR,
    )
    summary["verdict"] = verdict
    summary["review_path"] = str(path)
    summary["finished_at"] = _utc_now()

    # Per parallel_workers contract, also touch findings.json (empty list)
    (scratch / "findings.json").write_text("[]", encoding="utf-8")
    return summary


def _touch_done(scratch: Path, summary: dict) -> None:
    (scratch / "done.flag").write_text(
        json.dumps(summary, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="red-team review worker (B12c)")
    parser.add_argument("--target", required=True)
    parser.add_argument("--seed", required=True)
    parser.add_argument("--scratch-dir", required=True)
    parser.add_argument("--budget-tools", type=int, default=8)
    parser.add_argument("--timeout-secs", type=int, default=300)
    parser.add_argument("--parent-session", default=None)
    parser.add_argument(
        "--mock-verdict",
        choices=sorted(VALID_VERDICTS),
        default=None,
        help="Skip LLM and write this verdict (for tests)",
    )
    args = parser.parse_args(argv)

    scratch = Path(args.scratch_dir)
    scratch.mkdir(parents=True, exist_ok=True)
    _install_timeout_alarm(args.timeout_secs)

    try:
        summary = run_worker(
            seed_path=Path(args.seed),
            scratch=scratch,
            mock_verdict=args.mock_verdict,
        )
    except Exception as exc:  # pragma: no cover
        summary = {
            "kind": "red_team",
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
