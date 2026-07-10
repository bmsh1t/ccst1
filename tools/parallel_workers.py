#!/usr/bin/env python3
"""
parallel_workers.py — sibling-probe & hypothesis worker spawn primitive.

Phase 4 R6 (B6) foundation. Spawns isolated sub-process workers that
each test ONE focused candidate (a sibling probe, a hypothesis seed, a
red-team review, etc.) against a target. Workers write only to their
own scratch directory and signal completion by touching `done.flag`.

Reuse model:
    - B6   sibling-probe execution                  → spawn_sibling_worker
    - B12a parallel hypothesis fleet                → spawn_hypothesis_worker
    - B12c adversarial self-review                  → spawn_red_team_worker
    - B12b vision playwright                        → orthogonal (no worker)
    - B12d pattern calibration                      → orthogonal (no worker)

Concurrency model:
    Each worker is a separate Python process started via subprocess.Popen.
    Per-worker isolation directory:
        evidence/<target>/workers/<kind>-<worker_id>/
        ├── attempts.jsonl   # one row per HTTP attempt
        ├── findings.json    # confirmed findings
        ├── seed.json        # input payload (read-only for the worker)
        ├── log.txt          # worker stdout+stderr
        └── done.flag        # touched on completion

Global rate-limiter coordination (B6 R10):
    A small JSON state file at hunt-memory/audit/parallel_lock.json is
    locked via fcntl.flock for cross-process per-host pacing. The state
    is a dict of host -> last_request_epoch. Workers acquire the lock,
    check elapsed, sleep if needed, then update + release.
"""

from __future__ import annotations

import fcntl
import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

try:
    from tools.target_paths import target_storage_key
except ImportError:  # pragma: no cover - direct tools/ execution
    from target_paths import target_storage_key  # type: ignore


DEFAULT_BUDGET_TOOLS = 12
DEFAULT_TIMEOUT_SECS = 300        # 5 minutes per worker
DEFAULT_MAX_PARALLEL = 3
PARANOID_MAX_PARALLEL = 1
YOLO_MAX_PARALLEL = 8
RATE_LIMITER_SAFETY_MARGIN = 0.10  # 10% per B6 R10


# ---------------------------------------------------------------------
#  Dataclasses
# ---------------------------------------------------------------------

@dataclass
class WorkerHandle:
    """Reference to a running or completed worker subprocess."""

    worker_id: str
    kind: str                  # "sibling" | "hypothesis" | "red_team"
    target: str
    scratch_dir: str           # absolute path
    seed_path: str             # absolute path to seed.json
    proc: Optional[subprocess.Popen] = None
    started_at: str = ""
    budget_tools: int = DEFAULT_BUDGET_TOOLS
    timeout_secs: int = DEFAULT_TIMEOUT_SECS
    parent_session: Optional[str] = None

    @property
    def done_flag(self) -> Path:
        return Path(self.scratch_dir) / "done.flag"

    @property
    def findings_path(self) -> Path:
        return Path(self.scratch_dir) / "findings.json"

    @property
    def attempts_path(self) -> Path:
        return Path(self.scratch_dir) / "attempts.jsonl"

    @property
    def log_path(self) -> Path:
        return Path(self.scratch_dir) / "log.txt"

    def is_complete(self) -> bool:
        return self.done_flag.exists()

    def to_dict(self) -> dict:
        return {
            "worker_id": self.worker_id,
            "kind": self.kind,
            "target": self.target,
            "scratch_dir": self.scratch_dir,
            "seed_path": self.seed_path,
            "started_at": self.started_at,
            "budget_tools": self.budget_tools,
            "timeout_secs": self.timeout_secs,
            "parent_session": self.parent_session,
        }


@dataclass
class WorkerResult:
    """Outcome of a worker after join."""

    worker_id: str
    kind: str
    scratch_dir: str
    completed: bool          # done.flag was touched
    timed_out: bool          # parent reaped on timeout
    exit_code: Optional[int]
    findings: list[dict] = field(default_factory=list)
    attempt_count: int = 0
    parent_session: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------
#  Mode coercion (B6 R7, R8)
# ---------------------------------------------------------------------

def coerce_max_parallel(requested: int, mode: str) -> int:
    """Apply mode-aware caps to --max-parallel.

    paranoid: forces 1
    normal:   honours request (cap DEFAULT_MAX_PARALLEL=3)
    yolo:     honours request (cap YOLO_MAX_PARALLEL=8)
    """
    requested = max(1, int(requested or DEFAULT_MAX_PARALLEL))
    mode = (mode or "normal").lower()
    if mode == "paranoid":
        return PARANOID_MAX_PARALLEL
    if mode == "yolo":
        return min(requested, YOLO_MAX_PARALLEL)
    return min(requested, DEFAULT_MAX_PARALLEL)


# ---------------------------------------------------------------------
#  Scratch dir setup (B6 R2, C5)
# ---------------------------------------------------------------------

def _scratch_dir_for(target: str, kind: str, worker_id: str, repo_root: Path) -> Path:
    """Build the per-worker scratch dir path.

    Layout: evidence/<target>/workers/<kind>-<worker_id>/
    """
    return repo_root / "evidence" / target_storage_key(target) / "workers" / f"{kind}-{worker_id}"


def _prepare_scratch(scratch_dir: Path) -> None:
    """Create empty scratch dir, removing any prior contents."""
    if scratch_dir.exists():
        shutil.rmtree(scratch_dir)
    scratch_dir.mkdir(parents=True, exist_ok=True)
    # Pre-create empty files so consumers can read them safely.
    (scratch_dir / "attempts.jsonl").touch()
    (scratch_dir / "findings.json").write_text("[]", encoding="utf-8")


# ---------------------------------------------------------------------
#  Spawn primitives (B6 R1, B12a, B12c)
# ---------------------------------------------------------------------

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _start_worker_proc(
    *,
    worker_script: Path,
    seed_path: Path,
    scratch_dir: Path,
    target: str,
    budget_tools: int,
    timeout_secs: int,
    parent_session: Optional[str],
    extra_args: Optional[list[str]] = None,
    env_overrides: Optional[dict] = None,
) -> subprocess.Popen:
    """Start the worker subprocess; stdout+stderr → scratch_dir/log.txt."""
    log_handle = open(scratch_dir / "log.txt", "wb")
    cmd = [
        sys.executable,
        str(worker_script),
        "--target", target,
        "--seed", str(seed_path),
        "--scratch-dir", str(scratch_dir),
        "--budget-tools", str(budget_tools),
        "--timeout-secs", str(timeout_secs),
    ]
    if parent_session:
        cmd += ["--parent-session", parent_session]
    if extra_args:
        cmd += list(extra_args)
    env = os.environ.copy()
    if env_overrides:
        env.update(env_overrides)
    return subprocess.Popen(
        cmd,
        stdout=log_handle,
        stderr=subprocess.STDOUT,
        cwd=str(BASE_DIR),
        env=env,
        start_new_session=True,
    )


def spawn_sibling_worker(
    seed_finding: dict,
    worker_id: str,
    target: str,
    *,
    repo_root: Optional[Path] = None,
    budget_tools: int = DEFAULT_BUDGET_TOOLS,
    timeout_secs: int = DEFAULT_TIMEOUT_SECS,
    parent_session: Optional[str] = None,
    auto_start: bool = True,
) -> WorkerHandle:
    """Spawn a sibling-probe worker for one seed finding.

    seed_finding must include at least `id` and `endpoint`. The worker
    will use sibling_generator to expand the seed into a probe queue
    and HTTP-test each one, writing findings.json with confirmed
    sibling findings.
    """
    repo = Path(repo_root) if repo_root else BASE_DIR
    scratch = _scratch_dir_for(target, "sibling", worker_id, repo)
    _prepare_scratch(scratch)

    seed_payload = {
        "kind": "sibling",
        "worker_id": worker_id,
        "target": target,
        "seed_finding": dict(seed_finding),
        "parent_session": parent_session,
        "queued_at": _utc_now(),
    }
    seed_path = scratch / "seed.json"
    seed_path.write_text(json.dumps(seed_payload, indent=2), encoding="utf-8")

    handle = WorkerHandle(
        worker_id=worker_id,
        kind="sibling",
        target=target,
        scratch_dir=str(scratch),
        seed_path=str(seed_path),
        started_at=_utc_now(),
        budget_tools=budget_tools,
        timeout_secs=timeout_secs,
        parent_session=parent_session,
    )

    if auto_start:
        worker_script = BASE_DIR / "tools" / "sibling_worker.py"
        handle.proc = _start_worker_proc(
            worker_script=worker_script,
            seed_path=seed_path,
            scratch_dir=scratch,
            target=target,
            budget_tools=budget_tools,
            timeout_secs=timeout_secs,
            parent_session=parent_session,
        )
    return handle


def spawn_hypothesis_worker(
    hypothesis: dict,
    worker_id: str,
    target: str,
    *,
    repo_root: Optional[Path] = None,
    budget_tools: int = DEFAULT_BUDGET_TOOLS,
    timeout_secs: int = DEFAULT_TIMEOUT_SECS,
    parent_session: Optional[str] = None,
    auto_start: bool = True,
) -> WorkerHandle:
    """Spawn a hypothesis worker (B12a)."""
    repo = Path(repo_root) if repo_root else BASE_DIR
    scratch = _scratch_dir_for(target, "hypothesis", worker_id, repo)
    _prepare_scratch(scratch)

    seed_payload = {
        "kind": "hypothesis",
        "worker_id": worker_id,
        "target": target,
        "hypothesis": dict(hypothesis),
        "parent_session": parent_session,
        "queued_at": _utc_now(),
    }
    seed_path = scratch / "seed.json"
    seed_path.write_text(json.dumps(seed_payload, indent=2), encoding="utf-8")

    # Also write a human-readable seed (per B12a R2)
    (scratch / "hypothesis.md").write_text(
        f"# Hypothesis seed for worker {worker_id}\n\n"
        f"target: {target}\n"
        f"working_hypothesis: {hypothesis.get('working_hypothesis', '')}\n"
        f"queued_at: {seed_payload['queued_at']}\n",
        encoding="utf-8",
    )

    handle = WorkerHandle(
        worker_id=worker_id,
        kind="hypothesis",
        target=target,
        scratch_dir=str(scratch),
        seed_path=str(seed_path),
        started_at=_utc_now(),
        budget_tools=budget_tools,
        timeout_secs=timeout_secs,
        parent_session=parent_session,
    )

    if auto_start:
        worker_script = BASE_DIR / "tools" / "hypothesis_worker.py"
        handle.proc = _start_worker_proc(
            worker_script=worker_script,
            seed_path=seed_path,
            scratch_dir=scratch,
            target=target,
            budget_tools=budget_tools,
            timeout_secs=timeout_secs,
            parent_session=parent_session,
        )
    return handle


def spawn_red_team_worker(
    candidate_finding: dict,
    worker_id: str,
    target: str,
    *,
    repo_root: Optional[Path] = None,
    budget_tools: int = 8,        # B12c C2: smaller budget
    timeout_secs: int = DEFAULT_TIMEOUT_SECS,
    parent_session: Optional[str] = None,
    auto_start: bool = True,
) -> WorkerHandle:
    """Spawn an adversarial red-team review worker (B12c)."""
    repo = Path(repo_root) if repo_root else BASE_DIR
    scratch = _scratch_dir_for(target, "red_team", worker_id, repo)
    _prepare_scratch(scratch)

    seed_payload = {
        "kind": "red_team",
        "worker_id": worker_id,
        "target": target,
        "candidate_finding": dict(candidate_finding),
        "parent_session": parent_session,
        "queued_at": _utc_now(),
    }
    seed_path = scratch / "seed.json"
    seed_path.write_text(json.dumps(seed_payload, indent=2), encoding="utf-8")

    handle = WorkerHandle(
        worker_id=worker_id,
        kind="red_team",
        target=target,
        scratch_dir=str(scratch),
        seed_path=str(seed_path),
        started_at=_utc_now(),
        budget_tools=budget_tools,
        timeout_secs=timeout_secs,
        parent_session=parent_session,
    )

    if auto_start:
        worker_script = BASE_DIR / "tools" / "red_team_worker.py"
        handle.proc = _start_worker_proc(
            worker_script=worker_script,
            seed_path=seed_path,
            scratch_dir=scratch,
            target=target,
            budget_tools=budget_tools,
            timeout_secs=timeout_secs,
            parent_session=parent_session,
        )
    return handle


# ---------------------------------------------------------------------
#  Join helper (B6 R5, R4)
# ---------------------------------------------------------------------

def _read_json_safely(path: Path, default):
    try:
        text = path.read_text(encoding="utf-8")
        if not text.strip():
            return default
        return json.loads(text)
    except (OSError, ValueError):
        return default


def _count_lines(path: Path) -> int:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return sum(1 for _ in fh)
    except OSError:
        return 0


def _reap_handle(handle: WorkerHandle, timed_out: bool) -> WorkerResult:
    """Build a WorkerResult from a handle; do not delete scratch."""
    completed = handle.is_complete()
    findings = _read_json_safely(handle.findings_path, [])
    if not isinstance(findings, list):
        findings = []
    attempt_count = _count_lines(handle.attempts_path)
    exit_code: Optional[int] = None
    if handle.proc is not None:
        try:
            exit_code = handle.proc.poll()
            if exit_code is None and timed_out:
                # Worker still running on timeout — terminate group.
                try:
                    os.killpg(os.getpgid(handle.proc.pid), 15)  # SIGTERM
                except (ProcessLookupError, PermissionError, OSError):
                    pass
                try:
                    exit_code = handle.proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(os.getpgid(handle.proc.pid), 9)  # SIGKILL
                    except (ProcessLookupError, PermissionError, OSError):
                        pass
                    exit_code = handle.proc.wait(timeout=2)
        except Exception:
            exit_code = None
    return WorkerResult(
        worker_id=handle.worker_id,
        kind=handle.kind,
        scratch_dir=handle.scratch_dir,
        completed=completed,
        timed_out=timed_out and not completed,
        exit_code=exit_code,
        findings=findings,
        attempt_count=attempt_count,
        parent_session=handle.parent_session,
    )


def wait_for_workers(
    handles: Iterable[WorkerHandle],
    *,
    timeout_secs: int = DEFAULT_TIMEOUT_SECS,
    poll_interval_secs: float = 0.25,
    clock=time.monotonic,
    sleep=time.sleep,
) -> list[WorkerResult]:
    """Block until all handles complete OR aggregate timeout reached.

    Each handle's per-worker timeout still applies — workers terminate
    themselves at budget exhaustion. The aggregate `timeout_secs`
    stops the parent's polling loop and reaps any laggards.
    """
    handles = list(handles)
    if not handles:
        return []
    deadline = clock() + max(0.5, float(timeout_secs))
    while clock() < deadline:
        if all(h.is_complete() for h in handles):
            break
        sleep(poll_interval_secs)
    results: list[WorkerResult] = []
    for h in handles:
        timed_out = not h.is_complete()
        results.append(_reap_handle(h, timed_out=timed_out))
    return results


# ---------------------------------------------------------------------
#  Parent join + dedup + matrix-rebuild (B6 R6)
# ---------------------------------------------------------------------

def _consolidate_findings(results: Iterable[WorkerResult]) -> list[dict]:
    """Flatten worker findings + dedup by (endpoint, vuln_class)."""
    severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    seen: dict[tuple[str, str], dict] = {}
    for r in results:
        for f in r.findings:
            ep = str(f.get("endpoint") or f.get("url") or "")
            vc = str(f.get("vuln_class") or f.get("type") or "")
            if not ep:
                continue
            key = (ep, vc.lower())
            sev = str(f.get("severity") or "info").lower()
            f_with_origin = dict(f)
            f_with_origin.setdefault("worker_id", r.worker_id)
            existing = seen.get(key)
            if existing is None:
                seen[key] = f_with_origin
                continue
            existing_sev = str(existing.get("severity") or "info").lower()
            if severity_order.get(sev, 0) > severity_order.get(existing_sev, 0):
                seen[key] = f_with_origin
    return list(seen.values())


def _append_to_target_findings(target: str, new_findings: list[dict], repo: Path) -> int:
    """Append consolidated rows to findings/<target>/findings.json.

    Returns count of rows actually appended (after de-dup against existing).
    """
    findings_path = repo / "findings" / target_storage_key(target) / "findings.json"
    findings_path.parent.mkdir(parents=True, exist_ok=True)
    existing = _read_json_safely(findings_path, [])
    if not isinstance(existing, list):
        existing = []
    seen_keys = {
        (str(f.get("endpoint") or f.get("url") or ""), str(f.get("vuln_class") or "").lower())
        for f in existing
    }
    appended = 0
    for f in new_findings:
        key = (str(f.get("endpoint") or f.get("url") or ""), str(f.get("vuln_class") or "").lower())
        if key in seen_keys:
            continue
        existing.append(f)
        seen_keys.add(key)
        appended += 1
    findings_path.write_text(json.dumps(existing, indent=2), encoding="utf-8")
    return appended


def _trigger_matrix_rebuild(target: str, repo: Path) -> bool:
    """Re-run coverage_matrix.rebuild after worker join. Returns True on success."""
    try:
        from tools import coverage_matrix      # type: ignore
    except Exception:
        return False
    try:
        coverage_matrix.rebuild_matrix(target, repo_root=repo)
        return True
    except Exception:
        return False


def join_and_consolidate(
    results: Iterable[WorkerResult],
    target: str,
    *,
    repo_root: Optional[Path] = None,
) -> dict:
    """Apply B6 R6: dedup, append, rebuild matrix, emit a summary dict."""
    repo = Path(repo_root) if repo_root else BASE_DIR
    results = list(results)
    consolidated = _consolidate_findings(results)
    appended = _append_to_target_findings(target, consolidated, repo)
    rebuilt = _trigger_matrix_rebuild(target, repo)
    return {
        "workers_total": len(results),
        "workers_completed": sum(1 for r in results if r.completed),
        "workers_timed_out": sum(1 for r in results if r.timed_out),
        "consolidated_findings": len(consolidated),
        "appended_to_findings": appended,
        "matrix_rebuilt": rebuilt,
    }


# ---------------------------------------------------------------------
#  Global rate-limiter coordination (B6 R10)
# ---------------------------------------------------------------------

class GlobalRateLimiter:
    """File-locked per-host rate limiter for cross-process coordination.

    State file at hunt-memory/audit/parallel_lock.json is a JSON dict:
        {
          "host": {"last_request_epoch": float, "interval": float},
          ...
        }
    Workers acquire fcntl.LOCK_EX, sleep until the per-host interval has
    elapsed since the last recorded request, update last_request_epoch,
    then release.

    The active-worker count is read on each call to derive a per-worker
    sub-budget (host_interval × worker_count × (1 + safety_margin)).
    """

    def __init__(
        self,
        state_path: Path | str | None = None,
        *,
        recon_rps: float = 10.0,
        test_rps: float = 1.0,
        worker_count: int = 1,
        safety_margin: float = RATE_LIMITER_SAFETY_MARGIN,
    ):
        if state_path is None:
            state_path = BASE_DIR / "hunt-memory" / "audit" / "parallel_lock.json"
        self.state_path = Path(state_path)
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.state_path.exists():
            self.state_path.write_text("{}", encoding="utf-8")
        self.recon_interval = 1.0 / max(0.001, recon_rps)
        self.test_interval = 1.0 / max(0.001, test_rps)
        self.worker_count = max(1, int(worker_count))
        self.safety_margin = float(safety_margin)

    def _per_worker_interval(self, base_interval: float) -> float:
        # Each worker's share = base × worker_count × (1 + safety_margin).
        # With N workers running concurrently, this keeps the aggregate
        # request rate at or below 1/base_interval rps.
        return base_interval * self.worker_count * (1.0 + self.safety_margin)

    def wait(self, host: str, *, is_recon: bool = False, sleep=time.sleep) -> float:
        """Acquire lock, enforce per-worker interval against host, return secs slept."""
        base_interval = self.recon_interval if is_recon else self.test_interval
        interval = self._per_worker_interval(base_interval)
        slept = 0.0
        fd = os.open(str(self.state_path), os.O_RDWR | os.O_CREAT, 0o644)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                state = self._read_state(fd)
                now = time.time()
                last = float(state.get(host, {}).get("last_request_epoch", 0.0))
                elapsed = now - last
                wait_time = max(0.0, interval - elapsed)
                if wait_time > 0:
                    sleep(wait_time)
                    slept = wait_time
                state[host] = {
                    "last_request_epoch": time.time(),
                    "interval": interval,
                }
                self._write_state(fd, state)
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)
        return slept

    def _read_state(self, fd: int) -> dict:
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            raw = os.read(fd, 65536)
            if not raw:
                return {}
            return json.loads(raw.decode("utf-8") or "{}")
        except (ValueError, OSError):
            return {}

    def _write_state(self, fd: int, state: dict) -> None:
        encoded = json.dumps(state, separators=(",", ":")).encode("utf-8")
        os.lseek(fd, 0, os.SEEK_SET)
        os.ftruncate(fd, 0)
        written = 0
        while written < len(encoded):
            written += os.write(fd, encoded[written:])


# ---------------------------------------------------------------------
#  Audit-log helper (B6 R9)
# ---------------------------------------------------------------------

def worker_audit_extras(handle: WorkerHandle) -> dict:
    """Return the additive audit-log fields a worker should attach.

    Existing audit rows without these fields stay valid (additive schema).
    """
    return {
        "worker_id": handle.worker_id,
        "parent_session": handle.parent_session,
    }


# ---------------------------------------------------------------------
#  Module CLI (introspection / health)
# ---------------------------------------------------------------------

def _cli_workers_for_target(target: str, repo: Path) -> list[dict]:
    base = repo / "evidence" / target_storage_key(target) / "workers"
    if not base.exists():
        return []
    out = []
    for child in sorted(base.iterdir()):
        if not child.is_dir():
            continue
        seed = _read_json_safely(child / "seed.json", {})
        out.append({
            "scratch_dir": str(child),
            "kind": seed.get("kind"),
            "worker_id": seed.get("worker_id"),
            "completed": (child / "done.flag").exists(),
            "findings_count": len(_read_json_safely(child / "findings.json", []) or []),
            "attempt_count": _count_lines(child / "attempts.jsonl"),
        })
    return out


def main(argv: list[str] | None = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(
        description="parallel_workers: list per-target worker scratch state",
    )
    parser.add_argument("--target", required=True, help="target host/domain")
    parser.add_argument(
        "--repo-root",
        default=str(BASE_DIR),
        help="repository root (default: parent of this file)",
    )
    args = parser.parse_args(argv)
    rows = _cli_workers_for_target(args.target, Path(args.repo_root))
    print(json.dumps({"target": args.target, "workers": rows}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
